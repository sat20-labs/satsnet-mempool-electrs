use std::collections::{HashMap, HashSet};

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64;
use glob;
use hex;
use itertools::Itertools;
use satsnet::hashes::hex::{FromHex, ToHex};
use serde_json::{from_str, from_value, Value};

#[cfg(feature = "liquid")]
use elements::encode::{deserialize, serialize};
#[cfg(not(feature = "liquid"))]
use satsnet::consensus::encode::{deserialize, serialize};

use crate::chain::{Block, BlockHash, BlockHeader, Network, Transaction, Txid};
use crate::errors::*;
use crate::metrics::{HistogramOpts, HistogramVec, Metrics};
use crate::signal::Waiter;
use crate::util::HeaderList;

use log::{debug, info, warn};
use openssl::x509::X509;

use reqwest::blocking::{Client, Response};
use reqwest::header::AUTHORIZATION;

fn parse_hash<T>(value: &Value) -> Result<T>
where
    T: FromHex,
{
    T::from_hex(
        value
            .as_str()
            .chain_err(|| format!("non-string value: {}", value))?,
    )
    .chain_err(|| format!("non-hex value: {}", value))
}

fn header_from_value(value: Value) -> Result<BlockHeader> {
    let header_hex = value
        .as_str()
        .chain_err(|| format!("non-string header: {}", value))?;
    let header_bytes = hex::decode(header_hex).chain_err(|| "non-hex header")?;
    deserialize(&header_bytes).chain_err(|| format!("failed to parse header {}", header_hex))
}

fn block_from_value(value: Value) -> Result<Block> {
    let block_hex = value.as_str().chain_err(|| "non-string block")?;
    // println!("Block Hex: {}", block_hex);
    // block_hex = "000040204809ee2b571d6871514bf3b193ee362e3a6c66acd8315a313bfd6aa43c997d7a8e78480ac965e7828d4ca67559ade5b95bb8a078974427c1041fd98ba66a5fcfa6b10467ffff001d56465f6b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff18021801088f3b97678f7839360b2f503253482f627463642fffffffff010000000000000000002251201eca94fc175e45d42a907e97eabf3ec76a3237653537cc0f11faf4dfd8c0e1000000000001000000010000000000000000000000000000000000000000000000000000000000000000feffffff7140646137386239626266666462636532393161383365333336623664663433313638653530343162636133656664323063323565646564373064326233666231342251207e4e20121cd42053d971944ddd24d8442707062e4815d2b4090b7a62a18c411a0340420f08755ef2c77650b08bffffffff0140420f000000000002fe80841e00fe20a10700fe404b4c00fe20a107002251207e4e20121cd42053d971944ddd24d8442707062e4815d2b4090b7a62a18c411a00000000";
    let block_bytes = hex::decode(block_hex).chain_err(|| "non-hex block")?;
    // println!("Block Bytes: {:?}", block_bytes);
    deserialize(&block_bytes).chain_err(|| format!("failed to parse block {}", block_hex))
}

fn tx_from_value(value: Value) -> Result<Transaction> {
    let tx_hex = value.as_str().chain_err(|| "non-string tx")?;
    let tx_bytes = hex::decode(tx_hex).chain_err(|| "non-hex tx")?;
    deserialize(&tx_bytes).chain_err(|| format!("failed to parse tx {}", tx_hex))
}

/// Parse JSONRPC error code, if exists.
fn parse_error_code(err: &Value) -> Option<i64> {
    err.as_object()?.get("code")?.as_i64()
}

fn parse_jsonrpc_reply(mut reply: Value, method: &str, expected_id: u64) -> Result<Value> {
    if let Some(reply_obj) = reply.as_object_mut() {
        if let Some(err) = reply_obj.get("error") {
            if !err.is_null() {
                if let Some(code) = parse_error_code(err) {
                    match code {
                        // RPC_IN_WARMUP -> retry by later reconnection
                        -28 => bail!(ErrorKind::Connection(err.to_string())),
                        _ => bail!("{} RPC error: {}", method, err),
                    }
                }
            }
        }
        let id = reply_obj
            .get("id")
            .chain_err(|| format!("no id in reply: {:?}", reply_obj))?
            .clone();
        if id != expected_id {
            bail!(
                "wrong {} response id {}, expected {}",
                method,
                id,
                expected_id
            );
        }
        if let Some(result) = reply_obj.get_mut("result") {
            return Ok(result.take());
        }
        bail!("no result in reply: {:?}", reply_obj);
    }
    bail!("non-object reply: {:?}", reply);
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u32,
    pub headers: u32,
    pub bestblockhash: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MempoolInfo {
    pub size: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct NetworkInfo {
    version: u64,
    relayfee: f64, // in BTC/kB
}

#[derive(Serialize, Deserialize, Debug)]
struct MempoolFees {
    base: f64,
    #[serde(rename = "effective-feerate")]
    effective_feerate: f64,
    #[serde(rename = "effective-includes")]
    effective_includes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MempoolAcceptResult {
    txid: String,
    wtxid: String,
    allowed: Option<bool>,
    vsize: Option<u32>,
    fees: Option<MempoolFees>,
    #[serde(rename = "reject-reason")]
    reject_reason: Option<String>,
}

pub trait CookieGetter: Send + Sync {
    fn get(&self) -> Result<Vec<u8>>;
}

struct Connection {
    client: Client,
    cookie_getter: Arc<dyn CookieGetter>,
    url: String,
    cert_path: Option<PathBuf>,
    signal: Waiter,
}

fn validate_cert_path(cert_path: &PathBuf) -> Result<()> {
    let mut file = fs::File::open(cert_path).chain_err(|| "Failed to open cert file")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .chain_err(|| "Failed to read cert file")?;
    X509::from_pem(&buffer).chain_err(|| "Invalid certificate")?;

    Ok(())
}

impl Connection {
    fn new(
        url: String,
        cert_path: Option<PathBuf>,
        cookie_getter: Arc<dyn CookieGetter>,
        signal: Waiter,
    ) -> Result<Connection> {
        if let Some(ref path) = cert_path {
            validate_cert_path(path)?;
        }

        let client = Client::builder()
            .danger_accept_invalid_certs(cert_path.is_some())
            .build()
            .chain_err(|| "Failed to build client")?;

        Ok(Connection {
            client,
            cookie_getter,
            url,
            cert_path,
            signal,
        })
    }

    fn reconnect(&self) -> Result<Connection> {
        Connection::new(
            self.url.clone(),
            self.cert_path.clone(),
            self.cookie_getter.clone(),
            self.signal.clone(),
        )
    }

    fn send(&self, request: &str) -> Result<Response> {
        let cookie = self.cookie_getter.get()?;
        let url = &self.url;

        // let body = request.to_string();
        // println!("send body: {}", body);
        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, format!("Basic {}", base64::encode(cookie)))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request.to_string())
            .send()
            .chain_err(|| "Failed to send request")?;

        Ok(response)
    }

    fn recv(response: Response) -> Result<String> {
        let status = response.status();
        let contents = response
            .text()
            .chain_err(|| "Failed to read response text")?;

        // println!("recv contents: {}", contents);
        if status.is_success() {
            Ok(contents)
        } else {
            bail!("HTTP error: {}, Response: {}", status, contents);
        }
    }
}

struct Counter {
    value: Mutex<u64>,
}

impl Counter {
    fn new() -> Self {
        Counter {
            value: Mutex::new(0),
        }
    }

    fn next(&self) -> u64 {
        let mut value = self.value.lock().unwrap();
        *value += 1;
        *value
    }
}

pub struct Daemon {
    daemon_dir: PathBuf,
    blocks_dir: PathBuf,
    network: Network,
    magic: Option<u32>,
    conn: Mutex<Connection>,
    message_id: Counter, // for monotonic JSONRPC 'id'
    signal: Waiter,

    // monitoring
    latency: HistogramVec,
    size: HistogramVec,
}

impl Daemon {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        daemon_dir: PathBuf,
        blocks_dir: PathBuf,
        daemon_rpc_url: String,
        daemon_cert_path: Option<PathBuf>,
        cookie_getter: Arc<dyn CookieGetter>,
        network: Network,
        magic: Option<u32>,
        signal: Waiter,
        metrics: &Metrics,
    ) -> Result<Daemon> {
        let daemon = Daemon {
            daemon_dir,
            blocks_dir,
            network,
            magic,
            conn: Mutex::new(Connection::new(
                daemon_rpc_url.clone(),
                daemon_cert_path,
                cookie_getter,
                signal.clone(),
            )?),
            message_id: Counter::new(),
            signal: signal.clone(),
            latency: metrics.histogram_vec(
                HistogramOpts::new("daemon_rpc", "Bitcoind RPC latency (in seconds)"),
                &["method"],
            ),
            size: metrics.histogram_vec(
                HistogramOpts::new("daemon_bytes", "Bitcoind RPC size (in bytes)"),
                &["method", "dir"],
            ),
        };
        let info = daemon.getinfo()?;
        info!("{:?}", info);

        if info.version < 7_0_00 {
            bail!(
                "{} is not supported - please use satsnet? /btcd ?+",
                info.version,
            )
        }

        loop {
            let info = daemon.getblockchaininfo()?;
            let mempool = daemon.getmempoolinfo()?;

            let ibd_done = if network.is_regtest() {
                info.blocks == info.headers
            } else {
                // !info.initialblockdownload.unwrap_or(false)
                true
            };

            if ibd_done && info.blocks == info.headers {
                break;
            }

            // if mempool.size > 0 && ibd_done && info.blocks == info.headers {
            //     break;
            // }

            warn!(
                "waiting for btcd sync and mempool load to finish: {}/{} blocks, verification progress: {:.3}%, mempool loaded: {}",
                info.blocks,
                info.headers,
                100.0,
                // info.verificationprogress * 100.0,
                mempool.size
            );
            signal.wait(Duration::from_secs(5), false)?;
        }
        Ok(daemon)
    }

    pub fn reconnect(&self) -> Result<Daemon> {
        Ok(Daemon {
            daemon_dir: self.daemon_dir.clone(),
            blocks_dir: self.blocks_dir.clone(),
            network: self.network,
            magic: self.magic,
            conn: Mutex::new(self.conn.lock().unwrap().reconnect()?),
            message_id: Counter::new(),
            signal: self.signal.clone(),
            latency: self.latency.clone(),
            size: self.size.clone(),
        })
    }

    pub fn list_blk_files(&self) -> Result<Vec<PathBuf>> {
        let path = self.blocks_dir.join("blk*.dat");
        debug!("listing block files at {:?}", path);
        let mut paths: Vec<PathBuf> = glob::glob(path.to_str().unwrap())
            .chain_err(|| "failed to list blk*.dat files")?
            .map(|res| res.unwrap())
            .collect();
        paths.sort();
        Ok(paths)
    }

    pub fn magic(&self) -> u32 {
        self.magic.unwrap_or_else(|| self.network.magic())
    }

    fn call_jsonrpc(&self, method: &str, request: &Value) -> Result<Value> {
        let conn = self.conn.lock().unwrap();
        let timer = self.latency.with_label_values(&[method]).start_timer();
        let request = request.to_string();
        let response = conn.send(&request)?;
        self.size
            .with_label_values(&[method, "send"])
            .observe(request.len() as f64);
        let response_text = Connection::recv(response)?;
        let result: Value = from_str(&response_text).chain_err(|| "invalid JSON")?;
        timer.observe_duration();
        self.size
            .with_label_values(&[method, "recv"])
            .observe(response_text.len() as f64);
        Ok(result)
    }

    fn handle_request_batch(
        &self,
        method: &str,
        params_list: &[Value],
        failure_threshold: f64,
    ) -> Result<Vec<Value>> {
        let id = self.message_id.next();
        let chunks = params_list
            .iter()
            .map(|params| json!({"jsonrpc":"1.0", "method": method, "params": params, "id": id}))
            .chunks(50_000); // Max Amount of batched requests
        let mut results = vec![];
        let total_requests = params_list.len();
        let mut failed_requests: u64 = 0;
        let threshold = (failure_threshold * total_requests as f64).round() as u64;
        let mut n = 0;

        for chunk in &chunks {
            let reqs = chunk.collect();
            let mut replies = self.call_jsonrpc(method, &reqs)?;
            if let Some(replies_vec) = replies.as_array_mut() {
                for reply in replies_vec {
                    n += 1;
                    match parse_jsonrpc_reply(reply.take(), method, id) {
                        Ok(parsed_reply) => results.push(parsed_reply),
                        Err(e) => {
                            failed_requests += 1;
                            warn!(
                                "batch request {} {}/{} failed: {}",
                                method,
                                n,
                                total_requests,
                                e.to_string()
                            );
                            // abort and return the last error once a threshold number of requests have failed
                            if failed_requests > threshold {
                                return Err(e);
                            }
                        }
                    }
                }
            } else {
                bail!("non-array replies: {:?}", replies);
            }
        }

        Ok(results)
    }

    fn retry_request_batch(
        &self,
        method: &str,
        params_list: &[Value],
        failure_threshold: f64,
    ) -> Result<Vec<Value>> {
        loop {
            match self.handle_request_batch(method, params_list, failure_threshold) {
                Err(Error(ErrorKind::Connection(msg), _)) => {
                    warn!("reconnecting to satsnet/btcd: {}", msg);
                    self.signal.wait(Duration::from_secs(3), false)?;
                    let mut conn = self.conn.lock().unwrap();
                    *conn = conn.reconnect()?;
                    continue;
                }
                result => return result,
            }
        }
    }

    fn request(&self, method: &str, params: Value) -> Result<Value> {
        let mut values = self.retry_request_batch(method, &[params], 0.0)?;
        assert_eq!(values.len(), 1);
        Ok(values.remove(0))
    }

    fn requests(&self, method: &str, params_list: &[Value]) -> Result<Vec<Value>> {
        self.retry_request_batch(method, params_list, 0.0)
    }

    // btcd JSONRPC API:

    pub fn getblockchaininfo(&self) -> Result<BlockchainInfo> {
        let info: Value = self.request("getblockchaininfo", json!([]))?;
        from_value(info).chain_err(|| "invalid blockchain info")
    }

    fn getmempoolinfo(&self) -> Result<MempoolInfo> {
        let info: Value = self.request("getmempoolinfo", json!([]))?;
        from_value(info).chain_err(|| "invalid mempool info")
    }

    fn getinfo(&self) -> Result<NetworkInfo> {
        let info: Value = self.request("getinfo", json!([]))?;
        from_value(info).chain_err(|| "invalid info")
    }

    pub fn getbestblockhash(&self) -> Result<BlockHash> {
        parse_hash(&self.request("getbestblockhash", json!([]))?)
    }

    pub fn getblockheader(&self, blockhash: &BlockHash) -> Result<BlockHeader> {
        header_from_value(self.request(
            "getblockheader",
            json!([blockhash.to_hex(), /*verbose=*/ false]),
        )?)
    }

    pub fn getblockheaders(&self, heights: &[usize]) -> Result<Vec<BlockHeader>> {
        let heights: Vec<Value> = heights.iter().map(|height| json!([height])).collect();
        let params_list: Vec<Value> = self
            .requests("getblockhash", &heights)?
            .into_iter()
            .map(|hash| json!([hash, /*verbose=*/ false]))
            .collect();
        let mut result = vec![];
        for h in self.requests("getblockheader", &params_list)? {
            result.push(header_from_value(h)?);
        }
        Ok(result)
    }

    pub fn getblock(&self, blockhash: &BlockHash) -> Result<Block> {
        let block = block_from_value(
            self.request("getblock", json!([blockhash.to_hex(), /*verbose=*/ 0]))?,
        )?;
        assert_eq!(block.block_hash(), *blockhash);
        Ok(block)
    }

    pub fn getblock_raw(&self, blockhash: &BlockHash, verbose: u32) -> Result<Value> {
        self.request("getblock", json!([blockhash.to_hex(), verbose]))
    }

    pub fn getblocks(&self, blockhashes: &[BlockHash]) -> Result<Vec<Block>> {
        let params_list: Vec<Value> = blockhashes
            .iter()
            .map(|hash| json!([hash.to_hex(), /*verbose=*/ 0]))
            .collect();
        let values = self.requests("getblock", &params_list)?;
        // let mut count = 0;
        let mut blocks = vec![];
        for value in values {
            let block = block_from_value(value)?;
            // trace!("[count] | {count}");
            // count += 1;
            blocks.push(block);
        }
        Ok(blocks)
    }

    pub fn gettransactions(&self, txhashes: &[&Txid]) -> Result<Vec<Transaction>> {
        let params_list: Vec<Value> = txhashes
            .iter()
            .map(|txhash| json!([txhash.to_hex(), /*verbose=*/ 0]))
            .collect();
        let values = self.retry_request_batch("getrawtransaction", &params_list, 0.25)?;
        let mut txs = vec![];
        for value in values {
            txs.push(tx_from_value(value)?);
        }
        // missing transactions are skipped, so the number of txs returned may be less than the number of txids requested
        Ok(txs)
    }

    pub fn gettransaction_raw(
        &self,
        txid: &Txid,
        blockhash: &BlockHash,
        verbose: u32,
    ) -> Result<Value> {
        self.request(
            "getrawtransaction",
            json!([txid.to_hex(), verbose, blockhash]),
        )
    }

    pub fn getmempooltx(&self, txhash: &Txid) -> Result<Transaction> {
        let value = self.request(
            "getrawtransaction",
            json!([txhash.to_hex(), /*verbose=*/ 0]),
        )?;
        tx_from_value(value)
    }

    pub fn getmempooltxids(&self) -> Result<HashSet<Txid>> {
        let res = self.request("getrawmempool", json!([/*verbose=*/ false]))?;
        serde_json::from_value(res).chain_err(|| "invalid getrawmempool reply")
    }

    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        self.broadcast_raw(&hex::encode(serialize(tx)))
    }

    pub fn broadcast_raw(&self, txhex: &str) -> Result<Txid> {
        let txid = self.request("sendrawtransaction", json!([txhex]))?;
        Txid::from_hex(txid.as_str().chain_err(|| "non-string txid")?)
            .chain_err(|| "failed to parse txid")
    }

    pub fn test_mempool_accept(
        &self,
        txhex: Vec<String>,
        maxfeerate: Option<f64>,
    ) -> Result<Vec<MempoolAcceptResult>> {
        let params = match maxfeerate {
            Some(rate) => json!([txhex, format!("{:.8}", rate)]),
            None => json!([txhex]),
        };
        let result = self.request("testmempoolaccept", params)?;
        serde_json::from_value::<Vec<MempoolAcceptResult>>(result)
            .chain_err(|| "invalid testmempoolaccept reply")
    }

    // Get estimated feerates for the provided confirmation targets using a batch RPC request
    // Missing estimates are logged but do not cause a failure, whatever is available is returned
    #[allow(clippy::float_cmp)]
    pub fn estimatefee_batch(&self, conf_targets: &[u16]) -> Result<HashMap<u16, f64>> {
        let params_list: Vec<Value> = conf_targets.iter().map(|t| json!([t])).collect();

        Ok(self
            .requests("estimatefee", &params_list)?
            .iter()
            .zip(conf_targets)
            .filter_map(|(reply, target)| {
                match reply.as_f64() {
                    Some(feerate) if feerate != -1.0 => {
                        // from BTC/kB to sat/b
                        Some((*target, feerate * 100_000f64))
                    }
                    _ => {
                        warn!(
                            "invalid estimatefee response or not enough data for target {}",
                            target
                        );
                        None
                    }
                }
            })
            .collect())
    }

    fn get_all_headers(&self, tip: &BlockHash) -> Result<Vec<BlockHeader>> {
        let info: Value = self.request("getblockheader", json!([tip.to_hex()]))?;
        let tip_height = info
            .get("height")
            .expect("missing height")
            .as_u64()
            .expect("non-numeric height") as usize;
        let all_heights: Vec<usize> = (0..=tip_height).collect();
        let chunk_size = 100_000;
        let mut result = vec![];
        for heights in all_heights.chunks(chunk_size) {
            trace!("downloading {} block headers", heights.len());
            let mut headers = self.getblockheaders(heights)?;
            assert!(headers.len() == heights.len());
            result.append(&mut headers);
        }

        let mut blockhash = BlockHash::default();
        for header in &result {
            assert_eq!(header.prev_blockhash, blockhash);
            blockhash = header.block_hash();
        }
        assert_eq!(blockhash, *tip);
        Ok(result)
    }

    // Returns a list of BlockHeaders in ascending height (i.e. the tip is last).
    pub fn get_new_headers(
        &self,
        indexed_headers: &HeaderList,
        bestblockhash: &BlockHash,
    ) -> Result<Vec<BlockHeader>> {
        // Iterate back over headers until known blockash is found:
        if indexed_headers.is_empty() {
            debug!("downloading all block headers up to {}", bestblockhash);
            return self.get_all_headers(bestblockhash);
        }
        debug!(
            "downloading new block headers ({} already indexed) from {}",
            indexed_headers.len(),
            bestblockhash,
        );
        let mut new_headers = vec![];
        let null_hash = BlockHash::default();
        let mut blockhash = *bestblockhash;
        while blockhash != null_hash {
            if indexed_headers.header_by_blockhash(&blockhash).is_some() {
                break;
            }
            let header = self
                .getblockheader(&blockhash)
                .chain_err(|| format!("failed to get {} header", blockhash))?;
            blockhash = header.prev_blockhash;
            new_headers.push(header);
        }
        trace!("downloaded {} block headers", new_headers.len());
        new_headers.reverse(); // so the tip is the last vector entry
        Ok(new_headers)
    }

    pub fn get_relayfee(&self) -> Result<f64> {
        let relayfee = self.getinfo()?.relayfee;

        // from BTC/kB to sat/b
        Ok(relayfee * 100_000f64)
    }
}
