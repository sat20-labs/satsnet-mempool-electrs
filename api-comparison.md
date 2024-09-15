# btc node api Comparison Table

# bitcoind rpc https://developer.bitcoin.org/reference/rpc/
# btcd rpc https://github.com/btcsuite/btcd/blob/master/docs/json_rpc_api.md

bitcoind -> btcd 

1 pass
bitcoind: getnetworkinfo
btcd: getinfo
need info: relayfee,version

2 pass
bitcoind: getrawtransaction

3
bitcoind: getblockchaininfo
btcd: getchaintips? getblockcount? getinfo? getmininginfo? getcurrentnet?

4 pass
bitcoind: getmempoolinfo

5 pass
bitcoind: getbestblockhash

6 pass
bitcoind: getblockheader

7 pass
bitcoind: getblock

8 pass
bitcoind: getrawmempool

9 pass
bitcoind: sendrawtransaction

10
bitcoind: testmempoolaccept

11
bitcoind: estimatesmartfee
btcd: wallet rpc 

12 pass
bitcoind: getblockhash