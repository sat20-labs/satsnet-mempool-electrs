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
btcd: getrawtransaction

3 pass
bitcoind: getblockchaininfo
btcd: getchaintips? getblockcount? getinfo? getmininginfo? getcurrentnet?

4 pass
bitcoind: getmempoolinfo
btcd: getmempoolinfo

5 pass
bitcoind: getbestblockhash
btcd: getbestblockhash

6 pass
bitcoind: getblockheader
btcd: getblockheader

7 pass
bitcoind: getblock
btcd: getblock

8 pass
bitcoind: getrawmempool
btcd: getrawmempool

9 pass
bitcoind: sendrawtransaction
btcd: sendrawtransaction

10 pass
bitcoind: testmempoolaccept
btcd: testmempoolaccept

11 pass
bitcoind: estimatesmartfee
btcd: estimatefee  estimatesmartfee(官方还未实现，未来应该会实现)

12 pass
bitcoind: getblockhash
btcd: getblockhash