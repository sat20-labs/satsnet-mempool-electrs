#!/bin/bash

target/release/electrs -vvvv --cookie jacky:_RZekaGRgKQJSIOYi6vq0_CkJtjoCootamy81J2cDn0 --db-dir ./data --daemon-rpc-host "127.0.0.1:8337" \
    --network mainnet --jsonrpc-import --utxos-limit 5000 --electrum-txs-limit 5000 --address-search --index-unspendables \ --cors "*" --http-addr "0.0.0.0:3000"
