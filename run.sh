#!/bin/bash

target/release/electrs -vvvv --cookie jacky:_RZekaGRgKQJSIOYi6vq0_CkJtjoCootamy81J2cDn0 --db-dir ./data --daemon-rpc-host "192.168.10.103:19527" \
    --network mainnet --jsonrpc-import --utxos-limit 5000 --electrum-txs-limit 5000 --address-search --index-unspendables \ --cors "*" --http-addr "0.0.0.0:3000"

target/release/electrs -vvvv --cookie q17AIoqBJSEhW7djqjn0nTsZcz4=:nnlkAZn58bqsyYwVtHIajZ16cj8= --db-dir ./db --daemon-rpc-host "192.168.10.103:19527" --network satstestnet --utxos-limit 5000 --electrum-txs-limit 5000 --address-search --index-unspendables --cors "*" --http-addr "0.0.0.0:3000" --jsonrpc-import


