#!/bin/bash

#target/release/electrs -vvvv --cookie jacky:_RZekaGRgKQJSIOYi6vq0_CkJtjoCootamy81J2cDn0 --db-dir ./data --daemon-rpc-host "192.168.10.103:19527" \
 #   --network mainnet --jsonrpc-import --utxos-limit 5000 --electrum-txs-limit 5000 --address-search --index-unspendables \ --cors "*" --http-addr "0.0.0.0:3000"

# satstestnet
git checkout satsnet
argo build --release;
target/release/electrs -vvvv --cookie q17AIoqBJSEhW7djqjn0nTsZcz4=:nnlkAZn58bqsyYwVtHIajZ16cj8= --db-dir ./db --daemon-rpc-host "192.168.10.103:19527" \
    --monitoring-addr 127.0.0.1:44224 --electrum-rpc-addr 127.0.0.1:60501 \
    --network satstestnet --utxos-limit 5000 --electrum-txs-limit 5000 --address-search --index-unspendables --cors "*" --http-addr "0.0.0.0:3001" --jsonrpc-import


