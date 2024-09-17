#!/bin/bash

target/release/electrs -vvvv --cookie jacky:_RZekaGRgKQJSIOYi6vq0_CkJtjoCootamy81J2cDn0 --db-dir ./data --daemon-rpc-addr "192.168.10.188:8337" \
    --network mainnet --daemon-cert-path ./rpc1.cert --jsonrpc-import --cors "*" --http-addr "0.0.0.0:3002"
