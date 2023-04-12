# Integration test

We have a series of scripts for interacting with a l2geth, deliver transactions to it and collect the block trace as a json file,

which would be read the test by the integration-test binary

## Prerequisite 

+ PUt a hardhat.config.js for configuration, can just copy the `hardhat.config.js.example`

+ Launch a l2geth node should be launched, the default config in example require the node has enabled a http API so commonly it would be launch with following command line, and we need to enable the mptwitness switch:

> geth --datadir=\<data dir\> --unlock \<miner address\> --mine --allow-insecure-unlock --http --http.api=net,eth,scroll --maxpeers 0 --trace.mptwitness=1

## compile contracts

> npx hardhat compile

## deploy

> npx hardhat run scripts/deploy.js

All the addresses for each contracts would be saved in `deploy.json`

## select a tx to run

> npx hardhat run scripts/tx_<contract>.js

Script read `deploy.json` for contract address and deliver a tx for testing

## collect the trace of latest block

> npx hardhat run scripts/trace_tx.js

Collect the trace and mpt witness data of last block and save it inside `trace.json`

## run test binary

> cargo run integration-test
