doubletake
==========

A tool for creating Bitcoin double-spend punishment bonds on Liquid.


# How it works

This tool will allow you to create a bond on Liquid where you lock up some money
for a limited amount of time and that anyone can burn if they proof that you
have attempted a double spend on Bitcoin with the public key tied to the bond.

To start, you need to specidy which public key you want to create a bond for.

Note that a bond can only work for either segwit v0 **OR** taproot, not for both.
Also, currently only segwit is supported.




# Testing

There is an integration test that tests either

- against libelementsconsensus, but this one isn't working for now
- against an elementsregtest network that should be running

You can run a compatible regtest network as follows:

```
$ elementsd -chain=elementsregtest -server=1 -validatepegin=0 -rpcport=8888 -rpcuser=testuser -rpcpassword=testpass -anyonecanspendaremine=1 -initialfreecoins=2100000000000000 -blindedaddresses=0 -acceptnonstdtxn=1
$ # in another terminal, prepare as follows:
$ elements-cli -chain=elementsregtest -rpcuser=testuser -rpcpassword=testpass -rpcport=8888 createwallet ""
$ elements-cli -chain=elementsregtest -rpcuser=testuser -rpcpassword=testpass -rpcport=8888 rescanblockchain
```

You can run the tests as follows:

```
$ cd ./integration_test/
$ cargo run -- regtest
```


# WASM

To build for WASM, use the `wasm` feature.

```
$ wasm-pack build --target web -- --features wasm
```
