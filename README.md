doubletake
==========

A tool for creating Bitcoin double-spend punishment bonds on Liquid.

**WARNING**: Don't use this tool for real use cases yet. There are still a few
known shortcomings in the design that make the bond circumventable.


# How it works

This tool will allow you to create a bond on Liquid where you lock up some money
for a limited amount of time and that anyone can burn if they prove that you
have attempted a double spend on Bitcoin with the public key tied to the bond.

To start, you need to specify which public key you want to create a bond for.

Note that a bond can only work for either segwit v0 **OR** taproot, not for both.
Also, currently, only segwit is supported.


## CLI

There is a CLI tool included by default.

```
$ cargo install doubletake
$ doubletake create --segwit \
    --pubkey 028c920fd8a18688dada0af50177941c80920c0dc86c2ecba6b13784dcbd0ffcb7 \
    --bond-value "2 BTC" \
    --expiry 1722369854 \
    --reclaim-pubkey 03339c911ea18b24c3dea446ca4b8ba5d1b9cf5de0170a1d9fde2da17ec8431a56
{
  "address": "ex1qref05f3urpcrcr59x45tar2xu3y0hppfcd6avujq5kerxqfhr73smdjj5h",
  "spec": "AAKMkg_YoYaI2toK9QF3lByAkgwNyGwuy6axN4TcvQ_8twDC6wsAAAAAbVIcOOweoVc0riK3xGBkQSgpwNBXnwpxPRwE7el5Am8-R6lmAzOckR6hiyTD3qRGykuLpdG5z13gFwodn94toX7IQxpW"
}%
```


## As a Rust library

If you want to use doubletake purely as a Rust library, you can
turn off the CLI dependencies by disabling the default feature `cli`.


# Testing

There is an integration test that tests either

- against libelementsconsensus, but this one isn't working for now
- against an elementsregtest network that should be running

You can run a compatible regtest network as follows:

```
$ elementsd -chain=elementsregtest -server=1 -validatepegin=0 -rpcport=8888 -rpcuser=testuser -rpcpassword=testpass -anyonecanspendaremine=1 -initialfreecoins=2100000000000000 -blindedaddresses=0
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


# Observations

Currently we only support segwit v0 spends. This means that any segwit v0 spend
done by the given pubkey, should be covered. This means p2wpkh and p2wsh.

Also, our implementation should be robust enough that any sighash flags should
be supported. So if you hold an unconfirmed spend of an output with any sighash
flags, you will be able to burn the bond if any other kind of spend is done
using another sighash flag.

This becomes a lot harder with taproot, where the sighash structure changes
significantly depending on the sighash flags used. The taproot version
is still a work in progress.
