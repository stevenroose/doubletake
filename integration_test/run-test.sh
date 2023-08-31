#!/bin/sh

CARGO_TARGET="$(cargo metadata | jq -r '.target_directory')"
cargo run -- --regtest --regtest-port 8888 --regtest-user testuser --regtest-pass testpass 
    #--cli ${CARGO_TARGET}/debug/doubletake
