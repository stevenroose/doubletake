#!/bin/sh

elementsd -chain=elementsregtest -server=1 -validatepegin=0 -rpcport=8888 -rpcuser=testuser -rpcpassword=testpass -anyonecanspendaremine=1 -initialfreecoins=2100000000000000 -blindedaddresses=0

# after this, you need to run
# $ elements-cli -regtest -rpcuser=testuser -rpcpassword=testpass -rpcport=8888 createwallet ""
# $ elements-cli -regtest -rpcuser=testuser -rpcpassword=testpass -rpcport=8888 rescanblockchain
