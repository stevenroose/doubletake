#!/bin/sh

set -e


# Analyze the segwit version
python3 ~/code/bsst/bsst/__init__.py --input-file=./segwit.script \
    --z3-enabled=true \
    --is-elements=true \
    --sigversion=tapscript \
    | tee segwit.script.report

less ./segwit.script.report
