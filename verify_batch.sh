#!/bin/bash -e
prefix=${1:-wallet-b0b54476db350aa80aa8404d09ad2d2e} # the prefix for all wallets
n=${2:-5} # the number of wallets in the batch
passfile=${3:-all_passwords}
for i in $(seq -f "%03g" 0 $((n - 1))); do
    ii=$((10#$i))
    head -n "$((ii + 1))" "$passfile" | tail -n 1 | sed 's/.* = \(.*\)$/\1/g' | ethy.py --pass-stdin $prefix-$i.json > /dev/null
done
