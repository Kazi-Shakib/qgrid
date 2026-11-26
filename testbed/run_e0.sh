#!/bin/bash
# E0: the BB84 stack alone, ideal vs realistic detectors, 10 blocks of 2^22 sifted bits per point
cd "$(dirname "$0")"; mkdir -p results; rm -f results/e0.jsonl; P=2000
for d in 0 1; do for L in 10 25 50 75 100; do P=$((P+3000))
  timeout 1800 ./qgrid run=qkd port=$P dist=$L det=$d nz=4194304 blocks=10 label=e0 >> results/e0.jsonl
done; done
