#!/bin/bash
# Detector ablation at 50 km: one imperfection at a time
cd "$(dirname "$0")"; rm -f results/e0_abl.jsonl; P=3100
for c in "det=1 eta1=0.25 dead=0 ap=0 label=none" "det=1 dead=0 ap=0 label=mismatch" "det=1 eta1=0.25 ap=0 label=deadtime" "det=1 eta1=0.25 dead=0 label=afterpulse"; do
  P=$((P+1000)); timeout 1800 ./qgrid run=qkd port=$P dist=50 nz=4194304 blocks=4 $c >> results/e0_abl.jsonl; done
