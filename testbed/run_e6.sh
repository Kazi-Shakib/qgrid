#!/bin/bash
# E6: attack detection. D1 release audit, D2 delivery receipts (counted by the testbed), D3 feeder-head
# residuals (written per session to results/e6_resid.jsonl; thresholds set offline by analyze_e6.py).
cd "$(dirname "$0")"; mkdir -p results; P=2000
nextp() { P=$((P+3000)); [ $P -gt 29000 ] && P=2000; }
run() { nextp; timeout 2400 ./qgrid port=$P resid=results/e6_resid.jsonl "$@" >> results/e6.jsonl || echo "FAIL $*" >&2; }
rm -f results/e6.jsonl results/e6_resid.jsonl
Q="qm=2 dist=10 reserve=200000 tmo=300"
# honest sessions (false positives)
S=1; for c in "npath=1 bind=1 erase=1 meta=1" "npath=2 bind=1 erase=1 meta=1" "sae=1 meta=0" "topo=2 npath=2 bind=1 erase=1 meta=1"; do
  run run=security n=1000 $c mode=0 mseed=$S $Q label=honest; S=$((S+1)); done
# single-gateway attacks, unbound and bound, active and (where meaningful) passive
for v in "bind=0 meta=0" "bind=1 meta=1"; do
  for m in 1 2 3; do run run=security n=100 npath=1 $v mode=$m mseed=$S $Q label=single; S=$((S+1)); done
  run run=security n=100 npath=1 $v mode=2 passive=1 mseed=$S $Q label=single; S=$((S+1))
done
# compromise scenarios, active and passive
for p in 0 1; do
  for a in "npath=1 bind=1 erase=1 meta=1 mode=4 g1=1 g2=0" \
           "npath=2 bind=1 erase=1 meta=1 mode=4 g1=0 g2=0" \
           "npath=2 bind=1 erase=1 meta=1 mode=4 g1=2 g2=2" \
           "npath=2 bind=1 erase=0 meta=1 mode=4 g1=1 g2=3" \
           "npath=2 bind=1 erase=1 meta=1 mode=4 g1=1 g2=3" \
           "npath=2 bind=1 erase=1 meta=2 mode=4 fa=1" \
           "topo=1 npath=1 bind=1 erase=1 meta=1 mode=4 tn=1" \
           "topo=2 npath=2 bind=1 erase=1 meta=1 mode=4 tn=1"; do
    run run=security n=100 $a passive=$p mseed=$S $Q label=scen; S=$((S+1))
  done
done
# D3 over a day on each lateral (retained shares, post-delivery compromise, active)
for vi in 0 1 2; do acc=$(( (vi + 1) % 3 ))
  run run=security n=96 npath=2 bind=1 erase=0 meta=1 mode=4 g1=1 g2=3 victim=$vi acc=$acc mseed=$S $Q label=day; S=$((S+1))
done
python3 analyze_e6.py
