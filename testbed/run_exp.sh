#!/bin/bash
# E1-E3, E5 with keys from the software BB84 stack (realistic detectors). Results: results/*.jsonl
cd "$(dirname "$0")"; mkdir -p results; P=2000
nextp() { P=$((P+3000)); [ $P -gt 29000 ] && P=2000; }
run() { out=$1; shift; nextp; timeout 2400 ./qgrid port=$P "$@" >> results/$out.jsonl || echo "FAIL $out $*" >&2; }
N=${N:-100}
./sysinfo.sh > results/sysinfo.txt
rm -f results/e1.jsonl results/e2.jsonl results/e3.jsonl results/e3_bench.jsonl results/e5.jsonl
Q="qm=2 dist=10 reserve=100000"
# E1: single-gateway integration x attacker models (T1 redirect, T2 theft, T3 substitution)
for v in "bind=0 oid=0 meta=0" "bind=0 oid=1 meta=0" "bind=1 oid=0 meta=1" "bind=1 oid=1 meta=1"; do
  for m in 1 2 3; do run e1 run=security n=$N tmo=300 npath=1 $v mode=$m $Q label=e1; done
done
# E2: delivery architectures x compromise scenarios (S0 none, S1 G1 throughout, S2 G1 then G2 before
# delivery, S3 G1 throughout + G2 after delivery, S4 forged in-band announcements)
for a in "npath=1 bind=1 erase=1 meta=1" "npath=2 bind=0 erase=1 meta=0" "npath=2 bind=1 erase=0 meta=1" \
         "npath=2 bind=1 erase=1 meta=1" "npath=2 bind=1 erase=1 meta=2" "sae=1 meta=0"; do
  for sc in "g1=0 g2=0 fa=0" "g1=1 g2=0 fa=0" "g1=2 g2=2 fa=0" "g1=1 g2=3 fa=0" "g1=0 g2=0 fa=1"; do
    run e2 run=security n=$N tmo=300 $a mode=4 $sc $Q label=e2
  done
done
# E2 / S5: trusted-node relays, honest and with compromised relays
for a in "topo=1 npath=1 bind=1 erase=1 meta=1" "topo=1 sae=1 meta=0" "topo=2 route2=0 npath=2 bind=1 erase=1 meta=1" \
         "topo=2 npath=2 bind=1 erase=1 meta=1"; do
  for tn in 0 1 3; do run e2 run=security n=$N tmo=300 $a mode=4 tn=$tn $Q label=e2s5; done
done
# E3: honest performance; LAN, metro WAN, and a lossy wide-area WAN
for c in "npath=1 bind=1 meta=1 its=0" "npath=2 bind=1 meta=1 its=0" "npath=1 bind=1 meta=1 its=1 mpe=20" \
         "npath=2 bind=1 meta=1 its=1 mpe=20" "sae=1 its=0" "topo=2 npath=2 bind=1 meta=1 its=0"; do
  run e3 run=security n=1000 $c mode=0 qm=2 dist=10 reserve=600000 label=lan
  run e3 run=security n=300 $c mode=0 qm=2 dist=10 reserve=200000 wan=5 jit=1 loss=0 tmo=3000 label=metro
  run e3 run=security n=300 $c mode=0 qm=2 dist=10 reserve=200000 wan=25 jit=5 loss=0.01 tmo=5000 label=wide
done
for i in 1 2 3 4 5; do ./qgrid run=bench >> results/e3_bench.jsonl; done
# E5: grid impact over a day (one session every 15 min, victim on each lateral), key-retention attack
for vi in 0 1 2; do acc=$(( (vi + 1) % 3 ))
  for a in "npath=2 bind=1 erase=0 meta=1" "npath=2 bind=1 erase=1 meta=1"; do
    run e5 run=security n=96 tmo=300 $a mode=4 g1=1 g2=3 victim=$vi acc=$acc $Q label=e5
  done
done
