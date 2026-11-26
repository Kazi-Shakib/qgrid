#!/bin/bash
# E4: key supply on the BB84 stack's simulated clock. Each association re-keys every 100 s with a
# pool of 1000 one-time tags (10 authenticated messages/s); first epoch is warm-up.
cd "$(dirname "$0")"; mkdir -p results; rm -f results/e4.jsonl; P=2000
run() { P=$((P+3000)); [ $P -gt 29000 ] && P=2000; timeout 3600 ./qgrid port=$P run=supply its=1 mpe=1000 qm=2 simclock=1 epoch=100 epochs=8 warm=1 "$@" label=e4 >> results/e4.jsonl || echo "FAIL $*" >&2; }
for n in 3 4 5 6 7;     do run topo=0 L1=100 npath=1 bind=1 meta=1 nout=$n; done
for n in 1 2 3 4;       do run topo=0 L1=100 npath=2 bind=1 meta=1 nout=$n; done
for n in 45 55 65 75;   do run topo=1 L1=50 L2=50 npath=1 bind=1 meta=1 nout=$n; done
for n in 20 25 30 35;   do run topo=1 L1=50 L2=50 npath=2 bind=1 meta=1 nout=$n; done
for n in 55 65;         do run topo=2 L1=50 L2=50 npath=2 bind=1 meta=1 nout=$n; done
