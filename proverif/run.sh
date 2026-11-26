#!/bin/bash
# Runs every ProVerif model and prints one line per model with the verdict of each query.
# Usage: ./run.sh            (needs proverif >= 2.04 on PATH; e.g. `opam install proverif`)
cd "$(dirname "$0")"; mkdir -p out
python3 gen.py >/dev/null
for n in $(cat models/LIST); do
  start=$(date +%s.%N)
  timeout 3600 proverif models/$n.pv > out/$n.txt 2>&1
  t=$(echo "$(date +%s.%N) - $start" | bc)
  printf "%-28s %7.1fs  " "$n" "$t"
  grep -E "^RESULT" out/$n.txt | sed -E 's/.*(is true|is false|cannot be proved).*/\1/' | sed 's/is true/T/;s/is false/F/;s/cannot be proved/?/' | tr '\n' ' '
  echo
done | tee summary.txt
