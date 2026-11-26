#!/bin/sh
# Test PKI for the ETSI-014-style interfaces: one CA, KMEs, master SAE, gateway SAEs, outstation SAEs.
set -e
mkdir -p certs && cd certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 365 -subj "/CN=TestCA"
for n in KMEA KMEB M G1 G2 A B C D E F; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $n.key -out $n.csr -subj "/CN=$n"
  openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $n.crt -days 365
done
rm -f *.csr
