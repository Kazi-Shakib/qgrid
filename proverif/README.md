# ProVerif models of QKD key delivery into DNP3 SAv5 (replace the Tamarin models)

`./run.sh` regenerates `models/*.pv` with `gen.py`, runs ProVerif (>= 2.04) on each, and writes
`summary.txt`: one line per model with the run time and one letter per query
(T = "is true", F = "is false", ? = "cannot be proved"). Full outputs, including attack traces, are in `out/`.

Model names: `<architecture>_<scenario>` and `relay_<architecture>_tn<mask>`.
Architectures: gw1_unbound, gw1_bound (one gateway), p2_nobind, p2_retain, p2_netrcpt (two paths,
one protection removed), rb2k (full design), sae (outstation is its own SAE).
Scenarios (outstation B compromised in all): S0 none, S1 G1 throughout, S2 G1 then G2 before
delivery, S3 G1 throughout + G2 after delivery, S4 forged recipient announcements.
Relays: tn0 none, tn1 T1, tn3 T1 and T2 compromised; `sharedT1` routes both shares via T1.

Queries, in order:
- Q1 `event(BrokenK(k))`: T = update key of every session the master accepted with A stays secret.
- Q2 `event(BrokenSK(k))`: same for the session keys.
- Q3 injective agreement: A accepts context C only once per master session that intended it.
- Q4-Q6 (rb2k S0/S1/S3/S4 only): session-key agreement, telemetry origin, command origin.
- Q7-Q8 (same files): reachability of accepted telemetry and commands; must be F (= executable).

Expected Q1 (matches Table IV of the paper; T = secret):
| model | S0 | S1 | S2 | S3 | S4 |
|---|---|---|---|---|---|
| gw1_unbound | F | F | F | F | F |
| gw1_bound | T | F | F | F | T |
| p2_nobind | F | F | F | F | F |
| p2_retain | T | T | F | F | T |
| p2_netrcpt | T | T | F | T | F |
| rb2k | T | T | F | T | T |
| sae | T | T | T | T | T |
Relays (tn0, tn1, tn3): gw1_bound T F F; sae T F F; rb2k_sharedT1 T F F; rb2k_disjoint T T F.
A "?" on an expected-T query is a ProVerif over-approximation, not an attack; check `out/<model>.txt`.

Modelling choices: phase 0 = protocol run including share delivery, phase 1 = after delivery.
A gateway compromised before delivery outputs every share it holds; one compromised after
delivery outputs, in phase 1, the shares it still holds. Erasure is encoded by an attacker input,
taken before each share is created, that decides whether the share will be released (and deleted)
or still be held at phase 1; this keeps the two outcomes as different names, so ProVerif's
abstraction does not let a delivered share leak afterwards. K = comb(q1, q2) has no inverse,
standing for the XOR of two independent shares.
