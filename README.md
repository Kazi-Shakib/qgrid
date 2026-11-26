# QKD key delivery into DNP3 Secure Authentication: attacks, RB2K, and detection

Code for the paper *Securing QKD-Based DNP3 Communications: Gateway Attacks and
Compromise-Resistant Key Delivery* (K. H. Shakib and A. Munir).

When one substation gateway retrieves QKD keys for several DNP3 outstations, nothing in ETSI GS QKD
014 or DNP3 SAv5 checks which outstation receives a given key. This repository contains:

- **`testbed/`**: a C testbed that runs the whole chain in software. It covers decoy-state BB84 post-processing, ETSI 014 key managers, trusted-node relays, gateways, DNP3 SAv5 endpoints, an attacker-controlled WAN, and an IEEE 33-bus feeder model. It also implements the attacks, the RB2K defense (two recipient-bound gateway shares, erased on delivery), and three attack detectors.
- **`proverif/`**: ProVerif models of every delivery architecture under each compromise scenario.

## What is executed and what is simulated

| Executed in software | Simulated or emulated |
|---|---|
| BB84 sifting, finite-key parameter estimation (Lim et al. 2014), Cascade, verification, Toeplitz privacy amplification, Wegman–Carter authentication | Optical channel and detectors (loss, efficiency mismatch, dead time, afterpulsing) |
| ETSI GS QKD 014 `enc_keys` / `dec_keys` over mutual TLS 1.3; hop-by-hop trusted-node relay | Feeder behavior (precomputed pandapower power flows, IEEE 33-bus) |
| DNP3 link/transport/application layers; SAv5 update-key change, session-key change, challenge–response (g120 objects) | WAN delay, jitter, and loss (delay line in the proxy) |
| Attacks T1–T3, gateway and relay compromise, detectors D1–D3 | Feeder-head meter readings for D3 |

All components are threads that communicate over loopback TCP. Nothing here drives real QKD hardware or grid equipment.

## Layout

```
testbed/
  qkdsw.c        BB84 stack (simulated optics + executed post-processing), one instance per link
  keynet.c       key stores, KME_A/KME_B (ETSI 014 over TLS), trusted-node relays
  dnp3.c net.c   DNP3 framing (link CRCs, transport segmentation, application objects), TLS/HTTP helpers
  entities.c     master, outstations, gateways, attacker proxy + WAN emulation, feeder model,
                 ground-truth judge, detectors D1-D3
  main.c         experiment driver (run=qkd | security | supply | bench)
  crypto.c       HMAC, AES key wrap, Wegman-Carter tags, DNP3 CRC
  grid/          gen_grid.py, gen_meter.py (pandapower) and the generated CSVs
  run_*.sh       experiment scripts; analyze_e6.py (detection analysis)
proverif/
  gen.py         generates the 47 models; run.sh runs them and writes summary.txt
```

## Requirements

- Linux, `gcc`, `make`, OpenSSL 3 development headers (`libssl-dev`)
- Python 3 (analysis scripts)
- Only to regenerate the feeder CSVs: `pip install pandapower numpy`. The CSVs are included.
- For the formal models: ProVerif ≥ 2.04 (`opam install proverif`)

## Build and quick test

```bash
cd testbed
make
./qgrid run=security n=20 npath=2 bind=1 meta=1     # RB2K, honest sessions
./qgrid run=security n=20 npath=1 bind=0 meta=0 mode=2   # unbound gateway, key theft (T2)
```

Test certificates (a local CA and one certificate per entity) are generated on first run by `mkcerts.sh`. Each run prints one JSON line with the judge's counts, latencies, and traffic.

## Reproducing the experiments

| Script | Experiment | Time (4 vCPUs) |
|---|---|---|
| `run_e0.sh` | E0: BB84 stack, modeled vs ideal detectors, 10–100 km | ~10 min |
| `run_abl.sh` | Detector ablation at 50 km | ~5 min |
| `run_exp.sh` | E1 attacks, E2 architectures and relay compromise, E3 LAN/WAN performance, E5 feeder impact | ~45 min |
| `run_e4.sh` | E4: key supply, direct 100 km vs 50+50 km relay (simulated clock) | ~70 min |
| `run_e6.sh` | E6: detection (D1 release audit, D2 delivery receipts, D3 feeder-head cross-check) | ~15 min |

Results are written to `testbed/results/*.jsonl`, one JSON line per run or per QKD block. `sysinfo.sh` records the host.

Main parameters (`key=value` on the command line):

| Parameter | Meaning |
|---|---|
| `npath=1\|2` | one gateway or two (RB2K) |
| `bind`, `erase`, `meta` | recipient binding, erase on delivery, recipient metadata (0 none, 1 from the key manager, 2 network announcement) |
| `sae=1` | each outstation is its own SAE |
| `mode` | 0 none, 1 redirect (T1), 2 theft (T2), 3 substitution (T3), 4 compromise scenarios |
| `g1`, `g2` | gateway compromise windows: 1 throughout, 2 before delivery then released, 3 after delivery |
| `fa=1` | forged recipient announcements |
| `topo`, `L1`, `L2`, `route2`, `tn` | direct link / one relay / two disjoint relays, fiber lengths, routing, compromised relays |
| `qm=2` | keys from the BB84 stack (otherwise an emulator) |
| `det`, `ap`, `dead`, `eta1` | detector model |
| `wan`, `jit`, `loss` | WAN one-way delay (ms), jitter (ms), segment loss |
| `its=1`, `mpe` | one-time-tag mode and tags per update key |
| `passive=1` | the attacker copies keys but never uses them |
| `resid=FILE`, `meter`, `mseed` | D3 residual log, meter error, meter seed |

## Formal analysis (ProVerif)

```bash
cd proverif
./run.sh          # regenerates models/ with gen.py, runs ProVerif, writes summary.txt and out/
```

`proverif/README.md` describes the queries and the expected verdicts. The models are symbolic abstractions:
- the XOR of shares is an opaque two-input combiner;
- time is represented by two phases;
- erasure is a choice, made per share, between release (with deletion) and retention.

The included `summary.txt` was produced with ProVerif 2.00. Rerun with your installed version and keep the outputs.

## Scope and limitations

- Optical detection is modeled; finite-key bounds are applied to simulated statistics with correlated afterpulses. The key lengths are not a composable security proof for that detector model.
- The last hop uses TLS, and SAv5 mode uses HMAC and AES key wrap, so end-to-end secrecy in the testbed is computational.
- Feeder results come from precomputed power flows, not a co-simulation with protection devices.
- Only the DNP3 objects and SAv5 exchanges used in the experiments are implemented.
- Certificates in `testbed/certs/` are throwaway test credentials. Do not use them anywhere else.

## Citation

```bibtex
@inproceedings{shakib-rb2k,
  author = {Kazi Hassan Shakib, Muhammad Asfand Hafeez and Arslan Munir},
  title  = {Securing {QKD}-Based {DNP3} Communications: Gateway Attacks and Compromise-Resistant Key Delivery},
  note   = {Under review}
}
```
