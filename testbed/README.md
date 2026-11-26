# qgrid — testbed for QKD key delivery into DNP3 Secure Authentication

Build: `make` (gcc, OpenSSL 3 dev headers). Certificates are created on first run (`mkcerts.sh`).
Feeder data: `cd grid && python3 gen_grid.py` (pandapower; the generated CSVs are included).

## Components (threads, TCP on loopback only)
| file | what it does |
|---|---|
| `qkdsw.c` | decoy-state BB84 per link: simulated optics and detectors; executed sifting, finite-key parameter estimation (Lim et al. 2014), Cascade, verification, Toeplitz PA (NTT), WC-authenticated classical channel |
| `keynet.c` | key stores per link, KME_A / KME_B (ETSI GS QKD 014 `enc_keys`/`dec_keys` over mutual TLS 1.3), trusted-node relays (hop-by-hop OTP, one-time WC tag per hop) |
| `dnp3.c`, `net.c` | IEEE 1815 link frames (CRC per block), transport segmentation, application headers, objects g1v2, g12v1, g30v5, g60v1, g120 |
| `entities.c` | master, outstations, gateways G1/G2, attacker WAN proxy with WAN emulation, IEEE 33-bus feeder model, ground-truth judge |
| `main.c` | experiment driver (`run=qkd`, `run=security`, `run=supply`, `run=bench`) |

SAv5 exchange per session: g120v11/v12 (update key change request/reply), g120v13 carrying the QKD key
IDs (key change method 0x80) + g120v15 master confirmation, g120v15 outstation confirmation,
g120v4/v5/v6/v5 (session keys, AES-256 key wrap), class-0 poll challenged by the master (g120v1/v2),
CROB direct operate challenged by the outstation (g120v1/v2). `its=1` replaces session keys by
one-time Wegman-Carter tags carried in the update key.

Detector model (`det=1`, default): efficiencies 25%/22% symmetrized to 22%, 50 ns dead time
(count-rate correction), 2% afterpulsing. `det=0` gives ideal detectors. `ap=`, `dead=`, `eta1=`.

Topologies: `topo=0` direct link (`L1` km); `topo=1` KME_A–T1–KME_B (`L1`, `L2`); `topo=2` two disjoint
relays, G2's shares via T2 (`route2=0` sends both via T1). `tn=` bitmask of compromised trusted nodes.

WAN emulation in the proxy: `wan=` one-way ms, `jit=` ms s.d., `loss=` segment loss (200 ms RTO each).

Other parameters: npath, bind, erase, meta (0 none, 1 authenticated via KME, 2 network announcement),
oid, sae, mpe (tags per update key), mode (0 none, 1 redirect, 2 theft, 3 substitution, 4 compromise
scenarios), g1/g2 (gateway windows: 1 throughout, 2 before delivery then restored, 3 after delivery),
fa (forge announcements), victim/acc, n, qm=2 (keys from the BB84 stack), simclock=1, epoch, epochs, warm.

## Experiments
    ./run_e0.sh     # E0: BB84 stack alone, ideal vs realistic detectors, 10-100 km
    ./run_abl.sh    # detector ablation at 50 km
    ./run_exp.sh    # E1 attacks, E2 architectures + trusted-node compromise, E3 performance (LAN/WAN), E5 feeder impact
    ./run_e4.sh     # E4 key supply: direct 100 km vs relay 50+50 km, simulated clock
    ./sysinfo.sh    # host details
Results go to `results/*.jsonl` (one JSON line per run or per QKD block).

What is simulated: the optical channel and detectors (from a channel model), the feeder (precomputed
pandapower power flows), and the WAN (delay line in the proxy). Everything else is executed.

## Attack detection (E6)
    ./run_e6.sh     # D1 release audit, D2 delivery receipts, D3 feeder-head cross-check; runs analyze_e6.py
D1/D2 are raised by the gateways (or KME_B for SAE outstations) over a trusted audit channel; a
compromised gateway reports nothing (D1) and forges consistent receipts (D2). D3 uses
`grid/headp.csv` (from `grid/gen_meter.py`), meter error `meter=` (default 0.005) and seed `mseed=`;
its threshold is calibrated offline in `analyze_e6.py` on minutes the sessions never use.
`passive=1`: the attacker copies keys but never uses them. Per-session residuals: `resid=<file>`.
