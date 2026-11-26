#!/usr/bin/env python3
"""E6 analysis: D3 threshold calibrated on honest feeder-head residuals at minutes the testbed never
uses (m mod 15 != 0), then applied to the testbed's per-session residuals; D1/D2 from the testbed."""
import json, csv, random, collections, math, sys
SD = 0.005; DRAWS = 200
H = [list(map(float, r[1:])) for r in csv.reader(open('grid/headp.csv')) if r[0] != 'minute']
rng = random.Random(2026); cal = []
for m in range(1440):
    if m % 15 == 0: continue
    m1 = (m + 1) % 1440
    for _ in range(DRAWS):
        meas = H[m1][0] * (1 + SD * rng.gauss(0, 1)) - H[m][0] * (1 + SD * rng.gauss(0, 1))
        cal.append(abs(meas - (H[m1][4] - H[m][4])))
cal.sort()
thr = {fp: cal[int(math.ceil((1 - fp) * len(cal))) - 1] for fp in (0.01, 0.001)}
print("D3 calibration: %d honest residuals, sd %.1f kW; threshold %.1f kW (FP 1%%), %.1f kW (FP 0.1%%)"
      % (len(cal), math.sqrt(sum(x * x for x in cal) / len(cal)), thr[0.01], thr[0.001]))

runs = [json.loads(l) for l in open('results/e6.jsonl')]
allres = [json.loads(l) for l in open('results/e6_resid.jsonl')]   # n records per run, in run order
assert len(allres) == sum(r['n'] for r in runs), "residual file does not match the runs"

def name(r):
    if r['mode'] == 0: return 'honest ' + ('SAE' if r['sae'] else 'RB2K-2relay' if r['topo'] == 2 else 'RB2K' if r['npath'] == 2 else 'one gateway')
    if r['mode'] in (1, 2, 3): return ('T1', 'T2', 'T3')[r['mode'] - 1] + (' bound' if r['bind'] else ' unbound')
    sc = {(1, 0): 'S1', (0, 0): 'S0', (2, 2): 'S2', (1, 3): 'S3'}.get((r['g1'], r['g2']), '?')
    if r['fa']: sc = 'S4'
    if r['tn']: sc = 'relay T1'
    arch = 'one gw' if r['npath'] == 1 and not r['topo'] else 'retained' if not r['erase'] else 'net-rcpt' if r['meta'] == 2 else 'RB2K' if r['topo'] != 1 else 'one gw'
    if r['topo'] == 2: arch = 'RB2K disjoint'
    return f"{sc} {arch}"
print("\n%-22s %-7s %4s %6s %6s %6s %6s %6s %8s %8s" % ("case", "use", "n", "key", "trips", "D1", "D2", "D3", "D3|trip", "any"))
out = []; pos = 0
for r in runs:
    rs = allres[pos:pos + r['n']]; pos += r['n']
    assert all(x['mode'] == r['mode'] and x['passive'] == r['passive'] for x in rs)
    t = thr[0.001]
    d3 = sum(abs(x['resid']) > t for x in rs); trips = sum(x['open'] for x in rs)
    d3t = sum(abs(x['resid']) > t for x in rs if x['open'])
    anyd = sum((x['d1'] or x['d2'] or abs(x['resid']) > t) for x in rs)
    key = max(r['attacker_knows_key'], r['victim_accepts_attacker_key'], r['other_accepts_victim_key'])
    row = dict(case=name(r), label=r['label'], passive=r['passive'], n=r['n'], key=key, trips=trips,
               d1=r['d1_sessions'], d2=r['d2_sessions'], d3=d3, d3_trip=d3t, any=anyd,
               d1_ms=r['d1_ms_median'], d2_ms=r['d2_ms_median'], victim=r['victim'],
               min_trip_resid=min([abs(x['resid']) for x in rs if x['open']], default=None),
               fp1=sum(abs(x['resid']) > thr[0.01] for x in rs))
    out.append(row)
    print("%-22s %-7s %4d %6d %6d %6d %6d %6d %8s %8d" % (row['case'], 'passive' if r['passive'] else 'active' if r['mode'] else '-',
          r['n'], key, trips, row['d1'], row['d2'], d3, f"{d3t}/{trips}", anyd))
json.dump(dict(thr=thr, rows=out), open('results/e6_summary.json', 'w'), indent=1)
