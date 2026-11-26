"""Power-system data for the testbed: IEEE 33-bus distribution feeder (Baran & Wu) in pandapower.
Three outstations control the breakers at the heads of three laterals:
  A: line 24 (bus 5 -> 25, lateral 25-32)   B: line 21 (bus 2 -> 22, lateral 22-24)   C: line 17 (bus 1 -> 18, lateral 18-21)
Outputs
  telemetry.csv : minute, then for each outstation the end-of-lateral voltage (kV) with the breaker closed
  impact.csv    : minute, outstation, load shed (kW) and minimum feeder voltage (pu) if that breaker is opened
A residential/commercial 24-h load shape (1-min resolution) scales every load."""
import numpy as np, pandapower as pp, pandapower.networks as pn, csv, math

OUT = {"A": (24, 32), "B": (21, 24), "C": (17, 21)}       # name: (line index, monitored bus)
net = pn.case33bw()
p0, q0 = net.load.p_mw.copy(), net.load.q_mvar.copy()
vn = net.bus.vn_kv.iloc[0]
minutes = np.arange(1440)
shape = (0.55 + 0.25 * np.exp(-((minutes - 8.5 * 60) / 120) ** 2)
         + 0.45 * np.exp(-((minutes - 19 * 60) / 150) ** 2))     # morning and evening peaks
shape = shape / shape.max()
rng = np.random.default_rng(7)
tel = open("telemetry.csv", "w", newline=""); tw = csv.writer(tel); tw.writerow(["minute"] + list(OUT))
imp = open("impact.csv", "w", newline=""); iw = csv.writer(imp); iw.writerow(["minute", "outstation", "shed_kw", "vmin_pu"])
for m in minutes:
    s = shape[m] * (1 + 0.02 * rng.standard_normal(len(p0)))
    net.load.p_mw = p0 * s; net.load.q_mvar = q0 * s
    net.line.loc[[OUT[k][0] for k in OUT], "in_service"] = True
    pp.runpp(net)
    tw.writerow([m] + [round(net.res_bus.vm_pu.iloc[OUT[k][1]] * vn, 4) for k in OUT])
    if m % 15 == 0:                                   # breaker-open impact every 15 min
        base = net.res_load.p_mw.sum()
        for k, (li, _) in OUT.items():
            net.line.loc[li, "in_service"] = False
            pp.runpp(net)
            served = net.res_load.p_mw.fillna(0).sum()
            vmin = net.res_bus.vm_pu.dropna().min()
            iw.writerow([m, k, round((base - served) * 1000, 1), round(vmin, 4)])
            net.line.loc[li, "in_service"] = True
tel.close(); imp.close()
print("ok", vn)
