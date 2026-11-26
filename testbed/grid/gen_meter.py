"""Feeder-head active power for the physical cross-check (detector D3).
Reproduces the true per-bus loads of gen_grid.py (same seed and draw order) and computes, for every
minute, the substation (external-grid) active power with all breakers closed and with each lateral
open. The operator's expected value uses a load forecast that lacks the per-bus noise and carries a
slowly varying common-mode forecast error (AR(1), 3% s.d., 0.995 per-minute correlation).
Output headp.csv: minute, true_closed, true_A, true_B, true_C, fc_closed, fc_A, fc_B, fc_C (kW)."""
import numpy as np, pandapower as pp, pandapower.networks as pn, csv

OUT = {"A": 24, "B": 21, "C": 17}
net = pn.case33bw(); p0, q0 = net.load.p_mw.copy(), net.load.q_mvar.copy()
minutes = np.arange(1440)
shape = (0.55 + 0.25 * np.exp(-((minutes - 8.5 * 60) / 120) ** 2) + 0.45 * np.exp(-((minutes - 19 * 60) / 150) ** 2))
shape = shape / shape.max()
rng = np.random.default_rng(7)                       # identical to gen_grid.py
noise = [1 + 0.02 * rng.standard_normal(len(p0)) for _ in minutes]
frng = np.random.default_rng(11); c = np.zeros(1440); rho, sd = 0.995, 0.03
c[0] = sd * frng.standard_normal()
for m in range(1, 1440): c[m] = rho * c[m - 1] + sd * np.sqrt(1 - rho * rho) * frng.standard_normal()

def head(scale):
    net.load.p_mw = p0 * scale; net.load.q_mvar = q0 * scale
    res = []
    for k in [None, "A", "B", "C"]:
        net.line.loc[list(OUT.values()), "in_service"] = True
        if k: net.line.loc[OUT[k], "in_service"] = False
        pp.runpp(net); res.append(round(net.res_ext_grid.p_mw.sum() * 1000, 2))
    return res

with open("headp.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["minute", "true_closed", "true_A", "true_B", "true_C", "fc_closed", "fc_A", "fc_B", "fc_C"])
    for m in minutes:
        w.writerow([m] + head(shape[m] * noise[m]) + head(shape[m] * (1 + c[m])))
print("ok")
