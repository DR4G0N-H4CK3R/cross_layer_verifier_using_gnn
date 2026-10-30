"""Cross-Layer Gateway Verifier — simulated-testbed entry point.

    python simulator_main.py --scenario mixed            # commission, replay, dashboard
    python simulator_main.py --scenario forge --no-dashboard --realtime 0
    python simulator_main.py --scenario hide --rules-only

The radio and IP inputs come from the controlled translator in
gwverify.testbed (the nRF52840 witness is not attached yet); everything
downstream — loss accounting, signatures, the four invariants, the R-GCN
residual, persistence, attribution, the alert store, the evidence directory
and the dashboard — is the code that will run on the verification host.
Synthetic results are labelled as such in the dashboard and in every
manifest.
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path

import pandas as pd

from gwverify.dataset import save_run
from gwverify.model.residual import ResidualConfig
from gwverify.testbed.devices import default_manifest
from gwverify.testbed.generate import scenario_suite, simulate
from gwverify.verifier import Verifier, VerifierConfig
from verifier.dashboard import start_dashboard
from verifier.replay import replay

ROOT = Path(__file__).resolve().parent
STATE = ROOT / "state"
DATA = ROOT / "sample_data"
SCENARIOS = list(scenario_suite(1.0).keys())


def main() -> None:
    ap = argparse.ArgumentParser(description="Cross-Layer Gateway Verifier — simulated testbed")
    ap.add_argument("--scenario", choices=SCENARIOS, default="mixed")
    ap.add_argument("--duration", type=float, default=7200, help="seconds of attack run")
    ap.add_argument("--benign", type=float, default=10800, help="seconds of commissioning run")
    ap.add_argument("--completeness", type=float, default=0.95, help="witness capture completeness C")
    ap.add_argument("--T", type=float, default=5.0, help="window length, seconds")
    ap.add_argument("--horizon", type=float, default=120.0, help="rolling evidence horizon, seconds")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--rules-only", action="store_true", help="skip the R-GCN residual")
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--realtime", type=float, default=0.15, help="seconds per replayed window (0 = instant)")
    ap.add_argument("--no-dashboard", action="store_true")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--reuse-model", action="store_true", help="load state/model instead of re-commissioning")
    args = ap.parse_args()

    STATE.mkdir(exist_ok=True)
    labels = {d.short_addr: d.label for d in default_manifest()}
    cfg = VerifierConfig(T=args.T, horizon_s=args.horizon, use_model=not args.rules_only,
                         model=ResidualConfig(epochs=args.epochs))

    print("[*] SIMULATED TESTBED — the nRF52840 witness is not attached; inputs are synthetic.")
    print(f"[*] scenario={args.scenario} T={args.T}s horizon={args.horizon}s C={args.completeness} "
          f"model={'off' if args.rules_only else 'R-GCN residual'}")

    if args.reuse_model and (STATE / "model" / "signatures.json").exists():
        v = Verifier.load(STATE / "model", labels)
        print("[*] loaded commissioning state from state/model")
    else:
        t0 = time.time()
        ben = simulate(args.benign, [], seed=args.seed, completeness=args.completeness)
        save_run(DATA / "benign", ben.frames, ben.records, ben.truth, ben.meta)
        v = Verifier(cfg, labels).commission(ben.frames, ben.records, ben.duration)
        v.save(STATE / "model")
        print(f"[+] commissioned on {args.benign / 3600:.1f} h benign: {len(ben.frames)} frames, "
              f"{len(ben.records)} records, measured completeness {v.sigs.completeness:.3f} "
              f"({time.time() - t0:.0f}s)")
        for addr, s in v.sigs.devices.items():
            print(f"    {s.label:20s} {s.endpoint:24s} len {s.len_mu:6.1f}±{s.len_sigma:4.1f}B "
                  f"delay {s.delay_mu * 1000:5.1f}±{s.delay_sigma * 1000:4.1f}ms "
                  f"rssi {s.rssi_mu:6.1f}±{s.rssi_sigma:.2f}dBm")

    attacks = scenario_suite(args.duration)[args.scenario]
    jam = [(args.duration * 0.8, args.duration * 0.8 + 240)] if args.scenario == "mixed" else []
    res = simulate(args.duration, attacks, seed=args.seed + 1, completeness=args.completeness, jam=jam)
    save_run(DATA / args.scenario, res.frames, res.records, res.truth, res.meta)
    truth = pd.DataFrame([vars(e) for e in res.truth], columns=["ts", "kind", "device", "detail"])
    print(f"[+] attack run: {len(res.frames)} frames, {len(res.records)} records, "
          f"{len(res.truth)} labelled misbehaviours -> sample_data/{args.scenario}/")

    if not args.no_dashboard:
        threading.Thread(target=start_dashboard, args=("127.0.0.1", args.port), daemon=True).start()
        print(f"[*] dashboard: http://127.0.0.1:{args.port}/")

    def show(row):
        if row["status"] in ("ANOMALY_CONFIRMED", "DEGRADED_CANNOT_VERIFY") or row["new_alerts"]:
            al = ", ".join(f"{a['device']}/{a['invariant']}" for a in row["alerting"]) or row["degraded_reason"]
            print(f"window {row['index']:5d} t={row['start']:7.0f}s {row['status']:24s} "
                  f"C={row['completeness']:.2f} truth={','.join(row['ground_truth']) or '-':10s} {al}")

    result = replay(v, res.frames, res.records, res.duration, STATE, truth, realtime=args.realtime,
                    on_window=show)
    n_alert = sum(1 for a in result.alerts if a.verdict == "alert")
    print(f"\n[+] done: {len(result.windows)} windows, {n_alert} confirmed alerts, "
          f"{sum(1 for a in result.alerts if a.verdict == 'degraded')} degraded windows")
    print("[+] alerts   : state/alerts.db, state/alerts.jsonl   evidence: state/evidence/<alert_id>/")
    print("[+] model    : state/model/{signatures,bands}.json, residual_model.npz")
    if not args.no_dashboard:
        print("[*] dashboard stays up; Ctrl-C to exit")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
