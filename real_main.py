"""Cross-Layer Gateway Verifier — real-capture entry point (ZIOTP2025).

    python real_main.py --root ../ZIOTP2025 --topology A                 # benign replay + dashboard
    python real_main.py --root ../ZIOTP2025 --topology A --scenario mixed   # attacks injected on the real traffic
    python real_main.py --root ../ZIOTP2025 --topology B --scenario hide --realtime 0 --no-dashboard

Both sides are real: the 802.15.4 frames come from the CC2531 sniffer captures
and the IP records from the tcpdumps of the same Home Assistant hub, paired in
wall-clock time.  The verifier commissions on four of the six paired captures
of a topology and replays the other two through the dashboard.  With a
scenario other than `benign`, the hub's misbehaviour is injected on top of the
real streams by gwverify.testbed.inject (exact per-event ground truth).  Only
`forge` touches the radio side: spoofed frames under a device's address from a
transmitter that has not sniffed its counter — without RSSI in this dataset
they are visible only through the link-layer form of emitter consistency.
"""
from __future__ import annotations

import argparse
import threading
import time
from pathlib import Path

import pandas as pd

from gwverify.capture.loss import annotate_frames
from gwverify.datasets import ziotp
from gwverify.invariants.checks import learn_bands
from gwverify.pipeline.features import learn_signatures
from gwverify.pipeline.graph import NodeIndex
from gwverify.testbed.inject import attribute_records, inject
from gwverify.testbed.translator import AttackSpec
from gwverify.verifier import Verifier, VerifierConfig
from verifier.dashboard import start_dashboard
from verifier.replay import replay

ROOT = Path(__file__).resolve().parent
STATE = ROOT / "state"
PUSH = "ha-subscribers:8123"
SCENARIOS = ["benign", "hide", "invent", "swap", "change", "delay", "leak", "forge", "mixed"]


def scenario(name: str, dur: float, active: list) -> list:
    d1, d2 = active[0], (active[1] if len(active) > 1 else active[0])
    a, b = dur / 4, 3 * dur / 4
    table = {
        "benign": [],
        "hide": [AttackSpec("hide", a, b, devices=active[:2], fraction=0.8)],
        "invent": [AttackSpec("invent", a, b, devices=[d1], rate=1 / 15)],
        "swap": [AttackSpec("swap", a, b, devices=[d1], target=d2, fraction=1.0)],
        "change": [AttackSpec("change", a, b, devices=active[:2], fraction=1.0, change_bytes=60)],
        "delay": [AttackSpec("delay", a, b, devices=active[:2], fraction=1.0, delay_s=30)],
        "leak": [AttackSpec("leak", a, b, rate=1 / 20)],
        "forge": [AttackSpec("forge", a, b, devices=active[:2], rate=1 / 10)],
        "mixed": [AttackSpec("hide", dur * 0.15, dur * 0.35, devices=[d1], fraction=0.8),
                  AttackSpec("invent", dur * 0.40, dur * 0.55, devices=[d2], rate=1 / 15),
                  AttackSpec("forge", dur * 0.58, dur * 0.75, devices=[d1], rate=1 / 10),
                  AttackSpec("leak", dur * 0.78, dur * 0.95, rate=1 / 20)],
    }
    return table[name]


def main() -> None:
    ap = argparse.ArgumentParser(description="Cross-Layer Gateway Verifier — real captures (ZIOTP2025)")
    ap.add_argument("--root", required=True, help="path to the cloned ZIOTP2025 repository")
    ap.add_argument("--topology", choices=["A", "B"], default="A")
    ap.add_argument("--scenario", choices=SCENARIOS, default="benign")
    ap.add_argument("--test-pairs", type=int, nargs="*", default=[4, 5],
                    help="indices (0-5) of the paired captures to replay; the rest commission")
    ap.add_argument("--T", type=float, default=5.0)
    ap.add_argument("--horizon", type=float, default=60.0)
    ap.add_argument("--delta-t", type=float, default=1.0, help="provenance window (hub pushes are batched)")
    ap.add_argument("--min-events", type=int, default=4)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--realtime", type=float, default=0.5, help="seconds per replayed window (0 = instant)")
    ap.add_argument("--no-dashboard", action="store_true")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    root = Path(args.root)
    if not (root / "Data").exists():
        raise SystemExit(f"{root} does not contain Data/ — pass the cloned ZIOTP2025 folder as --root")
    STATE.mkdir(exist_ok=True)
    caps = ziotp.paired(root, args.topology)
    train = [c for i, c in enumerate(caps) if i not in args.test_pairs]
    test = [c for i, c in enumerate(caps) if i in args.test_pairs]
    labels = ziotp.labels(args.topology)

    print("[*] REAL CAPTURES — ZIOTP2025 (CC2531 802.15.4 sniffer + tcpdump of the Home Assistant hub)")
    print(f"[*] topology {args.topology}: commission on {[c.name.split('/')[-1] for c in train]}, "
          f"replay {[c.name.split('/')[-1] for c in test]}; scenario={args.scenario}")

    t0 = time.time()
    fr_tr, rc_tr, dur_tr, _ = ziotp.concat(root, train)
    cfg = VerifierConfig(T=args.T, horizon_s=args.horizon, delta_t=args.delta_t, use_model=False)
    v = Verifier(cfg, labels)
    fdf, _ = annotate_frames(fr_tr)
    v.sigs = learn_signatures(fdf, rc_tr, cfg.delta_t, labels, min_events=args.min_events)
    _, feats = v._features(fr_tr, rc_tr, dur_tr)
    v.bands = learn_bands(feats, q=cfg.band_q, completeness_min=cfg.completeness_min)
    v.idx = NodeIndex.from_signatures(v.sigs)
    v.save(STATE / "model")
    n_sig = sum(1 for s in v.sigs.devices.values() if s.n_events > 0)
    print(f"[+] commissioned on {dur_tr / 60:.1f} min of real paired traffic: {len(fr_tr)} frames, "
          f"{len(rc_tr)} hub records, measured completeness {v.sigs.completeness:.3f}, "
          f"signatures for {n_sig}/{len(v.sigs.devices)} devices ({time.time() - t0:.0f}s)")
    for a, s in sorted(v.sigs.devices.items()):
        if s.n_events:
            print(f"    {s.label:22s} {s.endpoint:22s} reports {s.n_events:4d}  len {s.len_mu:5.1f}±{s.len_sigma:4.1f}B  "
                  f"delay {s.delay_mu * 1000:5.0f}±{s.delay_sigma * 1000:4.0f}ms")

    fr_te, rc_te, dur_te, segs = ziotp.concat(root, test)
    truth = None
    if args.scenario != "benign":
        att = attribute_records(fr_te, rc_te, cfg.delta_t, PUSH)
        active = [int(d) for d in pd.Series(list(att.values())).value_counts().index[:4]]
        attacks = scenario(args.scenario, dur_te, active)
        fr_te, rc_te, events = inject(fr_te, rc_te, attacks, cfg.delta_t, PUSH, seed=args.seed)
        truth = pd.DataFrame([vars(e) for e in events], columns=["ts", "kind", "device", "detail"])
        print(f"[+] injected {len(events)} labelled misbehaviours on the real streams "
              f"(targets: {', '.join(labels.get(d, hex(d)) for d in active[:2])})")
    print(f"[+] replaying {dur_te / 60:.1f} min: {len(fr_te)} frames, {len(rc_te)} hub records, "
          f"{int(dur_te / cfg.T)} windows of {cfg.T:.0f} s")

    if not args.no_dashboard:
        threading.Thread(target=start_dashboard, args=("127.0.0.1", args.port), daemon=True).start()
        print(f"[*] dashboard: http://127.0.0.1:{args.port}/")

    def show(row):
        if row["status"] in ("ANOMALY_CONFIRMED", "DEGRADED_CANNOT_VERIFY") or row["new_alerts"]:
            al = ", ".join(f"{a['device']}/{a['invariant']}" for a in row["alerting"]) or row["degraded_reason"]
            print(f"window {row['index']:4d} t={row['start']:6.0f}s {row['status']:24s} C={row['completeness']:.2f} "
                  f"truth={','.join(row['ground_truth']) or '-':8s} {al}")

    src = (f"REAL CAPTURES — ZIOTP2025 topology {args.topology}: CC2531 802.15.4 sniffer + tcpdump of the "
           f"Home Assistant hub; replaying {', '.join(c.name.split('/')[-1] for c in test)}"
           + ("" if args.scenario == "benign" else f"; {args.scenario} misbehaviour injected on the real streams"))
    res = replay(v, fr_te, rc_te, dur_te + 30, STATE, truth, realtime=args.realtime, on_window=show, source=src)
    n_alert = sum(1 for a in res.alerts if a.verdict == "alert")
    n_deg = sum(1 for a in res.alerts if a.verdict == "degraded")
    print(f"\n[+] done: {len(res.windows)} windows, {n_alert} confirmed alerts, {n_deg} degraded windows")
    print("[+] alerts: state/alerts.db, state/alerts.jsonl   evidence: state/evidence/<alert_id>/   model: state/model/")
    if not args.no_dashboard:
        print("[*] dashboard stays up; Ctrl-C to exit")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
