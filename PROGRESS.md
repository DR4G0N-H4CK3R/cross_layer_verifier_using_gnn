# Progress map for the mid review (week 12)

Design doc: *Cross-Layer Verification of an Untrusted IoT Gateway*, v3-revised.
Legend: ✅ implemented and tested · 🟡 implemented, needs hardware data · ⬜ not started

| Doc § | Element | Code | Status | Notes |
|---|---|---|---|---|
| §2.1 | Seven-row attack taxonomy (hide, invent, swap, change, delay, leak, forge) | `testbed/translator.py` `AttackSpec` | ✅ | Each row at configurable rate/fraction; per-event `TruthEvent` ground truth; forge uses the hub's RSSI signature at the witness |
| §2.2 | Star topology, pinned channel, static placement | `testbed/devices.py`, `capture/loss.py` | ✅ | ACK attribution by turnaround timing assumes the star |
| §7 | Dual capture | `capture/radio.py`, `capture/ip.py`, `datasets/ziotp.py` | ✅ (real data) | Parsers validated on ZIOTP2025: 252,896 real 802.15.4 frames (CC2531), cleartext NWK originator, 12 real hub IP captures paired in time. nRF TAP format supported, awaits our own capture |
| §7 | Windowing on one clock | `pipeline/windowing.py` | ✅ | T configurable (5/10/20 s evaluated) |
| §7, §8 | Envelope features, no payload | `pipeline/features.py` | ✅ | Radio: counts, bytes, seq gaps, retx, ACKs, RSSI/LQI stats. IP: per-endpoint record counts/bytes/sizes |
| §8 | Cross-layer graph, gateway as bridge | `pipeline/graph.py` | ✅ | Device / gateway / endpoint (+ "unknown") nodes, 4 relations, radio-side inputs, IP-side targets |
| §8 | Segmenting inside long-lived TLS sessions | `capture/ip.py` `_Stream` | ✅ | Walks the TLS record layer per flow direction |
| §9 | Conservation, provenance, translation, emitter consistency | `invariants/checks.py` | ✅ | Bands learned from commissioning; rolling horizon; floors from measured loss. Emitter consistency has an RSSI form (simulator / own witness) and a link-layer form — sequence-counter discontinuity, duplicate ACKs — validated on real traffic (forge 0.56 episodes on ZIOTP, no added benign alerts) |
| §9.1 | Worked example rows | `tests/test_invariants.py` | ✅ | Each row is a unit test |
| §7 | Learned model: R-GCN translation residual | `model/rgcn_numpy.py`, `model/residual.py` | ✅ | Manual backprop gradient-checked (rel. err 2e-6); PyTorch/PyG backend in `model/rgcn_torch.py` (optional, untested in sandbox) |
| §7 | k-of-n persistence | `decision/persistence.py` | ✅ | Over *evaluable* windows; clears when evidence is absent |
| §7 | Attribution (device, window, invariant) | `decision/attribution.py` | ✅ | Signature classes when devices are IP-indistinguishable; swap → "misattribution (A reported as B)" |
| §7.1 | Alert schema and sinks | `schema.py` `Alert`, `alerting/store.py` | ✅ | SQLite, JSONL, MQTT (paho optional), evidence dir with size cap + eviction; degraded verdicts are written |
| §7.1 | Dashboard | `verifier/dashboard.py`, `web/index.html` | ✅ | FastAPI or stdlib server |
| §10 | Seq-gap counting | `capture/loss.py` | ✅ (real data) | On the MAC counter per transmitter — real stacks' NWK counters skip values (measured). Completeness 0.88–0.89 on ZIOTP; loss concentrates on routers far from the sniffer |
| §10 | ACK cross-check (orphan ACKs) | `capture/loss.py` | ✅ (real data) | 96–98 % of real uplinks confirmed by a captured coordinator ACK; 3,544 orphan ACKs recovered |
| §10 | Tolerance bands + persistence | `invariants/checks.py` | ✅ | |
| §10 | Fail-safe under jamming | `invariants/checks.py` | ✅ | completeness < 0.70 or retx rate > 40 % ⇒ "degraded — cannot verify" |
| §10 | Signature bands from measured variance | `pipeline/features.py` `learn_signatures` | ✅ | Robust (median/MAD) with variance floors |
| §10, §12 | Detection floor | `eval/detection_floor.py`, `scripts/run_detection_floor.py` | ✅ (simulated) | f × C × T sweep; figure in `results/` |
| §11 | Adversarial dataset with a lying gateway | `testbed/inject.py`, `testbed/generate.py` | ✅ (trace-driven + simulated) | Six attack classes injected on *real* paired ZIOTP captures with exact labels; forge only on the simulator (needs RSSI) |
| §11 | ZIOTP2025 benign baseline | `datasets/ziotp.py`, `scripts/ziotp_experiments.py` R1/R2 | ✅ | Real radio baseline (15 h) and real paired radio+IP baseline (43 min held-out) |
| §12 | Baselines (a)–(d) | `eval/baselines.py`, `scripts/run_ablations.py` | ✅ | Ablations are configurations of one pipeline |
| §12 | Metrics | `eval/metrics.py` | ✅ | Window TPR/FPR, episode detection, latency, false alerts/day, attribution accuracy, degraded fraction |
| §12 | Systems metrics on the Pi (CPU/mem/power) | — | ⬜ | Needs hardware |
| §13 | Cross-deployment transfer study | `scripts/ziotp_experiments.py` R4 | ✅ (preliminary) | Per-class conservation ratio within ~10 % across topologies A/B while relay structure differs completely; fingerprints known to collapse |
| §16 | Reproducibility | `Dockerfile`, `dataset.py` manifests, `tests/` | 🟡 | MLflow tracking not wired |

## What the real data changed (week 12)

- **Mesh, not star.** ZIOTP's networks relay: in topology A every battery sensor reaches the hub via
  a router. The Zigbee NWK header is cleartext, so the originating device is still identifiable and
  per-device accounting works; §2.2's star assumption becomes "the last hop into the coordinator".
- **Loss counting moved to the MAC counter.** Real stacks skip NWK sequence values (coordinator:
  every other value; Philips: two interleaved counters). Measured, then fixed.
- **The IP side of a real hub is not the simulator's.** On Home Assistant's websocket every device's
  push is ~40 ± 20 B (compressed); lengths carry no identity, pushes are batched (Δt = 1 s), pings and
  request/response pairs must be recognised. Conservation (as a ratio) and provenance survive;
  translation-by-length does not on this channel. The testbed must capture the MQTT/cloud telemetry
  path the design specifies.
- **Emitter consistency got a link-layer form.** No reachable public 802.15.4 corpus has RSSI/LQI,
  so the physical-layer form stays simulator-only; but a spoofed frame also breaks the device's MAC
  sequence counter and a spoofed ACK doubles up — both visible in metadata, both learned as
  per-device bands, and validated on ZIOTP (56 % of forgery episodes, no added false alerts). An
  attacker that sniffs the counter evades this form; the RSSI form is still the first thing to
  measure with our own witness.
- **Real attack captures are radio-only.** The CMU Zigator dataset (jamming, spoofing, PAN-ID
  conflict, ACK spoofing) and ZBDS2023 exist but need accounts / were unreachable here;
  `scripts/radio_attack_eval.py` is ready for them. No dataset has a lying hub — the testbed does.

## Design decisions made during implementation (to raise at the review)

1. **Rolling evidence horizon (120 s) on top of 5 s windows.** Battery devices report once a
   minute or two; a single window rarely holds enough of their traffic to check anything. The
   window remains the unit of decision and ground truth; the evidence behind each decision spans the
   horizon. This is also what turns "random loss scatters both ways, suppression is sustained" (§10)
   into a computable statistic.
2. **Signature-first attribution, provenance as the check.** Attributing records by "which device
   spoke last" would explain away misattribution. Records are credited by maximum likelihood over
   the translation signature and a miss-probability prior from measured completeness; provenance
   then either confirms or becomes the violation.
3. **Signature classes.** Two identical door contacts produce identical TLS records; the IP side
   cannot separate them. Unprovenanced records are pinned to the class, and alerts name the class.
   The radio side still separates them (conservation deficits are per device).
4. **Persistence counts evaluable windows, not wall-clock windows**, and clears when evidence is
   absent — an alert cannot stay "open" on silence.
5. **Warm-up.** Nothing is evaluated until the horizon is full; the alternative is "all clear" with no
   evidence, which §10 forbids.

## Known gaps / next steps (weeks 13–16)

- Attach the nRF52840 and Home Assistant testbed; capture the IP side on the hub (MQTT/cloud path);
  commission for hours; run `scripts/verify_capture.py`.
- Download ZigBeeNet (Zenodo) for a first real RSSI/LQI look at emitter consistency.
- Extend R4 to the 6 h of idle radio captures (radio-side invariants only).
- The R-GCN residual is a secondary signal: it adds recall on delay/invent but raises the benign
  false-alert rate (see `results/RESULTS.md`); calibration on real data decides whether it stays
  in the default configuration.
- Ingest ZIOTP2025 (radio side) for the §13 transfer study.
- Pi systems metrics; MLflow.
