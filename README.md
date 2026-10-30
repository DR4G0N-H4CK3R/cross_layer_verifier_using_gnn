# Cross-Layer Gateway Verifier

**Detecting a compromised smart-home hub with an independent radio witness.**
Bhaskar S L · Arjun S · Guide: Dr. Kurunandan Jain · Amrita Vishwa Vidyapeetham, Amritapuri

The gateway (Zigbee/Thread hub) is the only thing that sees both the 802.15.4 radio and the IP
uplink, and everything downstream believes whatever it reports. This project treats the hub as an
**untrusted translator** and checks its northbound reporting against a passive 802.15.4 witness
it does not control, using four closed-form invariants (conservation, provenance, translation,
emitter consistency) plus a learned translation residual (R-GCN), with k-of-n persistence, a
measured detection floor, and a fixed alert schema.

> **Status (week 12, mid review):** the full verification engine is implemented and evaluated on
> (a) **real captures** — ZIOTP2025: 15 h of 802.15.4 traffic from 21 commercial Zigbee devices behind
> a Home Assistant hub, including 12 captures paired with the hub's IP side, with misbehaviour injected
> on top of the real traffic (`results/ziotp/RESULTS_ZIOTP.md`), and (b) a simulated testbed with a
> controlled malicious translator for the attack class the public data cannot express (radio forgery
> needs RSSI, which ZIOTP does not record) and for the detection-floor sweep (`results/RESULTS.md`).
> The nRF52840 witness is not attached yet. See `PROGRESS.md` for the design-doc → code map.

## Layout

```
gwverify/                   the engine (pure Python, NumPy/pandas; no PyTorch needed on the Pi)
  schema.py                 RadioFrame / IPRecord / Window / Alert (§7.1 fixed schema)
  capture/radio.py          802.15.4 pcap/pcapng: nRF TAP (DLT 283), CC2531 (DLT 195, FCS or CC24xx
                            trailer auto-detected), cleartext Zigbee NWK header (originator), tshark CSV
  capture/ip.py             IP pcap/pcapng (Ethernet or Linux cooked): hub flows → TLS records (+SNI)
                            or per-segment records; tshark CSV
  capture/loss.py           MAC seq-gap counting per transmitter, retransmissions, relay de-duplication
                            by NWK originator, ACK cross-check (orphan ACKs), completeness (§10)
  datasets/ziotp.py         ZIOTP2025 adapter: catalog, device maps (A/B), radio↔IP pairing, hub-flow labels
  testbed/                  device manifest, honest+malicious translator, witness model, dataset builder (§11–12)
  testbed/inject.py         trace-driven attack injection on real paired captures (exact ground truth)
  pipeline/windowing.py     identical T-second windows on one clock, per-window ground truth
  pipeline/features.py      envelope features, commissioning signatures, ML record attribution (§8)
  pipeline/rolling.py       rolling evidence horizon (sparse battery devices become checkable)
  pipeline/graph.py         cross-layer heterogeneous graph tensors, radio-in / IP-out (§8)
  invariants/checks.py      the four invariants with learned tolerance bands (§9, §10)
  model/rgcn_numpy.py       2-layer R-GCN, batched dense, manual backprop, gradient-checked
  model/rgcn_torch.py       same model on PyTorch (+ PyG variant) — optional backend
  model/residual.py         translation-residual detector: train on benign, score, attribute
  decision/persistence.py   k-of-n over evaluable windows; degraded = "cannot verify" (§7, §10)
  decision/attribution.py   device + window + invariant + observed/expected → Alert (§7.1)
  alerting/store.py         SQLite record of truth, JSON lines, MQTT (optional), capped evidence dir
  eval/metrics.py           §12 metrics: TPR/FPR, episode detection, latency, false alerts/day, attribution
  eval/baselines.py         (a) IP-only IDS, (b) rules-only, (c) radio-ablated, (d) emitter-ablated
  eval/detection_floor.py   detection vs suppression fraction f for several C and T (headline figure)
  verifier.py               commission() / process() / save() / load()
verifier/                   application layer: window replay loop, local dashboard (FastAPI or stdlib)
web/index.html              dashboard page
simulator_main.py           entry point (commission → replay scenario → dashboard)
scripts/                    ziotp_experiments.py (real data R1–R4), verify_capture.py (own pcaps),
                            run_ablations.py, run_detection_floor.py, build_dataset.py
tests/                      pytest suite (17 tests: loss accounting, R-GCN gradient check, invariants,
                            end-to-end, and parsers/coupling checked against ZIOTP2025 ground truth)
configs/                    default.yaml, devices.example.json
results/                    generated tables and figures (see results/RESULTS.md)
```

## Real data: ZIOTP2025

```bash
git clone https://github.com/antonio-boiano/ZIOTP2025 /data/ZIOTP2025      # 114 MB, Apache-2.0
python scripts/ziotp_experiments.py --root /data/ZIOTP2025 --out results/ziotp   # ~4 min
ZIOTP_ROOT=/data/ZIOTP2025 python -m pytest tests/test_ziotp.py
```

R1 measures the witness on all 91 captures (completeness, ACK confirmation, relaying); R2
commissions on real paired radio+IP captures and verifies held-out ones (3-fold); R3 injects the
§2.1 attacks — including spoofed frames — on the held-out real pairs; R4 is the cross-topology
transfer study of §13. Results and their caveats are in `results/ziotp/RESULTS_ZIOTP.md`.

**Real attack captures.** No public corpus has a misreporting hub (that is this project's dataset
contribution), but real radio-side attacks exist: the CMU Zigator dataset (CRAWDAD
`cmu/zigbee-smarthome` on IEEE DataPort, free account — jamming, spoofing, PAN-ID conflict,
MAC-ACK spoofing) and ZBDS2023 (data.gouv.fr, multi-sniffer with RSSI). Put the pcaps under
`<root>/benign/` and `<root>/attack/`, copy the attack intervals from the dataset README into
`<root>/labels.csv` (`file,t_start,t_end,kind[,device]`), then:

```bash
python scripts/radio_attack_eval.py --root /data/zigator --out results/zigator
```

This runs the radio-side checks only (jamming → *degraded*; spoofed frames/ACKs → emitter
consistency, RSSI form if the capture has it, link-layer form otherwise). ZigBeeNet (Zenodo
10.5281/zenodo.13957306, CC2531 with RSSI/LQI) loads through the same reader; trailer format is
auto-detected.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# REAL captures (clone ZIOTP2025 first, see above): commission on four paired captures of a
# topology, replay the other two through the dashboard; optionally inject misbehaviour on them
python real_main.py --root ../ZIOTP2025 --topology A                    # benign replay
python real_main.py --root ../ZIOTP2025 --topology A --scenario mixed   # hide → invent → leak injected
#   http://127.0.0.1:8000/        scenarios: benign hide invent swap change delay leak mixed

# SIMULATED testbed: commission on 3 h of synthetic benign traffic, replay the "mixed" attack run
python simulator_main.py --scenario mixed

# other scenarios: benign hide invent swap change delay leak forge mixed
python simulator_main.py --scenario forge --rules-only --realtime 0 --no-dashboard

# evaluation
python scripts/run_ablations.py --out results/ablations           # 5 systems × 9 scenarios
python scripts/run_detection_floor.py --out results/detection_floor
python -m pytest -q tests
```

`real_main.py` is real on both sides (CC2531 radio capture + tcpdump of the same Home Assistant
hub); `simulator_main.py` is synthetic on both sides and exists for the forgery case (needs RSSI)
and the detection-floor sweep. The dashboard banner states which one is running.

Outputs land in `state/`: `alerts.db` and `alerts.jsonl` (one record per confirmed finding, §7.1
schema), `evidence/<alert_id>/` (frames and records of the offending window ± 10 s), `model/`
(signatures, bands, residual model — the commissioning state), `latest.json` / `history.jsonl`
(dashboard feed). Generated captures land in `sample_data/<scenario>/` with a versioned manifest.

## Five-minute demo for the review

1. `python real_main.py --root ../ZIOTP2025 --topology A --scenario mixed` — real captures:
   the commissioning table shows the signatures learned from 13 min of real hub traffic, then the
   dashboard replays two real captures with suppression → fabrication → exfiltration injected on
   them; the real witness's loss shows up as *degraded — cannot verify* windows and a real
   retransmission burst as the jamming indicator.
1b. `python simulator_main.py --scenario forge` — the one case the public data cannot show:
   forged radio frames caught by emitter consistency while conservation and provenance pass.
2. `sqlite3 state/alerts.db 'select window_index, device_label, invariant, direction, interpretation, observed, expected from alerts limit 10'`
   — the §7.1 record, with the observed value and the learned band it fell outside.
3. `ls state/evidence/<alert_id>/` — the retained frames and records for the offending window.
4. `results/RESULTS.md` — baselines (a)–(d) and the detection-floor figure.

## Running the verifier on a pair of capture files

`scripts/verify_capture.py` takes one 802.15.4 capture and one IP capture, commissions on a benign
pair, then verifies another pair against that state. A runnable example on the public ZIOTP2025
captures (a real Home Assistant hub; clone the dataset first, see above):

```bash
# commission on a benign pair
python scripts/verify_capture.py commission \
    --radio ../ZIOTP2025/Data/Web_Interaction/Topology_A/AppInteraction4.pcapng \
    --ip    ../ZIOTP2025/Data/Extra/IP-Traffic/Topology_A/tcpdumpWebAppInteraction1.pcapng \
    --gateway-ip 192.168.8.116 --ziotp A --server-ports 8123 --horizon 60 --min-events 4 \
    --rules-only --state state/model

# verify a later pair against it
python scripts/verify_capture.py verify \
    --radio ../ZIOTP2025/Data/Web_Interaction/Topology_A/AppInteraction5.pcapng \
    --ip    ../ZIOTP2025/Data/Extra/IP-Traffic/Topology_A/tcpdumpWebAppInteraction2.pcapng \
    --gateway-ip 192.168.8.116 --ziotp A --server-ports 8123 --state state/model --out state
```

The verify step prints every confirmed alert with the device (or signature class), invariant,
direction, observed value and learned band, and writes `state/alerts.db`, `state/alerts.jsonl` and
`state/evidence/`. Commissioning on a single 2-minute capture is far too short — expect a handful of
benign alerts, for the reasons in `results/ziotp/RESULTS_ZIOTP.md` §2; the point of the example is
that the pipeline runs on real hub captures end to end.

When your own nRF52840 + Home Assistant testbed exists, the same two commands apply with your
files: `--radio` your sniffer pcap (nRF TAP format has RSSI/LQI, so emitter consistency becomes
active), `--ip` a pcap of the hub's uplink, `--gateway-ip` the hub's address, `--manifest
configs/devices.json` (short address → label; `configs/devices.example.json` shows the format) and
`--server-ports` for any port on which the hub is a server. Options: `--T`, `--horizon`, `--min-events`,
`--rules-only`, `--save-run DIR` (export the parsed frames/records as CSV with a manifest).

## How a decision is made

1. **Windows and horizon.** Both streams are cut into T = 5 s windows on the host clock. Each
   decision uses the last 120 s of evidence (rolling horizon), so a sensor that reports once a
   minute still gets checked, and one missed frame is one count in two minutes of consistent traffic.
2. **Loss accounting.** Sequence gaps and orphan ACKs (an ACK we heard for a frame we missed) give a
   measured capture completeness C per horizon. Below 0.70 the window is *degraded — cannot verify*.
3. **Attribution.** Each outgoing TLS record is credited to a device by maximum likelihood over its
   translation signature (endpoint, length, delay) and whether that device had radio activity within
   Δt = 1 s. Devices whose signatures are indistinguishable form a *signature class*; a record with
   no radio behind it is pinned to the class, not guessed to a member.
4. **Invariants** (bands learned from the commissioning run, widened by measured loss):
   conservation deficit → suppression; surplus / unprovenanced → fabrication or misattribution;
   length/delay drift → tampered translation; RSSI/LQI out of band → forged radio evidence;
   egress to an endpoint never seen at commissioning → exfiltration.
5. **Residual.** An R-GCN over the per-window cross-layer graph predicts the IP-side counts from the
   radio side only; the standardised residual per node is a learned anomaly score.
6. **Persistence and attribution.** A (device, invariant) finding is confirmed when 3 of the last 5
   evaluable windows agree; the alert names the device (or class), window, invariant, direction,
   observed value and learned band, persistence and completeness.

## Honest limits (as in the design doc §14)

Star topology on a pinned channel; static placement (emitter consistency is re-learned after any
commissioning event); benign baseline assumed uncompromised; suppression below the measured floor
is invisible; the system detects and records, it does not block. The two identical door contacts
and the two motion sensors in the manifest are deliberately indistinguishable on the IP side —
alerts on those name the class, which is the truthful answer.

## Requirements

Python ≥ 3.10, numpy, pandas, scipy-free. `scapy` only for reading IP pcaps, `scikit-learn` only
for the IP-only baseline, `matplotlib` only for figures, `fastapi`/`uvicorn` optional for the
dashboard (falls back to the standard library), `paho-mqtt` optional for the MQTT sink, `torch`
optional for the alternative model backend.
