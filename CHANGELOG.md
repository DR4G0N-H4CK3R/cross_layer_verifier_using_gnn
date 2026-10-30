# Changelog

## v0.5 — 2026-09-25

- Emitter consistency, link-layer form: per-device MAC sequence-counter discontinuities and
  duplicate ACKs (`capture/loss.py`, `invariants/checks.py`) — spoofed frames detectable without
  RSSI; `forge` injection now works on captures without RSSI (`testbed/inject.py`), added to the
  ZIOTP suite and to `real_main.py` scenarios.
- `datasets/radio_attacks.py` + `scripts/radio_attack_eval.py`: loader and radio-only evaluation
  for real attack corpora (CMU Zigator / CRAWDAD cmu/zigbee-smarthome, ZBDS2023, own captures) with
  a `labels.csv` of attack intervals.
- `tests/test_loss.py`: spoofed-frame / duplicate-ACK test.

## v0.4.2 — 2026-09-25

- `real_main.py`: dashboard entry point on real captures (ZIOTP2025) — commission on four paired
  captures, replay two, optional trace-driven misbehaviour; dashboard banner now states the data
  source (real vs simulated).

## v0.4.1 — 2026-09-25

- `scripts/verify_capture.py`: runnable worked example on ZIOTP2025 files (`--ziotp A|B` labels,
  `--server-ports`, `--min-events`), clear message on missing input files, alerts printed after
  verify; `configs/devices.json` shipped; scripted runs start from a fresh alert store.
- `capture/ip.py`: `read_ip` reads pcapng and Linux cooked captures; `normalise_server_ports`.

## v0.4 — 2026-09-24 (real data)

### Added
- `gwverify/datasets/ziotp.py`: ZIOTP2025 adapter (catalog, device maps for both topologies,
  radio↔IP pairing by time overlap, hub-flow endpoint normalisation).
- `capture/radio.py`: pcapng input; CC2531 DLT-195 trailer auto-detection (real FCS vs. TI CC24xx
  metadata); CRC verification; cleartext Zigbee NWK header (originator, destination, type, seq).
- `capture/ip.py`: `read_pcapng_hub` — Ethernet or Linux-cooked pcap/pcapng, hub flows only.
- `capture/loss.py`: originator-aware annotation (`dev`, `uplink`, `relay`), relay de-duplication by
  (originator, NWK seq), multi-hop ACK propagation.
- `pipeline/features.py`: request/response recognition, control-frame and discrete background
  lengths, `InboundIndex`; `invariants/checks.py`: `report_ratio` (conservation as a ratio), count
  deficit gated on it.
- `testbed/inject.py`: trace-driven attack injection on real paired captures.
- `scripts/ziotp_experiments.py` (R1–R4), `tests/test_ziotp.py`, `results/ziotp/RESULTS_ZIOTP.md`.
- `eval/metrics.py`: episode detection counts an alert already active when the episode starts.

### Changed
- Loss is counted on MAC sequence numbers per transmitter (NWK counters are not loss counters on
  real stacks); RSSI-dependent statistics are skipped when a capture has no RSSI.

## v0.3 — 2026-09-19 (mid-review build)

Supersedes the v0.1 "dataset simulation edition". The CLI (`simulator_main.py --scenario …`),
the `state/` layout and the dashboard are kept; the engine underneath is new.

### What was wrong with v0.1 and is fixed here
- **IP records carried a `device` field.** The real IP tap cannot see which device a TLS record
  belongs to — that is the whole problem. v0.3 attributes records by learned translation
  signature + provenance (`pipeline/features.py`), and reports signature classes when devices are
  indistinguishable.
- **No capture-loss accounting.** v0.1 estimated completeness from sequence continuity only.
  v0.3 adds retransmission detection and the ACK cross-check (orphan ACKs prove both that a frame
  was missed and that the gateway received it), RSSI-aware attribution of orphan ACKs, and a
  measured completeness that widens the tolerance bands (§10).
- **Fixed thresholds** (−0.45 / +0.75 on a byte ratio, |z| > 4). v0.3 learns per-device bands
  from the commissioning run as quantiles, with floors derived from loss, over a rolling horizon.
- **Three devices, 18 windows, events every 350 ms.** v0.3 simulates a realistic Zigbee home:
  eight devices of five classes with spontaneous + periodic reporting, downlink commands, keepalive
  multiplexing on a long-lived TLS session, a witness with capture loss and jamming, and a
  controlled translator implementing **all seven attack rows** of §2.1 with per-event ground truth.
- **No emitter-consistency adversary.** v0.1's "emitter" scenario shifted the *device's* RSSI.
  v0.3's `forge` attack is the hub transmitting with a device's short address from its own radio,
  which is what the fourth invariant exists for.
- **No learned model, no evaluation, no detection floor.** v0.3 adds the R-GCN translation
  residual (NumPy, gradient-checked; PyTorch backend optional), the §12 metrics, the four baselines
  and the detection-floor sweep.

### Added
- `gwverify/` engine package (see README layout); `verifier/` application layer.
- Real-capture parsers: nRF 802.15.4 sniffer pcap (DLT 283 TAP / DLT 195) and tshark CSV; IP pcap
  with TLS application-data record segmentation and SNI; tshark CSV.
- §7.1 alert schema in SQLite + JSON lines, optional MQTT publish, capped append-only evidence
  directory with oldest-first eviction; degraded windows are written, never silently skipped.
- Versioned dataset manifests (`gwverify/dataset.py`), `scripts/build_dataset.py`.
- `scripts/verify_capture.py` for the hardware testbed; `scripts/run_ablations.py`,
  `scripts/run_detection_floor.py`; `tests/` (13 tests).
- Dashboard shows per-device invariant health, completeness, residual score, class labels and the
  full alert record.

### Removed
- v0.1 `verifier/{simulator,baseline,invariants,persistence,detector,models,store}.py` — replaced by
  the corresponding `gwverify/` modules.

## v0.1 — 2026-09-17
- Initial simulated verifier: 3-device toy generator, median/MAD baseline, four rule checks with
  fixed thresholds, 2-of-3 persistence, SQLite/JSONL store, FastAPI dashboard.
