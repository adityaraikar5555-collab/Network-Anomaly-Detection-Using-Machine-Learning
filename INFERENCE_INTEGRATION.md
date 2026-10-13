# CICIDS-2017 Live ML Inference Integration

This document describes the **live** pipeline that turns captured packets into
the exact 78 features expected by the existing trained CICIDS-2017 Random Forest
model, and the validation performed to prove that compatibility.

## 1. Pipeline

```text
Real PCAP / PCAPNG capture file
        ↓   src/pcap_reader.py  (Scapy-based reader; saved captures only, not live sniffing)
PacketRecord
        ↓   src/flow_extractor.py
FlowExtractor  →  NetworkFlow
        ↓   NetworkFlow.extract_features()   (78 features, canonical order/units)
src/prediction.py  →  validate_and_preprocess_cicids()
        ↓
models/cicids_anomaly_model.pkl  (existing model, NOT retrained)
models/cicids_label_encoder.pkl
        ↓
{"prediction": "BENIGN" | "ATTACK", "confidence": 0.0 - 1.0, "model": "cicids_random_forest"}
```

`predict_flow(flow)` in `src/prediction.py` is the end-to-end entry point:
`predict_flow(flow)` == `predict_cicids(flow.extract_features())`.

`scripts/validate_pcap.py` runs the whole path on a saved capture and writes a
JSON report and (with `--markdown`) a Markdown report, both rendered from the
same result object.

## 2. Canonical 78-Feature Schema

The single source of truth is **`src/cicids_features.py`**
(`CICIDS_FEATURE_NAMES`). It is imported by both
`src/flow_extractor.py` and `src/prediction.py`, so the extractor and the
inference validator can never drift apart.

The order was not assumed from a generic CICIDS list: it was verified directly
against `models/cicids_anomaly_model.pkl` via
`RandomForestClassifier.feature_names_in_`, which was produced by
`df.drop("Label", axis=1)` on the CICIDS-2017 `MachineLearningCSV` files
(i.e. the CSV column order). `tests/test_flow_extractor.py` asserts the extractor
output order equals both the shared constant **and** the model artifact order.

Order (index 1-78):

| # | Feature | # | Feature | # | Feature |
|---|---------|---|---------|---|---------|
| 1 | Destination Port | 28 | Bwd IAT Std | 55 | Fwd Header Length.1 |
| 2 | Flow Duration | 29 | Bwd IAT Max | 56 | Fwd Avg Bytes/Bulk |
| 3 | Total Fwd Packets | 30 | Bwd IAT Min | 57 | Fwd Avg Packets/Bulk |
| 4 | Total Backward Packets | 31 | Fwd PSH Flags | 58 | Fwd Avg Bulk Rate |
| 5 | Total Length of Fwd Packets | 32 | Bwd PSH Flags | 59 | Bwd Avg Bytes/Bulk |
| 6 | Total Length of Bwd Packets | 33 | Fwd URG Flags | 60 | Bwd Avg Packets/Bulk |
| 7 | Fwd Packet Length Max | 34 | Bwd URG Flags | 61 | Bwd Avg Bulk Rate |
| 8 | Fwd Packet Length Min | 35 | Fwd Header Length | 62 | Subflow Fwd Packets |
| 9 | Fwd Packet Length Mean | 36 | Bwd Header Length | 63 | Subflow Fwd Bytes |
| 10 | Fwd Packet Length Std | 37 | Fwd Packets/s | 64 | Subflow Bwd Packets |
| 11 | Bwd Packet Length Max | 38 | Bwd Packets/s | 65 | Subflow Bwd Bytes |
| 12 | Bwd Packet Length Min | 39 | Min Packet Length | 66 | Init_Win_bytes_forward |
| 13 | Bwd Packet Length Mean | 40 | Max Packet Length | 67 | Init_Win_bytes_backward |
| 14 | Bwd Packet Length Std | 41 | Packet Length Mean | 68 | act_data_pkt_fwd |
| 15 | Flow Bytes/s | 42 | Packet Length Std | 69 | min_seg_size_forward |
| 16 | Flow Packets/s | 43 | Packet Length Variance | 70 | Active Mean |
| 17 | Flow IAT Mean | 44 | FIN Flag Count | 71 | Active Std |
| 18 | Flow IAT Std | 45 | SYN Flag Count | 72 | Active Max |
| 19 | Flow IAT Max | 46 | RST Flag Count | 73 | Active Min |
| 20 | Flow IAT Min | 47 | PSH Flag Count | 74 | Idle Mean |
| 21 | Fwd IAT Total | 48 | ACK Flag Count | 75 | Idle Std |
| 22 | Fwd IAT Mean | 49 | URG Flag Count | 76 | Idle Max |
| 23 | Fwd IAT Std | 50 | CWE Flag Count | 77 | Idle Min |
| 24 | Fwd IAT Max | 51 | ECE Flag Count | | |
| 25 | Fwd IAT Min | 52 | Down/Up Ratio | | |
| 26 | Bwd IAT Total | 53 | Average Packet Size | | |
| 27 | Bwd IAT Mean | 54 | Avg Fwd Segment Size | | |

## 3. Unit & Meaning Assumptions

| Quantity | Unit / meaning |
|----------|----------------|
| `PacketRecord.timestamp` | **seconds** (float, e.g. `time.time()`) |
| `Flow Duration`, all `*IAT*` | **microseconds** (× 1,000,000), matching CICIDS-2017 |
| `Active *`, `Idle *` | **microseconds**; active/idle split threshold = **5.0 s** (CICFlowMeter `ACTIVE_TIMEOUT`) |
| `Flow Bytes/s`, `Flow Packets/s`, `Fwd/Bwd Packets/s` | per **second** |
| Packet/segment lengths, header lengths, window bytes | bytes |
| Flag counts | packet counts (no scaling) |

There is **no feature scaling** anywhere. The training pipeline
(`src/cicids_preprocessing.py` / the notebook) only strips column whitespace,
replaces ±Inf with NaN, drops NaN rows, and binarises the label
(`BENIGN` vs `ATTACK`) with a `LabelEncoder` (`classes_ = ['ATTACK', 'BENIGN']`,
so `0 → ATTACK`, `1 → BENIGN`). Inference therefore feeds raw values directly.

## 4. What Was Fixed

1. **Missing feature** — `tcp_flag_and_rate_features()` omitted `Fwd PSH Flags`
   (the property existed but was never emitted), producing **77** features.
   Added it, restoring exactly **78**.
2. **No canonical assembly / ordering** — the extractor exposed per-chunk dicts
   only. Added `NetworkFlow.extract_features()` (ordered by
   `CICIDS_FEATURE_NAMES`, validated for missing/extra keys) and
   `NetworkFlow.to_feature_vector()`, plus `FlowExtractor.extract_flow_features()`
   and `FlowExtractor.get_feature_vectors()`.
3. **Unit mismatch** — time features (`Flow Duration`, all IATs, Active/Idle)
   were emitted in **seconds**; CICIDS-2017 uses **microseconds**. Converted
   them to microseconds while keeping rate features per-second.
4. **Non-finite handling** — `extract_features()` does **not** silently coerce
   invalid values. Every legitimate fallback (zero denominators, insufficient
   observations, empty directions) yields a defined zero; if a value is still
   `NaN`/`±Inf` afterwards it indicates invalid input or an unguarded
   computation, and `NonFiniteFeatureError` is raised with per-feature
   diagnostics (`NetworkFlow.feature_diagnostics()`). Unexpected NaN/Inf values
   are never silently converted to `0.0`; division-by-zero is guarded throughout.
5. **Single schema definition** — extracted `CICIDS_FEATURE_NAMES` into
   `src/cicids_features.py`; `src/prediction.py` re-exports it for backward
   compatibility.
6. **Payload-driven features** — `act_data_pkt_fwd` and `min_seg_size_forward`
   are computed from the L4 payload, matching the reference definitions.
7. **Active/Idle & Bulk alignment** — `_active_idle_periods()` omits the trailing
   unclosed active period and `_statistics()` uses the sample standard deviation
   (N−1); `_bulk_features()` follows the reference state machine (payload-only,
   1.0 s clump timeout, `BULK_BOUND = 4`, directional interleaving reset).

The model (`models/cicids_anomaly_model.pkl`) and label encoder
(`models/cicids_label_encoder.pkl`) were **not retrained or replaced**.

## 5. Prediction Output

```python
from src.flow_extractor import FlowExtractor, PacketRecord
from src.prediction import predict_flow

extractor = FlowExtractor()
extractor.add_packet(PacketRecord(timestamp=..., src_ip=..., ...))
flow = extractor.get_flows()[0]

predict_flow(flow)
# {'prediction': 'BENIGN', 'confidence': 0.9519, 'model': 'cicids_random_forest'}
```

`confidence` is `predict_proba` for the predicted class, in `[0.0, 1.0]`.

## 6. Scapy Installation and PCAP Reader Setup

The PCAP/PCAPNG reader uses Scapy as an optional dependency. The base feature-extraction and inference code can be imported without Scapy, but saved-capture ingestion, `scripts/validate_pcap.py`, and the PCAP-reader tests require it. From the repository root, install the PCAP extras with:

```bash
python -m pip install -r requirements-pcap.txt
```

Then validate a saved capture and write a JSON report:

```bash
python scripts/validate_pcap.py --pcap path/to/capture.pcapng --json reports/wlan_validation.json
```

The adapter supports saved PCAP/PCAPNG files only. Continuous live-interface capture is pending integration and is not part of this implementation.

## 7. Tests Performed

```bash
python -m unittest discover -s tests
# Ran 88 tests ... OK
```

- `tests/test_flow_extractor.py` (49 tests): exactly 78 features; names match the
  schema; **order matches both the shared schema and `model.feature_names_in_`**;
  all values numeric; no NaN/Inf; the model accepts the extracted vector/dict;
  prediction ∈ {BENIGN, ATTACK}; confidence ∈ [0, 1]; deterministic extraction;
  `Fwd PSH Flags` present and correct; microsecond duration; TCP flag counts;
  payload-driven features; 8 bulk regression scenarios; 7 Active/Idle regression
  scenarios; non-finite rejection; packet validation.
- `tests/test_prediction.py` (13 tests): artifact loading, dict/sequence/array/
  pandas inputs, missing/extra feature rejection, non-numeric/NaN/Inf/None
  rejection, and deterministic `0 → ATTACK` / `1 → BENIGN` decoding.
- `tests/test_pcap_reader.py` (19 tests): packet→record conversion, unsupported
  filtering, malformed counting, `max_packets`, bidirectional grouping, capture
  error handling, end-to-end `validate_capture`, capture-metadata embedding,
  Markdown/JSON consistency, and PCAPNG support.
- `tests/test_reference_parity.py` (7 tests): pins Active/Idle and bulk features
  to real Java reference output recorded in `reports/java_reference_parity.json`.

These tests use **synthetic in-memory flows** and do not depend on any committed
PCAP or CICIDS dataset file. `tests/test_reference_parity.py` additionally
depends on the committed Java-reference evidence artifact (not on a JDK at test
time).

## 8. Real-Capture Validation

`src/pcap_reader.py` ingests saved classic libpcap (microsecond/nanosecond,
big/little endian) and PCAPNG captures via Scapy, and `scripts/validate_pcap.py`
runs the full `capture → features → model` path. The genuine public Wireshark
sample capture `http.cap` (SHA-256
`25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d`) was
processed end-to-end: 43 usable packets, 3 flows, 0 skipped/malformed, 100%
schema match, all `BENIGN` (90.11%–98.19% confidence). Both
`reports/pcap_validation_report.json` and `reports/pcap_validation_report.md`
are generated from the same result object.

> **Scope note:** `http.cap` is a *public Wireshark sample*, not the requested
> saved WLAN capture. The requested WLAN validation is **BLOCKED** until that
> capture is supplied; no WLAN report has been generated. See
> `REQUIREMENTS_COMPLIANCE.md` §7.

## 9. Reference Verification (Runtime, Java)

Active/Idle and bulk-transfer semantics were validated **numerically at
runtime** against the pinned upstream Java CICFlowMeter sources
(`ahlashkari/CICFlowMeter` commit
`98a5ebad0df579cc8b43eedd3421b3ae87699901`). The unmodified sources
`BasicFlow.java`, `BasicPacketInfo.java`, `IdGenerator.java` and
`DateFormatter.java` are compiled with a real JDK (Temurin 21) together with
`scripts/java_reference_parity/ParityHarness.java`, which drives
`BasicFlow.updateActiveIdleTime` / `BasicFlow.addPacket` on deterministic
scenarios and reads the feature getters. Packet capture / jnetpcap decoding is
**not** exercised — this validates the reference *feature arithmetic*, not its
decoder.

Reproduce and inspect:

```
python scripts/java_reference_parity.py --json reports/java_reference_parity.json
```

Evidence: `reports/java_reference_parity.json` (reference commit, JDK version,
per-scenario Java vs Python values, and pass/fail checks).
`tests/test_reference_parity.py` pins the current implementation to that
recorded output.

**Findings**

- **Active/Idle — exact numeric match.** All eight Active/Idle features agree
  with the Java reference to 1e-9 on every scenario. Confirmed semantics:
  intra-flow active threshold **5.0 s** (`ACTIVE_TIMEOUT`); sample standard
  deviation (N−1, Apache Commons Math); the trailing active period at flow
  termination is **not** recorded upstream (the `endActiveIdleTime` call is
  commented out).
- **Bulk — arithmetic identical, direction routing deviates.** The reference
  state machine (payload-only participation, **1.0 s** clump timeout,
  `BULK_BOUND = 4`, directional interleaving reset) reconciles exactly with our
  implementation: on a single-direction flow our *forward* bulk triple equals
  the reference's *backward* triple element-wise (`600 / 6 / 1200`).
- **Confirmed upstream defect:** `updateFlowBulk` selects direction with
  `this.src == packet.getSrc()`, a reference comparison against a fresh
  `Arrays.copyOf` array, which is **always false** in this revision. At runtime
  the reference therefore reports forward bulk `0 / 0 / 0` and accumulates
  *every* payload packet into the backward counters. An interleaved flow makes
  the reference synthesise a spurious backward bulk (`800 / 6 / 1600`) while
  correct per-direction semantics (ours) yield no bulk. Our extractor
  implements the **intended** per-direction behaviour instead.
- **Remaining deviations (documented, not hidden):** upstream length statistics
  use L4 payload bytes and the TCP header length only, whereas this extractor
  uses full frame length and IP+TCP header lengths (consistent with CICIDS-2017
  CSV semantics); and our bulk averages use floating-point division where the
  reference truncates via integer division.

## 10. Known Limitations

- Live-interface sniffing is **not** implemented; only saved capture files are
  read.
- Reference verification executes the reference *feature code* in a JVM but does
  not exercise the reference packet decoder (libpcap/jnetpcap), so parity with
  the full Java tool on real captures is not claimed. Active/Idle matches
  exactly; bulk direction intentionally follows the documented intended
  semantics rather than the upstream routing defect.
- BENIGN/ATTACK accuracy on real traffic was **not** measured against labelled
  data; `http.cap` contains only normal traffic, so all flows being `BENIGN` is
  expected but is not an accuracy measurement.
