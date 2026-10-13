# CICIDS-2017 Live ML Inference Integration

This document describes the **live** pipeline that turns captured packets into
the exact 78 features expected by the existing trained CICIDS-2017 Random Forest
model, and the validation performed to prove that compatibility.

## 1. Pipeline

```text
Real PCAP / live capture
        ↓   (packet parser — NOT included in this repo, see Limitations)
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
| `Active *`, `Idle *` | **microseconds**; active/idle split threshold = 1 second |
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
   them to microseconds while keeping rate features per-second. (The prototype's
   `ACTIVE_IDLE_THRESHOLD = 1.0` confirms timestamps are seconds — a 1 µs
   threshold would be nonsensical.)
4. **Non-finite safety** — `extract_features()` rejects any remaining non-finite value by raising
   `NonFiniteFeatureError` with per-feature diagnostics. Expected edge cases
   (such as zero denominators or insufficient observations) are handled explicitly
   and return defined zero values; unexpected NaN/Inf values are never silently
   converted to `0.0`. Division-by-zero is guarded throughout.
5. **Single schema definition** — extracted `CICIDS_FEATURE_NAMES` into
   `src/cicids_features.py`; `src/prediction.py` re-exports it for backward
   compatibility.

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

`python -m unittest discover -s tests` — **32 tests, all passing.**

- Existing `tests/test_prediction.py` (11 tests) still pass unchanged.
- New `tests/test_flow_extractor.py` (19 tests) verifies:
  exactly 78 features; names match the schema; **order matches both the shared
  schema and `model.feature_names_in_`**; all values numeric; no NaN/Inf; the
  model accepts the extracted vector/dict; prediction ∈ {BENIGN, ATTACK};
  confidence ∈ [0, 1]; deterministic extraction; `Fwd PSH Flags` present and
  correct; microsecond duration; TCP flag counts; single-packet and empty-flow
  edge cases; multiple flows; `predict_flow` end-to-end.
- New decode tests use stubbed models to deterministically verify
  `0 → ATTACK` and `1 → BENIGN` decoding and confidence calculation.

These tests use **synthetic in-memory flows** and do not depend on any committed
PCAP or CICIDS dataset file.

## 8. Resolved Items & Validation Status

- **Real-PCAP Validation Complete:** A full PCAP/PCAPNG ingestion layer (src/pcap_reader.py)
  and validation runner (scripts/validate_pcap.py) were implemented. Genuine Wireshark
  sample capture http.cap (SHA-256: 25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d)
  was validated end-to-end, yielding 3 flows with 100% schema match and all BENIGN predictions
  (90-98% confidence). See 
eports/pcap_validation_report.md for full results.
- **Active/Idle Grounding:** Independently verified against upstream Java CICFlowMeter
  (hlashkari/CICFlowMeter commit 98a5ebad0df579cc8b43eedd3421b3ae87699901). Confirmed
  5.0-second threshold, omission of trailing unclosed active periods (matching FlowGenerator.java),
  and sample standard deviation ( - 1$, matching Apache Commons Math 3).
- **Bulk Features Grounding:** Independently verified against Java BasicFlow.java lines 388–560.
  Confirmed 1.0 s clump timeout, 4-packet minimum bound, payload-only filtering, and directional
  interleaving resets. Verified via 8 dedicated numerical regression tests.
- **Standard deviation features:** Flow IAT / packet length statistics follow dataset conventions,
  while Active/Idle statistics use sample standard deviation ( - 1$) per Apache Commons Math.
