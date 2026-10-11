# CICIDS-2017 ML Inference Integration & Completion Report

**Repository:** `adityaraikar5555-collab/Network-Anomaly-Detection-Using-Machine-Learning`
**Branch:** `fix/live-ml-inference-clean` (based on `main`; implementation commit `318131b`)
**Related docs:** `LIVE_ML_INFERENCE_UPDATES.md`, `REQUIREMENTS_COMPLIANCE.md`

---

## 1. Overview & Architecture

This document summarizes the reusable Machine Learning inference layer implemented for the **CICIDS-2017 Random Forest Model**. It provides the integration contract for the backend/FastAPI service and risk scoring engine.

```text
Raw packets (PacketRecord)
            ↓
    src/flow_extractor.py
 (Flow grouping + 78-feature extraction)
            ↓
    src/prediction.py
 (Validation & Preprocessing)
            ↓
 cicids_anomaly_model.pkl
            ↓
  Prediction + Confidence
            ↓
FastAPI Backend / Risk Scoring
```

---

## 2. Completed Requirements Checklist

- [x] **Repository Inspection**: Analyzed CICIDS preprocessing, training script, evaluation pipeline, and serialized `.pkl` models.
- [x] **Label Mapping Verification**:
  - `0` $\rightarrow$ **`ATTACK`**
  - `1` $\rightarrow$ **`BENIGN`**
  (Verified directly against `models/cicids_label_encoder.pkl`).
- [x] **Exact Feature Order (78 Features)**: Extracted and codified from `rf.feature_names_in_`.
- [x] **Inference Module (`src/prediction.py`)**:
  - Reusable `predict_cicids(features)` function.
  - In-memory model artifact caching (`load_cicids_artifacts`) to avoid repeated disk reads.
  - Strict validation against missing, extra, malformed, or non-numeric/NaN/Inf values.
  - Preprocessing aligns keys (whitespace stripping) and outputs a single-row DataFrame matching training specs.
- [x] **Stable Output Format**: Returns a clean, JSON-serializable dictionary with `prediction`, `confidence`, and `model`.
- [x] **Unit Testing Suite (`tests/test_prediction.py`)**: 11 unit tests covering valid inputs, sequence inputs, key whitespace tolerance, pandas objects, missing features, extra features, invalid types, and non-finite values.
- [x] **Untouched Core Files**: Existing training, evaluation, and model files were preserved without modification.

---

## 3. Model & Feature Specifications

- **Model Type**: `RandomForestClassifier` (100 estimators, max depth 20)
- **Model Path**: `models/cicids_anomaly_model.pkl`
- **Label Encoder Path**: `models/cicids_label_encoder.pkl`
- **Number of Features**: 78
- **Feature Names & Order**:
  1. `Destination Port`
  2. `Flow Duration`
  3. `Total Fwd Packets`
  4. `Total Backward Packets`
  5. `Total Length of Fwd Packets`
  6. `Total Length of Bwd Packets`
  7. `Fwd Packet Length Max`
  8. `Fwd Packet Length Min`
  9. `Fwd Packet Length Mean`
  10. `Fwd Packet Length Std`
  11. `Bwd Packet Length Max`
  12. `Bwd Packet Length Min`
  13. `Bwd Packet Length Mean`
  14. `Bwd Packet Length Std`
  15. `Flow Bytes/s`
  16. `Flow Packets/s`
  17. `Flow IAT Mean`
  18. `Flow IAT Std`
  19. `Flow IAT Max`
  20. `Flow IAT Min`
  21. `Fwd IAT Total`
  22. `Fwd IAT Mean`
  23. `Fwd IAT Std`
  24. `Fwd IAT Max`
  25. `Fwd IAT Min`
  26. `Bwd IAT Total`
  27. `Bwd IAT Mean`
  28. `Bwd IAT Std`
  29. `Bwd IAT Max`
  30. `Bwd IAT Min`
  31. `Fwd PSH Flags`
  32. `Bwd PSH Flags`
  33. `Fwd URG Flags`
  34. `Bwd URG Flags`
  35. `Fwd Header Length`
  36. `Bwd Header Length`
  37. `Fwd Packets/s`
  38. `Bwd Packets/s`
  39. `Min Packet Length`
  40. `Max Packet Length`
  41. `Packet Length Mean`
  42. `Packet Length Std`
  43. `Packet Length Variance`
  44. `FIN Flag Count`
  45. `SYN Flag Count`
  46. `RST Flag Count`
  47. `PSH Flag Count`
  48. `ACK Flag Count`
  49. `URG Flag Count`
  50. `CWE Flag Count`
  51. `ECE Flag Count`
  52. `Down/Up Ratio`
  53. `Average Packet Size`
  54. `Avg Fwd Segment Size`
  55. `Avg Bwd Segment Size`
  56. `Fwd Header Length.1`
  57. `Fwd Avg Bytes/Bulk`
  58. `Fwd Avg Packets/Bulk`
  59. `Fwd Avg Bulk Rate`
  60. `Bwd Avg Bytes/Bulk`
  61. `Bwd Avg Packets/Bulk`
  62. `Bwd Avg Bulk Rate`
  63. `Subflow Fwd Packets`
  64. `Subflow Fwd Bytes`
  65. `Subflow Bwd Packets`
  66. `Subflow Bwd Bytes`
  67. `Init_Win_bytes_forward`
  68. `Init_Win_bytes_backward`
  69. `act_data_pkt_fwd`
  70. `min_seg_size_forward`
  71. `Active Mean`
  72. `Active Std`
  73. `Active Max`
  74. `Active Min`
  75. `Idle Mean`
  76. `Idle Std`
  77. `Idle Max`
  78. `Idle Min`

---

## 4. API Reference

### `predict_cicids(features, model=None, label_encoder=None) -> dict`

Main entry point for single-record prediction.

- **Parameters**:
  - `features`: Dictionary of `{feature_name: value}`, pandas Series/DataFrame (1 row), or 78-element list/numpy array.
  - `model` *(optional)*: Pre-loaded scikit-learn model instance.
  - `label_encoder` *(optional)*: Pre-loaded scikit-learn LabelEncoder instance.
- **Returns**:
  ```python
  {
      "prediction": "BENIGN",  # or "ATTACK"
      "confidence": 0.9323,
      "model": "cicids_random_forest"
  }
  ```
- **Exceptions Raised**:
  - `ValueError`: On missing/extra features, wrong feature counts, or NaN/Inf/None values.
  - `TypeError`: On non-numeric values or unsupported data types.

---

## 5. FastAPI Integration Example

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from src.prediction import predict_cicids, load_cicids_artifacts

app = FastAPI(title="Network Intrusion Detection API")

# Preload model artifacts on startup
@app.on_event("startup")
def startup_event():
    load_cicids_artifacts()

class FlowFeaturesRequest(BaseModel):
    features: Dict[str, Any]

@app.post("/api/v1/predict")
def predict_network_traffic(payload: FlowFeaturesRequest):
    try:
        result = predict_cicids(payload.features)
        return result
    except (ValueError, TypeError) as err:
        raise HTTPException(status_code=422, detail=str(err))
    except Exception as err:
        raise HTTPException(status_code=500, detail="Internal inference error")
```

---

## 6. Live Flow Extraction & End-to-End Inference

### 6.1 Canonical feature schema

The single source of truth for the 78 feature names and their order is
[`src/cicids_features.py`](src/cicids_features.py):

- `CICIDS_FEATURE_NAMES` — ordered tuple of the 78 names.
- `CICIDS_FEATURE_COUNT` — `78`.

`src/prediction.py` imports and re-exports `CICIDS_FEATURE_NAMES` for backward
compatibility, and `src/flow_extractor.py` imports the same tuple, so the
extractor and the inference layer can never drift apart. The tuple is asserted
against `RandomForestClassifier.feature_names_in_` by the test suite.

### 6.2 Extractor API (`src/flow_extractor.py`)

- `PacketRecord` — one captured packet (timestamp in **POSIX seconds**, 5-tuple,
  length, header lengths, TCP flags, window size).
- `FlowExtractor` — groups packets into bidirectional flows by 5-tuple.
  - `add_packet(packet)` -> `NetworkFlow`
  - `get_flows()` -> `List[NetworkFlow]`
  - `extract_flow_features()` -> `List[Dict[str, float]]`
  - `get_feature_vectors()` -> `List[List[float]]`
- `NetworkFlow`
  - `extract_features()` -> ordered `Dict[str, float]` (exactly 78 keys)
  - `to_feature_vector()` -> `List[float]` (78 values, training order)

`extract_features()` raises `ValueError` if the assembled schema does not match
the canonical 78 names, and replaces any non-finite value with `0.0`.

### 6.3 End-to-end inference (`predict_flow`)

`src/prediction.py` exposes:

```python
predict_flow(flow, model=None, label_encoder=None) -> dict
```

which calls `flow.extract_features()` and then `predict_cicids(...)`, returning
the same `{"prediction", "confidence", "model"}` dictionary. It raises
`TypeError` if the object has no `extract_features()` method.

```python
from src.flow_extractor import FlowExtractor
from src.prediction import predict_flow

extractor = FlowExtractor()
for packet in capture_source:   # your PCAP/live adapter yields PacketRecord
    extractor.add_packet(packet)

for flow in extractor.get_flows():
    print(predict_flow(flow))
```

### 6.4 Units

- Time-based features (`Flow Duration`, all `*IAT*`, `Active *`, `Idle *`) are
  emitted in **microseconds** to match CICIDS-2017.
- Rate features (`Flow Bytes/s`, `Flow Packets/s`, `Fwd Packets/s`,
  `Bwd Packets/s`) are per **second**.
- `PacketRecord.timestamp` is interpreted as epoch **seconds**; convert at the
  capture boundary if your source provides nanoseconds.

---

## 7. Setup & Dependencies

```bash
pip install -r requirements.txt
```

Runtime inference requires `numpy`, `pandas`, `scikit-learn`, and `joblib`. The
extractor and tests use only the Python standard library plus those packages;
no PCAP library is required to run the unit tests.

---

## 8. Running Tests

```bash
python -m unittest discover -s tests -v
```

The suite covers schema/count/order parity against the model artifact, extractor
edge cases (single-packet, empty, multi-flow), units, TCP flags, label decoding,
confidence mapping, and end-to-end `extractor -> model` inference.

---

## 9. Verification Status

**Verified (executed on this branch):**

- The 78 feature names and their order match `model.feature_names_in_` exactly
  (schema parity — not a claim about per-feature calculation parity).
- `Flow Duration` / IAT / Active-Idle emitted in microseconds; rates per second.
- No `NaN`/`Inf` values leave the extractor.
- `predict_flow` returns a label in `{BENIGN, ATTACK}` and a finite confidence
  in `[0, 1]`.
- The existing `models/cicids_anomaly_model.pkl` and
  `models/cicids_label_encoder.pkl` are used unchanged (identical Git blob hashes
  on `main` and on this branch).

**Not verified (requires artifacts/data not present in this repository):**

- **Real-PCAP end-to-end inference.** This repository contains no PCAP parser /
  capture adapter, no committed PCAP or CICIDS dataset, and no packet-parsing
  library (`scapy`/`dpkt`/`pyshark`) is installed. Only synthetic in-memory flows
  were used. To test on real traffic, provide a PCAP plus an adapter that yields
  `PacketRecord`s and run the snippet in section 6.3.
- **Attack detection on real, labeled traffic.** No labeled PCAP is available,
  so per-class accuracy on live traffic is unmeasured.
- **Bit-for-bit calculation parity with CICFlowMeter.** Not established for the
  approximated features listed in section 10.

---

## 10. Known Differences vs. CICFlowMeter

The extractor reproduces the CICIDS/CICFlowMeter feature definitions for the
fields below, but a few calculations are documented approximations and are
**not** claimed to be bit-for-bit identical to the CICFlowMeter reference:

- **Bulk features** (`*Avg Bytes/Bulk`, `*Avg Packets/Bulk`, `*Avg Bulk Rate`)
  use a fixed 1-second inter-packet threshold to group a bulk; CICFlowMeter uses
  an internal packet-count/timeout heuristic.
- **Active/Idle** uses a 1-second active threshold; period boundary semantics may
  differ from CICFlowMeter.
- **`min_seg_size_forward`** uses the minimum forward payload size rather than
  the initial TCP segment size only.
- **Standard-deviation features** (`*Std`) use the population formula (÷ N).
- **`Init_Win_bytes_forward` / `Init_Win_bytes_backward`** use the first packet in
  the respective direction with a non-zero window, rather than strictly the
  initial window advertisement.
- **`Fwd Header Length.1`** intentionally duplicates `Fwd Header Length`, matching
  the duplicated column present in the training CSV.
- **Bidirectional flow timing** relies on capture-observed timestamps; out-of-order
  arrival is handled by sorting, which may differ slightly from wire order.
