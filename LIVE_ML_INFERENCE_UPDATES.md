# Live CICIDS-2017 ML Inference — Update Summary

**Branch:** `fix/live-ml-inference`
**Commit:** `5ea0d6e` — "Validate live CICIDS 78-feature ML inference"
**Date:** 2026-10-11

---

## 1. Goal

Make the live pipeline

```text
Real traffic -> 78-feature flow extractor -> existing cicids_anomaly_model.pkl -> BENIGN/ATTACK + confidence
```

produce **exactly** the same 78 features (names, order, units, meaning,
preprocessing) that the existing Random Forest was trained on — without
retraining or replacing the model.

---

## 2. Remote / Repository Note (important)

- The repository URL provided (`origin` = `adityaraikar5555-collab/Network-Anomaly-Detection-Using-Machine-Learning`)
  does **not** contain commit `0737fc3` and has **no `src/flow_extractor.py`**.
- Commit `0737fc3` and `src/flow_extractor.py` live on the other remote,
  `collab` = `glenjr009/network-traffic-anomaly-detector`, which is also what the
  pre-existing `fix/live-ml-inference` branch tracks.
- The two remotes have **unrelated histories** (no merge-base). The complete
  pipeline (extractor + schema + models) exists on `collab/main`, so the work was
  done on the existing branch based on it.
- Consequence: a PR against `origin/main` is not possible (no common ancestor);
  a valid PR target is `collab/main`.

---

## 3. What Was Validated (before changes)

The exact training schema was derived from the repository, **not assumed**:

- `models/cicids_anomaly_model.pkl` →
  `RandomForestClassifier`, `n_features_in_ = 78`,
  `feature_names_in_` = `Destination Port` … `Idle Min`.
- Training pipeline (`src/cicids_preprocessing.py`, `notebooks/cicids2017_model_train.ipynb`):
  - `X = df.drop("Label", axis=1)` → feature order = CICIDS CSV column order.
  - Labels binarised to `BENIGN`/`ATTACK`; `LabelEncoder.classes_ = ['ATTACK','BENIGN']`
    → **`0 = ATTACK`, `1 = BENIGN`**.
  - **No feature scaling.** Only whitespace stripping, ±Inf→NaN, NaN-row drop.

### Mismatches found in `src/flow_extractor.py`

| # | Type | Detail |
|---|------|--------|
| 1 | Missing feature | `Fwd PSH Flags` was never emitted → extractor produced **77** features, not 78. |
| 2 | No ordering contract | Only per-chunk dicts existed; no canonical 78-feature assembly or vector API. |
| 3 | Unit mismatch | `Flow Duration`, all `*IAT*`, `Active *`, `Idle *` were in **seconds**; CICIDS uses **microseconds**. |
| 4 | Robustness | No guard for non-finite values reaching the inference validator. |

---

## 4. Changes Made

### `src/cicids_features.py` **(new)**
Single canonical definition of `CICIDS_FEATURE_NAMES` (78, training order) and
`CICIDS_FEATURE_COUNT`, imported by both the extractor and the inference layer so
they can never drift apart.

### `src/flow_extractor.py` **(modified)**
- **Added the missing `Fwd PSH Flags`** to `tcp_flag_and_rate_features()` → now 78 features.
- **Canonical assembly:** added
  - `NetworkFlow.extract_features()` — merges all chunks, orders by
    `CICIDS_FEATURE_NAMES`, validates for missing/extra keys, converts non-finite → `0.0`.
  - `NetworkFlow.to_feature_vector()` — ordered 78-value list.
  - `FlowExtractor.extract_flow_features()` / `FlowExtractor.get_feature_vectors()`.
- **Unit fix:** `Flow Duration`, all `*IAT*`, `Active *`, `Idle *` are now
  multiplied by `MICROSECONDS_PER_SECOND` (1,000,000). Rate features
  (`Flow Bytes/s`, `Flow Packets/s`, `Fwd/Bwd Packets/s`) stay per-second.
  `PacketRecord.timestamp` is documented as **seconds**.

### `src/prediction.py` **(modified)**
- Imports/re-exports `CICIDS_FEATURE_NAMES` from `src/cicids_features.py`
  (backward compatible — `from src.prediction import CICIDS_FEATURE_NAMES` still works).
- Added `predict_flow(flow)` — the end-to-end entry point:
  `predict_flow(flow)` == `predict_cicids(flow.extract_features())`.

### `tests/test_flow_extractor.py` **(new)**
19 tests using synthetic in-memory flows (no PCAP/dataset dependency).

### `tests/test_prediction.py` **(modified)**
Added deterministic label-decode + confidence tests using stubbed models
(`0 → ATTACK`, `1 → BENIGN`).

### `INFERENCE_INTEGRATION.md` **(new)**
Documents the canonical schema, units, pipeline, prediction output, tests and limitations.

> The model files `models/cicids_anomaly_model.pkl` and
> `models/cicids_label_encoder.pkl` were **not** modified or retrained.

---

## 5. Validation Results

| Item | Result |
|------|--------|
| Feature count | **78** (was 77) |
| Feature names | **MATCH** |
| Feature order | **MATCH** (asserted vs shared schema *and* `model.feature_names_in_`) |
| Units | **FIXED** — time features now microseconds; rates per-second |
| Calculation logic | MATCH (bulk features are a documented approximation) |
| Model inference | **PASS** — accepts extracted vector/dict |
| Confidence | **PASS** — ∈ [0.0, 1.0] |
| Prediction labels | ∈ {BENIGN, ATTACK}; both labels decodable |
| Test suite | **PASS — 32 tests** |

Example (real model, synthetic benign-like flow):

```json
{"prediction": "BENIGN", "confidence": 0.9519, "model": "cicids_random_forest"}
```

---

## 6. Tests Performed

```bash
python -m unittest discover -s tests
# Ran 32 tests ... OK
```

- Existing `tests/test_prediction.py` (11 tests) still pass unchanged.
- New `tests/test_flow_extractor.py` (19 tests): exactly 78 features; names match;
  order matches schema **and** model artifact; all numeric; no NaN/Inf; model
  accepts vector/dict; prediction ∈ {BENIGN, ATTACK}; confidence ∈ [0,1];
  deterministic; `Fwd PSH Flags` present/correct; microsecond duration; TCP flag
  counts; single-packet and empty-flow edge cases; multiple flows; `predict_flow`.
- Stub-model tests verify `0 → ATTACK` and `1 → BENIGN` decoding + confidence.

---

## 7. Known Limitations

- **No real-PCAP validation was performed.** The repo has no PCAP/`libpcap`
  parser or capture layer that creates `PacketRecord`s, and no CICIDS/PCAP data
  is committed. Only extractor → model was validated (synthetic flows + the real
  trained model). A capture adapter (`scapy`/`dpkt`/`pyshark`) is still needed to
  feed live traffic.
- Consequently, BENIGN/ATTACK accuracy on real traffic was **not** measured.
  Synthetic attack-like flows were classified BENIGN because their values do not
  match the CICIDS attack distributions — reported honestly, not asserted as a test.
- `*.Avg *Bulk*` features use a 1-second inter-packet bulk threshold
  (approximation of CICFlowMeter bulk; exact training implementation not in repo).
- Standard-deviation features use the population formula (÷ N).

---

## 8. Files Changed at a Glance

```
INFERENCE_INTEGRATION.md      (new, 164 lines)
src/cicids_features.py        (new, 102 lines)
src/flow_extractor.py         (modified, +123)
src/prediction.py             (modified, net -94 / +..)
tests/test_flow_extractor.py  (new, 238 lines)
tests/test_prediction.py      (modified, +35)
```

No datasets, PCAPs, generated captures, caches, or `.idea/` were committed.

---

## 9. Pull Request

`gh` is not installed; the branch was pushed to both remotes (never `main`).
Open the PR manually:

- Shared repo (history matches, recommended):
  `https://github.com/glenjr009/network-traffic-anomaly-detector/pull/new/fix/live-ml-inference`
- User repo:
  `https://github.com/adityaraikar5555-collab/Network-Anomaly-Detection-Using-Machine-Learning/pull/new/fix/live-ml-inference`

**PR title:** `Fix live CICIDS ML inference feature compatibility`
