# Live CICIDS-2017 ML Inference — Update Summary

**Branch:** `fix/live-ml-inference`
**First commit documented:** `5ea0d6e` — "Validate live CICIDS 78-feature ML inference"
**Date:** 2026-10-11

> **Status note.** This file was originally written for commit `5ea0d6e`. Later
> commits on the same branch (`e74bb43`, `dfd4c63`, and the report-consistency
> follow-up) changed several of the details below. Sections 4–7 are updated to
> the current branch state; where a value changed, the current value is given.

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
    `CICIDS_FEATURE_NAMES`, validates for missing/extra keys, and raises
    `NonFiniteFeatureError` (with per-feature diagnostics via
    `feature_diagnostics()`) if any value is still non-finite — it no longer
    silently coerces to `0.0`.
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
49 tests using synthetic in-memory flows (no PCAP/dataset dependency), including
8 bulk and 7 Active/Idle regression scenarios.

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
| Calculation logic | MATCH — Active/Idle matches Java reference at runtime; bulk arithmetic matches, direction routing deviation documented |
| Model inference | **PASS** — accepts extracted vector/dict |
| Confidence | **PASS** — ∈ [0.0, 1.0] |
| Prediction labels | ∈ {BENIGN, ATTACK}; both labels decodable |
| Test suite | **PASS — 88 tests** |

Example (real model, synthetic benign-like flow):

```json
{"prediction": "BENIGN", "confidence": 0.9519, "model": "cicids_random_forest"}
```

---

## 6. Tests Performed

```bash
python -m unittest discover -s tests
# Ran 88 tests ... OK
```

- `tests/test_prediction.py` (13 tests) and `tests/test_pcap_reader.py` (19 tests)
  also pass.
- `tests/test_reference_parity.py` (7 tests) pins Active/Idle and bulk behaviour to
  real Java reference output in `reports/java_reference_parity.json`.
- `tests/test_flow_extractor.py` (49 tests): exactly 78 features; names match;
  order matches schema **and** model artifact; all numeric; no NaN/Inf; model
  accepts vector/dict; prediction ∈ {BENIGN, ATTACK}; confidence ∈ [0,1];
  deterministic; `Fwd PSH Flags` present/correct; microsecond duration; TCP flag
  counts; single-packet and empty-flow edge cases; multiple flows; `predict_flow`.
- Stub-model tests verify `0 → ATTACK` and `1 → BENIGN` decoding + confidence.

---

## 7. Known Limitations

- Live-interface sniffing is **not** implemented; only saved capture files are
  read (`src/pcap_reader.py` + `scripts/validate_pcap.py`).
- Reference verification compiles and executes the pinned Java CICFlowMeter
  **feature code** in a JVM (via `scripts/java_reference_parity.py`). Active/Idle
  matches numerically; bulk arithmetic matches but direction routing intentionally
  follows the intended per-direction semantics rather than the reference's
  `byte[]` reference-equality defect. The reference's libpcap/jnetpcap decoder is
  not exercised.
- BENIGN/ATTACK **accuracy was not measured**: `http.cap` is normal traffic, so
  all flows classifying as BENIGN is expected, not an accuracy result.
- Bulk features follow the reference state machine (1.0 s clump timeout,
  `BULK_BOUND = 4`, payload-only, directional interleaving reset); our averages
  use floating-point division where the reference truncates.
- Standard-deviation features use the **sample** formula (N−1), matching Apache
  Commons Math as used by the reference.

---

## 8. Files Changed at a Glance

```
INFERENCE_INTEGRATION.md            (new/updated - canonical schema, units, validation)
src/cicids_features.py              (new - canonical 78-feature schema)
src/flow_extractor.py               (modified - 78 features, active/idle & bulk, sanitization)
src/prediction.py                   (modified - predict_flow, re-exported schema)
src/pcap_reader.py                  (new - PCAP/PCAPNG ingestion + report rendering)
scripts/validate_pcap.py            (new - end-to-end capture validation CLI)
scripts/compare_cicflowmeter.py     (new - diagnostic parity comparison)
scripts/java_reference_parity.py    (new - compiles & runs pinned Java reference, compares features)
scripts/java_reference_parity/      (new - Java harness + deterministic scenarios)
reports/pcap_validation_report.*    (generated - JSON + Markdown, same result object)
reports/java_reference_parity.json  (generated - real Java vs Python feature evidence)
tests/test_flow_extractor.py        (modified - schema, bulk, active/idle, sanitization)
tests/test_prediction.py            (modified - decode/confidence tests)
tests/test_pcap_reader.py           (new - ingestion + report tests)
tests/test_reference_parity.py      (new - pins features to recorded Java output)
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
