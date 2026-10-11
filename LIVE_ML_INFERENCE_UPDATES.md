# Live CICIDS-2017 ML Inference — Update Summary

**Repository:** `adityaraikar5555-collab/Network-Anomaly-Detection-Using-Machine-Learning` (remote `origin`)
**Pull-request head branch:** `fix/live-ml-inference-clean`
**Pull-request base branch:** `main`
**Implementation commit:** `318131b0d929cea9fa72b476a6b3bf2a38861570`
**Base commit:** `ec3300e5bca18016cf814f0db465296bb65c1a3c`
**Divergence:** based on `main`; linear history, 0 commits behind `main`
**Date:** 2026-10-11

> The branch head is `fix/live-ml-inference-clean`. `318131b` is the commit that
> adds the inference implementation; documentation-only commits may follow it,
> so the branch tip can advance without changing the code or the model.

---

## 1. Goal

Make the live pipeline

```text
Real traffic -> 78-feature flow extractor -> existing cicids_anomaly_model.pkl -> BENIGN/ATTACK + confidence
```

emit the same **78 features (names, order, count, units, label mapping)** that the
existing Random Forest was trained on — without retraining or replacing the model.

---

## 2. Repository / history provenance (important)

The final implementation lives in the user's repository and is based on its own
`main`. The original extractor prototype came from a collaborator repository:

- **`origin`** = `adityaraikar5555-collab/Network-Anomaly-Detection-Using-Machine-Learning`
  (the PR target). Its `main` contains the trained model, label encoder, training
  scripts and the pre-existing `src/prediction.py`, but originally had **no**
  `src/flow_extractor.py`.
- **`collab`** = `glenjr009/network-traffic-anomaly-detector` (a collaborator /
  upstream repository). The original `src/flow_extractor.py` prototype was
  authored here in commit `0737fc3` ("Add CICIDS 78-feature flow extraction
  prototype", author `cyb3rPh03n1x`). This repository has **unrelated history**
  from `origin` (no common ancestor).
- The pre-existing `fix/live-ml-inference` branch was built on top of the
  collaborator history, so it could not be merged into `origin/main`.

**Resolution:** the refined tree was rebased onto `origin/main` as a single commit,
producing `fix/live-ml-inference-clean` (`318131b`). The rebase is what makes the
PR against `origin/main` possible. The extractor transfer was verified by diffing
the clean-branch `src/flow_extractor.py` against the original prototype: the only
differences are the intended, documented fixes (+110 / −13 lines); everything else
in the branch comes from `origin/main` unchanged.

---

## 3. What Was Validated (training schema, before changes)

The exact training schema was derived from the model artifact, **not assumed**:

- `models/cicids_anomaly_model.pkl` →
  `RandomForestClassifier`, `n_features_in_ = 78`,
  `feature_names_in_` = `Destination Port` … `Idle Min`
  (100 estimators, max depth 20 — matching `src/cicids_train_model.py`).
- Training pipeline (`src/cicids_preprocessing.py`, `src/cicids_train_model.py`,
  `notebooks/cicids2017_model_train.ipynb`):
  - `X = df.drop("Label", axis=1)` → feature order = (stripped) CICIDS CSV column order.
  - Labels binarised to `BENIGN`/`ATTACK`; `LabelEncoder.classes_ = ['ATTACK','BENIGN']`
    → **`0 = ATTACK`, `1 = BENIGN`**.
  - **No feature scaling.** Only whitespace stripping, ±Inf→NaN, NaN-row drop,
    duplicate-row drop.

### Mismatches found in the original `src/flow_extractor.py`

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

### `src/flow_extractor.py` **(new file relative to `origin/main`; derived from the collaborator prototype)**
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
Added 2 deterministic label-decode + confidence tests using stubbed models
(`0 → ATTACK`, `1 → BENIGN`); the 11 pre-existing tests are unchanged.

### `INFERENCE_INTEGRATION.md` **(modified)**
Extended the existing integration doc with the canonical schema, units, live
pipeline, `predict_flow`, tests and limitations.

### `LIVE_ML_INFERENCE_UPDATES.md`, `REQUIREMENTS_COMPLIANCE.md` **(new)**
Validation summaries. (These documents describe an earlier state of the branch
and have since been corrected to the final `fix/live-ml-inference-clean` state.)

> The model files `models/cicids_anomaly_model.pkl` and
> `models/cicids_label_encoder.pkl` were **not** modified or retrained. Their Git
> blob hashes are identical on `main`, on this branch, and in the working tree
> (see section 8).

---

## 5. Validation Results

| Item | Result |
|------|--------|
| Feature count | **78** (was 77) |
| Feature names | **MATCH** (exact) |
| Feature order | **MATCH** (asserted vs shared schema *and* `model.feature_names_in_`) |
| Units | **FIXED** — time features now microseconds; rates per-second |
| Per-feature calculation logic | **Improved** — payload-based `act_data_pkt_fwd`/bulk, CICFlowMeter `ACTIVE_TIMEOUT=5s`, IPv4+transport header lengths; remaining approximations documented (bulk state machine, Active/Idle boundaries, `min_seg_size_forward`, population std, initial-window selection); **not claimed bit-for-bit identical to CICFlowMeter** |
| PCAP ingestion | **ADDED** — `src/pcap_reader.py` + `scripts/validate_pcap.py` (scapy, optional) |
| Model inference | **PASS** — accepts extracted vector/dict |
| Confidence | **PASS** — ∈ [0.0, 1.0] |
| Prediction labels | ∈ {BENIGN, ATTACK}; both labels decodable |
| Test suite | **PASS — 52 tests** with `scapy`; PCAP tests are skipped without it |

Example (real model, the synthetic flow built by `tests/test_flow_extractor.py::build_sample_flow`):

```json
{"prediction": "BENIGN", "confidence": 0.9356, "model": "cicids_random_forest"}
```

---

## 6. Tests Performed

Executed on the final working tree of `fix/live-ml-inference-clean`:

```bash
python -m unittest discover -s tests -v
# Ran 52 tests ... OK   (with scapy installed)
```

- `tests/test_prediction.py` (13 tests — 11 pre-existing + 2 new) pass.
- `tests/test_flow_extractor.py` (25 tests): exactly 78 features; names match;
  order matches schema **and** model artifact; all numeric; no NaN/Inf; model
  accepts vector/dict; prediction ∈ {BENIGN, ATTACK}; confidence ∈ [0,1];
  deterministic; `Fwd PSH Flags` present/correct; microsecond duration; TCP flag
  counts; payload-based `act_data_pkt_fwd`/`min_seg_size_forward`/bulk;
  Active/Idle `ACTIVE_TIMEOUT`; single-packet and empty-flow edge cases; multiple
  flows; `predict_flow`.
- `tests/test_pcap_reader.py` (14 tests): PCAP parsing, TCP/UDP handling, ICMP
  skipping, bidirectional grouping, 78-key schema, `validate_capture` report,
  JSON serialisability, empty/garbage/missing-file errors, and deterministic
  sample-capture generation. Skipped when `scapy` is not installed.
- Stub-model tests verify `0 → ATTACK` and `1 → BENIGN` decoding + confidence.

---

## 7. Known Limitations

- **No real-PCAP validation was performed.** A PCAP ingestion layer now exists
  ([`src/pcap_reader.py`](src/pcap_reader.py), scapy-based, optional) and is
  exercised end-to-end with a **synthetic** capture
  (`src/sample_capture.py`), but no genuine network capture or labeled
  CICIDS-2017 PCAP/dataset is available (outbound access to capture hosts is
  blocked in this environment) and none is committed. The synthetic capture is
  explicitly **not** CICIDS-2017 traffic.
- Consequently, BENIGN/ATTACK accuracy on real traffic was **not** measured.
  Synthetic attack-like flows were classified BENIGN because their values do not
  match the CICIDS attack distributions — reported honestly, not asserted as a test.
- `*.Avg *Bulk*` features use application-layer payload bytes and require at
  least `BULK_BOUND = 4` payload packets within a `CLUMP_TIMEOUT = 1 s` gap. This
  is closer to CICFlowMeter but still an approximation of its incremental bulk
  state machine.
- Standard-deviation features use the population formula (÷ N).
- Active/Idle period boundaries use `ACTIVE_TIMEOUT = 5 s` and may still differ
  from CICFlowMeter's exact boundary semantics.
- Byte-for-byte parity with CICFlowMeter is **not** claimed. The only offline
  reference (`cicflowmeter` Python port) has documented defects
  (first-packet duplication, IPv4-only header lengths, `CWE` aliased to `URG`,
  empty Active/Idle); see `INFERENCE_INTEGRATION.md` §10.

---

## 8. Files Changed at a Glance

Relative to `origin/main` (`ec3300e`):

```
 INFERENCE_INTEGRATION.md      | modified  (PCAP tooling, verification, parity notes)
 LIVE_ML_INFERENCE_UPDATES.md  | new
 REQUIREMENTS_COMPLIANCE.md    | new
 src/cicids_features.py        | new
 src/flow_extractor.py         | new to main (derived from collaborator prototype)
 src/pcap_reader.py            | new       (PCAP -> PacketRecord + validate_capture)
 src/sample_capture.py         | new       (deterministic synthetic capture generator)
 src/prediction.py             | modified
 scripts/validate_pcap.py      | new       (PCAP -> features -> model CLI)
 scripts/compare_cicflowmeter.py | new     (parity diagnostic vs cicflowmeter port)
 tests/test_flow_extractor.py  | new
 tests/test_pcap_reader.py     | new
 tests/test_prediction.py      | modified
 requirements.txt              | modified  (scapy noted as optional)
```

**Model preservation evidence** (Git blob hashes, identical everywhere):

```
models/cicids_anomaly_model.pkl   31693875e0fcc80437659ff74c86722d94178485
models/cicids_label_encoder.pkl   cbd48f4da13bbe908679b0a8c853adc8ff75f75c
```

No datasets, PCAPs, generated captures, caches, or `.idea/` were committed.

---

## 9. Pull Request

The branch `fix/live-ml-inference-clean` is based on `origin/main`, so a PR is
now possible. It was pushed to `origin` (and to `collab`, never to a `main`
branch).

- **Base repository/branch:** `adityaraikar5555-collab/Network-Anomaly-Detection-Using-Machine-Learning` : `main`
- **Head branch:** `fix/live-ml-inference-clean`
- **Compare URL:**
  `https://github.com/adityaraikar5555-collab/Network-Anomaly-Detection-Using-Machine-Learning/compare/main...fix/live-ml-inference-clean`
- **Open-PR URL:**
  `https://github.com/adityaraikar5555-collab/Network-Anomaly-Detection-Using-Machine-Learning/pull/new/fix/live-ml-inference-clean`

**PR title:** `Fix live CICIDS ML inference feature compatibility`
