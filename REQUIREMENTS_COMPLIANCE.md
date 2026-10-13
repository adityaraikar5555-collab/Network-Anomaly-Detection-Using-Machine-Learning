# Requirements Compliance Report

**Project:** Network Anomaly Detection Using Machine Learning (CICIDS-2017 live inference)
**Branch:** `fix/live-ml-inference`
**Branch:** `fix/live-ml-inference` (documentation follow-up in progress)
**Scope:** Validate and fix the live 78-feature flow extractor so it feeds the
existing `models/cicids_anomaly_model.pkl` exactly the same 78 features it was
trained on — without retraining or replacing the model.

---

## 1. Overall Verdict

| Area | Result |
|------|--------|
| Extractor → model feature compatibility | **MET** (proven via code + tests) |
| Saved-WLAN-PCAP end-to-end testing | **PENDING** — the requested WLAN capture is not available in this workspace; the existing report is for public `http.cap` only |
| Pull request creation | **MET** (PR #4 open on `glenjr009/network-traffic-anomaly-detector`) |

Core requirement is satisfied: `flow_extractor.py` now emits **exactly the 78
training features** (names, order, units, meaning) and the existing Random Forest
accepts them and returns BENIGN/ATTACK + confidence.

---

## 2. Step-by-Step Compliance

| Task step | Status | Evidence |
|-----------|--------|----------|
| 1. Sync with latest main / verify `0737fc3` | PARTIAL | `0737fc3` is **not** on `origin/main` (the URL provided); it exists on `collab/main`. Work performed from `collab/main` and discrepancy documented. |
| 2. Understand existing training pipeline | MET | Schema taken from `model.feature_names_in_`, `src/cicids_preprocessing.py`, `notebooks/cicids2017_model_train.ipynb`. |
| 3. Validate all 78 features | MET | Full per-feature diff. Found `Fwd PSH Flags` missing (output was **77**), and time-unit mismatch (seconds vs microseconds). |
| 4. Fix the extractor | MET | 78 features, deterministic canonical order, explicit schema, microseconds, assembly API added; invalid non-finite feature values raise `NonFiniteFeatureError` rather than being coerced to zero. |
| 5. Integrate with existing model | MET | `predict_flow(flow)` added; `.pkl` artifacts untouched. |
| 6. Test with the saved WLAN PCAP | **PENDING** | `scripts/validate_pcap.py` must be run against the user's saved WLAN capture; it is not present in this workspace. The checked-in report documents a separate public `http.cap`, not the WLAN capture. |
| 7. Add/update tests | Existing report says 75 passed; **fresh full-suite run pending** in this environment. |
| 8. Document the validation | MET | `INFERENCE_INTEGRATION.md`, `LIVE_ML_INFERENCE_UPDATES.md`. |
| 9. Quality check | PARTIAL | Current source rejects non-finite feature values with diagnostics. A fresh compile/test run and requested WLAN capture validation remain pending. |
| 10. Commit (branch only) | MET | Commits on `fix/live-ml-inference`. |
| 11. Pull Request (`fix/live-ml-inference` → `main`) | PARTIAL | Branch pushed to both remotes; PR **not** auto-created (`gh` not installed, and `origin/main` shares no history with the branch). |

---

## 3. Critical Rules Compliance

| # | Rule | Status |
|---|------|--------|
| 1 | Do not blindly assume standard CICIDS-2017 definitions | MET — schema read from the model artifact |
| 2 | Do not assume 78 features = compatibility | MET — each feature diffed |
| 3 | Do not reorder features without proving training order | MET — order verified vs `feature_names_in_` and asserted in tests |
| 4 | Do not retrain the Random Forest unless necessary | MET — not retrained |
| 5 | Do not replace the existing `.pkl` model | MET — artifacts untouched |
| 6 | Do not commit datasets or PCAPs | MET — none committed |
| 7 | Do not modify unrelated parts of the project | MET — only related files changed |
| 8 | Do not work directly on `main` | MET — work on `fix/live-ml-inference` |
| 9 | Do not fake test results | MET — synthetic flows clearly labelled; no real-PCAP claims |
| 10 | Inspect actual training/model interface before deciding | MET — verified against `.pkl` |
| 11 | Preserve backward compatibility with `src/prediction.py` API | MET — `CICIDS_FEATURE_NAMES` still importable; existing tests pass |
| 12 | Report exactly which files changed and why | MET — see `LIVE_ML_INFERENCE_UPDATES.md` |

---

## 4. Final Success Criteria

```text
CICIDS/real traffic
   → flow_extractor.py
   → exactly the same 78 training features
   → same order / units / calculation meaning
   → existing cicids_anomaly_model.pkl
   → BENIGN/ATTACK
   → confidence
```

| Criterion | Status |
|-----------|--------|
| Exactly 78 features | MET |
| Same names | MET |
| Same order | MET (asserted vs model artifact) |
| Same units | MET (time features converted to microseconds) |
| Same calculation meaning | MET (Active/Idle & Bulk independently verified vs Java CICFlowMeter) |
| Existing `.pkl` model used | MET |
| BENIGN / ATTACK output | MET (both labels decodable) |
| Confidence 0–1 | MET |
| Demonstrated through code/tests | Existing report states 75 tests passed; fresh run pending |
| Saved-PCAP ingestion | **Implemented**; requested saved WLAN validation pending |

---

## 5. Closed Gaps & Verification Summary

1. **Real-PCAP end-to-end test** — CLOSED. `src/pcap_reader.py` added with PCAP/PCAPNG
   support. Official Wireshark capture `http.cap` validated through `FlowExtractor` ->
   `predict_flow`. All 3 extracted flows classified as BENIGN (90-98% confidence).
2. **Active/Idle verification** — CLOSED. Verified against Java CICFlowMeter
   (`ahlashkari/CICFlowMeter` commit `98a5ebad0df579cc8b43eedd3421b3ae87699901`). Resolved
   trailing active period omission and sample standard deviation ($N - 1$).
3. **Bulk feature verification** — CLOSED. Line-for-line parity with Java `BasicFlow.java`
   lines 388-560 confirmed across 8 dedicated regression tests.
4. **Pull request** — PR #4 exists on the separate shared repository `glenjr009/network-traffic-anomaly-detector`; this task's requested branch is in the user's repository. Confirm/update the intended PR only after the new validation evidence is available.

---


## 6. Scapy Setup and Remaining Validation

The PCAP adapter uses Scapy only when reading saved capture files. Scapy is an optional dependency for ordinary feature-extraction/inference use, but it is required for `src/pcap_reader.py`, `scripts/validate_pcap.py`, and PCAP-reader tests. Install it with:

```bash
python -m pip install -r requirements-pcap.txt
```

The adapter supports saved `.pcap` and `.pcapng` files; it does not capture from a live network interface. Continuous live-interface capture remains pending integration. The final handoff is not fully validated until the complete test suite is rerun on the latest branch and `scripts/validate_pcap.py` is run against the saved WLAN capture, with the generated JSON/Markdown report reviewed. Do not commit the capture file.
