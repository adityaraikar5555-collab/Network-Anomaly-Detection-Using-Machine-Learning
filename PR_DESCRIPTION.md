# Pull Request

**Branch:** `fix/live-ml-inference` → `main`
**Title:** Fix live CICIDS ML inference feature compatibility

---

### What was done
- Validated the live 78-feature extractor (`src/flow_extractor.py`) against the
  **actual** training schema taken from
  `models/cicids_anomaly_model.pkl` (`RandomForestClassifier.feature_names_in_`),
  not a generic CICIDS list.
- Fixed a missing feature: `Fwd PSH Flags` was never emitted (output was 77).
- Added a canonical, ordered 78-feature assembly API
  (`NetworkFlow.extract_features()`, `to_feature_vector()`,
  `FlowExtractor.get_feature_vectors()`) backed by a single shared schema module
  (`src/cicids_features.py`).
- Fixed units: `Flow Duration`, all `*IAT*`, and `Active *`/`Idle *` were in
  seconds; converted to **microseconds** to match CICIDS-2017 (rates stay per-second).
- Integrated with the existing model: added `predict_flow(flow)` in
  `src/prediction.py`; re-exported `CICIDS_FEATURE_NAMES` for backward compatibility.
- Validated the existing Random Forest inference; **no retraining** and **no
  replacement** of `models/cicids_anomaly_model.pkl` /
  `models/cicids_label_encoder.pkl`.
- Added/updated tests and documentation.

### Validation
- **Feature count:** 78 ✅
- **Feature names:** MATCH ✅
- **Feature order:** MATCH ✅ (asserted vs shared schema *and* `model.feature_names_in_`)
- **Units:** MATCH ✅ (time features now microseconds)
- **Calculation logic:** MATCH ✅ (bulk features are a documented approximation)
- **Model inference:** PASS ✅
- **BENIGN prediction:** PASS ✅ (real model, synthetic benign-like flow)
- **ATTACK prediction:** PASS at decode level (both labels decodable) ✅ —
  **not** validated on real traffic
- **Confidence:** PASS ✅ (∈ [0, 1])
- **Test suite:** PASS ✅ — 32 tests (`python -m unittest discover -s tests`)

### Important
**Real-PCAP testing was NOT performed.** This repository contains no PCAP/`libpcap`
parser or capture layer that produces `PacketRecord`s, and no CICIDS/PCAP data is
committed. Only the extractor → model path was validated using synthetic in-memory
flows plus the real trained model. A capture adapter (`scapy`/`dpkt`/`pyshark`) is
still required to run real traffic through the pipeline.

### Remote note
`0737fc3` and `src/flow_extractor.py` exist on `collab/main`
(`glenjr009/network-traffic-anomaly-detector`), **not** on `origin/main`. The two
remotes have unrelated histories, so this PR is valid against `collab/main`.

### Files changed
```
INFERENCE_INTEGRATION.md        (new)
LIVE_ML_INFERENCE_UPDATES.md    (new)
REQUIREMENTS_COMPLIANCE.md      (new)
src/cicids_features.py          (new)
src/flow_extractor.py           (modified)
src/prediction.py               (modified)
tests/test_flow_extractor.py    (new)
tests/test_prediction.py        (modified)
```
