"""Regression tests pinning our Active/Idle + Bulk features to real Java output.

These tests do **not** require a JDK. They validate the current Python
implementation against ``reports/java_reference_parity.json``, an evidence
artifact produced by ``scripts/java_reference_parity.py`` running the
unmodified CICFlowMeter ``BasicFlow`` sources at pinned commit
``98a5ebad0df579cc8b43eedd3421b3ae87699901`` in a real JVM.

If the Python feature code or the scenarios change, these tests fail, which is
the point: they keep the implementation tied to observed reference behaviour
rather than to source-reading assumptions. Regenerate the JSON with::

    python scripts/java_reference_parity.py --json reports/java_reference_parity.json
"""

import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "java_reference_parity.py"
EVIDENCE_PATH = REPO_ROOT / "reports" / "java_reference_parity.json"
SCENARIO_DIR = REPO_ROOT / "scripts" / "java_reference_parity" / "scenarios"

PINNED_COMMIT = "98a5ebad0df579cc8b43eedd3421b3ae87699901"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "java_reference_parity", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_TOOL = _load_tool()


def _load_evidence():
    if not EVIDENCE_PATH.exists():
        raise unittest.SkipTest(
            f"reference evidence missing: {EVIDENCE_PATH}; regenerate with "
            "python scripts/java_reference_parity.py --json "
            "reports/java_reference_parity.json"
        )
    return json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))


class TestReferenceProvenance(unittest.TestCase):
    def test_evidence_targets_pinned_commit(self):
        evidence = _load_evidence()
        self.assertEqual(evidence["reference"]["commit"], PINNED_COMMIT)
        self.assertEqual(
            evidence["reference"]["harness"],
            "scripts/java_reference_parity/ParityHarness.java",
        )

    def test_evidence_covers_all_scenarios(self):
        evidence = _load_evidence()
        names = {scenario["name"] for scenario in evidence["scenarios"]}
        self.assertEqual(
            names,
            {"active_idle.csv", "bulk_fwd.csv", "bulk_mixed.csv"},
        )


class TestActiveIdleParity(unittest.TestCase):
    """Active/Idle must match the Java reference numerically."""

    def test_python_matches_recorded_java(self):
        evidence = _load_evidence()
        for scenario in evidence["scenarios"]:
            name = scenario["name"]
            java_values = scenario["java"]
            py_values = _TOOL.python_features(name, SCENARIO_DIR)
            for key in _TOOL.ACTIVE_IDLE_KEYS:
                self.assertTrue(
                    _TOOL._close(java_values[key], py_values[key]),
                    f"{name}: {key} java={java_values[key]} "
                    f"python={py_values[key]}",
                )


class TestBulkReferenceBehaviour(unittest.TestCase):
    """Bulk features: reference routing defect and our intended semantics."""

    def _java(self, scenario):
        evidence = _load_evidence()
        for entry in evidence["scenarios"]:
            if entry["name"] == scenario:
                return entry["java"]
        raise AssertionError(f"scenario {scenario} not in evidence")

    def test_reference_forward_bulk_is_always_zero(self):
        # Upstream defect: this.src == packet.getSrc() is always false.
        for scenario in ("active_idle.csv", "bulk_fwd.csv", "bulk_mixed.csv"):
            java_values = self._java(scenario)
            for key in _TOOL.FWD_BULK_KEYS:
                self.assertEqual(
                    java_values[key], 0.0, f"{scenario}: {key}"
                )

    def test_single_direction_python_forward_equals_reference_backward(self):
        # The bulk arithmetic is identical; only the direction routing differs.
        java_values = self._java("bulk_fwd.csv")
        py_values = _TOOL.python_features("bulk_fwd.csv", SCENARIO_DIR)
        for fwd_key, bwd_key in zip(
            _TOOL.FWD_BULK_KEYS, _TOOL.BWD_BULK_KEYS
        ):
            self.assertTrue(
                _TOOL._close(py_values[fwd_key], java_values[bwd_key]),
                f"{fwd_key}={py_values[fwd_key]} vs "
                f"java {bwd_key}={java_values[bwd_key]}",
            )

    def test_mixed_direction_reference_creates_spurious_backward_bulk(self):
        java_values = self._java("bulk_mixed.csv")
        self.assertTrue(
            any(java_values[key] != 0.0 for key in _TOOL.BWD_BULK_KEYS)
        )
        py_values = _TOOL.python_features("bulk_mixed.csv", SCENARIO_DIR)
        for key in _TOOL.FWD_BULK_KEYS + _TOOL.BWD_BULK_KEYS:
            self.assertEqual(py_values[key], 0.0, key)


class TestRecordedChecksPassed(unittest.TestCase):
    def test_all_recorded_checks_passed(self):
        evidence = _load_evidence()
        failed = [
            check["check"]
            for check in evidence["checks"]
            if not check["passed"]
        ]
        self.assertEqual(failed, [])
        self.assertTrue(evidence["passed"])


if __name__ == "__main__":
    unittest.main()
