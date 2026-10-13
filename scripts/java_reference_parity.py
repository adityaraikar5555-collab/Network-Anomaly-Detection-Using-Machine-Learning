#!/usr/bin/env python
"""Validate Active/Idle and Bulk features against the real Java CICFlowMeter.

This tooling exists because the Python ``cicflowmeter`` port is a
re-implementation, not the authoritative reference, and because source-reading
alone cannot establish numerical parity. It compiles and executes the
**unmodified** reference feature sources from ahlashkari/CICFlowMeter at a
pinned commit and compares their output, feature by feature, with our
``src.flow_extractor`` implementation on identical deterministic scenarios.

What is exercised
-----------------
``BasicFlow`` -> ``updateActiveIdleTime`` / ``updateFlowBulk`` (via
``addPacket``) and the feature getters. ``BasicPacketInfo`` is populated
programmatically, so the reference *feature arithmetic* is validated. The
reference's libpcap/jnetpcap packet decoding is **not** exercised.

Pinned reference
----------------
commit 98a5ebad0df579cc8b43eedd3421b3ae87699901
(https://github.com/ahlashkari/CICFlowMeter)

Tasks
-----
1. Resolve a checkout of the pinned reference (``--reference-dir``, else the
   ``CICFLOWMETER_REF_DIR`` environment variable, else clone into a temp dir).
2. Compile the four reference sources plus ``ParityHarness.java`` with the JDK.
3. Run the harness on each scenario.
4. Compute the same features with ``src.flow_extractor``.
5. Report agreement / documented deviation and optionally write JSON.

Requirements: a JDK (``javac`` + ``java``) and network access on first run
(to clone the reference and fetch ``commons-math3``). Missing requirements
are reported as BLOCKED with exit code 2 rather than fabricated as success.

Known upstream deviation
------------------------
In the pinned revision ``BasicFlow.updateFlowBulk`` routes every packet with
``this.src == packet.getSrc()``. Because ``BasicPacketInfo.getSrc()`` returns a
fresh ``Arrays.copyOf`` array, that reference comparison is always false, so
**all** payload packets are fed to the backward bulk state machine and the
forward bulk features are structurally zero. Our implementation implements the
intended per-direction semantics. The comparison asserts this relationship
explicitly instead of hiding it.

Usage::

    python scripts/java_reference_parity.py
    python scripts/java_reference_parity.py --json reports/java_reference_parity.json

Exit codes: 0 = parity checks passed, 1 = a parity check failed,
2 = prerequisites missing (BLOCKED).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.flow_extractor import NetworkFlow, PacketRecord  # noqa: E402

HERE = Path(__file__).resolve().parent
HARNESS_DIR = HERE / "java_reference_parity"
DEFAULT_SCENARIO_DIR = HARNESS_DIR / "scenarios"

PINNED_COMMIT = "98a5ebad0df579cc8b43eedd3421b3ae87699901"
REFERENCE_URL = "https://github.com/ahlashkari/CICFlowMeter.git"
COMMONS_MATH_URL = (
    "https://repo1.maven.org/maven2/org/apache/commons/"
    "commons-math3/3.5/commons-math3-3.5.jar"
)

REFERENCE_SOURCES = [
    "src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java",
    "src/main/java/cic/cs/unb/ca/jnetpcap/BasicPacketInfo.java",
    "src/main/java/cic/cs/unb/ca/jnetpcap/IdGenerator.java",
    "src/main/java/cic/cs/unb/ca/jnetpcap/DateFormatter.java",
]

FEATURE_KEYS = [
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
]

ACTIVE_IDLE_KEYS = FEATURE_KEYS[:8]
FWD_BULK_KEYS = FEATURE_KEYS[8:11]
BWD_BULK_KEYS = FEATURE_KEYS[11:]


class BlockedError(RuntimeError):
    """A prerequisite (JDK, git, network, reference) is unavailable."""


def _which(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise BlockedError(f"required executable not found on PATH: {name}")
    return path


def _run(cmd, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
        **kwargs,
    )


def resolve_reference(args) -> Path:
    ref = args.reference_dir or os.environ.get("CICFLOWMETER_REF_DIR")
    ref = Path(ref) if ref else Path(tempfile.gettempdir()) / "cicflowmeter_ref"
    git_dir = ref / ".git"

    if not git_dir.exists():
        _which("git")
        ref.parent.mkdir(parents=True, exist_ok=True)
        print(f"[ref] cloning {REFERENCE_URL} -> {ref}")
        _run(["git", "clone", REFERENCE_URL, str(ref)])

    rev = _run(["git", "-C", str(ref), "rev-parse", "HEAD"]).stdout.strip()
    if rev != PINNED_COMMIT:
        print(f"[ref] checking out pinned commit {PINNED_COMMIT}")
        _run(["git", "-C", str(ref), "checkout", PINNED_COMMIT])
        rev = _run(["git", "-C", str(ref), "rev-parse", "HEAD"]).stdout.strip()
    if rev != PINNED_COMMIT:
        raise BlockedError(
            f"reference is at {rev}, expected pinned {PINNED_COMMIT}"
        )
    print(f"[ref] using {ref} @ {rev}")
    return ref


def find_jnetpcap_jar(ref: Path) -> Path:
    jars = sorted(ref.glob("jnetpcap/**/jnetpcap.jar"))
    if not jars:
        raise BlockedError("bundled jnetpcap.jar not found in reference checkout")
    preferred = "win" if os.name == "nt" else "linux"
    for jar in jars:
        if preferred in jar.parts:
            return jar
    return jars[0]


def ensure_commons_math(work_dir: Path) -> Path:
    cache = work_dir / "jars" / "commons-math3-3.5.jar"
    if cache.exists():
        return cache
    cache.parent.mkdir(parents=True, exist_ok=True)
    print(f"[dep] downloading {COMMONS_MATH_URL}")
    try:
        urllib.request.urlretrieve(COMMONS_MATH_URL, cache)
    except Exception as exc:  # pragma: no cover - network failure path
        raise BlockedError(
            f"could not download commons-math3 and no cached copy at {cache}"
        ) from exc
    return cache


def compile_harness(javac, ref, work_dir, commons_jar, jnetpcap_jar) -> Path:
    classes = work_dir / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    classpath = os.pathsep.join([str(jnetpcap_jar), str(commons_jar)])
    sources = [str(ref / src) for src in REFERENCE_SOURCES]
    sources.append(str(HARNESS_DIR / "ParityHarness.java"))
    print("[build] compiling reference sources + ParityHarness")
    _run(
        [javac, "-encoding", "UTF-8", "-d", str(classes),
         "-cp", classpath, *sources]
    )
    return classes


def run_java_harness(java, classes, jnetpcap_jar, commons_jar, scenario) -> dict:
    classpath = os.pathsep.join([str(classes), str(jnetpcap_jar), str(commons_jar)])
    proc = _run([java, "-cp", classpath, "ParityHarness", str(scenario)])
    values = {}
    for line in proc.stdout.splitlines():
        if "=" not in line:
            continue
        key, _, raw = line.partition("=")
        key = key.strip()
        if key == "packet_count":
            continue
        values[key] = float(raw.strip())
    return values


def load_scenario(name: str, scenario_dir: Path):
    records = []
    with (scenario_dir / name).open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            records.append(
                PacketRecord(
                    timestamp=int(row["ts_us"]) / 1_000_000.0,
                    src_ip=row["srcIp"],
                    dst_ip=row["dstIp"],
                    src_port=int(row["srcPort"]),
                    dst_port=int(row["dstPort"]),
                    protocol=int(row["protocol"]),
                    length=int(row["payloadBytes"]) + int(row["headerBytes"]),
                    ip_header_length=20,
                    tcp_header_length=int(row["headerBytes"]),
                    payload_length=int(row["payloadBytes"]),
                    syn=row["syn"] == "1",
                    ack=row["ack"] == "1",
                    fin=row["fin"] == "1",
                    rst=row["rst"] == "1",
                    psh=row["psh"] == "1",
                    urg=row["urg"] == "1",
                    cwe=row["cwr"] == "1",
                    ece=row["ece"] == "1",
                    tcp_window_size=int(row["tcpWindow"]),
                )
            )
    return records


def python_features(name: str, scenario_dir: Path) -> dict:
    records = load_scenario(name, scenario_dir)
    src_ip = records[0].src_ip
    flow = NetworkFlow(
        key=(
            src_ip,
            records[0].dst_ip,
            records[0].src_port,
            records[0].dst_port,
            records[0].protocol,
        )
    )
    for packet in records:
        flow.add_packet(packet, forward=(packet.src_ip == src_ip))

    features = {}
    features.update(flow.chunk11_features())
    features.update(flow._bulk_features())
    return {key: float(features[key]) for key in FEATURE_KEYS}


def _close(a: float, b: float, rel_tol: float = 1e-9, abs_tol: float = 1e-9) -> bool:
    return abs(a - b) <= max(abs_tol, rel_tol * max(abs(a), abs(b)))


def compare_scenario(name, java_values, py_values) -> list:
    checks = []

    for key in ACTIVE_IDLE_KEYS:
        checks.append(
            {
                "check": f"active_idle:{name}:{key}",
                "passed": _close(java_values[key], py_values[key]),
                "java": java_values[key],
                "python": py_values[key],
            }
        )

    # Forward and backward bulk features are positionally aligned (Bytes,
    # Packets, Rate), so the reference's backward triple can be compared to our
    # forward triple element-wise.
    java_fwd = [java_values[k] for k in FWD_BULK_KEYS]
    java_bwd = [java_values[k] for k in BWD_BULK_KEYS]
    py_fwd = [py_values[k] for k in FWD_BULK_KEYS]
    py_bwd = [py_values[k] for k in BWD_BULK_KEYS]

    def as_dict(keys, values):
        return dict(zip(keys, values))

    if name == "active_idle.csv":
        all_zero = all(
            v == 0.0 for v in java_fwd + java_bwd + py_fwd + py_bwd
        )
        checks.append(
            {
                "check": f"bulk:{name}:all_zero",
                "passed": all_zero,
                "java_fwd": as_dict(FWD_BULK_KEYS, java_fwd),
                "java_bwd": as_dict(BWD_BULK_KEYS, java_bwd),
                "python_fwd": as_dict(FWD_BULK_KEYS, py_fwd),
                "python_bwd": as_dict(BWD_BULK_KEYS, py_bwd),
            }
        )
    elif name == "bulk_fwd.csv":
        # Single-direction flow: the reference's forward counter is always 0
        # (upstream routing defect); our forward values must equal the
        # reference's backward values, and our backward values must be 0.
        checks.append(
            {
                "check": f"bulk:{name}:reference_forward_is_zero",
                "passed": all(v == 0.0 for v in java_fwd),
                "java_fwd": as_dict(FWD_BULK_KEYS, java_fwd),
            }
        )
        checks.append(
            {
                "check": f"bulk:{name}:python_forward_equals_reference_backward",
                "passed": all(
                    _close(pf, jb) for pf, jb in zip(py_fwd, java_bwd)
                ),
                "python_fwd": as_dict(FWD_BULK_KEYS, py_fwd),
                "java_bwd": as_dict(BWD_BULK_KEYS, java_bwd),
            }
        )
        checks.append(
            {
                "check": f"bulk:{name}:python_backward_is_zero",
                "passed": all(v == 0.0 for v in py_bwd),
                "python_bwd": as_dict(BWD_BULK_KEYS, py_bwd),
            }
        )
    elif name == "bulk_mixed.csv":
        # Interleaved directions: the reference lumps every payload packet into
        # one backward bulk; a correct per-direction implementation produces no
        # bulk at all.
        checks.append(
            {
                "check": f"bulk:{name}:reference_forward_is_zero",
                "passed": all(v == 0.0 for v in java_fwd),
                "java_fwd": as_dict(FWD_BULK_KEYS, java_fwd),
            }
        )
        checks.append(
            {
                "check": f"bulk:{name}:reference_backward_nonzero",
                "passed": any(v != 0.0 for v in java_bwd),
                "java_bwd": as_dict(BWD_BULK_KEYS, java_bwd),
            }
        )
        checks.append(
            {
                "check": f"bulk:{name}:python_all_zero",
                "passed": all(v == 0.0 for v in py_fwd + py_bwd),
                "python_fwd": as_dict(FWD_BULK_KEYS, py_fwd),
                "python_bwd": as_dict(BWD_BULK_KEYS, py_bwd),
            }
        )

    return checks


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reference-dir", default=None,
                        help="Existing CICFlowMeter checkout (else clone).")
    parser.add_argument("--scenario-dir", default=str(DEFAULT_SCENARIO_DIR))
    parser.add_argument("--work-dir", default=None,
                        help="Scratch dir for jars/classes (default: temp).")
    parser.add_argument("--json", dest="json_path", default=None)
    args = parser.parse_args(argv)

    scenario_dir = Path(args.scenario_dir)
    scenarios = sorted(p.name for p in scenario_dir.glob("*.csv"))
    if not scenarios:
        print(f"ERROR: no scenarios found in {scenario_dir}", file=sys.stderr)
        return 2

    work_dir = Path(args.work_dir) if args.work_dir else (
        Path(tempfile.gettempdir()) / "java_reference_parity"
    )
    work_dir.mkdir(parents=True, exist_ok=True)

    try:
        java = _which("java")
        javac = _which("javac")
        ref = resolve_reference(args)
        jnetpcap_jar = find_jnetpcap_jar(ref)
        commons_jar = ensure_commons_math(work_dir)
        classes = compile_harness(
            javac, ref, work_dir, commons_jar, jnetpcap_jar
        )
    except BlockedError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        print(f"BLOCKED: build failed:\n{exc.stderr}", file=sys.stderr)
        return 2

    java_version = subprocess.run(
        [java, "-version"], capture_output=True, text=True
    ).stderr.splitlines()[0]

    report = {
        "reference": {
            "url": REFERENCE_URL,
            "commit": PINNED_COMMIT,
            "sources": REFERENCE_SOURCES,
            "harness": "scripts/java_reference_parity/ParityHarness.java",
        },
        "runtime": {
            "java": java_version,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "scenarios": [],
        "checks": [],
    }

    all_passed = True
    print("=" * 72)
    print("CICFlowMeter Java reference parity (Active/Idle + Bulk)")
    print("=" * 72)
    print(f"reference : {REFERENCE_URL} @ {PINNED_COMMIT}")
    print(f"runtime   : {java_version}")
    print()

    for name in scenarios:
        try:
            java_values = run_java_harness(
                java, classes, jnetpcap_jar, commons_jar, scenario_dir / name
            )
        except subprocess.CalledProcessError as exc:
            print(f"BLOCKED: harness failed on {name}:\n{exc.stderr}",
                  file=sys.stderr)
            return 2
        py_values = python_features(name, scenario_dir)
        checks = compare_scenario(name, java_values, py_values)
        all_passed = all_passed and all(c["passed"] for c in checks)

        report["scenarios"].append(
            {"name": name, "java": java_values, "python": py_values}
        )
        report["checks"].extend(checks)

        print(f"--- {name} ---")
        for key in FEATURE_KEYS:
            flag = "" if _close(java_values[key], py_values[key]) else "  (deviates)"
            print(
                f"  {key:<24} java={java_values[key]:<22g} "
                f"python={py_values[key]:g}{flag}"
            )
        for check in checks:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"    [{status}] {check['check']}")
        print()

    report["passed"] = all_passed

    if args.json_path:
        Path(args.json_path).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_path).write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        print(f"JSON report written to: {args.json_path}")

    if all_passed:
        print("ALL PARITY CHECKS PASSED")
        return 0
    print("PARITY CHECKS FAILED", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
