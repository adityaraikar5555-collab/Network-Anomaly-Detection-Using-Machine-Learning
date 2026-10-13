"""PCAP/PCAPNG ingestion for the live CICIDS-2017 inference pipeline.

This module turns saved capture files into the
:class:`~src.flow_extractor.PacketRecord` objects consumed by
:class:`~src.flow_extractor.FlowExtractor`, using `Scapy
<https://scapy.net/>`_ for packet parsing.

The end-to-end path is::

    PCAP file -> read_packets() -> FlowExtractor -> 78 CICIDS features
             -> existing model -> BENIGN/ATTACK + confidence

Scope and honesty
-----------------
* This reads **saved capture files only**. It does *not* sniff a live network
  interface. (Scapy can do that, but this adapter deliberately does not.)
* Only IPv4 TCP and UDP packets are converted. Everything else (ARP, IPv6,
  ICMP, non-IP frames) is skipped and counted, never fatal.
* Scapy is an *optional* dependency. It is imported lazily so importing
  :mod:`src.pcap_reader` (and running the non-PCAP test suite) works without it.

Safety
------
* A single packet that fails to parse is skipped and counted, never fatal.
* Empty (zero-byte) files, unrecognised magic and non-files raise
  :class:`CaptureReadError`.
* A missing Scapy installation raises :class:`ScapyUnavailableError`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

try:  # Support both "src.pcap_reader" and flat "pcap_reader" import styles.
    from .cicids_features import CICIDS_FEATURE_NAMES
    from .flow_extractor import FlowExtractor, PacketRecord
except ImportError:  # pragma: no cover - fallback for flat imports
    from cicids_features import CICIDS_FEATURE_NAMES
    from flow_extractor import FlowExtractor, PacketRecord

__all__ = [
    "ScapyUnavailableError",
    "CaptureReadError",
    "packet_to_record",
    "read_packets",
    "load_flows",
    "validate_capture",
    "render_markdown_report",
]

PathLike = Union[str, Path]


class ScapyUnavailableError(RuntimeError):
    """Raised when PCAP parsing is requested but Scapy is not installed."""


class CaptureReadError(RuntimeError):
    """Raised when a capture file cannot be opened or parsed at all."""


# Little/big-endian classic libpcap (microsecond and nanosecond variants) plus
# the pcapng section header block magic.
_PCAP_MAGICS = (
    b"\xa1\xb2\xc3\xd4",  # big-endian, microseconds
    b"\xd4\xc3\xb2\xa1",  # little-endian, microseconds
    b"\xa1\xb2\x3c\x4d",  # big-endian, nanoseconds
    b"\x4d\x3c\xb2\xa1",  # little-endian, nanoseconds
)
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _sha256_of_file(path: PathLike, chunk_size: int = 1 << 20) -> str:
    """Return the lowercase hex SHA-256 of a file (streamed, not loaded)."""

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _display_path(path: PathLike, base: PathLike) -> str:
    """Return ``path`` relative to ``base`` (POSIX separators) when possible."""

    try:
        return Path(path).resolve().relative_to(Path(base).resolve()).as_posix()
    except ValueError:
        return str(path)


def _import_scapy():
    """Import and return the Scapy pieces we need, or raise a clear error."""

    try:
        # Scapy prints a harmless "No libpcap provider available" warning on
        # Windows during import; suppress it. The pure-Python readers do not
        # need libpcap.
        import contextlib
        import io

        with contextlib.redirect_stderr(io.StringIO()):
            from scapy.layers.inet import IP, TCP, UDP  # type: ignore
            from scapy.layers.l2 import Ether  # type: ignore
            from scapy.utils import PcapNgReader, PcapReader  # type: ignore
    except Exception as exc:  # pragma: no cover - only without scapy
        if isinstance(exc, (ImportError, ModuleNotFoundError)):
            raise ScapyUnavailableError(
                "Reading PCAP files requires the optional 'scapy' dependency. "
                "Install it with:  pip install scapy"
            ) from exc
        raise

    try:
        import logging

        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    except Exception:  # pragma: no cover
        pass

    return IP, TCP, UDP, PcapReader, PcapNgReader


def packet_to_record(packet: Any, IP: Any, TCP: Any, UDP: Any) -> Optional[PacketRecord]:
    """Convert one Scapy packet into a :class:`PacketRecord`.

    Returns ``None`` for packets that are not IPv4 TCP/UDP (they are
    unsupported rather than malformed). Malformed packets are expected to be
    filtered by the caller, which catches conversion exceptions per packet.

    Preserved fields: timestamp, src/dst addresses and ports, protocol, full
    frame length, IP header length, transport header length, application
    payload length, TCP flags and advertised window.
    """

    if IP not in packet:
        return None
    if TCP not in packet and UDP not in packet:
        return None

    ip_layer = packet[IP]
    protocol = int(ip_layer.proto)

    if TCP in packet:
        transport = packet[TCP]
        dataofs = transport.dataofs
        try:
            tcp_header_length = int(dataofs) * 4 if dataofs else 20
        except Exception:
            tcp_header_length = 20
        tcp_window_size = int(transport.window or 0)
        flags = int(transport.flags)
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)
        psh = bool(flags & 0x08)
        urg = bool(flags & 0x20)
        ece = bool(flags & 0x40)
        cwe = bool(flags & 0x80)
    else:
        transport = packet[UDP]
        tcp_header_length = 8  # UDP header is a fixed 8 bytes
        tcp_window_size = 0
        syn = ack = fin = rst = psh = urg = ece = cwe = False

    # Application-layer payload (0 for header-only packets).
    payload_length = len(transport.payload)

    ip_header_length = int(ip_layer.ihl or 0) * 4
    if ip_header_length <= 0:
        ip_header_length = 20
    if TCP in packet:
        dataofs = getattr(packet[TCP], 'dataofs', None)
        try:
            thl = int(dataofs) * 4 if dataofs else tcp_header_length
        except Exception:
            thl = tcp_header_length or 20
        if thl <= 0:
            thl = 20
        tcp_header_length = thl

    return PacketRecord(
        timestamp=float(packet.time),
        src_ip=str(ip_layer.src),
        dst_ip=str(ip_layer.dst),
        src_port=int(transport.sport),
        dst_port=int(transport.dport),
        protocol=protocol,
        # Full captured frame length, matching CICFlowMeter's len(packet).
        length=int(len(packet)),
        ip_header_length=ip_header_length,
        tcp_header_length=tcp_header_length,
        payload_length=payload_length,
        tcp_window_size=tcp_window_size,
        syn=syn,
        ack=ack,
        fin=fin,
        rst=rst,
        psh=psh,
        urg=urg,
        cwe=cwe,
        ece=ece,
)


def read_packets(
    pcap_path: PathLike,
    *,
    max_packets: Optional[int] = None,
    stats: Optional[Dict[str, int]] = None,
) -> Iterator[PacketRecord]:
    """Yield :class:`PacketRecord` objects parsed from ``pcap_path``.

    Args:
        pcap_path: Path to a ``.pcap`` or ``.pcapng`` capture file.
        max_packets: Optional cap on the number of *usable* packets yielded.
        stats: Optional mutable mapping that is updated with counters:
            ``{"usable": n, "unsupported": n, "malformed": n}``.

    Yields:
        One :class:`PacketRecord` per usable IPv4 TCP/UDP packet.

    Raises:
        FileNotFoundError: If the capture file does not exist.
        ScapyUnavailableError: If Scapy is not installed.
        CaptureReadError: If the capture cannot be opened/parsed, is empty, or
            has unrecognised magic bytes.
    """

    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")
    if not path.is_file():
        raise CaptureReadError(f"PCAP path is not a file: {path}")
    if path.stat().st_size == 0:
        raise CaptureReadError(f"PCAP file is empty (0 bytes): {path}")

    with open(path, "rb") as handle:
        magic = handle.read(4)

    IP, TCP, UDP, PcapReader, PcapNgReader = _import_scapy()

    if magic == _PCAPNG_MAGIC:
        reader_factory = PcapNgReader
        reader_kwargs: Dict[str, Any] = {}
    elif magic in _PCAP_MAGICS:
        reader_factory = PcapReader
        reader_kwargs = {}
    else:
        raise CaptureReadError(
            f"File is not a recognised PCAP/PCAPNG capture: {path}"
        )

    counters = stats if stats is not None else {}
    counters.setdefault("usable", 0)
    counters.setdefault("unsupported", 0)
    counters.setdefault("malformed", 0)

    try:
        reader = reader_factory(str(path), **reader_kwargs)
    except Exception as exc:  # pragma: no cover - defensive
        raise CaptureReadError(
            f"Could not open capture '{path}' as a PCAP file: {exc}"
        ) from exc

    yielded = 0
    try:
        for raw_packet in reader:
            try:
                record = packet_to_record(raw_packet, IP, TCP, UDP)
            except Exception:
                # A single malformed packet must never abort the whole run.
                counters["malformed"] += 1
                continue

            if record is None:
                counters["unsupported"] += 1
                continue

            counters["usable"] += 1
            yield record
            yielded += 1
            if max_packets is not None and yielded >= max_packets:
                break
    except Exception as exc:  # truncated / corrupt stream mid-parse
        raise CaptureReadError(
            f"Error while reading capture '{path}': {exc}"
        ) from exc
    finally:
        try:
            reader.close()
        except Exception:
            pass


def load_flows(
    pcap_path: PathLike,
    *,
    max_packets: Optional[int] = None,
    stats: Optional[Dict[str, int]] = None,
) -> FlowExtractor:
    """Parse ``pcap_path`` and return a populated :class:`FlowExtractor`."""

    extractor = FlowExtractor()
    for record in read_packets(pcap_path, max_packets=max_packets, stats=stats):
        extractor.add_packet(record)
    return extractor


def validate_capture(
    pcap_path: PathLike,
    model_path: Optional[PathLike] = None,
    encoder_path: Optional[PathLike] = None,
    *,
    max_packets: Optional[int] = None,
) -> Dict[str, Any]:
    """Run the full ``PCAP -> features -> model -> prediction`` pipeline.

    Args:
        pcap_path: Path to the capture to analyse.
        model_path: Optional override for the trained model ``.pkl``.
        encoder_path: Optional override for the label encoder ``.pkl``.
        max_packets: Optional cap on usable packets parsed.

    Returns:
        A JSON-serialisable report dictionary with keys:

        * ``pcap``, ``pcap_filename``, ``pcap_sha256``, ``pcap_size_bytes``
        * ``packet_count``, ``flow_count``
        * ``skipped_unsupported``, ``skipped_malformed``
        * ``schema_ok`` (bool) and ``schema_errors`` (list)
        * ``flows`` (list of per-flow prediction records)
        * ``label_counts`` (``{"BENIGN": n, "ATTACK": n}``)
        * ``model_path``, ``encoder_path`` (resolved artifact paths)
        * ``errors`` (list of non-fatal error strings)

        The same dictionary is the single source for both the JSON and the
        Markdown report (see :func:`render_markdown_report`), so the two can
        never disagree.
    """

    # Imported lazily to avoid a hard dependency on scikit-learn/joblib at
    # module import time.
    try:
        from .prediction import load_cicids_artifacts, predict_cicids
    except ImportError:  # pragma: no cover - flat import fallback
        from prediction import load_cicids_artifacts, predict_cicids

    model, encoder = load_cicids_artifacts(
        model_path=model_path, encoder_path=encoder_path
    )

    repo_root = Path(__file__).resolve().parent.parent
    resolved_model = (
        Path(model_path) if model_path else repo_root / "models" / "cicids_anomaly_model.pkl"
    )
    resolved_encoder = (
        Path(encoder_path) if encoder_path else repo_root / "models" / "cicids_label_encoder.pkl"
    )

    stats: Dict[str, int] = {"usable": 0, "unsupported": 0, "malformed": 0}
    extractor = FlowExtractor()
    for record in read_packets(pcap_path, max_packets=max_packets, stats=stats):
        extractor.add_packet(record)

    expected_names = list(CICIDS_FEATURE_NAMES)
    flows_report: List[Dict[str, Any]] = []
    label_counts = {"BENIGN": 0, "ATTACK": 0}
    errors: List[str] = []
    schema_errors: List[str] = []

    for index, flow in enumerate(extractor.get_flows()):
        try:
            features = flow.extract_features()
        except Exception as exc:
            errors.append(f"flow {index}: feature extraction failed: {exc}")
            continue

        if list(features.keys()) != expected_names:
            schema_errors.append(
                f"flow {index}: feature schema mismatch "
                f"(got {len(features)} keys)"
            )
            continue

        try:
            result = predict_cicids(features, model=model, label_encoder=encoder)
        except Exception as exc:
            errors.append(f"flow {index}: prediction failed: {exc}")
            continue

        label = result["prediction"]
        if label in label_counts:
            label_counts[label] += 1

        source = flow.forward_packets[0] if flow.forward_packets else flow.packets[0]
        flows_report.append(
            {
                "flow_index": index,
                "src": f"{source.src_ip}:{source.src_port}",
                "dst": f"{source.dst_ip}:{source.dst_port}",
                "protocol": source.protocol,
                "packets": len(flow.packets),
                "fwd_packets": flow.total_fwd_packets,
                "bwd_packets": flow.total_backward_packets,
                "prediction": label,
                "confidence": result["confidence"],
                "model": result["model"],
            }
        )

    capture = Path(pcap_path)
    return {
        "pcap": str(pcap_path),
        "pcap_filename": capture.name,
        "pcap_sha256": _sha256_of_file(capture),
        "pcap_size_bytes": capture.stat().st_size,
        "packet_count": stats["usable"],
        "flow_count": len(flows_report),
        "skipped_unsupported": stats["unsupported"],
        "skipped_malformed": stats["malformed"],
        "schema_ok": not schema_errors,
        "schema_errors": schema_errors,
        "flows": flows_report,
        "label_counts": label_counts,
        "model_path": _display_path(resolved_model, repo_root),
        "encoder_path": _display_path(resolved_encoder, repo_root),
        "errors": errors,
    }


def _md_table_row(cells: List[Any]) -> str:
    return "| " + " | ".join(str(cell) for cell in cells) + " |"


def render_markdown_report(report: Dict[str, Any]) -> str:
    """Render a human-readable Markdown report from a ``validate_capture`` result.

    The Markdown is derived **entirely** from the same dictionary that is
    serialised to JSON, so packet/flow counts, per-flow forward/backward splits
    and predictions can never disagree between the two formats. Optional
    provenance keys (``command``, ``generated_at``, ``environment``) are included
    when present.
    """

    filename = report.get("pcap_filename") or Path(report.get("pcap", "")).name
    lines: List[str] = []

    lines.append("# PCAP -> CICIDS-2017 Inference Validation Report")
    lines.append("")
    lines.append(
        "> Auto-generated by `scripts/validate_pcap.py`. Every value below is "
        "rendered from the same result object that is written to the JSON "
        "report; do not hand-edit."
    )
    lines.append("")

    # 1. Provenance
    lines.append("## 1. Capture provenance")
    lines.append("")
    lines.append(_md_table_row(["Field", "Value"]))
    lines.append(_md_table_row(["---", "---"]))
    lines.append(_md_table_row(["Capture file", f"`{filename}`"]))
    lines.append(_md_table_row(["SHA-256", f"`{report.get('pcap_sha256', 'n/a')}`"]))
    size = report.get("pcap_size_bytes")
    lines.append(
        _md_table_row(
            ["Size (bytes)", size if size is not None else "n/a"]
        )
    )
    lines.append(_md_table_row(["Model", f"`{report.get('model_path', 'n/a')}`"]))
    lines.append(_md_table_row(["Label encoder", f"`{report.get('encoder_path', 'n/a')}`"]))
    if report.get("generated_at"):
        lines.append(_md_table_row(["Generated at (UTC)", report["generated_at"]]))
    if report.get("command"):
        lines.append(_md_table_row(["Command", f"`{report['command']}`"]))
    lines.append("")

    # 2. Environment
    environment = report.get("environment") or {}
    if environment:
        lines.append("## 2. Environment")
        lines.append("")
        lines.append(_md_table_row(["Component", "Version"]))
        lines.append(_md_table_row(["---", "---"]))
        for key, value in environment.items():
            lines.append(_md_table_row([key, value]))
        lines.append("")

    # 3. Packet / flow summary
    lines.append("## 3. Packet and flow summary")
    lines.append("")
    lines.append(_md_table_row(["Metric", "Value"]))
    lines.append(_md_table_row(["---", "---"]))
    lines.append(_md_table_row(["Usable packets", report.get("packet_count", 0)]))
    lines.append(_md_table_row(["Skipped (unsupported)", report.get("skipped_unsupported", 0)]))
    lines.append(_md_table_row(["Skipped (malformed)", report.get("skipped_malformed", 0)]))
    lines.append(_md_table_row(["Extracted flows", report.get("flow_count", 0)]))
    lines.append("")

    # 4. Schema validation
    lines.append("## 4. Feature schema validation")
    lines.append("")
    lines.append(f"- Schema OK: **{report.get('schema_ok')}**")
    schema_errors = report.get("schema_errors") or []
    if schema_errors:
        for error in schema_errors:
            lines.append(f"- {error}")
    else:
        lines.append("- No schema errors.")
    lines.append("")

    # 5. Per-flow predictions
    lines.append("## 5. Per-flow predictions")
    lines.append("")
    flows = report.get("flows") or []
    if flows:
        lines.append(
            _md_table_row(
                [
                    "Flow",
                    "Source",
                    "Destination",
                    "Proto",
                    "Packets",
                    "Fwd",
                    "Bwd",
                    "Prediction",
                    "Confidence",
                ]
            )
        )
        lines.append(
            _md_table_row(["---"] * 9)
        )
        for flow in flows:
            lines.append(
                _md_table_row(
                    [
                        flow.get("flow_index"),
                        f"`{flow.get('src')}`",
                        f"`{flow.get('dst')}`",
                        flow.get("protocol"),
                        flow.get("packets"),
                        flow.get("fwd_packets"),
                        flow.get("bwd_packets"),
                        f"**{flow.get('prediction')}**",
                        f"{float(flow.get('confidence', 0.0)):.4f}",
                    ]
                )
            )
    else:
        lines.append("_No flows were extracted._")
    lines.append("")

    label_counts = report.get("label_counts") or {}
    lines.append(
        "- Label counts: "
        + ", ".join(f"{key}={value}" for key, value in label_counts.items())
    )
    lines.append("")

    # 6. Errors
    errors = report.get("errors") or []
    if errors:
        lines.append("## 6. Non-fatal errors")
        lines.append("")
        for error in errors:
            lines.append(f"- {error}")
        lines.append("")

    return "\n".join(lines) + "\n"
