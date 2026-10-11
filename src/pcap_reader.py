"""PCAP ingestion for the live CICIDS-2017 inference pipeline.

This module turns raw capture files into the :class:`~src.flow_extractor.PacketRecord`
objects consumed by :class:`~src.flow_extractor.FlowExtractor`, using `Scapy
<https://scapy.net/>`_ for packet parsing.

The end-to-end path is::

    PCAP file -> read_packets() -> FlowExtractor -> 78 CICIDS features
             -> existing model -> BENIGN/ATTACK + confidence

Scapy is an *optional* dependency: it is only required to read PCAP files. This
module imports it lazily so that importing :mod:`src.pcap_reader` (and running the
non-PCAP test suite) never fails when Scapy is absent.

Handled safely:

* TCP and UDP flows (bidirectional grouping is delegated to ``FlowExtractor``).
* Non-IP / non-TCP / non-UDP packets are skipped.
* Packets that fail to parse are skipped and counted, never fatal.
* Empty (zero-packet) captures produce zero flows without error.
* Nonexistent or unreadable files raise a clear exception.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from .cicids_features import CICIDS_FEATURE_NAMES
from .flow_extractor import FlowExtractor, PacketRecord

__all__ = [
    "ScapyUnavailableError",
    "CaptureReadError",
    "read_packets",
    "load_flows",
    "validate_capture",
]

PathLike = Union[str, Path]


class ScapyUnavailableError(RuntimeError):
    """Raised when PCAP parsing is requested but Scapy is not installed."""


class CaptureReadError(RuntimeError):
    """Raised when a capture file cannot be opened or parsed at all."""


# Little/big-endian classic libpcap plus the nanosecond variant and pcapng.
_PCAP_MAGICS = (
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",
)


def _import_scapy():
    """Import and return the Scapy pieces we need, or raise a clear error."""

    try:
        # Scapy prints a harmless "No libpcap provider available" warning on
        # Windows during import; redirect it while importing, then quiet its
        # logger. The pure-python pcap reader does not need libpcap.
        import contextlib
        import io

        with contextlib.redirect_stderr(io.StringIO()):
            from scapy.layers.inet import IP, TCP, UDP  # type: ignore
            from scapy.utils import PcapReader  # type: ignore
    except Exception as exc:  # pragma: no cover - exercised only without scapy
        if isinstance(exc, (ImportError, ModuleNotFoundError)):
            raise ScapyUnavailableError(
                "Reading PCAP files requires the optional 'scapy' dependency. "
                "Install it with:  pip install scapy"
            ) from exc
        raise

    try:
        import logging

        logging.getLogger("scapy").setLevel(logging.ERROR)
    except Exception:  # pragma: no cover
        pass
    return IP, TCP, UDP, PcapReader


def _packet_to_record(packet: Any, IP: Any, TCP: Any, UDP: Any) -> Optional[PacketRecord]:
    """Convert one Scapy packet into a :class:`PacketRecord`.

    Returns ``None`` for packets we cannot use (no IP layer, or no TCP/UDP
    transport). Malformed packets are expected to be filtered by the caller.
    """

    if IP not in packet:
        return None
    if TCP not in packet and UDP not in packet:
        return None

    ip_layer = packet[IP]
    protocol = int(ip_layer.proto)

    if TCP in packet:
        transport = packet[TCP]
        tcp_header_length = int(transport.dataofs or 0) * 4
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

    # Application-layer payload (0 for header-only packets). Used for the
    # payload-based features (act_data_pkt_fwd, bulk statistics).
    payload_length = len(transport.payload)

    return PacketRecord(
        timestamp=float(packet.time),
        src_ip=str(ip_layer.src),
        dst_ip=str(ip_layer.dst),
        src_port=int(transport.sport),
        dst_port=int(transport.dport),
        protocol=protocol,
        # Full captured frame length (matches CICFlowMeter's len(packet)).
        length=int(len(packet)),
        ip_header_length=int(ip_layer.ihl or 0) * 4,
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
) -> Iterator[PacketRecord]:
    """Yield :class:`PacketRecord` objects parsed from ``pcap_path``.

    Args:
        pcap_path: Path to a ``.pcap`` (or ``.pcapng``) capture file.
        max_packets: Optional cap on the number of *usable* packets yielded.

    Yields:
        One :class:`PacketRecord` per usable TCP/UDP packet.

    Raises:
        FileNotFoundError: If the capture file does not exist.
        ScapyUnavailableError: If Scapy is not installed.
        CaptureReadError: If the capture cannot be opened/parsed or is an
            empty (zero-length) file.
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
    if magic not in _PCAP_MAGICS:
        raise CaptureReadError(
            f"File is not a recognised PCAP/PCAPNG capture: {path}"
        )

    IP, TCP, UDP, PcapReader = _import_scapy()

    yielded = 0
    try:
        reader = PcapReader(str(path))
    except Exception as exc:  # unreadable / wrong magic
        raise CaptureReadError(
            f"Could not open capture '{path}' as a PCAP file: {exc}"
        ) from exc

    try:
        for raw_packet in reader:
            try:
                record = _packet_to_record(raw_packet, IP, TCP, UDP)
            except Exception:
                # A single malformed packet should never abort the whole run.
                continue
            if record is None:
                continue
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
) -> FlowExtractor:
    """Parse ``pcap_path`` and return a populated :class:`FlowExtractor`."""

    extractor = FlowExtractor()
    for record in read_packets(pcap_path, max_packets=max_packets):
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

        * ``pcap``, ``packet_count``, ``flow_count``
        * ``schema_ok`` (bool) and ``schema_errors`` (list)
        * ``flows`` (list of per-flow prediction records)
        * ``label_counts`` (``{"BENIGN": n, "ATTACK": n}``)
        * ``errors`` (list of non-fatal error strings)
    """

    # Imported lazily to avoid a hard dependency on scikit-learn/joblib at
    # module import time.
    from .prediction import load_cicids_artifacts, predict_cicids

    model, encoder = load_cicids_artifacts(
        model_path=model_path, encoder_path=encoder_path
    )

    packet_count = 0
    extractor = FlowExtractor()
    for record in read_packets(pcap_path, max_packets=max_packets):
        extractor.add_packet(record)
        packet_count += 1

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

        src = flow.forward_packets[0] if flow.forward_packets else flow.packets[0]
        flows_report.append(
            {
                "flow_index": index,
                "src": f"{src.src_ip}:{src.src_port}",
                "dst": f"{src.dst_ip}:{src.dst_port}",
                "protocol": src.protocol,
                "packets": len(flow.packets),
                "fwd_packets": flow.total_fwd_packets,
                "bwd_packets": flow.total_backward_packets,
                "prediction": label,
                "confidence": result["confidence"],
                "model": result["model"],
            }
        )

    return {
        "pcap": str(pcap_path),
        "packet_count": packet_count,
        "flow_count": len(flows_report),
        "schema_ok": not schema_errors,
        "schema_errors": schema_errors,
        "flows": flows_report,
        "label_counts": label_counts,
        "errors": errors,
    }
