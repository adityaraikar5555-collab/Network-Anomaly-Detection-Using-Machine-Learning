"""
Flow extraction utilities for real network traffic.

This module groups packets into bidirectional network flows and calculates
CICIDS-style flow features.
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:  # Support both "src.flow_extractor" and flat "flow_extractor" import styles.
    from .cicids_features import CICIDS_FEATURE_NAMES
except ImportError:  # pragma: no cover - fallback for flat imports
    from cicids_features import CICIDS_FEATURE_NAMES


# CICIDS-2017 time-based features (Flow Duration, IATs, Active/Idle) are
# expressed in microseconds, while rate features (Flow Bytes/s, Flow Packets/s,
# Fwd/Bwd Packets/s) are expressed per second. ``PacketRecord.timestamp`` is
# interpreted as POSIX/epoch seconds (a float), matching typical live capture
# sources such as ``time.time()``.
MICROSECONDS_PER_SECOND = 1_000_000

# ---------------------------------------------------------------------------
# CICFlowMeter reference constants
# ---------------------------------------------------------------------------
# Values taken verbatim from the ``cicflowmeter`` Python reference package
# (``cicflowmeter/constants.py``, v0.5.0), which ports the original CICFlowMeter
# Java tool. They are kept explicit so the extractor's behaviour is auditable and
# can be compared against the reference via ``scripts/compare_cicflowmeter.py``.
#
# All three are SECONDS because ``PacketRecord.timestamp`` is seconds:
#   * ACTIVE_TIMEOUT - maximum intra-flow gap that still counts as "active".
#   * CLUMP_TIMEOUT  - minimum gap that ends a "clump"/bulk run.
#   * BULK_BOUND     - minimum number of payload packets required for a bulk.
ACTIVE_TIMEOUT = 5.0
CLUMP_TIMEOUT = 1.0
BULK_BOUND = 4


class FlowFeatureError(ValueError):
    """Base class for errors raised while extracting CICIDS flow features."""


class InvalidPacketError(FlowFeatureError):
    """Raised when a packet holds structurally invalid (non-finite) fields.

    Rather than silently producing a corrupt feature vector, invalid packet
    input is rejected at ingestion time.
    """


class NonFiniteFeatureError(FlowFeatureError):
    """Raised when a computed feature is ``NaN`` or ``+/-Infinity``.

    Every expected fallback (zero denominators, too few observations, empty
    directions) is already handled explicitly and returns a *defined* zero. Any
    non-finite value that survives is therefore an unexpected invalid
    intermediate result, not a legitimate zero, and must never be silently
    converted to ``0.0`` and fed to the model.

    Attributes:
        diagnostics: List of ``(feature_name, value)`` pairs that were
            non-finite, for logging/triage.
    """

    def __init__(self, diagnostics: List[Tuple[str, float]]) -> None:
        self.diagnostics = list(diagnostics)
        details = ", ".join(
            f"{name}={value!r}" for name, value in self.diagnostics
        )
        super().__init__(
            "Feature extraction produced non-finite value(s): "
            f"{details}. Refusing to silently coerce them to 0.0; the input "
            "or an intermediate calculation is invalid."
        )


@dataclass
class PacketRecord:
    """Represents one captured network packet.

    ``timestamp`` is expected to be in seconds.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    length: int

    ip_header_length: int = 0
    tcp_header_length: int = 0

    # Application-layer payload byte count (0 for header-only packets). Used by
    # the payload-driven features (act_data_pkt_fwd, min_seg_size_forward, bulk).
    payload_length: int = 0

    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False

    # Chunk 8
    cwe: bool = False
    ece: bool = False

    # Chunk 10
    tcp_window_size: int = 0


@dataclass
class NetworkFlow:
    """Stores packets belonging to one bidirectional network flow."""

    key: Tuple

    packets: List[PacketRecord] = field(default_factory=list)
    forward_packets: List[PacketRecord] = field(default_factory=list)
    backward_packets: List[PacketRecord] = field(default_factory=list)

    # Direction of each packet in ``packets`` (True = forward). Needed for the
    # directional bulk algorithm, which depends on the interleaving of forward
    # and backward packets in arrival order.
    forward_flags: List[bool] = field(default_factory=list)

    def add_packet(
        self,
        packet: PacketRecord,
        forward: bool,
    ) -> None:

        self.packets.append(packet)
        self.forward_flags.append(bool(forward))

        if forward:
            self.forward_packets.append(packet)
        else:
            self.backward_packets.append(packet)

    @property
    def start_time(self) -> Optional[float]:

        if not self.packets:
            return None

        return min(
            packet.timestamp
            for packet in self.packets
        )

    @property
    def end_time(self) -> Optional[float]:

        if not self.packets:
            return None

        return max(
            packet.timestamp
            for packet in self.packets
        )

    @property
    def duration(self) -> float:

        if self.start_time is None or self.end_time is None:
            return 0.0

        return self.end_time - self.start_time

    @property
    def duration_microseconds(self) -> float:
        """Flow duration in microseconds (the unit used by CICIDS-2017)."""

        return self.duration * MICROSECONDS_PER_SECOND

    @property
    def destination_port(self) -> int:

        if not self.forward_packets:
            return 0

        return self.forward_packets[0].dst_port

    @property
    def total_fwd_packets(self) -> int:

        return len(self.forward_packets)

    @property
    def total_backward_packets(self) -> int:

        return len(self.backward_packets)

    @property
    def total_length_fwd_packets(self) -> int:

        return sum(
            packet.length
            for packet in self.forward_packets
        )

    @property
    def total_length_bwd_packets(self) -> int:

        return sum(
            packet.length
            for packet in self.backward_packets
        )

    @staticmethod
    def _packet_length_stats(
        packets: List[PacketRecord],
    ) -> Tuple[float, float, float, float]:

        if not packets:
            return 0.0, 0.0, 0.0, 0.0

        lengths = [
            packet.length
            for packet in packets
        ]

        maximum = max(lengths)
        minimum = min(lengths)
        mean = sum(lengths) / len(lengths)

        if len(lengths) == 1:
            std = 0.0
        else:

            variance = sum(
                (length - mean) ** 2
                for length in lengths
            ) / len(lengths)

            std = variance ** 0.5

        return maximum, minimum, mean, std

    @property
    def fwd_packet_length_stats(self):

        return self._packet_length_stats(
            self.forward_packets
        )

    @property
    def bwd_packet_length_stats(self):

        return self._packet_length_stats(
            self.backward_packets
        )

    # =========================================================
    # FEATURES 1-14
    # =========================================================

    def basic_cicids_features(self) -> Dict[str, float]:

        (
            fwd_max,
            fwd_min,
            fwd_mean,
            fwd_std,
        ) = self.fwd_packet_length_stats

        (
            bwd_max,
            bwd_min,
            bwd_mean,
            bwd_std,
        ) = self.bwd_packet_length_stats

        return {

            "Destination Port":
                self.destination_port,

            "Flow Duration":
                self.duration_microseconds,

            "Total Fwd Packets":
                self.total_fwd_packets,

            "Total Backward Packets":
                self.total_backward_packets,

            "Total Length of Fwd Packets":
                self.total_length_fwd_packets,

            "Total Length of Bwd Packets":
                self.total_length_bwd_packets,

            "Fwd Packet Length Max":
                fwd_max,

            "Fwd Packet Length Min":
                fwd_min,

            "Fwd Packet Length Mean":
                fwd_mean,

            "Fwd Packet Length Std":
                fwd_std,

            "Bwd Packet Length Max":
                bwd_max,

            "Bwd Packet Length Min":
                bwd_min,

            "Bwd Packet Length Mean":
                bwd_mean,

            "Bwd Packet Length Std":
                bwd_std,
        }

    # =========================================================
    # FEATURES 15-20
    # =========================================================

    @property
    def flow_bytes_per_second(self):

        if self.duration <= 0:
            return 0.0

        total_bytes = sum(
            packet.length
            for packet in self.packets
        )

        return total_bytes / self.duration

    @property
    def flow_packets_per_second(self):

        if self.duration <= 0:
            return 0.0

        return len(self.packets) / self.duration

    @property
    def flow_iat_stats(self):

        if len(self.packets) < 2:
            return 0.0, 0.0, 0.0, 0.0

        timestamps = sorted(
            packet.timestamp
            for packet in self.packets
        )

        # Inter-arrival times are computed in seconds and only converted to
        # microseconds after the statistics are formed. Epoch-scale timestamps
        # (about 1e9) have roughly 2.4e-7 s of float resolution, so scaling each
        # difference first would amplify that noise into the variance/std.
        iats = [
            timestamps[index] - timestamps[index - 1]
            for index in range(1, len(timestamps))
        ]

        if not iats:
            return 0.0, 0.0, 0.0, 0.0

        mean = sum(iats) / len(iats)

        if len(iats) == 1:
            std = 0.0
        else:

            variance = sum(
                (iat - mean) ** 2
                for iat in iats
            ) / len(iats)

            std = variance ** 0.5

        return (
            mean * MICROSECONDS_PER_SECOND,
            std * MICROSECONDS_PER_SECOND,
            max(iats) * MICROSECONDS_PER_SECOND,
            min(iats) * MICROSECONDS_PER_SECOND,
        )

    def rate_iat_cicids_features(self):

        (
            iat_mean,
            iat_std,
            iat_max,
            iat_min,
        ) = self.flow_iat_stats

        return {

            "Flow Bytes/s":
                self.flow_bytes_per_second,

            "Flow Packets/s":
                self.flow_packets_per_second,

            "Flow IAT Mean":
                iat_mean,

            "Flow IAT Std":
                iat_std,

            "Flow IAT Max":
                iat_max,

            "Flow IAT Min":
                iat_min,
        }

    # =========================================================
    # FEATURES 21-30
    # =========================================================

    @staticmethod
    def _iat_stats(packets):

        if len(packets) < 2:
            return 0.0, 0.0, 0.0, 0.0, 0.0

        timestamps = sorted(
            packet.timestamp
            for packet in packets
        )

        # See Flow.flow_iat_stats: statistics are formed in seconds and only
        # then converted to microseconds to avoid float noise amplification.
        iats = [
            timestamps[index] - timestamps[index - 1]
            for index in range(1, len(timestamps))
        ]

        if not iats:
            return 0.0, 0.0, 0.0, 0.0, 0.0

        total = sum(iats)
        mean = total / len(iats)

        if len(iats) == 1:
            std = 0.0
        else:

            variance = sum(
                (iat - mean) ** 2
                for iat in iats
            ) / len(iats)

            std = variance ** 0.5

        return (
            total * MICROSECONDS_PER_SECOND,
            mean * MICROSECONDS_PER_SECOND,
            std * MICROSECONDS_PER_SECOND,
            max(iats) * MICROSECONDS_PER_SECOND,
            min(iats) * MICROSECONDS_PER_SECOND,
        )

    def forward_backward_iat_features(self):

        (
            fwd_iat_total,
            fwd_iat_mean,
            fwd_iat_std,
            fwd_iat_max,
            fwd_iat_min,
        ) = self._iat_stats(
            self.forward_packets
        )

        (
            bwd_iat_total,
            bwd_iat_mean,
            bwd_iat_std,
            bwd_iat_max,
            bwd_iat_min,
        ) = self._iat_stats(
            self.backward_packets
        )

        return {

            "Fwd IAT Total":
                fwd_iat_total,

            "Fwd IAT Mean":
                fwd_iat_mean,

            "Fwd IAT Std":
                fwd_iat_std,

            "Fwd IAT Max":
                fwd_iat_max,

            "Fwd IAT Min":
                fwd_iat_min,

            "Bwd IAT Total":
                bwd_iat_total,

            "Bwd IAT Mean":
                bwd_iat_mean,

            "Bwd IAT Std":
                bwd_iat_std,

            "Bwd IAT Max":
                bwd_iat_max,

            "Bwd IAT Min":
                bwd_iat_min,
        }

    # =========================================================
    # FEATURES 31-38
    # =========================================================

    @property
    def fwd_psh_flags(self):

        return sum(
            1
            for packet in self.forward_packets
            if packet.psh
        )

    @property
    def bwd_psh_flags(self):

        return sum(
            1
            for packet in self.backward_packets
            if packet.psh
        )

    @property
    def fwd_urg_flags(self):

        return sum(
            1
            for packet in self.forward_packets
            if packet.urg
        )

    @property
    def bwd_urg_flags(self):

        return sum(
            1
            for packet in self.backward_packets
            if packet.urg
        )

    @property
    def fwd_header_length(self):

        return sum(
            packet.ip_header_length
            + packet.tcp_header_length
            for packet in self.forward_packets
        )

    @property
    def bwd_header_length(self):

        return sum(
            packet.ip_header_length
            + packet.tcp_header_length
            for packet in self.backward_packets
        )

    @property
    def fwd_packets_per_second(self):

        if self.duration <= 0:
            return 0.0

        return self.total_fwd_packets / self.duration

    @property
    def bwd_packets_per_second(self):

        if self.duration <= 0:
            return 0.0

        return self.total_backward_packets / self.duration

    def tcp_flag_and_rate_features(self):

        return {

            "Fwd PSH Flags":
                self.fwd_psh_flags,

            "Bwd PSH Flags":
                self.bwd_psh_flags,

            "Fwd URG Flags":
                self.fwd_urg_flags,

            "Bwd URG Flags":
                self.bwd_urg_flags,

            "Fwd Header Length":
                self.fwd_header_length,

            "Bwd Header Length":
                self.bwd_header_length,

            "Fwd Packets/s":
                self.fwd_packets_per_second,

            "Bwd Packets/s":
                self.bwd_packets_per_second,
        }

    # =========================================================
    # FEATURES 39-49
    # =========================================================

    @property
    def min_packet_length(self):

        if not self.packets:
            return 0

        return min(
            packet.length
            for packet in self.packets
        )

    @property
    def max_packet_length(self):

        if not self.packets:
            return 0

        return max(
            packet.length
            for packet in self.packets
        )

    @property
    def packet_length_mean(self):

        if not self.packets:
            return 0.0

        return sum(
            packet.length
            for packet in self.packets
        ) / len(self.packets)

    @property
    def packet_length_variance(self):

        if not self.packets:
            return 0.0

        mean = self.packet_length_mean

        return sum(
            (packet.length - mean) ** 2
            for packet in self.packets
        ) / len(self.packets)

    @property
    def packet_length_std(self):

        return self.packet_length_variance ** 0.5

    @property
    def fin_flag_count(self):

        return sum(
            1
            for packet in self.packets
            if packet.fin
        )

    @property
    def syn_flag_count(self):

        return sum(
            1
            for packet in self.packets
            if packet.syn
        )

    @property
    def rst_flag_count(self):

        return sum(
            1
            for packet in self.packets
            if packet.rst
        )

    @property
    def psh_flag_count(self):

        return sum(
            1
            for packet in self.packets
            if packet.psh
        )

    @property
    def ack_flag_count(self):

        return sum(
            1
            for packet in self.packets
            if packet.ack
        )

    @property
    def urg_flag_count(self):

        return sum(
            1
            for packet in self.packets
            if packet.urg
        )

    def packet_length_and_tcp_flag_features(self):

        return {

            "Min Packet Length":
                self.min_packet_length,

            "Max Packet Length":
                self.max_packet_length,

            "Packet Length Mean":
                self.packet_length_mean,

            "Packet Length Std":
                self.packet_length_std,

            "Packet Length Variance":
                self.packet_length_variance,

            "FIN Flag Count":
                self.fin_flag_count,

            "SYN Flag Count":
                self.syn_flag_count,

            "RST Flag Count":
                self.rst_flag_count,

            "PSH Flag Count":
                self.psh_flag_count,

            "ACK Flag Count":
                self.ack_flag_count,

            "URG Flag Count":
                self.urg_flag_count,
        }

    # =========================================================
    # FEATURES 50-56
    # =========================================================

    @property
    def cwe_flag_count(self):

        return sum(
            1
            for packet in self.packets
            if packet.cwe
        )

    @property
    def ece_flag_count(self):

        return sum(
            1
            for packet in self.packets
            if packet.ece
        )

    @property
    def down_up_ratio(self):

        if self.total_fwd_packets == 0:
            return 0.0

        return (
            self.total_backward_packets
            / self.total_fwd_packets
        )

    @property
    def average_packet_size(self):

        if not self.packets:
            return 0.0

        return sum(
            packet.length
            for packet in self.packets
        ) / len(self.packets)

    @property
    def avg_fwd_segment_size(self):

        if self.total_fwd_packets == 0:
            return 0.0

        return (
            self.total_length_fwd_packets
            / self.total_fwd_packets
        )

    @property
    def avg_bwd_segment_size(self):

        if self.total_backward_packets == 0:
            return 0.0

        return (
            self.total_length_bwd_packets
            / self.total_backward_packets
        )

    def chunk8_features(self):

        return {

            "CWE Flag Count":
                self.cwe_flag_count,

            "ECE Flag Count":
                self.ece_flag_count,

            "Down/Up Ratio":
                self.down_up_ratio,

            "Average Packet Size":
                self.average_packet_size,

            "Avg Fwd Segment Size":
                self.avg_fwd_segment_size,

            "Avg Bwd Segment Size":
                self.avg_bwd_segment_size,

            "Fwd Header Length.1":
                self.fwd_header_length,
        }

    # =========================================================
    # FEATURES 57-62
    # =========================================================

    @staticmethod
    def _empty_bulk_state() -> Dict[str, float]:

        return {
            "last_timestamp": 0.0,
            "start_tmp": 0.0,
            "count": 0,
            "count_tmp": 0,
            "duration": 0.0,
            "packet_count": 0,
            "size": 0.0,
            "size_tmp": 0.0,
        }

    def _bulk_features(self) -> Dict[str, float]:
        """Bulk-transfer features, ported from the CICFlowMeter reference.

        This is a faithful port of
        ``cicflowmeter.flow.Flow.update_flow_bulk`` (v0.5.0). Bulk state is
        *directional and interleaved*: assembling a forward bulk can be reset by
        an intervening backward payload packet and vice versa, so the result
        cannot be derived from the forward/backward lists in isolation. Only
        packets with a non-empty payload participate.

        The reference uses ``packet.time``; we use ``packet.timestamp`` (both
        float seconds). ``CLUMP_TIMEOUT`` and ``BULK_BOUND`` are identical to
        the reference. A ``0`` timestamp is used as the "unset" sentinel,
        exactly as in the reference (which assumes epoch timestamps != 0).

        Parity note: the bulk arithmetic was compared at runtime against the
        unmodified Java CICFlowMeter ``BasicFlow`` (pinned commit
        ``98a5ebad0df579cc8b43eedd3421b3ae87699901``). On a single-direction
        flow our forward triple equals the reference's backward triple
        element-wise, confirming identical arithmetic. The reference selects
        direction with ``this.src == packet.getSrc()`` (reference equality on a
        fresh ``byte[]``), which is always ``false`` in that revision, so its
        forward bulk is structurally zero and every payload packet is routed to
        the backward counters. This implementation intentionally keeps the
        per-direction semantics; see ``scripts/java_reference_parity.py`` and
        ``reports/java_reference_parity.json``.
        """

        state = {
            "fwd": self._empty_bulk_state(),
            "bwd": self._empty_bulk_state(),
        }

        for packet, forward in zip(self.packets, self.forward_flags):

            payload = int(packet.payload_length)
            if payload == 0:
                continue

            direction = "fwd" if forward else "bwd"
            other = "bwd" if forward else "fwd"
            d = state[direction]

            if state[other]["last_timestamp"] > d["start_tmp"]:
                d["start_tmp"] = 0.0

            if d["start_tmp"] == 0.0:
                d["start_tmp"] = packet.timestamp
                d["last_timestamp"] = packet.timestamp
                d["count_tmp"] = 1
                d["size_tmp"] = payload

            elif packet.timestamp - d["last_timestamp"] > CLUMP_TIMEOUT:
                d["start_tmp"] = packet.timestamp
                d["last_timestamp"] = packet.timestamp
                d["count_tmp"] = 1
                d["size_tmp"] = payload

            else:
                d["count_tmp"] += 1
                d["size_tmp"] += payload

                if d["count_tmp"] == BULK_BOUND:
                    d["count"] += 1
                    d["packet_count"] += d["count_tmp"]
                    d["size"] += d["size_tmp"]
                    d["duration"] += packet.timestamp - d["start_tmp"]

                elif d["count_tmp"] > BULK_BOUND:
                    d["packet_count"] += 1
                    d["size"] += payload
                    d["duration"] += packet.timestamp - d["last_timestamp"]

                d["last_timestamp"] = packet.timestamp

        def averages(d: Dict[str, float]) -> Tuple[float, float, float]:
            # Defined fallbacks: no completed bulk -> all zero (matches the
            # reference's ``if ... != 0 else 0`` guards).
            bytes_per_bulk = d["size"] / d["count"] if d["count"] else 0.0
            packets_per_bulk = (
                d["packet_count"] / d["count"] if d["count"] else 0.0
            )
            rate = d["size"] / d["duration"] if d["duration"] else 0.0
            return bytes_per_bulk, packets_per_bulk, rate

        fwd_bytes, fwd_packets, fwd_rate = averages(state["fwd"])
        bwd_bytes, bwd_packets, bwd_rate = averages(state["bwd"])

        return {
            "Fwd Avg Bytes/Bulk": fwd_bytes,
            "Fwd Avg Packets/Bulk": fwd_packets,
            "Fwd Avg Bulk Rate": fwd_rate,
            "Bwd Avg Bytes/Bulk": bwd_bytes,
            "Bwd Avg Packets/Bulk": bwd_packets,
            "Bwd Avg Bulk Rate": bwd_rate,
        }

    def fwd_bulk_features(self):

        features = self._bulk_features()

        return {
            "Fwd Avg Bytes/Bulk": features["Fwd Avg Bytes/Bulk"],
            "Fwd Avg Packets/Bulk": features["Fwd Avg Packets/Bulk"],
            "Fwd Avg Bulk Rate": features["Fwd Avg Bulk Rate"],
        }

    def bwd_bulk_features(self):

        features = self._bulk_features()

        return {
            "Bwd Avg Bytes/Bulk": features["Bwd Avg Bytes/Bulk"],
            "Bwd Avg Packets/Bulk": features["Bwd Avg Packets/Bulk"],
            "Bwd Avg Bulk Rate": features["Bwd Avg Bulk Rate"],
        }

    def chunk9_features(self):

        return self._bulk_features()

    # =========================================================
    # FEATURES 63-70
    # =========================================================

    @property
    def subflow_fwd_packets(self):

        return self.total_fwd_packets

    @property
    def subflow_fwd_bytes(self):

        return self.total_length_fwd_packets

    @property
    def subflow_bwd_packets(self):

        return self.total_backward_packets

    @property
    def subflow_bwd_bytes(self):

        return self.total_length_bwd_packets

    @property
    def init_win_bytes_forward(self):

        for packet in self.forward_packets:

            if packet.tcp_window_size > 0:
                return packet.tcp_window_size

        return 0

    @property
    def init_win_bytes_backward(self):

        for packet in self.backward_packets:

            if packet.tcp_window_size > 0:
                return packet.tcp_window_size

        return 0

    @property
    def act_data_pkt_fwd(self):
        """Forward packets that carry an application payload.

        Matches the reference ``PacketCount.has_payload(FORWARD)`` definition:
        a packet counts only if its L4 payload is non-empty. Requires the
        adapter to populate ``PacketRecord.payload_length``.
        """

        return sum(
            1
            for packet in self.forward_packets
            if packet.payload_length > 0
        )

    @property
    def min_seg_size_forward(self):
        """Minimum forward payload (segment) size, or 0 when undefined.

        NOTE: the ``cicflowmeter`` Python reference implementation returns the
        minimum *IP header* length here (``get_min_forward_header_bytes``),
        which is a known deviation from the CICIDS-2017 dataset semantics.
        We use the minimum forward payload size, which is the meaning described
        for ``min_seg_size_forward`` in the dataset. See INFERENCE_INTEGRATION.md.
        """

        payload_sizes = [
            packet.payload_length
            for packet in self.forward_packets
        ]

        if not payload_sizes:
            return 0

        return min(payload_sizes)

    def chunk10_features(self):

        return {

            "Subflow Fwd Packets":
                self.subflow_fwd_packets,

            "Subflow Fwd Bytes":
                self.subflow_fwd_bytes,

            "Subflow Bwd Packets":
                self.subflow_bwd_packets,

            "Subflow Bwd Bytes":
                self.subflow_bwd_bytes,

            "Init_Win_bytes_forward":
                self.init_win_bytes_forward,

            "Init_Win_bytes_backward":
                self.init_win_bytes_backward,

            "act_data_pkt_fwd":
                self.act_data_pkt_fwd,

            "min_seg_size_forward":
                self.min_seg_size_forward,
        }

    # =========================================================
    # FEATURES 71-78
    # =========================================================

    # Maximum intra-flow gap that still counts as "active", using the
    # CICFlowMeter reference constant (ACTIVE_TIMEOUT = 5 s).
    ACTIVE_IDLE_THRESHOLD = ACTIVE_TIMEOUT

    def _active_idle_periods(self):
        """Return ``(active_periods_us, idle_periods_us)``.

        Semantics: consecutive packets separated by **at most**
        ``ACTIVE_TIMEOUT`` (5 s) belong to the same active period; a gap strictly
        greater than 5 s closes the active period and is recorded as an idle
        period. Zero-length active periods are not recorded, matching the
        reference ``if duration > 0`` guard. Durations are microseconds.

        NOTE on parity: the ``cicflowmeter`` Python reference port never
        populates its active/idle lists (its ``latest_timestamp`` is updated
        before the gap check, so the gap is always <= 0). It therefore emits
        all-zero Active/Idle features and cannot serve as ground truth here.
        This implementation was instead compared numerically against the
        unmodified Java CICFlowMeter ``BasicFlow`` sources (pinned commit
        ``98a5ebad0df579cc8b43eedd3421b3ae87699901``) executed in a JVM: all
        eight Active/Idle features match exactly. See
        ``scripts/java_reference_parity.py`` and
        ``reports/java_reference_parity.json``.
        """

        if len(self.packets) < 2:
            return [], []

        packets = sorted(
            self.packets,
            key=lambda packet: packet.timestamp,
        )

        active_periods = []
        idle_periods = []

        active_start = packets[0].timestamp
        previous = packets[0].timestamp

        for packet in packets[1:]:

            gap = packet.timestamp - previous

            if gap > self.ACTIVE_IDLE_THRESHOLD:

                # Close the current active period (microseconds).
                active_duration = (
                    previous - active_start
                ) * MICROSECONDS_PER_SECOND
                if active_duration > 0:
                    active_periods.append(active_duration)

                # Record the idle period (microseconds).
                idle_periods.append(gap * MICROSECONDS_PER_SECOND)

                # New active period begins.
                active_start = packet.timestamp

            previous = packet.timestamp

        return active_periods, idle_periods

    @staticmethod
    def _statistics(values):

        if not values:
            return 0.0, 0.0, 0.0, 0.0

        mean = (
            sum(values)
            / len(values)
        )

        if len(values) == 1:

            std = 0.0

        else:

            # Apache Commons Math SummaryStatistics sample std (N - 1)
            variance = sum(
                (value - mean) ** 2
                for value in values
            ) / (len(values) - 1)

            std = variance ** 0.5

        return (
            mean,
            std,
            max(values),
            min(values),
        )

    def chunk11_features(self):

        (
            active_periods,
            idle_periods,
        ) = self._active_idle_periods()

        (
            active_mean,
            active_std,
            active_max,
            active_min,
        ) = self._statistics(
            active_periods
        )

        (
            idle_mean,
            idle_std,
            idle_max,
            idle_min,
        ) = self._statistics(
            idle_periods
        )

        return {

            "Active Mean":
                active_mean,

            "Active Std":
                active_std,

            "Active Max":
                active_max,

            "Active Min":
                active_min,

            "Idle Mean":
                idle_mean,

            "Idle Std":
                idle_std,

            "Idle Max":
                idle_max,

            "Idle Min":
                idle_min,
        }

    # =========================================================
    # CANONICAL ASSEMBLY (78 features, training order)
    # =========================================================

    def extract_features(self) -> Dict[str, float]:
        """Return all 78 CICIDS features in the exact training schema order.

        The returned mapping is ordered according to
        :data:`src.cicids_features.CICIDS_FEATURE_NAMES`, which matches
        ``RandomForestClassifier.feature_names_in_`` of the trained model.

        Invalid values are **not** silently coerced. Every legitimate fallback
        (zero denominators, insufficient observations, empty directions) is
        handled explicitly in the feature properties and yields a *defined*
        zero. If a feature is still ``NaN`` or ``+/-Infinity`` after that, it
        indicates invalid input or an unguarded computation, and
        :class:`NonFiniteFeatureError` is raised with per-feature diagnostics
        rather than returning an apparently-valid vector.
        """

        chunks = [
            self.basic_cicids_features(),
            self.rate_iat_cicids_features(),
            self.forward_backward_iat_features(),
            self.tcp_flag_and_rate_features(),
            self.packet_length_and_tcp_flag_features(),
            self.chunk8_features(),
            self.chunk9_features(),
            self.chunk10_features(),
            self.chunk11_features(),
        ]

        collected: Dict[str, float] = {}
        for chunk in chunks:
            for name, value in chunk.items():
                collected[name] = value

        missing = [
            name for name in CICIDS_FEATURE_NAMES if name not in collected
        ]
        extra = [
            name for name in collected if name not in CICIDS_FEATURE_NAMES
        ]
        if missing or extra:
            raise ValueError(
                "Extracted feature schema does not match the CICIDS training "
                f"schema. Missing={missing}, Extra={extra}."
            )

        ordered: Dict[str, float] = {}
        diagnostics: List[Tuple[str, float]] = []
        for name in CICIDS_FEATURE_NAMES:
            value = float(collected[name])
            if not math.isfinite(value):
                diagnostics.append((name, value))
            ordered[name] = value

        if diagnostics:
            raise NonFiniteFeatureError(diagnostics)

        return ordered

    def feature_diagnostics(self) -> List[Tuple[str, float]]:
        """Return ``(name, value)`` pairs for any non-finite feature.

        Intended for logging/triage when :meth:`extract_features` would raise.
        Returns an empty list when the feature vector is fully finite.
        """

        try:
            self.extract_features()
        except NonFiniteFeatureError as exc:
            return exc.diagnostics
        return []

    def to_feature_vector(self) -> List[float]:
        """Return the 78 features as an ordered numeric vector."""

        features = self.extract_features()
        return [features[name] for name in CICIDS_FEATURE_NAMES]


# =============================================================
# FLOW EXTRACTOR
# =============================================================

class FlowExtractor:
    """Groups packets into bidirectional network flows."""

    def __init__(self):

        self.flows: Dict[
            Tuple,
            NetworkFlow
        ] = {}

    @staticmethod
    def _make_flow_key(packet):

        endpoint_a = (
            packet.src_ip,
            packet.src_port,
        )

        endpoint_b = (
            packet.dst_ip,
            packet.dst_port,
        )

        if endpoint_a <= endpoint_b:

            first = endpoint_a
            second = endpoint_b

        else:

            first = endpoint_b
            second = endpoint_a

        return (
            first,
            second,
            packet.protocol,
        )

    @staticmethod
    def _is_forward(packet, flow):

        if not flow.packets:
            return True

        first_packet = flow.packets[0]

        return (
            packet.src_ip
            == first_packet.src_ip
            and
            packet.dst_ip
            == first_packet.dst_ip
            and
            packet.src_port
            == first_packet.src_port
            and
            packet.dst_port
            == first_packet.dst_port
            and
            packet.protocol
            == first_packet.protocol
        )

    @staticmethod
    def validate_packet(packet) -> None:
        """Reject packets whose core fields are non-finite or malformed.

        Called by :meth:`add_packet` so that invalid capture data fails loudly
        at ingestion instead of silently producing corrupt features later.

        Raises:
            InvalidPacketError: If ``timestamp``, ``length`` or
                ``payload_length`` is non-numeric, non-finite, or negative.
        """

        try:
            timestamp = float(packet.timestamp)
        except (TypeError, ValueError) as err:
            raise InvalidPacketError(
                f"Packet timestamp is not numeric: {packet.timestamp!r}"
            ) from err
        if not math.isfinite(timestamp):
            raise InvalidPacketError(
                f"Packet timestamp is not finite: {packet.timestamp!r}"
            )

        try:
            length = float(packet.length)
        except (TypeError, ValueError) as err:
            raise InvalidPacketError(
                f"Packet length is not numeric: {packet.length!r}"
            ) from err
        if not math.isfinite(length) or length < 0:
            raise InvalidPacketError(
                f"Packet length must be a finite, non-negative number: "
                f"{packet.length!r}"
            )

        payload_length = getattr(packet, "payload_length", 0)
        if payload_length is None:
            payload_length = 0
        try:
            payload_length = float(payload_length)
        except (TypeError, ValueError) as err:
            raise InvalidPacketError(
                f"Packet payload_length is not numeric: "
                f"{getattr(packet, 'payload_length', None)!r}"
            ) from err
        if not math.isfinite(payload_length) or payload_length < 0:
            raise InvalidPacketError(
                "Packet payload_length must be a finite, non-negative number: "
                f"{getattr(packet, 'payload_length', None)!r}"
            )

    def add_packet(self, packet):

        self.validate_packet(packet)

        key = self._make_flow_key(packet)

        if key not in self.flows:

            self.flows[key] = NetworkFlow(
                key=key
            )

        flow = self.flows[key]

        forward = self._is_forward(
            packet,
            flow
        )

        flow.add_packet(
            packet,
            forward
        )

        return flow

    def get_flows(self):

        return list(
            self.flows.values()
        )

    def extract_flow_features(self) -> List[Dict[str, float]]:
        """Return canonical 78-feature mappings for every extracted flow."""

        return [
            flow.extract_features()
            for flow in self.get_flows()
        ]

    def get_feature_vectors(self) -> List[List[float]]:
        """Return canonical 78-value vectors for every extracted flow."""

        return [
            flow.to_feature_vector()
            for flow in self.get_flows()
        ]

    def clear(self):

        self.flows.clear()
