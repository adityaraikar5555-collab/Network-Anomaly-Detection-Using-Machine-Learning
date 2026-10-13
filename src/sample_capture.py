"""Deterministic *synthetic* PCAP generator for testing the live pipeline.

This module builds a small, fully synthetic TCP + UDP capture with Scapy and
writes it to a ``.pcap`` file. It exists so the PCAP -> features -> model path
can be exercised end-to-end without committing any capture to the repository.

.. warning::
   The traffic produced here is **synthetic**. It is not captured from a real
   network and is **not** CICIDS-2017 traffic. It must never be used as evidence
   of real-world detection accuracy or as a substitute for genuine captures.

Scapy is imported lazily; this module cannot be used without it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

__all__ = ["build_sample_capture"]

PathLike = Union[str, Path]

# Fixed epoch so the generated capture is byte-for-byte deterministic.
BASE_TIME = 1_700_000_000.0


def build_sample_capture(pcap_path: PathLike) -> str:
    """Write a deterministic synthetic TCP + UDP capture to ``pcap_path``.

    The capture contains:

    * one bidirectional TCP flow: three-way handshake, a six-packet forward
      payload burst (to exercise bulk features), a reverse ACK, and a
      FIN/RST teardown (12 packets total),
    * one bidirectional UDP flow: four requests and one response (5 packets),
    * one ICMP packet that the TCP/UDP adapter must skip (1 packet).

    Returns the path written.
    """

    try:
        from scapy.all import (  # type: ignore
            Ether,
            ICMP,
            IP,
            Raw,
            TCP,
            UDP,
            wrpcap,
        )
    except Exception as exc:  # pragma: no cover - only without scapy
        raise RuntimeError(
            "Generating a sample capture requires the optional 'scapy' package."
        ) from exc

    def stamp(pkt, offset):
        pkt.time = BASE_TIME + offset
        return pkt

    client, server = "10.0.0.1", "10.0.0.2"
    u_client, u_server = "10.0.0.3", "8.8.8.8"
    # Fixed MACs avoid Scapy trying to resolve neighbours on the local host.
    cmac, smac, ucmac = (
        "02:00:00:00:00:01",
        "02:00:00:00:00:02",
        "02:00:00:00:00:03",
    )

    packets = []

    # ---- TCP flow: three-way handshake --------------------------------
    packets.append(stamp(
        Ether(src=cmac, dst=smac) / IP(src=client, dst=server)
        / TCP(sport=40000, dport=80, flags="S", seq=1000, window=65535),
        0.000000,
    ))
    packets.append(stamp(
        Ether(src=smac, dst=cmac) / IP(src=server, dst=client)
        / TCP(sport=80, dport=40000, flags="SA", seq=5000, ack=1001, window=64240),
        0.000500,
    ))
    packets.append(stamp(
        Ether(src=cmac, dst=smac) / IP(src=client, dst=server)
        / TCP(sport=40000, dport=80, flags="A", seq=1001, ack=5001, window=65535),
        0.001000,
    ))

    # ---- TCP flow: forward data burst (>= BULK_BOUND payload packets) --
    sizes = [100, 200, 300, 400, 500, 600]
    seq = 1001
    t = 0.001100
    for index, size in enumerate(sizes):
        payload = bytes([65 + index]) * size
        packets.append(stamp(
            Ether(src=cmac, dst=smac) / IP(src=client, dst=server)
            / TCP(sport=40000, dport=80, flags="PA", seq=seq, ack=5001,
                  window=65535)
            / Raw(load=payload),
            t,
        ))
        seq += size
        t += 0.000400

    # ---- TCP flow: one reverse ACK ------------------------------------
    packets.append(stamp(
        Ether(src=smac, dst=cmac) / IP(src=server, dst=client)
        / TCP(sport=80, dport=40000, flags="A", seq=5001, ack=seq, window=64240),
        t,
    ))
    t += 0.000500

    # ---- TCP flow: teardown -------------------------------------------
    packets.append(stamp(
        Ether(src=cmac, dst=smac) / IP(src=client, dst=server)
        / TCP(sport=40000, dport=80, flags="FA", seq=seq, ack=5001, window=65535),
        t,
    ))
    t += 0.000200
    packets.append(stamp(
        Ether(src=smac, dst=cmac) / IP(src=server, dst=client)
        / TCP(sport=80, dport=40000, flags="RA", seq=5001, ack=seq + 1,
              window=64240),
        t,
    ))

    # ---- UDP flow ------------------------------------------------------
    u_t = 0.000000
    for _ in range(4):
        packets.append(stamp(
            Ether(src=ucmac, dst=smac) / IP(src=u_client, dst=u_server)
            / UDP(sport=5000, dport=53) / Raw(load=b"Q" * 40),
            u_t,
        ))
        u_t += 0.000600
    packets.append(stamp(
        Ether(src=smac, dst=ucmac) / IP(src=u_server, dst=u_client)
        / UDP(sport=53, dport=5000) / Raw(load=b"R" * 80),
        u_t,
    ))

    # ---- Non-TCP/UDP packet (must be skipped) --------------------------
    packets.append(stamp(
        Ether(src=cmac, dst=smac) / IP(src=client, dst=server) / ICMP(),
        0.010000,
    ))

    pcap_path = str(pcap_path)
    wrpcap(pcap_path, packets)
    return pcap_path


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Write a deterministic synthetic TCP+UDP PCAP for testing."
    )
    parser.add_argument("output", help="Destination .pcap path.")
    args = parser.parse_args(argv)

    path = build_sample_capture(args.output)
    print(f"Wrote synthetic sample capture: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
