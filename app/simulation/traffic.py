"""In-memory synthetic packets for simulations. Nothing here is ever sent on a network."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Sequence

from scapy.all import Ether, IP, TCP, UDP


SRC_MAC = "00:11:22:33:44:55"
DST_MAC = "66:77:88:99:aa:bb"


def tcp_packet(*, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: str, timestamp: datetime):
    packet = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags=flags)
    packet.time = float(timestamp.timestamp())
    return packet


def udp_packet(*, src_ip: str, dst_ip: str, src_port: int, dst_port: int, timestamp: datetime):
    packet = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
    packet.time = float(timestamp.timestamp())
    return packet


def syn_burst(*, base_time: datetime, count: int, span_seconds: float, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> List:
    """`count` SYN packets on one five-tuple, evenly spread over `span_seconds`."""
    step = span_seconds / (count - 1) if count > 1 else 0.0
    return [
        tcp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flags="S",
            timestamp=base_time + timedelta(seconds=step * index),
        )
        for index in range(count)
    ]


def port_probe(*, base_time: datetime, dst_ports: Sequence[int], span_seconds: float, src_ip: str, dst_ip: str, src_port_start: int) -> List:
    """One SYN per destination port, evenly spread over `span_seconds`, a new source port each."""
    step = span_seconds / (len(dst_ports) - 1) if len(dst_ports) > 1 else 0.0
    return [
        tcp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port_start + index,
            dst_port=port,
            flags="S",
            timestamp=base_time + timedelta(seconds=step * index),
        )
        for index, port in enumerate(dst_ports)
    ]


def dns_lookups(*, base_time: datetime, count: int, src_ip: str, dst_ip: str) -> List:
    return [
        udp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=12345,
            dst_port=53,
            timestamp=base_time + timedelta(milliseconds=index * 10),
        )
        for index in range(count)
    ]
