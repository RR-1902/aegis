"""Test-only in-memory synthetic traffic builders for AEGIS validation."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Sequence

from scapy.all import Ether, IP, IPv6, TCP, UDP


DEFAULT_SRC_MAC = "00:11:22:33:44:55"
DEFAULT_DST_MAC = "66:77:88:99:aa:bb"


def tcp_packet(
    *,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.10",
    src_port: int = 12345,
    dst_port: int = 80,
    flags: str = "S",
    timestamp: datetime,
    ipv6: bool = False,
):
    network = IPv6(src=src_ip, dst=dst_ip) if ipv6 else IP(src=src_ip, dst=dst_ip)
    packet = Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / network / TCP(
        sport=src_port,
        dport=dst_port,
        flags=flags,
    )
    packet.time = float(timestamp.timestamp())
    return packet


def udp_packet(
    *,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.10",
    src_port: int = 12345,
    dst_port: int = 53,
    timestamp: datetime,
    ipv6: bool = False,
):
    network = IPv6(src=src_ip, dst=dst_ip) if ipv6 else IP(src=src_ip, dst=dst_ip)
    packet = Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / network / UDP(
        sport=src_port,
        dport=dst_port,
    )
    packet.time = float(timestamp.timestamp())
    return packet


def normal_tcp_handshake(*, base_time: datetime, src_ip: str = "10.0.0.5", dst_ip: str = "10.0.0.10", src_port: int = 12345, dst_port: int = 80):
    return [
        tcp_packet(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, flags="S", timestamp=base_time),
        tcp_packet(src_ip=dst_ip, dst_ip=src_ip, src_port=dst_port, dst_port=src_port, flags="SA", timestamp=base_time + timedelta(milliseconds=50)),
        tcp_packet(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, flags="A", timestamp=base_time + timedelta(milliseconds=100)),
        tcp_packet(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, flags="PA", timestamp=base_time + timedelta(milliseconds=150)),
        tcp_packet(src_ip=dst_ip, dst_ip=src_ip, src_port=dst_port, dst_port=src_port, flags="A", timestamp=base_time + timedelta(milliseconds=200)),
    ]


def udp_benign_sequence(*, base_time: datetime, count: int = 5, src_ip: str = "10.0.0.5", dst_ip: str = "10.0.0.10", src_port: int = 12345, dst_port: int = 53):
    return [
        udp_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            timestamp=base_time + timedelta(milliseconds=i * 10),
        )
        for i in range(count)
    ]


def port_scan_sequence(*, base_time: datetime, dst_ports: Sequence[int], src_ip: str = "10.0.0.5", dst_ip: str = "10.0.0.10", src_port_start: int = 40000, step: timedelta | None = None):
    packets = []
    spacing = step or timedelta(milliseconds=1)
    for i, dst_port in enumerate(dst_ports):
        packets.append(
            tcp_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port_start + i,
                dst_port=dst_port,
                flags="S",
                timestamp=base_time + (spacing * i),
            )
        )
    return packets


def syn_burst_sequence(*, base_time: datetime, count: int, span_seconds: float, src_ip: str = "10.0.0.5", dst_ip: str = "10.0.0.10", src_port: int = 40000, dst_port: int = 80):
    if count <= 0:
        return []
    step = span_seconds / max(1, count - 1) if count > 1 else 0.0
    packets = []
    for i in range(count):
        packets.append(
            tcp_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                flags="S",
                timestamp=base_time + timedelta(seconds=step * i),
            )
        )
    return packets


def combined_suspicious_sequence(*, base_time: datetime, dst_ports: Sequence[int], span_seconds: float = 1.0, src_ip: str = "10.0.0.5", dst_ip: str = "10.0.0.10", src_port_start: int = 50000):
    if not dst_ports:
        return []
    step = span_seconds / max(1, len(dst_ports) - 1) if len(dst_ports) > 1 else 0.0
    packets = []
    for i, dst_port in enumerate(dst_ports):
        packets.append(
            tcp_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port_start + i,
                dst_port=dst_port,
                flags="S",
                timestamp=base_time + timedelta(seconds=step * i),
            )
        )
    return packets
