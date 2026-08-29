# Networking Concepts in AEGIS

This document explains the networking concepts and protocols that AEGIS observes and analyzes. It demonstrates the system's understanding of computer networks, TCP/IP, and packet-level operations.

## Table of Contents

1. [OSI Model and Network Layers](#osi-model-and-network-layers)
2. [Ethernet (Layer 2)](#ethernet-layer-2)
3. [IP Protocol (Layer 3)](#ip-protocol-layer-3)
4. [TCP Protocol (Layer 4)](#tcp-protocol-layer-4)
5. [UDP Protocol (Layer 4)](#udp-protocol-layer-4)
6. [ICMP Protocol (Layer 3/4)](#icmp-protocol-layer-34)
7. [TCP Three-Way Handshake](#tcp-three-way-handshake)
8. [TCP Connection Lifecycle](#tcp-connection-lifecycle)
9. [Network Flow Concepts](#network-flow-concepts)
10. [Packet Capture Fundamentals](#packet-capture-fundamentals)

---

## OSI Model and Network Layers

AEGIS operates primarily at Layers 2-4 of the OSI model:

```
┌─────────────────────────────────────────┐
│ Layer 7: Application (HTTP, DNS, etc.)  │ ← Not analyzed in Phase 1
├─────────────────────────────────────────┤
│ Layer 6: Presentation                  │
├─────────────────────────────────────────┤
│ Layer 5: Session                       │
├─────────────────────────────────────────┤
│ Layer 4: Transport (TCP, UDP, ICMP)    │ ← AEGIS analyzes
├─────────────────────────────────────────┤
│ Layer 3: Network (IP, IPv6)            │ ← AEGIS analyzes
├─────────────────────────────────────────┤
│ Layer 2: Data Link (Ethernet, MAC)     │ ← AEGIS analyzes
├─────────────────────────────────────────┤
│ Layer 1: Physical (cables, signals)    │
└─────────────────────────────────────────┘
```

### Why This Matters for Security

- **Layer 2 (Ethernet)**: MAC addresses help identify devices on the local network
- **Layer 3 (IP)**: Source/destination IPs are fundamental for network communication and security policies
- **Layer 4 (Transport)**: TCP flags and port information reveal connection state and service types

---

## Ethernet (Layer 2)

### Ethernet Frame Structure

AEGIS parses Ethernet frames to extract:

```
┌──────────────┬──────────────┬──────────────┬──────────────┐
│ Destination  │ Source       │ EtherType    │ Payload      │
│ MAC (6 bytes)│ MAC (6 bytes)│ (2 bytes)    │ (46-1500)    │
└──────────────┴──────────────┴──────────────┴──────────────┘
```

### Key Fields AEGIS Extracts

- **Source MAC**: Identifies the sending network interface
- **Destination MAC**: Identifies the receiving network interface
- **EtherType**: Indicates the next layer protocol (0x0800 for IPv4, 0x86DD for IPv6, 0x0806 for ARP)

### Security Relevance

- MAC addresses can be used for device identification and access control
- MAC spoofing is a common technique in man-in-the-middle attacks
- ARP poisoning attacks manipulate MAC-to-IP mappings

### Implementation in AEGIS

```python
# From app/protocols/parser.py
def _parse_ethernet(self, packet: Packet, parsed: ParsedPacket) -> None:
    if Ether in packet:
        eth_layer = packet[Ether]
        parsed.src_mac = eth_layer.src
        parsed.dst_mac = eth_layer.dst
        parsed.ethertype = eth_layer.type
```

---

## IP Protocol (Layer 3)

### IPv4 Header Structure

AEGIS analyzes IPv4 headers to extract routing and addressing information:

```
┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│ Version │ IHL     │ TOS     │ Total   │ ID      │ Flags   │
│ (4 bits)│ (4 bits)│ (8 bits)│ Length  │(16 bits)│ (3 bits)│
├─────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ Fragment │ TTL     │ Protocol│ Header  │ Source  │ Dest    │
│ Offset   │ (8 bits)│ (8 bits)│ Checksum│ IP      │ IP      │
│(13 bits) │         │         │         │(32 bits)│(32 bits)│
└─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘
```

### Key Fields AEGIS Extracts

- **Source IP**: Originating host address (e.g., 192.168.1.1)
- **Destination IP**: Target host address (e.g., 192.168.1.2)
- **TTL (Time To Live)**: Decremented at each router, prevents routing loops
- **Protocol**: Next layer protocol (6=TCP, 17=UDP, 1=ICMP)

### Security Relevance

- **IP Addresses**: Fundamental for network segmentation, firewall rules, and geolocation
- **TTL Analysis**: Unusual TTL values can indicate network mapping or traceroute attempts
- **IP Spoofing**: Attackers may forge source IPs to hide identity or bypass filters
- **Fragmentation**: Can be used to evade detection (fragmentation attacks)

### TTL Security Implications

Normal TTL values:
- Windows: Typically 128
- Linux/Unix: Typically 64
- Network devices: Typically 255

Security significance:
- Very low TTL may indicate network reconnaissance
- TTL differences can reveal OS fingerprinting attempts
- Abnormal TTL decay patterns may indicate routing anomalies

### Implementation in AEGIS

```python
# From app/protocols/parser.py
def _parse_network_layer(self, packet: Packet, parsed: ParsedPacket) -> None:
    if IP in packet:
        ip_layer = packet[IP]
        parsed.network_protocol = Protocol.IPV4
        parsed.src_ip = ip_layer.src
        parsed.dst_ip = ip_layer.dst
        parsed.ttl = ip_layer.ttl
```

---

## TCP Protocol (Layer 4)

### TCP Segment Structure

AEGIS deeply analyzes TCP segments due to their security significance:

```
┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│ Source  │ Dest    │ Sequence│ Ack     │ Data    │ Reserved│
│ Port    │ Port    │ Number  │ Number  │ Offset  │ (6 bits)│
│(16 bits)│(16 bits)│(32 bits)│(32 bits)│ (4 bits)│         │
├─────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
│ Flags   │ Window  │ Checksum│ Urgent  │ Options │ Payload │
│ (9 bits)│(16 bits)│(16 bits)│ Pointer │         │         │
│         │         │         │(16 bits)│         │         │
└─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘
```

### TCP Flags (Critical for Security)

AEGIS extracts and analyzes all TCP flags:

| Flag | Name | Purpose | Security Significance |
|------|------|---------|----------------------|
| SYN | Synchronize | Initiates connection | Port scans, SYN floods |
| ACK | Acknowledgment | Confirms receipt | Connection tracking |
| FIN | Finish | Closes connection | Normal termination |
| RST | Reset | Aborts connection | Rejection, attacks |
| PSH | Push | Deliver immediately | Data timing analysis |
| URG | Urgent | Priority data | Rarely used legitimately |
| ECE | ECN-Echo | Congestion notification | Network condition analysis |
| CWR | Congestion Window Reduced | Congestion response | Network condition analysis |

### Flag Combinations and Their Meanings

**SYN only**: Connection initiation (first step of handshake)
- Normal: Client starting a connection
- Suspicious: Rapid SYN packets may indicate port scanning or SYN flood

**SYN-ACK**: Connection response (second step of handshake)
- Normal: Server accepting connection
- Suspicious: Unusual SYN-ACK ratio may indicate spoofing

**ACK only**: Data acknowledgment
- Normal: Part of established connection data transfer
- Suspicious: ACK scans (stealth port scanning technique)

**FIN only**: Connection termination
- Normal: Graceful connection close
- Suspicious: FIN scans (stealth port scanning)

**RST**: Connection reset
- Normal: Connection rejected or error
- Suspicious: RST floods, port scanning responses

### Security Relevance

- **Port Scanning**: Sequential SYN packets to many ports
- **SYN Floods**: Overwhelming SYN packets without completing handshakes
- **Connection Tracking**: Understanding connection state is crucial for stateful firewalls
- **Stealth Scanning**: Using unusual flag combinations to evade detection
- **Covert Channels**: Abusing flag fields for data exfiltration

### Implementation in AEGIS

```python
# From app/models/packet.py
@dataclass
class TCPFlags:
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False
    ece: bool = False
    cwr: bool = False
    
    def is_syn_only(self) -> bool:
        """Check if this is a SYN-only packet (connection initiation)."""
        return self.syn and not (self.ack or self.fin or self.rst)
    
    def is_syn_ack(self) -> bool:
        """Check if this is a SYN-ACK packet (connection response)."""
        return self.syn and self.ack and not (self.fin or self.rst)
```

---

## UDP Protocol (Layer 4)

### UDP Datagram Structure

AEGIS analyzes UDP for connectionless protocols:

```
┌─────────┬─────────┬─────────┬─────────┐
│ Source  │ Dest    │ Length  │ Checksum│
│ Port    │ Port    │(16 bits)│(16 bits)│
│(16 bits)│(16 bits)│         │         │
├─────────┴─────────┴─────────┴─────────┤
│ Payload (variable length)             │
└───────────────────────────────────────┘
```

### Key Fields AEGIS Extracts

- **Source Port**: Originating application port
- **Destination Port**: Target application port
- **Length**: Total UDP datagram length

### Security Relevance

- **Connectionless**: No handshake, harder to track state
- **DNS**: Typically uses UDP (port 53), DNS amplification attacks
- **Amplification Attacks**: UDP's lack of handshake makes it ideal for reflection attacks
- **Covert Channels**: UDP can be abused for data exfiltration
- **Service Discovery**: Many services use UDP for broadcasting

### Common UDP Services and Security Implications

| Port | Service | Security Considerations |
|------|---------|------------------------|
| 53 | DNS | DNS amplification, cache poisoning |
| 67/68 | DHCP | Rogue DHCP servers, information leakage |
| 123 | NTP | NTP amplification attacks |
| 161 | SNMP | Default communities, information disclosure |
| 514 | Syslog | Unencrypted logging, injection |

### Implementation in AEGIS

```python
# From app/protocols/parser.py
elif UDP in packet:
    udp_layer = packet[UDP]
    parsed.transport_protocol = TransportProtocol.UDP
    parsed.src_port = udp_layer.sport
    parsed.dst_port = udp_layer.dport
```

---

## ICMP Protocol (Layer 3/4)

### ICMP Message Structure

AEGIS monitors ICMP for network diagnostics and potential reconnaissance:

```
┌─────────┬─────────┬─────────┬─────────┐
│ Type    │ Code    │ Checksum│ Rest of │
│ (8 bits)│ (8 bits)│(16 bits)│ Header  │
├─────────┴─────────┴─────────┴─────────┤
│ Payload (variable)                    │
└───────────────────────────────────────┘
```

### Common ICMP Types

| Type | Name | Purpose | Security Significance |
|------|------|---------|----------------------|
| 0 | Echo Reply | Ping response | Network mapping |
| 8 | Echo Request | Ping request | Network reconnaissance |
| 3 | Destination Unreachable | Error reporting | Network topology discovery |
| 11 | Time Exceeded | TTL expiration | Traceroute, network mapping |

### Security Relevance

- **Network Mapping**: ICMP echo requests can reveal active hosts
- **Traceroute**: ICMP time exceeded messages reveal network topology
- **Covert Channels**: ICMP can be tunneled for data exfiltration
- **DoS Attacks**: ICMP floods can overwhelm targets
- **Tunneling**: ICMP can encapsulate other protocols

### Implementation in AEGIS

```python
# From app/protocols/parser.py
elif ICMP in packet:
    icmp_layer = packet[ICMP]
    parsed.transport_protocol = TransportProtocol.ICMP
    parsed.icmp_type = icmp_layer.type
    parsed.icmp_code = icmp_layer.code
```

---

## TCP Three-Way Handshake

### The Handshake Process

AEGIS tracks the TCP three-way handshake to understand connection state:

```
Client                                    Server
  │                                         │
  │────────── SYN (seq=x) ─────────────────>│
  │                                         │
  │<───────── SYN-ACK (seq=y, ack=x+1) ────│
  │                                         │
  │────────── ACK (seq=x+1, ack=y+1) ──────>│
  │                                         │
  │          ESTABLISHED                     │
```

### Security Relevance

- **Connection Tracking**: Essential for stateful firewalls
- **SYN Flood Detection**: Many SYNs without completing handshake
- **Stealth Scanning**: Manipulating handshake flags for reconnaissance
- **Connection Hijacking**: Predicting sequence numbers for session takeover

### AEGIS Handshake Analysis

AEGIS can detect:
- **Incomplete Handshakes**: SYN without SYN-ACK (potential scan)
- **Handshake anomalies**: Unusual flag combinations
- **Connection rate**: Abnormal connection establishment rates

---

## TCP Connection Lifecycle

### Connection States

AEGIS tracks TCP connection states:

```
CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED
         ↘ (SYN received) ↗
        LISTEN → SYN_RECEIVED → ESTABLISHED
```

### Normal Termination

```
Client                                    Server
  │                                         │
  │────────── FIN (seq=x) ─────────────────>│
  │                                         │
  │<───────── ACK (ack=x+1) ────────────────│
  │  FIN_WAIT_1                              │  CLOSE_WAIT
  │  FIN_WAIT_2                              │
  │<───────── FIN (seq=y) ──────────────────│
  │                                         │
  │────────── ACK (ack=y+1) ───────────────>│
  │  TIME_WAIT                               │  LAST_ACK
  │                                         │  CLOSED
  │  CLOSED                                  │
```

### Abnormal Termination

```
Client                                    Server
  │                                         │
  │────────── RST ─────────────────────────>│
  │                                         │
  │          CLOSED (both sides)            │
```

### Security Relevance

- **Connection State Analysis**: Detecting abnormal connection patterns
- **Incomplete Connections**: May indicate scanning or attacks
- **Connection Flooding**: Overwhelming with incomplete connections
- **Session Hijacking**: Exploiting connection state

---

## Network Flow Concepts

### What is a Flow?

AEGIS aggregates packets into flows for analysis:

**Flow Definition**: A unidirectional or bidirectional sequence of packets between two endpoints sharing common characteristics.

### Flow Keys

AEGIS uses multiple flow key strategies:

**5-Tuple Flow** (most precise):
```
(Source IP, Destination IP, Source Port, Destination Port, Protocol)
```

**3-Tuple Flow** (for broader analysis):
```
(Source IP, Destination IP, Protocol)
```

**Bidirectional Flow** (for conversation tracking):
```
Canonicalized endpoint pair: direction-independent over the two
(IP, port) endpoints plus protocol.
```

### Flow Aggregation

AEGIS aggregates packets within time windows:

```
Time Window: 5 seconds (configurable)

Flow: 192.168.1.50 → 192.168.1.1, TCP, Port 80
┌─────────────────────────────────────────┐
│ Packets: 150                            │
│ Bytes: 85,000                           │
│ Duration: 4.8 seconds                   │
│ SYN count: 1                            │
│ ACK count: 140                          │
│ FIN count: 1                            │
│ Unique ports: 1                         │
└─────────────────────────────────────────┘
```

### Security Relevance

- **Behavioral Analysis**: Flows reveal communication patterns
- **Anomaly Detection**: Deviations from normal flow patterns
- **Bandwidth Analysis**: Identifying data exfiltration or DoS
- **Connection Tracking**: Understanding long-lived connections

### Feature Observations in AEGIS

AEGIS extracts features from a **per-window Flow**, not directly from raw
packets and not from lifetime conversations across windows.

Canonical feature output is a **finalized-only FeatureObservation**:

- extraction unit: one `Flow` inside one time window
- observation identity: `(flow_key, window_start, window_end)`
- metadata is kept alongside the numeric feature values
- the current mutable window does not emit canonical observations
- a retained fixed window also does not emit until it is no longer mutable by
  accepted late packets
- sliding windows may legitimately produce multiple observations for the same
  traffic because overlapping window bounds represent different temporal views

Event-time semantics apply throughout:

- packet assignment to flows/windows uses `packet.timestamp`
- accepted late packets are incorporated before canonical observation emission
- removed historical windows are not recreated for canonical output

### Implementation in AEGIS

```python
# From app/models/packet.py
def get_flow_key(self) -> str:
    """Generate a legacy directional packet key string."""
    if not self.src_ip or not self.dst_ip:
        return f"unknown_{self.timestamp.timestamp()}"

    return f"{self.src_ip}_{self.dst_ip}_{self.transport_protocol.value}"

def get_five_tuple(self) -> Optional[tuple]:
    """Get the 5-tuple for precise flow tracking."""
    if not all([self.src_ip, self.dst_ip, self.src_port, self.dst_port]):
        return None

    return (
        self.src_ip,
        self.dst_ip,
        self.src_port,
        self.dst_port,
        self.transport_protocol.value
    )
```

---

## Packet Capture Fundamentals

### How Packet Capture Works

AEGIS captures packets using the following process:

```
Network Interface → Network Driver → Packet Capture Library → AEGIS
                      ↓                    ↓                    ↓
                 Npcap/WinPcap         libpcap           Scapy
                 (Windows)             (Linux)         (Python)
```

### Capture Filters (BPF Syntax)

AEGIS uses BPF (Berkeley Packet Filter) syntax for efficient filtering:

```
# Capture only TCP and UDP
tcp or udp

# Capture HTTP traffic
tcp port 80

# Capture DNS traffic
udp port 53

# Capture traffic from specific IP
src host 192.168.1.1

# Complex filter
tcp and (port 80 or port 443) and src net 192.168.1.0/24
```

### Promiscuous Mode

**Normal Mode**: Interface only processes packets destined to its MAC address
**Promiscuous Mode**: Interface processes all packets on the network segment

Security implications:
- Required for monitoring network-wide traffic
- Can be used for legitimate monitoring or malicious sniffing
- Hub networks: All traffic visible to all interfaces
- Switched networks: Normally only see broadcast/multicast and own traffic

### Privilege Requirements

Packet capture requires elevated privileges:

**Windows**: Administrator privileges
- Npcap driver installation
- Raw socket access

**Linux**: root privileges or CAP_NET_RAW capability
- Raw socket access
- libpcap installation

### Implementation in AEGIS

```python
# From app/capture/packet_capture.py
def start(self) -> bool:
    """Start packet capture."""
    try:
        sniff(
            iface=self.interface,
            filter=self.capture_filter,  # BPF filter
            prn=self._packet_handler,    # Packet callback
            stop_filter=lambda x: self.stop_event.is_set(),
            store=False,  # Don't store packets in memory
        )
    except Exception as e:
        logger.error(f"Capture error: {e}")
```

---

## Security Applications of Network Analysis

### Attack Detection Capabilities

Based on the networking concepts above, AEGIS can detect:

1. **Port Scanning**
   - Many SYN packets to different destination ports
   - High unique destination port count in time window
   - Low connection completion rate

2. **SYN Flood**
   - High SYN rate
   - High incomplete connection ratio
   - SYN packets without corresponding SYN-ACK

3. **Traffic Anomalies**
   - Sudden packet rate spikes
   - Unusual byte transfer patterns
   - Abnormal protocol distributions

4. **Network Reconnaissance**
   - ICMP echo requests to many hosts
   - Low TTL values (traceroute)
   - Unusual flag combinations

### Why This Matters

Understanding these networking fundamentals is crucial because:

1. **Accuracy**: Detection rules must be based on correct protocol understanding
2. **False Positives**: Misunderstanding protocols leads to incorrect alerts
3. **Evasion**: Attackers exploit protocol quirks to evade detection
4. **Performance**: Efficient parsing requires understanding packet structure
5. **Explainability**: Security analysts need to understand why alerts were generated

---

## Conclusion

AEGIS demonstrates deep understanding of:

- **Protocol Structure**: Ethernet, IP, TCP, UDP, ICMP headers
- **Connection State**: TCP handshake, connection lifecycle
- **Network Behavior**: Flow aggregation, traffic patterns
- **Security Implications**: How protocol features can be abused

This networking foundation enables AEGIS to build sophisticated detection rules while maintaining accuracy and explainability.

The implementation in Phase 1 focuses on correct parsing and observation, providing the foundation for the detection engines that will be built in subsequent phases.
