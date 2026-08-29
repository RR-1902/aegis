# AEGIS — Intelligent Network Intrusion Detection & Response System

> **Observe the network. Detect threats. Protect the system.**

AEGIS is a complete academic-grade but genuinely functional Network Intrusion Detection and Response System (NIDS) designed for Computer Networks and Cybersecurity education and research.

## 🛡️ What is AEGIS?

AEGIS is a defensive security system that currently:

- **Observes** network traffic in real-time
- **Analyzes** packets, flows, and protocol behavior
- **Detects** suspicious patterns using deterministic rules
- **Scores** combined detection evidence with heuristic risk scoring

Planned future phases include dashboard/API integration, richer response execution, and ML-based analysis.

## 🎯 Project Goals

Build a working system that demonstrates real understanding of:

- Computer Networks (TCP/IP, protocols, packet structure)
- Packet capture and traffic analysis
- Network flows and feature extraction
- Intrusion detection (rule-based + ML)
- Anomaly detection and threat scoring
- Security event processing
- Controlled response mechanisms
- Linux networking/security primitives
- Backend architecture and real-time systems

## 🏗️ Architecture

### Implemented pipeline

```
NETWORK → Packet Capture → Protocol Parser → Flow Builder → Finalized Feature Observations
                                                                       ↓
                                                    ┌───────────────┐
                                                    │ Rule Engine   │
                                                    │ (Deterministic)│
                                                    └───────────────┘
                                                            ↓
                                                    ┌───────────────┐
                                                    │ Risk Scoring  │
                                                    │ (Heuristic)   │
                                                    └───────────────┘
```

### Implemented extended pipeline

```
Finalized Feature Observations
            ↓
     Deterministic Rules
            ↓
       Risk Scoring
            ↓
      Policy Engine
            ↓
   Simulation-Only Response
            ↓
       Security Events
            ↓
           SQLite
```

### Planned/future architecture

```
Security Events
      ↓
API / Dashboard / WebSocket
      ↓
Reporting / Investigation / ML
```

## 📋 Current Status

### ✅ Phase 1: Packet Capture + Parser (COMPLETE)

- **Project Structure**: Complete modular architecture
- **Packet Models**: Structured representations of network packets
- **Protocol Parser**: Ethernet, IPv4, TCP, UDP, ICMP parsing
- **Packet Capture**: Scapy-based capture with BPF filtering
- **Configuration**: Environment-based settings with thresholds
- **Testing**: Comprehensive unit tests for parser
- **Documentation**: Detailed networking concepts documentation

### 🚧 Phase 2: Flow Builder + Feature Extraction (IMPLEMENTED)

### 🚧 Phase 3: Rule-Based Detection (IMPLEMENTED)

### 🚧 Phase 4: Heuristic Risk Scoring (IMPLEMENTED)

### 🚧 Phase 4b: Security Event + SQLite Persistence (IMPLEMENTED)

### 🚧 Phase 5: Policy Engine (IMPLEMENTED)

### 🚧 Phase 5b: Response Engine (SIMULATION-ONLY IMPLEMENTED)

### 🚧 Phase 6: Real-Time Dashboard (PENDING)

### 🚧 Phase 7: ML/Anomaly Detection (PENDING)

### 🚧 Phase 8: AI Investigation Layer (PENDING)

### 🚧 Phase 9: Testing, Hardening, Documentation (PENDING)

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Administrator/root privileges (for packet capture)
- Npcap (Windows) or libpcap (Linux) for packet capture

### Installation

1. **Clone the repository**
```bash
cd "C:\Users\admin\Downloads\Computer Networks\aegis"
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your settings
```

4. **Run tests**
```bash
# Test protocol parser
python -m pytest tests/test_protocol_parser.py -v

# Test packet capture (requires Npcap)
python scripts/test_capture.py
```

## 📁 Project Structure

### Implemented repository structure

```
aegis/
├── app/
│   ├── __init__.py
│   ├── api/                            # Present but not yet implemented in this phase
│   ├── capture/
│   │   └── packet_capture.py           # Packet capture interface
│   ├── config/
│   │   ├── __init__.py
│   │   ├── settings.py                 # Runtime configuration
│   │   └── thresholds.py               # Threshold documentation/helper config
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── engine.py                   # Deterministic detection engine
│   │   ├── anomaly/                    # Reserved for future anomaly/ML work
│   │   └── rules/
│   │       ├── __init__.py
│   │       ├── base.py                 # Detection rule interface
│   │       ├── port_scan.py            # Port scan detection
│   │       └── syn_flood.py            # SYN flood detection
│   ├── features/
│   │   ├── __init__.py
│   │   ├── extractor.py                # Feature extraction / observations
│   │   └── feature_definitions.py      # Feature catalog
│   ├── flows/
│   │   ├── flow_builder.py             # Flow aggregation logic
│   │   ├── flow_key.py                 # Flow identity strategies
│   │   └── time_window.py              # Fixed + sliding windows
│   ├── models/
│   │   ├── __init__.py
│   │   ├── detection.py                # Detection models
│   │   ├── flow.py                     # Flow / FeatureObservation models
│   │   ├── packet.py                   # Packet models
│   │   ├── response.py                 # Response result models
│   │   ├── risk.py                     # Risk scoring models
│   │   └── security_event.py           # Durable security event model
│   ├── protocols/
│   │   └── parser.py                   # Protocol parser
│   ├── response/                       # Simulation-only response engine
│   ├── scoring/
│   │   ├── __init__.py
│   │   └── risk_scorer.py              # Heuristic risk scoring
│   └── storage/                        # SQLite-backed security event persistence
├── docs/
│   ├── detection.md
│   ├── networking.md
│   ├── policy.md
│   ├── response.md
│   ├── scoring.md
│   └── security_events.md
├── tests/
│   ├── __init__.py
│   ├── test_detection_rules.py
│   ├── test_feature_extraction.py
│   ├── test_flow_builder.py
│   ├── test_protocol_parser.py
│   └── test_scoring.py
├── requirements.txt
└── README.md
```

### Planned/future areas

The repository still contains placeholder or future-facing areas such as
`app/api/` and `app/detection/anomaly/`. API delivery, dashboards, WebSocket
integration, richer response execution, and ML remain future work.

## 🔧 Configuration

Key environment variables (see `.env.example`):

```bash
# Network Capture
CAPTURE_INTERFACE=Wi-Fi 2
CAPTURE_FILTER=tcp or udp

# Flow Processing
FLOW_WINDOW_SECONDS=5

# Detection Thresholds
PORT_SCAN_THRESHOLD=20
SYN_RATE_THRESHOLD=10.0
TRAFFIC_SPIKE_MULTIPLIER=3.0

# Response Policy
SAFE_MODE=true
BLOCK_DURATION_SECONDS=60

# Database
DATABASE_URL=sqlite:///aegis.db
```

## 🧪 Testing

### Unit Tests
```bash
python -m pytest tests/ -v
```

### Packet Capture Test
```bash
python scripts/test_capture.py
```

## 📊 Detection Capabilities

### Supported Attack Types

Currently implemented:

1. **Port Scanning / Reconnaissance**
   - Detects unusual destination port access patterns
   - Analyzes unique port counts with explainable rule evidence

2. **SYN Flood / Connection Flood**
   - Identifies high TCP SYN activity
   - Detects incomplete connection patterns

Planned/future:

3. **Brute-Force Authentication Behavior**
4. **Traffic Anomaly / Volumetric Anomaly**

### Detection Approach

AEGIS currently uses:

1. **Deterministic Rules**: Explicit, explainable rules with documented thresholds
2. **Heuristic Risk Scoring**: Deterministic additive scoring over detection results

Planned/future phases include anomaly detection, policy, and response.

## 🔒 Safety Features

### SAFE_MODE

`SAFE_MODE` is present in runtime configuration for future response phases.
The current implemented packet/flow/feature/detection/scoring pipeline does not
execute blocking or remediation actions.

## 📚 Documentation

- [Networking Concepts](docs/networking.md) - Detailed explanation of protocols and networking fundamentals

- [Detection Methods](docs/detection.md) - Deterministic detection engine and rule definitions
- [Risk Scoring](docs/scoring.md) - Heuristic risk scoring and level mapping
- [Policy](docs/policy.md) - Conservative policy decisions and SAFE_MODE behavior
- [Response](docs/response.md) - Simulation-only response handling and safety boundary
- [Security Events](docs/security_events.md) - Durable security-event model and SQLite persistence


## 🎓 Educational Value

AEGIS demonstrates:

1. **Networking Fundamentals**
   - TCP/IP protocol stack
   - Packet structure and parsing
   - Connection state management
   - Flow aggregation

2. **Security Concepts**
   - Intrusion detection methodologies
   - Threat scoring and risk assessment
   - Defensive response strategies
   - Audit trail and compliance

3. **Software Engineering**
   - Modular architecture
   - Configuration management
   - Testing strategies
   - Documentation practices

4. **Planned Machine Learning Integration**
   - Feature engineering foundations
   - Future anomaly detection work
   - Model evaluation concepts
   - Limitations and trade-offs

## 🚨 Limitations

- **Platform**: Designed for Linux, Windows support varies
- **Scale**: Not designed for enterprise-scale networks
- **Encryption**: Cannot inspect encrypted payload data
- **Real-Time**: Processing latency depends on traffic volume
- **Future ML Work**: ML/anomaly detection is planned but not yet implemented

## 🔮 Future Work

- Event persistence and historical storage
- Response/policy engine implementation
- API and dashboard implementation
- ML/anomaly detection implementation
- Support for additional protocols (DNS, HTTP analysis)
- Geographic IP analysis
- User behavior analytics
- Integration with SIEM systems
- Advanced visualization and reporting

## 📄 License

This project is for educational and research purposes.

## 🤝 Contributing

This is an academic project. Contributions should focus on:
- Educational value
- Clarity and documentation
- Security best practices
- Testing and validation

## 📧 Support

For questions or issues, please refer to the documentation or create an issue in the repository.

---

**AEGIS** — Protecting networks through intelligent observation, detection, and scoring.
