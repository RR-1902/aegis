# AEGIS — Intelligent Network Intrusion Detection & Response System

> **Observe the network. Detect threats. Protect the system.**

AEGIS is a complete academic-grade but genuinely functional Network Intrusion Detection and Response System (NIDS) designed for Computer Networks and Cybersecurity education and research.

## 🛡️ What is AEGIS?

AEGIS is a defensive security system that:

- **Observes** network traffic in real-time
- **Analyzes** packets, flows, and protocol behavior
- **Detects** suspicious patterns using deterministic rules and machine learning
- **Scores** threats based on multiple evidence sources
- **Responds** with controlled defensive actions
- **Logs** all security events for audit trails
- **Visualizes** activity through a real-time dashboard

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

```
NETWORK → Packet Capture → Protocol Parser → Flow Builder → Finalized Feature Observations
                                                                       ↓
                                                    ┌───────────────┐
                                                    │ Rule Engine   │
                                                    │ (Deterministic)│
                                                    └───────────────┘
                                                            ↓
                                                    ┌───────────────┐
                                                    │ ML Engine     │
                                                    │ (Anomaly)     │
                                                    └───────────────┘
                                                            ↓
                                                    ┌───────────────┐
                                                    │ Threat Engine │
                                                    │ (Scoring)     │
                                                    └───────────────┘
                                                            ↓
                                                    ┌───────────────┐
                                                    │ Policy Engine │
                                                    │ (Response)    │
                                                    └───────────────┘
                                                            ↓
                                              Alert → Block → Isolate
                                                            ↓
                                              Security Event Store
                                                            ↓
                                            REST API + Real-time Dashboard
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

### 🚧 Phase 3: Rule-Based Detection (PENDING)

### 🚧 Phase 4: Threat Scoring + Event Persistence (PENDING)

### 🚧 Phase 5: Controlled Response Engine (PENDING)

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

```
aegis/
├── app/
│   ├── __init__.py
│   ├── main.py                          # FastAPI application entry point
│   ├── config/
│   │   ├── __init__.py
│   │   ├── settings.py                  # Pydantic settings from env vars
│   │   └── thresholds.py                # Detection thresholds configuration
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── packet_capture.py            # Packet capture interface
│   │   └── capture_manager.py           # Capture lifecycle management
│   ├── protocols/
│   │   ├── __init__.py
│   │   └── parser.py                    # Protocol parser (Ethernet/IP/TCP/UDP)
│   ├── flows/
│   │   ├── __init__.py
│   │   ├── flow_builder.py              # Flow aggregation logic
│   │   ├── flow_key.py                  # Flow key definitions
│   │   └── time_window.py               # Time window management
│   ├── features/
│   │   ├── __init__.py
│   │   ├── extractor.py                 # Feature extraction from flows
│   │   └── feature_definitions.py       # Feature catalog
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── base_detector.py             # Base detector interface
│   │   ├── rules/
│   │   │   ├── __init__.py
│   │   │   ├── port_scan.py             # Port scan detection
│   │   │   ├── syn_flood.py             # SYN flood detection
│   │   │   ├── traffic_anomaly.py      # Traffic spike detection
│   │   │   └── auth_abuse.py            # Authentication abuse detection
│   │   └── anomaly/
│   │       ├── __init__.py
│   │       └── isolation_forest.py     # Anomaly detection (Phase 7)
│   ├── scoring/
│   │   ├── __init__.py
│   │   ├── threat_engine.py             # Threat scoring logic
│   │   └── risk_calculator.py           # Risk score calculation
│   ├── response/
│   │   ├── __init__.py
│   │   ├── policy_engine.py             # Response policy enforcement
│   │   ├── actions.py                   # Response action implementations
│   │   └── safety.py                    # SAFE_MODE controls
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py                  # Database connection management
│   │   ├── models.py                    # SQLAlchemy models
│   │   └── repositories.py              # Data access layer
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   ├── events.py                # Security events API
│   │   │   ├── metrics.py               # Live metrics API
│   │   │   └── responses.py             # Response actions API
│   │   └── websocket/
│   │       ├── __init__.py
│   │       └── manager.py               # WebSocket connection manager
│   └── models/
│       ├── __init__.py
│       ├── packet.py                    # Packet data models
│       ├── flow.py                      # Flow data models
│       ├── detection.py                 # Detection result models
│       └── event.py                     # Security event models
├── tests/
│   ├── __init__.py
│   ├── test_protocol_parser.py
│   ├── test_flow_builder.py
│   ├── test_feature_extraction.py
│   ├── test_detection_rules.py
│   ├── test_scoring.py
│   ├── test_response_safety.py
│   └── test_integration.py
├── data/
│   ├── raw/                             # Raw pcap files for testing
│   ├── processed/                       # Processed data
│   └── models/                          # Trained ML models
├── scripts/
│   ├── setup_db.py                      # Database initialization
│   ├── generate_test_traffic.py         # Test traffic generator
│   └── test_capture.py                  # Packet capture test
├── docs/
│   ├── architecture.md
│   ├── detection.md
│   ├── networking.md
│   ├── ml.md
│   ├── response.md
│   ├── testing.md
│   ├── deployment.md
│   ├── threat_model.md
│   └── api.md
├── frontend/
│   ├── index.html
│   ├── static/
│   │   ├── css/
│   │   └── js/
│   └── templates/
├── .env.example
├── requirements.txt
├── pyproject.toml
└── README.md
```

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

### Integration Tests
```bash
python -m pytest tests/test_integration.py -v
```

### Packet Capture Test
```bash
python scripts/test_capture.py
```

## 📊 Detection Capabilities

### Supported Attack Types

1. **Port Scanning / Reconnaissance**
   - Detects unusual destination port access patterns
   - Analyzes connection rates and unique port counts

2. **SYN Flood / Connection Flood**
   - Identifies high TCP SYN activity
   - Detects incomplete connection patterns

3. **Brute-Force Authentication Behavior**
   - Monitors repeated failed connection attempts
   - Analyzes authentication failure patterns

4. **Traffic Anomaly / Volumetric Anomaly**
   - Detects packet/byte rate spikes
   - Identifies connection rate anomalies

### Detection Approach

AEGIS uses a **hybrid detection approach**:

1. **Deterministic Rules**: Explicit, explainable rules with documented thresholds
2. **Anomaly Detection**: Statistical and ML-based anomaly detection (Phase 7)
3. **Threat Scoring**: Combines evidence from multiple sources into unified risk score
4. **Policy-Driven Response**: Configurable response policies based on risk levels

## 🔒 Safety Features

### SAFE_MODE

By default, AEGIS runs in **SAFE_MODE**:

- All blocking actions are simulated
- Actions are logged but not executed
- Safe for development and testing

To enable active responses:
```bash
SAFE_MODE=false
```

**Warning**: Only disable SAFE_MODE in controlled lab environments.

### Audit Trail

All actions are logged with:
- Timestamp
- Target (IP, port, etc.)
- Reason
- Action taken
- Execution status

## 📚 Documentation

- [Networking Concepts](docs/networking.md) - Detailed explanation of protocols and networking fundamentals
- [Architecture](docs/architecture.md) - System architecture and data flow
- [Detection Methods](docs/detection.md) - Detection algorithms and rule definitions
- [Response System](docs/response.md) - Response policies and safety mechanisms
- [API Documentation](docs/api.md) - REST API and WebSocket endpoints

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

4. **Machine Learning Integration**
   - Feature engineering
   - Anomaly detection
   - Model evaluation
   - Limitations and trade-offs

## 🚨 Limitations

- **Platform**: Designed for Linux, Windows support varies
- **Scale**: Not designed for enterprise-scale networks
- **Encryption**: Cannot inspect encrypted payload data
- **Real-Time**: Processing latency depends on traffic volume
- **ML Accuracy**: Model performance depends on training data quality

## 🔮 Future Work

- Enhanced ML models with ensemble methods
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

**AEGIS** — Protecting networks through intelligent observation and response.
