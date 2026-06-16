# Kyber-6G Project

## Secure 5G/6G Drone Swarm Communication Using Post-Quantum Cryptography (CRYSTALS-Kyber)

This project designs and simulates a secure 5G/6G communication system using NS-3, evaluating how post-quantum cryptography (CRYSTALS-Kyber KEM + AES-256-GCM) affects network performance in drone swarm and mobile UE scenarios. It replaces quantum-vulnerable ECC/ECDH with the NIST-standardized Kyber key encapsulation mechanism and provides a full PQC security framework, an interactive visualization website, and publication-ready analysis plots.

### Project Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     Kyber-6G System Architecture                 │
│                                                                  │
│  Drone Swarm / UE Layer                                          │
│  ┌────────┐  ┌────────┐  ┌────────┐       ┌────────┐            │
│  │ Drone1 │  │ Drone2 │  │ Drone3 │  ...  │ DroneN │            │
│  │ (UE)   │  │ (UE)   │  │ (UE)   │       │ (UE)   │            │
│  └───┬────┘  └───┬────┘  └───┬────┘       └───┬────┘            │
│      │  Kyber KEM + AES-256-GCM encrypted      │                 │
│  ────┴──────────────────────────────────────────┴────────────     │
│                         5G NR Air Interface                       │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐                      │
│  │  gNB-1  │    │  gNB-2  │    │  gNB-N  │    (relay only)      │
│  └────┬────┘    └────┬────┘    └────┬────┘                      │
│       └──────────┬───┴─────────────┘                             │
│            ┌─────┴─────┐                                         │
│            │  EPC/5GC   │   X2 handover between gNBs             │
│            │  (PGW)     │                                        │
│            └─────┬─────┘                                         │
│             ┌────┴────┐                                          │
│             │ Remote  │   Ground Control / Backend               │
│             │  Host   │                                          │
│             └─────────┘                                          │
└──────────────────────────────────────────────────────────────────┘
```

### Core Security Stack

| Layer | Component | Description |
|-------|-----------|-------------|
| KEM | CRYSTALS-Kyber-768 | NIST FIPS 203 post-quantum key encapsulation |
| KEM | X25519-ECDH | Classical key exchange (hybrid mode) |
| KEM | Hybrid Combiner | HKDF-based fusion of Kyber + X25519 shared secrets |
| Signature | ML-DSA-65 | Post-quantum digital signatures for handshake auth |
| Encryption | AES-256-GCM | Symmetric encryption of data plane traffic |
| Key Mgmt | Adaptive Key Manager | Mobility-aware rekeying with forward secrecy |

---

## Implementation Steps

| Step | Description | Status |
|------|-------------|--------|
| 1 | Basic 5G NR communication (1 gNB + 2 UEs, UDP) | Done |
| 2 | CRYSTALS-Kyber key exchange between users (liboqs) | Done |
| 3 | AES-256-GCM encryption using Kyber-derived shared secret | Done |
| 4 | User mobility and X2 handover between gNBs | Done |
| 5 | Performance analysis (throughput, delay, jitter, packet loss) | Done |
| 6 | Full PQC framework (contrib module with hybrid KEM, ML-DSA, PDCP, RRC) | Done |
| 7 | Drone swarm simulation (multi-drone, commander/follower, queueing analysis) | Done |
| 8 | Publication-ready simulation (5 scenarios: baseline, PQC, dense-urban, high-speed, quantum-attack) | Done |
| 9 | Interactive visualization website (React + Three.js + Recharts) | Done |
| 10 | Plot generation (7 mathematical/performance plots, 300 DPI) | Done |

---

## Development Environment

### System Requirements
- **OS**: Ubuntu 22.04 LTS (or WSL2 with Ubuntu 22.04)
- **Compiler**: GCC 11+ with C++17 support
- **CMake**: 3.22+
- **Python**: 3.10+
- **Node.js**: 18+ (for the visualization website)

### Software Versions
| Component | Version | Notes |
|-----------|---------|-------|
| NS-3 | 3.42 | Network simulator base |
| 5G-LENA NR | v3.1 (5g-lena-v3.1.y) | CTTC 5G NR module |
| liboqs | latest | Open Quantum Safe library (Kyber, ML-DSA) |
| OpenSSL | 3.x | AES-256-GCM, X25519, HKDF |
| Eigen3 | 3.4.0 | For MIMO features |
| SQLite3 | 3.37 | For data output |

### Directory Structure
```
Kyber-6G project/
├── README.md                               # This file
├── create_project.py                       # Generates kyber-6g scratch simulation
├── generate_plots.py                       # Generates 7 publication-ready plots
├── simulation_results.json                 # Simulation output data
├── docs/
│   └── advantages-and-limitations.md       # Analysis of hybrid PQC approach
├── plots/                                  # Generated plot images (300 DPI)
│   ├── handshake_latency_vs_swarm_size.png
│   ├── e2e_application_latency.png
│   ├── rrc_message_overhead.png
│   ├── gateway_queueing_delay.png
│   ├── security_strength_comparison.png
│   ├── ber_reliability_awgn.png
│   └── mm1_queue_validation.png
├── kyber6g-website/                        # Interactive visualization (React/Vite)
│   ├── src/
│   │   ├── App.jsx
│   │   ├── sections/                       # 9 page sections
│   │   │   ├── Hero.jsx                    # Landing with 3D drone scene
│   │   │   ├── Overview.jsx                # Project capabilities
│   │   │   ├── Architecture.jsx            # System architecture diagram
│   │   │   ├── CryptoWorkflow.jsx          # 6-step handshake protocol
│   │   │   ├── MathModels.jsx              # 8 mathematical equations (KaTeX)
│   │   │   ├── Simulation.jsx              # 7-experiment matrix
│   │   │   ├── ResultsDashboard.jsx        # Interactive charts (Recharts)
│   │   │   ├── ThreatModel.jsx             # 4 threat categories + mitigations
│   │   │   └── Conclusions.jsx             # 8 key findings
│   │   └── components/
│   │       ├── DroneSwarmScene.jsx          # Three.js 3D visualization
│   │       ├── Icons.jsx                   # SVG icon library
│   │       ├── Navigation.jsx              # Sticky nav with scroll-spy
│   │       └── ScrollReveal.jsx            # Scroll animation
│   └── public/data/
│       └── simulation_results.json         # Data for dashboard charts
├── ns-3-dev/
│   ├── contrib/
│   │   ├── nr/                             # 5G-LENA NR module (v3.1)
│   │   └── pqc-security/                   # Custom PQC security framework
│   │       ├── CMakeLists.txt
│   │       ├── model/
│   │       │   ├── crystals-kyber-kem.cc/h     # FIPS 203 Kyber-512/768/1024
│   │       │   ├── x25519-ecdh.cc/h            # Classical ECDH baseline
│   │       │   ├── hybrid-kem-combiner.cc/h    # Kyber + X25519 HKDF fusion
│   │       │   ├── ml-dsa-signer.cc/h          # ML-DSA-65 signatures
│   │       │   ├── aes-gcm-cipher.cc/h         # AES-256-GCM encryption
│   │       │   ├── pqc-session-keys.cc/h       # Key material management
│   │       │   ├── pqc-pdcp-layer.cc/h         # PQC-aware PDCP layer
│   │       │   ├── pqc-rrc-extension.cc/h      # RRC handshake enhancement
│   │       │   ├── pqc-handover-manager.cc/h   # Forward secrecy on handover
│   │       │   ├── pqc-adaptive-key-manager.cc/h # Mobility-aware rekeying
│   │       │   ├── pqc-drone-app.cc/h          # Commander/follower drone app
│   │       │   ├── pqc-metrics-collector.cc/h  # Telemetry + CSV export
│   │       │   └── quantum-attacker.cc/h       # HNDL attack simulation
│   │       ├── helper/
│   │       │   ├── pqc-security-helper.cc/h    # PQC stack installer
│   │       │   └── pqc-scenario-helper.cc/h    # Topology scenario builder
│   │       └── test/
│   │           └── pqc-security-test-suite.cc  # Unit tests
│   └── scratch/
│       ├── kyber-5g-sim.cc                 # Step 1: Basic 5G NR baseline
│       ├── drone-swarm-pqc-sim.cc          # Drone swarm PQC evaluation
│       ├── pqc-6g-simulation.cc            # Publication-ready multi-scenario sim
│       ├── run_drone_experiments.sh         # Automated experiment runner (12 configs)
│       ├── plot_drone_metrics.py            # Metrics plotter for drone experiments
│       └── threat_model_assessment.md       # Threat model documentation
```

---

## Quick Start

### 1. Prerequisites (Ubuntu 22.04)
```bash
sudo apt-get update
sudo apt-get install -y cmake g++ python3 python3-dev pkg-config \
    sqlite3 libsqlite3-dev libeigen3-dev libc6-dev \
    qtbase5-dev libgtk-3-dev libfl-dev libxml2 libxml2-dev \
    libgsl-dev libboost-all-dev ninja-build \
    libssl-dev astyle

# Install liboqs (Open Quantum Safe)
cd /tmp
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja && sudo ninja install
```

### 2. Clone and Build NS-3 + NR + PQC Module
```bash
cd "/home/$USER/Kyber-6G project"

# Clone NS-3
git clone https://gitlab.com/nsnam/ns-3-dev.git
cd ns-3-dev
git checkout -b ns-3.42 ns-3.42

# Clone the NR module
cd contrib
git clone https://gitlab.com/cttc-lena/nr.git
cd nr
git checkout -b 5g-lena-v3.1.y origin/5g-lena-v3.1.y
cd ../..

# The pqc-security contrib module is already in contrib/pqc-security/

# Configure and build
./ns3 configure
./ns3 build -j$(nproc)
```

### 3. Run Simulations

#### Step 1 Baseline (Basic 5G NR)
```bash
./ns3 run kyber-5g-sim
```

#### Drone Swarm PQC Simulation
```bash
./ns3 run "drone-swarm-pqc-sim --nDrones=10 --crypto=Kyber768"
```

#### Publication-Ready Multi-Scenario Simulation
```bash
./ns3 run "pqc-6g-simulation --scenario=baseline"
./ns3 run "pqc-6g-simulation --scenario=dense-urban --numUes=15"
./ns3 run "pqc-6g-simulation --scenario=high-speed --speed=120"
./ns3 run "pqc-6g-simulation --scenario=quantum-attack"
```

#### Automated Experiment Suite (12 configurations)
```bash
cd scratch
bash run_drone_experiments.sh
python3 plot_drone_metrics.py
```

#### Kyber-6G Full Simulation (Kyber KEM + AES + Mobility + Handover)
```bash
# First generate the simulation files
cd "/home/$USER/Kyber-6G project"
python3 create_project.py

# Run with Kyber-768
./ns3 run "kyber-6g-sim --kyberLevel=1 --encryption=true --mobility=true --handover=true"

# Run ECC baseline for comparison
./ns3 run "kyber-6g-sim --eccBaseline=true --encryption=true --mobility=true"
```

### 4. Generate Plots
```bash
cd "/home/$USER/Kyber-6G project"
pip install matplotlib numpy
python3 generate_plots.py
# Output: plots/ directory with 7 publication-ready PNGs (300 DPI)
```

### 5. Launch Visualization Website
```bash
cd kyber6g-website
npm install
npm run dev
# Opens at http://localhost:5173
```

---

## Simulation Parameters

### kyber-6g-sim (Full simulation)
| Parameter | Default | Description |
|-----------|---------|-------------|
| `simTime` | 3000 ms | Total simulation duration |
| `packetSize` | 1024 bytes | UDP data packet size |
| `pps` | 100 | Packets per second |
| `speed` | 20 m/s | UE mobility speed |
| `kyberLevel` | 1 | Kyber level: 0=512, 1=768, 2=1024 |
| `mobility` | true | Enable UE mobility |
| `handover` | true | Enable X2 handover between gNBs |
| `kyber` | true | Enable Kyber key exchange |
| `encryption` | true | Enable AES-256-GCM data encryption |
| `eccBaseline` | false | Use ECC baseline for comparison |
| `output` | kyber6g | Output CSV file prefix |

### pqc-6g-simulation (Multi-scenario)
| Scenario | Description |
|----------|-------------|
| `baseline` | 1 gNB, 2 UEs, no PQC (control) |
| `dense-urban` | 7 gNBs, up to 105 UEs, PQC enabled |
| `high-speed` | 5 gNBs, 10 UEs at 120+ m/s with handover |
| `quantum-attack` | Validate HNDL attack fails against PQC |

---

## Plots Generated

| Plot | Description |
|------|-------------|
| Handshake Latency vs Swarm Size | ECC vs Kyber-768 vs Kyber-768-Cached key exchange timing |
| E2E Application Latency | End-to-end latency with area fill comparison |
| RRC Message Overhead | Horizontal bar chart of RRC request/setup sizes |
| Gateway Queueing Delay | Queue delay scaling with drone count |
| Security Strength Comparison | Classical vs quantum adversary computational cost |
| BER / Packet Delivery Ratio | AWGN channel reliability for Navigation (64B) vs Kyber KEM (1184B) |
| M/M/1 Queue Validation | Measured queueing delay vs theoretical M/M/1 model |

---

## References

- [NS-3 Network Simulator](https://www.nsnam.org/)
- [CTTC 5G-LENA NR Module](https://5g-lena.cttc.es/)
- [CRYSTALS-Kyber — NIST FIPS 203](https://pq-crystals.org/kyber/)
- [ML-DSA — NIST FIPS 204](https://pq-crystals.org/dilithium/)
- [Open Quantum Safe (liboqs)](https://openquantumsafe.org/)
- [3GPP TS 38.300 — NR Overall Description](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3191)
