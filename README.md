# Kyber-6G Project

## Secure 5G/6G Communication Using Post-Quantum Cryptography (CRYSTALS-Kyber)

This project designs and simulates a secure 5G/6G communication system using NS-3 where two users communicate through a base station (gNB). The project studies how post-quantum security (CRYSTALS-Kyber key encapsulation) affects network performance, replacing the quantum-vulnerable ECC/ECDH with quantum-safe key exchange.

### Project Architecture

```
User A (UE1) <--5G NR--> gNB (Tower) <--EPC Core--> gNB <--5G NR--> User B (UE2)
```

- **User A & User B**: Mobile devices (UE nodes) that communicate end-to-end
- **gNB (Tower)**: 5G NR base station that forwards traffic (cannot read encrypted data)
- **EPC Core**: Evolved Packet Core handling routing between users

---

## Step 1: Basic 5G NR Communication (Current)

Establishes a stable, working 5G NR network foundation.

### What Step 1 Implements
- 1 gNB (base station) + 2 UE nodes at fixed positions
- 5G NR Non-Standalone (NSA) architecture using the CTTC 5G-LENA module
- UDP data transfer from User A to User B through the gNB
- Basic flow monitoring (throughput, delay, jitter, packet loss)
- No cryptography, no mobility, no handover

### Verified Results
| Metric | Value |
|--------|-------|
| Tx/Rx Packets | 60 / 60 |
| Packet Loss | 0% |
| Throughput | 0.84 Mbps |
| Mean Delay | 8.8 ms |
| Mean Jitter | 0.057 ms |

---

## Development Environment

### System Requirements
- **OS**: Ubuntu 22.04 LTS (or WSL2 with Ubuntu 22.04)
- **Compiler**: GCC 11+ with C++17 support
- **CMake**: 3.22+
- **Python**: 3.10+

### Software Versions
| Component | Version | Notes |
|-----------|---------|-------|
| NS-3 | 3.42 | Network simulator base |
| 5G-LENA NR | v3.1 (5g-lena-v3.1.y) | CTTC 5G NR module |
| Eigen3 | 3.4.0 | For MIMO features |
| SQLite3 | 3.37 | For data output |

### Directory Structure
```
Kyber-6G project/
├── README.md                          # This file
├── ns-3-dev/                          # NS-3 simulator
│   ├── contrib/
│   │   └── nr/                        # 5G-LENA NR module (v3.1)
│   ├── scratch/
│   │   └── kyber-5g-sim.cc           # Step 1 simulation file
│   ├── build/                         # Compiled binaries
│   └── ...
└── write_sim.py                       # Helper script (can be removed)
```

---

## Quick Start

### 1. Prerequisites (Ubuntu 22.04)
```bash
sudo apt-get update
sudo apt-get install -y cmake g++ python3 python3-dev pkg-config \
    sqlite3 libsqlite3-dev libeigen3-dev libc6-dev \
    qtbase5-dev libgtk-3-dev libfl-dev libxml2 libxml2-dev \
    libgsl-dev libboost-all-dev ninja-build
```

### 2. Clone and Build NS-3 + NR Module
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

# Configure and build
./ns3 configure
./ns3 build -j2
```

### 3. Run Step 1 Simulation
```bash
./ns3 run kyber-5g-sim
```

#### With custom parameters:
```bash
./ns3 run "kyber-5g-sim --packetSize=512 --packetsPerSecond=200 --simTime=2000"
```

#### Available parameters:
| Parameter | Default | Description |
|-----------|---------|-------------|
| `simTime` | 1000 ms | Total simulation duration |
| `packetSize` | 1024 bytes | UDP packet size |
| `packetsPerSecond` | 100 | Sending rate |
| `logging` | true | Enable console logging |
| `frequency` | 3.5 GHz | NR central frequency |
| `bandwidth` | 20 MHz | Channel bandwidth |
| `numerology` | 1 | NR numerology (30 kHz SCS) |
| `txPower` | 35 dBm | gNB transmit power |

---

## Future Steps

| Step | Description | Status |
|------|-------------|--------|
| 1 | Basic 5G NR communication (1 gNB + 2 UEs, UDP) | Done |
| 2 | Integrate CRYSTALS-Kyber key exchange between users | Planned |
| 3 | Add AES encryption using Kyber-derived shared secret | Planned |
| 4 | Implement user mobility and handover scenarios | Planned |
| 5 | Performance analysis (delay, fragmentation, loss, throughput) | Planned |

---

## References

- [NS-3 Network Simulator](https://www.nsnam.org/)
- [CTTC 5G-LENA NR Module](https://5g-lena.cttc.es/)
- [CRYSTALS-Kyber (NIST PQC Standard)](https://pq-crystals.org/kyber/)
- [3GPP TS 38.300 - NR Overall Description](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3191)
