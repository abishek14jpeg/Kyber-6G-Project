#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Automated Experiment Execution Workflow
# Military Drone Swarm Quantum-Resilient Simulation
# ═══════════════════════════════════════════════════════════

echo "Starting automated PQC vs ECC Drone Swarm evaluation..."

# Ensure we're in the right directory
if [ ! -f "ns3" ]; then
    echo "Error: Please run this script from the base ns-3 root directory."
    exit 1
fi

# 1. Scalability and Saturation Analysis (ECC Baseline)
echo "
-----------------------------------
[1/3] Running ECC Baseline Models
-----------------------------------"
./ns3 run "drone-swarm-pqc-sim --crypto=ECC --nodes=10"
./ns3 run "drone-swarm-pqc-sim --crypto=ECC --nodes=25"
./ns3 run "drone-swarm-pqc-sim --crypto=ECC --nodes=50"

# 2. Scalability and Saturation Analysis (Kyber Post-Quantum)
echo "
-----------------------------------
[2/3] Running Kyber-768 Models
-----------------------------------"
./ns3 run "drone-swarm-pqc-sim --crypto=Kyber768 --nodes=10"
./ns3 run "drone-swarm-pqc-sim --crypto=Kyber768 --nodes=25"
./ns3 run "drone-swarm-pqc-sim --crypto=Kyber768 --nodes=50"

# 3. High Mobility & Optimization (Adaptive Caching)
echo "
-----------------------------------
[3/3] Running High Mobility Optimization
-----------------------------------"
./ns3 run "drone-swarm-pqc-sim --crypto=Kyber768 --nodes=50 --speed=25.0 --caching=1"

# 4. Analytics and Comparative Visualization
echo "
-----------------------------------
[Analytics] Generating Comparative Visualizations
-----------------------------------"
python3 scratch/plot_drone_metrics.py

echo "
=============================================================
Workflow Complete! 
Check the 'analysis_plots/' directory for theoretical models, 
throughput comparisons, M/M/1 queuing validation, and 
security strength charts.
============================================================="
