#!/bin/bash
# ═══════════════════════════════════════════════════════════
# PQC-6G Security Framework — Build Script
# ═══════════════════════════════════════════════════════════
#
# Usage:
#   cd ~/Kyber-6G\ project/ns-3-dev
#   chmod +x build-pqc.sh
#   ./build-pqc.sh
#
# This script will:
#   1. Configure NS-3 with examples and tests enabled
#   2. Build the entire NS-3 + NR + pqc-security module
#   3. Run the PQC unit tests
#   4. Run the baseline simulation
#
# Approximate time: 20-40 minutes for full build (depends on hardware)
# ═══════════════════════════════════════════════════════════

set -e  # Exit on error

NS3_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$NS3_DIR"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       PQC-6G Security Framework — Build Pipeline         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo "  Working directory: $NS3_DIR"
echo ""

# ── Step 1: Configure ──
echo "═══ Step 1/4: Configuring NS-3... ═══"
./ns3 configure --enable-examples --enable-tests 2>&1 | tail -5
echo "  ✓ Configuration complete"
echo ""

# ── Step 2: Build ──
echo "═══ Step 2/4: Building NS-3 (this may take 20-40 minutes)... ═══"
BUILD_START=$(date +%s)
./ns3 build 2>&1 | tail -20
BUILD_END=$(date +%s)
BUILD_TIME=$((BUILD_END - BUILD_START))
echo "  ✓ Build complete in ${BUILD_TIME}s"
echo ""

# ── Step 3: Run Unit Tests ──
echo "═══ Step 3/4: Running PQC unit tests... ═══"
./ns3 run "test-runner --suite=pqc-security" 2>&1
echo "  ✓ Unit tests complete"
echo ""

# ── Step 4: Run Baseline Simulation ──
echo "═══ Step 4/4: Running baseline simulation... ═══"
./ns3 run "pqc-6g-simulation --scenario=baseline --simTime=2" 2>&1
echo "  ✓ Baseline simulation complete"
echo ""

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       BUILD PIPELINE COMPLETE — ALL STEPS PASSED         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "  To run other scenarios:"
echo "    ./ns3 run 'pqc-6g-simulation --scenario=dense-urban'"
echo "    ./ns3 run 'pqc-6g-simulation --scenario=high-speed --speed=120'"
echo "    ./ns3 run 'pqc-6g-simulation --scenario=quantum-attack'"
echo ""
