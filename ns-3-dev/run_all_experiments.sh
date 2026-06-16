#!/bin/bash
set -e

cd "$(dirname "$0")"
echo "Working dir: $(pwd)"

mkdir -p results

MODES="ecc kyber kyber_cached hybrid"
NODES_LIST="10 28 56"
COUNT=0
TOTAL=12
PASS=0
FAIL=0

echo ""
echo "Running all $TOTAL experiments..."
echo ""

for mode in $MODES; do
    for nodes in $NODES_LIST; do
        COUNT=$((COUNT + 1))
        echo "[$COUNT/$TOTAL] mode=$mode nodes=$nodes"
        if ./ns3 run "drone-swarm-pqc-sim --cryptoMode=$mode --nodes=$nodes" 2>&1; then
            PASS=$((PASS + 1))
            echo "  [PASS]"
        else
            FAIL=$((FAIL + 1))
            echo "  [FAIL]"
        fi
        echo ""
    done
done

echo "========================================="
echo "SUMMARY: $PASS passed, $FAIL failed / $TOTAL total"
echo "========================================="

echo ""
echo "CSV files:"
find . -name "*.csv" -newer ns3 2>/dev/null || true
ls -la results/*.csv 2>/dev/null || true
