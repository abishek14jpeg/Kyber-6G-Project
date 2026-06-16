#!/usr/bin/env python3
"""Run all 12 drone-swarm PQC experiments and collect CSV results."""
import subprocess, os, sys, glob

os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.makedirs("results", exist_ok=True)

# Remove old CSVs
for f in glob.glob("results/*.csv"):
    os.remove(f)

MODES = ["ecc", "kyber", "kyber_cached", "hybrid"]
NODES = [10, 28, 56]
total = len(MODES) * len(NODES)
passed = 0
failed = 0

for mode in MODES:
    for nodes in NODES:
        idx = passed + failed + 1
        print(f"\n[{idx}/{total}] Running: mode={mode} nodes={nodes}")
        cmd = f'./ns3 run "drone-swarm-pqc-sim --cryptoMode={mode} --nodes={nodes}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout + result.stderr
        # Print last few relevant lines
        for line in output.strip().split('\n')[-5:]:
            print(f"  {line}")
        if result.returncode == 0:
            passed += 1
            print(f"  [PASS]")
        else:
            failed += 1
            print(f"  [FAIL] exit code {result.returncode}")

print(f"\n{'='*50}")
print(f"SUMMARY: {passed} passed, {failed} failed / {total} total")
print(f"{'='*50}")

# Show CSV files
print("\nCSV files in results/:")
for f in sorted(glob.glob("results/*.csv")):
    size = os.path.getsize(f)
    print(f"  {f} ({size} bytes)")

print("\nCSV files in current dir:")
for f in sorted(glob.glob("*.csv")):
    size = os.path.getsize(f)
    print(f"  {f} ({size} bytes)")
