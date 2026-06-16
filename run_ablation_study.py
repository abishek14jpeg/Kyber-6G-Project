import subprocess
import os
import shutil

def main():
    seeds = range(1, 51)
    swarm_sizes = [10, 20, 40, 60, 80]
    
    # 5 Variants for IEEE Access ablation study
    variants = [
        {"name": "ecc", "desc": "Baseline ECC (P-256) LoS", "nlos": False},
        {"name": "kyber", "desc": "Pure Kyber-768 Uncached LoS", "nlos": False},
        {"name": "hybrid", "desc": "Hybrid Kyber-768+ECDH Uncached LoS", "nlos": False},
        {"name": "kyber_cached", "desc": "Hybrid Cached Ideal LoS", "nlos": False},
        {"name": "kyber_cached_nlos", "desc": "Hybrid Cached Stressed NLoS+Revocation", "nlos": True}
    ]
    
    ns3_dir = "ns-3-dev"
    ns3_executable = "./ns3"
    results_dir = os.path.abspath("results_data")
    os.makedirs(results_dir, exist_ok=True)
    
    print("Starting 50-Run Monte Carlo Ablation Study...")
    
    for variant in variants:
        mode_arg = variant["name"]
        if mode_arg == "kyber_cached_nlos":
            mode_arg = "kyber_cached" # The NS-3 script expects kyber_cached, NLoS is assumed default in this build
            
        for size in swarm_sizes:
            for seed in seeds:
                print(f"Running: {variant['desc']} | Swarm: {size} | Seed: {seed}")
                
                cmd = [
                    ns3_executable, "run",
                    f"drone-swarm-pqc-sim --cryptoMode={mode_arg} --nodes={size} --RngRun={seed}"
                ]
                
                try:
                    subprocess.run(cmd, cwd=ns3_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    # Move generated intermediate CSVs to uniquely named files to avoid overwrite
                    files_to_move = [
                        "pdr_snr_log.csv", 
                        "mac_delay_log.csv", 
                        "e2e_latency_log.csv", 
                        "handoff_log.csv", 
                        "energy_trace_log.csv"
                    ]
                    
                    for f in files_to_move:
                        src = os.path.join(ns3_dir, "results_data", f)
                        if os.path.exists(src):
                            dst = os.path.join(results_dir, f"{variant['name']}_{size}_{seed}_{f}")
                            shutil.move(src, dst)
                            
                except subprocess.CalledProcessError as e:
                    print(f"Error during simulation: {e}")

    print("Ablation study complete. Raw data saved to results_data/.")

if __name__ == "__main__":
    main()
