import os
import subprocess

wsl_root = r"c:\wsl.localhost\Ubuntu-22.04\home\abishek14\Kyber-6G project\ns-3-dev"
linux_root = "/home/abishek14/Kyber-6G project/ns-3-dev"

files_to_sync = [
    "CMakeLists.txt",
    "scratch/drone-swarm-pqc-sim.cc",
    "scratch/plot_drone_metrics.py",
    "contrib/pqc-security/model/crystals-kyber-kem.cc",
    "contrib/pqc-security/model/crystals-kyber-kem.h",
    "contrib/pqc-security/model/pqc-metrics-collector.h",
    "contrib/pqc-security/model/pqc-metrics-collector.cc",
    "contrib/pqc-security/model/pqc-adaptive-key-manager.h",
    "contrib/pqc-security/model/pqc-adaptive-key-manager.cc",
    "contrib/pqc-security/model/pqc-drone-app.h",
    "contrib/pqc-security/model/pqc-drone-app.cc",
    "contrib/pqc-security/helper/pqc-security-helper.h",
    "contrib/pqc-security/helper/pqc-security-helper.cc",
    "contrib/pqc-security/model/quantum-attacker.h",
    "contrib/pqc-security/model/quantum-attacker.cc",
    "contrib/pqc-security/model/pqc-handover-manager.h"
]

print("Starting deep sync from Windows to Linux Ext4...")

# Create directories first
directories = set(os.path.dirname(f) for f in files_to_sync)
for d in directories:
    if d:
        target_dir = f"{linux_root}/{d}"
        cmd = ["wsl", "-d", "Ubuntu-22.04", "--exec", "bash", "-c", f"mkdir -p '{target_dir}'"]
        subprocess.run(cmd)

# Copy files
for f in files_to_sync:
    win_path = os.path.join(wsl_root, os.path.normpath(f))
    linux_path = f"{linux_root}/{f}"
    
    if not os.path.exists(win_path):
        print(f"File missing on Windows side! {win_path}")
        continue
        
    try:
        with open(win_path, "rb") as file_in:
            content = file_in.read()
            # Convert CRLF to LF just in case
            content = content.replace(b'\r\n', b'\n')
            
        print(f"Syncing: {f}")
        
        # Execute bash cat to write natively
        process = subprocess.Popen(
            ["wsl", "-d", "Ubuntu-22.04", "--exec", "bash", "-c", f"cat > '{linux_path}'"],
            stdin=subprocess.PIPE
        )
        process.communicate(input=content)
        
        if process.returncode != 0:
            print(f"Failed to sync {f}")
            
    except Exception as e:
        print(f"Error accessing {win_path}: {e}")

print("Sync complete.")
