import os, subprocess

WSL_ROOT = r"c:\wsl.localhost\Ubuntu-22.04\home\abishek14\Kyber-6G project\ns-3-dev"
LINUX_ROOT = "/home/abishek14/Kyber-6G project/ns-3-dev"

for f in ["scratch/drone-swarm-pqc-sim.cc"]:
    win_path = os.path.join(WSL_ROOT, os.path.normpath(f))
    linux_path = f"{LINUX_ROOT}/{f}"
    with open(win_path, "rb") as fh:
        content = fh.read().replace(b"\r\n", b"\n")
    proc = subprocess.Popen(
        ["wsl", "-d", "Ubuntu-22.04", "--exec", "bash", "-c", f"cat > '{linux_path}'"],
        stdin=subprocess.PIPE)
    proc.communicate(input=content)
    print(f"{'OK' if proc.returncode == 0 else 'FAIL'}: {f}")
