import os

def convert_to_lf(filepath):
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        content = content.replace(b'\r\n', b'\n')
        with open(filepath, 'wb') as f:
            f.write(content)
        print(f"Successfully converted {filepath} to LF format inside WSL")
    except Exception as e:
        print(f"Failed to convert {filepath}: {e}")

convert_to_lf('/home/abishek14/Kyber-6G project/ns-3-dev/ns3')
convert_to_lf('/home/abishek14/Kyber-6G project/ns-3-dev/scratch/run_drone_experiments.sh')
