"""
core/enum_tools.py
Very small wrapper for enum4linux (-a).
"""

import subprocess
from pathlib import Path

OUTPUT_DIR = Path("outputs")

def run_enum4linux(target: str) -> Path:
    """
    Run enum4linux against *target* and save output.

    Returns
    -------
    Path to the saved result file.
    """
    OUTPUT_DIR.mkdir(exist_ok=True)
    out_file = OUTPUT_DIR / f"{target}_enum4linux.txt"

    cmd = ["enum4linux", "-a", target]
    print(f"[enum] ▶ {' '.join(cmd)}")

    # capture stdout & stderr into the file
    with out_file.open("w") as handle:
        subprocess.run(cmd, stdout=handle, stderr=subprocess.STDOUT, text=True, check=False)

    print(f"[enum] ✔ Results saved to {out_file}")
    return out_file


# --------------------------------------------------------------------------- #
# Stand‑alone test:  python -m core.enum_tools 10.10.10.10
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Quick enum4linux test")
    p.add_argument("target", help="IP or hostname to enumerate")
    run_enum4linux(p.parse_args().target)
