
from pathlib import Path
import subprocess

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

# adjust if you keep your wordlist elsewhere
USER_WL = "/usr/share/wordlists/footprinting-wordlist.txt"

def _outfile(target: str, suffix: str) -> Path:
    """Build outputs/<target>_smtp_<suffix>.txt"""
    return OUTPUT_DIR / f"{target}_smtp_{suffix}.txt"

def _run(cmd: list[str], dst: Path) -> None:
    print(f"[smtp] ▶ {' '.join(cmd)}")
    with dst.open("w") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, text=True, check=False)
    print(f"[smtp] ✔ Output → {dst}")

def footprint(target: str) -> None:
    print(f"[+] SMTP detected – launching SMTP footprinting on {target}…")

    
    _run(
        ["nmap", "-sC", "-sV", "-p25", target],
        _outfile(target, "nmap_basic"),
    )

    
    _run(
        ["nmap", "-p25", "--script", "smtp-open-relay", "-v", target],
        _outfile(target, "nmap_open_relay"),
    )

    
    _run(
        ["smtp-user-enum", "-M", "VRFY", "-U", USER_WL, "-t", target, "-w", "60"],
        _outfile(target, "user_enum"),
    )

    print(f"[+] SMTP footprinting complete for {target}.")
