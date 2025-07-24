
from pathlib import Path
import subprocess

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

def _outfile(target: str, suffix: str) -> Path:
    """Build outputs/<target>_mssql_<suffix>.txt"""
    return OUTPUT_DIR / f"{target}_mssql_{suffix}.txt"

def _run(cmd: list[str], dst: Path) -> None:
    """Run a shell command and capture stdout+stderr to dst."""
    print(f"[mssql] ▶ {' '.join(cmd)}")
    with dst.open("w") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, text=True, check=False)
    print(f"[mssql] ✔ Output → {dst}")

def footprint(target: str) -> None:
    print(f"[+] MSSQL detected – launching MSSQL footprinting on {target}…")

    
    scripts = [
        "ms-sql-info",
        "ms-sql-empty-password",
        "ms-sql-xp-cmdshell",
        "ms-sql-config",
        "ms-sql-ntlm-info",
        "ms-sql-tables",
        "ms-sql-hasdbaccess",
        "ms-sql-dac",
        "ms-sql-dump-hashes",
    ]
    _run(
        ["nmap", "-p1433", "-sV", "--script", ",".join(scripts), target],
        _outfile(target, "nmap_scripts"),
    )

    
    msf_cmd = (
        "use auxiliary/scanner/mssql/mssql_ping; "
        f"set RHOSTS {target}; "
        "run; "
        "exit"
    )
    _run(
        ["msfconsole", "-q", "-x", msf_cmd],
        _outfile(target, "msf_mssql_ping"),
    )

   
    mssqlclient = "/usr/share/doc/python3-impacket/examples/mssqlclient.py"
    _run(
        ["python3", mssqlclient, f"Administrator@{target}", "-windows-auth"],
        _outfile(target, "mssqlclient"),
    )

    print(f"[+] MSSQL footprinting complete for {target}.")
