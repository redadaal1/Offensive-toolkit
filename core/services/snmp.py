

from pathlib import Path
import subprocess
import re

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

# ‑‑ modifie ce chemin si tu utilises une autre word‑list
WORDLIST = "/usr/share/seclists/Discovery/SNMP/snmp-community-strings.txt"


def _outfile(target: str, suffix: str) -> Path:
    return OUTPUT_DIR / f"{target}_{suffix}.txt"


def _run(cmd: list[str], dst: Path) -> None:
    print(f"[snmp] ▶ {' '.join(cmd)}")
    with dst.open("w") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, text=True, check=False)
    print(f"[snmp] ✔ Output → {dst}")


def _extract_community(out_file: Path) -> list[str]:
    """
    Parse l’output de onesixtyone et retourne la/les community strings trouvées.
    Format typique :  IP [STRING] (réponse en X ms)
    """
    found: list[str] = []
    r = re.compile(r"\s+\[(.+?)\]\s+\(")
    for line in out_file.read_text().splitlines():
        m = r.search(line)
        if m:
            found.append(m.group(1))
    return found


def footprint(target: str) -> None:
    print("[+] SNMP détecté – lancement du footprinting…")

    
    onesixtyone_out = _outfile(target, "snmp_onesixtyone")
    _run(
        ["onesixtyone", "-c", WORDLIST, target],
        onesixtyone_out,
    )

    strings = _extract_community(onesixtyone_out)
    if not strings:
        print("[snmp] ⚠️  Aucune community string trouvée. Arrêt du module SNMP.")
        return

    print(f"[snmp] Community string(s) trouvée(s) : {', '.join(strings)}")

    
    for comm in strings:
        fname_safe = comm.replace("/", "_")
        _run(
            ["snmpwalk", "-v2c", "-c", comm, target],
            _outfile(target, f"snmpwalk_{fname_safe}"),
        )

       

    print("[+] Footprinting SNMP terminé.")
