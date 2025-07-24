"""
core/mail_footprint.py
----------------------
Footprinting workflow for IMAP / POP3 if the service is detected.

Runs:
  1. Nmap service/baseline scripts on 110,143,993,995
  2. curl banner pull on IMAPS
  3. openssl s_client tests on 993 & 995
(You can extend with authenticated checks later.)

Every command’s stdout/stderr is saved to outputs/<target>_<name>.txt
"""

import subprocess
from pathlib import Path
from typing import Iterable

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)


def _outfile(target: str, suffix: str) -> Path:
    return OUTPUT_DIR / f"{target}_{suffix}.txt"


def _run(cmd: Iterable[str], dst: Path) -> None:
    print(f"[mail] ▶ {' '.join(cmd)}")
    with dst.open("w") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, text=True, check=False)
    print(f"[mail] ✔ Output → {dst}")


def mail_footprint(target: str) -> None:
    """IMAP / POP3 enumeration chain."""
    print("[+] IMAP/POP3 detected – launching mail footprinting…")

    # 1. Nmap discovery & default scripts
    _run(
        ["nmap", "-sV", "-sC", "-p110,143,993,995", target],
        _outfile(target, "mail_nmap_basic"),
    )

    # 2. curl banner / TLS check (IMAPS)
    _run(
        ["curl", "-k", f"imaps://{target}", "-v"],
        _outfile(target, "mail_curl_imaps"),
    )

    # 3. openssl manual SSL handshake tests
    _run(
        ["openssl", "s_client", "-connect", f"{target}:995", "-servername", target],
        _outfile(target, "mail_openssl_pop3s"),
    )
    _run(
        ["openssl", "s_client", "-connect", f"{target}:993", "-servername", target],
        _outfile(target, "mail_openssl_imaps"),
    )

    print("[+] Mail footprinting complete.")
