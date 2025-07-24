"""
core/services/dns.py
--------------------

DNS Footprinting Workflow:

1. NS record discovery (dig)
2. Secondary NS queries
3. Version & ANY queries
4. Zone transfer attempts (AXFR)
5. Subdomain brute‑force via dnsenum
6. SOA / MX / TXT record pulls

All outputs go to outputs/<target>_dns_<step>.txt
"""

import subprocess
from pathlib import Path
from typing import List

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)


def _outfile(target: str, step: str) -> Path:
    return OUTPUT_DIR / f"{target}_dns_{step}.txt"


def _run(cmd: List[str], dst: Path) -> None:
    print(f"[dns] ▶ {' '.join(cmd)}")
    with dst.open("w") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, text=True, check=False)
    print(f"[dns] ✔ {dst}")


def footprint(target: str) -> None:
    """
    Full DNS footprinting for a domain or DNS server IP.
    'target' may be an IP (DNS server) or domain name.
    """
    print(f"[+] DNS footprinting on {target}…")

    # 1. NS record discovery via default resolver
    _run(["dig", "NS", target, "+noall", "+answer"], _outfile(target, "ns_default"))

    # 2. NS record discovery via each discovered nameserver
    # parse servers from previous output
    ns_file = _outfile(target, "ns_default")
    servers = []
    for line in ns_file.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3].upper() == "NS":
            servers.append(parts[4].rstrip('.'))

    for ns in set(servers):
        _run(["dig", "@"+ns, "NS", target, "+noall", "+answer"],
             _outfile(target, f"ns_{ns}"))

    # 3. Version.bind query (TXT) against each server
    for ns in set(servers):
        _run(["dig", "@"+ns, "CH", "TXT", "version.bind", "+short"],
             _outfile(target, f"version_{ns}"))

    # 4. ANY query against each server
    for ns in set(servers):
        _run(["dig", "@"+ns, "ANY", target, "+noall", "+answer"],
             _outfile(target, f"any_{ns}"))

    # 5. Zone transfer attempts (AXFR) against each server
    for ns in set(servers):
        _run(["dig", "@"+ns, "AXFR", target, "+noall", "+answer"],
             _outfile(target, f"axfr_{ns}"))

    # 6. SOA / MX / TXT
    _run(["dig", "SOA", target, "+noall", "+answer"], _outfile(target, "soa"))
    _run(["dig", "MX", target, "+noall", "+answer"], _outfile(target, "mx"))
    _run(["dig", "TXT", target, "+noall", "+answer"], _outfile(target, "txt"))

    # 7. Subdomain enumeration with dnsenum
    # requires dnsenum installed and a wordlist at /usr/share/wordlists/dns.txt
    wordlist = "/usr/share/wordlists/dns.txt"
    _run([
        "dnsenum",
        "--dnsserver", servers[0] if servers else "8.8.8.8",
        "--enum",
        "-f", wordlist,
        "-o", _outfile(target, "subdomains").with_suffix(""),
        target
    ], _outfile(target, "dnsenum_raw"))

    print(f"[+] DNS footprinting complete for {target}.")
