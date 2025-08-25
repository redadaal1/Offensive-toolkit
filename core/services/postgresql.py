#!/usr/bin/env python3
import subprocess
import re
import json
from pathlib import Path

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

def _run(cmd):
    print(f"[postgresql] ▶ {' '.join(cmd)}")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return res.stdout.strip()

def strip_ansi(text):
    return re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]').sub('', text)

def search_msf(service_name):
    mods, cves = set(), set()
    out = subprocess.getoutput(f"msfconsole -q -x 'search {service_name}; exit'")
    found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
    mods.update(strip_ansi(m.split()[1]) for m in found if m)
    for mod in sorted(mods):
        info = subprocess.getoutput(f"msfconsole -q -x 'info {mod}; exit'")
        cves.update(re.findall(r"CVE-\d{4}-\d{4,7}", info))
    return sorted(mods), sorted(cves)

def footprint(target):
    report_md = OUTPUT_DIR / f"{target}_postgresql_report.md"
    report_json = OUTPUT_DIR / f"{target}_postgresql_report.json"
    print(f"[+] Generating PostgreSQL recon report → {report_md}")

    # Run nmap to get service info
    nmap_postgresql = _run(["nmap", "-p", "5432", "-sV", "-Pn", target])

    # PostgreSQL usually doesn't send a banner with netcat
    banner = "[!] No banner — PostgreSQL requires proper handshake."

    # Use concise query terms for MSF
    msf_queries = ["postgresql", "postgres"]

    all_mods, all_cves = set(), set()
    for q in msf_queries:
        mods, cves = search_msf(q)
        all_mods.update(mods)
        all_cves.update(cves)

    metadata = {
        "target": target,
        "nmap_postgresql_banner": nmap_postgresql,
        "raw_postgresql_banner": banner,
        "msf_exploit_found": "yes" if all_mods else "no",
        "msf_exploit_mods": sorted(all_mods) if all_mods else ["none"],
        "msf_exploit_cves": sorted(all_cves) if all_cves else ["none"],
    }

    # Markdown report
    with report_md.open("w") as rpt:
        rpt.write("# PostgreSQL Recon Report\n")
        rpt.write(f"## Target: {target}\n\n")
        rpt.write("## Nmap PostgreSQL Scan\n```\n")
        rpt.write(nmap_postgresql + "\n```\n\n")
        rpt.write("## Raw PostgreSQL Banner (via netcat)\n```\n")
        rpt.write(banner + "\n```\n\n")
        rpt.write("## Metadata\n")
        for k, v in metadata.items():
            key_title = k.capitalize().replace('_', ' ')
            if isinstance(v, list):
                rpt.write(f"- {key_title}:\n")
                for item in v:
                    rpt.write(f"  - {item}\n")
            else:
                rpt.write(f"- {key_title}: {v}\n")

    # JSON metadata report
    with report_json.open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] Report written: {report_md}")
    print(f"[✓] Metadata JSON written: {report_json}")

    return metadata

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: ./postgresql.py <target>")
        exit(1)
    footprint(sys.argv[1])
