#!/usr/bin/env python3
import subprocess
import re
import json
from pathlib import Path
import socket

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

def _run(cmd):
    print(f"[ajp] ▶ {' '.join(cmd)}")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return res.stdout.strip()

def ajp_banner_grab(target, port=8009):
    try:
        s = socket.create_connection((target, port), timeout=5)
        s.sendall(b"\x12\x34\x00\x00")
        data = s.recv(1024).hex()
        s.close()
        return data
    except Exception as e:
        return f"Error: {e}"

def strip_ansi(text):
    return re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]').sub('', text)

def search_msf(query):
    mods, cves = set(), set()
    out = subprocess.getoutput(f"msfconsole -q -x 'search {query}; exit'")
    found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
    mods.update(strip_ansi(m.split()[1]) for m in found if m)
    for mod in sorted(mods):
        info = subprocess.getoutput(f"msfconsole -q -x 'info {mod}; exit'")
        cves.update(re.findall(r"CVE-\d{4}-\d{4,7}", info))
    return sorted(mods), sorted(cves)

def footprint(target):
    report = OUTPUT_DIR / f"{target}_ajp_report.md"
    print(f"[+] Generating AJP recon report → {report}")

    nmap_ajp = _run(["nmap", "-p", "8009", "-sV", "-Pn", target])
    banner = ajp_banner_grab(target)

    msf_queries = [nmap_ajp, banner]
    msf_queries = list({q.strip() for q in msf_queries if q.strip() and not q.startswith("Error")})

    all_mods, all_cves = set(), set()
    for q in msf_queries:
        mods, cves = search_msf(q)
        all_mods.update(mods)
        all_cves.update(cves)

    metadata = {
        "target": target,
        "nmap_ajp_banner": nmap_ajp,
        "raw_ajp_banner": banner,
        "msf_exploit_found": "yes" if all_mods else "no",
        "msf_exploit_mods": sorted(all_mods) if all_mods else ["none"],
        "msf_exploit_cves": sorted(all_cves) if all_cves else ["none"],
    }

    with report.open("w") as rpt:
        rpt.write("# AJP Recon Report\n")
        rpt.write(f"## Target: {target}\n\n")

        rpt.write("## Nmap AJP Scan\n```\n")
        rpt.write(nmap_ajp + "\n```\n\n")

        rpt.write("## Raw AJP Banner (hex)\n```\n")
        rpt.write(banner + "\n```\n\n")

        rpt.write("## Metadata\n")
        for k,v in metadata.items():
            key_title = k.capitalize().replace('_', ' ')
            if isinstance(v, list):
                rpt.write(f"- {key_title}:\n")
                for item in v:
                    rpt.write(f"  - {item}\n")
            else:
                rpt.write(f"- {key_title}: {v}\n")

    with (OUTPUT_DIR / f"{target}_ajp_metadata.json").open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] Report written: {report}")
    print(f"[✓] Metadata JSON written: {OUTPUT_DIR / f'{target}_ajp_metadata.json'}")

    return metadata

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: ./ajp.py <target>")
        exit(1)
    footprint(sys.argv[1])
