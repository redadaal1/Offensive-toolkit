#!/usr/bin/env python3
import subprocess
import re
import json
from pathlib import Path
from typing import Dict, List

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

WORDLIST = "/usr/share/seclists/Discovery/SNMP/snmp-community-strings.txt"

def _run(cmd: List[str]) -> str:
    print(f"[snmp] ▶ {' '.join(cmd)}")
    res = subprocess.run(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, check=False)
    return res.stdout.strip()

def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def search_msf(query: str):
    mods, cves = set(), set()
    # Simple direct search for community strings or "snmp"
    out = subprocess.getoutput(f"msfconsole -q -x 'search {query}; exit'")
    found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
    mods.update(strip_ansi(m.split()[1]) for m in found if m)
    for mod in sorted(mods):
        info = subprocess.getoutput(f"msfconsole -q -x 'info {mod}; exit'")
        cves.update(re.findall(r"CVE-\d{4}-\d{4,7}", info))
    return sorted(mods), sorted(cves)

def footprint(target: str) -> Dict:
    report = OUTPUT_DIR / f"{target}_snmp_report.md"
    print(f"[+] Generating SNMP Footprint Report → {report}")

    sections = {}
    metadata = {"target": target}

    # 1. onesixtyone enumeration for community strings
    onesixtyone_out = _run(["onesixtyone", "-c", WORDLIST, target])
    sections['onesixtyone'] = onesixtyone_out

    found_communities = re.findall(r"\[([^\]]+)\]", onesixtyone_out)
    metadata['community_count'] = len(found_communities)
    metadata['communities'] = found_communities or ['none']

    if not found_communities:
        print("[snmp] ⚠️  No community strings found. Exiting SNMP footprint.")
        # Write minimal report and return early
        with report.open('w') as rpt:
            rpt.write(f"# SNMP Footprint Report – {target}\n\n")
            rpt.write(f"## onesixtyone\n```bash\n{onesixtyone_out}\n```\n\n")
            rpt.write("## Metadata\n")
            rpt.write(f"- Target: {target}\n")
            rpt.write("- Community Count: 0\n")
            rpt.write("- Communities: none\n")
        return metadata

    # 2. snmpwalk for each found community string
    for comm in found_communities:
        safe_comm = comm.replace('/', '_')
        out = _run(["snmpwalk", "-v2c", "-c", comm, target])
        sections[f'snmpwalk_{safe_comm}'] = out
        metadata[f'snmp_entries_{safe_comm}'] = len(out.splitlines())

        # Optional: MSF search for exploits using community string as keyword
        mods, cves = search_msf(comm)
        metadata[f'snmp_exploit_found_{safe_comm}'] = "yes" if mods else "no"
        metadata[f'snmp_exploit_mods_{safe_comm}'] = mods or ["none"]
        metadata[f'snmp_exploit_cves_{safe_comm}'] = cves or ["none"]

    # Write full markdown report
    with report.open('w') as rpt:
        rpt.write(f"# SNMP Footprint Report – {target}\n\n")
        for name, content in sections.items():
            rpt.write(f"## {name.replace('_', ' ').title()}\n```bash\n{content}\n```\n\n")
        rpt.write("## Metadata\n")
        for k, v in metadata.items():
            key_title = k.replace('_', ' ').capitalize()
            if isinstance(v, list):
                rpt.write(f"- {key_title}:\n")
                for item in v:
                    rpt.write(f"  - {item}\n")
            else:
                rpt.write(f"- {key_title}: {v}\n")

    # Write JSON metadata file
    meta_file = OUTPUT_DIR / f"{target}_snmp_metadata.json"
    with meta_file.open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] SNMP report written: {report}")
    print(f"[✓] Metadata JSON written: {meta_file}")

    return metadata

if __name__ == "__main__":
    import sys
    footprint(sys.argv[1])
