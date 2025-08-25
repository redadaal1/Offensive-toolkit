#!/usr/bin/env python3
import subprocess
import re
import json
from pathlib import Path
from typing import Dict, List

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

USER_WL = "/usr/share/wordlists/footprinting-wordlist.txt"

def _run(cmd: List[str]) -> str:
    print(f"[smtp] ▶ {' '.join(cmd)}")
    res = subprocess.run(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, check=False)
    return res.stdout.strip()

def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def search_msf(query: str):
    mods, cves = set(), set()
    # No special version parsing here, just direct search
    out = subprocess.getoutput(f"msfconsole -q -x 'search {query}; exit'")
    found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
    mods.update(strip_ansi(m.split()[1]) for m in found if m)
    for mod in sorted(mods):
        info = subprocess.getoutput(f"msfconsole -q -x 'info {mod}; exit'")
        cves.update(re.findall(r"CVE-\d{4}-\d{4,7}", info))
    return sorted(mods), sorted(cves)

def parse_smtp_banner(output: str) -> str:
    # Extract banner from typical SMTP banner lines (usually first line)
    lines = output.splitlines()
    if lines:
        # Common banner starts with "220 " or similar
        banner_line = lines[0].strip()
        # Clean ANSI if any
        banner_line = strip_ansi(banner_line)
        # Sometimes banner has server name after 220, extract that
        m = re.match(r"220\s+(\S+)", banner_line)
        return m.group(1) if m else banner_line
    return "unknown"

def footprint(target: str) -> Dict:
    report = OUTPUT_DIR / f"{target}_smtp_report.md"
    print(f"[+] Generating SMTP Footprint Report → {report}")

    sections = {}
    metadata = {"target": target}

    # Nmap basic scan on port 25 with scripts
    sections['nmap_basic'] = _run(["nmap", "-sC", "-sV", "-p25", target])
    metadata['smtp_open'] = 'yes' if '25/tcp open' in sections['nmap_basic'] else 'no'
    metadata['smtp_banner'] = parse_smtp_banner(sections['nmap_basic'])

    # Check for open relay with NSE
    sections['open_relay'] = _run([
        "nmap", "-p25", "--script", "smtp-open-relay", "-v", target
    ])
    metadata['open_relay'] = 'yes' if 'open relay' in sections['open_relay'].lower() else 'no'

    # User enumeration via VRFY (using smtp-user-enum)
    user_enum_out = _run([
        "smtp-user-enum", "-M", "VRFY", "-U", USER_WL,
        "-t", target, "-w", "60"
    ])
    sections['user_enum'] = user_enum_out
    metadata['users_valid'] = len(re.findall(r"^250 ", user_enum_out, re.MULTILINE))

    # MSF searches on SMTP banner to find exploits if possible
    if metadata['smtp_banner'] != "unknown":
        mods, cves = search_msf(metadata['smtp_banner'])
        metadata['smtp_exploit_found'] = "yes" if mods else "no"
        metadata['smtp_exploit_mods'] = mods or ["none"]
        metadata['smtp_exploit_cves'] = cves or ["none"]
    else:
        metadata['smtp_exploit_found'] = "no"
        metadata['smtp_exploit_mods'] = ["none"]
        metadata['smtp_exploit_cves'] = ["none"]

    # Write Markdown report
    with report.open('w') as rpt:
        rpt.write(f"# SMTP Footprint Report – {target}\n\n")
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

    # Write metadata JSON
    meta_file = OUTPUT_DIR / f"{target}_smtp_metadata.json"
    with meta_file.open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] SMTP report written: {report}")
    print(f"[✓] Metadata JSON written: {meta_file}")

    return metadata

if __name__ == "__main__":
    import sys
    footprint(sys.argv[1])
