#!/usr/bin/env python3
import subprocess
import re
import json
from pathlib import Path
from typing import Dict, List
import requests

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

WORDLIST_DNS = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
DNSENUM_WORDLIST = "/usr/share/wordlists/dns.txt"

def _run(cmd):
    print(f"[dns] ▶ {' '.join(cmd)}")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return res.stdout.strip()

def _fetch_url(url):
    try:
        r = requests.get(url, timeout=10, verify=False)
        return r.text.strip()
    except requests.RequestException:
        return ''

def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def search_msf(query):
    mods, cves = set(), set()
    out = subprocess.getoutput(f"msfconsole -q -x 'search {query}; exit'")
    found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
    mods.update(strip_ansi(m.split()[1]) for m in found if m)
    for mod in sorted(mods):
        info = subprocess.getoutput(f"msfconsole -q -x 'info {mod}; exit'")
        cves.update(re.findall(r"CVE-\d{4}-\d{4,7}", info))
    return sorted(mods), sorted(cves)

def parse_axfr(output: str) -> str:
    if output and "Transfer failed" not in output:
        return "allowed"
    else:
        return "denied"

def parse_dnsenum(output: str) -> int:
    return len(re.findall(r"Found\s+\S+", output))

def parse_dnsrecon(output: str, target: str) -> List[str]:
    return list(set(re.findall(r"\s(\S+\.%s)" % re.escape(target), output)))

def parse_ns_servers(output: str) -> List[str]:
    return re.findall(r"\sNS\s+(\S+)", output)

def footprint(target: str) -> Dict:
    report = OUTPUT_DIR / f"{target}_dns_report.md"
    print(f"[+] Generating DNS footprint report → {report}")

    sections = {}
    metadata = {"target": target}

    # Default NS query
    sections['ns_default'] = _run(["dig", "NS", target, "+noall", "+answer"])
    ns_servers = parse_ns_servers(sections['ns_default'])
    metadata['ns_count'] = len(ns_servers)

    # Per NS detailed queries
    for ns in set(ns_servers):
        key = ns.replace('.', '_')
        sections[f'ns_{key}'] = _run(["dig", f"@{ns}", "NS", target, "+noall", "+answer"])
        sections[f'version_{key}'] = _run(["dig", f"@{ns}", "CH", "TXT", "version.bind", "+short"])
        sections[f'any_{key}'] = _run(["dig", f"@{ns}", "ANY", target, "+noall", "+answer"])
        axfr = _run(["dig", f"@{ns}", "AXFR", target, "+noall", "+answer"])
        sections[f'axfr_{key}'] = axfr
        metadata[f'axfr_{key}_status'] = parse_axfr(axfr)

    # Common DNS record types
    for rec in ['SOA', 'MX', 'TXT']:
        output = _run(["dig", rec, target, "+noall", "+answer"])
        sections[rec.lower()] = output
        metadata[f'{rec.lower()}_count'] = len(output.splitlines())

    # dnsenum enumeration using first NS or 8.8.8.8 fallback
    dnsenum_out = _run([
        "dnsenum",
        "--dnsserver", ns_servers[0] if ns_servers else "8.8.8.8",
        "--enum",
        "-f", DNSENUM_WORDLIST,
        target
    ])
    sections['dnsenum'] = dnsenum_out
    metadata['dnsenum_found'] = parse_dnsenum(dnsenum_out)

    # Search Metasploit modules related to DNS
    msf_mods, msf_cves = search_msf("dns")
    metadata.update({
        "msf_modules_found": "yes" if msf_mods else "no",
        "msf_modules": msf_mods or ["none"],
        "msf_cves": msf_cves or ["none"]
    })

    # Write markdown report
    with report.open("w") as rpt:
        rpt.write(f"# DNS Footprint Report – {target}\n\n")
        for name, content in sections.items():
            rpt.write(f"## {name.replace('_', ' ').title()}\n```\n{content}\n```\n\n")
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
    meta_json_file = OUTPUT_DIR / f"{target}_dns_metadata.json"
    with meta_json_file.open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] Report written: {report}")
    print(f"[✓] Metadata JSON written: {meta_json_file}")

    return metadata

if __name__ == "__main__":
    import sys
    footprint(sys.argv[1])
