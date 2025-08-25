#!/usr/bin/env python3
import subprocess
import re
import json
from pathlib import Path
from typing import Dict, List
import argparse

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

def _run(cmd: List[str]) -> str:
    print(f"[mail] ▶ {' '.join(cmd)}")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, check=False)
    return res.stdout.strip()

def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def search_msf(query: str):
    mods, cves = set(), set()
    match = re.search(r"Linux (\d+)\.(\d+)\.(\d+)?\s*-\s*(\d+)\.(\d+)\.(\d+)?", query)
    if match:
        v_start = (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))
        v_end = (int(match.group(4)), int(match.group(5)), int(match.group(6) or 0))
        current = list(v_start)
        while tuple(current) <= v_end:
            version_str = f"Linux {current[0]}.{current[1]}.{current[2]}"
            out = subprocess.getoutput(f"msfconsole -q -x 'search {version_str}; exit'")
            found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
            mods.update(strip_ansi(m.split()[1]) for m in found if m)
            current[2] += 1
            if current[2] > 99:
                current[2] = 0
                current[1] += 1
                if current[1] > 99:
                    current[1] = 0
                    current[0] += 1
    else:
        out = subprocess.getoutput(f"msfconsole -q -x 'search {query}; exit'")
        found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
        mods.update(strip_ansi(m.split()[1]) for m in found if m)
    for mod in sorted(mods):
        info = subprocess.getoutput(f"msfconsole -q -x 'info {mod}; exit'")
        cves.update(re.findall(r"CVE-\d{4}-\d{4,7}", info))
    return sorted(mods), sorted(cves)

def extract_mail_banner(output: str) -> str:
    # Extract Server: banner line (e.g., from curl verbose or openssl output)
    m = re.search(r"Server:\s*([^\s]+)", output, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # fallback: search for common mail server software names in output
    for software in ['Dovecot', 'Exim', 'Postfix', 'Microsoft', 'Courier', 'Sendmail']:
        if software.lower() in output.lower():
            return software
    return "unknown"

def mail_footprint(target: str) -> Dict:
    report = OUTPUT_DIR / f"{target}_mail_report.md"
    print(f"[+] Generating Mail Footprint Report → {report}")

    sections = {}
    metadata = {"target": target}

    # Nmap scan on mail-related ports
    sections['nmap_mail'] = _run([
        'nmap', '-p110,143,993,995', '-sV', '-sC', target
    ])

    # Detect services from nmap output
    nmap_lower = sections['nmap_mail'].lower()
    metadata['pop3'] = 'yes' if 'pop3' in nmap_lower else 'no'
    metadata['imap'] = 'yes' if 'imap' in nmap_lower else 'no'
    metadata['pop3s'] = 'yes' if '995/tcp' in sections['nmap_mail'] else 'no'
    metadata['imaps'] = 'yes' if '993/tcp' in sections['nmap_mail'] else 'no'

    # Curl to imaps to extract banner
    sections['curl_imaps'] = _run(['curl', '-k', f'imaps://{target}', '-v'])
    metadata['imaps_banner'] = extract_mail_banner(sections['curl_imaps'])

    # OpenSSL TLS connection to POP3S and IMAPS to grab banners & TLS info
    sections['openssl_pop3s'] = _run([
        'openssl', 's_client', '-connect', f'{target}:995', '-quiet'
    ])
    sections['openssl_imaps'] = _run([
        'openssl', 's_client', '-connect', f'{target}:993', '-quiet'
    ])

    metadata['pop3s_tls'] = 'yes' if 'SSL-Session:' in sections['openssl_pop3s'] else 'no'
    metadata['imaps_tls'] = 'yes' if 'SSL-Session:' in sections['openssl_imaps'] else 'no'

    # Search MSF modules for mail banners & protocols
    msf_imaps_mods, msf_imaps_cves = search_msf(metadata['imaps_banner'])
    msf_pop3_mods, msf_pop3_cves = search_msf('pop3')
    msf_imap_mods, msf_imap_cves = search_msf('imap')

    metadata.update({
        "imaps_exploit_found": "yes" if msf_imaps_mods else "no",
        "imaps_exploit_mods": msf_imaps_mods or ["none"],
        "imaps_exploit_cves": msf_imaps_cves or ["none"],

        "pop3_exploit_found": "yes" if msf_pop3_mods else "no",
        "pop3_exploit_mods": msf_pop3_mods or ["none"],
        "pop3_exploit_cves": msf_pop3_cves or ["none"],

        "imap_exploit_found": "yes" if msf_imap_mods else "no",
        "imap_exploit_mods": msf_imap_mods or ["none"],
        "imap_exploit_cves": msf_imap_cves or ["none"],
    })

    # Write report markdown
    with report.open("w") as rpt:
        rpt.write(f"# Mail (IMAP/POP3) Footprint Report – {target}\n\n")
        for section_name, content in sections.items():
            rpt.write(f"## {section_name.replace('_', ' ').title()}\n```bash\n{content}\n```\n\n")
        rpt.write("## Metadata\n")
        for k, v in metadata.items():
            key_title = k.replace('_', ' ').capitalize()
            if isinstance(v, list):
                rpt.write(f"- {key_title}:\n")
                for item in v:
                    rpt.write(f"  - {item}\n")
            else:
                rpt.write(f"- {key_title}: {v}\n")

    # Write JSON metadata
    meta_file = OUTPUT_DIR / f"{target}_mail_metadata.json"
    with meta_file.open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] Mail report written: {report}")
    print(f"[✓] Metadata JSON written: {meta_file}")

    return metadata

if __name__ == "__main__":
    import sys
    mail_footprint(sys.argv[1])
