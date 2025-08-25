#!/usr/bin/env python3
import subprocess
import re
import json
from pathlib import Path
from typing import Dict, List

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

def _run(cmd: List[str]) -> str:
    print(f"[mssql] ▶ {' '.join(cmd)}")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, check=False)
    return res.stdout.strip()

def strip_ansi(text: str) -> str:
    import re
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

def extract_mssql_version(nmap_output: str) -> str:
    # Try to extract MSSQL version info from nmap output
    m = re.search(r"Microsoft SQL Server\s*([^,\n]*)", nmap_output, re.IGNORECASE)
    if m:
        return "Microsoft SQL Server " + m.group(1).strip()
    elif "Microsoft SQL Server" in nmap_output:
        return "Microsoft SQL Server"
    return "unknown"

def footprint(target: str) -> Dict:
    report = OUTPUT_DIR / f"{target}_mssql_report.md"
    print(f"[+] Generating MSSQL Footprint Report → {report}")

    sections = {}
    metadata = {"target": target}

    # Nmap MSSQL scripts scan
    scripts = [
        'ms-sql-info','ms-sql-empty-password','ms-sql-xp-cmdshell',
        'ms-sql-config','ms-sql-ntlm-info','ms-sql-tables',
        'ms-sql-hasdbaccess','ms-sql-dac','ms-sql-dump-hashes'
    ]
    nmap_out = _run([
        'nmap', '-p1433', '-sV', '--script', ','.join(scripts), target
    ])
    sections['nmap_mssql'] = nmap_out

    metadata['mssql_version'] = extract_mssql_version(nmap_out)
    metadata['empty_pwd'] = 'yes' if 'ms-sql-empty-password' in nmap_out else 'no'

    # Metasploit ping auxiliary module
    msf_cmd = (
        'use auxiliary/scanner/mssql/mssql_ping; '
        f'set RHOSTS {target}; run; exit'
    )
    msf_out = _run(['msfconsole', '-q', '-x', msf_cmd])
    sections['msf_mssql_ping'] = msf_out
    metadata['ping_success'] = 'yes' if 'hosts: ' in msf_out else 'no'

    # Impacket mssqlclient test login
    client_path = '/usr/share/doc/python3-impacket/examples/mssqlclient.py'
    client_out = _run(['python3', client_path, f'Administrator@{target}', '-windows-auth'])
    sections['mssqlclient'] = client_out
    metadata['login_success'] = 'yes' if '1> exec' in client_out else 'no'

    # Search msf modules for MSSQL version info
    msf_mods, msf_cves = search_msf(metadata['mssql_version']) if metadata['mssql_version'] != "unknown" else ([], [])
    metadata.update({
        "exploit_found": "yes" if msf_mods else "no",
        "exploit_mods": msf_mods or ["none"],
        "exploit_cves": msf_cves or ["none"],
    })

    # Write markdown report
    with report.open('w') as rpt:
        rpt.write(f"# MSSQL Footprint Report – {target}\n\n")
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
    meta_file = OUTPUT_DIR / f"{target}_mssql_metadata.json"
    with meta_file.open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] MSSQL report written: {report}")
    print(f"[✓] Metadata JSON written: {meta_file}")

    return metadata

if __name__ == "__main__":
    import sys
    footprint(sys.argv[1])
