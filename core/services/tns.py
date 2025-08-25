#!/usr/bin/env python3
import subprocess
import re
import json
from pathlib import Path
from typing import Dict, List

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

ODAT_SCRIPT = "odat.py"
WORDLIST = "/usr/share/wordlists/oratools/sid.txt"

def _run(cmd: List[str]) -> str:
    print(f"[tns] ▶ {' '.join(cmd)}")
    res = subprocess.run(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, check=False)
    return res.stdout.strip()

def strip_ansi(text: str) -> str:
    import re
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def search_msf(query: str):
    mods, cves = set(), set()
    out = subprocess.getoutput(f"msfconsole -q -x 'search {query}; exit'")
    found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
    mods.update(strip_ansi(m.split()[1]) for m in found if m)
    for mod in sorted(mods):
        info = subprocess.getoutput(f"msfconsole -q -x 'info {mod}; exit'")
        cves.update(re.findall(r"CVE-\d{4}-\d{4,7}", info))
    return sorted(mods), sorted(cves)

def footprint(target: str) -> Dict:
    report = OUTPUT_DIR / f"{target}_tns_report.md"
    print(f"[+] Generating TNS Footprint Report → {report}")

    sections = {}
    metadata = {"target": target}

    # 1. Nmap basic service detection
    nmap_out = _run(["nmap", "-p1521", "-sV", "--open", target])
    sections['nmap_basic'] = nmap_out
    metadata['port_open'] = 'yes' if '1521/tcp open' in nmap_out else 'no'
    m = re.search(r"1521/tcp.*?\s(\S+)", nmap_out)
    metadata['tns_banner'] = m.group(1) if m else ''

    # 2. SID brute-force with NSE
    sid_brute_out = _run([
        "nmap", "-p1521", "-sV", "--script", "oracle-sid-brute",
        "--script-args", f"oracle-sid-brute.sidFile={WORDLIST}", target
    ])
    sections['nmap_sid_brute'] = sid_brute_out
    sids = re.findall(r"\| SID:\s*(\S+)", sid_brute_out)
    metadata['sids_found'] = sids or ['none']

    # 3. ODAT full enumeration
    odat_out = _run([ODAT_SCRIPT, "all", "-s", target])
    sections['odat_all'] = odat_out
    metadata['odat_all_lines'] = len(odat_out.splitlines())

    # 4. SQL*Plus table/role enumeration
    sql = (
        "SET PAGESIZE 200;\n"
        "SELECT table_name FROM all_tables;\n"
        "SELECT * FROM user_role_privs;\n"
        "EXIT;\n"
    )
    sqlplus_out = _run([
        "bash", "-c",
        f"echo \"{sql}\" | sqlplus -s scott/tiger@{target}/XE"
    ])
    sections['sqlplus'] = sqlplus_out
    if 'SELECT table_name' in sqlplus_out:
        after_select = sqlplus_out.split('SELECT table_name')[1]
    else:
        after_select = ''
    tables_count = len(re.findall(r"[A-Z0-9_]+", after_select))
    metadata['tables_count'] = tables_count

    # 5. ODAT putFile test
    odat_putfile_out = _run([
        ODAT_SCRIPT, "utlfile", "-s", target, "-d", "XE",
        "-U", "scott", "-P", "tiger", "--sysdba",
        "--putFile", "testing.txt", "./testing.txt"
    ])
    sections['odat_putfile'] = odat_putfile_out
    metadata['putfile_success'] = 'success' if 'OK' in odat_putfile_out or 'success' in odat_putfile_out.lower() else 'no'

    # Optional: MSF search for banner and sids for exploits
    msf_mods_banner, msf_cves_banner = search_msf(metadata['tns_banner']) if metadata['tns_banner'] else ([], [])
    metadata['tns_banner_exploits'] = msf_mods_banner or ['none']
    metadata['tns_banner_cves'] = msf_cves_banner or ['none']

    for sid in sids:
        mods, cves = search_msf(sid)
        metadata[f'sid_exploits_{sid}'] = mods or ['none']
        metadata[f'sid_cves_{sid}'] = cves or ['none']

    # Write Markdown report
    with report.open('w') as rpt:
        rpt.write(f"# TNS Footprint Report – {target}\n\n")
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

    # Write JSON metadata
    json_file = OUTPUT_DIR / f"{target}_tns_metadata.json"
    with json_file.open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] TNS report written: {report}")
    print(f"[✓] Metadata JSON written: {json_file}")

    return metadata

if __name__ == "__main__":
    import sys
    footprint(sys.argv[1])
