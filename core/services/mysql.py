#!/usr/bin/env python3
import subprocess, re, json
from pathlib import Path
OUTPUT_DIR = Path("outputs"); OUTPUT_DIR.mkdir(exist_ok=True)

def _run(cmd):
    print(f"[mysql] ▶ {' '.join(cmd)}")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return res.stdout.strip()

def strip_ansi(text): return re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]').sub('', text)

def search_msf(query: str):
    mods, cves = set(), set()
    out = subprocess.getoutput(f"msfconsole -q -x 'search {query}; exit'")
    found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
    mods.update(strip_ansi(m.split()[1]) for m in found if m)
    for mod in sorted(mods):
        info = subprocess.getoutput(f"msfconsole -q -x 'info {mod}; exit'")
        cves.update(re.findall(r"CVE-\d{4}-\d{4,7}", info))
    return sorted(mods), sorted(cves)

def footprint(target):
    report = OUTPUT_DIR / f"{target}_mysql_report.md"
    print(f"[+] Generating MySQL recon report → {report}")

    nmap_mysql = _run(["nmap", "-p", "3306", "-sV", "-Pn", target])
    # Attempt banner grab using nc
    banner = _run(["timeout", "3", "nc", target, "3306"])

    msf_queries = [nmap_mysql, banner]
    msf_queries = list({q.strip() for q in msf_queries if q.strip()})

    all_mods, all_cves = set(), set()
    for q in msf_queries:
        mods, cves = search_msf(q)
        all_mods.update(mods)
        all_cves.update(cves)

    metadata = {
        "target": target,
        "nmap_mysql_banner": nmap_mysql,
        "mysql_raw_banner": banner,
        "msf_exploit_found": "yes" if all_mods else "no",
        "msf_exploit_mods": sorted(all_mods) if all_mods else ["none"],
        "msf_exploit_cves": sorted(all_cves) if all_cves else ["none"],
    }

    with report.open("w") as rpt:
        rpt.write("# MySQL Recon Report\n")
        rpt.write(f"## Target: {target}\n\n")
        rpt.write("## Nmap MySQL Scan\n```\n" + nmap_mysql + "\n```\n\n")
        rpt.write("## Raw MySQL Banner\n```\n" + banner + "\n```\n\n")
        rpt.write("## Metadata\n")
        for k,v in metadata.items():
            if isinstance(v, list):
                rpt.write(f"- {k}:\n")
                for i in v:
                    rpt.write(f"  - {i}\n")
            else:
                rpt.write(f"- {k}: {v}\n")

    with (OUTPUT_DIR / f"{target}_mysql_metadata.json").open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] Report written: {report}")
    print(f"[✓] Metadata JSON written: {OUTPUT_DIR / f'{target}_mysql_metadata.json'}")

    return metadata

if __name__=="__main__":
    import sys; footprint(sys.argv[1]) if len(sys.argv)>1 else print("Usage: mysql.py <target>")
