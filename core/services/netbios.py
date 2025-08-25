#!/usr/bin/env python3
import subprocess, re, json
from pathlib import Path
OUTPUT_DIR = Path("outputs"); OUTPUT_DIR.mkdir(exist_ok=True)

def _run(cmd):
    print(f"[netbios] ▶ {' '.join(cmd)}")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return res.stdout.strip()

def strip_ansi(text): return re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]').sub('', text)

def search_msf(query):
    # same as smb.py
    ...

def footprint(target):
    report = OUTPUT_DIR / f"{target}_netbios_report.md"
    print(f"[+] Generating NetBIOS recon report → {report}")

    # nmap scan for netbios ports (137,138,139)
    nmap_netbios = _run(["nmap", "-p", "137,138,139", "-sV", "-Pn", target])

    # nbtscan or nmblookup for additional NetBIOS info
    nbtscan_out = _run(["nbtscan", target])

    msf_queries = [nmap_netbios, nbtscan_out]
    msf_queries = list({q.strip() for q in msf_queries if q.strip()})

    all_mods, all_cves = set(), set()
    for q in msf_queries:
        mods, cves = search_msf(q)
        all_mods.update(mods)
        all_cves.update(cves)

    metadata = {
        "target": target,
        "nmap_netbios": nmap_netbios,
        "nbtscan": nbtscan_out,
        "msf_exploit_found": "yes" if all_mods else "no",
        "msf_exploit_mods": sorted(all_mods) if all_mods else ["none"],
        "msf_exploit_cves": sorted(all_cves) if all_cves else ["none"],
    }

    with report.open("w") as rpt:
        rpt.write("# NetBIOS Recon Report\n")
        rpt.write(f"## Target: {target}\n\n")
        rpt.write("## Nmap NetBIOS Scan\n```\n" + nmap_netbios + "\n```\n\n")
        rpt.write("## nbtscan Output\n```\n" + nbtscan_out + "\n```\n\n")
        rpt.write("## Metadata\n")
        for k,v in metadata.items():
            if isinstance(v, list):
                rpt.write(f"- {k}:\n")
                for i in v:
                    rpt.write(f"  - {i}\n")
            else:
                rpt.write(f"- {k}: {v}\n")

    with (OUTPUT_DIR / f"{target}_netbios_metadata.json").open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] Report written: {report}")
    print(f"[✓] Metadata JSON written: {OUTPUT_DIR / f'{target}_netbios_metadata.json'}")

    return metadata

if __name__=="__main__":
    import sys; footprint(sys.argv[1]) if len(sys.argv)>1 else print("Usage: netbios.py <target>")
