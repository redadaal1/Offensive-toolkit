#!/usr/bin/env python3
import subprocess
import re
import json
from pathlib import Path
from typing import Dict, List

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)


def _run(cmd: List[str]) -> str:
    print(f"[nfs] ▶ {' '.join(cmd)}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return result.stdout.strip()


def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


def search_msf(query: str) -> List[str]:
    modules = set()
    out = subprocess.getoutput(f"msfconsole -q -x 'search {query}; exit'")
    found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
    modules.update(strip_ansi(line.split()[1]) for line in found if line)
    return sorted(modules)


def parse_nmap(nmap_output: str) -> str:
    m = re.search(r"2049/tcp\s+open\s+([\S]+)", nmap_output)
    return m.group(1) if m else "unknown"


def parse_showmount(output: str) -> List[str]:
    return re.findall(r"/\S+", output)


def parse_rpcinfo(output: str) -> int:
    return len(output.splitlines())


def footprint(target: str) -> Dict:
    report = OUTPUT_DIR / f"{target}_nfs_report.md"
    metadata_file = OUTPUT_DIR / f"{target}_nfs_metadata.json"
    print(f"[+] Generating NFS recon report → {report}")

    sections = {
        "nmap": _run(["nmap", "-sV", "-p2049", target]),
        "showmount": _run(["showmount", "-e", target]),
        "rpcinfo": _run(["rpcinfo", "-p", target])
    }

    version = parse_nmap(sections["nmap"])
    exports = parse_showmount(sections["showmount"])
    rpc_services = parse_rpcinfo(sections["rpcinfo"])

    msf_mods = search_msf(f"nfs {version}")

    metadata = {
        "target": target,
        "nfs_version": version,
        "nfs_exports": exports or ["none"],
        "nfs_exports_count": len(exports),
        "rpc_services_count": rpc_services,
        "exploits_found": "yes" if msf_mods else "no",
        "metasploit_modules": msf_mods or ["none"]
    }

    with report.open("w") as rpt:
        rpt.write("# NFS Recon Report\n")
        rpt.write(f"## Target: {target}\n\n")
        for name, content in sections.items():
            rpt.write(f"## {name.replace('_', ' ').title()}\n")
            rpt.write("```bash\n")
            rpt.write(content + "\n")
            rpt.write("```\n\n")

        rpt.write("## Metadata\n")
        for k, v in metadata.items():
            key_title = k.capitalize().replace('_', ' ')
            if isinstance(v, list):
                rpt.write(f"- {key_title}:\n")
                for item in v:
                    rpt.write(f"  - {item}\n")
            else:
                rpt.write(f"- {key_title}: {v}\n")

    with metadata_file.open("w") as json_file:
        json.dump(metadata, json_file, indent=2)

    print(f"[✓] Report written: {report}")
    print(f"[✓] Metadata JSON written: {metadata_file}")
    return metadata


if __name__ == "__main__":
    import sys
    footprint(sys.argv[1])
