#!/usr/bin/env python3
import subprocess
import re
import json
import argparse
from pathlib import Path
from typing import Dict, Tuple, List

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)


def run_cmd(cmd, *, shell=False, timeout=120) -> Tuple[str, bool]:
    """Run a command and return its output and success status."""
    cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
    print(f"[ssh] ▶ {cmd_str}")
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, shell=shell, timeout=timeout, check=True
        )
        return result.stdout.strip(), True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        output = e.output.strip() if hasattr(e, 'output') else "Command timed out or failed."
        if "command not found" in output.lower():
            print(f"[!] Command not found for: {cmd_str}")
        return output, False


def parse_ssh_version(nmap_output: str) -> Tuple[str, str]:
    """Parse SSH server and version from nmap output."""
    match = re.search(r"ssh\s+(OpenSSH\s+[\d\w\.-]+)", nmap_output, re.IGNORECASE)
    if match:
        full_version_string = match.group(1)
        parts = full_version_string.split()
        server = parts[0]
        version = parts[1] if len(parts) > 1 else "unknown"
        return server, version
    return "unknown", "unknown"


def search_exploits(query: str) -> Tuple[list, list, list, list]:
    """Search ExploitDB and Metasploit for exploits, cleaning and de-duplicating results."""
    if not query or query == "unknown":
        return [], [], [], []

    print(f"[*] Searching exploits for: '{query}'")
    exploitdb_mods, exploitdb_cves, msf_mods, msf_cves = [], [], [], []
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    # Search ExploitDB
    out_db, _ = run_cmd(["searchsploit", "--disable-colour", "OpenSSH", query])
    processed_titles = set()
    for line in out_db.splitlines():
        if not line or '|' not in line or 'Path' in line: continue
        title, path = line.split('|')[0].strip(), line.split('|')[1].strip()
        core_title = re.sub(r'[\d\.]+', '', title).strip()
        if core_title not in processed_titles:
            exploitdb_mods.append(f"{title} ({path})")
            exploitdb_cves.extend(re.findall(r"CVE-\d{4}-\d{4,7}", title))
            processed_titles.add(core_title)

    # Search Metasploit
    out_msf, _ = run_cmd(["msfconsole", "-q", "-x", f"search OpenSSH {query}; exit"])
    found_msf_mods_raw = set(re.findall(r"(auxiliary|exploit)/\S+", out_msf))
    cleaned_msf_mods = {ansi_escape.sub('', mod) for mod in found_msf_mods_raw}
    
    for mod in sorted(list(cleaned_msf_mods)):
        msf_mods.append(mod)
        info, _ = run_cmd(["msfconsole", "-q", "-x", f"info {mod}; exit"])
        msf_cves.extend(re.findall(r"CVE-\d{4}-\d{4,7}", info))
    
    return sorted(exploitdb_mods), sorted(list(set(exploitdb_cves))), msf_mods, sorted(list(set(msf_cves)))


def parse_ssh_audit(audit_output: str) -> Dict:
    """Parse the output of ssh-audit into a structured dictionary."""
    if "command not found" in audit_output.lower():
        return {"ssh_audit_error": "ssh-audit tool not found. Please install it."}

    parsed = {}
    key_sections = {
        '(kex)': 'kex_algorithms',
        '(key)': 'host_key_algorithms',
        '(mac)': 'mac_algorithms',
        '(enc)': 'encryption_algorithms'
    }
    for line in audit_output.splitlines():
        line = line.strip()
        for key, section_name in key_sections.items():
            if line.startswith(key):
                parts = line.split()
                if len(parts) > 2:
                    algorithm = parts[1]
                    status = parts[-1]
                    if section_name not in parsed:
                        parsed[section_name] = {'weak': [], 'good': []}
                    if status == '(weak)':
                        parsed[section_name]['weak'].append(algorithm)
                    else:
                        parsed[section_name]['good'].append(algorithm)
    return parsed


def footprint(target: str, port: int = 22):
    """Run a comprehensive SSH reconnaissance scan."""
    report_path = OUTPUT_DIR / f"{target}_{port}_ssh_report.md"
    json_path = OUTPUT_DIR / f"{target}_{port}_ssh_metadata.json"
    print(f"[+] Generating SSH footprint report → {report_path}")

    # 1. Run Scans
    nmap_output, _ = run_cmd([
        "nmap", "-Pn", f"-p{port}", "-sV",
        "--script", "ssh-auth-methods,ssh2-enum-algos", target
    ])
    sshaudit_output, _ = run_cmd([f"ssh-audit -T {target}:{port}"], shell=True) # Use -T for faster connection

    # 2. Parse Information
    server, version = parse_ssh_version(nmap_output)
    auth_methods_match = re.search(r"ssh-auth-methods:(.*?)\n", nmap_output, re.DOTALL)
    auth_methods = [m.strip() for m in auth_methods_match.group(1).splitlines()] if auth_methods_match else []
    allows_password_auth = any("password" in method for method in auth_methods)
    
    audit_results = parse_ssh_audit(sshaudit_output)

    # 3. Search Exploits
    search_query = version if version != "unknown" else ""
    exploitdb_mods, exploitdb_cves, msf_mods, msf_cves = search_exploits(search_query)

    # 4. Assemble Metadata
    metadata = {
        "target": target,
        "port": port,
        "server": server,
        "version": version,
        "auth_methods": auth_methods,
        "allows_password_auth": allows_password_auth,
        "audit": audit_results,
        "exploitdb_mods": exploitdb_mods or ["none"],
        "exploitdb_cves": exploitdb_cves or ["none"],
        "msf_mods": msf_mods or ["none"],
        "msf_cves": msf_cves or ["none"],
    }
    
    # 5. Generate Reports
    with report_path.open("w") as rpt:
        rpt.write(f"# SSH Recon Report: {target}:{port}\n\n")
        rpt.write("## Summary\n\n")
        rpt.write("```json\n")
        rpt.write(json.dumps(metadata, indent=2))
        rpt.write("\n```\n\n")
        rpt.write("## Nmap Scan Output\n\n")
        rpt.write(f"```\n{nmap_output}\n```\n\n")
        rpt.write("## ssh-audit Output\n\n")
        rpt.write(f"```\n{sshaudit_output}\n```\n\n")

    with json_path.open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] Report written: {report_path}")
    print(f"[✓] Metadata JSON written: {json_path}")
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced SSH Reconnaissance Script")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=22, help="Target port (default: 22)")
    args = parser.parse_args()
    footprint(args.target, args.port)