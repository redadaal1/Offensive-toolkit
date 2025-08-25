#!/usr/bin/env python3
import subprocess
import re
import json
import argparse
from pathlib import Path
from typing import Dict, Tuple

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)
TEST_FILE = OUTPUT_DIR / "ftp_test_upload.txt"


def run_cmd(cmd, *, shell=False, timeout=60) -> Tuple[str, bool]:
    """Run a command and return its output and success status."""
    cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
    print(f"[ftp] ▶ {cmd_str}")
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=shell,
            timeout=timeout,
            check=True  # Raise CalledProcessError on non-zero exit codes
        )
        return result.stdout.strip(), True
    except subprocess.CalledProcessError as e:
        # For commands that are expected to fail sometimes (like nc), we don't treat it as a hard error.
        return e.output.strip(), False
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out: {cmd_str}")
        return "Command timed out", False
    except Exception as e:
        print(f"[!] Unexpected error running command: {e}")
        return str(e), False


def parse_ftp_version(nmap_output: str) -> Tuple[str, str]:
    """Parse FTP server and version from nmap output."""
    # Pattern for vsftpd, ProFTPD, Pure-FTPd, and Microsoft FTP servers
    patterns = [
        r"(vsftpd)\s+([\d.]+)",
        r"(ProFTPD)\s+([\d.]+)",
        r"(Pure-FTPd)",
        r"Microsoft FTP",
    ]
    for pattern in patterns:
        match = re.search(pattern, nmap_output, re.IGNORECASE)
        if match:
            groups = match.groups()
            server = groups[0].strip()
            version = groups[1] if len(groups) > 1 else "unknown"
            return server, version
    return "unknown", "unknown"


def parse_ftp_syst(nmap_output: str):
    raw = ""
    if "| ftp-syst:" in nmap_output:
        raw = nmap_output.split("| ftp-syst:")[1].split("\n\n",1)[0].strip()
    parsed = {}
    for line in raw.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            parsed[k.strip()] = v.strip()
    return raw, parsed


def search_exploits(query: str) -> Tuple[list, list, list, list]:
    """Search ExploitDB and Metasploit for exploits."""
    if not query or query == "unknown":
        return [], [], [], []

    print(f"[*] Searching exploits for: '{query}'")
    exploitdb_mods, exploitdb_cves, msf_mods, msf_cves = [], [], [], []

    # Search ExploitDB
    out_db, _ = run_cmd(["searchsploit", "--disable-colour", query])
    lines = out_db.splitlines()
    try:
        start_index = next(i for i, line in enumerate(lines) if 'Exploit Title' in line and 'Path' in line) + 2
    except StopIteration:
        start_index = 4  # Fallback for different searchsploit versions
    lines = lines[start_index:-1]

    for line in lines:
        parts = line.split('|')
        if len(parts) > 1:
            title = parts[0].strip()
            path = parts[1].strip()
            if "Path" not in path: # Filter out header remnants
                exploitdb_mods.append(f"{title} ({path})")
                exploitdb_cves.extend(re.findall(r"CVE-\d{4}-\d{4,7}", title))

    # Search Metasploit
    out_msf, _ = run_cmd(["msfconsole", "-q", "-x", f"search {query}; exit"])
    found_msf_mods_raw = set(re.findall(r"exploit/\S+", out_msf))
    
    # Clean ANSI escape codes from module names
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    found_msf_mods = {ansi_escape.sub('', mod) for mod in found_msf_mods_raw}

    for mod in list(found_msf_mods):
        info, _ = run_cmd(["msfconsole", "-q", "-x", f"info {mod}; exit"])
        msf_cves.extend(re.findall(r"CVE-\d{4}-\d{4,7}", info))
    
    msf_mods = sorted(list(found_msf_mods))
    exploitdb_cves = sorted(list(set(exploitdb_cves)))
    msf_cves = sorted(list(set(msf_cves)))
    
    return exploitdb_mods, exploitdb_cves, msf_mods, msf_cves


def grab_tls_banner(target: str, port: int):
    output, _ = run_cmd(["openssl", "s_client", "-connect", f"{target}:{port}", "-starttls", "ftp", "-quiet"], timeout=10)
    return output


def anon_ftp_command(target: str, port: int, command: str) -> Tuple[str, bool]:
    here_doc = f"user anonymous anonymous\n{command}\nquit"
    ftp_cmd = f"ftp -n -v {target} {port}"
    # Use Popen to pipe commands to ftp process stdin
    process = subprocess.Popen(ftp_cmd.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        output, _ = process.communicate(input=here_doc, timeout=30)
        return output.strip(), process.returncode == 0
    except subprocess.TimeoutExpired:
        process.kill()
        return "Command timed out", False


def check_anon_upload(target: str, port: int) -> Tuple[bool, str]:
    """Checks if anonymous user can upload files."""
    if not TEST_FILE.exists():
        TEST_FILE.write_text("This is a test file for anonymous FTP upload.")

    filename = TEST_FILE.name
    output, _ = anon_ftp_command(target, port, f"put {TEST_FILE.resolve()} {filename}")
    
    can_upload = "226" in output and "Transfer complete" in output

    if can_upload:
        # Try to delete the file to clean up
        anon_ftp_command(target, port, f"delete {filename}")

    return can_upload, output


def footprint(target: str, port: int) -> Dict:
    report_path = OUTPUT_DIR / f"{target}_{port}_ftp_report.md"
    print(f"[+] Generating FTP report → {report_path}")

    # 1. Nmap Scan
    print("[*] Running comprehensive Nmap scan...")
    nmap_scripts = "ftp-anon,ftp-syst,ftp-vsftpd-backdoor,ftp-bounce,ftp-proftpd-backdoor,ftp-vuln-cve2010-4221"
    nmap_cmd = ["nmap", "-p", str(port), "-sV", "--script", nmap_scripts, target]
    nmap_output, _ = run_cmd(nmap_cmd)

    # 2. Banner Grabbing
    print("[*] Grabbing banners...")
    banner_output, _ = run_cmd(["nc", "-nv", "-w", "5", target, str(port)])
    tls_banner_output = grab_tls_banner(target, port)

    # 3. Parse Nmap Results
    server, version = parse_ftp_version(nmap_output)
    syst_raw, syst_parsed = parse_ftp_syst(nmap_output)

    # 4. Anonymous Login Checks
    print("[*] Checking for anonymous access...")
    anon_allowed = "Anonymous FTP login allowed" in nmap_output
    anon_ls_output = ""
    anon_upload_allowed = False
    anon_upload_output = ""

    if anon_allowed:
        print("[+] Anonymous login detected. Probing further...")
        anon_ls_output, _ = anon_ftp_command(target, port, "ls -la")
        anon_upload_allowed, anon_upload_output = check_anon_upload(target, port)
    else:
        print("[-] Anonymous login not detected by Nmap.")

    # 5. Search for Exploits
    search_query = f"{server} {version}".strip() if server != "unknown" else ""
    if not search_query:
        # Fallback to nmap service info if parsing fails
        service_match = re.search(fr"^{port}/tcp\s+open\s+ftp\s+(.*)", nmap_output, re.MULTILINE)
        if service_match:
            search_query = service_match.group(1).strip()
    
    exploitdb_mods, exploitdb_cves, msf_mods, msf_cves = search_exploits(search_query)

    # 6. Assemble Metadata
    metadata = {
        "target": target,
        "port": port,
        "server": server,
        "version": version,
        "anonymous_login_allowed": "yes" if anon_allowed else "no",
        "anonymous_upload_allowed": "yes" if anon_upload_allowed else "no",
        "backdoor_detected": "yes" if "backdoor" in nmap_output.lower() or (server == "vsftpd" and version == "2.3.4") else "no",
        "ftp_syst": syst_parsed,
        "exploitdb_mods": exploitdb_mods or ["none"],
        "exploitdb_cves": exploitdb_cves or ["none"],
        "msf_mods": msf_mods or ["none"],
        "msf_cves": msf_cves or ["none"],
    }
    
    # 7. Generate Report
    print(f"[*] Writing reports to {OUTPUT_DIR}/")

    sections = {
        "nmap_scan": nmap_output,
        "ftp_banner": banner_output,
        "ftp_tls_banner": tls_banner_output,
        "anonymous_listing": anon_ls_output if anon_allowed else "Not attempted.",
        "anonymous_upload_test": anon_upload_output if anon_allowed else "Not attempted."
    }

    with report_path.open("w") as rpt:
        rpt.write(f"# FTP Recon Report for {target}:{port}\n\n")
        rpt.write("## Metadata Summary\n")
        rpt.write("```json\n")
        rpt.write(json.dumps(metadata, indent=2))
        rpt.write("\n```\n\n")

        for name, content in sections.items():
            if content:
                rpt.write(f"## {name.replace('_', ' ').title()}\n")
                rpt.write("```bash\n")
                rpt.write(content.strip() + "\n")
                rpt.write("```\n\n")

    json_path = OUTPUT_DIR / f"{target}_{port}_ftp_metadata.json"
    with json_path.open("w") as jf:
        json.dump(metadata, jf, indent=2)

    print(f"[✓] Report written: {report_path}")
    print(f"[✓] Metadata JSON written: {json_path}")
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced FTP Reconnaissance Script")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("--port", type=int, default=21, help="Target FTP port (default: 21)")
    args = parser.parse_args()
    footprint(args.target, args.port)
