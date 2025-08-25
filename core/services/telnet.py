#!/usr/bin/env python3
import subprocess
import re
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, Tuple, List, Optional
import socket
import time
import telnetlib

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)
LOOT_DIR = OUTPUT_DIR / "loot"
LOOT_DIR.mkdir(exist_ok=True)

# --- Robust Command Execution ---
def run_command(cmd: list[str], timeout: int = 60) -> tuple[str, bool]:
    cmd_str = ' '.join(cmd)
    logger.info(f"Running command: {cmd_str}")
    try:
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False 
        )
        return process.stdout.strip(), process.returncode == 0
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {cmd_str}")
        return "Command timed out", False
    except Exception as e:
        logger.error(f"Error running command {cmd_str}: {e}")
        return str(e), False

def clean_ansi_codes(text: str) -> str:
    """Removes ANSI escape codes from text."""
    return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)

# --- Telnet Specific Functions ---
def parse_telnet_banner(output: str) -> str:
    """Extracts a clean banner from Telnet connection output."""
    lines = output.splitlines()
    banner_lines = []
    for line in lines:
        cleaned_line = clean_ansi_codes(line).strip()
        if cleaned_line:
            banner_lines.append(cleaned_line)
    return "\n".join(banner_lines)

def check_anonymous_access(target: str, port: int) -> tuple[bool, str]:
    """
    Checks for anonymous/blank password access using Hydra for reliability.
    """
    # Create a temporary list of common users to check for blank password access
    user_list_path = OUTPUT_DIR / f"{target}_{port}_telnet_anon_users.txt"
    with user_list_path.open("w") as f:
        f.write("root\\nadmin\\nuser\\nmsfadmin\\nguest\\nanonymous\\n")
    
    # Use Hydra to test for blank passwords (-p "") for the user list
    hydra_cmd = [
        "hydra",
        "-L", str(user_list_path),
        "-p", '""',  # Test an empty password
        "-t", "4",
        f"telnet://{target}:{port}"
    ]
    
    output, success = run_command(hydra_cmd, timeout=300)
    
    # Clean up the temporary file
    user_list_path.unlink()

    if success and "password found" in output:
        proof = f"Hydra confirmed that a user account has a blank password. This allows for unauthenticated access.\\n\\nHydra Output:\\n{output}"
        logger.info(proof)
        return True, proof
        
    return False, "Anonymous (blank password) access check with Hydra did not find any vulnerable accounts."

def search_exploits(query: str) -> Tuple[list, list, list, list]:
    logger.info(f"Searching exploits for: '{query}'")
    
    # Exploit-DB
    cmd_exploitdb = ["searchsploit", "--disable-colour", query]
    out_exploitdb, success_exploitdb = run_command(cmd_exploitdb)
    found_exploitdb_mods = list(set(re.findall(r"^(.*?)\s*\|", out_exploitdb, re.MULTILINE))) if success_exploitdb else []
    found_exploitdb_cves = list(set(re.findall(r"CVE-\d{4}-\d+", out_exploitdb))) if success_exploitdb else []

    # Metasploit
    msf_script = f"search {query}; exit"
    cmd_msf = ["msfconsole", "-q", "-x", msf_script]
    out_msf, success_msf = run_command(cmd_msf, timeout=180)
    
    if success_msf:
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        cleaned_output = ansi_escape.sub('', out_msf)
        found_msf_mods_raw = set(re.findall(r"exploit/\S+", cleaned_output))
        cleaned_msf_mods = {mod.strip() for mod in found_msf_mods_raw}
        found_msf_cves = list(set(re.findall(r"CVE-\d{4}-\d+", out_msf)))
    else:
        cleaned_msf_mods = set()
        found_msf_cves = []

    return found_exploitdb_mods, found_exploitdb_cves, list(cleaned_msf_mods), found_msf_cves

# --- Main Footprinting Logic ---
def footprint(target: str, port: int) -> Dict:
    """Perform Telnet reconnaissance."""
    report_path = OUTPUT_DIR / f"{target}_{port}_telnet_report.md"
    json_path = OUTPUT_DIR / f"{target}_{port}_telnet_metadata.json"
    logger.info(f"Generating Telnet recon report for {target}:{port} -> {report_path}")

    # 1. Nmap Scan
    nmap_cmd = ["nmap", "-sV", "-p", str(port), "--script=telnet-ntlm-info", target]
    nmap_output, _ = run_command(nmap_cmd)
    
    version_match = re.search(r"(\S+)\s+telnet\s+(.*)", nmap_output)
    version = version_match.group(2).strip() if version_match else "unknown"
    
    # 2. Check Anonymous Access
    anon_allowed, anon_proof = check_anonymous_access(target, port)

    # 3. Search for exploits
    search_query = version if version != "unknown" else "telnet"
    exploitdb_mods, exploitdb_cves, msf_mods, msf_cves = search_exploits(search_query)

    # 4. Aggregate Metadata
    metadata = {
        "target": target,
        "port": port,
        "service": "telnet",
        "version": version,
        "nmap_output": nmap_output,
        "anonymous_access": anon_allowed,
        "anonymous_access_proof": anon_proof,
        "exploitdb_mods": exploitdb_mods or ["none"],
        "exploitdb_cves": exploitdb_cves or ["none"],
        "msf_mods": msf_mods or ["none"],
        "msf_cves": msf_cves or ["none"],
    }

    # 5. Write Reports
    # Markdown Report
    with report_path.open("w") as f:
        f.write(f"# Telnet Reconnaissance Report for {target}:{port}\n\n")
        f.write("## Summary\n")
        f.write(f"- **Target:** {target}:{port}\n")
        f.write(f"- **Service:** Telnet\n")
        f.write(f"- **Version:** {version}\n")
        f.write(f"- **Anonymous Access:** {'Allowed' if anon_allowed else 'Not Detected'}\n\n")
        
        f.write("## Nmap Scan Results\n")
        f.write("```\n")
        f.write(nmap_output)
        f.write("\n```\n\n")

        if anon_allowed:
            f.write("## Anonymous Access Check\n")
            f.write("Status: **VULNERABLE**\n")
            f.write("```\n")
            f.write(anon_proof)
            f.write("\n```\n\n")

        f.write("## Potential Exploits\n")
        f.write("### Exploit-DB\n")
        if exploitdb_mods and "none" not in exploitdb_mods:
            for mod in exploitdb_mods:
                f.write(f"- {mod}\n")
        else:
            f.write("No specific exploits found in Exploit-DB.\n")
        
        f.write("\n### Metasploit Framework\n")
        if msf_mods and "none" not in msf_mods:
            for mod in msf_mods:
                f.write(f"- {mod}\n")
        else:
            f.write("No specific exploits found in Metasploit.\n")
    
    logger.info(f"Markdown report written to {report_path}")

    # JSON Report
    with json_path.open("w") as f:
        json.dump(metadata, f, indent=4)
    logger.info(f"JSON metadata written to {json_path}")

    return metadata

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Telnet Reconnaissance Script")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=23, help="Target Telnet port")
    args = parser.parse_args()
    footprint(args.target, args.port)