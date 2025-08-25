#!/usr/bin/env python3
import subprocess
import re
import json
from pathlib import Path
from typing import Dict, Tuple, List, Optional
import logging

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

# --- Robust Command Execution ---
def run_command(cmd: list[str], timeout: int = 300) -> tuple[str, bool]:
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
    return re.sub(r'\\x1B(?:[@-Z\\\\-_]|\\[[0-?]*[ -/]*[@-~])', '', text)

# --- SMB Specific Functions ---
def parse_nmap_vulns(nmap_output: str) -> Dict:
    """Parses the output of Nmap's smb-vuln* scripts to find critical vulnerabilities."""
    findings = {
        "allows_anonymous_login": False,
        "is_vulnerable_to_ms17_010": False,
        "vulnerabilities": []
    }
    
    # Check for anonymous/guest access
    if "Anonymous access: READ" in nmap_output or "Guest account access: READ" in nmap_output:
        findings["allows_anonymous_login"] = True

    # Check for MS17-010 (EternalBlue)
    if "State: VULNERABLE" in nmap_output and "MS17-010" in nmap_output:
        findings["is_vulnerable_to_ms17_010"] = True
        findings["vulnerabilities"].append({
            "id": "MS17-010",
            "details": "The target is vulnerable to MS17-010 (EternalBlue), allowing for remote code execution.",
            "severity": "Critical"
        })

    # You can add more parsers for other specific SMB vulnerabilities here
    
    return findings

# --- Main Footprinting Logic ---
def footprint(target: str, port: int = 445) -> Dict:
    """
    Performs deep reconnaissance of the SMB service.
    """
    logger.info(f"Starting SMB footprinting of {target}:{port}")
    
    # 1. Enhanced Nmap Scan for SMB
    nmap_cmd = [
        "nmap", "-p", str(port),
        "--script", "smb-enum-shares,smb-os-discovery,smb-vuln*",
        "-sV", "-Pn", target
    ]
    nmap_output, _ = run_command(nmap_cmd)
    
    # 2. Parse for critical vulnerabilities
    vuln_findings = parse_nmap_vulns(nmap_output)
    
    # 3. List shares with smbclient (as a fallback/confirmation)
    smbclient_cmd = ["smbclient", "-L", f"//{target}/", "-N"] # -N for no password
    smbclient_output, _ = run_command(smbclient_cmd)

    # 4. Search for exploits
    version_match = re.search(r"Samba smbd ([\d.]+)", nmap_output)
    query = f"Samba {version_match.group(1)}" if version_match else "Samba"
    # (Exploit search logic can be added here if desired)

    # 5. Compile Metadata
    metadata = {
        "target": target,
        "port": port,
        "service": "smb",
        "allows_anonymous_login": vuln_findings["allows_anonymous_login"],
        "is_vulnerable_to_ms17_010": vuln_findings["is_vulnerable_to_ms17_010"],
        "discovered_shares": [],
        "os_details": "Unknown",
        "full_nmap_output": nmap_output,
        "smbclient_output": smbclient_output,
        "potential_vulnerabilities": vuln_findings["vulnerabilities"]
    }

    # Parse OS details
    os_match = re.search(r"OS: (.*?)\s+Computer name:", nmap_output, re.DOTALL)
    if os_match:
        metadata["os_details"] = os_match.group(1).strip()

    # Parse shares from smbclient
    shares = re.findall(r"^\s+(Disk\s+.*)", smbclient_output, re.MULTILINE)
    metadata["discovered_shares"] = [s.strip() for s in shares]

    # Save reports
    save_smb_report(metadata)
    
    return metadata

def save_smb_report(metadata: Dict) -> None:
    """Saves the SMB reconnaissance findings to JSON and Markdown files."""
    target = metadata["target"]
    port = metadata["port"]
    report_path = OUTPUT_DIR / f"{target}_{port}_smb_report.md"
    json_path = OUTPUT_DIR / f"{target}_{port}_smb_metadata.json"

    with json_path.open("w", encoding='utf-8') as f:
        json.dump(metadata, f, indent=4)
    logger.info(f"JSON report saved: {json_path}")

    with report_path.open("w", encoding='utf-8') as f:
        f.write(f"# SMB Reconnaissance Report for {target}:{port}\\n\\n")
        f.write("## Executive Summary\\n\\n")
        f.write(f"This report details the findings from the reconnaissance phase against the SMB service on **{target}:{port}**. Key findings are summarized below.\\n\\n")

        f.write("### Key Findings\\n")
        f.write(f"- **Anonymous/Guest Share Access:** {'Allowed' if metadata['allows_anonymous_login'] else 'Not Detected'}\\n")
        f.write(f"- **Vulnerable to MS17-010 (EternalBlue):** {'YES (CRITICAL)' if metadata['is_vulnerable_to_ms17_010'] else 'No'}\\n")
        f.write(f"- **Discovered Shares:** {len(metadata['discovered_shares'])} shares found.\\n")
        f.write(f"- **Operating System:** {metadata['os_details']}\\n\\n")

        f.write("## Discovered Shares\\n")
        f.write("```\\n")
        f.write('\\n'.join(metadata['discovered_shares']) or "No shares found or accessible.")
        f.write("\\n```\\n\\n")

        f.write("## Nmap Vulnerability Scan Details\\n")
        f.write("```\\n")
        f.write(metadata['full_nmap_output'])
        f.write("\\n```\\n\\n")

    logger.info(f"Markdown report saved: {report_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: ./smb.py <target>")
        sys.exit(1)
    footprint(sys.argv[1])
