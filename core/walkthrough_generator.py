#!/usr/bin/env python3
import json
import argparse
import time
from pathlib import Path
from typing import Dict, List
import sys
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Constants
OUTPUT_DIR = Path("outputs")
WALKTHROUGH_JSON = "{target}_walkthrough.json"
WALKTHROUGH_MD = "{target}_walkthrough.md"

def collect_all_data(target: str) -> Dict:
    """Collect all data for the target."""
    data = {
        "recon": {},
        "exploit": {},
        "post_exploit": {}
    }
    
    # Collect reconnaissance data
    metadata_files = list(OUTPUT_DIR.glob(f"{target}_*_metadata.json"))
    for file in metadata_files:
        try:
            with file.open("r", encoding='utf-8') as f:
                service = file.stem.replace(f"{target}_", "").replace("_metadata", "")
                data["recon"][service] = json.load(f)
        except Exception as e:
            logger.error(f"Error reading {file}: {e}")
    
    # Collect exploitation data
    exploit_files = list(OUTPUT_DIR.glob(f"{target}_*_exploit.json"))
    for file in exploit_files:
        try:
            with file.open("r", encoding='utf-8') as f:
                service = file.stem.replace(f"{target}_", "").replace("_exploit", "")
                data["exploit"][service] = json.load(f)
        except Exception as e:
            logger.error(f"Error reading {file}: {e}")
    
    # Collect post-exploitation data
    post_exploit_files = list(OUTPUT_DIR.glob(f"{target}_*_post_exploit.json"))
    for file in post_exploit_files:
        try:
            with file.open("r", encoding='utf-8') as f:
                service = file.stem.replace(f"{target}_", "").replace("_post_exploit", "")
                data["post_exploit"][service] = json.load(f)
        except Exception as e:
            logger.error(f"Error reading {file}: {e}")
    
    return data

def generate_service_walkthrough(service: str, data: Dict, target: str) -> List[str]:
    """Generate walkthrough for a specific service."""
    lines = []
    
    service_names = {
        "http": "HTTP Web Server",
        "ssh": "SSH Remote Access", 
        "ftp": "FTP File Transfer",
        "smtp": "SMTP Mail Server",
        "mysql": "MySQL Database",
        "smb": "SMB File Sharing",
        "telnet": "Telnet Remote Access",
        "dns": "DNS Name Resolution",
        "vnc": "VNC Remote Desktop",
        "postgresql": "PostgreSQL Database",
        "bindshell": "Direct Backdoor Shell",
        "nfs": "NFS File Sharing"
    }
    
    service_name = service_names.get(service, service.upper())
    lines.append(f"## {service_name} ({service.upper()})")
    lines.append("")
    
    # Reconnaissance
    if service in data["recon"]:
        recon = data["recon"][service]
        lines.append("### Reconnaissance")
        lines.append(f"- **Port**: {recon.get('port', 'N/A')}")
        lines.append(f"- **Service**: {recon.get('service', 'N/A')}")
        lines.append(f"- **Version**: {recon.get('version', 'N/A')}")
        lines.append(f"- **Banner**: {recon.get('banner', 'N/A')}")
        lines.append("")
    
    # Exploitation
    if service in data["exploit"]:
        exploit = data["exploit"][service]
        successful_exploits = exploit.get("successful_exploits", [])
        
        if successful_exploits:
            lines.append("### Exploitation")
            lines.append("")
            
            for exp in successful_exploits:
                if "type" in exp:
                    lines.append(f"#### {exp['type']}")
                    lines.append(f"- **Target**: {exp.get('target', f'{target}')}")
                    lines.append(f"- **Details**: {exp.get('details', 'N/A')}")
                    if "poc" in exp:
                        lines.append("**Proof of Concept:**")
                        lines.append("```bash")
                        lines.append(exp["poc"])
                        lines.append("```")
                    lines.append("")
    
    # Post-Exploitation
    if service in data["post_exploit"]:
        post_exploit = data["post_exploit"][service]
        post_results = post_exploit.get("post_exploitation_results", [])
        
        if post_results:
            lines.append("### Post-Exploitation")
            lines.append("")
            
            for post_exp in post_results:
                if "type" in post_exp:
                    lines.append(f"#### {post_exp['type']}")
                    lines.append(f"- **Details**: {post_exp.get('details', 'N/A')}")
                    if "poc" in post_exp:
                        lines.append("**Proof of Concept:**")
                        lines.append("```bash")
                        lines.append(post_exp["poc"])
                        lines.append("```")
                    lines.append("")
    
    return lines

def generate_comprehensive_walkthrough(target: str, data: Dict) -> str:
    """Generate comprehensive walkthrough."""
    lines = []
    
    # Header
    lines.append(f"# Complete Penetration Testing Walkthrough")
    lines.append(f"## Target: {target}")
    lines.append(f"## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("This document provides a complete walkthrough of the penetration testing engagement against the target system.")
    lines.append("")
    
    # Methodology
    lines.append("## Methodology")
    lines.append("")
    lines.append("### Phase 1: Reconnaissance")
    lines.append("- Port scanning and service enumeration")
    lines.append("- Vulnerability assessment")
    lines.append("")
    lines.append("### Phase 2: Exploitation")
    lines.append("- Systematic exploitation of vulnerabilities")
    lines.append("- Proof of concept demonstrations")
    lines.append("")
    lines.append("### Phase 3: Post-Exploitation")
    lines.append("- Privilege escalation")
    lines.append("- Data exfiltration")
    lines.append("")
    
    # Detailed Walkthrough
    lines.append("## Detailed Walkthrough")
    lines.append("")
    
    # Process each service
    all_services = set()
    all_services.update(data["recon"].keys())
    all_services.update(data["exploit"].keys())
    all_services.update(data["post_exploit"].keys())
    
    for service in sorted(all_services):
        service_lines = generate_service_walkthrough(service, data, target)
        lines.extend(service_lines)
        lines.append("---")
        lines.append("")
    
    # Impact Assessment
    lines.append("## Impact Assessment")
    lines.append("")
    lines.append("### Critical Findings")
    lines.append("- Multiple methods to gain unauthorized access")
    lines.append("- Sensitive data exposure")
    lines.append("- Service vulnerabilities")
    lines.append("")
    
    # Remediation
    lines.append("## Remediation Recommendations")
    lines.append("")
    lines.append("### Immediate Actions")
    lines.append("1. Patch vulnerable services")
    lines.append("2. Change default credentials")
    lines.append("3. Disable unnecessary services")
    lines.append("4. Implement network segmentation")
    lines.append("")
    
    return "\n".join(lines)

def save_walkthrough_report(walkthrough_content: str, target: str) -> None:
    """Save walkthrough report."""
    
    # Save Markdown
    md_path = OUTPUT_DIR / WALKTHROUGH_MD.format(target=target)
    with md_path.open("w", encoding='utf-8') as f:
        f.write(walkthrough_content)
    logger.info(f"Saved walkthrough report to {md_path}")
    
    # Save JSON metadata
    json_path = OUTPUT_DIR / WALKTHROUGH_JSON.format(target=target)
    metadata = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "walkthrough_generated": True,
        "walkthrough_file": str(md_path)
    }
    with json_path.open("w", encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Saved walkthrough metadata to {json_path}")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Comprehensive Walkthrough Generator")
    parser.add_argument("target", help="Target domain or IP")
    args = parser.parse_args()
    
    logger.info(f"Generating comprehensive walkthrough for {args.target}")
    
    # Collect all data
    data = collect_all_data(args.target)
    
    if not data["recon"] and not data["exploit"]:
        logger.error("No data found. Run reconnaissance and exploitation first.")
        sys.exit(1)
    
    # Generate walkthrough
    walkthrough_content = generate_comprehensive_walkthrough(args.target, data)
    
    # Save walkthrough
    save_walkthrough_report(walkthrough_content, args.target)
    
    logger.info("Walkthrough generation complete.")
    logger.info(f"Walkthrough saved to: outputs/{args.target}_walkthrough.md")

if __name__ == "__main__":
    main() 