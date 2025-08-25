#!/usr/bin/env python3
import json
import subprocess
import argparse
import time
import re
from pathlib import Path
from typing import Dict, List, Tuple
import sys
import logging
import shutil
from datetime import datetime
import markdown

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Constants
OUTPUT_DIR = Path("outputs")
REPORT_JSON = "{target}_comprehensive_report.json"
REPORT_MD = "{target}_comprehensive_report.md"
REPORT_PDF = "{target}_comprehensive_report.pdf"

VULNERABILITY_DATA = {
    "lfi": {
        "name": "Local File Inclusion (LFI)",
        "risk": "High",
        "impact": "Can lead to information disclosure, such as leaking sensitive files, and may be escalated to Remote Code Execution (RCE) on misconfigured systems.",
        "remediation": "- Sanitize all user-supplied input to prevent directory traversal attacks (e.g., remove `../`).\n- Implement a whitelist of allowed files and paths that can be accessed.\n- Keep server software and PHP updated to the latest stable versions."
    },
    "rce": {
        "name": "Remote Code Execution (RCE)",
        "risk": "Critical",
        "impact": "Allows an attacker to execute arbitrary commands on the server, potentially leading to a full system compromise.",
        "remediation": "- If possible, disable dangerous functions that can execute code (e.g., `exec`, `system`, `shell_exec`).\n- Deploy a Web Application Firewall (WAF) to detect and block malicious command injection attempts.\n- Follow the principle of least privilege for the web server user."
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "risk": "Medium",
        "impact": "Can be used to hijack user sessions, deface websites, or redirect users to malicious sites.",
        "remediation": "- Sanitize all user-supplied input by properly encoding special characters (e.g., `<`, `>`, `\"`).\n- Implement a strong Content Security Policy (CSP) to restrict the sources of executable scripts."
    },
    "sql injection": {
        "name": "SQL Injection",
        "risk": "High",
        "impact": "May lead to data exfiltration, authentication bypass, and in some cases, remote code execution on the database server.",
        "remediation": "- Use parameterized queries (prepared statements) for all database interactions.\n- Avoid building SQL queries by concatenating strings with user input.\n- Validate and sanitize all user input before it is used in a database query."
    },
    "default credentials": {
        "name": "Default or Weak Credentials",
        "risk": "Critical",
        "impact": "Provides attackers with unauthorized access to administrative panels or services, often with high privileges.",
        "remediation": "- Immediately change all default credentials for applications and services.\n- Enforce a strong password policy for all users and services.\n- Where possible, enable Multi-Factor Authentication (MFA)."
    },
    "backdoor": {
        "name": "Software Backdoor",
        "risk": "Critical",
        "impact": "Indicates that the software has been compromised with a built-in mechanism for unauthorized access.",
        "remediation": "- Immediately take the affected system offline.\n- Re-install the compromised software from an official, trusted source.\n- Conduct a full system audit to check for other signs of compromise or persistence mechanisms."
    },
    "vulnerability": {
        "name": "General Vulnerability",
        "risk": "High",
        "impact": "Indicates an exploitable weakness in software, which could range from information disclosure to remote code execution.",
        "remediation": "- Apply all available security patches for the affected software.\n- Upgrade the software to the latest stable version to ensure all known vulnerabilities are addressed."
    },
    "misconfiguration": {
        "name": "Security Misconfiguration",
        "risk": "Medium",
        "impact": "Exposes sensitive information or unintended functionality that can be leveraged by an attacker.",
        "remediation": "- Review server and application configurations to ensure they align with security best practices.\n- Disable unnecessary features or services (e.g., HTTP TRACE method, directory listing)."
    },
    "http trace": {
        "name": "HTTP TRACE Method Enabled",
        "risk": "Low",
        "impact": "Can be used in Cross-Site Tracing (XST) attacks to steal cookies.",
        "remediation": "- Disable the HTTP TRACE method in your web server's configuration."
    }
}

service_mapping = {
    "http": "HTTP Web Server (Port 80)",
    "ssh": "SSH (Port 22)",
    "ftp": "FTP (Port 21)",
    "smtp": "SMTP (Port 25)",
    "dns": "DNS (Port 53)",
    "vnc": "VNC (Port 5900)",
    "telnet": "Telnet (Port 23)",
    "mysql": "MySQL (Port 3306)",
    "postgresql": "PostgreSQL (Port 5432)",
    "irc": "IRC (Port 6667)",
    "java_rmi": "Java RMI (Port 1099)",
    "smb": "SMB (Port 139/445)",
    "nfs": "NFS (Port 2049)",
    "rpc": "RPC (Port 111)",
    "distcc": "DistCC (Port 3632)",
    "ajp": "AJP (Port 8009)",
    "tomcat": "Tomcat (Port 8180)"
}


def analyze_attack_chains(exploit_results: Dict, post_exploit_results: Dict, recon_results: Dict) -> List[Dict]:
    """Analyze results to identify and describe potential attack chains as a list of dictionaries."""
    chains = []
    
    # Example Chain 1: LFI -> Password File -> Potentially leads to brute-forcing other services
    lfi_exploits = [e for s in exploit_results.values() for e in s.get("successful_exploits", []) if "lfi" in e['type'].lower()]
    lfi_downloads_passwd = [p for s in post_exploit_results.values() for p in s.get("post_exploitation_results", []) if "lfi" in p['type'].lower() and "passwd" in p.get('details', '').lower()]
    
    if lfi_exploits and lfi_downloads_passwd:
        chains.append({
            "name": "LFI to Credential Exposure",
            "steps": "1. **LFI Exploited**: A Local File Inclusion vulnerability was confirmed.\n"
                     "2. **Password File Leaked**: The LFI was used to download the `/etc/passwd` file.\n"
                     "3. **Impact**: The user list from this file significantly increases the risk of successful brute-force attacks against other services like SSH or FTP.",
            "risk": "High"
        })

    return chains


def format_json_to_markdown(data: Dict, indent_level: int = 0) -> List[str]:
    """Recursively format a dictionary into a markdown list."""
    lines = []
    indent = "  " * indent_level
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{indent}- **{key.replace('_', ' ').title()}**:")
            lines.extend(format_json_to_markdown(value, indent_level + 1))
        elif isinstance(value, list) and value:
            lines.append(f"{indent}- **{key.replace('_', ' ').title()}**:")
            for item in value:
                if isinstance(item, dict):
                    lines.extend(format_json_to_markdown(item, indent_level + 1))
                else:
                    lines.append(f"{indent}  - {item}")
        elif value is not None and value != "" and value != []:
            lines.append(f"{indent}- **{key.replace('_', ' ').title()}**: {value}")
    return lines


def run_command(cmd: List[str], timeout: int = 300, shell: bool = False) -> Tuple[str, bool]:
    """Run a shell command and return its output and success status."""
    cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)
    logger.info(f"Running: {cmd_str}")
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), True
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd_str} - {e.output}")
        return e.output, False
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {cmd_str}")
        return "Command timed out", False
    except Exception as e:
        logger.error(f"Error running command: {cmd_str} - {e}")
        return str(e), False

def collect_exploit_results(target: str) -> Dict:
    """Collect all exploit results for the target."""
    results = {}
    
    # Find all exploit JSON files
    exploit_files = list(OUTPUT_DIR.glob(f"{target}_*_exploit.json"))
    
    for exploit_file in exploit_files:
        try:
            with exploit_file.open("r", encoding='utf-8') as f:
                data = json.load(f)
            
            service = exploit_file.stem.replace(f"{target}_", "").replace("_exploit", "")
            results[service] = data
            
        except Exception as e:
            logger.error(f"Error reading {exploit_file}: {e}")
    
    return results

def collect_post_exploit_results(target: str) -> Dict:
    """Collect all post-exploitation results for the target."""
    results = {}
    
    # Find all post-exploit JSON files
    post_exploit_files = list(OUTPUT_DIR.glob(f"{target}_*_post_exploit.json"))
    
    for post_exploit_file in post_exploit_files:
        try:
            with post_exploit_file.open("r", encoding='utf-8') as f:
                data = json.load(f)
            
            service = post_exploit_file.stem.replace(f"{target}_", "").replace("_post_exploit", "")
            results[service] = data
            
        except Exception as e:
            logger.error(f"Error reading {post_exploit_file}: {e}")
    
    return results

def collect_recon_results(target: str) -> Dict:
    """Collect and merge all reconnaissance results for the target."""
    results = {}
    
    # Find all metadata files
    metadata_files = list(OUTPUT_DIR.glob(f"{target}_*_metadata.json"))
    
    for metadata_file in metadata_files:
        try:
            with metadata_file.open("r", encoding='utf-8') as f:
                data = json.load(f)
            
            service_name = metadata_file.stem.split('_')[1]
            if service_name in results:
                # Merge data for the same service (e.g., http from different ports)
                results[service_name].update(data)
            else:
                results[service_name] = data
            
        except Exception as e:
            logger.error(f"Error reading {metadata_file}: {e}")
    
    return results

def generate_comprehensive_report(target: str, exploit_results: Dict, post_exploit_results: Dict, recon_results: Dict) -> str:
    """Generate a comprehensive Metasploitable 2 style report."""
    
    lines = []
    
    # Header
    lines.append(f"# Comprehensive Exploitation Report")
    lines.append(f"## Target: {target}")
    lines.append(f"## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    
    total_exploits = sum(len(data.get("successful_exploits", [])) for data in exploit_results.values())
    successful_services = len([data for data in exploit_results.values() if data.get("successful_exploits")])
    
    lines.append(f"- **Total Exploits Found**: {total_exploits}")
    lines.append(f"- **Successful Services**: {successful_services}")
    lines.append(f"- **Services Tested**: {len(exploit_results)}")
    lines.append("")

    # --- Risk Rating Summary ---
    confirmed_risks = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    potential_risks = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    
    # Calculate confirmed risks from exploits
    for service, data in exploit_results.items():
        for exploit in data.get("successful_exploits", []):
            exploit_type = exploit['type'].lower()
            for keyword, details in VULNERABILITY_DATA.items():
                if all(word in exploit_type for word in keyword.split()):
                    risk = details.get("risk", "Low")
                    if risk in confirmed_risks:
                        confirmed_risks[risk] += 1
                    break
    
    # (Simplified) Calculate potential risks from recon data
    # In a real scenario, this would be more sophisticated
    for service, data in recon_results.items():
        if data.get('outdated_software'):
            potential_risks["High"] += len(data['outdated_software'])
        if data.get('misconfigurations'):
            potential_risks["Medium"] += len(data['misconfigurations'])

    lines.append("## Risk Summary")
    lines.append("")
    lines.append("| Severity | Confirmed | Potential |")
    lines.append("|---|---|---|")
    lines.append(f"| Critical | {confirmed_risks['Critical']} | {potential_risks['Critical']} |")
    lines.append(f"| High | {confirmed_risks['High']} | {potential_risks['High']} |")
    lines.append(f"| Medium | {confirmed_risks['Medium']} | {potential_risks['Medium']} |")
    lines.append(f"| Low | {confirmed_risks['Low']} | {potential_risks['Low']} |")
    lines.append("")
    
    # Attack Chain Analysis
    attack_chains = analyze_attack_chains(exploit_results, post_exploit_results, recon_results)
    if attack_chains:
        lines.append("## Critical Attack Chains")
        lines.append("")
        lines.append("| Attack Chain | Risk | Description |")
        lines.append("|---|---|---|")
        for chain in attack_chains:
            lines.append(f"| **{chain['name']}** | {chain['risk']} | {chain['steps'].replace('\n', '<br/>')} |")
        lines.append("")

    # Confirmed Vulnerabilities (from Exploitation)
    lines.append("## Confirmed Vulnerabilities")
    lines.append("")
    lines.append("The following vulnerabilities were actively exploited and confirmed on the target system.")
    lines.append("")

    # Group exploits by type to de-duplicate the analysis
    grouped_exploits = {}
    for service, data in exploit_results.items():
        for exploit in data.get("successful_exploits", []):
            exploit_type = exploit['type'].lower()
            for keyword, details in VULNERABILITY_DATA.items():
                if all(word in exploit_type for word in keyword.split()):
                    if keyword not in grouped_exploits:
                        grouped_exploits[keyword] = {
                            "name": details.get("name", keyword.replace("_", " ").title()),
                            "risk": details.get("risk", "Unknown"),
                            "impact": details.get("impact", "Unknown impact")
                        }
                    break
    
    lines.append("| Vulnerability | Risk | Impact |")
    lines.append("|---|---|---|")
    for keyword, details in sorted(grouped_exploits.items(), key=lambda item: ["Critical", "High", "Medium", "Low", "Unknown"].index(item[1]["risk"])):
        lines.append(f"| {details['name']} | {details['risk']} | {details['impact']} |")
    lines.append("")

    # Detailed Exploitation Results (moved to appendix)
    
    # Burp Suite Findings (if present)
    try:
        burp_issues_path = OUTPUT_DIR / f"{target}_burp_issues.json"
        if burp_issues_path.exists():
            with burp_issues_path.open("r", encoding="utf-8") as f:
                burp_issues = json.load(f)
            # Summarize severities
            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            top_rows = []
            for issue in burp_issues:
                sev = str(issue.get("severity", "Info")).title()
                if sev not in sev_counts:
                    sev = "Info"
                sev_counts[sev] += 1
            lines.append("## Burp Suite Findings")
            lines.append("")
            lines.append(f"- **Critical**: {sev_counts['Critical']}  |  **High**: {sev_counts['High']}  |  **Medium**: {sev_counts['Medium']}  |  **Low**: {sev_counts['Low']}  |  **Info**: {sev_counts['Info']}")
            lines.append("")
            # Show up to 10 issues
            lines.append("| Severity | Name | URL | Confidence |")
            lines.append("|---|---|---|---|")
            for issue in burp_issues[:10]:
                lines.append(f"| {str(issue.get('severity', 'Info')).title()} | {issue.get('name','')} | {issue.get('url','')} | {str(issue.get('confidence','')).title()} |")
            lines.append("")
    except Exception:
        pass

    # Potential Vulnerabilities Section
    lines.append("## Potential Vulnerabilities")
    lines.append("")
    lines.append("The following vulnerabilities were identified but not actively exploited during the engagement.")
    lines.append("")

    # Group recon findings by type to de-duplicate
    grouped_recon = {}
    for service, data in recon_results.items():
        if data.get('outdated_software'):
            for software in data['outdated_software']:
                if software not in grouped_recon:
                    grouped_recon[software] = {
                        "name": software,
                        "risk": "High",
                        "impact": "Outdated software can be exploited by attackers to gain unauthorized access or execute malicious code."
                    }
        if data.get('misconfigurations'):
            for config in data['misconfigurations']:
                if config not in grouped_recon:
                    grouped_recon[config] = {
                        "name": config,
                        "risk": "Medium",
                        "impact": "Security misconfigurations can expose sensitive data or functionality, potentially leading to unauthorized access."
                    }
        if data.get('http_trace'):
            if 'HTTP TRACE Method Enabled' not in grouped_recon:
                grouped_recon['HTTP TRACE Method Enabled'] = {
                    "name": "HTTP TRACE Method Enabled",
                    "risk": "Low",
                    "impact": "HTTP TRACE method can be used in Cross-Site Tracing (XST) attacks to steal cookies."
                }

    lines.append("| Vulnerability | Risk | Impact |")
    lines.append("|---|---|---|")
    for keyword, details in sorted(grouped_recon.items(), key=lambda item: ["Critical", "High", "Medium", "Low", "Unknown"].index(item[1]["risk"])):
        lines.append(f"| {details['name']} | {details['risk']} | {details['impact']} |")
    lines.append("")

    # Remediation Recommendations
    lines.append("## Prioritized Remediation Plan")
    lines.append("")

    lines.append("### Immediate Actions Required (Critical & High Risk):")
    lines.append("")

    remediation_by_risk = {"Critical": set(), "High": set(), "Medium": set(), "Low": set()}
    for service, data in exploit_results.items():
        for exploit in data.get("successful_exploits", []):
            exploit_type = exploit['type'].lower()
            for keyword, details in VULNERABILITY_DATA.items():
                if all(word in exploit_type for word in keyword.split()):
                    risk = details.get("risk", "Low")
                    remediation = details.get("remediation")
                    if risk in remediation_by_risk and remediation:
                        remediation_by_risk[risk].add(remediation)
                    break
    
    for advice in sorted(list(remediation_by_risk["Critical"])):
        lines.append(advice)
    for advice in sorted(list(remediation_by_risk["High"])):
        lines.append(advice)
    lines.append("")
    
    lines.append("### Secondary Actions (Medium & Low Risk):")
    lines.append("")
    for advice in sorted(list(remediation_by_risk["Medium"])):
        lines.append(advice)
    for advice in sorted(list(remediation_by_risk["Low"])):
        lines.append(advice)
    lines.append("")

    # Technical Details
    lines.append("## Detailed Reconnaissance Findings")
    lines.append("")
    
    for service, data in recon_results.items():
        service_name = service_mapping.get(service, f"{service.upper()}")
        lines.append(f"### {service_name}") 
        
        if data:
            lines.extend(format_json_to_markdown(data))
        else:
            lines.append("- No detailed reconnaissance data found.")

        lines.append("")
    
    # Appendices
    lines.append("## Appendices")
    lines.append("")
    
    lines.append("### A. Detailed Exploitation Results")
    lines.append("")
    
    for service, data in exploit_results.items():
        service_name = service_mapping.get(service, f"{service.upper()}")
        exploits = data.get("successful_exploits", [])
        actual_exploits = [e for e in exploits if 'type' in e]
        
        if actual_exploits:
            lines.append(f"#### {service_name}")
            lines.append("")
            
            for exploit in actual_exploits:
                lines.append(f"- **Type**: {exploit['type']}")
                lines.append(f"- **Target**: {exploit.get('target', f'{target}')}")
                lines.append(f"- **Details**: {exploit.get('details', 'N/A')}")
                lines.append(f"- **PoC**: `{exploit.get('poc', 'N/A')}`")
                lines.append("")
    
    return "\n".join(lines)

def save_comprehensive_report(report_content: str, target: str) -> None:
    """Save comprehensive report to multiple formats."""
    
    # Save Markdown
    md_path = OUTPUT_DIR / REPORT_MD.format(target=target)
    with md_path.open("w", encoding='utf-8') as f:
        f.write(report_content)
    logger.info(f"Saved comprehensive report to {md_path}")
    
    # Save JSON metadata
    json_path = OUTPUT_DIR / REPORT_JSON.format(target=target)
    metadata = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "report_generated": True,
        "report_file": str(md_path)
    }
    with json_path.open("w", encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Saved report metadata to {json_path}")
    
    # Generate PDF if weasyprint is available
    try:
        import weasyprint
        import markdown
        pdf_path = OUTPUT_DIR / REPORT_PDF.format(target=target)
        
        # Convert markdown to HTML
        html_content = markdown.markdown(report_content, extensions=['tables'])
        
        # Create full HTML document
        html_doc = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Comprehensive Report - {target}</title>
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&family=Roboto+Mono&display=swap');
                
                @page {{
                    size: A4;
                    margin: 1.5cm;
                    @bottom-center {{
                        content: "Comprehensive Report | Target: {target} | Page " counter(page);
                        font-family: 'Roboto', sans-serif;
                        font-size: 10px;
                        color: #6c757d;
                    }}
                }}

                body {{
                    font-family: 'Roboto', sans-serif;
                    line-height: 1.7;
                    color: #343a40;
                }}
                .container {{ margin: 0 auto; }}
                .report-header {{
                    text-align: center;
                    border-bottom: 4px solid #0056b3;
                    padding-bottom: 10px;
                    margin-bottom: 30px;
                }}
                .report-header h1 {{
                    color: #0056b3;
                    margin: 0;
                    font-size: 2.8em;
                    font-weight: 700;
                }}
                h2 {{ 
                    font-size: 2em; 
                    color: #0056b3;
                    border-bottom: 2px solid #dee2e6;
                    padding-bottom: 10px;
                    margin-top: 45px;
                }}
                h3 {{ 
                    font-size: 1.5em; 
                    color: #0069d9;
                    border-left: 5px solid #0069d9;
                    padding-left: 12px;
                    margin-top: 35px; 
                }}
                h4 {{ font-size: 1.15em; font-weight: 500; }}

                code, pre {{
                    font-family: 'Roboto Mono', monospace;
                    background-color: #f1f3f5;
                    border: 1px solid #e9ecef;
                    border-radius: 4px;
                }}
                code {{ padding: 3px 6px; color: #bf4d5d; }}
                pre {{
                    padding: 1rem;
                    line-height: 1.5;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                    margin-bottom: 20px;
                }}
                th, td {{
                    border: 1px solid #dee2e6;
                    padding: 12px;
                    text-align: left;
                }}
                th {{
                    background-color: #f8f9fa;
                    font-weight: 700;
                    color: #0056b3;
                }}
                tr:nth-child(even) {{ background-color: #f8f9fa; }}
                ul {{ padding-left: 25px; }}
                li {{ margin-bottom: 10px; }}
                .success {{ color: #28a745; font-weight: 700; }}
                .failed {{ color: #dc3545; font-weight: 700; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="report-header">
                    <h1>Comprehensive Report</h1>
                </div>
                {html_content}
            </div>
        </body>
        </html>
        """
        
        # Generate PDF
        weasyprint.HTML(string=html_doc).write_pdf(str(pdf_path))
        logger.info(f"Generated PDF report: {pdf_path}")
        
    except ImportError:
        logger.warning("weasyprint or markdown not available. PDF generation skipped.")
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")

def main():
    """Main function to generate comprehensive report."""
    parser = argparse.ArgumentParser(description="Comprehensive Report Generator")
    parser.add_argument("target", help="Target domain or IP")
    args = parser.parse_args()

    logger.info(f"Generating comprehensive report for {args.target}")

    # Collect all results
    exploit_results = collect_exploit_results(args.target)
    post_exploit_results = collect_post_exploit_results(args.target)
    recon_results = collect_recon_results(args.target)

    if not exploit_results:
        logger.warning("No exploit results found. This is normal if exploitation failed or no vulnerabilities were found.")
        exploit_results = {}  # Use empty dict instead of exiting

    # Generate comprehensive report
    report_content = generate_comprehensive_report(
        args.target, 
        exploit_results, 
        post_exploit_results, 
        recon_results
    )

    # Save report
    save_comprehensive_report(report_content, args.target)
    
    logger.info("Comprehensive report generation complete.")
    logger.info(f"Report saved to: outputs/{args.target}_comprehensive_report.md")

if __name__ == "__main__":
    main() 