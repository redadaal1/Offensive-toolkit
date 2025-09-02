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
from urllib.parse import urlparse

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
            
            service_raw = exploit_file.stem.replace(f"{target}_", "").replace("_exploit", "")
            # Normalize names like "22_ssh" -> "ssh"
            if re.match(r"^\d+_", service_raw):
                parts = service_raw.split("_")
                service = parts[-1] if parts else service_raw
            else:
                service = service_raw
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
            
            service_raw = post_exploit_file.stem.replace(f"{target}_", "").replace("_post_exploit", "")
            # Normalize names like "22_ssh" -> "ssh"
            if re.match(r"^\d+_", service_raw):
                parts = service_raw.split("_")
                service = parts[-1] if parts else service_raw
            else:
                service = service_raw
            results[service] = data
            
        except Exception as e:
            logger.error(f"Error reading {post_exploit_file}: {e}")
    
    # Also ingest combined post-exploitation metadata if present
    try:
        combined_path = OUTPUT_DIR / "post_exploitation_metadata.json"
        if combined_path.exists():
            combined = json.loads(combined_path.read_text(encoding='utf-8'))
            if str(combined.get("target")) == str(target):
                for entry in combined.get("results", []):
                    service = entry.get("service") or entry.get("script") or "general"
                    # Normalize service like "22_ssh" to "ssh"
                    if isinstance(service, str) and re.match(r"^\d+_", service):
                        parts = service.split("_")
                        service = parts[-1] if parts else service
                    container = results.setdefault(service, {})
                    lst = container.setdefault("post_exploitation_results", [])
                    # Build a concise summary item
                    output_text = entry.get("output") or ""
                    if isinstance(output_text, str) and len(output_text) > 1200:
                        output_text = output_text[:1200].rstrip() + "..."
                    lst.append({
                        "type": f"{entry.get('script','post_exploit')} summary",
                        "details": output_text or ("Success" if entry.get("success") else "No actions taken"),
                        "success": entry.get("success", False),
                    })
    except Exception as e:
        logger.warning(f"Failed to read combined post-exploitation metadata: {e}")

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

            # Robust service name extraction from filename
            # Examples:
            #   192.168.1.113_22_ssh_metadata.json      -> service: ssh
            #   192.168.1.113_http_80_tcp_metadata.json -> service: http
            #   192.168.1.113_smb_445_tcp_metadata.json -> service: smb
            #   192.168.1.113_http_burp_metadata.json   -> (handled separately)
            stem = metadata_file.stem
            parts = stem.split('_')
            service_name = None
            if len(parts) >= 3 and parts[1].isdigit():
                # target_port_service_metadata
                service_name = parts[2]
            elif len(parts) >= 2:
                service_name = parts[1]
            else:
                service_name = stem

            # Skip raw Burp metadata here; VA section handles it cleanly
            file_lower = metadata_file.name.lower()
            if 'burp' in file_lower or (isinstance(data, dict) and str(data.get('tool','')).lower() == 'burp'):
                continue
            if service_name in results:
                # Merge data for the same service (e.g., http from different ports)
                results[service_name].update(data)
            else:
                results[service_name] = data
            
        except Exception as e:
            logger.error(f"Error reading {metadata_file}: {e}")
    
    return results

def _safe_name(value: str) -> str:
    return ''.join(ch if ch.isalnum() or ch in ('-', '_', '.') else '_' for ch in value)

def _canonicalize_text(text: str) -> str:
    """Normalize text for de-duplication (trim whitespace/punctuation variations)."""
    if not isinstance(text, str):
        return str(text)
    normalized = text.strip()
    # Remove trailing punctuation like '.', ')', ':' commonly duplicated
    while normalized and normalized[-1] in ".):; ":
        normalized = normalized[:-1].rstrip()
    return normalized

def _is_url_for_target(url: str, target: str) -> bool:
    try:
        if not isinstance(url, str) or not url:
            return False
        # Allow absolute URLs pointing to target or path-only URLs
        if url.startswith('/'):
            return True
        parsed = urlparse(url)
        return parsed.hostname == target
    except Exception:
        return False

def _sanitize_dict_for_report(data: Dict, target: str) -> Dict:
    """Remove overly verbose or sensitive fields and deduplicate simple lists."""
    if not isinstance(data, dict):
        return data
    sensitive_keys = {
        'evidence', 'request_response', 'request', 'response', 'bytes', 'data',
        'SnipSegment', 'HighlightSegment', 'length', 'was_redirect_followed',
        'request_time', 'band_flags', 'payload'
    }
    sanitized: Dict = {}
    for key, value in data.items():
        key_l = str(key).lower()
        if key_l in sensitive_keys:
            continue
        # Drop raw Burp issues here; VA section summarizes them
        if key_l == 'issues':
            continue
        if isinstance(value, dict):
            sanitized[key] = _sanitize_dict_for_report(value, target)
        elif isinstance(value, list):
            new_items: List = []
            seen = set()
            for item in value:
                if isinstance(item, dict):
                    # Special handling: filter discovered_endpoints by target
                    if key_l in {'discovered_endpoints', 'vulnerable_endpoints'}:
                        url_val = item.get('url') or item.get('path')
                        if url_val and not _is_url_for_target(str(url_val), target):
                            continue
                    new_items.append(_sanitize_dict_for_report(item, target))
                else:
                    canon = _canonicalize_text(item)
                    if canon not in seen:
                        seen.add(canon)
                        new_items.append(canon)
            if new_items:
                sanitized[key] = new_items
        else:
            if value not in (None, "", []):
                sanitized[key] = value
    return sanitized

def sanitize_recon_results(recon_results: Dict, target: str) -> Dict:
    """Produce a cleaned version of recon results for human-friendly reporting."""
    trivial_keys = {'target', 'port', 'protocol', 'note', 'port_protocol', 'svc_name', 'risk_level'}
    cleaned: Dict = {}
    for service, data in recon_results.items():
        pruned = _sanitize_dict_for_report(data, target)
        # Determine if there is anything meaningful beyond trivial keys
        meaningful_keys = [k for k in pruned.keys() if k not in trivial_keys]
        if not meaningful_keys:
            # Skip sections that only state "No footprint module available"
            continue
        cleaned[service] = pruned
    return cleaned

def _summarize_params(params: List[str], max_items: int = 3) -> str:
    try:
        if not isinstance(params, list):
            return "-"
        shown = params[:max_items]
        more = len(params) - len(shown)
        return ", ".join(str(x) for x in shown) + (f" (+{more})" if more > 0 else "")
    except Exception:
        return "-"

def collect_vuln_assessment(target: str) -> Dict:
    """Collect Vulnerability Assessment outputs if present (Burp + Nessus)."""
    out: Dict[str, Dict] = {"burp": {}, "nessus": {}, "combined": {}}
    safe = _safe_name(target)
    try:
        # Burp (prefer sanitized, then unsanitized)
        burp_issues: List[Dict] = []
        burp_obj: Dict = {}
        # Metadata and combined JSON
        for cand in [
            OUTPUT_DIR / f"{safe}_http_burp_metadata.json",
            OUTPUT_DIR / f"{target}_http_burp_metadata.json",
            OUTPUT_DIR / f"{safe}_vuln_burp.json",
            OUTPUT_DIR / f"{target}_vuln_burp.json",
            OUTPUT_DIR / f"{target}_burp_issues.json",
        ]:
            try:
                if cand.exists():
                    data = json.loads(cand.read_text(encoding='utf-8'))
                    if isinstance(data, dict):
                        if data.get("issues") and isinstance(data["issues"], list):
                            burp_issues.extend(data["issues"])  # normalized already
                        # keep last seen object for metadata
                        burp_obj = {**burp_obj, **data}
                    elif isinstance(data, list):
                        burp_issues.extend(data)
            except Exception:
                pass
        # NDJSON streaming file
        nd = OUTPUT_DIR / f"{safe}_burp.ndjson"
        if nd.exists():
            try:
                for line in nd.read_text(encoding='utf-8').splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        if isinstance(rec, dict):
                            burp_issues.append(rec)
                    except Exception:
                        continue
            except Exception:
                pass
        # Per-issue JSON directory
        per_dir = OUTPUT_DIR / f"{safe}_burp_issues"
        if per_dir.exists() and per_dir.is_dir():
            for jf in per_dir.glob("*.json"):
                try:
                    rec = json.loads(jf.read_text(encoding='utf-8'))
                    if isinstance(rec, dict):
                        burp_issues.append(rec)
                except Exception:
                    continue
        # De-duplicate issues
        seen = set()
        deduped: List[Dict] = []
        for it in burp_issues:
            if not isinstance(it, dict):
                continue
            key = (
                str(it.get("name", "")).strip(),
                str(it.get("url") or it.get("path") or "").strip(),
                str(it.get("severity", "Info")).title(),
                str(it.get("evidence", ""))[:120],
            )
            if key in seen:
                continue
            seen.add(key)
            # Normalize minimal fields for table
            it["severity"] = str(it.get("severity", "Info")).title()
            it["name"] = it.get("name") or it.get("issueName") or "Unknown"
            it["url"] = it.get("url") or it.get("path") or ""
            it["confidence"] = str(it.get("confidence") or it.get("issueConfidence") or "").title()
            deduped.append(it)
        if deduped:
            burp_obj["issues"] = deduped
            # Recompute summary
            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for i in deduped:
                s = str(i.get("severity", "Info")).title()
                if s not in sev_counts:
                    s = "Info"
                sev_counts[s] += 1
            burp_obj["summary"] = sev_counts
        if burp_obj:
            out["burp"] = burp_obj
    except Exception:
        pass
    try:
        # Nessus
        n = OUTPUT_DIR / f"{target}_nessus_results.json"
        if n.exists():
            out["nessus"] = json.loads(n.read_text(encoding='utf-8'))
    except Exception:
        pass
    try:
        nx = OUTPUT_DIR / f"{target}_nuclei.json"
        if nx.exists():
            out["nuclei"] = json.loads(nx.read_text(encoding='utf-8'))
    except Exception:
        pass
    try:
        sx = OUTPUT_DIR / f"{target}_sslyze.json"
        if sx.exists():
            out["sslyze"] = json.loads(sx.read_text(encoding='utf-8'))
    except Exception:
        pass
    try:
        sh = OUTPUT_DIR / f"{target}_ssh_audit.json"
        if sh.exists():
            out["ssh_audit"] = json.loads(sh.read_text(encoding='utf-8'))
    except Exception:
        pass
    try:
        nv = OUTPUT_DIR / f"{target}_nmap_vuln.json"
        if nv.exists():
            out["nmap_vuln"] = json.loads(nv.read_text(encoding='utf-8'))
    except Exception:
        pass
    try:
        sm = OUTPUT_DIR / f"{target}_smb_checks.json"
        if sm.exists():
            out["smb_checks"] = json.loads(sm.read_text(encoding='utf-8'))
    except Exception:
        pass
    try:
        c = OUTPUT_DIR / f"{target}_vulnerability_assessment.json"
        if c.exists():
            out["combined"] = json.loads(c.read_text(encoding='utf-8'))
    except Exception:
        pass
    return out

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

    # Pre-compute VA and sanitized recon for overviews and sections below
    va = collect_vuln_assessment(target)
    recon_clean = sanitize_recon_results(recon_results, target)

    # Services and Scan Overview
    lines.append("## Services & Scan Overview")
    lines.append("")
    # Tools executed overview
    tools_executed = []
    for key in ["burp", "nessus", "nuclei", "sslyze", "ssh_audit", "nmap_vuln", "smb_checks", "combined"]:
        if va.get(key):
            tools_executed.append(key)
    if tools_executed:
        lines.append(f"- **Tools Executed**: {', '.join(t.replace('_',' ').title() for t in tools_executed)}")
        lines.append("")
    # Services table
    lines.append("| Service | Ports | Recon | Exploit | Post-Exploitation |")
    lines.append("|---|---|---|---|---|")
    all_services_overview = set()
    all_services_overview.update(recon_results.keys())
    all_services_overview.update(exploit_results.keys())
    all_services_overview.update(post_exploit_results.keys())
    for service in sorted(all_services_overview):
        data = recon_results.get(service, {})
        ports: List[str] = []
        try:
            if isinstance(data, dict) and data.get("instances") and isinstance(data["instances"], list):
                for inst in data["instances"]:
                    p = inst.get("port")
                    proto = inst.get("protocol")
                    if p and proto:
                        ports.append(f"{p}/{proto}")
            else:
                p = data.get("port")
                proto = data.get("protocol")
                if p and proto:
                    ports.append(f"{p}/{proto}")
        except Exception:
            pass
        ports_str = ", ".join(sorted(set(str(x) for x in ports))) if ports else "-"
        recon_flag = "Yes" if service in recon_clean else "-"
        exp_count = len(exploit_results.get(service, {}).get("successful_exploits", []) or [])
        exploit_flag = f"Yes ({exp_count})" if exp_count > 0 else "-"
        post_count = len(post_exploit_results.get(service, {}).get("post_exploitation_results", []) or [])
        post_flag = f"Yes ({post_count})" if post_count > 0 else "-"
        service_name = service_mapping.get(service, service.upper())
        lines.append(f"| {service_name} | {ports_str} | {recon_flag} | {exploit_flag} | {post_flag} |")
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
    
    # Vulnerability Assessment Section (Burp + Nessus consolidated)
    if va.get("burp") or va.get("nessus"):
        lines.append("## Vulnerability Assessment")
        lines.append("")
        # Burp summary
        if va.get("burp"):
            burp = va["burp"]
            issues = burp.get("issues") or []
            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for issue in issues:
                sev = str(issue.get("severity", "Info")).title()
                if sev not in sev_counts:
                    sev = "Info"
                sev_counts[sev] += 1
            lines.append("### Burp Suite Findings")
            lines.append(f"- **Critical**: {sev_counts['Critical']}  |  **High**: {sev_counts['High']}  |  **Medium**: {sev_counts['Medium']}  |  **Low**: {sev_counts['Low']}  |  **Info**: {sev_counts['Info']}")
            lines.append("")
            if issues:
                lines.append("| Severity | Name | URL | Confidence |")
                lines.append("|---|---|---|---|")
                for issue in issues[:10]:
                    lines.append(f"| {str(issue.get('severity','Info')).title()} | {issue.get('name','')} | {issue.get('url','')} | {str(issue.get('confidence','')).title()} |")
                lines.append("")
        # Nessus summary
        if va.get("nessus"):
            ness = va["nessus"]
            sev = ness.get("summary") or {}
            lines.append("### Nessus Findings")
            lines.append(f"- **Critical**: {sev.get('Critical',0)}  |  **High**: {sev.get('High',0)}  |  **Medium**: {sev.get('Medium',0)}  |  **Low**: {sev.get('Low',0)}  |  **Info**: {sev.get('Info',0)}")
            findings = ness.get("findings") or []
            if findings:
                lines.append("| Severity | Name | Count |")
                lines.append("|---|---|---|")
                for f in findings[:10]:
                    lines.append(f"| {f.get('severity','Info')} | {f.get('name','Issue')} | {f.get('count',1)} |")
                lines.append("")
        # Nuclei summary
        if va.get("nuclei"):
            nl = va["nuclei"]
            sev = nl.get("summary") or {}
            lines.append("### Nuclei Findings")
            lines.append(f"- **Critical**: {sev.get('Critical',0)}  |  **High**: {sev.get('High',0)}  |  **Medium**: {sev.get('Medium',0)}  |  **Low**: {sev.get('Low',0)}  |  **Info**: {sev.get('Info',0)}")
            lines.append("")
        # SSLyze summary
        if va.get("sslyze"):
            sl = va["sslyze"]
            lines.append("### TLS/SSL Checks (SSLyze)")
            lines.append(f"- Findings (approx): {sl.get('summary',{}).get('findings',0)}")
            lines.append("")
        # SSH Audit summary
        if va.get("ssh_audit"):
            sa = va["ssh_audit"]
            lines.append("### SSH Audit")
            lines.append(f"- Recommendations: {sa.get('summary',{}).get('recommendations',0)}")
            lines.append("")
        # Nmap vulners/vuln summary
        if va.get("nmap_vuln"):
            nv = va["nmap_vuln"]
            lines.append("### Nmap Vuln/Vulners")
            lines.append(f"- CVE references found: {nv.get('cve_count',0)}")
            lines.append("")
        # SMB checks summary
        if va.get("smb_checks"):
            sm = va["smb_checks"]
            lines.append("### SMB Quick Checks")
            lines.append(f"- Vulnerable script hits: {sm.get('vuln_hits',0)}")
            lines.append("")

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
    lines.append("## Reconnaissance")
    lines.append("")
    
    # Sanitize recon for human-friendly output
    recon_clean = sanitize_recon_results(recon_results, target)
    for service, data in recon_clean.items():
        service_name = service_mapping.get(service, f"{service.upper()}")
        lines.append(f"### {service_name}") 
        
        if not data:
            lines.append("- No detailed reconnaissance data found.")
            lines.append("")
            continue
        
        # Pretty summary block for common keys
        target_val = data.get("target", target)
        port_val = data.get("port") or (data.get("port_protocol") if isinstance(data.get("port_protocol"), str) else None)
        os_f = data.get("os_fingerprint") or data.get("os fingerprint")
        http_banner = data.get("http_banner")
        https_banner = data.get("https_banner")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        lines.append(f"| Target | {target_val} |")
        if port_val:
            lines.append(f"| Port | {port_val} |")
        if os_f:
            lines.append(f"| OS Fingerprint | {os_f} |")
        if http_banner:
            lines.append(f"| HTTP Banner | {http_banner} |")
        if https_banner:
            lines.append(f"| HTTPS Banner | {https_banner} |")
        # Quick counts for endpoints
        endpoints = data.get("discovered_endpoints", [])
        vulns = data.get("vulnerable_endpoints", {})
        if endpoints:
            lines.append(f"| Discovered Endpoints | {len(endpoints)} |")
        if isinstance(vulns, dict) and vulns:
            lines.append(f"| Vulnerable Endpoint Categories | {', '.join(sorted(vulns.keys()))} |")
        lines.append("")

        # Condensed endpoints table
        if endpoints:
            lines.append("#### Discovered Endpoints (top 25)")
            lines.append("| URL | Type | Params |")
            lines.append("|---|---|---|")
            for ep in endpoints[:25]:
                url = ep.get("url", "-")
                etype = ep.get("type", "-")
                params = _summarize_params(ep.get("parameters", []))
                lines.append(f"| {url} | {etype} | {params} |")
            if len(endpoints) > 25:
                lines.append(f"... and {len(endpoints) - 25} more endpoints")
            lines.append("")

        # Vulnerable endpoints table
        if isinstance(vulns, dict) and vulns:
            lines.append("#### Vulnerable Endpoints")
            lines.append("| Type | URL | Parameter | Evidence |")
            lines.append("|---|---|---|---|")
            shown = 0
            for vtype, items in vulns.items():
                for item in items:
                    if shown >= 20:
                        break
                    lines.append(f"| {vtype.replace('_',' ').title()} | {item.get('url','-')} | {item.get('parameter','-')} | {item.get('evidence','-')} |")
                    shown += 1
                if shown >= 20:
                    break
            if shown >= 20:
                lines.append("... more vulnerable endpoints omitted for brevity")
            lines.append("")

        # Any remaining fields (light fallback)
        remaining_keys = {k for k in data.keys() if k not in {"target","port","port_protocol","os_fingerprint","http_banner","https_banner","discovered_endpoints","vulnerable_endpoints"}}
        if remaining_keys:
            subset = {k: data[k] for k in sorted(remaining_keys)}
            lines.extend(format_json_to_markdown(subset))
        
        lines.append("")
    # Exploitation
    lines.append("## Exploitation")
    lines.append("")
    if exploit_results:
        for service in sorted(exploit_results.keys()):
            data = exploit_results.get(service, {})
            successes = data.get("successful_exploits", [])
            if not successes:
                continue
            service_name = service_mapping.get(service, f"{service.upper()}")
            lines.append(f"### {service_name}")
            lines.append("")
            for exp in successes:
                if isinstance(exp, dict):
                    lines.append(f"- Type: {exp.get('type','N/A')}")
                    if exp.get('details'):
                        lines.append(f"  - Details: {exp.get('details')}")
                    if exp.get('poc'):
                        lines.append("  - PoC:")
                        lines.append("    ")
                        lines.append("    ```bash")
                        lines.append(str(exp.get('poc')))
                        lines.append("    ```")
            lines.append("")

    # Post-Exploitation
    lines.append("## Post-Exploitation")
    lines.append("")
    if post_exploit_results:
        for service in sorted(post_exploit_results.keys()):
            post = post_exploit_results.get(service, {})
            posts = post.get("post_exploitation_results", [])
            if not posts:
                continue
            service_name = service_mapping.get(service, f"{service.upper()}")
            lines.append(f"### {service_name}")
            lines.append("")
            for pe in posts:
                if isinstance(pe, dict):
                    lines.append(f"- Type: {pe.get('type','N/A')}")
                    if pe.get('details'):
                        lines.append(f"  - Details: {pe.get('details')}")
                    if pe.get('poc'):
                        lines.append("  - PoC:")
                        lines.append("    ")
                        lines.append("    ```bash")
                        lines.append(str(pe.get('poc')))
                        lines.append("    ```")
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