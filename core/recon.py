#!/usr/bin/env python3
import subprocess
import concurrent.futures
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from weasyprint import HTML
import logging
from typing import Dict, Any, List

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# Constants
TEMPLATES_DIR = Path(__file__).parent / "templates"
OUTPUT_DIR = Path("outputs").absolute()
ENV = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))

OUTPUT_DIR.mkdir(exist_ok=True)

# Nmap scan flags
FAST_FLAGS = ["-sV", "-T4", "-Pn"]
FULL_FLAGS = ["-sV", "-p-", "-T4", "-Pn"]
UDP_FLAGS = ["-sU", "-F", "-T4", "-Pn"]

MAIL_SERVICES = {"smtp", "pop3", "imap"}

def get_output_file(target: str, name: str) -> Path:
    return OUTPUT_DIR / f"{target}_{name}.txt"

def run_command(cmd: List[str], output_path: Path):
    logger.info(f"Running command: {' '.join(cmd)}")
    try:
        with open(output_path, "w", encoding='utf-8') as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, text=True, check=True)
        logger.info(f"Saved output to {output_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running command {' '.join(cmd)}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error running command {' '.join(cmd)}: {e}")
    return output_path

def nmap_scan(target: str, flags: List[str], name: str) -> Path:
    output = get_output_file(target, name)
    return run_command(["nmap", *flags, target, "-oN", str(output)], output)

def extract_services(nmap_output: Path) -> List[Tuple[str, int, str]]:
    services = []
    regex = re.compile(r"^(\d+)/(tcp|udp)\s+\S+\s+(\S+)")
    try:
        with open(nmap_output, "r", encoding='utf-8') as f:
            for line in f.read().splitlines():
                match = regex.match(line.strip())
                if match:
                    port, proto, service = match.groups()
                    services.append((service.lower(), int(port), proto))
        logger.info(f"Extracted {len(services)} services from {nmap_output}")
    except FileNotFoundError:
        logger.error(f"Nmap output file {nmap_output} not found")
    except UnicodeDecodeError as e:
        logger.error(f"Error decoding {nmap_output}: {e}")
    return services

def run_footprint_for_services(target: str, services: List[Tuple[str, int, str]], service_data: Dict, footprinted_services: set):
    for service, port, proto in services:
        # Sanitize service name for filesystem safety (avoid characters like '/')
        safe_service = re.sub(r"[^A-Za-z0-9._-]", "-", service)
        if service in footprinted_services:
            logger.info(f"Skipping footprint for {service} on {port}/{proto}, already processed")
            continue
        footprinted_services.add(service)
        try:
            mod = __import__(f"core.services.{service}", fromlist=["footprint"])
        except ModuleNotFoundError:
            logger.warning(f"No footprint module for service: {service} on {port}/{proto}, including basic info")
            service_data[f"{service}_{port}_{proto}"] = {
                "target": target,
                "port": port,
                "protocol": proto,
                "note": f"No footprint module available for {service}"
            }
            json_path = OUTPUT_DIR / f"{target}_{safe_service}_{port}_{proto}_metadata.json"
            with open(json_path, "w", encoding='utf-8') as f:
                json.dump(service_data[f"{service}_{port}_{proto}"], f, indent=4)
            logger.info(f"Saved basic metadata to {json_path}")
            continue

        if hasattr(mod, "footprint"):
            try:
                logger.info(f"Running footprint for service: {service} on port {port}/{proto}")
                result = mod.footprint(target, port=port) if "port" in mod.footprint.__code__.co_varnames else mod.footprint(target)
                if isinstance(result, dict):
                    service_data[f"{service}_{port}_{proto}"] = result
                    json_path = OUTPUT_DIR / f"{target}_{safe_service}_{port}_{proto}_metadata.json"
                    with open(json_path, "w", encoding='utf-8') as f:
                        json.dump(result, f, indent=4)
                    logger.info(f"Saved service metadata to {json_path}")
                else:
                    logger.warning(f"Module {service} returned non-dict output")
            except UnicodeDecodeError as e:
                logger.error(f"Decoding error in {service}.footprint() on {port}/{proto}: {e}")
                service_data[f"{service}_{port}_{proto}"] = {
                    "target": target,
                    "port": port,
                    "protocol": proto,
                    "error": f"Decoding error: {str(e)}"
                }
                json_path = OUTPUT_DIR / f"{target}_{safe_service}_{port}_{proto}_metadata.json"
                with open(json_path, "w", encoding='utf-8') as f:
                    json.dump(service_data[f"{service}_{port}_{proto}"], f, indent=4)
                logger.info(f"Saved error metadata to {json_path}")
            except Exception as e:
                logger.error(f"Error in {service}.footprint() on {port}/{proto}: {e}")
                service_data[f"{service}_{port}_{proto}"] = {
                    "target": target,
                    "port": port,
                    "protocol": proto,
                    "error": f"Footprint error: {str(e)}"
                }
                json_path = OUTPUT_DIR / f"{target}_{safe_service}_{port}_{proto}_metadata.json"
                with open(json_path, "w", encoding='utf-8') as f:
                    json.dump(service_data[f"{service}_{port}_{proto}"], f, indent=4)
                logger.info(f"Saved error metadata to {json_path}")
        else:
            logger.warning(f"Module {service} missing footprint() function")
            service_data[f"{service}_{port}_{proto}"] = {
                "target": target,
                "port": port,
                "protocol": proto,
                "note": f"No footprint function for {service}"
            }
            json_path = OUTPUT_DIR / f"{target}_{safe_service}_{port}_{proto}_metadata.json"
            with open(json_path, "w", encoding='utf-8') as f:
                json.dump(service_data[f"{service}_{port}_{proto}"], f, indent=4)
            logger.info(f"Saved basic metadata to {json_path}")

def clean_ansi_codes(text: str) -> str:
    """Remove ANSI escape codes from text."""
    ansi_pattern = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_pattern.sub('', text)

def validate_metadata(data: Any, svc_key: str = "root") -> Any:
    """Recursively validate and clean metadata, preserving data structures."""
    if isinstance(data, dict):
        return {k: validate_metadata(v, f"{svc_key}.{k}") for k, v in data.items()}
    if isinstance(data, list):
        return [validate_metadata(item, svc_key) for item in data]
    if isinstance(data, str):
        return clean_ansi_codes(data)
    if isinstance(data, (int, float, bool)) or data is None:
        return data
    
    logger.warning(f"Unexpected data type for {svc_key}: {type(data)}. Converting to string.")
    return str(data)

def aggregate_json_results(target: str) -> Dict[str, Any]:
    """Aggregate all JSON results into a comprehensive report."""
    combined = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "services": {},
        "tcp_fast_scan": "No TCP fast scan data available",
        "tcp_full_scan": "No TCP full scan data available", 
        "udp_fast_scan": "No UDP fast scan data available",
        "scan_summary": {
            "total_services": 0,
            "open_ports": 0,
            "vulnerable_services": 0,
            "high_risk_services": 0,
            "medium_risk_services": 0,
            "low_risk_services": 0
        }
    }
    
    # Load scan files
    tcp_fast_path = OUTPUT_DIR / f"{target}_tcp_fast.txt"
    tcp_full_path = OUTPUT_DIR / f"{target}_tcp_full.txt"
    udp_fast_path = OUTPUT_DIR / f"{target}_udp_fast.txt"
    
    if tcp_fast_path.exists():
        try:
            with open(tcp_fast_path, "r", encoding='utf-8') as f:
                combined["tcp_fast_scan"] = f.read()
        except Exception as e:
            logger.error(f"Error reading TCP fast scan: {e}")
    
    if tcp_full_path.exists():
        try:
            with open(tcp_full_path, "r", encoding='utf-8') as f:
                combined["tcp_full_scan"] = f.read()
        except Exception as e:
            logger.error(f"Error reading TCP full scan: {e}")
    
    if udp_fast_path.exists():
        try:
            with open(udp_fast_path, "r", encoding='utf-8') as f:
                combined["udp_fast_scan"] = f.read()
        except Exception as e:
            logger.error(f"Error reading UDP fast scan: {e}")
    
    # Create scans JSON for detailed analysis
    scans_json = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "scans": {
            "tcp_fast": {
                "file": str(tcp_fast_path),
                "exists": tcp_fast_path.exists(),
                "size": tcp_fast_path.stat().st_size if tcp_fast_path.exists() else 0
            },
            "tcp_full": {
                "file": str(tcp_full_path),
                "exists": tcp_full_path.exists(),
                "size": tcp_full_path.stat().st_size if tcp_full_path.exists() else 0
            },
            "udp_fast": {
                "file": str(udp_fast_path),
                "exists": udp_fast_path.exists(),
                "size": udp_fast_path.stat().st_size if udp_fast_path.exists() else 0
            }
        }
    }
    
    scans_json_path = OUTPUT_DIR / f"{target}_scans.json"
    try:
        with open(scans_json_path, "w", encoding='utf-8') as f:
            json.dump(scans_json, f, indent=4)
        logger.info(f"Saved scan results JSON to {scans_json_path}")
    except Exception as e:
        logger.error(f"Error saving scans JSON {scans_json_path}: {e}")

    # Aggregate service footprints
    metadata_files = list(OUTPUT_DIR.glob(f"{target}_*_*_metadata.json"))
    logger.info(f"Found {len(metadata_files)} metadata files for {target}: {', '.join([f.name for f in metadata_files]) or 'none'}")
    
    consolidated_services: Dict[str, List] = {}
    risk_services = {
        "high": [],
        "medium": [],
        "low": []
    }
    
    for jf in metadata_files:
        try:
            with open(jf, "r", encoding='utf-8') as f:
                data = json.load(f)
            
            # This part of the filename parsing is brittle. Let's make it more robust.
            # Example: 192.168.1.21_http_80_tcp_metadata.json -> http
            # Example: 192.168.1.21_21_ftp_metadata.json -> ftp
            # Example: 192.168.1.21_netbios-ssn_445_tcp_metadata.json -> netbios-ssn
            parts = jf.name.replace(f"{target}_", "").replace("_metadata.json", "").split("_")
            
            svc_name_parts = []
            port_proto_parts = []
            found_port = False
            for part in parts:
                if part.isdigit() and not found_port:
                    found_port = True
                    port_proto_parts.append(part)
                elif found_port:
                    port_proto_parts.append(part)
                else:
                    svc_name_parts.append(part)
            
            svc_name = "-".join(svc_name_parts)
            if not svc_name: # Handle cases like '21_ftp' where the name is after the port
                svc_name = port_proto_parts.pop(0) if port_proto_parts else 'unknown'

            port_proto = "_".join(port_proto_parts)
            svc_key = f"{svc_name}_{port_proto}"

            data["port_protocol"] = port_proto.replace("_", "/")
            data["svc_name"] = svc_name.title()
            
            # Validate and clean metadata
            data = validate_metadata(data)
            
            if not data.get("port"):
                data["port"] = port_proto.split("_")[0] if "_" in port_proto else "N/A"
                logger.warning(f"Port missing for {svc_key}. Using {data['port']}")
            
            # Assess risk level
            risk_level = assess_service_risk(svc_name, data)
            data["risk_level"] = risk_level
            risk_services[risk_level].append(svc_name)
            
            if svc_name not in consolidated_services:
                consolidated_services[svc_name] = []
            consolidated_services[svc_name].append((svc_key, data))
            logger.info(f"Loaded service metadata {jf}: {svc_key} (Risk: {risk_level})")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON {jf}: {e}")
            combined["services"][svc_key] = {
                "error": f"Failed to parse metadata JSON: {str(e)}",
                "svc_name": svc_name.title(),
                "port_protocol": port_proto.replace("_", "/"),
                "port": port_proto.split("_")[0] if "_" in port_proto else "N/A",
                "risk_level": "unknown"
            }
        except Exception as e:
            logger.error(f"Error loading JSON {jf}: {e}")
            combined["services"][svc_key] = {
                "error": f"Failed to load metadata: {str(e)}",
                "svc_name": svc_name.title(),
                "port_protocol": port_proto.replace("_", "/"),
                "port": port_proto.split("_")[0] if "_" in port_proto else "N/A",
                "risk_level": "unknown"
            }
    
    # Consolidate services
    for svc_name, instances in consolidated_services.items():
        if len(instances) == 1:
            combined["services"][instances[0][0]] = instances[0][1]
        else:
            consolidated = {
                "svc_name": svc_name.title(),
                "port_protocol": "Multiple",
                "instances": [data for _, data in instances],
                "risk_level": instances[0][1].get("risk_level", "unknown")
            }
            combined["services"][svc_name] = consolidated
            logger.info(f"Consolidated {len(instances)} instances for service {svc_name}")
    
    # Update scan summary
    combined["scan_summary"] = {
        "total_services": len(combined["services"]),
        "open_ports": len([s for s in combined["services"].values() if s.get("port_protocol")]),
        "vulnerable_services": len([s for s in combined["services"].values() if s.get("exploitdb_cves") or s.get("msf_cves")]),
        "high_risk_services": len(risk_services["high"]),
        "medium_risk_services": len(risk_services["medium"]),
        "low_risk_services": len(risk_services["low"]),
        "risk_breakdown": risk_services
    }
    
    # Log combined JSON for debugging
    json_path = OUTPUT_DIR / f"{target}_combined_report.json"
    try:
        with open(json_path, "w", encoding='utf-8') as f:
            json.dump(combined, f, indent=4)
        logger.info(f"Saved combined JSON report to {json_path}")
        # Log summary of services
        logger.info(f"Combined JSON contains {len(combined['services'])} services: {', '.join(combined['services'].keys())}")
        logger.info(f"Risk breakdown - High: {len(risk_services['high'])}, Medium: {len(risk_services['medium'])}, Low: {len(risk_services['low'])}")
    except Exception as e:
        logger.error(f"Error saving combined JSON {json_path}: {e}")

    return combined

def assess_service_risk(service_name: str, data: Dict) -> str:
    """Assess the risk level of a service based on its configuration and vulnerabilities."""
    high_risk_services = ["ssh", "ftp", "telnet", "vnc", "rsh", "rlogin", "rexec"]
    medium_risk_services = ["http", "https", "smtp", "pop3", "imap", "dns", "snmp", "ldap"]
    
    # Check for known vulnerabilities
    has_vulnerabilities = bool(data.get("exploitdb_cves") or data.get("msf_cves"))
    
    # Check for default credentials or weak configurations
    has_weak_config = any([
        data.get("default_credentials"),
        data.get("weak_ciphers"),
        data.get("anonymous_access"),
        data.get("guest_access")
    ])
    
    # High risk if:
    # - Service is inherently high risk
    # - Has known vulnerabilities
    # - Has weak configurations
    if (service_name in high_risk_services or 
        has_vulnerabilities or 
        has_weak_config):
        return "high"
    
    # Medium risk if:
    # - Service is medium risk
    # - Has some configuration issues
    elif service_name in medium_risk_services:
        return "medium"
    
    # Low risk for everything else
    else:
        return "low"

def build_combined_report(target: str, combined_results: Dict):
    try:
        logger.info("Loading Jinja2 template for PDF generation")
        template = ENV.get_template("combined_report.html")
        logger.info("Rendering HTML with combined results")
        html_out = template.render(
            target=target,
            combined=combined_results,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        output_path = OUTPUT_DIR / f"{target}_full_report.pdf"
        logger.info(f"Generating PDF at {output_path}")
        HTML(string=html_out).write_pdf(str(output_path))
        logger.info(f"Final PDF report generated at {output_path}")
    except Exception as e:
        logger.error(f"Error generating PDF report: {e}")
        raise  # Re-raise to ensure error is visible in logs

def regenerate_pdf(target: str):
    logger.info(f"Regenerating PDF report for {target} using existing data")
    combined_json = aggregate_json_results(target)
    json_path = OUTPUT_DIR / f"{target}_combined_report.json"
    try:
        with open(json_path, "w", encoding='utf-8') as f:
            json.dump(combined_json, f, indent=4)
        logger.info(f"Combined JSON report updated at {json_path}")
    except Exception as e:
        logger.error(f"Error saving JSON report: {e}")
    build_combined_report(target, combined_json)
    logger.info("PDF regeneration complete")

def run_recon(target: str, selected_services: Optional[List[str]] = None):
    service_data = {}
    footprinted_services = set()  # Track footprinted services
    all_services = set()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        logger.info("Running TCP fast scan...")
        tcp_fast = executor.submit(nmap_scan, target, FAST_FLAGS, "tcp_fast")
        logger.info("Running TCP full scan...")
        tcp_full = executor.submit(nmap_scan, target, FULL_FLAGS, "tcp_full")
        logger.info("Running UDP fast scan...")
        udp_fast = executor.submit(nmap_scan, target, UDP_FLAGS, "udp_fast")

        tcp_fast_out = tcp_fast.result()
        services_tcp_fast = extract_services(tcp_fast_out)
        logger.info(f"TCP Fast found: {', '.join(f'{s} on {p}/{t}' for s, p, t in services_tcp_fast) or 'none'}")
        all_services.update(services_tcp_fast)

        tcp_full_out = tcp_full.result()
        services_tcp_full = [(s, p, t) for s, p, t in extract_services(tcp_full_out) if (s, p, t) not in all_services]
        logger.info(f"TCP Full found: {', '.join(f'{s} on {p}/{t}' for s, p, t in services_tcp_full) or 'none'}")
        all_services.update(services_tcp_full)

        udp_fast_out = udp_fast.result()
        services_udp_fast = [(s, p, t) for s, p, t in extract_services(udp_fast_out) if (s, p, t) not in all_services]
        logger.info(f"UDP Fast found: {', '.join(f'{s} on {p}/{t}' for s, p, t in services_udp_fast) or 'none'}")
        all_services.update(services_udp_fast)

        # Filter services if specific services are requested
        if selected_services:
            logger.info(f"Filtering services to: {', '.join(selected_services)}")
            filtered_services = []
            for service, port, proto in all_services:
                # Map netbios-ssn to smb
                if service.lower() == 'netbios-ssn' and 'smb' in [s.lower() for s in selected_services]:
                    filtered_services.append(('smb', port, proto))
                    logger.info(f"Including netbios-ssn as smb on {port}/{proto} (requested)")
                elif service.lower() in [s.lower() for s in selected_services]:
                    filtered_services.append((service, port, proto))
                    logger.info(f"Including {service} on {port}/{proto} (requested)")
                else:
                    logger.info(f"Skipping {service} on {port}/{proto} (not requested)")
            all_services = filtered_services
            logger.info(f"Filtered to {len(all_services)} services: {', '.join(f'{s} on {p}/{t}' for s, p, t in all_services)}")

        run_footprint_for_services(target, all_services, service_data, footprinted_services)

    # Mail service detection
    if any(s[0] in MAIL_SERVICES for s in all_services):
        try:
            if "mail" not in footprinted_services:
                mail_mod = __import__("core.services.mail_footprint", fromlist=["footprint"])
                if hasattr(mail_mod, "footprint"):
                    logger.info("Running mail_footprint for mail protocols")
                    mail_result = mail_mod.footprint(target)
                    if isinstance(mail_result, dict):
                        service_data["mail"] = mail_result
                        json_path = OUTPUT_DIR / f"{target}_mail_metadata.json"
                        with open(json_path, "w", encoding='utf-8') as f:
                            json.dump(mail_result, f, indent=4)
                        logger.info(f"Saved mail metadata to {json_path}")
                    footprinted_services.add("mail")
        except Exception as e:
            logger.error(f"Error in mail_footprint: {e}")

    # Aggregate and save results
    combined_json = aggregate_json_results(target)
    json_path = OUTPUT_DIR / f"{target}_combined_report.json"
    try:
        with open(json_path, "w", encoding='utf-8') as f:
            json.dump(combined_json, f, indent=4)
        logger.info(f"Combined JSON report saved at {json_path}")
    except Exception as e:
        logger.error(f"Error saving JSON report: {e}")

    # Create PDF report
    build_combined_report(target, combined_json)
    logger.info("Recon complete")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Advanced Auto-Recon with Footprinting")
    parser.add_argument("target", help="IP or domain to scan")
    parser.add_argument("--regenerate-pdf", action="store_true", help="Regenerate PDF report using existing data")
    args = parser.parse_args()

    if args.regenerate_pdf:
        regenerate_pdf(args.target)
    else:
        run_recon(args.target)