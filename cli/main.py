#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import subprocess
import re
import socket
from pathlib import Path
from typing import List, Optional

from core import recon, enum_tools, exploit, post_exploit, report_generator
from core.vuln_assessment import run_vulnerability_assessment
from cli.style import print_info, print_success, print_error, print_warning, print_separator, print_phase

OUTPUT_DIR = "outputs"


def load_results(target):
    """Collect previously saved *.txt results for this target."""
    results = {}
    if not os.path.exists(OUTPUT_DIR):
        return results

    for name in os.listdir(OUTPUT_DIR):
        if name.startswith(target) and name.endswith(".txt"):
            tool = name.split("_")[1].replace(".txt", "")
            with open(os.path.join(OUTPUT_DIR, name)) as fh:
                results[tool] = fh.read()
    return results


def validate_target(target: str) -> bool:
    """Validate target format (IP or domain)."""
    import re
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    if re.match(ip_pattern, target) or re.match(domain_pattern, target):
        return True
    return False


def get_available_services() -> List[str]:
    """Get list of available services for exploitation."""
    return [
        "http", "ftp", "ssh", "smtp", "mysql", "smb", "telnet", "dns", "vnc",
        "snmp", "postgresql", "ajp", "java-rmi", "rpc", "irc", "netbios", 
        "nfs", "mssql", "tns", "bindshell"
    ]


def get_python_executable() -> str:
    """Gets the correct Python executable, prioritizing the virtual environment."""
    # Check if we are in a virtual environment
    venv_python = Path(".venv/bin/python3")
    if venv_python.exists():
        return str(venv_python.absolute())
    # Fallback to the system python
    return "/usr/bin/python3"


def detect_attacker_ip(target: Optional[str] = None) -> Optional[str]:
    """Best-effort local IPv4 detection for reverse shells.

    Priority:
    1) UDP socket trick toward resolved target (or 8.8.8.8)
    2) ip route get <resolved_target> → src <ip>
    3) ip -4 addr show scope global
    4) ifconfig parsing
    """
    # Resolve target to IPv4 if it's a hostname
    resolved: Optional[str] = None
    if target:
        try:
            # Avoid resolving if already IPv4
            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", target):
                resolved = target
            else:
                resolved = socket.gethostbyname(target)
        except Exception:
            resolved = None

    # 1) Socket-based discovery (no packets actually sent)
    try:
        probe_target = resolved or "8.8.8.8"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((probe_target, 53))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass

    # 2) Use routing decision toward the resolved target if provided
    if resolved:
        try:
            proc = subprocess.run(["ip", "route", "get", resolved], capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                m = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b", proc.stdout)
                if m:
                    return m.group(1)
        except Exception:
            pass

    # 3) Global v4 addresses via `ip`
    try:
        proc = subprocess.run(["ip", "-4", "addr", "show", "scope", "global"], capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            ips = re.findall(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", proc.stdout)
            for ip in ips:
                if not ip.startswith("127."):
                    return ip
    except Exception:
        pass

    # 4) Fallback to ifconfig parsing
    try:
        proc = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            ips = re.findall(r"\binet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)", proc.stdout)
            for ip in ips:
                if not ip.startswith("127."):
                    return ip
    except Exception:
        pass
    return None


def run_reconnaissance(target: str, services: Optional[List[str]] = None) -> bool:
    """Run reconnaissance phase."""
    print_info("Starting reconnaissance phase...")
    # Machine-readable phase marker for GUI to track
    print("[PHASE] recon: Reconnaissance", flush=True)
    try:
        # Run full reconnaissance with optional service filtering
        recon.run_recon(target, services)
        print_success("Reconnaissance completed successfully!")
        return True
    except Exception as e:
        print_error(f"Reconnaissance failed: {e}")
        return False


def run_exploitation(target: str, attacker_ip: str, attacker_port: str = "4444", 
                    services: Optional[List[str]] = None, use_rockyou: bool = False) -> bool:
    """Run exploitation phase."""
    print_info("Starting exploitation phase...")
    print("[PHASE] exploit: Exploitation", flush=True)
    try:
        # Run exploitation using subprocess to handle command-line arguments properly
        cmd = ["python3", "-m", "core.exploit", target, "--attacker-ip", attacker_ip, "--attacker-port", attacker_port]
        if use_rockyou:
            cmd.append("--use-rockyou")
        if "--no-confirm" in sys.argv:
            cmd.append("--no-confirm")
        if services:
            cmd.extend(["--services", ",".join(services)])

        result = subprocess.run(cmd, text=True, timeout=None)
        if result.returncode == 0:
            print_success("Exploitation completed successfully!")
            return True
        else:
            print_error("Exploitation failed.")
            return False
    except Exception as e:
        print_error(f"Exploitation failed: {e}")
        return False


def run_post_exploitation(target: str, attacker_ip: str, attacker_port: str, services: Optional[List[str]] = None) -> bool:
    """Run post-exploitation phase."""
    print_info("Starting post-exploitation phase...")
    print("[PHASE] post: Post-Exploitation", flush=True)
    try:
        # Run post-exploitation using subprocess to handle command-line arguments properly
        cmd = ["python3", "-m", "core.post_exploit", target, "--attacker-ip", attacker_ip, "--attacker-port", attacker_port]
        if "--no-confirm" in sys.argv:
            cmd.append("--no-confirm")
        if services:
            cmd.extend(["--services", ",".join(services)])
        
        result = subprocess.run(cmd, text=True, timeout=None)
        if result.returncode == 0:
            print_success("Post-exploitation completed successfully!")
            return True
        else:
            print_error("Post-exploitation failed.")
            return False
    except Exception as e:
        print_error(f"Post-exploitation failed: {e}")
        return False


def generate_comprehensive_report(target: str) -> bool:
    """Generate comprehensive report."""
    print_info("Generating comprehensive report...")
    print("[PHASE] report: Reporting", flush=True)
    try:
        # Run report generation using subprocess
        cmd = ["python3", "-m", "core.report_generator", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode == 0:
            print_success("Comprehensive report generated successfully!")
            return True
        else:
            print_error("Report generation failed.")
            return False
    except Exception as e:
        print_error(f"Report generation failed: {e}")
        return False


 


def run_evasion(target: str,
                fast: bool = False,
                timeout: Optional[int] = None,
                all_ports: bool = False,
                test_port: Optional[int] = None,
                decoys: Optional[int] = None) -> bool:
    """Run network evasion phase (firewall/IDS bypass tests)."""
    print_info("Starting evasion phase...")
    try:
        cmd = ["python3", "-m", "core.evasion", target]
        if "--no-confirm" in sys.argv:
            cmd.append("--no-confirm")
        if fast:
            cmd.append("--fast")
        if all_ports:
            cmd.append("--all-ports")
        if timeout is not None:
            cmd.extend(["--timeout", str(timeout)])
        if test_port is not None:
            cmd.extend(["--test-port", str(test_port)])
        if decoys is not None:
            cmd.extend(["--decoys", str(decoys)])
        result = subprocess.run(cmd, text=True, timeout=None)
        if result.returncode == 0:
            print_success("Evasion phase completed successfully!")
            return True
        else:
            print_error("Evasion phase failed.")
            return False
    except Exception as e:
        print_error(f"Evasion failed: {e}")
        return False


def run_complete_walkthrough(target: str, attacker_ip: str, attacker_port: str = "4444",
                           services: Optional[List[str]] = None, use_rockyou: bool = False,
                           include_vuln_assess: bool = False) -> bool:
    """Run complete penetration testing workflow with enhanced logging and progress tracking."""
    print_separator()
    print_info("Starting complete penetration testing workflow...")
    print_info(f"Target: {target}")
    print_info(f"Attacker IP: {attacker_ip}")
    print_info(f"Attacker Port: {attacker_port}")
    if services:
        print_info(f"Selected Services: {', '.join(services)}")
    if use_rockyou:
        print_info("Using rockyou.txt for brute force")
    print_separator()
    
    # Phase 1: Reconnaissance
    print_phase("Phase 1/4: Reconnaissance")
    print("[PHASE] recon: Reconnaissance", flush=True)
    print_info("Step 1/5: Starting reconnaissance phase...")
    if not run_reconnaissance(target, services):
        print_error("Reconnaissance phase failed. Stopping workflow.")
        return False
    print_success("Step 1/5: Reconnaissance completed successfully!")
    
    # Optional: Vulnerability Assessment (Burp + Nessus)
    if include_vuln_assess:
        print_phase("Add-on: Vulnerability Assessment")
        print_info("Running Vulnerability Assessment (Burp + Nessus)...")
        try:
            _ = run_vulnerability_assessment(target)
            print_success("Vulnerability Assessment completed!")
        except Exception as e:
            print_warning(f"Vulnerability Assessment failed: {e}")
    
    # Phase 2: Exploitation
    print_phase("Phase 2/4: Exploitation")
    print("[PHASE] exploit: Exploitation", flush=True)
    print_info("Step 2/5: Starting exploitation phase...")
    exploitation_success = run_exploitation(target, attacker_ip, attacker_port, services, use_rockyou)
    if not exploitation_success:
        print_warning("Exploitation phase failed or no vulnerabilities found. Continuing with post-exploitation...")
    else:
        print_success("Step 2/5: Exploitation completed successfully!")
    
    # Phase 3: Post-Exploitation
    print_phase("Phase 3/4: Post-Exploitation")
    print("[PHASE] post: Post-Exploitation", flush=True)
    print_info("Step 3/5: Starting post-exploitation phase...")
    post_exploit_success = run_post_exploitation(target, attacker_ip, attacker_port, services)
    if not post_exploit_success:
        print_warning("Post-exploitation phase failed. Continuing with reporting...")
    else:
        print_success("Step 3/5: Post-exploitation completed successfully!")
    
    # Phase 4: Reporting
    print_phase("Phase 4/4: Reporting")
    print("[PHASE] report: Reporting", flush=True)
    print_info("Step 4/5: Generating comprehensive report...")
    report_success = generate_comprehensive_report(target)
    if not report_success:
        print_warning("Comprehensive report generation failed.")
    else:
        print_success("Step 4/5: Report generation completed successfully!")
    
    print_separator()
    print_success("Complete penetration testing workflow finished!")
    print_info("Check the outputs directory for all generated reports and results.")
    return True


def main():
    # Ensure logs are visible and flushed immediately when run under the server / CLI
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s', force=True)
    logging.getLogger('core.integrations.burp').setLevel(logging.INFO)
    parser = argparse.ArgumentParser(
        description="Offensive Security Automation Toolkit - Complete Penetration Testing Solution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Complete walkthrough with all services
  python3 -m cli.main --target 192.168.1.10 --attacker-ip 192.168.1.16 --walkthrough

  # Complete walkthrough with specific services
  python3 -m cli.main --target 192.168.1.10 --attacker-ip 192.168.1.16 --walkthrough --services http,ssh,ftp

  # Complete walkthrough with RockYou
  python3 -m cli.main --target 192.168.1.10 --attacker-ip 192.168.1.16 --walkthrough --use-rockyou

  # Reconnaissance only
  python3 -m cli.main --target 192.168.1.10 --recon

  # Exploitation only (requires recon output)
  python3 -m cli.main --target 192.168.1.10 --attacker-ip 192.168.1.16 --exploit

  # Post-exploitation only (requires exploit output)
  python3 -m cli.main --target 192.168.1.10 --post-exploit

  # Report generation only
  python3 -m cli.main --target 192.168.1.10 --report

  # Walkthrough generation only
  python3 -m cli.main --target 192.168.1.10 --generate-walkthrough

Available Services: http, ftp, ssh, smtp, mysql, smb, telnet, dns, vnc, snmp, postgresql, ajp, java-rmi, rpc, irc, netbios, nfs, mssql, tns, bindshell
        """
    )
    
    # Target and basic options
    parser.add_argument("--target", required=False, help="Target IP or domain")
    parser.add_argument("--attacker-ip", help="Attacker IP for reverse shells")
    parser.add_argument("--attacker-port", default="4444", help="Attacker port for reverse shells (default: 4444)")
    
    # Workflow options
    parser.add_argument("--walkthrough", action="store_true", 
                       help="Run complete penetration testing walkthrough (recon + exploit + post-exploit + report)")
    parser.add_argument("--recon", action="store_true", help="Run reconnaissance phase only")
    parser.add_argument("--exploit", action="store_true", help="Run exploitation phase only (requires recon output)")
    parser.add_argument("--post-exploit", action="store_true", help="Run post-exploitation phase only (requires exploit output)")
    parser.add_argument("--report", action="store_true", help="Generate comprehensive report (includes walkthrough section)")
    parser.add_argument("--vuln-assess", action="store_true", help="Run Vulnerability Assessment (Burp + Nessus) only")
    parser.add_argument("--with-vuln-assess", action="store_true", help="Run Vulnerability Assessment alongside recon (parallel)")
    parser.add_argument("--evasion", action="store_true", help="Run network evasion tests and generate a dedicated report")
    # Evasion tuning flags
    parser.add_argument("--fast", action="store_true", help="Evasion: skip sudo-heavy/slow steps; use faster timing")
    parser.add_argument("--timeout", type=int, help="Evasion: per-step timeout in seconds")
    parser.add_argument("--all-ports", action="store_true", help="Evasion: scan all TCP ports (-p-) where applicable")
    parser.add_argument("--test-port", type=int, default=50000, help="Evasion: high TCP port for DNS source-port tests (default: 50000)")
    parser.add_argument("--decoys", type=int, default=5, help="Evasion: number of random decoys for -D RND:<n> (default: 5)")
    
    # Service selection
    parser.add_argument("--services", help="Comma-separated list of services to test (e.g., http,ssh,ftp)")
    
    # Advanced options
    parser.add_argument("--use-rockyou", action="store_true", 
                       help="Use rockyou.txt for brute forcing (requires rockyou.txt in current directory)")
    parser.add_argument("--list-services", action="store_true", help="List all available services")
    parser.add_argument("--no-confirm", action="store_true", help="Skip all confirmation prompts")
    
    args = parser.parse_args()

    # Validate target (skip if listing services)
    if args.target and not validate_target(args.target):
        print_error("Invalid target format. Please provide a valid IP address or domain.")
        sys.exit(1)
    
    # List services if requested
    if args.list_services:
        services = get_available_services()
        print_info("Available services:")
        for service in services:
            print(f"  • {service}")
        sys.exit(0)
    
    # Parse services if specified
    selected_services = None
    if args.services:
        selected_services = [s.strip().lower() for s in args.services.split(",")]
        available_services = get_available_services()
        invalid_services = [s for s in selected_services if s not in available_services]
        if invalid_services:
            print_error(f"Invalid services: {', '.join(invalid_services)}")
            print_info(f"Available services: {', '.join(available_services)}")
            sys.exit(1)
    
    # Auto-detect attacker IP if needed and not provided
    needs_attacker_ip = (args.exploit or args.walkthrough or args.post_exploit) and not args.list_services
    if needs_attacker_ip and not args.attacker_ip:
        auto_ip = detect_attacker_ip(args.target)
        if auto_ip:
            print_info(f"Auto-detected attacker IP: {auto_ip} (override with --attacker-ip)")
            args.attacker_ip = auto_ip
    
    # Check for required arguments
    if (args.exploit or args.walkthrough or args.post_exploit) and not args.list_services:
        if not args.target:
            print_error("--target is required for this action")
            sys.exit(1)
        if not args.attacker_ip:
            print_error("Unable to auto-detect attacker IP. Provide --attacker-ip explicitly.")
            sys.exit(1)
    
    # Legal warning (unless --no-confirm is used or listing services)
    if not args.no_confirm and not args.list_services:
        print_warning("LEGAL WARNING: This tool is for authorized penetration testing only!")
        print_warning("Only use against systems you own or have explicit permission to test!")
        confirm = input("Do you have authorization to test this target? (y/n): ")
        if confirm.lower() != "y":
            print_info("Exiting...")
            sys.exit(0)
    
    # Run selected workflow
    success = False
    
    if args.list_services:
        services = get_available_services()
        print_info("Available services:")
        for service in services:
            print(f"  • {service}")
        sys.exit(0)
    elif args.walkthrough:
        success = run_complete_walkthrough(
            args.target, 
            args.attacker_ip, 
            args.attacker_port,
            selected_services,
            args.use_rockyou,
            include_vuln_assess=args.with_vuln_assess
        )
    elif args.recon:
        if args.with_vuln_assess:
            print_info("Running Recon and Vulnerability Assessment in parallel...")
            # Fire recon in a subprocess and vuln assess in current process for simplicity
            py = get_python_executable()
            proc = subprocess.Popen([py, "-m", "core.recon", args.target], text=True)
            try:
                _ = run_vulnerability_assessment(args.target)
            finally:
                proc.wait()
            success = True
        else:
            success = run_reconnaissance(args.target, selected_services)
    elif args.exploit:
        success = run_exploitation(args.target, args.attacker_ip, args.attacker_port, selected_services, args.use_rockyou)
    elif args.post_exploit:
        success = run_post_exploitation(args.target, args.attacker_ip, args.attacker_port, selected_services)
    elif args.evasion:
        success = run_evasion(
            args.target,
            fast=args.fast,
            timeout=args.timeout,
            all_ports=args.all_ports,
            test_port=args.test_port,
            decoys=args.decoys,
        )
    elif args.report:
        success = generate_comprehensive_report(args.target)
    elif hasattr(args, 'generate_walkthrough') and args.generate_walkthrough:
        print_warning("--generate-walkthrough is deprecated; use --report instead. The report now includes the walkthrough.")
        success = generate_comprehensive_report(args.target)
    elif args.vuln_assess:
        _ = run_vulnerability_assessment(args.target)
        success = True
    else:
        print_error("No action specified. Use --help for usage information.")
        sys.exit(1)
    
    if success:
        print_success("Operation completed successfully!")
        sys.exit(0)
    else:
        print_error("Operation failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
