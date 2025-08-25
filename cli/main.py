#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import subprocess
from pathlib import Path
from typing import List, Optional

from core import recon, enum_tools, exploit, post_exploit, report_generator, walkthrough_generator
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


def run_reconnaissance(target: str, services: Optional[List[str]] = None) -> bool:
    """Run reconnaissance phase."""
    print_info("Starting reconnaissance phase...")
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
    try:
        # Run exploitation using subprocess to handle command-line arguments properly
        cmd = ["python3", "-m", "core.exploit", target, "--attacker-ip", attacker_ip, "--attacker-port", attacker_port]
        if use_rockyou:
            cmd.append("--use-rockyou")
        if "--no-confirm" in sys.argv:
            cmd.append("--no-confirm")
        if services:
            cmd.extend(["--services", ",".join(services)])
        
        # Add a space before the next command if necessary
        if cmd[-1] == "--no-confirm":
            cmd.append(" ")

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


def generate_walkthrough(target: str) -> bool:
    """Generate comprehensive walkthrough."""
    print_info("Generating comprehensive walkthrough...")
    try:
        # Run walkthrough generation using subprocess
        cmd = ["python3", "-m", "core.walkthrough_generator", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode == 0:
            print_success("Comprehensive walkthrough generated successfully!")
            return True
        else:
            print_error("Walkthrough generation failed.")
            return False
    except Exception as e:
        print_error(f"Walkthrough generation failed: {e}")
        return False


def run_complete_walkthrough(target: str, attacker_ip: str, attacker_port: str = "4444",
                           services: Optional[List[str]] = None, use_rockyou: bool = False) -> bool:
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
    print_phase("Phase 1/5: Reconnaissance")
    print_info("Step 1/5: Starting reconnaissance phase...")
    if not run_reconnaissance(target, services):
        print_error("Reconnaissance phase failed. Stopping workflow.")
        return False
    print_success("Step 1/5: Reconnaissance completed successfully!")
    
    # Phase 2: Exploitation
    print_phase("Phase 2/5: Exploitation")
    print_info("Step 2/5: Starting exploitation phase...")
    exploitation_success = run_exploitation(target, attacker_ip, attacker_port, services, use_rockyou)
    if not exploitation_success:
        print_warning("Exploitation phase failed or no vulnerabilities found. Continuing with post-exploitation...")
    else:
        print_success("Step 2/5: Exploitation completed successfully!")
    
    # Phase 3: Post-Exploitation
    print_phase("Phase 3/5: Post-Exploitation")
    print_info("Step 3/5: Starting post-exploitation phase...")
    post_exploit_success = run_post_exploitation(target, attacker_ip, attacker_port, services)
    if not post_exploit_success:
        print_warning("Post-exploitation phase failed. Continuing with reporting...")
    else:
        print_success("Step 3/5: Post-exploitation completed successfully!")
    
    # Phase 4: Reporting
    print_phase("Phase 4/5: Reporting")
    print_info("Step 4/5: Generating comprehensive report...")
    report_success = generate_comprehensive_report(target)
    if not report_success:
        print_warning("Comprehensive report generation failed.")
    else:
        print_success("Step 4/5: Report generation completed successfully!")
    
    # Phase 5: Walkthrough
    print_phase("Phase 5/5: Walkthrough")
    print_info("Step 5/5: Generating comprehensive walkthrough...")
    walkthrough_success = generate_walkthrough(target)
    if not walkthrough_success:
        print_warning("Walkthrough generation failed.")
    else:
        print_success("Step 5/5: Walkthrough generation completed successfully!")
    
    print_separator()
    print_success("Complete penetration testing workflow finished!")
    print_info("Check the outputs directory for all generated reports and results.")
    return True


def main():
    # Ensure logs are visible and flushed immediately when run under the server
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
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
    parser.add_argument("--report", action="store_true", help="Generate comprehensive report only")
    parser.add_argument("--generate-walkthrough", action="store_true", help="Generate comprehensive walkthrough only")
    
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
    
    # Check for required arguments
    if (args.exploit or args.walkthrough) and not args.list_services:
        if not args.target:
            print_error("--target is required for exploitation")
            sys.exit(1)
        if not args.attacker_ip:
            print_error("--attacker-ip is required for exploitation")
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
            args.use_rockyou
        )
    elif args.recon:
        success = run_reconnaissance(args.target, selected_services)
    elif args.exploit:
        success = run_exploitation(args.target, args.attacker_ip, args.attacker_port, selected_services, args.use_rockyou)
    elif args.post_exploit:
        success = run_post_exploitation(args.target, args.attacker_ip, args.attacker_port, selected_services)
    elif args.report:
        success = generate_comprehensive_report(args.target)
    elif args.generate_walkthrough:
        success = generate_walkthrough(args.target)
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
