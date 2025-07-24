import argparse
import os

from core import recon, vulnscan, enum_tools          # <── NEW name here
from core import report
from cli.style import print_info, print_success, print_error

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


def main():
    parser = argparse.ArgumentParser(description="Offensive Security Automation Toolkit")
    parser.add_argument("--target", required=True, help="IP or domain")
    parser.add_argument("--recon",  action="store_true", help="Run reconnaissance")
    parser.add_argument("--vuln",   action="store_true", help="Run vulnerability scan")
    parser.add_argument("--enum",   action="store_true", help="Run enumeration")
    parser.add_argument("--report", action="store_true", help="Generate report")
    parser.add_argument("--full",   action="store_true", help="Run all steps")
    args = parser.parse_args()

    t = args.target

    if args.full or args.recon:
        print_info("Starting reconnaissance …")
        try:
            recon.run_nmap_sV(t)                           # or recon.run_nmap()
            print_success("Reconnaissance finished.")
        except Exception as e:
            print_error(e)

    if args.full or args.vuln:
        print_info("Starting vulnerability scan …")
        try:
            vulnscan.run_nikto(t)
            print_success("Vulnerability scan finished.")
        except Exception as e:
            print_error(e)

    if args.full or args.enum:
        print_info("Starting enumeration …")
        try:
            enum_tools.run_enum4linux(t)                   # <── UPDATED call
            print_success("Enumeration finished.")
        except Exception as e:
            print_error(e)

    if args.full or args.report:
        print_info("Generating report …")
        try:
            report.generate_report(t, load_results(t), output_dir=OUTPUT_DIR)
            print_success("Report generated.")
        except Exception as e:
            print_error(e)


if __name__ == "__main__":
    main()
