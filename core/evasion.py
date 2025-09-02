#!/usr/bin/env python3
import argparse
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.config import config

logger = logging.getLogger(__name__)


OUTPUT_DIR = Path(config.get("general.output_directory", "outputs")).absolute()
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

REPORT_JSON = "{target}_evasion_report.json"
REPORT_MD = "{target}_evasion_report.md"
REPORT_PDF = "{target}_evasion_report.pdf"


def _truncate(text: str, limit: int = 4000) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [truncated] ...\n"


def run_command(cmd: List[str], timeout: Optional[int] = None, env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    try:
        logger.info("Running: %s", " ".join(shlex.quote(c) for c in cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        out = proc.stdout or ""
        err = proc.stderr or ""
        # Normalize types defensively
        if isinstance(out, (bytes, bytearray)):
            try:
                out = out.decode("utf-8", errors="ignore")
            except Exception:
                out = str(out)
        if isinstance(err, (bytes, bytearray)):
            try:
                err = err.decode("utf-8", errors="ignore")
            except Exception:
                err = str(err)
        return proc.returncode, out, err
    except FileNotFoundError as e:
        return 127, "", f"Executable not found: {e}"
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        err = (e.stderr or "")
        if isinstance(out, (bytes, bytearray)):
            try:
                out = out.decode("utf-8", errors="ignore")
            except Exception:
                out = str(out)
        if isinstance(err, (bytes, bytearray)):
            try:
                err = err.decode("utf-8", errors="ignore")
            except Exception:
                err = str(err)
        err = (err or "") + "\n[timeout]"
        return 124, out, err
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"


def has_binary(name: str) -> bool:
    return shutil.which(name) is not None


def parse_nmap_ports(stdout: str) -> Dict[int, str]:
    """Parse Nmap output table into {port: state}. Handles SYN/ACK/FIN variants.
    Example lines: '80/tcp open http', '50000/tcp filtered unknown', '22/tcp closed ssh'.
    """
    import re
    # Ensure text
    if isinstance(stdout, (bytes, bytearray)):
        try:
            stdout = stdout.decode("utf-8", errors="ignore")
        except Exception:
            stdout = str(stdout)
    states: Dict[int, str] = {}
    for line in (stdout or "").splitlines():
        if isinstance(line, (bytes, bytearray)):
            try:
                line = line.decode("utf-8", errors="ignore")
            except Exception:
                line = str(line)
        m = re.match(r"^(\d+)/tcp\s+([^\s]+)\s+", line.strip())
        if m:
            try:
                port = int(m.group(1))
                state = m.group(2).lower()
                states[port] = state
            except Exception:
                continue
    return states


def merge_port_states(existing: Dict[int, Dict[str, str]], new_states: Dict[int, str], source: str) -> None:
    """Accumulate per-port states with provenance."""
    for port, state in new_states.items():
        rec = existing.setdefault(port, {"final": state, "history": []})
        rec["history"].append({"from": source, "state": state})
        # Promote to open if any scan shows open
        if state == "open":
            rec["final"] = "open"
            rec["reason"] = f"Opened according to {source}"
        elif rec.get("final") != "open":
            # Prefer non-ambiguous over ambiguous
            if state in {"filtered", "closed", "unfiltered"}:
                rec["final"] = state
            else:
                # open|filtered or similar ambiguous
                if rec.get("final") in {"", None}:
                    rec["final"] = state


def build_steps(target: str, iface: Optional[str], spoof_ip: Optional[str], all_ports: bool, decoys: int,
                test_port: int, fast: bool) -> List[Dict[str, str]]:
    pflag = "-p-" if all_ports else "-p 22,80,445,139,443,3389,53"
    base_common = ["nmap", target, "-n", "-Pn", pflag]

    steps: List[Dict[str, str]] = []

    # 1) ACK scan (firewall rule mapping)
    steps.append({
        "name": "TCP ACK scan (firewall rule mapping)",
        "tool": "nmap",
        "command": ("nmap {t} -n -Pn {p} -sA " + ("-T4" if fast else "")).strip().format(t=target, p=pflag),
        "rationale": "Map stateful filtering: ACK reveals filtered vs unfiltered without opening connections."
    })

    # 2) SYN scan baseline (stealth)
    steps.append({
        "name": "SYN scan baseline",
        "tool": "nmap",
        "command": ("nmap {t} -n -Pn {p} -sS " + ("-T4" if fast else "--scan-delay 100ms")).format(t=target, p=pflag),
        "rationale": "Establish baseline open/closed ports with stealthy SYN before evasion."
    })

    # 3) Decoy scan
    if not fast:
        steps.append({
            "name": "Decoy SYN scan",
            "tool": "nmap",
            "command": f"sudo -n nmap {target} -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:{decoys}",
            "rationale": "If baseline hints at monitoring, use decoys to obscure scanner identity while validating reachability."
        })

    # 4) SYN from DNS source port
    if not fast:
        steps.append({
            "name": "SYN scan with spoofed source port 53",
            "tool": "nmap",
            "command": f"sudo -n nmap {target} -p {test_port} -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53",
            "rationale": "Test firewall trust of DNS by sending from source port 53 to traverse ACLs."
        })

    # 5) Optional spoofed source IP (requires iface)
    if (spoof_ip and iface) and (not fast):
        steps.append({
            "name": "SYN/OS detection with spoofed source IP",
            "tool": "nmap",
            "command": f"sudo -n nmap {target} -n -Pn -p{test_port} -O -S {spoof_ip} -e {iface}",
            "rationale": "If subnet/IP-based filtering suspected, try spoofed source IP on interface."
        })

    # 6) FIN stealth
    steps.append({
        "name": "FIN stealth scan",
        "tool": "nmap",
        "command": (f"nmap {target} -n -Pn {pflag} -sF --max-retries 2 " + ("-T4" if fast else "--scan-delay 150ms")),
        "rationale": "FIN probes can slip past stateless filters; closed ports should RST."
    })
    # 7) NULL stealth
    steps.append({
        "name": "NULL stealth scan",
        "tool": "nmap",
        "command": (f"nmap {target} -n -Pn {pflag} -sN --max-retries 2 " + ("-T4" if fast else "--scan-delay 150ms")),
        "rationale": "NULL probes can bypass simplistic detection; closed ports RST."
    })
    # 8) XMAS stealth
    steps.append({
        "name": "XMAS stealth scan",
        "tool": "nmap",
        "command": (f"nmap {target} -n -Pn {pflag} -sX --max-retries 2 " + ("-T4" if fast else "--scan-delay 150ms")),
        "rationale": "XMAS probes test RFC compliance and filtering behavior."
    })

    # Fragmentation
    if not fast:
        steps.append({
            "name": "Packet fragmentation",
            "tool": "nmap",
            "command": f"nmap {target} -n -Pn {pflag} -sS -f --mtu 16 -T0",
            "rationale": "Fragment TCP headers to evade stateless ACLs and signature-based IDS."
        })

    # 8) DNS version bind (CHAOS)
    steps.append({
        "name": "DNS version.bind (CHAOS)",
        "tool": "dig",
        "command": f"dig @{target} version.bind CHAOS TXT",
        "rationale": "If DNS responds, reveal BIND version to assess defense stack exposure."
    })

    # 9) Netcat validation from source port 53
    if not fast:
        steps.append({
            "name": "nc validate from source port 53",
            "tool": "ncat",
            "command": f"ncat -nv --source-port 53 {target} {test_port}",
            "rationale": "Validate port accessibility using DNS-like source port to confirm Nmap findings."
        })

    # 10) Proxychains example (if installed)
    if not fast:
        steps.append({
            "name": "proxychains nmap TCP connect",
            "tool": "proxychains,nmap",
            "command": f"proxychains nmap -sT -Pn -p 80,443 {target}",
            "rationale": "Demonstrate scanning via proxies to bypass IP-based blocks/EDR egress rules."
        })

    return steps


def execute_steps(steps: List[Dict[str, str]], per_step_timeout: Optional[int]) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    def _analyze_step(step: Dict[str, str], rc: int, out: str, err: str) -> str:
        tool = step.get("tool", "")
        name = step.get("name", "")
        if "nmap" in tool:
            states = parse_nmap_ports(out)
            if states:
                counts: Dict[str, int] = {}
                for st in states.values():
                    counts[st] = counts.get(st, 0) + 1
                parts = [f"{k}={v}" for k, v in sorted(counts.items())]
                return f"Nmap parsed states: {'; '.join(parts)}"
            if rc == 124 or (err and "timeout" in err.lower()):
                return "Nmap timed out; likely heavy filtering or very slow responses"
            return "No parsable Nmap port table; possibly filtered or host unreachable"
        if "ncat" in tool:
            if "Connected to" in (out or err):
                return "Netcat connected successfully (port reachable)"
            if "Connection refused" in (out or err):
                return "Netcat refused (port closed but reachable)"
            if "timeout" in (out or err).lower():
                return "Netcat timed out (likely filtered)"
            return "Netcat did not establish a connection"
        if tool == "dig":
            if "no servers could be reached" in (out or err):
                return "DNS CHAOS query failed (no DNS reachable on target)"
            if "status: NOERROR" in out:
                return "DNS responded to CHAOS version.bind"
            return "DNS CHAOS check inconclusive"
        return f"Command exited rc={rc}"
    for step in steps:
        cmd_str = step["command"]
        # Only run commands whose primary tool exists; skip gracefully otherwise
        primary = (step.get("tool", "").split(",") or [""]) [0]
        if primary and not has_binary(primary):
            results.append({
                **step,
                "skipped": True,
                "reason": f"Missing binary: {primary}",
            })
            continue

        rc, out, err = run_command(shlex.split(cmd_str), timeout=per_step_timeout)
        interpretation = _analyze_step(step, rc, out, err)
        logger.info("Step '%s': %s", step.get("name", ""), interpretation)
        results.append({
            **step,
            "returncode": rc,
            # keep full for analysis, truncated for report readability
            "stdout_full": out,
            "stderr_full": err,
            "stdout": _truncate(out),
            "stderr": _truncate(err),
            "interpretation": interpretation,
            "skipped": False,
            "success": rc == 0
        })
    return results


def build_markdown(target: str, steps: List[Dict[str, str]], analysis: Dict[int, Dict[str, str]]) -> str:
    lines: List[str] = []
    lines.append(f"# Evasion Report for {target}\n")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    lines.append("")

    # Summary table
    if analysis:
        lines.append("## Port Summary\n")
        lines.append("| Port | Final State | Notes |\n| --- | --- | --- |\n")
        for port in sorted(analysis.keys()):
            rec = analysis[port]
            lines.append(f"| {port} | {rec.get('final','?')} | {rec.get('reason','')} |\n")
        lines.append("")

    lines.append("## Overview\n")
    lines.append("This report documents firewall/IDS/IPS evasion tests, the exact commands executed, and observed outcomes.\n")
    lines.append("")

    lines.append("## Executed Steps and Results\n")
    for i, step in enumerate(steps, 1):
        lines.append(f"### {i}. {step['name']}\n")
        lines.append(f"- **Tool**: {step.get('tool','')}\n")
        lines.append(f"- **Command**: `{step['command']}`\n")
        if step.get("rationale"):
            lines.append(f"- **Why this step**: {step['rationale']}\n")
        if step.get("skipped"):
            lines.append(f"- **Status**: Skipped ({step.get('reason','')})\n")
            lines.append("")
            continue
        success = step.get("success")
        lines.append(f"- **Status**: {'Success' if success else 'Failed'} (rc={step.get('returncode')})\n")
        if step.get("interpretation"):
            lines.append(f"- **What happened**: {step['interpretation']}\n")
        if step.get("stdout"):
            lines.append("<details><summary>Output (stdout)</summary>\n\n")
            lines.append("```\n" + (step.get("stdout") or "") + "\n```\n")
            lines.append("</details>\n")
        if step.get("stderr"):
            lines.append("<details><summary>Output (stderr)</summary>\n\n")
            lines.append("```\n" + (step.get("stderr") or "") + "\n```\n")
            lines.append("</details>\n")
        # Add adaptive reasoning hints
        if i < len(steps):
            lines.append("- **Next decision**: If results suggest filtering (filtered/timeouts), escalate to the next stealth technique; otherwise, keep baseline.\n")
        lines.append("")

    lines.append("## Techniques Reference\n")
    lines.append(textwrap.dedent(
        """
        ### Firewall evasion by Nmap

        - Use `-sA` (ACK) to map filtering vs. `-sS` (SYN) baseline.
        - Decoys with `-D RND:<n>`; fragmentation `-f`/`--mtu`.
        - Spoof DNS source with `--source-port 53`; try FIN/NULL/XMAS.
        - Optional `-S <ip> -e <iface>` for source IP spoofing (where supported).
        - Slow timing `-T0`/`-T1`, `--scan-delay` to reduce detection.

        ### IDS/IPS detection strategy
        - Vary sources (multiple VPS), observe blocks; use decoys or idle scans.
        - Throttle probes, randomize order, and split port ranges.

        ### Proxying
        - `proxychains nmap -sT -Pn -p 80,443 <target>` to route via SOCKS/HTTP proxies.

        ### Validation via Netcat
        - `ncat -nv --source-port 53 <target> <port>` to confirm server behavior.
        """
    ).strip() + "\n")

    return "\n".join(lines)


def save_reports(target: str, step_results: List[Dict[str, str]], analysis: Dict[int, Dict[str, str]]) -> None:
    # JSON
    json_path = OUTPUT_DIR / REPORT_JSON.format(target=target)
    md_path = OUTPUT_DIR / REPORT_MD.format(target=target)
    pdf_path = OUTPUT_DIR / REPORT_PDF.format(target=target)

    data = {
        "target": target,
        "generated": datetime.now().isoformat(),
        "steps": step_results,
        "analysis": analysis,
    }
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    logger.info("Saved evasion JSON to %s", json_path)

    # Markdown
    md_content = build_markdown(target, step_results, analysis)
    md_path.write_text(md_content, encoding="utf-8")
    logger.info("Saved evasion Markdown to %s", md_path)

    # PDF via markdown + weasyprint
    try:
        import markdown as md
        import weasyprint

        html_body = md.markdown(md_content, extensions=['tables'])
        html_doc = f"""
        <!doctype html>
        <html>
        <head>
            <meta charset=\"utf-8\" />
            <title>Evasion Report - {target}</title>
            <style>
                body {{ font-family: Arial, Helvetica, sans-serif; font-size: 12px; color: #222; }}
                h1, h2, h3 {{ color: #111; }}
                code, pre {{ font-family: Menlo, Consolas, 'Roboto Mono', monospace; font-size: 11px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 6px; }}
                th {{ background: #f0f0f0; }}
            </style>
        </head>
        <body>
            {html_body}
        </body>
        </html>
        """
        weasyprint.HTML(string=html_doc).write_pdf(str(pdf_path))
        logger.info("Saved evasion PDF to %s", pdf_path)
    except Exception as e:
        logger.warning("Failed to generate PDF: %s", e)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    parser = argparse.ArgumentParser(
        description="Firewall/IDS/IPS evasion tests for a single target"
    )
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("--iface", "-e", dest="iface", help="Network interface for spoofing (with -S)")
    parser.add_argument("--spoof-ip", "-S", dest="spoof_ip", help="Spoofed source IP for tests requiring -S")
    parser.add_argument("--all-ports", action="store_true", help="Scan all TCP ports where applicable (-p-)")
    parser.add_argument("--decoys", type=int, default=5, help="Number of random decoys for -D RND:<n>")
    parser.add_argument("--test-port", type=int, default=50000, help="High port used for source-port/validation tests")
    parser.add_argument("--no-confirm", action="store_true", help="Skip confirmation prompt")
    parser.add_argument("--fast", action="store_true", help="Skip sudo-heavy steps and use faster timing")
    parser.add_argument("--timeout", type=int, default=None, help="Per-step timeout in seconds (overrides defaults)")

    args = parser.parse_args()

    if not args.no_confirm:
        print("LEGAL WARNING: Use only with explicit authorization. Continue? [y/N] ", end="", flush=True)
        try:
            ans = sys.stdin.readline().strip().lower()
        except Exception:
            ans = "n"
        if ans != "y":
            print("Exiting...")
            return 0

    if not has_binary("nmap"):
        logger.error("nmap binary not found in PATH")
    steps = build_steps(args.target, args.iface, args.spoof_ip, args.all_ports, args.decoys, args.test_port, args.fast)
    # Remove timeouts if not explicitly provided
    default_timeout = args.timeout if args.timeout is not None else None
    results = execute_steps(steps, per_step_timeout=default_timeout)

    # Adaptive follow-ups based on parsed results
    port_analysis: Dict[int, Dict[str, str]] = {}
    # Helper to parse and merge any nmap result list
    def _merge_from(result_list: List[Dict[str, str]], source_hint: str = "NMAP"):
        nonlocal port_analysis
        for r in result_list:
            if r.get("skipped"):
                continue
            states = parse_nmap_ports(r.get("stdout_full") or r.get("stdout") or "") if "nmap" in r.get("tool", "") else {}
            if not states:
                continue
            name = r.get("name", "").lower()
            source = source_hint
            if "ack" in name:
                source = "ACK"
            elif "syn" in name:
                source = "SYN"
            merge_port_states(port_analysis, states, source)

    # Parse baseline SYN and ACK where available
    _merge_from(results)

    # Identify targets for evasion
    filtered_ports = [p for p, rec in port_analysis.items() if rec.get("final") in {"filtered", "open|filtered"}]
    # If we scanned specific test_port only, ensure it is considered
    if args.test_port not in port_analysis:
        port_analysis.setdefault(args.test_port, {"final": "unknown", "history": []})

    # Stage-based adaptive escalation: unstealthy -> stealth
    # Stage 0 result check: if no filtered and we have at least one open/closed across ports scanned, stop
    def _needs_stealth(pa: Dict[int, Dict[str, str]]) -> bool:
        if not pa:
            return True
        has_definitive = any(v.get("final") in {"open", "closed"} for v in pa.values())
        has_filtered = any(v.get("final") in {"filtered", "open|filtered", "unknown"} for v in pa.values())
        return (not has_definitive) or has_filtered

    # If still ambiguous/filtered, escalate: source-port 53 on filtered ports
    if _needs_stealth(port_analysis) and filtered_ports and not args.fast:
        batch = ",".join(str(p) for p in sorted(filtered_ports)[:50]) or str(args.test_port)
        follow_src53 = [{
            "name": "SYN from source port 53 on filtered ports",
            "tool": "nmap",
            "command": f"sudo -n nmap {args.target} -p {batch} -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53"
        }]
        fr = execute_steps(follow_src53, per_step_timeout=default_timeout)
        results.extend(fr)
        _merge_from(fr, source_hint="SRC-53")

    # Re-evaluate filtered ports after SRC-53
    filtered_ports = [p for p, rec in port_analysis.items() if rec.get("final") in {"filtered", "open|filtered", "unknown"}]

    # If still filtered, try stealth scans (FIN/NULL/XMAS) limited to suspect ports if we didn't scan all
    if _needs_stealth(port_analysis):
        scope_flag = f"-p {','.join(str(p) for p in sorted(filtered_ports)[:100])}" if filtered_ports and not args.all_ports else ("-p-" if args.all_ports else "-p 22,80,445,139,443,3389,53")
        stealth_steps = [
            {"name": "FIN stealth scan (focused)", "tool": "nmap", "command": f"nmap {args.target} -n -Pn {scope_flag} -sF --max-retries 1 --scan-delay 200ms"},
            {"name": "NULL stealth scan (focused)", "tool": "nmap", "command": f"nmap {args.target} -n -Pn {scope_flag} -sN --max-retries 1 --scan-delay 200ms"},
            {"name": "XMAS stealth scan (focused)", "tool": "nmap", "command": f"nmap {args.target} -n -Pn {scope_flag} -sX --max-retries 1 --scan-delay 200ms"},
        ]
        fr2 = execute_steps(stealth_steps, per_step_timeout=default_timeout)
        results.extend(fr2)
        _merge_from(fr2)

    # If any ports became open, attempt ncat PoC on a few
    confirm_ports = [p for p, rec in port_analysis.items() if rec.get("final") == "open"]
    for p in confirm_ports[:10]:
        poc = [{
            "name": f"nc PoC from source port 53 to {p}",
            "tool": "ncat",
            "command": f"printf 'HEAD / HTTP/1.0\r\n\r\n' | ncat -nv --source-port 53 {args.target} {p}"
        }]
        results.extend(execute_steps(poc, per_step_timeout=default_timeout))

    # Save final reports with analysis
    save_reports(args.target, results, port_analysis)
    print(f"Evasion report saved under: {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

