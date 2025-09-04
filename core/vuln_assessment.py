#!/usr/bin/env python3
import argparse
import json
import logging
import time
from pathlib import Path
from typing import Dict

import requests
import subprocess
import re
import socket

from core.config import config
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(config.get("general.output_directory", "outputs")).absolute()
OUTPUT_DIR.mkdir(exist_ok=True)


def _safe_name(value: str) -> str:
    return ''.join(ch if ch.isalnum() or ch in ('-', '_', '.') else '_' for ch in value)


def run_burp(target: str) -> Dict:
    """Run Burp via configured mode (REST or Runner)."""
    results = {"tool": "burp", "summary": {}, "issues": []}
    try:
        # Prefer runner if enabled; else REST
        use_runner = bool(config.get("integrations.burpRunner.enabled", False))
        if use_runner:
            from core.integrations import burp_runner
            ok, issues_path, meta_path = burp_runner.run_single_target(f"http://{target}/")
            # meta file contains normalized data already
            if meta_path and Path(meta_path).exists():
                try:
                    results = json.loads(Path(meta_path).read_text(encoding="utf-8"))
                except Exception:
                    results = {"tool": "burp", "meta_path": str(meta_path)}
        else:
            from core.integrations import burp
            urls = [f"http://{target}/"]
            results = burp.scan_urls(target, urls)
    except Exception as e:
        logger.error(f"Burp error: {e}")
    return results


def nessus_headers() -> Dict[str, str]:
    return {
        "X-ApiKeys": f"accessKey={config.get('integrations.nessus.access_key','')}; secretKey={config.get('integrations.nessus.secret_key','')}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def run_nessus(target: str) -> Dict:
    """Very small Nessus API runner: create scan from template UUID, launch, poll, fetch issues summary.
    If not configured, it returns an empty result.
    """
    if not config.get("integrations.nessus.enabled", False):
        return {"tool": "nessus", "enabled": False, "summary": {}, "findings": []}

    base = config.get("integrations.nessus.url", "https://127.0.0.1:8834")
    mode = (config.get("integrations.nessus.mode", "fast") or "fast").lower()
    tmpl = config.get("integrations.nessus.fast_template_uuid") if mode == "fast" else config.get("integrations.nessus.scan_template_uuid")
    timeout_minutes = int(config.get("integrations.nessus.timeout_minutes", 30) or 30)
    if not tmpl:
        return {"tool": "nessus", "enabled": True, "summary": {}, "findings": [], "note": "no template uuid"}

    headers = nessus_headers()
    verify_ssl = False

    try:
        logger.info(f"[VULN][nessus] Creating {mode} scan for {target} on {base}")
        # Create scan
        payload = {
            "uuid": tmpl,
            "settings": {
                "name": f"Offsec Scan {target}",
                "text_targets": target,
            }
        }
        r = requests.post(f"{base}/scans", headers=headers, json=payload, verify=verify_ssl, timeout=20)
        r.raise_for_status()
        scan = r.json().get("scan") or {}
        scan_id = scan.get("id")
        if not scan_id:
            return {"tool": "nessus", "error": "no scan id"}

        # Launch
        _ = requests.post(f"{base}/scans/{scan_id}/launch", headers=headers, json={}, verify=verify_ssl, timeout=20)
        # Poll status
        deadline = time.time() + timeout_minutes * 60
        status = ""
        logger.info(f"[VULN][nessus] Launched scan id={scan_id}; polling up to {timeout_minutes} min")
        while time.time() < deadline:
            time.sleep(10)
            s = requests.get(f"{base}/scans/{scan_id}", headers=headers, verify=verify_ssl, timeout=20)
            if s.status_code != 200:
                continue
            j = s.json()
            status = (j.get("info") or {}).get("status", "").lower()
            if status in {"completed", "complete", "finished", "done"}:
                break

        # Fetch findings summary (vulnerabilities list)
        s = requests.get(f"{base}/scans/{scan_id}", headers=headers, verify=verify_ssl, timeout=30)
        vulns = []
        sev_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        if s.status_code == 200:
            j = s.json()
            for v in (j.get("vulnerabilities") or []):
                name = v.get("plugin_name") or v.get("pluginFamily") or "Issue"
                severity_id = int(v.get("severity", 0))
                # Map Nessus severity id to text
                sev_map = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}
                sev = sev_map.get(severity_id, "Info")
                sev_summary[sev] = sev_summary.get(sev, 0) + int(v.get("count", 1))
                vulns.append({
                    "name": name,
                    "severity": sev,
                    "count": v.get("count", 1),
                })

        result = {
            "tool": "nessus",
            "scan_id": scan_id,
            "status": status or "unknown",
            "summary": sev_summary,
            "findings": vulns,
        }
        logger.info(f"[VULN][nessus] Done id={scan_id}; summary: {sev_summary}")

        # Save JSON
        safe = _safe_name(target)
        (OUTPUT_DIR / f"{safe}_nessus_results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
    except Exception as e:
        logger.error(f"Nessus error: {e}")
        return {"tool": "nessus", "error": str(e)}


def run_vulnerability_assessment(target: str) -> Dict:
    """Orchestrate Burp + Nessus scans as a separate, resumable assessment.
    Returns a combined dict and writes artifacts to outputs/.
    """
    logger.info(f"[VULN] Starting vulnerability assessment for {target}")
    results = {"target": target, "burp": {}, "nessus": {}, "nuclei": {}, "sslyze": {}, "ssh_audit": {}, "nmap_vuln": {}, "smb_checks": {}, "timestamp": int(time.time())}

    # Run non-Burp tools in parallel first
    tasks = {}
    with ThreadPoolExecutor(max_workers=8) as executor:
        logger.info("[VULN] Launching non-Burp tools in parallel")
        if config.get("integrations.nessus.enabled", False):
            tasks[executor.submit(run_nessus, target)] = "nessus"
        if config.get("integrations.nuclei.enabled", False):
            tasks[executor.submit(run_nuclei, target)] = "nuclei"
        if config.get("integrations.sslyze.enabled", False):
            tasks[executor.submit(run_sslyze, target)] = "sslyze"
        if config.get("integrations.ssh_audit.enabled", False):
            tasks[executor.submit(run_ssh_audit, target)] = "ssh_audit"
        if config.get("integrations.nmap_vuln.enabled", False):
            tasks[executor.submit(run_nmap_vuln, target)] = "nmap_vuln"
        if config.get("integrations.smb_checks.enabled", False):
            tasks[executor.submit(run_smb_checks, target)] = "smb_checks"

        for future in as_completed(tasks):
            name = tasks[future]
            try:
                results[name] = future.result()
                logger.info(f"[VULN] {name} completed")
            except Exception as e:
                logger.error(f"[VULN] {name} failed: {e}")
                results[name] = {"tool": name, "error": str(e)}

    # Run Burp last (after others finished)
    try:
        if config.get("integrations.burp.enabled", False) or config.get("integrations.burpRunner.enabled", False):
            logger.info("[VULN] Running Burp last after other tools completed")
            results["burp"] = run_burp(target)
    except Exception as e:
        logger.error(f"[VULN] burp failed: {e}")
        results["burp"] = {"tool": "burp", "error": str(e)}

    # Persist individual artifacts
    safe = _safe_name(target)
    if results.get("burp"):
        (OUTPUT_DIR / f"{safe}_vuln_burp.json").write_text(json.dumps(results["burp"], indent=2), encoding="utf-8")
    if results.get("nessus"):
        (OUTPUT_DIR / f"{safe}_vuln_nessus.json").write_text(json.dumps(results["nessus"], indent=2), encoding="utf-8")
    if results.get("nuclei"):
        (OUTPUT_DIR / f"{safe}_nuclei.json").write_text(json.dumps(results["nuclei"], indent=2), encoding="utf-8")
    if results.get("sslyze"):
        (OUTPUT_DIR / f"{safe}_sslyze.json").write_text(json.dumps(results["sslyze"], indent=2), encoding="utf-8")
    if results.get("ssh_audit"):
        (OUTPUT_DIR / f"{safe}_ssh_audit.json").write_text(json.dumps(results["ssh_audit"], indent=2), encoding="utf-8")
    if results.get("nmap_vuln"):
        (OUTPUT_DIR / f"{safe}_nmap_vuln.json").write_text(json.dumps(results["nmap_vuln"], indent=2), encoding="utf-8")
    if results.get("smb_checks"):
        (OUTPUT_DIR / f"{safe}_smb_checks.json").write_text(json.dumps(results["smb_checks"], indent=2), encoding="utf-8")

    # Combined
    safe = _safe_name(target)
    (OUTPUT_DIR / f"{safe}_vulnerability_assessment.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    logger.info(f"[VULN] Saved vulnerability assessment outputs for {target}")
    return results


def run_nuclei(target: str) -> Dict:
    """Run nuclei with JSON output and return normalized summary."""
    bin_path = config.get("integrations.nuclei.binary", "nuclei")
    rate = str(config.get("integrations.nuclei.rate_limit", 50))
    conc = str(config.get("integrations.nuclei.concurrency", 50))
    sev = config.get("integrations.nuclei.severity", "low,medium,high,critical")
    templates = config.get("integrations.nuclei.templates")
    url = f"http://{target}"
    safe = _safe_name(target)
    out_path = OUTPUT_DIR / f"{safe}_nuclei.ndjson"
    # Prefer modern JSON Lines flag; fall back if unsupported
    cmd_jsonl = [bin_path, "-u", url, "-rate-limit", rate, "-c", conc, "-severity", sev, "-jsonl", "-o", str(out_path)]
    cmd_json = [bin_path, "-u", url, "-rate-limit", rate, "-c", conc, "-severity", sev, "-json", "-o", str(out_path)]
    if templates:
        cmd_jsonl.extend(["-t", templates])
        cmd_json.extend(["-t", templates])
    try:
        logger.info(f"[VULN][nuclei] Running: {' '.join(cmd_jsonl)}")
        subprocess.run(cmd_jsonl, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, check=False)
        # If no output produced, retry with legacy flag
        content = out_path.read_text(encoding="utf-8") if out_path.exists() else ""
        if not content.strip():
            logger.info("[VULN][nuclei] No output with -jsonl; retrying with -json")
            subprocess.run(cmd_json, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, check=False)
        issues = []
        if out_path.exists():
            for line in out_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    issues.append(json.loads(line))
                except Exception:
                    continue
        # summarize
        sev_counts: Dict[str, int] = {}
        for i in issues:
            s = str(i.get("severity", "info")).title()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        logger.info(f"[VULN][nuclei] Findings: {sev_counts} (total {len(issues)}) -> {out_path}")
        return {"tool": "nuclei", "issues": issues, "summary": sev_counts}
    except Exception as e:
        logger.error(f"nuclei error: {e}")
        return {"tool": "nuclei", "error": str(e)}


def run_sslyze(target: str) -> Dict:
    bin_path = config.get("integrations.sslyze.binary", "sslyze")
    port = int(config.get("integrations.sslyze.port", 443) or 443)
    skip_if_closed = bool(config.get("integrations.sslyze.skip_if_closed", True))
    safe = _safe_name(target)
    out_path = OUTPUT_DIR / f"{safe}_sslyze_raw.json"
    try:
        # Optional: skip if port not open
        if skip_if_closed:
            try:
                with socket.create_connection((target, port), timeout=3):
                    pass
            except Exception:
                logger.info(f"[VULN][sslyze] Skipping; {target}:{port} is closed or TLS handshake not accepted")
                return {"tool": "sslyze", "skipped": True, "port": port, "reason": "port_closed"}
        # Prefer JSON output file if supported
        cmd = [bin_path, f"{target}:{port}", f"--json_out={str(out_path)}"]
        logger.info(f"[VULN][sslyze] Running: {' '.join(cmd)}")
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, check=False)
        summary = {"findings": 0}
        data = {}
        if out_path.exists():
            try:
                data = json.loads(out_path.read_text(encoding="utf-8"))
                # naive summary: count failed checks
                issues = re.findall(r'"failed":\s*true', out_path.read_text(encoding="utf-8"))
                summary["findings"] = len(issues)
            except Exception:
                pass
        logger.info(f"[VULN][sslyze] Findings approx: {summary.get('findings',0)} -> {out_path}")
        return {"tool": "sslyze", "summary": summary, "raw_path": str(out_path), "data_present": bool(data)}
    except Exception as e:
        logger.error(f"sslyze error: {e}")
        return {"tool": "sslyze", "error": str(e)}


def run_ssh_audit(target: str) -> Dict:
    bin_path = config.get("integrations.ssh_audit.binary", "ssh-audit")
    try:
        logger.info(f"[VULN][ssh-audit] Running: {bin_path} -j {target}")
        proc = subprocess.run([bin_path, "-j", target], capture_output=True, text=True, check=False)
        data = {}
        try:
            data = json.loads(proc.stdout.strip() or "{}")
        except Exception:
            pass
        recs = data.get("recommendations") or []
        logger.info(f"[VULN][ssh-audit] Recommendations: {len(recs)}")
        return {"tool": "ssh-audit", "recommendations": recs, "summary": {"recommendations": len(recs)}}
    except Exception as e:
        logger.error(f"ssh-audit error: {e}")
        return {"tool": "ssh-audit", "error": str(e)}


def run_nmap_vuln(target: str) -> Dict:
    bin_path = config.get("integrations.nmap_vuln.binary", "nmap")
    safe = _safe_name(target)
    out_path = OUTPUT_DIR / f"{safe}_nmap_vuln.txt"
    try:
        cmd = [bin_path, "-sV", "--script", "vulners,vuln", target]
        logger.info(f"[VULN][nmap_vuln] Running: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        out_path.write_text(proc.stdout, encoding="utf-8")
        cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", proc.stdout or ""))
        logger.info(f"[VULN][nmap_vuln] CVEs referenced: {len(cves)} -> {out_path}")
        return {"tool": "nmap_vuln", "cve_count": len(cves), "output_path": str(out_path)}
    except Exception as e:
        logger.error(f"nmap vuln error: {e}")
        return {"tool": "nmap_vuln", "error": str(e)}


def run_smb_checks(target: str) -> Dict:
    bin_path = config.get("integrations.smb_checks.binary", "nmap")
    safe = _safe_name(target)
    out_path = OUTPUT_DIR / f"{safe}_smb_checks.txt"
    try:
        cmd = [bin_path, "-p", "445", "--script", "smb-vuln*", target]
        logger.info(f"[VULN][smb_checks] Running: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        out_path.write_text(proc.stdout, encoding="utf-8")
        vulnerable_hits = len(re.findall(r"VULNERABLE:", proc.stdout or ""))
        logger.info(f"[VULN][smb_checks] Vulnerable script hits: {vulnerable_hits} -> {out_path}")
        return {"tool": "smb_checks", "vuln_hits": vulnerable_hits, "output_path": str(out_path)}
    except Exception as e:
        logger.error(f"smb checks error: {e}")
        return {"tool": "smb_checks", "error": str(e)}

    # Combined
    safe = _safe_name(target)
    (OUTPUT_DIR / f"{safe}_vulnerability_assessment.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    logger.info(f"[VULN] Saved vulnerability assessment outputs for {target}")
    return results


def main():
    parser = argparse.ArgumentParser(description="Run Vulnerability Assessment (Burp + Nessus)")
    parser.add_argument("target", help="Target domain or IP")
    args = parser.parse_args()
    res = run_vulnerability_assessment(args.target)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

