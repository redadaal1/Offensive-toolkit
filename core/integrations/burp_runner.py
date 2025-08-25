#!/usr/bin/env python3
import os
import time
import json
import logging
import signal
from subprocess import Popen, DEVNULL
from pathlib import Path
from typing import Dict, Tuple, List

import requests

from core.config import config

logger = logging.getLogger(__name__)


def _get_runner_cfg() -> Dict:
    return {
        "java": config.get("integrations.burpRunner.java", "/usr/bin/java"),
        "burp_jar": config.get("integrations.burpRunner.burpJar", "/reda_daal/burpsuite/burpsuite_pro_v2025.8.jar"),
        "project_file": config.get("integrations.burpRunner.project", "/opt/BurpSuitePro/default.burp"),
        "memory": config.get("integrations.burpRunner.memory", "2048m"),
        "headless": str(config.get("integrations.burpRunner.headless", True)).lower(),
        "base_url": config.get("integrations.burp.rest_url", "http://127.0.0.1:1337"),
        "api_key": config.get("integrations.burp.api_key", "toMchADzVXqBwsYld1k7OlS8JlJQAGyX"),
        "retry": int(config.get("integrations.burpRunner.retry", 10) or 10),
        "timeout_minutes": int(config.get("integrations.burpRunner.timeout_minutes", 10) or 10),
        "scan_configuration": config.get("integrations.burpRunner.scan_configuration", "Audit - Lightweight"),
        "output_dir": Path(config.get("general.output_directory", "outputs")).absolute(),
    }


def _headers(api_key: str) -> Dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        headers["X-API-Key"] = api_key
    return headers


def _start_burp(java: str, burp_jar: str, project_file: str, memory: str, headless: str) -> int:
    cmd = f'{java} -Xmx{memory} -Djava.awt.headless={headless} -jar "{burp_jar}" --project-file="{project_file}" --unpause-spider-and-scanner'
    logger.info(f"Starting Burp: {cmd}")
    pid = Popen(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL).pid
    return pid


def _safe_name(value: str) -> str:
    return ''.join(ch if ch.isalnum() or ch in ('-', '_', '.') else '_' for ch in value)


def _artifact_paths(out_dir: Path, target: str) -> Tuple[Path, Path, List[Path], List[Path]]:
    """Return (issues_path_new, meta_path_new, legacy_issue_paths, legacy_meta_paths)."""
    safe = _safe_name(target)
    issues_new = out_dir / f"{safe}_burp_issues.json"
    meta_new = out_dir / f"{safe}_http_burp_metadata.json"
    # Legacy paths that may contain slashes from target
    legacy_issue = out_dir / f"{target}_burp_issues.json"
    legacy_meta = out_dir / f"{target}_http_burp_metadata.json"
    # Also check a variant where 'http://' becomes 'http:/' due to accidental path join
    legacy_issue2 = out_dir / (target.replace('://', ':/') + "_burp_issues.json")
    legacy_meta2 = out_dir / (target.replace('://', ':/') + "_http_burp_metadata.json")
    return issues_new, meta_new, [legacy_issue, legacy_issue2], [legacy_meta, legacy_meta2]


def _wait_api(base_url: str, api_key: str, headers: Dict[str, str], retry: int) -> bool:
    # Try both key-in-path and bearer-only endpoints
    paths = [f"/{api_key}/v0.1/", "/v0.1/scan"]
    for _ in range(retry):
        for p in paths:
            try:
                r = requests.get(f"{base_url}{p}", headers=headers, timeout=5)
                if r.status_code in (200, 400):
                    time.sleep(5)
                    return True
            except Exception:
                pass
        time.sleep(5)
    return False


def _start_scan(base_url: str, api_key: str, headers: Dict[str, str], target: str, scan_configuration: str) -> str:
    bodies = [
        {"urls": [target]},
        {"urls": [target], "scanConfiguration": {"type": "Named", "name": scan_configuration}},
        {"urls": [target], "scope": {"type": "SimpleScopeDefinition", "include": [{"url": target}]}}
    ]
    paths = [f"/{api_key}/v0.1/scan", "/v0.1/scan", "/scan"]
    last = None
    for body in bodies:
        for p in paths:
            try:
                resp = requests.post(f"{base_url}{p}", headers=headers, json=body, timeout=20)
                last = (p, resp.status_code, resp.text[:200])
                if resp.status_code in (200, 201, 202):
                    scan_id = None
                    ct = resp.headers.get("content-type", "")
                    if ct.startswith("application/json"):
                        try:
                            j = resp.json()
                        except Exception:
                            j = {}
                        scan_id = j.get("id") or j.get("scan_id") or (j.get("scan") or {}).get("id")
                    if not scan_id and resp.headers.get("Location"):
                        scan_id = resp.headers["Location"].rstrip("/").split("/")[-1]
                    if scan_id:
                        logger.info(f"Started scan via {p}: id={scan_id}")
                        return scan_id
            except Exception:
                pass
    logger.error(f"Failed to start scan. Last response: {last}")
    return ""


def _resume_scan(base_url: str, api_key: str, headers: Dict[str, str], scan_id: str) -> bool:
    paths = [
        f"/{api_key}/v0.1/scan/{scan_id}/resume",
        f"/v0.1/scan/{scan_id}/resume",
        f"/scan/{scan_id}/resume",
    ]
    for p in paths:
        try:
            r = requests.post(f"{base_url}{p}", headers=headers, timeout=10)
            if r.status_code in (200, 204):
                logger.info(f"Resumed scan via {p}")
                return True
        except Exception:
            pass
    return False


def _poll_until_done(base_url: str, api_key: str, headers: Dict[str, str], scan_id: str, timeout_minutes: int) -> bool:
    deadline = time.time() + timeout_minutes * 60
    done = {"done", "completed", "finished", "succeeded"}
    while time.time() < deadline:
        paths = [
            f"/{api_key}/v0.1/scan/{scan_id}",
            f"/v0.1/scan/{scan_id}/state",
            f"/v0.1/scan/{scan_id}",
            f"/scan/{scan_id}",
        ]
        for p in paths:
            try:
                r = requests.get(f"{base_url}{p}", headers=headers, timeout=15)
                if r.status_code == 200:
                    j = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                    state = (j.get("scan_status") or j.get("state") or j.get("status") or j.get("phase") or "").lower()
                    if state:
                        logger.info(f"State: {state}")
                        if state == "paused":
                            _ = _resume_scan(base_url, api_key, headers, scan_id)
                        if state in done:
                            return True
                        break
            except Exception:
                pass
        time.sleep(5)
    return False


def _fetch_issues(base_url: str, api_key: str, headers: Dict[str, str], scan_id: str) -> List[Dict]:
    paths = [
        f"/{api_key}/v0.1/scan/{scan_id}/issues",
        f"/v0.1/scan/{scan_id}/issues",
        f"/scan/{scan_id}/issues",
    ]
    for p in paths:
        try:
            r = requests.get(f"{base_url}{p}", headers=headers, timeout=20)
            if r.status_code == 200:
                j = r.json()
                issues = j.get("issues", j)
                if isinstance(issues, dict):
                    issues = [issues]
                return issues
        except Exception:
            pass
    # Fall back to full scan details containing issue_events
    for p in (f"/{api_key}/v0.1/scan/{scan_id}", f"/v0.1/scan/{scan_id}", f"/scan/{scan_id}"):
        try:
            r = requests.get(f"{base_url}{p}", headers=headers, timeout=20)
            if r.status_code == 200:
                j = r.json()
                if "issue_events" in j:
                    return [e.get("issue", e) for e in j["issue_events"]]
        except Exception:
            pass
    return []


def run_single_target(target: str) -> Tuple[bool, Path, Path]:
    cfg = _get_runner_cfg()
    headers = _headers(cfg["api_key"])
    out_dir = cfg["output_dir"]
    out_dir.mkdir(exist_ok=True)

    # Determine artifact paths (new sanitized and legacy)
    issues_new, meta_new, legacy_issue_paths, legacy_meta_paths = _artifact_paths(out_dir, target)

    # Check for existing scan via saved metadata
    existing_scan_id = ""
    for mp in [*legacy_meta_paths, meta_new]:
        try:
            if mp.exists():
                j = json.loads(mp.read_text(encoding="utf-8"))
                existing_scan_id = str(j.get("scan_id") or "")
                if existing_scan_id:
                    logger.info(f"Reusing existing scan_id from {mp}: {existing_scan_id}")
                    break
        except Exception:
            continue

    pid = _start_burp(cfg["java"], cfg["burp_jar"], cfg["project_file"], cfg["memory"], cfg["headless"])
    try:
        if not _wait_api(cfg["base_url"], cfg["api_key"], headers, cfg["retry"]):
            logger.error("Burp API did not become ready")
            return False, Path(), Path()

        scan_id = existing_scan_id or _start_scan(cfg["base_url"], cfg["api_key"], headers, target, cfg["scan_configuration"])
        if not scan_id:
            return False, Path(), Path()

        if existing_scan_id:
            logger.info("Existing scan detected; attaching and polling status")

        finished = _poll_until_done(cfg["base_url"], cfg["api_key"], headers, scan_id, cfg["timeout_minutes"])
        if not finished:
            logger.warning("Scan did not finish within timeout; fetching partial issues")

        issues = _fetch_issues(cfg["base_url"], cfg["api_key"], headers, scan_id)

        # Save results (prefer sanitized file names). If legacy exists, we will overwrite sanitized only.
        issues_path = issues_new
        meta_path = meta_new

        result = {
            "tool": "burp",
            "target": target,
            "scan_id": scan_id,
            "urls": [target],
            "issues": issues,
            "summary": {
                "Critical": sum(1 for i in issues if str(i.get("severity","Info")).title() == "Critical"),
                "High": sum(1 for i in issues if str(i.get("severity","Info")).title() == "High"),
                "Medium": sum(1 for i in issues if str(i.get("severity","Info")).title() == "Medium"),
                "Low": sum(1 for i in issues if str(i.get("severity","Info")).title() == "Low"),
                "Info": sum(1 for i in issues if str(i.get("severity","Info")).title() == "Info"),
            }
        }
        try:
            issues_path.write_text(json.dumps(issues, indent=2), encoding="utf-8")
            meta_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
            logger.info(f"Saved Burp artifacts: {issues_path}, {meta_path}")
        except Exception as e:
            logger.error(f"Failed to save Burp results: {e}")

        return True, issues_path, meta_path

    finally:
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass


def main():
    import argparse
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    p = argparse.ArgumentParser(description="Run a single Burp scan and save issues")
    p.add_argument("target", help="URL to scan, e.g. http://192.168.1.27/")
    args = p.parse_args()
    ok, issues_path, meta_path = run_single_target(args.target)
    if not ok:
        exit(1)
    print(f"Saved: {issues_path}\nSaved: {meta_path}")


if __name__ == "__main__":
    main()

