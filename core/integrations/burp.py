#!/usr/bin/env python3
import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import requests

from core.config import config

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(config.get("general.output_directory", "outputs")).absolute()
OUTPUT_DIR.mkdir(exist_ok=True)


def _normalize_issue(issue: Dict) -> Dict:
    """Normalize a Burp issue dict into a common schema used in reports."""
    return {
        "name": issue.get("name") or issue.get("issueName") or "Unknown",
        "type": (issue.get("type") or issue.get("issueTypeName") or "vulnerability").lower(),
        "severity": (issue.get("severity") or issue.get("issueSeverity") or "Info").title(),
        "confidence": (issue.get("confidence") or issue.get("issueConfidence") or "Tentative").title(),
        "host": issue.get("host") or issue.get("hostIp") or "",
        "path": issue.get("path") or issue.get("url") or "",
        "url": issue.get("url") or issue.get("path") or "",
        "evidence": issue.get("evidence") or issue.get("evidenceDetail") or "",
        "description": issue.get("description") or "",
        "remediation": issue.get("remediation") or "",
        "references": issue.get("references") or [],
    }


def _summarize_issues(issues: List[Dict]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for issue in issues:
        sev = issue.get("severity", "Info").title()
        if sev not in counts:
            sev = "Info"
        counts[sev] += 1
    return counts


def _try_post_json(base_url: str, headers: Dict[str, str], path_candidates: List[str], body: Dict) -> Tuple[Optional[Dict], Optional[str]]:
    """Try POSTing JSON to a list of path candidates and return (json_like, path).

    Accepts 200/201/202. If body is empty, tries Location header to synthesize an id.
    """
    for path in path_candidates:
        try:
            resp = requests.post(f"{base_url}{path}", headers=headers, json=body, timeout=15)
            # 200/201 expected; some APIs return 202 Accepted
            if resp.status_code in (200, 201, 202):
                try:
                    return resp.json(), path
                except Exception:
                    # Some servers return empty body; attempt to extract id from Location header
                    location = resp.headers.get("Location") or resp.headers.get("location")
                    if location:
                        # e.g., /v0.1/scan/<id>
                        scan_id = location.rstrip("/").split("/")[-1]
                        if scan_id:
                            return {"id": scan_id}, path
        except Exception:
            continue
    return None, None


def _try_get_json(base_url: str, headers: Dict[str, str], path_candidates: List[str]) -> Tuple[Optional[Dict], Optional[str]]:
    """Try GET against candidates and return first JSON payload that works."""
    for path in path_candidates:
        try:
            resp = requests.get(f"{base_url}{path}", headers=headers, timeout=15)
            if resp.status_code == 200:
                try:
                    return resp.json(), path
                except Exception:
                    # If body empty or not JSON, skip
                    pass
        except Exception:
            continue
    return None, None


def _rest_scan(target: str, urls: List[str]) -> Tuple[List[Dict], Dict]:
    """Trigger a Burp scan via REST API and fetch results.

    Expects a Burp REST API service to be available. Configuration keys:
    integrations.burp.rest_url, integrations.burp.api_key, integrations.burp.timeout_seconds
    """
    base_url = config.get("integrations.burp.rest_url", "http://127.0.0.1:1337")
    api_key = config.get("integrations.burp.api_key")
    timeout_seconds = int(config.get("integrations.burp.timeout_seconds", 3600) or 3600)

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        # Some adapters require X-API-Key instead of Bearer
        headers["X-API-Key"] = api_key

    # Start scan (try common endpoints)
    errors: List[str] = []
    scan_json = None
    used_scan_path = None
    # Try multiple payload shapes used by popular REST adapters
    scan_bodies = [
        {
            "urls": urls,
            "scan_configuration": "Audit - Active",
        },
        {
            "urls": urls,
            "scanConfiguration": {"type": "Named", "name": "Audit - Active"},
        },
        {
            # Some adapters expect a single 'url' field
            "url": urls[0] if urls else "",
        },
        {
            # Some adapters expect a nested object: { "scan": { "urls": [..] } }
            "scan": {
                "urls": urls,
            }
        },
    ]
    for body in scan_bodies:
        scan_json, used_scan_path = _try_post_json(
            base_url,
            headers,
            path_candidates=[
                "/scan",  # Some adapters
                "/v0.1/scan",  # vishnunair/burp-rest-api
                "/burp/scan",  # other variants
                *( [f"/{api_key}/v0.1/scan"] if api_key else [] ),  # API key in path
            ],
            body=body,
        )
        if scan_json:
            break
    if not scan_json:
        logger.error("Failed to start Burp scan: no compatible endpoint responded with JSON")
        return [], {}

    # Extract scan ID from various possible shapes
    scan_id = (
        scan_json.get("scan_id")
        or scan_json.get("id")
        or (scan_json.get("scan") or {}).get("id")
        or scan_json.get("task_id")
    )
    if not scan_id:
        logger.error(f"Could not determine scan ID from response at {used_scan_path}: {scan_json}")
        return [], {}
    logger.info(f"Burp scan started: {scan_id} via {used_scan_path}")

    # Poll status
    start = time.time()
    while True:
        if time.time() - start > timeout_seconds:
            logger.warning("Burp scan timed out; fetching partial results if available")
            break
        # Try several status endpoints
        status_json, used_status_path = _try_get_json(
            base_url,
            headers,
            path_candidates=[
                f"/scan/{scan_id}",
                f"/v0.1/scan/{scan_id}",
                f"/v0.1/scan/{scan_id}/status",
                f"/v0.1/scan/{scan_id}/state",
                f"/burp/scan/{scan_id}",
                *( [f"/{api_key}/v0.1/scan/{scan_id}"] if api_key else [] ),
                *( [f"/{api_key}/v0.1/scan/{scan_id}/state"] if api_key else [] ),
            ],
        )
        if status_json:
            status_str = str(
                status_json.get("status")
                or status_json.get("state")
                or status_json.get("scan_status")
                or ""
            ).lower()
            if status_str in {"done", "completed", "finished", "succeeded"}:
                break
        time.sleep(5)

    # Fetch issues via multiple candidate paths
    issues_json, used_issues_path = _try_get_json(
        base_url,
        headers,
        path_candidates=[
            f"/scan/{scan_id}/issues",
            f"/v0.1/scan/{scan_id}/issues",
            f"/burp/scan/{scan_id}/issues",
            *( [f"/{api_key}/v0.1/scan/{scan_id}/issues"] if api_key else [] ),
        ],
    )
    if not issues_json:
        logger.error("Failed to fetch Burp issues from any known endpoint")
        return [], {}

    try:
        # Some APIs wrap issues, others return a list directly
        raw_issues = issues_json.get("issues", issues_json)
        if isinstance(raw_issues, dict):
            # Unexpected shape; convert to list of one
            raw_issues = [raw_issues]
        issues = [_normalize_issue(i) for i in (raw_issues or [])]
        summary = _summarize_issues(issues)
        logger.info(f"Fetched {len(issues)} Burp issues from {used_issues_path}")
        return issues, summary
    except Exception as e:
        logger.error(f"Error normalizing Burp issues: {e}")
        return [], {}


def scan_urls(target: str, urls: List[str]) -> Dict:
    """Run a Burp scan against a set of URLs and return normalized results.

    Mode is selected via config: integrations.burp.mode in {"rest", "cli"}.
    For now, REST is implemented; CLI can be added later.
    """
    mode = (config.get("integrations.burp.mode", "rest") or "rest").lower()

    if not urls:
        return {"tool": "burp", "issues": [], "summary": {}, "urls": []}

    if mode == "rest":
        issues, summary = _rest_scan(target, urls)
    else:
        logger.warning("Burp CLI mode not implemented yet; skipping")
        issues, summary = [], {}

    result = {
        "tool": "burp",
        "target": target,
        "urls": urls,
        "issues": issues,
        "summary": summary,
    }

    # Persist artifacts for later phases
    try:
        (OUTPUT_DIR / f"{target}_burp_issues.json").write_text(json.dumps(issues, indent=2), encoding="utf-8")
        (OUTPUT_DIR / f"{target}_http_burp_metadata.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        logger.info("Saved Burp issues and metadata to outputs/")
    except Exception as e:
        logger.error(f"Failed saving Burp artifacts: {e}")

    return result

