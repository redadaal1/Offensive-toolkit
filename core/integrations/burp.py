#!/usr/bin/env python3
import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse

import requests

from core.config import config

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(config.get("general.output_directory", "outputs")).absolute()
OUTPUT_DIR.mkdir(exist_ok=True)


def _safe_name(value: str) -> str:
    return ''.join(ch if ch.isalnum() or ch in ('-', '_', '.') else '_' for ch in value)


def _append_ndjson(path: Path, items: List[Dict]) -> None:
    if not items:
        return
    try:
        with path.open("a", encoding="utf-8") as f:
            for item in items:
                try:
                    f.write(json.dumps(item) + "\n")
                except Exception:
                    continue
    except Exception:
        pass


def _try_get_text(base_url: str, headers: Dict[str, str], path_candidates: List[str]) -> str:
    for path in path_candidates:
        try:
            resp = requests.get(f"{base_url}{path}", headers=headers, timeout=10)
            if resp.status_code == 200 and isinstance(resp.text, str) and resp.text:
                return resp.text
        except Exception:
            continue
    return ""


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


def _artifact_paths(out_dir: Path, target: str) -> Tuple[Path, List[Path]]:
    """Return (sanitized_meta_path, legacy_meta_paths)."""
    safe = _safe_name(target)
    meta_new = out_dir / f"{safe}_http_burp_metadata.json"
    legacy_meta1 = out_dir / f"{target}_http_burp_metadata.json"
    legacy_meta2 = out_dir / (target.replace('://', ':/') + "_http_burp_metadata.json")
    return meta_new, [legacy_meta1, legacy_meta2]


def _load_existing_scan_id(out_dir: Path, target: str) -> str:
    meta_new, legacy_meta_paths = _artifact_paths(out_dir, target)
    for mp in [meta_new, *legacy_meta_paths]:
        try:
            if mp.exists():
                j = json.loads(mp.read_text(encoding="utf-8"))
                scan_id = str(j.get("scan_id") or (j.get("scan") or {}).get("id") or "")
                if scan_id:
                    logger.info(f"Reusing existing scan_id from {mp}: {scan_id}")
                    return scan_id
        except Exception:
            continue
    return ""


def _find_existing_scan(base_url: str, headers: Dict[str, str], target_url: str, api_key: Optional[str]) -> str:
    """Locate an existing Burp scan for the target by listing scans and matching URL/host.

    Tries multiple list endpoints (with and without API-key-in-path) and matches case-insensitively
    by full URL and by hostname. Returns the best candidate scan_id if found, else "".
    """
    base_paths = [
        "/v0.1/scans",
        "/v0.1/scan",
        "/v0.1/scan/list",
        "/v0.1/scans/active",
        "/scans",
        "/scan",
        "/scan/list",
        "/scans/active",
        "/burp/scan",
        "/burp/scans",
        "/burp/scan/list",
    ]
    paths: List[str] = []
    paths.extend(base_paths)
    if api_key:
        for p in base_paths:
            if p.startswith("/v0.1"):
                paths.append(f"/{api_key}{p}")
        paths.extend([
            f"/{api_key}/v0.1/scans",
            f"/{api_key}/v0.1/scan",
            f"/{api_key}/v0.1/scan/list",
            f"/{api_key}/v0.1/scans/active",
            f"/{api_key}/scans",
            f"/{api_key}/scan",
            f"/{api_key}/scan/list",
            f"/{api_key}/scans/active",
        ])

    done_states = {"done", "completed", "finished", "succeeded"}
    active_states = {"running", "active", "in_progress", "scanning", "audit", "crawl", "queued", "starting"}
    target_host = (urlparse(target_url).hostname or target_url).strip().lower()
    best_scan: Tuple[Optional[str], int] = (None, -1)
    tried: List[Tuple[str, int, int]] = []  # (path, status, items_len)

    for p in paths:
        status = -1
        count = -1
        try:
            resp = requests.get(f"{base_url}{p}", headers=headers, timeout=10)
            status = resp.status_code
            if resp.status_code != 200:
                tried.append((p, status, 0))
                continue
            try:
                data = resp.json()
            except Exception:
                tried.append((p, status, 0))
                continue
            items = data
            if isinstance(data, dict):
                # Known list wrappers
                for key in ("scans", "items", "data", "results", "list"):
                    if isinstance(data.get(key), list):
                        items = data[key]
                        break
                # Some APIs return an object map of id->scan
                if not isinstance(items, list) and isinstance(data, dict):
                    maybe_values = list(data.values())
                    if maybe_values and all(isinstance(v, dict) for v in maybe_values):
                        items = maybe_values
            if not isinstance(items, list):
                tried.append((p, status, 0))
                continue
            count = len(items)
            tried.append((p, status, count))
            for it in items:
                try:
                    urls = it.get("urls") or (it.get("scan") or {}).get("urls") or []
                    if isinstance(urls, str):
                        urls = [urls]
                    match = any(str(u).rstrip('/').lower() == target_url.rstrip('/').lower() for u in urls)
                    if not match:
                        u = (
                            it.get("url")
                            or it.get("base_url")
                            or it.get("baseUrl")
                            or (it.get("settings") or {}).get("text_targets")
                            or it.get("siteUrl")
                            or it.get("site_url")
                            or ""
                        )
                        if isinstance(u, str) and u:
                            cand = str(u).strip().split(',')[0].strip()
                            match = cand.rstrip('/').lower() == target_url.rstrip('/').lower()
                            if not match:
                                cand_host = (urlparse(cand).hostname or cand).strip().lower()
                                match = cand_host == target_host
                    if not match:
                        for hk in ("host", "hostname", "site", "target"):
                            hv = it.get(hk)
                            if isinstance(hv, str) and hv.strip().lower() == target_host:
                                match = True
                                break
                    if not match:
                        continue
                    state = str(it.get("state") or it.get("status") or it.get("scan_status") or "").lower()
                    scan_id = it.get("id") or it.get("scan_id") or (it.get("scan") or {}).get("id")
                    if not scan_id:
                        continue
                    score = 0
                    if state in active_states:
                        score += 100
                    ts = it.get("updated_at") or it.get("updated") or it.get("lastUpdated") or it.get("created") or it.get("created_at")
                    try:
                        if isinstance(ts, (int, float)):
                            score += int(ts) % 1000
                        elif isinstance(ts, str) and ts:
                            score += len(ts)
                    except Exception:
                        pass
                    if score > best_scan[1]:
                        best_scan = (str(scan_id), score)
                except Exception:
                    continue
        except Exception:
            tried.append((p, status, count))
            continue

    if not best_scan[0]:
        # Log discovery diagnostics once to help troubleshooting user adapters
        try:
            diag = "; ".join([f"{pa}=>{st},{cnt}" for (pa, st, cnt) in tried[:10]])
            logger.info(f"[Burp Discovery] No existing scan matched for {target_host}. Tried: {diag} ...")
        except Exception:
            pass
    else:
        logger.info(f"Found existing scan for {target_host}: id={best_scan[0]}")

    return best_scan[0] or ""


def _maybe_resume_scan(base_url: str, headers: Dict[str, str], api_key: Optional[str], scan_id: str) -> None:
    paths = [
        f"/v0.1/scan/{scan_id}/resume",
        f"/scan/{scan_id}/resume",
    ]
    if api_key:
        paths.insert(0, f"/{api_key}/v0.1/scan/{scan_id}/resume")
    for p in paths:
        try:
            r = requests.post(f"{base_url}{p}", headers=headers, timeout=10)
            if r.status_code in (200, 204):
                logger.info(f"Resumed scan via {p}")
                return
        except Exception:
            continue

def _match_target_in_scan_obj(obj: Dict, target_url: str, target_host: str) -> bool:
    urls = obj.get("urls") or (obj.get("scan") or {}).get("urls") or []
    if isinstance(urls, str):
        urls = [urls]
    if any(str(u).rstrip('/').lower() == target_url.rstrip('/').lower() for u in urls):
        return True
    u = (
        obj.get("url")
        or obj.get("base_url")
        or obj.get("baseUrl")
        or (obj.get("settings") or {}).get("text_targets")
        or obj.get("siteUrl")
        or obj.get("site_url")
        or ""
    )
    if isinstance(u, str) and u:
        cand = str(u).strip().split(',')[0].strip()
        if cand.rstrip('/').lower() == target_url.rstrip('/').lower():
            return True
        cand_host = (urlparse(cand).hostname or cand).strip().lower()
        if cand_host == target_host:
            return True
    for hk in ("host", "hostname", "site", "target"):
        hv = obj.get(hk)
        if isinstance(hv, str) and hv.strip().lower() == target_host:
            return True
    # NEW: check issue_events to infer target from issue fields
    try:
        events = obj.get("issue_events")
        if isinstance(events, list):
            for ev in events:
                src = ev.get("issue") if isinstance(ev, dict) else None
                if not isinstance(src, dict):
                    continue
                for fk in ("origin", "url", "target", "host", "hostname", "hostIp"):
                    val = src.get(fk)
                    if not isinstance(val, str) or not val:
                        continue
                    # origin/url can be a URL; others may be host/IP
                    val_host = (urlparse(val).hostname or val).strip().lower()
                    if val_host == target_host:
                        return True
    except Exception:
        pass
    return False


def _probe_existing_scan_by_sweep(base_url: str, headers: Dict[str, str], api_key: Optional[str], target_url: str, max_id: int = 100) -> str:
    """Last-resort: probe a bounded range of scan IDs to find a matching running scan.
    This is useful when the adapter does not expose any list endpoints.
    """
    target_host = (urlparse(target_url).hostname or target_url).strip().lower()
    # Try descending first (recent ids more likely)
    found = ""
    tried = 0
    for sid in range(max_id, 0, -1):
        path = f"/v0.1/scan/{sid}"
        if api_key:
            # Prefer key-in-path variant first
            detail_json, _ = _try_get_json(base_url, headers, [f"/{api_key}{path}", path])
        else:
            detail_json, _ = _try_get_json(base_url, headers, [path])
        tried += 1
        if not isinstance(detail_json, dict):
            continue
        if _match_target_in_scan_obj(detail_json, target_url, target_host):
            found = str(sid)
            break
        # Some APIs wrap under 'scan'
        scan_obj = detail_json.get("scan") if isinstance(detail_json.get("scan"), dict) else None
        if scan_obj and _match_target_in_scan_obj(scan_obj, target_url, target_host):
            found = str(sid)
            break
        if tried >= max_id:
            break
    if found:
        logger.info(f"[Burp Discovery] Found existing scan by ID sweep: id={found}")
    else:
        logger.info("[Burp Discovery] ID sweep did not find a matching scan")
    return found


def _rest_scan(target: str, urls: List[str]) -> Tuple[List[Dict], Dict]:
    """Trigger a Burp scan via REST API and fetch results.

    Expects a Burp REST API service to be available. Configuration keys:
    integrations.burp.rest_url, integrations.burp.api_key, integrations.burp.timeout_seconds
    """
    base_url = config.get("integrations.burp.rest_url", "http://127.0.0.1:1337")
    api_key = config.get("integrations.burp.api_key")
    # Support disabling timeout with values: 0, -1, "none", "infinite"
    raw_timeout = config.get("integrations.burp.timeout_seconds", 3600)
    timeout_seconds = None
    try:
        if str(raw_timeout).strip().lower() in {"0", "-1", "none", "null", "infinite"} or raw_timeout in (0, -1, None):
            timeout_seconds = None
        else:
            timeout_seconds = int(raw_timeout)
    except Exception:
        timeout_seconds = 3600
    scan_configuration = config.get("integrations.burp.scan_configuration", "Audit - Passive")

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        # Some adapters require X-API-Key instead of Bearer
        headers["X-API-Key"] = api_key

    # Determine target URL/host early for matching
    target_url = urls[0] if urls else f"http://{target}/"
    target_host = (urlparse(target_url).hostname or target_url).strip().lower()

    # Optional override: force attach to a specific existing scan id (validated against target)
    forced_attach = str(config.get("integrations.burp.force_attach_scan_id", "")).strip()
    if forced_attach.isdigit():
        cand_id = forced_attach
        # verify the forced scan belongs to this target
        details_json, _ = _try_get_json(
            base_url,
            headers,
            path_candidates=[
                *( [f"/{api_key}/v0.1/scan/{cand_id}"] if api_key else [] ),
                f"/v0.1/scan/{cand_id}",
                f"/scan/{cand_id}",
            ],
        )
        cand_obj = None
        if isinstance(details_json, dict):
            cand_obj = details_json.get("scan") if isinstance(details_json.get("scan"), dict) else details_json
        if cand_obj and _match_target_in_scan_obj(cand_obj, target_url, target_host):
            scan_id = cand_id
            logger.info(f"Force-attaching to existing Burp scan: {scan_id}")
            _maybe_resume_scan(base_url, headers, api_key, scan_id)
        else:
            logger.info(f"Forced scan id={cand_id} does not match target {target_host}; ignoring force_attach")
            scan_id = ""
    else:
        scan_id = ""

    # Determine scan id to use: prefer attaching to an existing Burp scan for this host/URL
    if not scan_id:
        scan_id = _find_existing_scan(base_url, headers, target_url, api_key)
    used_scan_path = None
    if not scan_id:
        # Fallback to previously saved metadata (older runs)
        scan_id = _load_existing_scan_id(OUTPUT_DIR, target)
    if not scan_id:
        # Final fallback: probe a bounded range of IDs when listing endpoints are unavailable
        probe_max =  int(config.get("integrations.burp.scan_id_probe_max", 100) or 100)
        scan_id = _probe_existing_scan_by_sweep(base_url, headers, api_key, target_url, max_id=probe_max)
    if not scan_id:
        # Start scan (try common endpoints)
        errors: List[str] = []
        scan_json = None
        # Try multiple payload shapes used by popular REST adapters
        scan_bodies = [
            {
                "urls": urls,
                "scan_configuration": scan_configuration,
            },
            {
                "urls": urls,
                "scanConfiguration": {"type": "Named", "name": scan_configuration},
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
    else:
        logger.info(f"Attaching to existing Burp scan: {scan_id}")
        _maybe_resume_scan(base_url, headers, api_key, scan_id)

    # Prepare streaming artifacts
    safe = _safe_name(target)
    ndjson_path = OUTPUT_DIR / f"{safe}_burp.ndjson"
    burp_log_path = OUTPUT_DIR / f"{safe}_burp_log.txt"
    per_issue_dir = OUTPUT_DIR / f"{safe}_burp_issues"
    try:
        per_issue_dir.mkdir(exist_ok=True)
    except Exception:
        pass
    seen_issue_keys: set = set()
    last_log_snapshot: str = ""
    # Track processed event ids to avoid duplicate logs
    seen_event_ids: set = set()

    # Snapshot current issues immediately (better UX on attach)
    try:
        details_json, _ = _try_get_json(
            base_url,
            headers,
            path_candidates=[
                *( [f"/{api_key}/v0.1/scan/{scan_id}"] if api_key else [] ),
                f"/v0.1/scan/{scan_id}",
                f"/scan/{scan_id}",
            ],
        )
        if isinstance(details_json, dict):
            # From issue_events
            events = details_json.get("issue_events")
            if isinstance(events, list):
                initial_issues: List[Dict] = []
                for ev in events:
                    if isinstance(ev, dict):
                        eid = str(ev.get("id") or "").strip()
                        if eid:
                            seen_event_ids.add(eid)
                        src = ev.get("issue") if isinstance(ev.get("issue"), dict) else ev
                        initial_issues.append(_normalize_issue(src))
                if initial_issues:
                    _append_ndjson(ndjson_path, initial_issues)
                    for it in initial_issues:
                        try:
                            issue_id = _safe_name((it.get("name") or "issue") + "_" + (it.get("url") or it.get("path") or ""))
                            (per_issue_dir / f"{issue_id}.json").write_text(json.dumps(it, indent=2), encoding="utf-8")
                        except Exception:
                            pass
                        logger.info(f"[Burp Issue] {it.get('severity','Info')}: {it.get('name','Issue')} - {it.get('url') or it.get('path','')}")
            # From issues endpoint shape if embedded
            raw_issues = details_json.get("issues")
            if isinstance(raw_issues, list) and raw_issues:
                normalized = [_normalize_issue(i) for i in raw_issues]
                _append_ndjson(ndjson_path, normalized)
                for it in normalized:
                    try:
                        issue_id = _safe_name((it.get("name") or "issue") + "_" + (it.get("url") or it.get("path") or ""))
                        (per_issue_dir / f"{issue_id}.json").write_text(json.dumps(it, indent=2), encoding="utf-8")
                    except Exception:
                        pass
                    logger.info(f"[Burp Issue] {it.get('severity','Info')}: {it.get('name','Issue')} - {it.get('url') or it.get('path','')}")
    except Exception:
        pass

    # Poll status (and stream issues/logs)
    start = time.time()
    while True:
        if timeout_seconds is not None and time.time() - start > timeout_seconds:
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

        # Stream issues incrementally from issues endpoint if available
        try:
            current_issues_json, _ = _try_get_json(
                base_url,
                headers,
                path_candidates=[
                    f"/scan/{scan_id}/issues",
                    f"/v0.1/scan/{scan_id}/issues",
                    f"/burp/scan/{scan_id}/issues",
                    *( [f"/{api_key}/v0.1/scan/{scan_id}/issues"] if api_key else [] ),
                ],
            )
            if current_issues_json:
                raw_issues = current_issues_json.get("issues", current_issues_json)
                if isinstance(raw_issues, dict):
                    raw_issues = [raw_issues]
                normalized = [_normalize_issue(i) for i in (raw_issues or [])]
                new_items: List[Dict] = []
                for ni in normalized:
                    key = (
                        ni.get("name"),
                        ni.get("url") or ni.get("path"),
                        ni.get("severity"),
                        ni.get("evidence") or "",
                    )
                    if key not in seen_issue_keys:
                        seen_issue_keys.add(key)
                        new_items.append(ni)
                if new_items:
                    _append_ndjson(ndjson_path, new_items)
                    # Write per-issue JSON files
                    for it in new_items:
                        try:
                            issue_id = _safe_name((it.get("name") or "issue") + "_" + (it.get("url") or it.get("path") or ""))
                            (per_issue_dir / f"{issue_id}.json").write_text(json.dumps(it, indent=2), encoding="utf-8")
                        except Exception:
                            pass
                    for it in new_items:
                        logger.info(f"[Burp Issue] {it.get('severity','Info')}: {it.get('name','Issue')} - {it.get('url') or it.get('path','')}")
        except Exception:
            pass

        # Stream issues from scan details issue_events if available
        try:
            details_json, _ = _try_get_json(
                base_url,
                headers,
                path_candidates=[
                    *( [f"/{api_key}/v0.1/scan/{scan_id}"] if api_key else [] ),
                    f"/v0.1/scan/{scan_id}",
                    f"/scan/{scan_id}",
                ],
            )
            if details_json and isinstance(details_json, dict) and isinstance(details_json.get("issue_events"), list):
                raw_events = details_json["issue_events"]
                issues_from_events = []
                new_event_items: List[Dict] = []
                for ev in raw_events:
                    if not isinstance(ev, dict):
                        continue
                    eid = str(ev.get("id") or "").strip()
                    if eid and eid in seen_event_ids:
                        continue
                    if eid:
                        seen_event_ids.add(eid)
                    src = ev.get("issue") or ev
                    ni = _normalize_issue(src)
                    issues_from_events.append(ni)
                    new_event_items.append(ni)
                if new_event_items:
                    _append_ndjson(ndjson_path, new_event_items)
                    for it in new_event_items:
                        try:
                            issue_id = _safe_name((it.get("name") or "issue") + "_" + (it.get("url") or it.get("path") or ""))
                            (per_issue_dir / f"{issue_id}.json").write_text(json.dumps(it, indent=2), encoding="utf-8")
                        except Exception:
                            pass
                    for it in new_event_items:
                        logger.info(f"[Burp Issue] {it.get('severity','Info')}: {it.get('name','Issue')} - {it.get('url') or it.get('path','')}")
        except Exception:
            pass

        # Stream Burp logs if the adapter exposes them
        try:
            log_text = _try_get_text(
                base_url,
                headers,
                path_candidates=[
                    f"/v0.1/scan/{scan_id}/log",
                    f"/scan/{scan_id}/log",
                    *( [f"/{api_key}/v0.1/scan/{scan_id}/log"] if api_key else [] ),
                ],
            )
            if log_text:
                # Append only new content if endpoint returns full log each time
                if log_text.startswith(last_log_snapshot):
                    delta = log_text[len(last_log_snapshot):]
                else:
                    delta = log_text
                if delta:
                    try:
                        with burp_log_path.open("a", encoding="utf-8") as lf:
                            lf.write(delta)
                    except Exception:
                        pass
                    for line in delta.splitlines():
                        if line.strip():
                            logger.info(line)
                last_log_snapshot = log_text
        except Exception:
            pass

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

    # If direct issues endpoint fails, fall back to full scan details and parse issue_events
    if not issues_json:
        fallback_json, used_fallback_path = _try_get_json(
            base_url,
            headers,
            path_candidates=[
                *( [f"/{api_key}/v0.1/scan/{scan_id}"] if api_key else [] ),
                f"/v0.1/scan/{scan_id}",
                f"/scan/{scan_id}",
            ],
        )
        if fallback_json and isinstance(fallback_json, dict):
            if "issue_events" in fallback_json and isinstance(fallback_json["issue_events"], list):
                try:
                    issues_list = [e.get("issue", e) for e in fallback_json["issue_events"]]
                    issues_json = {"issues": issues_list}
                    used_issues_path = used_fallback_path or ""
                    logger.info("Fetched issues via fallback scan details endpoint")
                except Exception:
                    pass

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
        # Persist sanitized metadata with scan_id to enable reuse
        try:
            safe = _safe_name(target)
            meta_new = OUTPUT_DIR / f"{safe}_http_burp_metadata.json"
            meta_payload = {
                "tool": "burp",
                "target": target,
                "scan_id": scan_id,
                "urls": urls,
                "issues_count": len(issues),
                "summary": summary,
            }
            meta_new.write_text(json.dumps(meta_payload, indent=2), encoding="utf-8")
        except Exception:
            pass
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

