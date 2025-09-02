#!/usr/bin/env python3
import asyncio
import json
import os
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional
from dataclasses import dataclass, field
import uuid
import signal
import logging
import shutil
import time
import json as _json
from urllib import request as _req
from urllib.error import URLError

from fastapi import FastAPI, Request, BackgroundTasks, Query, Response
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "outputs"

app = FastAPI(title="Offsec Dashboard", version="1.0")

# CORS for React dev server or other frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Optionally mount React build if available at gui/frontend/dist
FRONTEND_DIST = ROOT / "gui" / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/app", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="react-app")
    # Also expose compiled assets at a stable root path used by the SPA
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="react-assets")


# Simple in-memory multi-session store for log streaming and process control
@dataclass
class Session:
    id: str
    log_queue: asyncio.Queue[str] = field(default_factory=asyncio.Queue)
    task: Optional[asyncio.Task] = None
    proc: Optional[asyncio.subprocess.Process] = None
    status: Dict[str, str] = field(default_factory=lambda: {"state": "idle", "action": "none"})


sessions: Dict[str, Session] = {}
webhook_config: Dict[str, Optional[str]] = {"url": None, "token": None}


def get_or_create_session(session_id: Optional[str]) -> Session:
    sid = session_id or uuid.uuid4().hex[:8]
    if sid not in sessions:
        sessions[sid] = Session(id=sid)
    return sessions[sid]


def build_cli_cmd(action: str, target: str, attacker_ip: Optional[str], attacker_port: str,
                  services: Optional[List[str]], use_rockyou: bool, no_confirm: bool,
                  with_vuln_assess: bool = False,
                  evasion_fast: bool = False, evasion_all_ports: bool = False,
                  evasion_timeout: Optional[int] = None, evasion_test_port: Optional[int] = None,
                  evasion_decoys: Optional[int] = None) -> List[str]:
    # Use unbuffered mode so logs stream immediately
    cmd = ["python3", "-u", "-m", "cli.main", "--target", target]
    # Only attach services for modes that actually use them
    actions_accepting_services = {"recon", "exploit", "post-exploit", "walkthrough-full"}
    if services and action in actions_accepting_services:
        cmd += ["--services", ",".join(services)]
    if no_confirm:
        cmd += ["--no-confirm"]
    if action == "recon":
        cmd += ["--recon"]
        if with_vuln_assess:
            cmd += ["--with-vuln-assess"]
    elif action == "exploit":
        # Allow CLI to auto-detect attacker IP; only pass if provided
        cmd += ["--exploit"]
        if attacker_ip:
            cmd += ["--attacker-ip", attacker_ip]
        cmd += ["--attacker-port", attacker_port]
        if use_rockyou:
            cmd += ["--use-rockyou"]
    elif action == "post-exploit":
        # Allow CLI to auto-detect attacker IP; only pass if provided
        cmd += ["--post-exploit"]
        if attacker_ip:
            cmd += ["--attacker-ip", attacker_ip]
        cmd += ["--attacker-port", attacker_port]
    elif action == "report":
        cmd += ["--report"]
    elif action == "walkthrough":
        # Map walkthrough-only to report generation now that walkthrough is merged
        cmd += ["--report"]
    elif action == "walkthrough-full":
        # Allow CLI to auto-detect attacker IP; only pass if provided
        cmd = ["python3", "-m", "cli.main", "--target", target, "--walkthrough"]
        if attacker_ip:
            cmd += ["--attacker-ip", attacker_ip]
        cmd += ["--attacker-port", attacker_port]
        if services:
            cmd += ["--services", ",".join(services)]
        if use_rockyou:
            cmd += ["--use-rockyou"]
        if no_confirm:
            cmd += ["--no-confirm"]
        if with_vuln_assess:
            cmd += ["--with-vuln-assess"]
    elif action == "vuln-assess":
        cmd += ["--vuln-assess"]
    elif action == "evasion":
        cmd += ["--evasion"]
        if evasion_fast:
            cmd += ["--fast"]
        if evasion_all_ports:
            cmd += ["--all-ports"]
        if evasion_timeout is not None:
            cmd += ["--timeout", str(evasion_timeout)]
        if evasion_test_port is not None:
            cmd += ["--test-port", str(evasion_test_port)]
        if evasion_decoys is not None:
            cmd += ["--decoys", str(evasion_decoys)]
    elif action == "list-services":
        cmd += ["--list-services"]
    else:
        raise ValueError(f"Unknown action: {action}")
    return cmd


async def run_cli_and_stream(session: Session, cmd: List[str]) -> int:
    # Start in its own process group so we can pause/stop the whole tree
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        preexec_fn=os.setsid,
        env=env,
    )
    session.proc = proc
    assert proc.stdout is not None
    # Stream output line-by-line to queue and update session status on phase markers
    def _normalize_phase(key: str) -> str:
        k = key.strip().lower()
        if k in {"post-exploit", "post_exploit", "postexploit", "postexp", "post-ex"}:
            return "post"
        if k in {"vuln-assess", "va", "vuln", "vuln_assess"}:
            return "vuln-assess"
        if k in {"reporting", "reports"}:
            return "report"
        return k

    async def _send_webhook(payload: Dict):
        url = webhook_config.get("url")
        if not url:
            return
        try:
            body = _json.dumps(payload).encode()
            req = _req.Request(url, data=body, headers={"Content-Type": "application/json", "Authorization": f"Bearer {webhook_config.get('token') or ''}"}, method="POST")
            await asyncio.get_event_loop().run_in_executor(None, lambda: _req.urlopen(req, timeout=5))
        except URLError:
            pass

    async for line in proc.stdout:
        text = line.decode(errors="ignore").rstrip()
        try:
            if text.startswith("[PHASE] "):
                # Format: [PHASE] key: Label
                rest = text[len("[PHASE] "):]
                if ":" in rest:
                    key, label = rest.split(":", 1)
                    key = _normalize_phase(key)
                    label = label.strip()
                    session.status = {"state": session.status.get("state", "running") or "running", "action": key}
                    await _send_webhook({"type":"phase","session_id":session.id,"phase":key,"label":label})
        except Exception:
            pass
        await session.log_queue.put(text)
    rc = await proc.wait()
    await session.log_queue.put(f"[DONE] Return code: {rc}")
    session.status = {"state": "idle", "action": "none"}
    session.proc = None
    try:
        await _send_webhook({"type":"done","session_id":session.id,"returncode":rc})
    except Exception:
        pass
    return rc


def _tpl(name: str) -> str:
    tpl = ROOT / "gui" / "templates" / f"{name}.html"
    if tpl.exists():
        return tpl.read_text(encoding="utf-8")
    return f"<h3>Template {name} missing</h3>"


def detect_local_ip(target: Optional[str] = None) -> Optional[str]:
    """Robust local IPv4 detection used by the UI helper endpoint.
    Priority: socket trick to resolved target (or 8.8.8.8), ip route get, ip addr, ifconfig.
    """
    import subprocess, re, socket as _socket
    resolved: Optional[str] = None
    if target:
        try:
            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", target):
                resolved = target
            else:
                resolved = _socket.gethostbyname(target)
        except Exception:
            resolved = None
    # 1) socket trick
    try:
        probe = resolved or "8.8.8.8"
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect((probe, 53))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    # 2) route src
    if resolved:
        try:
            p = subprocess.run(["ip", "route", "get", resolved], capture_output=True, text=True, timeout=3)
            if p.returncode == 0:
                m = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b", p.stdout)
                if m:
                    return m.group(1)
        except Exception:
            pass
    # 3) ip addr
    try:
        p = subprocess.run(["ip", "-4", "addr", "show", "scope", "global"], capture_output=True, text=True, timeout=3)
        if p.returncode == 0:
            m_all = re.findall(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", p.stdout)
            for ip in m_all:
                if not ip.startswith("127."):
                    return ip
    except Exception:
        pass
    # 4) ifconfig
    try:
        p = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3)
        if p.returncode == 0:
            m_all = re.findall(r"\binet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)", p.stdout)
            for ip in m_all:
                if not ip.startswith("127."):
                    return ip
    except Exception:
        pass
    return None


@app.get("/")
async def root_page():
    # Serve dashboard directly at root
    if FRONTEND_DIST.exists():
        index_path = FRONTEND_DIST / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
    return _tpl("index")

@app.head("/")
async def head_root():
    return Response(status_code=200)


@app.get("/dashboard", response_class=HTMLResponse)
async def page_dashboard():
    # If SPA build exists, prefer it
    if FRONTEND_DIST.exists():
        return RedirectResponse(url="/app")
    return _tpl("index")

@app.head("/dashboard")
async def head_dashboard():
    # Allow HEAD checks for curl -I
    if FRONTEND_DIST.exists():
        return RedirectResponse(url="/app")
    return Response(status_code=200)


@app.get("/recon", response_class=HTMLResponse)
async def page_recon():
    return _tpl("recon")


@app.get("/exploit", response_class=HTMLResponse)
async def page_exploit():
    return _tpl("exploit")


@app.get("/post-exploit", response_class=HTMLResponse)
async def page_post():
    return _tpl("post_exploit")


@app.get("/reports", response_class=HTMLResponse)
async def page_reports():
    return _tpl("reports")


@app.get("/walkthrough", response_class=HTMLResponse)
async def page_walkthrough():
    return _tpl("walkthrough")


@app.get("/outputs", response_class=HTMLResponse)
async def page_outputs():
    return _tpl("outputs_page")


@app.get("/settings", response_class=HTMLResponse)
async def page_settings():
    return _tpl("settings")


@app.get("/app", response_class=HTMLResponse)
async def page_spa():
    # If SPA build exists, redirect to the mounted static app index
    if FRONTEND_DIST.exists():
        return RedirectResponse(url="/app/")
    # Fallback to legacy dashboard template
    return _tpl("index")

@app.head("/app")
async def head_spa():
    # Allow HEAD checks for curl -I
    if FRONTEND_DIST.exists():
        return RedirectResponse(url="/app/")
    return Response(status_code=200)


@app.get("/api/attacker-ip")
async def api_attacker_ip(target: Optional[str] = Query(None)):
    ip = detect_local_ip(target)
    if not ip:
        return JSONResponse({"ip": None}, status_code=404)
    return {"ip": ip}


@app.post("/api/run")
async def api_run(payload: Dict):
    """Start a CLI task in the background and stream logs via /api/logs/{session_id}."""
    session_id = payload.get("session_id")
    session = get_or_create_session(session_id)
    if session.task and not session.task.done():
        return JSONResponse({"error": "Session already running", "session_id": session.id}, status_code=409)

    action = payload.get("action")
    target = payload.get("target")
    attacker_ip = payload.get("attacker_ip")
    attacker_port = str(payload.get("attacker_port") or "4444")
    services = payload.get("services") or []
    use_rockyou = bool(payload.get("use_rockyou"))
    no_confirm = bool(payload.get("no_confirm", True))
    with_vuln_assess = bool(payload.get("with_vuln_assess", False))

    # Evasion flags (optional)
    ev_fast = bool(payload.get("fast", False))
    ev_all = bool(payload.get("all_ports", False))
    ev_timeout = payload.get("timeout")
    try:
        ev_timeout = int(ev_timeout) if ev_timeout is not None else None
    except Exception:
        ev_timeout = None
    ev_tport = payload.get("test_port")
    try:
        ev_tport = int(ev_tport) if ev_tport is not None else None
    except Exception:
        ev_tport = None
    ev_decoys = payload.get("decoys")
    try:
        ev_decoys = int(ev_decoys) if ev_decoys is not None else None
    except Exception:
        ev_decoys = None

    cmd = build_cli_cmd(action, target, attacker_ip, attacker_port, services, use_rockyou, no_confirm, with_vuln_assess,
                        evasion_fast=ev_fast, evasion_all_ports=ev_all, evasion_timeout=ev_timeout,
                        evasion_test_port=ev_tport, evasion_decoys=ev_decoys)
    session.status = {"state": "running", "action": action or "unknown"}
    await session.log_queue.put(f"[RUN] {' '.join(cmd)}")
    session.task = asyncio.create_task(run_cli_and_stream(session, cmd))
    return {"status": "started", "session_id": session.id}


@app.post("/api/stop")
async def api_stop(payload: Dict):
    """Terminate the running task for a specific session (entire process group)."""
    session = get_or_create_session(payload.get("session_id"))
    if session.proc and (session.task and not session.task.done()):
        try:
            pgid = os.getpgid(session.proc.pid)  # type: ignore[arg-type]
            os.killpg(pgid, signal.SIGTERM)
            await session.log_queue.put("[CTRL] Sent SIGTERM to process group")
        except ProcessLookupError:
            pass
    session.status = {"state": "idle", "action": "none"}
    return {"status": "stopped", "session_id": session.id}


@app.post("/api/pause")
async def api_pause(payload: Dict):
    """Pause the running task using SIGSTOP on its process group for a session."""
    session = get_or_create_session(payload.get("session_id"))
    if session.proc and session.status.get("state") == "running":
        try:
            pgid = os.getpgid(session.proc.pid)  # type: ignore[arg-type]
            os.killpg(pgid, signal.SIGSTOP)
            session.status["state"] = "paused"
            await session.log_queue.put("[CTRL] Sent SIGSTOP (paused)")
            return {"status": "paused", "session_id": session.id}
        except ProcessLookupError:
            pass
    return JSONResponse({"error": "no running task"}, status_code=409)


@app.post("/api/resume")
async def api_resume(payload: Dict):
    """Resume a paused task using SIGCONT on its process group for a session."""
    session = get_or_create_session(payload.get("session_id"))
    if session.proc and session.status.get("state") == "paused":
        try:
            pgid = os.getpgid(session.proc.pid)  # type: ignore[arg-type]
            os.killpg(pgid, signal.SIGCONT)
            session.status["state"] = "running"
            await session.log_queue.put("[CTRL] Sent SIGCONT (resumed)")
            return {"status": "running", "session_id": session.id}
        except ProcessLookupError:
            pass
    return JSONResponse({"error": "no paused task"}, status_code=409)


@app.get("/api/logs/{session_id}")
async def api_logs(session_id: str) -> StreamingResponse:
    session = get_or_create_session(session_id)
    async def event_stream() -> AsyncGenerator[bytes, None]:
        # Drain old logs for this session
        while not session.log_queue.empty():
            _ = session.log_queue.get_nowait()
        while True:
            line = await session.log_queue.get()
            yield f"data: {line}\n\n".encode()
    return StreamingResponse(event_stream(), media_type="text/event-stream")

@app.head("/api/logs/{session_id}")
async def api_logs_head(session_id: str):
    # Simple OK for HEAD probe
    _ = get_or_create_session(session_id)
    return Response(status_code=200)


@app.get("/api/status")
async def api_status(session_id: Optional[str] = Query(None)):
    if session_id:
        s = get_or_create_session(session_id)
        return {"session_id": s.id, **s.status}
    # Return overview of all sessions if none requested
    return {"sessions": {sid: sess.status for sid, sess in sessions.items()}}


@app.get("/api/sessions")
async def api_sessions():
    return {"sessions": [{"id": sid, **sess.status} for sid, sess in sessions.items()]}


@app.get("/api/outputs")
async def api_outputs(phase: Optional[str] = Query(None), contains: Optional[str] = Query(None),
                      ext: Optional[str] = Query(None), tool: Optional[str] = Query(None)):
    OUTPUT_DIR.mkdir(exist_ok=True)

    def infer_tags(name: str) -> Dict[str, Optional[str]]:
        n = name.lower()
        phase_tag: Optional[str] = None
        if any(x in n for x in ["_recon", "recon_"]):
            phase_tag = "recon"
        elif "evasion" in n:
            phase_tag = "evasion"
        elif any(x in n for x in ["_exploit", "exploit_"]):
            phase_tag = "exploit"
        elif any(x in n for x in ["_post", "post_"]):
            phase_tag = "post"
        elif "report" in n or n.endswith(".pdf"):
            phase_tag = "report"

        tool_tag: Optional[str] = None
        if "nmap" in n:
            tool_tag = "nmap"
        elif any(x in n for x in ["dig", "dns"]):
            tool_tag = "dns"
        elif any(x in n for x in ["ncat", "nc_"]):
            tool_tag = "ncat"
        elif "report" in n or n.endswith(".pdf"):
            tool_tag = "report"

        ext_tag = Path(name).suffix.lstrip(".")
        return {"phase": phase_tag, "tool": tool_tag, "ext": ext_tag}

    all_paths = [p for p in sorted(OUTPUT_DIR.glob("*")) if p.is_file()]
    items = []
    for p in all_paths:
        tags = infer_tags(p.name)
        items.append({
            "name": p.name,
            "size": p.stat().st_size,
            "mtime": int(p.stat().st_mtime),
            "tags": tags,
        })

    def _match(it: Dict) -> bool:
        if phase and (it["tags"].get("phase") != phase.lower()):
            return False
        if ext and (it["tags"].get("ext") != ext.lstrip(".").lower()):
            return False
        if tool and (it["tags"].get("tool") != tool.lower()):
            return False
        if contains and (contains.lower() not in it["name"].lower()):
            return False
        return True

    filtered = [it for it in items if _match(it)]
    return {"files": [it["name"] for it in filtered], "items": filtered}


@app.get("/api/preflight")
async def api_preflight():
    tools = ["nmap", "dig", "ncat", "proxychains", "python3"]
    present = {t: (shutil.which(t) is not None) for t in tools}
    versions: Dict[str, Optional[str]] = {}

    async def _version(cmd: List[str]) -> Optional[str]:
        try:
            p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            try:
                assert p.stdout is not None
                out = await asyncio.wait_for(p.stdout.read(), timeout=3)
            except asyncio.TimeoutError:
                try: p.kill()
                except Exception: pass
                return None
            return out.decode(errors="ignore").splitlines()[0][:200]
        except Exception:
            return None

    # Fire in parallel
    tasks = {t: asyncio.create_task(_version([t, "--version"])) for t, ok in present.items() if ok and t != "python3"}
    if present.get("python3"):
        tasks["python3"] = asyncio.create_task(_version(["python3", "--version"]))
    for t, task in tasks.items():
        versions[t] = await task

    # Basic reachability: existence of outputs dir
    OUTPUT_DIR.mkdir(exist_ok=True)
    writable = False
    try:
        probe = OUTPUT_DIR / f".probe_{int(time.time())}"
        probe.write_text("ok", encoding="utf-8")
        writable = True
        probe.unlink(missing_ok=True)  # type: ignore[call-arg]
    except Exception:
        writable = False

    return {"tools": present, "versions": versions, "outputs_writable": writable}


@app.post("/api/webhook-config")
async def api_webhook_config(payload: Dict):
    webhook_config["url"] = payload.get("url")
    webhook_config["token"] = payload.get("token")
    return {"ok": True}


@app.post("/api/clear-outputs")
async def api_clear_outputs():
    """Clear outputs directory except persistent loot folder (if present)."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    removed: List[str] = []
    for path in OUTPUT_DIR.iterdir():
        try:
            if path.is_file():
                path.unlink()
                removed.append(path.name)
            elif path.is_dir():
                if path.name.lower() == "loot":
                    continue
                # Recursively delete dir
                for root, dirs, files in os.walk(path, topdown=False):
                    for name in files:
                        try:
                            (Path(root) / name).unlink()
                        except Exception:
                            pass
                    for name in dirs:
                        try:
                            (Path(root) / name).rmdir()
                        except Exception:
                            pass
                path.rmdir()
                removed.append(path.name + "/")
        except Exception:
            continue
    # Broadcast clean-up notice to all sessions
    for s in sessions.values():
        await s.log_queue.put(f"[CLEAN] Removed: {', '.join(removed) if removed else 'nothing'}")
    return {"removed": removed}


@app.get("/outputs/{name}")
async def get_output(name: str):
    fp = OUTPUT_DIR / name
    if not fp.exists() or not fp.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(fp)


def main():
    import uvicorn
    # Attach a logging handler to also forward server logs to the SSE stream
    class SSELogHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            try:
                msg = self.format(record)
                loop = asyncio.get_event_loop()
                for s in sessions.values():
                    loop.call_soon_threadsafe(asyncio.create_task, s.log_queue.put(f"[SERVER] {msg}"))
            except Exception:
                pass

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    if not any(isinstance(h, SSELogHandler) for h in root_logger.handlers):
        handler = SSELogHandler()
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

    port = int(os.getenv("OFFSEC_GUI_PORT", "8000"))
    uvicorn.run("gui.server:app", host="0.0.0.0", port=port, reload=False, access_log=False)


if __name__ == "__main__":
    # Enforce running via module: python3 -m gui.server
    if not __package__:
        print("Please run this server using: python3 -m gui.server")
        raise SystemExit(1)
    main()

