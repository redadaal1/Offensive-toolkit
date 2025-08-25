#!/usr/bin/env python3
import asyncio
import json
import os
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional
import signal
import logging

from fastapi import FastAPI, Request, BackgroundTasks, Query
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


# Simple in-memory event bus for log streaming
log_queue: asyncio.Queue[str] = asyncio.Queue()
current_task: Optional[asyncio.Task] = None
current_proc: Optional[asyncio.subprocess.Process] = None
current_status: Dict[str, str] = {"state": "idle", "action": "none"}


def build_cli_cmd(action: str, target: str, attacker_ip: Optional[str], attacker_port: str,
                  services: Optional[List[str]], use_rockyou: bool, no_confirm: bool) -> List[str]:
    # Use unbuffered mode so logs stream immediately
    cmd = ["python3", "-u", "-m", "cli.main", "--target", target]
    if services:
        cmd += ["--services", ",".join(services)]
    if no_confirm:
        cmd += ["--no-confirm"]
    if action == "recon":
        cmd += ["--recon"]
    elif action == "exploit":
        if not attacker_ip:
            raise ValueError("--attacker-ip required for exploitation")
        cmd += ["--exploit", "--attacker-ip", attacker_ip, "--attacker-port", attacker_port]
        if use_rockyou:
            cmd += ["--use-rockyou"]
    elif action == "post-exploit":
        if not attacker_ip:
            raise ValueError("--attacker-ip required for post-exploit")
        cmd += ["--post-exploit", "--attacker-ip", attacker_ip, "--attacker-port", attacker_port]
    elif action == "report":
        cmd += ["--report"]
    elif action == "walkthrough":
        cmd += ["--generate-walkthrough"]
    elif action == "walkthrough-full":
        if not attacker_ip:
            raise ValueError("--attacker-ip required for full walkthrough")
        cmd = ["python3", "-m", "cli.main", "--target", target, "--attacker-ip", attacker_ip, "--attacker-port", attacker_port, "--walkthrough"]
        if services:
            cmd += ["--services", ",".join(services)]
        if use_rockyou:
            cmd += ["--use-rockyou"]
        if no_confirm:
            cmd += ["--no-confirm"]
    else:
        raise ValueError(f"Unknown action: {action}")
    return cmd


async def run_cli_and_stream(cmd: List[str]) -> int:
    global current_status, current_proc
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
    current_proc = proc
    assert proc.stdout is not None
    # Stream output line-by-line to queue
    async for line in proc.stdout:
        text = line.decode(errors="ignore").rstrip()
        await log_queue.put(text)
    rc = await proc.wait()
    await log_queue.put(f"[DONE] Return code: {rc}")
    current_status = {"state": "idle", "action": "none"}
    current_proc = None
    return rc


def _tpl(name: str) -> str:
    tpl = ROOT / "gui" / "templates" / f"{name}.html"
    if tpl.exists():
        return tpl.read_text(encoding="utf-8")
    return f"<h3>Template {name} missing</h3>"


@app.get("/")
async def root_redirect():
    return RedirectResponse(url="/dashboard")


@app.get("/dashboard", response_class=HTMLResponse)
async def page_dashboard():
    return _tpl("index")


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
    return _tpl("app")


@app.post("/api/run")
async def api_run(payload: Dict):
    """Start a CLI task in the background and stream logs via /api/logs."""
    global current_task, current_status
    if current_task and not current_task.done():
        return JSONResponse({"error": "Another task is running"}, status_code=409)

    action = payload.get("action")
    target = payload.get("target")
    attacker_ip = payload.get("attacker_ip")
    attacker_port = str(payload.get("attacker_port") or "4444")
    services = payload.get("services") or []
    use_rockyou = bool(payload.get("use_rockyou"))
    no_confirm = bool(payload.get("no_confirm", True))

    cmd = build_cli_cmd(action, target, attacker_ip, attacker_port, services, use_rockyou, no_confirm)
    current_status = {"state": "running", "action": action}
    await log_queue.put(f"[RUN] {' '.join(cmd)}")
    current_task = asyncio.create_task(run_cli_and_stream(cmd))
    return {"status": "started"}


@app.post("/api/stop")
async def api_stop():
    """Terminate the running task (entire process group)."""
    global current_task, current_proc, current_status
    if current_proc and (current_task and not current_task.done()):
        try:
            pgid = os.getpgid(current_proc.pid)  # type: ignore[arg-type]
            os.killpg(pgid, signal.SIGTERM)
            await log_queue.put("[CTRL] Sent SIGTERM to process group")
        except ProcessLookupError:
            pass
    current_status = {"state": "idle", "action": "none"}
    return {"status": "stopped"}


@app.post("/api/pause")
async def api_pause():
    """Pause the running task using SIGSTOP on its process group."""
    global current_proc, current_status
    if current_proc and current_status.get("state") == "running":
        try:
            pgid = os.getpgid(current_proc.pid)  # type: ignore[arg-type]
            os.killpg(pgid, signal.SIGSTOP)
            current_status["state"] = "paused"
            await log_queue.put("[CTRL] Sent SIGSTOP (paused)")
            return {"status": "paused"}
        except ProcessLookupError:
            pass
    return JSONResponse({"error": "no running task"}, status_code=409)


@app.post("/api/resume")
async def api_resume():
    """Resume a paused task using SIGCONT on its process group."""
    global current_proc, current_status
    if current_proc and current_status.get("state") == "paused":
        try:
            pgid = os.getpgid(current_proc.pid)  # type: ignore[arg-type]
            os.killpg(pgid, signal.SIGCONT)
            current_status["state"] = "running"
            await log_queue.put("[CTRL] Sent SIGCONT (resumed)")
            return {"status": "running"}
        except ProcessLookupError:
            pass
    return JSONResponse({"error": "no paused task"}, status_code=409)


@app.get("/api/logs")
async def api_logs() -> StreamingResponse:
    async def event_stream() -> AsyncGenerator[bytes, None]:
        # Drain old logs
        while not log_queue.empty():
            _ = log_queue.get_nowait()
        while True:
            line = await log_queue.get()
            yield f"data: {line}\n\n".encode()
    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/status")
async def api_status():
    return current_status


@app.get("/api/outputs")
async def api_outputs():
    OUTPUT_DIR.mkdir(exist_ok=True)
    files = [str(p.name) for p in sorted(OUTPUT_DIR.glob("*")) if p.is_file()]
    return {"files": files}


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
    await log_queue.put(f"[CLEAN] Removed: {', '.join(removed) if removed else 'nothing'}")
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
                loop.call_soon_threadsafe(asyncio.create_task, log_queue.put(f"[SERVER] {msg}"))
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

