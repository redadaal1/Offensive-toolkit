## Work in Progress (WIP) — Offensive Toolkit

Updated: <replace with date when editing>

### Repos and branches
- GitHub (primary): `https://github.com/redadaal1/Offsec`
- Target repo: `https://github.com/redadaal1/Offensive-toolkit`
- Local working branch: `restore-all`
- Pushed branch on target repo: `offensive-import`
- Recovery branches (keep for safety): `recovered-safe`, `recover-f41a175`

### PRs / Links
- Open PR to merge into target main: `https://github.com/redadaal1/Offensive-toolkit/compare/main...offensive-import`

### Current status
- Git LFS initialized. Large file tracked via LFS: `hydra.restore`.
- Node/build/vendor dirs untracked via `.gitignore` to prevent bloat.
- Project builds locally after installing frontend deps.
- Reports and summaries present: `offsec_toolkit_full_report.txt`, `commands_summary.txt`, `tools_summary.txt`, `exploits_functions_summary.txt`, `post_exploit_functions_summary.txt`.

### Next actions (checklist)
- [ ] Review the PR diff on `Offensive-toolkit` and merge to `main`.
- [ ] After merge, set default branch to `main` (if needed) in repo settings.
- [ ] Optional: purge any large vendor files that were pushed in earlier commits (see Cleanup) to silence GitHub warnings.
- [ ] Tag a release after validating build and tests.

### Local development quickstart
Backend/CLI
```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m cli.main -h
```

GUI frontend
```
cd gui/frontend
npm ci || npm i
npm run build
```

Run tests
```
pytest -q
```

### Notes
- LFS: repo uses Git LFS for `hydra.restore`. Ensure contributors run `git lfs install` once locally.
- Frontend: TypeScript/React app (Vite). Ensure `@types/react`, `@types/react-dom`, `@types/estree`, and `@vitejs/plugin-react-swc` are installed.
- Backend: Python 3.10+ recommended. See `requirements.txt`.

### Cleanup (optional, only if you want to remove large history blobs)
- If earlier commits included large vendor binaries (e.g., `gui/frontend/node_modules/...swc*.node`), you can rewrite history to remove them:
```
python3 -m pip install --user git-filter-repo
git filter-repo --invert-paths --path gui/frontend/node_modules --force
git push -f origin HEAD
```
Use with care; prefer doing this on a feature branch and opening a PR.

### Known modules/files of interest
- `core/`: orchestrators, services, integrations.
- `gui/server.py`: FastAPI backend for GUI.
- `gui/frontend/`: React/Vite frontend.
- `core/vuln_assessment.py`: new module present locally (track/commit after review if needed).

### Support matrix (high level)
- Recon → Exploit → Post-Exploit → Report/Walkthrough
- Services: HTTP, SSH, FTP, SMB, DNS, VNC, MySQL, PostgreSQL, AJP, Java RMI, RPC, IRC, NetBIOS, TNS (plus more via patterns).

### Maintainer checklist before release
- [ ] `pytest` passes
- [ ] Lint/format (black/isort/flake8) clean
- [ ] `npm run build` succeeds
- [ ] README usage verified
- [ ] Large files tracked via LFS only

