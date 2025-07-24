import subprocess
from pathlib import Path

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

def _run(cmd):
    print(f"[ssh] ▶ {' '.join(cmd)}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, check=False)
    return result.stdout

def footprint(target: str):
    report = OUTPUT_DIR / f"{target}_ssh_report.md"
    print(f"[+] Génération du rapport SSH dans {report}")

    banner = _run(["ssh", "-vvv", "-o", "BatchMode=yes", f"{target}", "exit"]).splitlines()[0]
    version_scripts = _run([
        "nmap", "-p22", "-sV", "--script", "ssh-auth-methods,ssh-vuln*,ssh-version",
        target
    ])
    audit = _run(["bash", "-c", f"ssh-audit {target}"])

    with report.open("w") as rpt:
        rpt.write(f"# SSH Footprint – {target}\n\n")
        rpt.write("## 1. Bannière SSH\n```bash\n" + banner + "\n```\n\n")
        rpt.write("## 2. Nmap Version & Vulnérabilités\n```bash\n" + version_scripts + "\n```\n\n")
        rpt.write("## 3. Audit cryptographique (ssh-audit)\n```bash\n" + audit + "\n```\n\n")
        rpt.write("## 4. Recommandations\n")
        rpt.write("- Si bannière contient `openssh_5` ou `openssh_6`, utiliser Metasploit ssh_login.\n")
        rpt.write("- Si bannière contient `openssh_7`, utiliser Metasploit ssh_key_exchange.\n")
        rpt.write("- Si bannière contient `8.8p1`→`9.7p1`, vulnérable à CVE-2024-6387 (regreSSHion). Lancer PoC.\n")
        rpt.write("- Si `weak` ou `vulnerable` détecté, lancer un scan Metasploit ssh_version.\n")
        rpt.write("- En cas d’échec, bruteforce SSH avec Hydra ou Medusa.\n")

    print(f"[✓] Rapport SSH généré : {report}")