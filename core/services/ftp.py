import subprocess
from pathlib import Path

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

def _run(cmd, capture: bool = True):
    """Exécute la commande et retourne stdout+stderr en texte."""
    print(f"[ftp] ▶ {' '.join(cmd)}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    return result.stdout

def footprint(target: str):
    report_md = OUTPUT_DIR / f"{target}_ftp_report.md"
    print(f"[+] Génération du rapport FTP complet dans {report_md}")

    sections = {}

    sections["Nmap"] = _run([
        "nmap", "-p21", "-sV", "--script", "ftp-anon,ftp-syst,ftp-bounce,ftp-vuln*,ftp-libopie,ftp-proftpd-backdoor",
        target
    ])

    sections["Bannière FTP (netcat)"] = _run(["nc", "-nv", target, "21"])

    sections["Login anonyme"] = _run([
        "bash", "-c",
        f"ftp -n {target} <<EOF\nuser anonymous anonymous\nquit\nEOF"
    ])

    sections["Listing anonyme"] = _run([
        "bash", "-c",
        f"ftp -n {target} <<EOF\nuser anonymous anonymous\nls\nquit\nEOF"
    ])

    sections["Récupération README"] = _run([
        "bash", "-c",
        f"ftp -n {target} <<EOF\nuser anonymous anonymous\nget README -\nquit\nEOF"
    ])

# rapport final
    with report_md.open("w") as rpt:
        rpt.write(f"# FTP Report for {target}\n\n")

        for title, content in sections.items():
            rpt.write(f"## {title}\n")
            rpt.write("```bash\n")
            rpt.write(content.strip() + "\n")
            rpt.write("```\n\n")

        rpt.write("## Next Steps / Exploit Instructions\n")
        rpt.write("- Rechercher les versions vulnérables (e.g., `vsftpd 2.3.4`, `ProFTPD 1.3.5`) dans la section Nmap.\n")
        rpt.write("- Si `vsftpd 2.3.4` détecté → exploiter via Metasploit (exploit/unix/ftp/vsftpd_234_backdoor).\n")
        rpt.write("- Si `ProFTPD 1.3.5` détecté → exploiter via Metasploit (exploit/unix/ftp/proftpd_135).\n")
        rpt.write("- Si login anonyme réussi → tenter l’énumération ou l’upload de shell.\n")
        rpt.write("- Sinon → lancer un bruteforce avec Hydra ou Medusa (`hydra -L /usr/share/wordlists/users.txt -P /usr/share/wordlists/rockyou.txt {target} ftp -t 4 -f -V`).\n")
        rpt.write("- Vérifier les CVEs spécifiques dans les sorties Nmap et utiliser les modules Metasploit correspondants.\n")

    print(f"[✓] Rapport FTP complet généré : {report_md}")