
import subprocess
import concurrent.futures
import re
from pathlib import Path
from typing import List


OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)


FAST_FLAGS = ["-sV", "-T4", "-Pn"]               
FULL_FLAGS = ["-sV", "-p-", "-T4", "-Pn"]        


# Créer chemin vers un fichier de sortie
def get_output_file(target: str, name: str) -> Path:
    return OUTPUT_DIR / f"{target}_{name}.txt"

# Lancer une commande shell et enregistrer la sortie
def run_command(cmd: List[str], output_path: Path):
    print(f"[CMD] ▶ {' '.join(cmd)}")
    with open(output_path, "w") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
    print(f"[OK] Résultat → {output_path}")

# Lancer un scan Nmap
def nmap_scan(target: str, flags: List[str], name: str) -> Path:
    output = get_output_file(target, name)
    run_command(["nmap", *flags, target, "-oN", str(output)], output)
    return output

# Extraire les services détectés depuis un rapport Nmap
def extract_services(nmap_output: Path) -> set:
    services = set()
    regex = re.compile(r"^(\d+)/(tcp|udp)\s+\S+\s+(\S+)")
    for line in nmap_output.read_text().splitlines():
        match = regex.match(line.strip())
        if match:
            services.add(match.group(3).lower())
    return services


def run_recon(target: str):
    from core import report  

    with concurrent.futures.ThreadPoolExecutor() as executor:
        
        fut_fast = executor.submit(nmap_scan, target, FAST_FLAGS, "fast")
        fut_full = executor.submit(nmap_scan, target, FULL_FLAGS, "full")
        

        
        fast_result = fut_fast.result()
        services = extract_services(fast_result)

        
        

        print(f"[+] Services détectés : {', '.join(sorted(services)) or 'aucun'}")

        
        for service in services:
            try:
                mod = __import__(f"core.services.{service}", fromlist=["footprint"])
            except ModuleNotFoundError:
                print(f"[!] Aucun module pour le service : {service}")
                continue

            if hasattr(mod, "footprint"):
                try:
                    print(f"[>] Footprinting du service : {service}")
                    mod.footprint(target)
                except Exception as e:
                    print(f"[!] Erreur dans {service}.footprint(): {e}")
            else:
                print(f"[!] Le module {service} n'a pas de fonction footprint()")

        
        fut_full.result()
        print("[+] Scan complet TCP terminé.")
        print("[+] Scan complet UDP terminé.")

    
    print("[+] Génération du rapport…")
    report.build_report(target)
    print("[✓] Reconnaissance terminée.")

# Entrée CLI
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Recon automatique avec services dynamiques")
    parser.add_argument("target", help="Adresse IP à scanner")
    args = parser.parse_args()
    run_recon(args.target)
