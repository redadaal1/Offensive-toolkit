#!/usr/bin/env python3
import subprocess
import logging
import requests
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple
import urllib.parse
from bs4 import BeautifulSoup
from core.config import config
logger = logging.getLogger(__name__)
try:
    from core.integrations import burp
except Exception:
    burp = None
try:
    from core.integrations import burp_runner
except Exception:
    burp_runner = None

OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

WORDLIST_DIR = "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
SUBDOMAIN_LIST = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
LINKFINDER_PATH = "/home/user/tools/LinkFinder/linkfinder.py"

def _run(cmd, timeout: int = None):
    logger.info("[http] ▶ %s", ' '.join(cmd))
    # Default per-tool timeout (seconds). Falls back to 300 if not set.
    tool_timeout = timeout or int(config.get("services.http.timeout") or 300)
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=tool_timeout,
        )
        return res.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"[timeout] Command exceeded {tool_timeout}s: {' '.join(cmd)}"

def _fetch_url(url):
    try:
        r = requests.get(url, timeout=10, verify=False)
        return r.text.strip()
    except requests.RequestException:
        return ''

def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def search_msf(query):
    """Enhanced Metasploit search with better banner parsing and exploitdb integration."""
    try:
        mods, cves = set(), set()
        
        # Handle version ranges with dash separator
        if "-" in query and "Linux" in query:
            match = re.search(r"Linux (\d+)\.(\d+)\.(\d+)?\s*-\s*(\d+)\.(\d+)\.(\d+)?", query)
            if match:
                v_start = (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))
                v_end = (int(match.group(4)), int(match.group(5)), int(match.group(6) or 0))
                current = list(v_start)
                while tuple(current) <= v_end:
                    version_str = f"Linux {current[0]}.{current[1]}.{current[2]}"
                    out = subprocess.getoutput(f"msfconsole -q -x 'search {version_str}; exit'")
                    found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
                    mods.update(strip_ansi(m.split()[1]) for m in found if m)
                    current[2] += 1
                    if current[2] > 99:
                        current[2] = 0
                        current[1] += 1
                        if current[1] > 99:
                            current[1] = 0
                            current[0] += 1
        else:
            # Handle HTTP banners with version separators
            if "Apache/" in query or "PHP/" in query:
                # Extract version numbers and search for each
                versions = re.findall(r'(\w+/\d+\.\d+\.\d+)', query)
                for version in versions:
                    out = subprocess.getoutput(f"msfconsole -q -x 'search {version}; exit'")
                    found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
                    mods.update(strip_ansi(m.split()[1]) for m in found if m)
                    
                    # Also search for major.minor versions
                    major_minor = re.search(r'(\w+/\d+\.\d+)', version)
                    if major_minor:
                        out = subprocess.getoutput(f"msfconsole -q -x 'search {major_minor.group(1)}; exit'")
                        found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
                        mods.update(strip_ansi(m.split()[1]) for m in found if m)
            else:
                # Generic search
                out = subprocess.getoutput(f"msfconsole -q -x 'search {query}; exit'")
                found = re.findall(r"^\s*\d+\s+exploit/\S+", out, re.MULTILINE)
                mods.update(strip_ansi(m.split()[1]) for m in found if m)
        
        # Get CVE information for found modules
        for mod in sorted(mods):
            info = subprocess.getoutput(f"msfconsole -q -x 'info {mod}; exit'")
            cves.update(re.findall(r"CVE-\d{4}-\d{4,7}", info))
        
        return sorted(mods), sorted(cves)
    except Exception as e:
        print(f"Error in search_msf for query '{query}': {e}")
        return [], []

def search_exploitdb(query):
    """Search ExploitDB for additional exploits."""
    try:
        exploits = []
        # Use searchsploit for ExploitDB search
        out = subprocess.getoutput(f"searchsploit {query}")
        lines = out.split('\n')
        for line in lines:
            if '|' in line and not line.startswith('Exploit Title'):
                parts = line.split('|')
                if len(parts) >= 3:
                    exploit = {
                        'title': parts[0].strip(),
                        'path': parts[1].strip(),
                        'type': parts[2].strip()
                    }
                    exploits.append(exploit)
        return exploits
    except Exception as e:
        print(f"ExploitDB search failed for query '{query}': {e}")
        return []

def extract_server_banner(header: str) -> str:
    match = re.search(r"Server:\s*(.+)", header, re.IGNORECASE)
    return match.group(1).strip() if match else "unknown"

def parse_nikto(output: str, target: str) -> Dict:
    findings = {"outdated_software": [], "security_headers_missing": [],
                "exposed_dirs": [], "default_files": [],
                "misconfigurations": [], "exploitable_versions": {},
                "vulnerable_endpoints": [], "auth_bypass_opportunities": []}
    
    for line in output.splitlines():
        line = line.strip()
        if 'Apache/' in line or 'PHP/' in line or 'Python/' in line:
            matches = re.findall(r'(Apache/\S+|PHP/\S+|Python/\S+)', line)
            findings["outdated_software"].extend(matches)
            for software in matches:
                mods, _ = search_msf(software)
                if mods:
                    findings["exploitable_versions"][software] = mods
        if any(h in line for h in ["X-Frame-Options", "X-Content-Type-Options"]):
            if "not" in line:
                header = re.search(r"(X-[^\s]+)", line)
                if header:
                    findings["security_headers_missing"].append(header.group(1))
        if any(p in line for p in ["/admin", "/backup", "/config", "/phpMyAdmin"]):
            path = re.search(r"(/\S+)", line)
            if path:
                findings["exposed_dirs"].append(path.group(1))
                # Add to vulnerable endpoints for exploitation
                findings["vulnerable_endpoints"].append({
                    "url": f"http://{target}{path.group(1)}",
                    "type": "admin_panel",
                    "parameters": ["username", "password", "user", "pass"]
                })
        if "/robots.txt" in line or ".php" in line:
            path = re.search(r"(/\S+)", line)
            if path:
                findings["default_files"].append(path.group(1))
                # Add PHP files as potential injection points
                if path.group(1).endswith('.php'):
                    findings["vulnerable_endpoints"].append({
                        "url": f"http://{target}{path.group(1)}",
                        "type": "php_file",
                        "parameters": ["id", "file", "page", "include", "path", "cmd", "exec"]
                    })
        if "TRACE method is active" in line:
            findings["misconfigurations"].append("HTTP TRACE Method Enabled (XST Attack)")
            findings["auth_bypass_opportunities"].append("HTTP TRACE Method")
        if "mod_negotiation" in line and "MultiViews" in line:
            findings["misconfigurations"].append("mod_negotiation + MultiViews Enabled (Brute-force Files)")
        if "ETags" in line or "inode" in line:
            findings["misconfigurations"].append("ETag Information Leak (Inode Leakage)")
    return findings

def parse_gobuster_dir(output: str, target: str) -> List[Dict]:
    """Enhanced gobuster parsing with better categorization and phpMyAdmin detection."""
    paths = list(set(re.findall(r"/(\S+)\s+\(Status:", output)))
    vulnerable_endpoints = []
    
    for path in paths:
        full_url = f"http://{target}/{path}"
        
        # Enhanced categorization with more specific detection
        if any(keyword in path.lower() for keyword in ["admin", "administrator", "manage", "panel", "dashboard"]):
            vulnerable_endpoints.append({
                "url": full_url,
                "type": "admin_panel",
                "parameters": ["username", "password", "user", "pass", "admin", "login", "auth"]
            })
        elif any(keyword in path.lower() for keyword in ["phpmyadmin", "mysql", "database", "db"]):
            vulnerable_endpoints.append({
                "url": full_url,
                "type": "database_admin",
                "parameters": ["username", "password", "user", "pass", "pma_username", "pma_password"]
            })
        elif any(keyword in path.lower() for keyword in ["upload", "file", "media", "images", "files"]):
            vulnerable_endpoints.append({
                "url": full_url,
                "type": "upload_directory",
                "parameters": ["file", "upload", "image", "document", "attachment"]
            })
        elif path.endswith(('.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl')):
            vulnerable_endpoints.append({
                "url": full_url,
                "type": "dynamic_file",
                "parameters": ["id", "file", "page", "include", "path", "cmd", "exec", "param", "action"]
            })
        elif any(keyword in path.lower() for keyword in ["search", "query", "filter", "find"]):
            vulnerable_endpoints.append({
                "url": full_url,
                "type": "search_function",
                "parameters": ["q", "query", "search", "term", "keyword", "s"]
            })
        elif any(keyword in path.lower() for keyword in ["login", "auth", "signin", "user"]):
            vulnerable_endpoints.append({
                "url": full_url,
                "type": "authentication",
                "parameters": ["username", "password", "user", "pass", "email", "login"]
            })
        elif any(keyword in path.lower() for keyword in ["api", "rest", "json", "xml"]):
            vulnerable_endpoints.append({
                "url": full_url,
                "type": "api_endpoint",
                "parameters": ["id", "param", "data", "token", "key"]
            })
        elif any(keyword in path.lower() for keyword in ["backup", "bak", "old", "backup", "config", "conf"]):
            vulnerable_endpoints.append({
                "url": full_url,
                "type": "sensitive_file",
                "parameters": ["file", "path", "include"]
            })
        else:
            vulnerable_endpoints.append({
                "url": full_url,
                "type": "general_endpoint",
                "parameters": ["id", "file", "page", "param", "action"]
            })
    
    return vulnerable_endpoints

def parse_vhost(output: str) -> List[str]:
    hosts = []
    for line in output.splitlines():
        if line.startswith("http://") or line.startswith("https://"):
            hosts.append(line.split()[0])
    return list(set(hosts))

def parse_linkfinder(output: str, target: str) -> List[Dict]:
    endpoints = list(set(re.findall(r"(https?://[\w\./?=&%-]+)", output)))
    vulnerable_endpoints = []
    
    for endpoint in endpoints:
        # Parse URL to extract parameters
        parsed = urllib.parse.urlparse(endpoint)
        params = urllib.parse.parse_qs(parsed.query)
        
        # Determine endpoint type based on path and parameters
        path = parsed.path.lower()
        if any(keyword in path for keyword in ["admin", "login", "auth"]):
            endpoint_type = "authentication"
            parameters = list(params.keys()) + ["username", "password", "user", "pass"]
        elif any(keyword in path for keyword in ["upload", "file", "media"]):
            endpoint_type = "file_upload"
            parameters = list(params.keys()) + ["file", "upload", "image"]
        elif any(keyword in path for keyword in ["search", "query", "filter"]):
            endpoint_type = "search_function"
            parameters = list(params.keys()) + ["q", "query", "search", "term"]
        elif any(keyword in path for keyword in ["api", "rest", "json"]):
            endpoint_type = "api_endpoint"
            parameters = list(params.keys()) + ["id", "param", "data"]
        else:
            endpoint_type = "general_endpoint"
            parameters = list(params.keys()) + ["id", "file", "page", "param"]
        
        vulnerable_endpoints.append({
            "url": endpoint,
            "type": endpoint_type,
            "parameters": list(set(parameters))  # Remove duplicates
        })
    
    return vulnerable_endpoints

def parse_wayback(output: str) -> List[str]:
    try:
        data = json.loads(output)
        return list({item for item in (data[1:] if len(data) > 1 else [])})
    except Exception:
        return []

def parse_dnsrecon(output: str, target: str) -> List[str]:
    return list(set(re.findall(r"\s(\S+\.%s)" % re.escape(target), output)))

def parse_whatweb(output: str) -> Dict:
    """Parse whatweb output for technology detection."""
    technologies = {
        "web_server": [],
        "programming_language": [],
        "framework": [],
        "cms": [],
        "database": [],
        "javascript": [],
        "other": []
    }
    
    # Extract technologies from whatweb output
    if "Apache" in output:
        technologies["web_server"].append("Apache")
    if "nginx" in output.lower():
        technologies["web_server"].append("nginx")
    if "PHP" in output:
        technologies["programming_language"].append("PHP")
    if "WordPress" in output:
        technologies["cms"].append("WordPress")
    if "Joomla" in output:
        technologies["cms"].append("Joomla")
    if "Drupal" in output:
        technologies["cms"].append("Drupal")
    if "MySQL" in output:
        technologies["database"].append("MySQL")
    if "jQuery" in output:
        technologies["javascript"].append("jQuery")
    
    return technologies

def parse_wpscan(output: str) -> Dict:
    """Parse wpscan output for WordPress vulnerabilities."""
    wp_findings = {
        "version": "unknown",
        "plugins": [],
        "themes": [],
        "vulnerabilities": []
    }
    
    # Extract WordPress version
    version_match = re.search(r"WordPress version: (\d+\.\d+\.\d+)", output)
    if version_match:
        wp_findings["version"] = version_match.group(1)
    
    # Extract plugins
    plugin_matches = re.findall(r"Plugin: ([^\s]+)", output)
    wp_findings["plugins"] = plugin_matches
    
    # Extract themes
    theme_matches = re.findall(r"Theme: ([^\s]+)", output)
    wp_findings["themes"] = theme_matches
    
    # Extract vulnerabilities
    vuln_matches = re.findall(r"Vulnerability: ([^\n]+)", output)
    wp_findings["vulnerabilities"] = vuln_matches
    
    return wp_findings

def parse_joomscan(output: str) -> Dict:
    """Parse joomscan output for Joomla vulnerabilities."""
    joomla_findings = {
        "version": "unknown",
        "components": [],
        "vulnerabilities": []
    }
    
    # Extract Joomla version
    version_match = re.search(r"Joomla version: (\d+\.\d+\.\d+)", output)
    if version_match:
        joomla_findings["version"] = version_match.group(1)
    
    # Extract components
    component_matches = re.findall(r"Component: ([^\s]+)", output)
    joomla_findings["components"] = component_matches
    
    # Extract vulnerabilities
    vuln_matches = re.findall(r"Vulnerability: ([^\n]+)", output)
    joomla_findings["vulnerabilities"] = vuln_matches
    
    return joomla_findings

def parse_sqlmap_basic(output: str) -> Dict:
    """Parse sqlmap basic scan output."""
    sqlmap_findings = {
        "injectable_parameters": [],
        "database_type": "unknown",
        "technique": "unknown"
    }
    
    # Extract injectable parameters
    param_matches = re.findall(r"Parameter: ([^\s]+)", output)
    sqlmap_findings["injectable_parameters"] = param_matches
    
    # Extract database type
    if "MySQL" in output:
        sqlmap_findings["database_type"] = "MySQL"
    elif "PostgreSQL" in output:
        sqlmap_findings["database_type"] = "PostgreSQL"
    elif "SQLite" in output:
        sqlmap_findings["database_type"] = "SQLite"
    
    # Extract technique
    if "boolean-based" in output:
        sqlmap_findings["technique"] = "boolean-based"
    elif "time-based" in output:
        sqlmap_findings["technique"] = "time-based"
    elif "union-based" in output:
        sqlmap_findings["technique"] = "union-based"
    
    return sqlmap_findings

def test_sql_injection_endpoints(endpoints: List[Dict]) -> List[Dict]:
    """Test discovered endpoints for SQL injection vulnerabilities."""
    sql_vulnerable = []
    
    for endpoint in endpoints:
        if endpoint["type"] in ["dynamic_file", "search_function", "general_endpoint"]:
            for param in endpoint["parameters"]:
                # Test for SQL injection
                test_url = f"{endpoint['url']}?{param}=1'"
                try:
                    response = requests.get(test_url, timeout=5, verify=False)
                    if any(error in response.text.lower() for error in ["sql", "mysql", "oracle", "postgresql", "sqlite"]):
                        sql_vulnerable.append({
                            "url": endpoint["url"],
                            "parameter": param,
                            "type": "sql_injection",
                            "evidence": "SQL error detected"
                        })
                except:
                    continue
    
    return sql_vulnerable

def test_xss_endpoints(endpoints: List[Dict]) -> List[Dict]:
    """Test discovered endpoints for XSS vulnerabilities."""
    xss_vulnerable = []
    
    for endpoint in endpoints:
        if endpoint["type"] in ["search_function", "general_endpoint"]:
            for param in endpoint["parameters"]:
                # Test for XSS
                test_payload = "<script>alert('XSS')</script>"
                test_url = f"{endpoint['url']}?{param}={urllib.parse.quote(test_payload)}"
                try:
                    response = requests.get(test_url, timeout=5, verify=False)
                    if test_payload in response.text:
                        xss_vulnerable.append({
                            "url": endpoint["url"],
                            "parameter": param,
                            "type": "xss",
                            "evidence": "XSS payload reflected"
                        })
                except:
                    continue
    
    return xss_vulnerable

def test_lfi_endpoints(endpoints: List[Dict]) -> List[Dict]:
    """Test discovered endpoints for LFI vulnerabilities."""
    lfi_vulnerable = []
    
    for endpoint in endpoints:
        if endpoint["type"] in ["dynamic_file", "general_endpoint"]:
            for param in endpoint["parameters"]:
                if param in ["file", "include", "path", "page"]:
                    # Test for LFI
                    test_payload = "../../../etc/passwd"
                    test_url = f"{endpoint['url']}?{param}={urllib.parse.quote(test_payload)}"
                    try:
                        response = requests.get(test_url, timeout=5, verify=False)
                        content = response.text
                        if ("root:" in content and ":0:0:" in content) or ("bin:/" in content):
                            lfi_vulnerable.append({
                                "url": endpoint["url"],
                                "parameter": param,
                                "type": "lfi",
                                "evidence": "LFI vulnerability confirmed (passwd markers present)"
                            })
                    except:
                        continue
    
    return lfi_vulnerable

def find_login_form(url: str) -> Tuple[object, Dict, str]:
    """Find login forms on a webpage and return form, cookies, and URL."""
    try:
        r = requests.get(url, timeout=5, verify=False)
    except:
        return None, {}, ""

    soup = BeautifulSoup(r.text, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        inputs = form.find_all("input")
        input_names = [i.get("name") for i in inputs if i.get("name")]
        if any("user" in (name or "").lower() or "email" in (name or "").lower() for name in input_names) \
           and any("pass" in (name or "").lower() for name in input_names):
            return form, r.cookies.get_dict(), r.url
    return None, {}, ""

def build_request_file(form: object, cookies: Dict, page_url: str, target: str) -> Tuple[str, List[str]]:
    """Build a request file for sqlmap testing."""
    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")

    # Prepare post data with test values
    data_pairs = []
    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue
        if "user" in name.lower() or "email" in name.lower():
            value = "admin"
        elif "pass" in name.lower():
            value = "admin"
        else:
            value = inp.get("value", "")
        data_pairs.append(f"{name}={value}")
    post_data = "&".join(data_pairs)

    target_path = urllib.parse.urljoin(page_url, action)
    host = target_path.split("/")[2]
    
    req_content = f"""POST {target_path.replace('http://'+host, '')} HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Accept: */*
Cookie: {"; ".join(f"{k}={v}" for k, v in cookies.items())}

{post_data}
"""
    req_file = OUTPUT_DIR / f"{target}_login.req"
    with req_file.open("w") as f:
        f.write(req_content)
    
    params = [name for name, _ in (i.split("=") for i in data_pairs) if "user" in name.lower() or "email" in name.lower()]
    return str(req_file), params

def test_login_form_sql_injection(base_url: str, target: str) -> Tuple[bool, str, str, Dict]:
    """Test login forms for SQL injection using the smart detection method."""
    logger.info("[http] Testing login forms for SQL injection on %s", base_url)
    
    # Find login form
    form, cookies, page_url = find_login_form(base_url)
    if not form:
        print("[http] No login form found")
        return False, "", "", {}
    
    print(f"[http] Login form found at {page_url}")
    
    # Build request file
    req_file, params = build_request_file(form, cookies, page_url, target)
    logger.info("[http] Request file created: %s, testing parameters: %s", req_file, params)
    
    # Test each parameter with sqlmap
    successful_injections = []
    for param in params:
        sqlmap_cmd = [
            "sqlmap", "-r", req_file, "-p", param,
            "--risk=3", "--level=5", "--batch",
            "--random-agent", "--timeout=15", "--threads=1"
        ]
        
        output = _run(sqlmap_cmd)
        text = (output or "").lower()
        
        # Check for successful injection
        if any(s in text for s in [
            "parameter is vulnerable", "is injectable", "the back-end dbms is",
            "injection point found", "vulnerable to"
        ]):
            successful_injections.append({
                "parameter": param,
                "url": page_url,
                "output": output[:1000]
            })
    
    if successful_injections:
        proof = f"SQL injection found in login form parameters: {[s['parameter'] for s in successful_injections]}"
        poc = f"sqlmap -r {req_file} -p {' '.join([s['parameter'] for s in successful_injections])} --risk=3 --level=5"
        evidence = {
            "type": "login_form_sql_injection",
            "form_url": page_url,
            "vulnerable_parameters": [s['parameter'] for s in successful_injections],
            "sqlmap_output": successful_injections[0]['output'],
            "request_file": req_file
        }
        return True, proof, poc, evidence
    
    return False, "", "", {}

def test_upload_endpoints(endpoints: List[Dict]) -> List[Dict]:
    """Test discovered endpoints for file upload vulnerabilities."""
    upload_vulnerable = []
    
    for endpoint in endpoints:
        if endpoint["type"] == "upload_directory":
            # Test if upload directory is accessible
            try:
                response = requests.get(endpoint["url"], timeout=5, verify=False)
                if response.status_code == 200:
                    upload_vulnerable.append({
                        "url": endpoint["url"],
                        "type": "file_upload",
                        "evidence": "Upload directory accessible"
                    })
            except:
                continue
    
    return upload_vulnerable

def footprint(target: str) -> Dict:
    report = OUTPUT_DIR / f"{target}_http_report.md"
    logger.info("[+] Generating HTTP recon report: %s", report)
    
    # Enhanced reconnaissance with more tools
    sections = {
        "os_fingerprint": _run(["nmap", "-O", "-Pn", target]),
        "banner_http": _run(["curl", "-I", f"http://{target}"]),
        "banner_https": _run(["curl", "-I", f"https://{target}"]),
        "nikto": _run(["nikto", "-h", target, "-Tuning", "b"]),
        "gobuster_dir": _run(["gobuster", "dir", "-u", f"http://{target}", "-w", WORDLIST_DIR, "-x", "php,txt,bak,zip,config", "-t", "50"]),
        "gobuster_dir_large": _run(["gobuster", "dir", "-u", f"http://{target}", "-w", "/usr/share/wordlists/seclists/Discovery/Web-Content/big.txt", "-x", "php,txt,bak,zip,config", "-t", "50"]),
        "gobuster_vhost": _run(["gobuster", "vhost", "-u", f"http://{target}", "-w", SUBDOMAIN_LIST]),
        "gobuster_subdomain": _run(["gobuster", "dns", "-d", target, "-w", "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"]),
        "linkfinder": _run(["python3", LINKFINDER_PATH, "-i", f"http://{target}", "-o", "cli"]),
        "wayback": _fetch_url(f"https://web.archive.org/cdx/search?url={target}/*&output=json&fl=original"),
        "dnsrecon": _run(["dnsrecon", "-d", target, "-t", "std"]),
        "dirb": _run(["dirb", f"http://{target}", "/usr/share/dirb/wordlists/common.txt"]),
        "wfuzz": _run(["wfuzz", "-w", "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt", "-u", f"http://{target}/FUZZ"]),
        "whatweb": _run(["whatweb", f"http://{target}"]),
        # WPScan can hang due to update checks/network; disable update and force non-interactive run
        "wpscan": _run([
            "wpscan", "--url", f"http://{target}",
            "--enumerate", "p",
            "--random-user-agent",
            "--no-update",
            "--force",
            "--request-timeout", "30"
        ]),
        "joomscan": _run(["joomscan", "--url", f"http://{target}"]),
        "sqlmap_basic": _run(["sqlmap", "-u", f"http://{target}/", "--batch", "--random-agent", "--level", "1", "--risk", "1"]),
    }
    
    os_version = "unknown"
    if "OS details:" in sections["os_fingerprint"]:
        m = re.search(r"OS details:\s+(.+)", sections["os_fingerprint"])
        if m:
            os_version = m.group(1).strip()
    
    http_banner = extract_server_banner(sections["banner_http"])
    https_banner = extract_server_banner(sections["banner_https"])
    
    # Parse findings from all tools
    nikto_findings = parse_nikto(sections["nikto"], target)
    gobuster_endpoints = parse_gobuster_dir(sections["gobuster_dir"], target)
    gobuster_large_endpoints = parse_gobuster_dir(sections["gobuster_dir_large"], target)
    linkfinder_endpoints = parse_linkfinder(sections["linkfinder"], target)
    whatweb_tech = parse_whatweb(sections["whatweb"])
    wpscan_findings = parse_wpscan(sections["wpscan"])
    joomscan_findings = parse_joomscan(sections["joomscan"])
    sqlmap_findings = parse_sqlmap_basic(sections["sqlmap_basic"])
    
    # Combine all endpoints (remove duplicates)
    all_endpoints = gobuster_endpoints + gobuster_large_endpoints + linkfinder_endpoints
    unique_endpoints = []
    seen_urls = set()
    for endpoint in all_endpoints:
        if endpoint["url"] not in seen_urls:
            unique_endpoints.append(endpoint)
            seen_urls.add(endpoint["url"])

    # Optional: Run Burp Suite scan against discovered URLs (existing REST client)
    burp_summary = {}
    if config.get("integrations.burp.enabled", False) and burp is not None:
        try:
            seed_urls = [f"http://{target}/"]
            seed_urls.extend([e["url"] for e in unique_endpoints if e.get("url")])
            # Deduplicate and cap to reasonable size
            deduped = []
            seen = set()
            for u in seed_urls:
                if u not in seen:
                    seen.add(u)
                    deduped.append(u)
            urls_to_scan = deduped[:100]
            burp_result = burp.scan_urls(target, urls_to_scan)
            burp_summary = burp_result.get("summary", {}) or {}
        except Exception as e:
            print(f"[!] Burp integration error: {e}")

    # Optional: Run Burp via local runner (headless jar + REST)
    burp_runner_result = {}
    if config.get("integrations.burpRunner.enabled", False) and burp_runner is not None:
        try:
            ok, issues_path, meta_path = burp_runner.run_single_target(f"http://{target}/")
            if meta_path and str(meta_path):
                try:
                    burp_runner_result = json.loads(Path(meta_path).read_text(encoding="utf-8"))
                except Exception:
                    burp_runner_result = {"meta_path": str(meta_path)}
        except Exception as e:
            print(f"[!] Burp runner error: {e}")
    
    # Test endpoints for specific vulnerabilities
    sql_vulnerable = test_sql_injection_endpoints(unique_endpoints)
    xss_vulnerable = test_xss_endpoints(unique_endpoints)
    lfi_vulnerable = test_lfi_endpoints(unique_endpoints)
    upload_vulnerable = test_upload_endpoints(unique_endpoints)
    
    # Test login forms for SQL injection
    print(f"[+] Testing login forms for SQL injection on {target}")
    login_sql_success, login_sql_proof, login_sql_poc, login_sql_evidence = test_login_form_sql_injection(f"http://{target}", target)
    
    # Enhanced metadata with all findings
    metadata = {
        "target": target,
        "os_fingerprint": os_version,
        "http_banner": http_banner,
        "https_banner": https_banner,
        "discovered_endpoints": unique_endpoints,
        "vulnerable_endpoints": {
            "sql_injection": sql_vulnerable,
            "xss": xss_vulnerable,
            "lfi": lfi_vulnerable,
            "file_upload": upload_vulnerable
        },
        "auth_bypass_opportunities": nikto_findings["auth_bypass_opportunities"],
        "exposed_directories": nikto_findings["exposed_dirs"],
        "default_files": nikto_findings["default_files"],
        "misconfigurations": nikto_findings["misconfigurations"],
        "outdated_software": nikto_findings["outdated_software"],
        "exploitable_versions": nikto_findings["exploitable_versions"],
        "vhosts": parse_vhost(sections["gobuster_vhost"]),
        "subdomains": parse_vhost(sections["gobuster_subdomain"]),
        "wayback_urls": parse_wayback(sections["wayback"]),
        "dns_records": parse_dnsrecon(sections["dnsrecon"], target),
        "technologies": whatweb_tech,
        "wordpress_findings": wpscan_findings,
        "joomla_findings": joomscan_findings,
        "sqlmap_findings": sqlmap_findings,
        "burp_summary": burp_summary,
        "burp_runner": burp_runner_result,
        "login_form_sql_injection": {
            "success": login_sql_success,
            "proof": login_sql_proof,
            "poc": login_sql_poc,
            "evidence": login_sql_evidence
        }
    }
    
    # Enhanced Metasploit and ExploitDB searches
    print(f"[+] Searching Metasploit for OS: {os_version}")
    try:
        msf_os_mods, msf_os_cves = search_msf(os_version) if os_version != "unknown" else ([], [])
    except Exception as e:
        print(f"Error searching Metasploit for OS: {e}")
        msf_os_mods, msf_os_cves = [], []
    
    print(f"[+] Searching Metasploit for HTTP banner: {http_banner}")
    try:
        msf_http_mods, msf_http_cves = search_msf(http_banner) if http_banner != "unknown" else ([], [])
    except Exception as e:
        print(f"Error searching Metasploit for HTTP banner: {e}")
        msf_http_mods, msf_http_cves = [], []
    
    print(f"[+] Searching Metasploit for HTTPS banner: {https_banner}")
    try:
        msf_https_mods, msf_https_cves = search_msf(https_banner) if https_banner != "unknown" else ([], [])
    except Exception as e:
        print(f"Error searching Metasploit for HTTPS banner: {e}")
        msf_https_mods, msf_https_cves = [], []
    
    # Search ExploitDB for additional exploits
    print(f"[+] Searching ExploitDB for OS: {os_version}")
    try:
        exploitdb_os = search_exploitdb(os_version) if os_version != "unknown" else []
    except Exception as e:
        print(f"Error searching ExploitDB for OS: {e}")
        exploitdb_os = []
    
    print(f"[+] Searching ExploitDB for HTTP banner: {http_banner}")
    try:
        exploitdb_http = search_exploitdb(http_banner) if http_banner != "unknown" else []
    except Exception as e:
        print(f"Error searching ExploitDB for HTTP banner: {e}")
        exploitdb_http = []
    
    # Search for specific software versions found
    all_software = nikto_findings["outdated_software"] + [http_banner, https_banner]
    exploitdb_software = []
    for software in all_software:
        if software != "unknown":
            print(f"[+] Searching ExploitDB for: {software}")
            try:
                exploitdb_software.extend(search_exploitdb(software))
            except Exception as e:
                print(f"Error searching ExploitDB for {software}: {e}")
                continue
    
    metadata.update({
        "os_exploit_found": "yes" if msf_os_mods else "no",
        "os_exploit_mods": msf_os_mods or ["none"],
        "os_exploit_cves": msf_os_cves or ["none"],
        "os_exploitdb_exploits": exploitdb_os,
        "http_exploit_found": "yes" if msf_http_mods else "no",
        "http_exploit_mods": msf_http_mods or ["none"],
        "http_exploit_cves": msf_http_cves or ["none"],
        "http_exploitdb_exploits": exploitdb_http,
        "https_exploit_found": "yes" if msf_https_mods else "no",
        "https_exploit_mods": msf_https_mods or ["none"],
        "https_exploit_cves": msf_https_cves or ["none"],
        "software_exploitdb_exploits": exploitdb_software
    })
    
    # Write comprehensive report
    with report.open("w") as rpt:
        rpt.write("# HTTP Reconnaissance Report\n")
        rpt.write(f"## Target: {target}\n\n")
        
        # Executive Summary
        rpt.write("## Executive Summary\n")
        rpt.write(f"- **OS Detected**: {os_version}\n")
        rpt.write(f"- **HTTP Server**: {http_banner}\n")
        rpt.write(f"- **HTTPS Server**: {https_banner}\n")
        rpt.write(f"- **Total Endpoints Discovered**: {len(unique_endpoints)}\n")
        rpt.write(f"- **SQL Injection Vulnerabilities**: {len(sql_vulnerable)}\n")
        rpt.write(f"- **XSS Vulnerabilities**: {len(xss_vulnerable)}\n")
        rpt.write(f"- **LFI Vulnerabilities**: {len(lfi_vulnerable)}\n")
        rpt.write(f"- **File Upload Vulnerabilities**: {len(upload_vulnerable)}\n")
        rpt.write(f"- **Login Form SQL Injection**: {'Yes' if login_sql_success else 'No'}\n")
        rpt.write(f"- **Metasploit OS Exploits**: {len(msf_os_mods) if msf_os_mods else 0}\n")
        rpt.write(f"- **Metasploit HTTP Exploits**: {len(msf_http_mods) if msf_http_mods else 0}\n")
        rpt.write(f"- **ExploitDB Exploits**: {len(exploitdb_software)}\n\n")
        
        # Technology Stack
        if whatweb_tech:
            rpt.write("## Technology Stack\n")
            for tech_type, technologies in whatweb_tech.items():
                if technologies:
                    rpt.write(f"### {tech_type.replace('_', ' ').title()}\n")
                    for tech in technologies:
                        rpt.write(f"- {tech}\n")
                    rpt.write("\n")
        
        # WordPress Findings
        if wpscan_findings["version"] != "unknown":
            rpt.write("## WordPress Analysis\n")
            rpt.write(f"- **Version**: {wpscan_findings['version']}\n")
            if wpscan_findings["plugins"]:
                rpt.write(f"- **Plugins**: {', '.join(wpscan_findings['plugins'])}\n")
            if wpscan_findings["themes"]:
                rpt.write(f"- **Themes**: {', '.join(wpscan_findings['themes'])}\n")
            if wpscan_findings["vulnerabilities"]:
                rpt.write("### Vulnerabilities\n")
                for vuln in wpscan_findings["vulnerabilities"]:
                    rpt.write(f"- {vuln}\n")
            rpt.write("\n")
        
        # Joomla Findings
        if joomscan_findings["version"] != "unknown":
            rpt.write("## Joomla Analysis\n")
            rpt.write(f"- **Version**: {joomscan_findings['version']}\n")
            if joomscan_findings["components"]:
                rpt.write(f"- **Components**: {', '.join(joomscan_findings['components'])}\n")
            if joomscan_findings["vulnerabilities"]:
                rpt.write("### Vulnerabilities\n")
                for vuln in joomscan_findings["vulnerabilities"]:
                    rpt.write(f"- {vuln}\n")
            rpt.write("\n")
        
        # SQLMap Findings
        if sqlmap_findings["injectable_parameters"]:
            rpt.write("## SQL Injection Analysis\n")
            rpt.write(f"- **Database Type**: {sqlmap_findings['database_type']}\n")
            rpt.write(f"- **Technique**: {sqlmap_findings['technique']}\n")
            rpt.write(f"- **Injectable Parameters**: {', '.join(sqlmap_findings['injectable_parameters'])}\n\n")
        
        # Vulnerable Endpoints
        rpt.write("## Vulnerable Endpoints\n")
        for vuln_type, endpoints in metadata["vulnerable_endpoints"].items():
            if endpoints:
                rpt.write(f"### {vuln_type.replace('_', ' ').title()}\n")
                for endpoint in endpoints:
                    rpt.write(f"- {endpoint['url']} (param: {endpoint.get('parameter', 'N/A')})\n")
                rpt.write("\n")
        
        # Exploit Modules
        if msf_os_mods and msf_os_mods != ["none"]:
            rpt.write("## Metasploit OS Exploits\n")
            for module in msf_os_mods:
                rpt.write(f"- {module}\n")
            rpt.write("\n")
        
        if msf_http_mods and msf_http_mods != ["none"]:
            rpt.write("## Metasploit HTTP Exploits\n")
            for module in msf_http_mods:
                rpt.write(f"- {module}\n")
            rpt.write("\n")
        
        if exploitdb_software:
            rpt.write("## ExploitDB Exploits\n")
            for exploit in exploitdb_software[:10]:  # Show first 10
                rpt.write(f"- {exploit['title']} ({exploit['type']})\n")
            if len(exploitdb_software) > 10:
                rpt.write(f"- ... and {len(exploitdb_software) - 10} more exploits\n")
            rpt.write("\n")
        
        # Discovered Endpoints by Category
        rpt.write("## Discovered Endpoints by Category\n")
        categories = {}
        for endpoint in unique_endpoints:
            cat = endpoint["type"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(endpoint["url"])
        
        for category, urls in categories.items():
            rpt.write(f"### {category.replace('_', ' ').title()} ({len(urls)})\n")
            for url in urls[:5]:  # Show first 5
                rpt.write(f"- {url}\n")
            if len(urls) > 5:
                rpt.write(f"- ... and {len(urls) - 5} more\n")
            rpt.write("\n")
        
        # Raw Tool Output
        rpt.write("## Raw Tool Output\n")
        for name, content in sections.items():
            rpt.write(f"### {name.replace('_', ' ').title()}\n")
            rpt.write("```bash\n")
            rpt.write(content + "\n")
            rpt.write("```\n\n")
        
        # Complete Metadata
        rpt.write("## Complete Metadata\n")
        for k, v in metadata.items():
            key_title = k.capitalize().replace('_', ' ')
            if isinstance(v, list):
                rpt.write(f"- {key_title}:\n")
                for item in v:
                    rpt.write(f"  - {item}\n")
            elif isinstance(v, dict):
                rpt.write(f"- {key_title}:\n")
                for subk, subv in v.items():
                    rpt.write(f"  - {subk}:\n")
                    if isinstance(subv, list):
                        for i in subv:
                            rpt.write(f"    - {i}\n")
                    elif isinstance(subv, dict):
                        for subk2, subv2 in subv.items():
                            rpt.write(f"    - {subk2}: {subv2}\n")
                    else:
                        rpt.write(f"    - {subv}\n")
            else:
                rpt.write(f"- {key_title}: {v}\n")
    
    # Save metadata
    with (OUTPUT_DIR / f"{target}_http_metadata.json").open("w") as json_file:
        json.dump(metadata, json_file, indent=2)
    
    print(f"[+] Report written: {report}")
    print(f"[+] Metadata JSON written: {OUTPUT_DIR / f'{target}_http_metadata.json'}")
    print(f"[+] Found {len(unique_endpoints)} unique endpoints across all tools")
    print(f"[+] Vulnerabilities: {len(sql_vulnerable)} SQL injection, {len(xss_vulnerable)} XSS, {len(lfi_vulnerable)} LFI, {len(upload_vulnerable)} upload")
    print(f"[+] Metasploit: {len(msf_os_mods) if msf_os_mods else 0} OS exploits, {len(msf_http_mods) if msf_http_mods else 0} HTTP exploits")
    print(f"[+] ExploitDB: {len(exploitdb_software)} additional exploits found")
    print(f"[+] Technologies: {sum(len(techs) for techs in whatweb_tech.values())} technologies detected")
    if wpscan_findings["version"] != "unknown":
        print(f"[+] WordPress: {wpscan_findings['version']} with {len(wpscan_findings['plugins'])} plugins")
    if joomscan_findings["version"] != "unknown":
        print(f"[+] Joomla: {joomscan_findings['version']} with {len(joomscan_findings['components'])} components")
    if sqlmap_findings["injectable_parameters"]:
        print(f"[+] SQLMap: {len(sqlmap_findings['injectable_parameters'])} injectable parameters found")
    
    return metadata

if __name__ == "__main__":
    import sys
    footprint(sys.argv[1])