# Offensive Security Automation Toolkit

A comprehensive penetration testing automation toolkit that performs reconnaissance, exploitation, post-exploitation, and generates detailed reports with proof of concepts.

## 🚀 Features

### **Reconnaissance**
- **Network Scanning**: Nmap integration with fast/full/UDP scans
- **Service Enumeration**: Comprehensive service fingerprinting
- **Vulnerability Assessment**: Nikto, Gobuster, SQLMap integration
- **Web Application Testing**: Directory bruteforcing, parameter discovery
- **DNS Enumeration**: Subdomain discovery and DNS reconnaissance

### **Exploitation**
- **Multi-Service Support**: HTTP, FTP, SSH, Telnet, SMB, MySQL, PostgreSQL, VNC, NFS
- **Metasploit Integration**: Automated exploit module selection and execution
- **Brute Force**: Hydra integration with rockyou.txt support
- **Custom Exploits**: Service-specific exploitation scripts
- **Proof of Concept**: Detailed exploitation evidence collection

### **Post-Exploitation**
- **Privilege Escalation**: SUID, Sudo, cron, kernel exploits
- **Data Exfiltration**: Sensitive file download and analysis
- **Persistence**: Backdoor creation and maintenance
- **Network Discovery**: Internal network mapping
- **System Information**: Comprehensive system enumeration

### **Reporting**
- **Professional Reports**: HTML, PDF, and Markdown formats
- **Executive Summary**: High-level findings and recommendations
- **Technical Details**: Step-by-step exploitation walkthroughs
- **Proof of Concepts**: Screenshots, command outputs, and evidence
- **Remediation**: Detailed security recommendations

## 📋 Requirements

### **System Requirements**
- Python 3.8+
- Linux/Unix environment (Kali Linux recommended)
- 4GB+ RAM
- 10GB+ disk space

### **External Tools**
```bash
# Essential tools
sudo apt update
sudo apt install -y nmap hydra metasploit-framework sqlmap nikto gobuster

# Additional tools
sudo apt install -y enum4linux smbclient ftp telnet ssh

# Wordlists
sudo apt install -y wordlists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

## 🛠️ Installation

### **1. Clone the Repository**
```bash
git clone https://github.com/yourusername/offsec-toolkit.git
cd offsec-toolkit
```

### **2. Install Python Dependencies**
```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### **3. Configure the Toolkit**
```bash
# Copy and edit configuration
cp config/settings.json.example config/settings.json
nano config/settings.json
```

### **4. Verify Installation**
```bash
# Run tests
python3 -m pytest tests/ -v

# Check CLI
python3 -m cli.main --help
```

## 🎯 Quick Start

### **Complete Penetration Test**
```bash
# Run full walkthrough
python3 -m cli.main --target 192.168.1.10 --attacker-ip 192.168.1.16 --walkthrough

# With specific services
python3 -m cli.main --target 192.168.1.10 --attacker-ip 192.168.1.16 --walkthrough --services http,ssh,ftp

# With rockyou.txt for brute forcing
python3 -m cli.main --target 192.168.1.10 --attacker-ip 192.168.1.16 --walkthrough --use-rockyou
```

### **Individual Phases**
```bash
# Reconnaissance only
python3 -m cli.main --target 192.168.1.10 --recon

# Exploitation only (requires recon output)
python3 -m cli.main --target 192.168.1.10 --attacker-ip 192.168.1.16 --exploit

# Post-exploitation only (requires exploit output)
python3 -m cli.main --target 192.168.1.10 --post-exploit

# Report generation
python3 -m cli.main --target 192.168.1.10 --report
```

### **Direct Script Usage**
```bash
# Run specific exploit script
python3 core/exploit/ftp_exploit.py 192.168.1.10 --attacker-ip 192.168.1.16 --no-confirm

# Run reconnaissance
python3 -m core.recon 192.168.1.10

# Generate comprehensive report
python3 -m core.report_generator 192.168.1.10
```

## 📁 Project Structure

```
Offsec/
├── cli/                    # Command-line interface
│   ├── main.py            # Main CLI entry point
│   └── style.py           # CLI styling and formatting
├── core/                   # Core functionality
│   ├── exploit/           # Exploitation scripts
│   │   ├── ftp_exploit.py
│   │   ├── http_exploit.py
│   │   ├── ssh_exploit.py
│   │   └── ...
│   ├── services/          # Service reconnaissance
│   │   ├── http.py
│   │   ├── ftp.py
│   │   └── ...
│   ├── post-exploit/      # Post-exploitation scripts
│   ├── templates/         # Report templates
│   ├── recon.py           # Reconnaissance orchestrator
│   ├── exploit.py         # Exploitation orchestrator
│   ├── post_exploit.py    # Post-exploitation orchestrator
│   ├── report_generator.py # Report generation
│   ├── walkthrough_generator.py # Walkthrough generation
│   ├── config.py          # Configuration management
│   └── resume.py          # Resume capability
├── config/                # Configuration files
│   └── settings.json      # Main configuration
├── outputs/               # Generated reports and data
├── tests/                 # Test suite
├── tools/                 # External tools
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## ⚙️ Configuration

### **Main Configuration File**
Edit `config/settings.json` to customize:

```json
{
    "general": {
        "output_directory": "outputs",
        "log_level": "INFO",
        "default_timeout": null
    },
    "exploitation": {
        "default_attacker_ip": "192.168.1.16",
        "default_attacker_port": "4444",
        "enable_rockyou_by_default": false
    },
    "services": {
        "http": {
            "enabled": true,
            "tools": ["nikto", "gobuster", "sqlmap", "metasploit"]
        }
    }
}
```

### **Service-Specific Configuration**
Each service can be configured independently:

```json
{
    "services": {
        "ftp": {
            "enabled": true,
            "tools": ["hydra", "metasploit"],
            "timeout": null,
            "credentials": ["anonymous", "msfadmin", "user"]
        }
    }
}
```

## 🔧 Advanced Usage

### **Resume Capability**
```bash
# Resume interrupted operation
python3 -m cli.main --target 192.168.1.10 --resume

# Check progress
python3 -m cli.main --target 192.168.1.10 --status
```

### **Custom Wordlists**
```bash
# Use custom wordlists
python3 -m cli.main --target 192.168.1.10 --wordlist /path/to/custom.txt

# Multiple wordlists
python3 -m cli.main --target 192.168.1.10 --wordlists users.txt,passwords.txt
```

### **Parallel Execution**
```bash
# Run multiple services in parallel
python3 -m cli.main --target 192.168.1.10 --parallel --services http,ftp,ssh

# Limit concurrent processes
python3 -m cli.main --target 192.168.1.10 --max-processes 4
```

### **Custom Reports**
```bash
# Generate specific report types
python3 -m cli.main --target 192.168.1.10 --report-type executive
python3 -m cli.main --target 192.168.1.10 --report-type technical
python3 -m cli.main --target 192.168.1.10 --report-type walkthrough
```

## 📊 Output and Reports

### **Generated Files**
- `outputs/{target}_combined_report.json` - Raw reconnaissance data
- `outputs/{target}_{service}_exploit.json` - Exploitation results
- `outputs/{target}_{service}_post_exploit.json` - Post-exploitation data
- `outputs/{target}_comprehensive_report.pdf` - Professional PDF report
- `outputs/{target}_walkthrough.pdf` - Step-by-step walkthrough

### **Report Types**
1. **Executive Summary**: High-level findings for management
2. **Technical Report**: Detailed technical analysis
3. **Walkthrough**: Step-by-step exploitation guide
4. **Remediation**: Security recommendations and fixes

## 🧪 Testing

### **Run All Tests**
```bash
python3 -m pytest tests/ -v
```

### **Run Specific Test Categories**
```bash
# Test exploit scripts
python3 -m pytest tests/test_exploit_scripts.py -v

# Test configuration
python3 -m pytest tests/test_configuration.py -v

# Test CLI
python3 -m pytest tests/test_cli.py -v
```

### **Test Individual Components**
```bash
# Test FTP exploit
python3 tests/test_ftp_exploit.py

# Test HTTP exploit
python3 tests/test_http_exploit.py

# Test configuration loading
python3 tests/test_config.py
```

## 🔒 Security and Legal

### **Legal Notice**
This toolkit is designed for **authorized penetration testing only**. Users must:

- Obtain proper authorization before testing
- Comply with local laws and regulations
- Use responsibly and ethically
- Not use against unauthorized targets

### **Best Practices**
- Always get written permission before testing
- Document all testing activities
- Follow responsible disclosure procedures
- Respect privacy and data protection laws

## 🤝 Contributing

### **How to Contribute**
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### **Development Setup**
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run linting
python3 -m flake8 core/ cli/ tests/

# Run tests with coverage
python3 -m pytest tests/ --cov=core --cov-report=html
```

## 📝 Changelog

### **Version 1.0.0**
- Initial release
- Complete reconnaissance automation
- Multi-service exploitation
- Professional reporting system
- Configuration management
- Resume capability

## 📞 Support

### **Getting Help**
- **Issues**: Create an issue on GitHub
- **Documentation**: Check the wiki
- **Discussions**: Use GitHub Discussions

### **Community**
- Join our Discord server
- Follow us on Twitter
- Subscribe to our newsletter

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Metasploit Framework** for exploitation modules
- **Nmap** for network scanning capabilities
- **Hydra** for brute force functionality
- **SQLMap** for SQL injection testing
- **Nikto** for web vulnerability scanning

---

**⚠️ Disclaimer**: This toolkit is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool against any target.
