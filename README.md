# VectorProbe - Network Enumeration Tool

## Overview

VectorProbe is a comprehensive network enumeration and security assessment tool designed for ethical penetration testing and security assessments. It integrates Nmap, Searchsploit, and enum4linux-ng to provide automated network reconnaissance with vulnerability correlation.

## Features

- **Deep Service Enumeration**: Nmap integration for detailed service detection and OS fingerprinting
- **Vulnerability Correlation**: Automatic searchsploit integration for exploit identification
- **SMB Enumeration**: Automated Windows/Samba enumeration with enum4linux-ng
- **Markdown Reports**: Clean, structured reporting in Markdown format
- **Active Directory Enumeration**: LDAP and domain information enumeration against Windows Domain Controllers

### Active Directory Enumeration Capabilities

VectorProbe performs comprehensive unauthenticated Active Directory enumeration on detected Domain Controllers:

- **LDAP Base DSE Queries**: Domain structure, naming contexts, functional levels, and forest configuration
- **SMB Security Mode Detection**: Signing requirements, authentication levels, and security posture
- **NetBIOS Role Identification**: Domain Controller identification via NetBIOS type codes
- **DNS SRV Record Discovery**: LDAP and Kerberos service record enumeration
- **Global Catalog Detection**: Global Catalog server availability and port detection

**Limitations**: AD enumeration is performed using unauthenticated methods only. This provides domain structure and DC identification but does not include user/group enumeration or password policies (which require credentials). See [limitations.md](limitations.md) for complete details.

## Installation

### Prerequisites

**Required Tools:**
- **Python 3.12+** (tested on 3.12.x; newer versions print a warning but are supported)
- nmap
- searchsploit (from the `exploitdb` package)

**Optional Tools (for enhanced functionality):**
- enum4linux-ng (for SMB enumeration)

### Step 1: Verify Python 3.12+

VectorProbe requires Python **3.12** or newer. Kali Linux 2024.4+ includes Python 3.12 by default:

```bash
python3 --version  # Should show 3.12.x or newer
```

### Step 2: Install System Dependencies

```bash
sudo apt install -y nmap exploitdb
# Optional - for AD/LDAP and SMB enumeration
sudo apt install -y ldap-utils dnsutils samba-common-bin enum4linux-ng
```

### Step 3: Install VectorProbe

1. Clone the repository:
   ```bash
   git clone https://github.com/kismatkunwar89/VectorProbe.git
   cd VectorProbe
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Verify installation:**
   ```bash
   python src/main.py --help
   ```
   
   You should see the VectorProbe banner and help menu.

### Running with Sudo (Required for Network Scanning)

Network scanning requires raw socket access:
```bash
sudo python src/main.py -t <target>
```

## Usage

### Basic Scan

Scan a single IP or hostname:
```bash
python src/main.py -t 192.168.1.100
```

### Scan CIDR Range

Scan an entire subnet:
```bash
python src/main.py -t 192.168.1.0/24
```

### Multiple Targets

Scan multiple targets (comma-separated):
```bash
python src/main.py -t 192.168.1.100,192.168.1.101,10.0.0.0/24
```

### Exclude Hosts

Exclude specific hosts or ranges:
```bash
python src/main.py -t 192.168.1.0/24 -x 192.168.1.1,192.168.1.254
```

### Custom Output File

Specify output report filename:
```bash
python src/main.py -t 192.168.1.0/24 -o my_scan_report.md
```

### Non-Interactive Mode

Disable prompts (useful for automation):
```bash
python src/main.py -t example.com --no-prompt
```

### Scan Type Options

**Default Scan** (Top 1000 TCP ports with service/OS detection):
```bash
python src/main.py -t 192.168.1.100 --scan-type default
```

**Quick Scan** (Top 100 TCP ports for fast enumeration):
```bash
python src/main.py -t 192.168.1.0/24 --scan-type quick
```

**Full Scan** (All 65535 TCP ports - comprehensive but slow):
```bash
python src/main.py -t 192.168.1.100 --scan-type full
```

**UDP Scan** (Top 20 UDP ports - DNS, SNMP, DHCP, etc.):
```bash
python src/main.py -t 192.168.1.100 --scan-type udp
```

### Active Directory Enumeration Examples

Scan a Windows Domain Controller to enumerate LDAP and domain information:
```bash
python src/main.py -t <DC_IP>
python src/main.py -t <DC_IP> -o ad_enumeration_report.md
```

## Command-Line Options

```
usage: VectorProbe [-h] -t TARGETS [-x EXCLUDE] [-o OUTPUT] [--scan-type {default,quick,full,udp}] [--no-prompt]

options:
  -h, --help            Show help message and exit
  -t TARGETS, --targets TARGETS
                        Targets to scan: IP, CIDR, DNS, or comma-separated mix.
  -x EXCLUDE, --exclude EXCLUDE
                        Excluded out-of-scope hosts: IP, CIDR, DNS, or comma-separated mix.
  -o OUTPUT, --output OUTPUT
                        Output report path/filename. Defaults to UTC timestamp.
  --scan-type {default,quick,full,udp}
                        Scan type: 'default' = TCP SYN top 1000 ports with service/OS detection;
                        'quick' = Fast scan top 100 TCP ports; 'full' = All 65535 TCP ports;
                        'udp' = Top 20 UDP ports.
  --no-prompt           Disable interactive prompts (DNS safety prompt).
```

## DNS Safety Feature

When DNS names are provided as targets (e.g., `server.example.com`), VectorProbe implements a safety check to prevent accidental scope violations due to DNS misconfiguration:

1. **Displays** the currently configured DNS servers on your system
2. **Lists** all DNS targets that will be resolved
3. **Prompts** for confirmation with `[y/N]` (defaults to No if no input)

This prevents scanning unintended targets if DNS is misconfigured or hijacked.

```bash
# Example: DNS safety prompt in action
python src/main.py -t webserver.company.com

[DNS SAFETY CHECK]
Configured DNS servers:
  - 192.168.1.1
  - 8.8.8.8

DNS targets to resolve:
  - webserver.company.com

Proceed with DNS resolution? [y/N]: y
```

Use `--no-prompt` to disable this check (for automation):
```bash
python src/main.py -t webserver.company.com --no-prompt
```

## Workflow

1. **Stage 1: Deep Scanning** - Nmap performs service detection and OS fingerprinting
2. **Stage 2: Vulnerability Correlation** - Searchsploit queries for known exploits
3. **Stage 3: SMB Enumeration** - Auto-runs enum4linux-ng when SMB detected
4. **Stage 4: Active Directory Enumeration** - LDAP and domain enumeration when DC detected
5. **Stage 5: Report Generation** - Creates comprehensive Markdown report

## Troubleshooting

### "Permission denied" errors
Use `sudo` when scanning requires raw sockets:
```bash
sudo python src/main.py -t 192.168.1.0/24
```

### "Searchsploit not found"
```bash
sudo apt-get install exploitdb
searchsploit -u  # Update database
```

## Testing

Run the test suite:
```bash
source venv/bin/activate
pytest -v
```

## Security & Ethics

**IMPORTANT:** This tool is designed for authorized security testing only.

✅ **Authorized Use:**
- Penetration testing with written permission
- Security assessments on your own networks
- CTF competitions and educational labs

❌ **Unauthorized Use:**
- Scanning networks without permission
- Accessing systems you don't own or have authorization for

**Always obtain proper authorization before scanning any network or system.**

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

---

**Note:** This is an academic project for ethical hacking coursework. Use responsibly and legally.
