# User Guide for VectorProbe

## Introduction

VectorProbe is a comprehensive network enumeration and security assessment tool designed for ethical penetration testing. It integrates Nmap, Searchsploit, and enum4linux-ng to provide automated network reconnaissance with vulnerability correlation.

**Version:** 1.0.0

## Requirements

### System Requirements

- **Python 3.12 or newer** (required)
- **Root/sudo privileges** (required for Nmap SYN scans and OS detection)

### Required Tools

The following tools must be installed and available in your PATH:

| Tool | Purpose | Installation (Debian/Ubuntu) |
|------|---------|------------------------------|
| Nmap | Port scanning and service detection | `sudo apt install nmap` |
| Searchsploit | Vulnerability correlation | `sudo apt install exploitdb` |
| enum4linux-ng | SMB/Windows enumeration | `sudo apt install enum4linux-ng` |
| nmblookup | NetBIOS enumeration | `sudo apt install samba-common-bin` |
| ldapsearch | Active Directory enumeration | `sudo apt install ldap-utils` |
| dig | DNS SRV record queries | `sudo apt install dnsutils` |

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/kismatkunwar89/VectorProbe.git
   cd VectorProbe
   ```

2. **Set up a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Syntax

```bash
sudo python src/main.py -t <targets> [options]
```

**Note:** Root/sudo privileges are required for most scan types.

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Display help information and exit |
| `-t, --targets` | **Required.** Target hosts to scan (see Target Formats below) |
| `-x, --exclude` | Exclude specific hosts from the scan (same format as targets) |
| `-o, --output` | Custom output file path/name (default: timestamped filename) |
| `--scan-type` | Scan type: `default`, `quick`, `full`, or `udp` (see Scan Types below) |
| `--no-prompt` | Disable interactive prompts (useful for automation) |

### Target Formats

Targets can be specified in the following formats:

- **Single IP:** `192.168.1.1`
- **Multiple IPs:** `192.168.1.1,192.168.1.2,192.168.1.3`
- **CIDR notation:** `192.168.1.0/24`
- **DNS hostname:** `server.example.com`
- **Mixed:** `192.168.1.1,server.example.com,10.0.0.0/24`

### Scan Types

| Type | Nmap Flags | Description |
|------|------------|-------------|
| `default` | `-sS -sV -sC -O` | TCP SYN scan on top 1000 ports with service/OS detection (recommended) |
| `quick` | `--top-ports 100` | Fast scan on top 100 TCP ports for rapid discovery |
| `full` | `-p-` | Comprehensive scan of all 65535 TCP ports (time-intensive) |
| `udp` | `-sU --top-ports 20` | UDP scan on top 20 common ports (DNS, SNMP, DHCP, etc.) |

## Features

### Automated Enumeration Workflow

VectorProbe runs the following stages automatically:

1. **Target Resolution** - Resolves DNS names and processes exclusions
2. **Host Discovery** - For CIDR ranges, discovers live hosts before deep scanning
3. **Port Scanning** - Runs Nmap with the selected scan type
4. **Vulnerability Correlation** - Queries Searchsploit for known exploits matching detected services
5. **SMB Enumeration** - Automatically runs enum4linux-ng on hosts with port 445 open
6. **NetBIOS Enumeration** - Automatically runs nmblookup on hosts with port 139 open
7. **Active Directory Enumeration** - Automatically enumerates Domain Controllers when detected

### DNS Safety Feature

When providing DNS hostnames as targets, VectorProbe will:
- Display the currently configured DNS server
- Prompt for confirmation before proceeding (default: No)

Use `--no-prompt` to bypass this confirmation for automated/scripted usage.

### Domain Controller Detection

VectorProbe identifies Domain Controllers using multiple criteria:
- LDAP ports (389, 636, 3268, 3269)
- Kerberos port (88)
- SYSVOL/NETLOGON shares detected via SMB
- Active Directory LDAP service signatures

When a DC is detected, additional enumeration includes:
- LDAP Base DSE and RootDSE queries
- SMB security mode analysis
- NetBIOS role identification
- DNS SRV record queries
- Kerberos information (if port 88 is open)

### Vulnerability Correlation

For each detected service, VectorProbe automatically:
- Builds search queries from service name and version fingerprint
- Queries Searchsploit for matching exploits
- Limits results to top 5 most relevant exploits per service
- Caches results to avoid duplicate queries

## Report Generation

VectorProbe generates a comprehensive Markdown report containing:

### Report Sections

1. **Scan Summary**
   - Total hosts discovered
   - Top 10 common open ports
   - Operating system breakdown

2. **Network Topology**
   - Hosts organized by subnet
   - Quick overview table with IP, hostname, OS, services, and status

3. **Per-Host Details**
   - **Verified Information:** IP address, hostname, OS type
   - **Active Services:** Port, protocol, service name, fingerprint, exploit count
   - **Active Directory Information:** Domain, DC hostname, functional levels, naming contexts, SMB security posture (for DCs)
   - **SMB Enumeration:** OS info, null session status, users, shares, groups
   - **NetBIOS Enumeration:** NetBIOS names and workgroup
   - **Unverified Information:** Probable but unconfirmed details
   - **Potential Vulnerabilities:** Matching exploits from Searchsploit
   - **Command Outputs:** Raw output from executed commands

### Output File

By default, reports are saved in the current directory with the naming format:
```
host_enumeration_report_YYYYMMDD_HHMM_UTC.md
```

Use `-o` to specify a custom path/filename.

## Examples

### Basic Single Host Scan

```bash
sudo python src/main.py -t 192.168.1.1
```

### Quick Scan for Rapid Discovery

```bash
sudo python src/main.py -t 192.168.1.0/24 --scan-type quick
```

### Full Port Scan

```bash
sudo python src/main.py -t 192.168.1.100 --scan-type full
```

### UDP Scan

```bash
sudo python src/main.py -t 192.168.1.1 --scan-type udp
```

### Scan with Host Exclusions

```bash
sudo python src/main.py -t 192.168.1.0/24 -x 192.168.1.1,192.168.1.254
```

### Custom Output File

```bash
sudo python src/main.py -t 192.168.1.1 -o /path/to/my_report.md
```

### Automated/Scripted Usage (No Prompts)

```bash
sudo python src/main.py -t server.example.com --no-prompt
```

### Multiple Target Types Combined

```bash
sudo python src/main.py -t 192.168.1.1,dc.corp.local,10.0.0.0/24 -x 10.0.0.1
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "nmap not found in PATH" | Install Nmap: `sudo apt install nmap` |
| "enum4linux-ng not found" | Install: `sudo apt install enum4linux-ng` |
| "Permission denied" or scan fails | Run with `sudo` |
| "Python 3.12 required" | Upgrade Python or use pyenv to install 3.12+ |
| DNS resolution fails | Check network connectivity and DNS configuration |
| Scan takes too long | Use `--scan-type quick` for faster results |

### Tool Availability

VectorProbe will warn you if required tools are not installed. Enumeration stages that depend on missing tools will be skipped gracefully.

## Legal Notice

VectorProbe is designed for **authorized security testing only**. Always ensure you have explicit permission before scanning any network or system. Unauthorized scanning may violate laws and regulations.

## Conclusion

This user guide covers all features and options available in VectorProbe. For additional help, run:

```bash
python src/main.py -h
```

For bug reports or feature requests, please refer to the project repository.
