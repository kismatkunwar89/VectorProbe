# VectorProbe - Network Enumeration Tool

## Overview

VectorProbe is a comprehensive network enumeration and security assessment tool designed for ethical penetration testing and security assessments. It integrates Masscan, Nmap, Searchsploit, and enum4linux-ng to provide automated network reconnaissance with vulnerability correlation.

## Features

- **Fast Network Discovery**: Masscan integration for rapid port scanning
- **Deep Service Enumeration**: Nmap integration for detailed service detection and OS fingerprinting
- **Vulnerability Correlation**: Automatic searchsploit integration for exploit identification
- **SMB Enumeration**: Automated Windows/Samba enumeration with enum4linux-ng
- **Markdown Reports**: Clean, structured reporting in Markdown format

## Installation

### Prerequisites

**Required Tools:**
- Python 3.8+
- nmap
- searchsploit (exploitdb)

**Optional Tools (for enhanced functionality):**
- masscan (for --fast-scan mode)
- enum4linux-ng (for SMB enumeration)

### Install System Dependencies

**Debian/Ubuntu/Kali:**
```bash
# Required
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv nmap exploitdb

# Optional - for fast scanning
sudo apt-get install -y masscan

# Optional - for SMB enumeration
sudo apt-get install -y enum4linux-ng
```

**Arch Linux:**
```bash
# Required
sudo pacman -S python python-pip nmap exploitdb

# Optional
sudo pacman -S masscan
```

**macOS:**
```bash
# Required
brew install python3 nmap exploitdb

# Optional
brew install masscan
```

### Install VectorProbe

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd ProjectFinalEthical
   ```

2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Verify installation:
   ```bash
   python src/main.py --help
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

### Fast Scan Mode

Use masscan for initial discovery, then nmap for deep scanning:
```bash
sudo python src/main.py -t 192.168.1.0/24 --fast-scan
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

## Command-Line Options

```
usage: VectorProbe [-h] -t TARGETS [-x EXCLUDE] [-o OUTPUT] [--no-prompt] [--fast-scan]

options:
  -t TARGETS, --targets TARGETS
                        Targets to scan: IP, CIDR, DNS, or comma-separated mix.
  -x EXCLUDE, --exclude EXCLUDE
                        Excluded out-of-scope hosts.
  -o OUTPUT, --output OUTPUT
                        Output report path/filename.
  --no-prompt           Disable interactive prompts.
  --fast-scan           Use masscan for fast initial host discovery.
```

## Workflow

1. **Stage 1 (Optional): Fast Discovery** - Masscan identifies live hosts
2. **Stage 2: Deep Scanning** - Nmap performs service detection and OS fingerprinting
3. **Stage 3: Vulnerability Correlation** - Searchsploit queries for known exploits
4. **Stage 4: SMB Enumeration** - Auto-runs enum4linux-ng when SMB detected
5. **Stage 5: Report Generation** - Creates comprehensive Markdown report

## Troubleshooting

### "Masscan is not installed"
Install masscan: `sudo apt-get install masscan`
Or run without `--fast-scan` flag (uses nmap only)

### "Permission denied" errors
Use `sudo` when scanning requires raw sockets:
```bash
sudo python src/main.py -t 192.168.1.0/24 --fast-scan
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