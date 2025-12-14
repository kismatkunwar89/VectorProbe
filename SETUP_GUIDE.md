# VectorProbe - Complete Setup Guide

## For Your Friend: Getting Started with VectorProbe

This guide will walk you through setting up VectorProbe from scratch on a fresh system.

---

## Step 1: System Requirements

**Supported Operating Systems:**
- Kali Linux (Recommended)
- Ubuntu/Debian
- Arch Linux
- macOS

**You'll need:**
- Root/sudo access
- Internet connection
- At least 2GB free disk space

---

## Step 2: Install System Dependencies

### On Kali Linux / Ubuntu / Debian:

```bash
# Update package lists
sudo apt-get update

# Install REQUIRED tools
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    exploitdb \
    git

# Install OPTIONAL tools (recommended for full functionality)
sudo apt-get install -y \
    masscan \
    enum4linux-ng

# Update searchsploit database
sudo searchsploit -u
```

### On Arch Linux:

```bash
# Install required tools
sudo pacman -S python python-pip nmap exploitdb git

# Install optional tools
sudo pacman -S masscan
```

### On macOS:

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required tools
brew install python3 nmap exploitdb git

# Install optional tools
brew install masscan
```

---

## Step 3: Get VectorProbe

### Option A: Clone from GitHub (if shared on GitHub)

```bash
# Clone the repository
git clone https://github.com/YOUR-USERNAME/ProjectFinalEthical.git
cd ProjectFinalEthical
```

### Option B: From Shared Archive

```bash
# If you received a ZIP/TAR file
unzip VectorProbe.zip
# OR
tar -xzf VectorProbe.tar.gz

cd ProjectFinalEthical
```

---

## Step 4: Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Your prompt should now show (venv) at the beginning
```

**Important:** You need to activate the venv every time you use VectorProbe!

---

## Step 5: Install Python Dependencies

```bash
# Make sure venv is activated (you should see (venv) in your prompt)
pip install -r requirements.txt
```

**What this installs:**
- pytest (for testing)
- pytest-cov (for test coverage)
- Any other Python dependencies

---

## Step 6: Verify Installation

### Test the tool launches:

```bash
python src/main.py --help
```

You should see the VectorProbe banner and help menu!

### Run the test suite:

```bash
pytest -v
```

You should see **153 tests passing**!

---

## Step 7: Your First Scan

### Scan localhost (safe test):

```bash
python src/main.py -t 127.0.0.1 -o my_first_scan.md
```

### Scan your local network (requires sudo):

```bash
sudo python src/main.py -t 192.168.1.0/24 --fast-scan -o network_report.md
```

**Note:** Replace `192.168.1.0/24` with your actual network range!

---

## Quick Reference Card

### Essential Commands:

```bash
# Activate environment (do this first every time!)
source venv/bin/activate

# Basic scan
python src/main.py -t <IP>

# Fast scan (uses masscan)
sudo python src/main.py -t <IP> --fast-scan

# Scan network range
python src/main.py -t 192.168.1.0/24

# Exclude hosts
python src/main.py -t 192.168.1.0/24 -x 192.168.1.1,192.168.1.254

# Custom output file
python src/main.py -t <IP> -o my_report.md

# Run tests
pytest -v

# Deactivate venv when done
deactivate
```

---

## Troubleshooting Common Issues

### Issue 1: "Command not found: python3"

**Solution:**
```bash
# On some systems, try:
python --version  # Check if python (not python3) works
# If so, use 'python' instead of 'python3'
```

### Issue 2: "Masscan is not installed"

**Solution:**
```bash
sudo apt-get install masscan
# OR run without --fast-scan flag
python src/main.py -t <IP>  # No --fast-scan
```

### Issue 3: "Permission denied" when scanning

**Solution:**
```bash
# Use sudo for network scans
sudo python src/main.py -t <IP> --fast-scan
```

### Issue 4: "No module named 'pytest'"

**Solution:**
```bash
# Make sure venv is activated
source venv/bin/activate
# Then install requirements again
pip install -r requirements.txt
```

### Issue 5: "Searchsploit not found"

**Solution:**
```bash
sudo apt-get install exploitdb
sudo searchsploit -u  # Update database
```

### Issue 6: Tests failing

**Solution:**
```bash
# Make sure you're in the project directory
cd ProjectFinalEthical

# Activate venv
source venv/bin/activate

# Run tests
pytest -v

# If still failing, reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

---

## Understanding the Reports

After a scan, you'll get a Markdown report (`.md` file).

**Report Structure:**
- **Summary**: Total hosts, scan type
- **Per-Host Details**:
  - IP address, hostname, OS
  - Open ports and services
  - Known vulnerabilities (from searchsploit)
  - SMB enumeration (if port 445 found)

**View the report:**
```bash
# In terminal
cat network_report.md

# Or open in any text editor/Markdown viewer
```

---

## Security & Legal Warning

**READ THIS CAREFULLY:**

✅ **You CAN scan:**
- Your own computers
- Your own home network
- Lab environments you control
- Systems you have WRITTEN PERMISSION to test

❌ **You CANNOT scan:**
- Networks you don't own
- Your school/work network (without permission)
- Public networks
- Any system without explicit authorization

**Unauthorized scanning is ILLEGAL and can result in:**
- Criminal charges
- Expulsion from school
- Job termination
- Legal prosecution

**Always get permission first!**

---

## What Each Tool Does

**Masscan (optional):**
- Super fast port scanner
- Scans entire networks in seconds
- Identifies which hosts have open ports

**Nmap (required):**
- Deep port and service scanner
- Detects service versions
- OS fingerprinting
- Industry standard tool

**Searchsploit (required):**
- Searches exploit database
- Finds known vulnerabilities for detected services
- Part of Exploit-DB

**enum4linux-ng (optional):**
- Windows/Samba enumeration
- Extracts users, groups, shares
- Detects null session vulnerabilities

---

## Tips for Best Results

1. **Use sudo for better results:**
   ```bash
   sudo python src/main.py -t <target> --fast-scan
   ```

2. **Start small:**
   - Test on localhost first
   - Then scan a single known host
   - Finally scan network ranges

3. **Use --no-prompt for automation:**
   ```bash
   python src/main.py -t <IP> --no-prompt
   ```

4. **Check your network range:**
   ```bash
   # Find your network
   ip addr show
   # or
   ifconfig
   ```

5. **Exclude important hosts:**
   ```bash
   # Don't scan your router or critical servers
   python src/main.py -t 192.168.1.0/24 -x 192.168.1.1,192.168.1.254
   ```

---

## Complete Example Workflow

```bash
# 1. Navigate to project
cd ~/ProjectFinalEthical

# 2. Activate environment
source venv/bin/activate

# 3. Run a test scan on localhost
python src/main.py -t 127.0.0.1 -o test.md

# 4. Check the report
cat test.md

# 5. Run full network scan (if authorized!)
sudo python src/main.py -t 192.168.1.0/24 --fast-scan -o full_scan.md

# 6. View results
cat full_scan.md

# 7. Run tests to verify everything works
pytest -v

# 8. Deactivate when done
deactivate
```

---

## Getting Help

**If you encounter issues:**

1. **Check this guide first** - most issues are covered
2. **Read the README.md** - has detailed documentation
3. **Run the tests** - `pytest -v` should pass 153 tests
4. **Check you activated venv** - you should see `(venv)` in prompt

**Common mistakes:**
- Forgetting to activate venv
- Not using sudo for network scans
- Scanning networks without permission
- Not installing all dependencies

---

## What You Should Have Now

After following this guide:

- ✅ All system tools installed (nmap, searchsploit, etc.)
- ✅ Python virtual environment created
- ✅ Python dependencies installed
- ✅ VectorProbe tested and working
- ✅ 153 tests passing
- ✅ Successfully ran your first scan
- ✅ Understanding of how to use the tool

---

## Next Steps

**Practice:**
1. Scan your own computer
2. Scan a virtual machine you control
3. Set up a test lab (VirtualBox/VMware)
4. Try different scan options

**Learn More:**
- Read about nmap: `man nmap`
- Explore searchsploit: `searchsploit -h`
- Study the code: `src/main.py`
- Read test cases: `tests/`

---

## Quick Checklist

Before sharing VectorProbe with someone, make sure they have:

- [ ] Kali Linux / Ubuntu / Compatible OS
- [ ] Root/sudo access
- [ ] Internet connection
- [ ] This SETUP_GUIDE.md file
- [ ] The requirements.txt file
- [ ] The entire project folder
- [ ] Understanding of legal/ethical use
- [ ] Authorization to scan target networks

---

**You're all set! Happy (legal and authorized) scanning!**

For questions or issues, check the README.md or run `python src/main.py --help`.
