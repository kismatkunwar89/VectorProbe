# Contributions

## Team Members

### Kismat Kunwar
- **Project Lead & Core Architecture:**
  - Set up the initial project structure, modular design, and virtual environment.
  - Designed the main orchestration workflow in `main.py`.
- **CLI & Input Handling:**
  - Implemented the `argparse` CLI, including all flags (`-t`, `-x`, `-o`, `--scan-type`, `--no-prompt`).
  - Developed the target and exclusion parsing logic in `host_discovery.py`.
  - Implemented the `--scan-type` option with default/quick/full/udp modes.
- **DNS Safety Feature:**
  - Implemented DNS safety confirmation prompt showing configured DNS servers.
  - Defaults to "No" if no input provided, preventing accidental scope violations.
- **Host Discovery & Network Scanning:**
  - Implemented CIDR expansion and host discovery using `nmap -sn`.
  - Enhanced the `nmap` and `smb` handlers and parsers.
  - Implemented the main orchestration logic connecting all scanning stages.
- **NetBIOS Enumeration:**
  - Implemented `netbios_handler.py` and `netbios_parser.py` for NetBIOS enumeration.
  - Integrated `nmblookup` for workgroup and computer name discovery.
- **Active Directory Enumeration:**
  - Implemented comprehensive unauthenticated AD enumeration in `ad_handler.py` and `ad_parser.py`.
  - Integrated LDAP Base DSE queries, DNS SRV record lookups, NetBIOS role detection, and SMB security mode analysis.
  - Enhanced Nmap parser with generic NSE metadata extraction for hostname/domain parsing.
  - Implemented DC detection logic based on ports (389, 636, 3268, 88) and SMB shares (SYSVOL, NETLOGON).
- **Utilities & Infrastructure:**
  - Created shared `CommandResult` model and centralized command execution in `shell.py`.
  - Created generic tool availability checker (`tool_checker.py`).
  - Implemented utility decorators (`@retry`, `@timing`, `@validate_ip`) in `decorators.py`.
  - Developed `dns_utils.py` and `network_utils.py` for network operations.
  - Implemented input validation in `validation.py`.
- **Bug Fixes & Code Quality:**
  - Fixed SMB null session detection with negative pattern matching.
  - Implemented exploit deduplication across services in report generation.
  - Added conditional rendering for NetBIOS sections (only shown when data exists).
  - Fixed `nmblookup_failure_recorded` undefined variable bug.


### Gamvirta Poudel
- **Initial Handler Implementation:**
  - Developed the initial handler for Nmap scans.
  - Contributed to the initial SMB handler implementation.
- **OS Detection:**
  - Implemented `os_detection.py` for operating system fingerprinting.
  - Integrated OS detection results into the enumeration pipeline.
- **Vulnerability Correlation:**
  - Implemented `vulnerability_handler.py` to run `searchsploit`.
  - Implemented `vulnerability_parser.py` to process JSON output from `searchsploit`.
  - Created `query_builder.py` for constructing optimized searchsploit queries.
  - Wrote unit tests for the vulnerability parser.
- **Data Modeling:**
  - Updated the data models (`ServiceResult`, `HostResult`) to include and store exploit information.
- **Testing & Validation:**
  - Established the `pytest` framework, fixtures, and `pytest.ini` configuration.
  - Wrote the complete suite of unit tests for all parsers and handlers, achieving 100% pass rate (205 tests).
- **Reporting & UX:**
  - Enhanced the report generator with scan summary, AD information section, and per-host command outputs.
  - Implemented UTC timestamp formatting for report filenames (`YYYYMMDD_HHMM_UTC`).
  - Created the ASCII art banner for the CLI in `banner.py`.
  - Improved report formatting with clear separation of verified vs. unverified data.
  - Added command execution details with exit codes and error handling.
  - Configured logging system in `logger.py`.