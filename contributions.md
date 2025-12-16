# Contributions

## Team Members

### Kismat Kunwar
- **Project Lead & Core Architecture:**
  - Set up the initial project structure, modular design, and virtual environment.
  - Designed the main orchestration workflow in `main.py`.
- **CLI & Input Handling:**
  - Implemented the `argparse` CLI, including all flags (`-o`, `-x`, `--no-prompt`).
  - Developed the target and exclusion parsing logic.
- **Scanning & Enumeration:**
  - Enhanced the `nmap` and `smb` handlers and parsers.
  - Implemented the main orchestration logic connecting all scanning stages.
- **Active Directory Enumeration (Tasks 6.5.1-6.5.11):**
  - Implemented comprehensive unauthenticated AD enumeration in `ad_handler.py` and `ad_parser.py`.
  - Integrated LDAP Base DSE queries, DNS SRV record lookups, NetBIOS role detection, and SMB security mode analysis.
  - Enhanced Nmap parser with generic NSE metadata extraction for hostname/domain parsing.
  - Implemented DC detection logic based on ports (389, 636, 3268, 88) and SMB shares (SYSVOL, NETLOGON).
- **Bug Fixes & Code Quality:**
  - Fixed SMB null session detection with negative pattern matching (addressing false positives).
  - Implemented exploit deduplication across services in report generation.
  - Added conditional rendering for NetBIOS sections (only shown when data exists).
  - Consolidated duplicate code: Created shared `CommandResult` model and centralized command execution in `shell.py`.
  - Created generic tool availability checker (`tool_checker.py`) eliminating duplicate validation across handlers.
  - Fixed `nmblookup_failure_recorded` undefined variable bug in NetBIOS enumeration.
- **Testing & Validation:**
  - Established the `pytest` framework, fixtures, and `pytest.ini` configuration.
  - Wrote the complete suite of unit tests for all parsers and handlers, achieving 100% pass rate.
- **Reporting & UX:**
  - Enhanced the report generator with the scan summary, AD information section, and per-host command outputs.
  - Created the ASCII art banner for the CLI.
  - Improved report formatting with clear separation of verified vs. unverified data.
  - Added command execution details with exit codes and error handling.

### Gamvirta Poudel
- **Initial Handler Implementation:**
  - Developed the initial handler for Nmap scans.
  - Contributed to the initial SMB handler implementation.
- **Vulnerability Correlation:**
  - Implemented the `vulnerability_handler.py` to run `searchsploit`.
  - Implemented the `vulnerability_parser.py` to process JSON output from `searchsploit`.
  - Wrote unit tests for the vulnerability parser.
- **Data Modeling:**
  - Updated the data models (`ServiceResult`) to include and store exploit information.