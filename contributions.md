# Contributions

## Team Members

### Kismat Kunwar
- **Project Lead & Core Architecture:**
  - Set up the initial project structure, modular design, and virtual environment.
  - Designed the main orchestration workflow in `main.py`.
- **CLI & Input Handling:**
  - Implemented the `argparse` CLI, including all flags (`--fast-scan`, `-o`, `-x`).
  - Developed the target and exclusion parsing logic.
- **Scanning & Enumeration:**
  - Implemented the `masscan` handler and parser for high-speed discovery.
  - Enhanced the `nmap` and `smb` handlers and parsers.
  - Implemented the main orchestration logic connecting all scanning stages.
- **Testing & Validation:**
  - Established the `pytest` framework, fixtures, and `pytest.ini` configuration.
  - Wrote the complete suite of unit tests for all parsers and handlers, achieving 100% pass rate.
- **Reporting & UX:**
  - Enhanced the report generator with the scan summary, AD information section, and per-host command outputs.
  - Created the ASCII art banner for the CLI.

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