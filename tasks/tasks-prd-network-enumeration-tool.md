## Relevant Files (Final Corrected Version)

- `src/main.py` - Your main entry point.
- `requirements.txt` - Lists all Python dependencies.
- `pytest.ini` - **New file** for configuring the test framework.
- `src/cli/argument_parser.py` - Your CLI argument parsing module.
- `src/handlers/` - Your "scanners" directory.
  - `masscan_handler.py` - **New file** for wrapping `masscan`.
  - `nmap_handler.py` - Wraps `nmap`.
  - `smb_handler.py` - For `enum4linux-ng` and `smbmap`.
  - `http_handler.py` - For `nikto`, `gobuster`, and banner grabbing.
  - `dns_handler.py` - For `dnsrecon`.
  - `vulnerability_handler.py` - For `searchsploit`.
- `src/parsers/` - Your directory for parsing logic.
  - `masscan_parser.py` - **New file** for parsing `masscan` output.
  - `nmap_parser.py` - Parses `nmap` output.
  - `smb_parser.py` - For `enum4linux-ng` and `smbmap`.
  - `http_parser.py` - For `nikto` and `gobuster`.
  - `dns_parser.py` - For `dnsrecon`.
  - `vulnerability_parser.py` - For `searchsploit`.
- `src/models/` - Your data models.
- `src/report/report_generator.py` - Your report generation module.
- `src/utils/` - Your utilities.
- `tests/` - Your directory for unit tests.
  - `fixtures/` - **New directory** to store sample outputs from tools.

---

## Tasks (Updated to Your Progress)

- [x] 1.0 **Project Setup and Core Structure**
  - [x] 1.1 Venv setup.
  - [x] 1.2 Modular `src` directory structure.
  - [x] 1.3 Main package files.
  - [x] 1.4 `requirements.txt` created. Add `netaddr`, `lxml`, `dnspython`, `pytest`.
  - [x] 1.5 Logging utility created.
  - [x] 1.6 Data models created.
  - [x] 1.7 Create a generic utility in `src/utils/shell.py` for executing commands.

- [x] 2.0 **CLI, Input, and Test Framework Setup**
  - [x] 2.1 `argparse` implemented.
  - [ ] 2.2 Add `--fast-scan` flag to `src/cli/argument_parser.py`.
  - [x] 2.3 Enhance `src/utils/target_parser.py` for target/exclusion strings.
  - [x] 2.4 Implement the DNS Safety feature.
  - [x] 2.5 **Establish Pytest Framework**
    - [x] 2.5.1 Create `pytest.ini` at the project root with `pythonpath = src`.
    - [x] 2.5.2 Create `tests/fixtures/` directory.
    - [x] 2.5.3 `tests/test_host_model.py` is confirmed as a good template.
  - [ ] 2.6 Write unit tests in `tests/test_target_parser.py`.

- [ ] 3.0 **Stage 1 (Optional): High-Speed Discovery (Masscan)**
  - [ ] 3.1 In your controller, check if the `--fast-scan` flag is present.
  - [ ] 3.2 Create `src/handlers/masscan_handler.py` to run `masscan`.
  - [ ] 3.3 Create `src/parsers/masscan_parser.py` to parse its output.
  - [ ] 3.4 **Write unit tests in `tests/test_masscan_parser.py` using a fixture file.**

- [x] 4.0 **Stage 2: Foundational Deep Scan (Nmap)**
  - [x] 4.1 In `src/handlers/nmap_handler.py`, handle either a full scan or a `masscan`-based target list. Ensure XML output.
  - [x] 4.2 In `src/parsers/nmap_parser.py`, parse the Nmap XML.
  - [ ] 4.3 **Write unit tests in `tests/test_nmap_parser.py` using a sample `nmap.xml` fixture.**

- [ ] 5.0 **Stage 3: Vulnerability Correlation (Searchsploit)**
  - [ ] 5.1 In the controller, call the vulnerability handler for each service.
  - [ ] 5.2 Create `src/handlers/vulnerability_handler.py` to run `searchsploit --json`.
  - [ ] 5.3 Create `src/parsers/vulnerability_parser.py` to parse the JSON.
  - [ ] 5.4 **Write unit tests in `tests/test_vulnerability_parser.py` using a sample `searchsploit.json` fixture.**
  - [ ] 5.5 Update data models to store exploit info.

- [ ] 6.0 **Stage 4: Service-Specific Deep Enumeration**
  - [ ] 6.1 Implement the orchestration logic in the controller.
  - [ ] 6.2 **HTTP/S:** Create `http_handler.py` and `http_parser.py`. **Write unit tests using fixtures.**
  - [x] 6.3 **SMB:** Enhance `smb_handler.py` and `smb_parser.py`. **Write unit tests using fixtures.**
  - [ ] 6.4 **DNS:** Create `dns_handler.py` and `dns_parser.py`. **Write unit tests using fixtures.**

- [x] 7.0 **Stage 5: Report Generation**
  - [x] 7.1 Enhance `src/report/report_generator.py` to handle all data.
  - [ ] 7.2 Add a "Scan Summary & Cross-Host Analysis" section using `collections.Counter` and `set`.
  - [ ] 7.3 Ensure the report includes sections for all tools.

- [ ] 8.0 **Finalization and Documentation**
  - [ ] 8.1 Write a comprehensive `README.md`.
  - [ ] 8.2 Write `contributions.md` and `limitations.md`.
  - [ ] 8.3 Generate sample reports.

- [ ] 9.0 **CLI User Experience Enhancements**
  - [ ] 9.1 Implement an ASCII art banner.

