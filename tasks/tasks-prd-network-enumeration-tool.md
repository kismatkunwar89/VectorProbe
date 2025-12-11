## Relevant Files (Reflecting Your Structure)

- `src/main.py` - Your main entry point.
- `requirements.txt` - Lists all Python dependencies.
- `src/cli/argument_parser.py` - Your CLI argument parsing module.
- `src/core/` - Your modules for core logic like discovery and enumeration.
- `src/handlers/` - Your "scanners" directory for wrapping external tools.
  - `nmap_handler.py` - Wraps `nmap`.
  - `smb_handler.py` - To be enhanced for `enum4linux-ng` and `smbmap`.
  - `http_handler.py` - **New file** for `nikto`, `gobuster`, and banner grabbing.
  - `dns_handler.py` - **New file** for `dnsrecon`.
  - `vulnerability_handler.py` - **New file** for `searchsploit`.
- `src/parsers/` - Your directory for parsing logic.
  - `nmap_parser.py` - Parses `nmap` output.
  - `smb_parser.py` - To be enhanced for new tools.
  - `http_parser.py` - **New file**.
  - `dns_parser.py` - **New file**.
  - `vulnerability_parser.py` - **New file**.
- `src/models/` - Your data models (e.g., `host_result.py`).
- `src/report/report_generator.py` - Your module for generating the final report.
- `src/utils/` - Your utilities for logging and network functions.
- `tests/` - Your directory for unit tests.

---

## Tasks (Updated to Your Progress)

- [x] 1.0 **Project Setup and Core Structure**
  - [x] 1.1 Create a Python 3.12 virtual environment and activate it.
    > *__Status:__ You have a `venv` directory, so this is complete.*
  - [x] 1.2 Initialize the modular project directory structure.
    > *__Status:__ Your `src` directory with its sub-packages is well-structured and complete.*
  - [x] 1.3 Create main package files (`src/__init__.py`, `src/main.py`).
    > *__Status:__ These files exist. Complete.*
  - [x] 1.4 Create `requirements.txt`.
    > *__Status:__ This file exists. You will need to add new dependencies as we integrate more tools.*
  - [x] 1.5 Set up basic `logging` configuration.
    > *__Status:__ You have a `src/utils/logger.py`, so this is complete.*
  - [x] 1.6 Create the data models.
    > *__Status:__ You have a `src/models/` directory with several result models. This is complete, though we may need to add fields as we integrate more tools.*
  - [ ] 1.7 Create a generic utility in `src/utils/shell.py` to reliably execute external commands and capture their output.
    > *__Why:__ Creating a standardized wrapper for `subprocess` will make all your handler modules cleaner and more consistent.*

- [x] 2.0 **CLI and Input Processing**
  - [x] 2.1 Implement `argparse` for command-line arguments.
    > *__Status:__ You have `src/cli/argument_parser.py`. Complete.*
  - [ ] 2.2 Create or enhance a parser in `src/utils/target_parser.py` for target and exclusion strings.
  - [ ] 2.3 Write unit tests in `tests/` for the target parser.
  - [ ] 2.4 Implement the DNS Safety feature in `src/main.py` or a core module.

- [ ] 3.0 **Stage 1: Initial Discovery**
  - [ ] 3.1 In `src/utils/network_utils.py`, create a "pre-flight" function that uses `socket` to quickly check if a host is reachable on a common port (e.g., 80 or 443) before launching a full scan.
    > *__Why:__ This makes our tool more efficient. If a host doesn't respond to a simple socket connection, we can potentially skip the much slower, more intensive Nmap scan, saving a significant amount of time on large networks.*
  - [ ] 3.2 In `src/handlers/nmap_handler.py`, ensure the `nmap` scan performs service version detection (`-sV`) and outputs to XML (`-oX`).
  - [ ] 3.3 In `src/parsers/nmap_parser.py`, ensure it can parse the Nmap XML output into your `HostResult` objects.

- [ ] 4.0 **Stage 2: Vulnerability Correlation (Searchsploit)**
  - [ ] 4.1 In your main controller/orchestrator logic, add a step to call a new vulnerability handler for each service version found.
  - [ ] 4.2 Create `src/handlers/vulnerability_handler.py` to run `searchsploit --json`.
  - [ ] 4.3 Create `src/parsers/vulnerability_parser.py` to parse the JSON output.
  - [ ] 4.4 Update your models in `src/models/` to store exploit information.

- [ ] 5.0 **Stage 3: Service-Specific Deep Enumeration**
  - [ ] 5.1 Implement the main orchestration logic in your controller to call specialized handlers based on port.
  - [ ] 5.2 **HTTP/S Enumeration:**
    - [ ] 5.2.1 Create `src/handlers/http_handler.py` to run `nikto` and `gobuster`.
    - [ ] 5.2.2 In the same `http_handler.py`, add a "manual banner grabbing" function using `socket`.
    - [ ] 5.2.3 Create `src/parsers/http_parser.py` to parse the output from all HTTP tools.
  - [ ] 5.3 **SMB Enumeration:**
    - [ ] 5.3.1 Enhance `src/handlers/smb_handler.py` to also run `smbmap` for permissions, in addition to `enum4linux-ng` for general info.
    - [ ] 5.3.2 Enhance `src/parsers/smb_parser.py` to handle output from both tools.
  - [ ] 5.4 **DNS Enumeration:**
    - [ ] 5.4.1 Create `src/handlers/dns_handler.py` to run `dnsrecon`.
    - [ ] 5.4.2 Create `src/parsers/dns_parser.py` to parse its output.

- [ ] 6.0 **Stage 4: Report Generation**
  - [ ] 6.1 Enhance `src/report/report_generator.py` to handle the data from all the new handlers.
  - [ ] 6.2 Add a "Scan Summary & Cross-Host Analysis" section at the top of the report using `collections.Counter` and `set`.
  - [ ] 6.3 Ensure the report includes dedicated sections for findings from `Searchsploit`, `Nikto`, `Gobuster`, `smbmap`, etc.

- [ ] 7.0 **Finalization and Documentation**
  - [ ] 7.1 Write a comprehensive `README.md`.
  - [ ] 7.2 Write `contributions.md` and `limitations.md`.
  - [ ] 7.3 Generate sample reports in the `samples/` directory.

- [ ] 8.0 **CLI User Experience Enhancements**
  - [ ] 8.1 Implement an ASCII art banner for tool startup.

