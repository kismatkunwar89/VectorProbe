## Relevant Files (Updated to Reflect Current Progress)

- `src/main.py` - Your main entry point.
- `requirements.txt` - Lists all Python dependencies.
- `pytest.ini` - For configuring the test framework.
- `src/cli/argument_parser.py` - Your CLI argument parsing module.
- `src/handlers/` - Your "scanners" directory.
  - `masscan_handler.py` - For wrapping `masscan`.
  - `nmap_handler.py` - Wraps `nmap`.
  - `smb_handler.py` - For `enum4linux-ng` and `smbmap`.
  - `http_handler.py` - For `nikto`, `gobuster`, and banner grabbing.
  - `dns_handler.py` - For `dnsrecon`.
  - `vulnerability_handler.py` - For `searchsploit`.
- `src/parsers/` - Your directory for parsing logic.
  - `masscan_parser.py` - For parsing `masscan` output.
  - `nmap_parser.py` - Parses `nmap` output.
  - `smb_parser.py` - For `enum4linux-ng` and `smbmap`.
  - `http_parser.py` - For `nikto` and `gobuster`.
  - `dns_parser.py` - For `dnsrecon`.
  - `vulnerability_parser.py` - For `searchsploit`.
- `src/models/` - Your data models.
  - `enumeration_result.py`
  - `host_result.py`
  - `service_result.py`
- `src/report/report_generator.py` - Your report generation module.
- `src/utils/` - Your utilities.
  - `shell.py`
  - `target_parser.py`
  - `dns_utils.py`
  - `network_utils.py`
  - `logger.py`
  - `validation.py`
  - `banner.py`
  - `decorators.py`
  - `query_builder.py`
- `tests/` - Your directory for unit tests.
  - `fixtures/` - To store sample outputs from tools.
  - `test_orchestration.py` - End-to-end test.
  - `test_masscan_parser.py`
  - `test_nmap_parser.py`
  - `test_smb_parser.py`
  - `test_vulnerability_parser.py`
  - `test_target_parser.py`
  - `test_host_model.py`

---

## Tasks (with Assignments - Updated)

- [x] 1.0 **Project Setup and Core Structure**
  > *__Covered by:__ Kismat & Gamvirta*
  - [x] 1.1 Venv setup.
  - [x] 1.2 Modular `src` directory structure.
  - [x] 1.3 Main package files.
  - [x] 1.4 `requirements.txt` created.
  - [x] 1.5 Logging utility created.
  - [x] 1.6 Data models created.
  - [x] 1.7 Create a generic utility in `src/utils/shell.py`.

- [x] 2.0 **CLI, Input, and Test Framework Setup**
  > *__Covered by:__ Gamvirta & Kismat*
  - [x] 2.1 Add `--fast-scan` flag to `src/cli/argument_parser.py`.
  - [x] 2.2 Enhance `src/utils/target_parser.py` for target/exclusion strings.
  - [x] 2.3 Implement the DNS Safety feature.
  - [x] 2.4 **Establish Pytest Framework**
    - [x] 2.4.1 Create `pytest.ini` at the project root.
    - [x] 2.4.2 Create `tests/fixtures/` directory.
  - [x] 2.5 Write unit tests in `tests/test_target_parser.py`.
    > *__Covered by:__ Kismat (29 tests - all passing)*

- [x] 3.0 **Stage 1 (Optional): High-Speed Discovery (Masscan)**
  > *__Covered by:__ Kismat*
  - [x] 3.1 In your controller, check if the `--fast-scan` flag is present.
  - [x] 3.2 Create `src/handlers/masscan_handler.py` to run `masscan`.
  - [x] 3.3 Create `src/parsers/masscan_parser.py` to parse its output.
  - [x] 3.4 **Write unit tests in `tests/test_masscan_parser.py` using a fixture file.**
    > *__Covered by:__ Kismat (31 tests - all passing)*

- [x] 4.0 **Stage 2: Foundational Deep Scan (Nmap)**
  > *__Covered by:__ Gamvirta (initial) & Kismat (enhancements)*
  - [x] 4.1 In `src/handlers/nmap_handler.py`, handle either a full scan or a `masscan`-based target list. Ensure XML output.
  - [x] 4.2 In `src/parsers/nmap_parser.py`, parse the Nmap XML.
  - [x] 4.3 **Write unit tests in `tests/test_nmap_parser.py` using a sample nmap fixture.**
    > *__Covered by:__ Kismat (17 tests - all passing)*

- [x] **Main Orchestration: Masscan + Nmap + Models + Report**
  > *__Covered by:__ Kismat*
  - [x] Wire Masscan execution and display results
  - [x] Wire Nmap execution (standard mode - no fast-scan)
  - [x] Wire Nmap execution (fast-scan mode - narrow scope)
  - [x] Implement `NmapHandler.scan_targets()` method for multi-target scanning
  - [x] Create HostResult models from parser output
  - [x] Generate Markdown reports with summary and host details
  - [x] Implement 4-stage orchestration workflow (Masscan → Nmap → Models → Report)
  - [x] Add display functions for formatted console output
  - [x] Complete end-to-end testing with `test_orchestration.py`
  - [x] All 118 unit tests passing
  > *__Status:__ COMPLETE - Full pipeline implemented and verified*

- [x] 5.0 **Stage 3: Vulnerability Correlation (Searchsploit)**
  > *__Covered by:__ Gamvirta*
  - [x] 5.1 In the controller, call the vulnerability handler for each service.
  - [x] 5.2 Create `src/handlers/vulnerability_handler.py` to run `searchsploit --json`.
  - [x] 5.3 Create `src/parsers/vulnerability_parser.py` to parse the JSON.
  - [x] 5.4 **Write unit tests in `tests/test_vulnerability_parser.py` using a sample `searchsploit.json` fixture.**
    > *__Covered by:__ Gamvirta (1 test - passing)*
  - [x] 5.5 Update data models to store exploit info.
    > *__Covered by:__ Gamvirta (ServiceResult.exploits field added)*

- [ ] 6.0 **Stage 4: Service-Specific Deep Enumeration**
  - [x] 6.1 Implement the orchestration logic in the controller.
    > *__Covered by:__ Kismat (Main 4-stage orchestration implemented)*
  - [c] 6.2 **HTTP/S Enumeration:**
    > *__Cancelled:__ Not explicitly required by project.md*
    - [c] 6.2.1 Create `http_handler.py` and `http_parser.py`.
    - [c] 6.2.2 **Write unit tests using fixtures.**
  - [x] 6.3 **SMB Enumeration:**
    > *__Covered by:__ Gamvirta (initial) & Kismat (enhancements)*
    - [x] 6.3.1 **Write unit tests using fixtures.**
      > *__Covered by:__ Kismat (27 tests - all passing, 4 fixture files)*
  - [c] 6.4 **DNS Enumeration:**
    > *__Cancelled:__ Not explicitly required by project.md (beyond the DNS Safety Feature, which is done)*
    - [c] 6.4.1 Create `dns_handler.py` and `dns_parser.py`.
    - [c] 6.4.2 **Write unit tests using fixtures.**
  - [x] 6.5 **Active Directory Enumeration (Unauthenticated)**
    > *__Covered by:__ Kismat*
    - [x] 6.5.1 Create `ad_handler.py` and `ad_parser.py` files.
      > *__Covered by:__ Kismat (ADHandler with 6 methods, ADParser with 7 parsing methods + LDAP merge)*
    - [x] 6.5.2 In `main.py`, implement trigger logic to run the AD handler if LDAP/Kerberos ports are found or if SMB enumeration indicates domain membership.
      > *__Covered by:__ Kismat (STAGE 3.7: Multi-criteria DC identification - LDAP/Kerberos ports, SYSVOL/NETLOGON shares, service detection)*
    - [x] 6.5.3 Implement LDAP `rootDSE` enumeration (`nmap --script ldap-rootdse`) in the handler and parser.
      > *__Covered by:__ Kismat (ldap_rootdse() method, parse_ldap_rootdse() for NSE output)*
    - [x] 6.5.4 Implement LDAP `baseDSE` enumeration (`ldapsearch`) in the handler and parser.
      > *__Covered by:__ Kismat (ldap_basedse() method, parse_ldap_basedse() with LDIF multi-line continuation, merge_ldap_data() with Base DSE precedence)*
    - [x] 6.5.5 Implement SMB security posture enumeration (`nmap --script smb-enum-domains,smb-security-mode`) in the handler and parser.
      > *__Covered by:__ Kismat (smb_security_mode() method, parse_smb_security() with relay attack interpretation)*
    - [x] 6.5.6 Implement NetBIOS role enumeration (`nmblookup -A`) in the handler and parser.
      > *__Covered by:__ Kismat (netbios_role() method, parse_netbios_role() with DC detection via <1c>/<1b> groups)*
    - [x] 6.5.7 Implement DNS SRV record enumeration (`dig SRV ...`) in the handler and parser.
      > *__Covered by:__ Kismat (dns_srv_records() method, parse_dns_srv() with .local domain interpretation)*
    - [x] 6.5.8 Implement Kerberos info enumeration (`nmap --script krb5-info`) in the handler and parser.
      > *__Covered by:__ Kismat (kerberos_info() method, parse_kerberos_info() with graceful script unavailability handling)*
    - [x] 6.5.9 Update `report_generator.py` to add the new `### Active Directory Enumeration (Unauthenticated)` section with all required subsections.
      > *__Covered by:__ Kismat (_format_ad_enumeration_section() with 6 subsections: AD Identity & Roles, Functional Levels, Naming Contexts, LDAP Capabilities, SMB Security, NetBIOS, DNS SRV, conditional rendering to avoid redundancy)*
    - [x] 6.5.10 Write unit tests in `tests/test_ad_parser.py` using fixtures for all new tool outputs.
      > *__Covered by:__ Kismat (43 tests - all passing, 8 fixture files from real FNN.LOCAL DC: ldap_rootdse, ldap_basedse, smb_security DC/workstation, netbios, dns_srv nxdomain/found, kerberos_unavailable)*
    - [ ] 6.5.11 Update `README.md` with new dependencies (`ldap-utils`, `dnsutils`) and `limitations.md` as per the plan.
      > *__To Do:__ Documentation update needed*


- [x] 7.0 **Stage 5: Report Generation**
  > *__Covered by:__ Kismat*
  - [x] 7.1 Initial `report_generator.py` created.
  - [x] 7.2 Add a "Scan Summary & Cross-Host Analysis" section.
  - [x] 7.3 Ensure the report includes sections for all new tools.

- [ ] 8.0 **Finalization and Documentation**
  > *__To Do:__ Both*
  - [ ] 8.1 Write a comprehensive `README.md`.
  - [ ] 8.2 Write `contributions.md` and `limitations.md`.
  - [ ] 8.3 Generate sample reports.
  - [ ] 8.4 Finalize `user_guide.md`.

- [x] 9.0 **CLI User Experience Enhancements**
  > *__Covered by:__ Kismat*
  - [x] 9.1 Implement an ASCII art banner.
    > *__Covered by:__ Kismat (Created `src/utils/banner.py` with VectorProbe ASCII art)*

