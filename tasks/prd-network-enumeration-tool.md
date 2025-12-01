# Product Requirements Document: Network Enumeration Tool

## 1. Introduction/Overview

This document outlines the requirements for a sophisticated network enumeration tool. The project's goal is to develop a Python-based script that automates the discovery and documentation of network hosts, services, and potential vulnerabilities. The tool will be operated via a command-line interface (CLI) and will produce a professional, comprehensive report in Markdown format. This tool is intended to streamline the reconnaissance phase for a junior security analyst.

## 2. Goals

*   **Fulfill Academic Requirements:** Satisfy all technical and documentation requirements for the Ethical Hacking final project to achieve a high grade.
*   **Improve Efficiency:** Automate repetitive enumeration tasks to accelerate the information-gathering phase of a security assessment.
*   **Produce Professional Reports:** Generate clear, well-structured, and actionable reports suitable for technical review.
*   **Build a Reusable Tool:** Create a robust, modular, and extensible tool that can be used for personal projects or labs beyond the course.

## 3. User Stories

*   **Story 1:** As a security analyst, I want to scan a whole subnet but exclude a specific sensitive server, so I can get a complete inventory of active hosts without disrupting critical systems.
*   **Story 2:** As a pen tester, I want the tool to automatically run deeper Windows-specific checks (like SMB enumeration) when it detects a Windows host, so I can speed up my search for common vulnerabilities.
*   **Story 3:** As a consultant, I want to provide a domain name for scanning and be forced to confirm the resolved IP addresses, so I can prevent accidental out-of-scope testing due to DNS misconfigurations.

## 4. Functional Requirements

### Core Application
1.  The script **must** be written in Python 3.12.
2.  All external Python dependencies **must** be listed in a `requirements.txt` file.
3.  The code **must** be well-commented and follow PEP 8 style guidelines.
4.  The script **must** implement proper error handling and logging for issues like network timeouts or invalid user input.

### Command-Line Interface (CLI)
5.  The tool **must** be executable from the command line.
6.  The tool **must** support target specification via:
    *   Individual IPv4 addresses (e.g., `192.168.1.1`)
    *   DNS records (e.g., `server.example.com`)
    *   Subnets in CIDR notation (e.g., `192.168.1.0/24`)
    *   A comma-separated list of any combination of the above.
7.  The tool **must** support the exclusion of hosts using the same specification formats as target selection.
8.  The tool **must** provide a comprehensive usage and examples page when run with the `--help` flag.
9.  The tool **must** allow the user to specify a custom output file path and name using the `-o <path>` option.

### DNS Safety Feature
10. When a DNS record is provided as a target, the tool **must** display the system's currently configured DNS server.
11. The tool **must** then prompt the user for confirmation (y/N) before proceeding with the scan.
12. The confirmation prompt **must** default to "No" if no input is provided.

### Enumeration Capabilities
13. The tool **must** perform general host enumeration, including:
    *   Host discovery and availability verification.
    *   Operating system detection (Windows/Linux/Unix/Unknown).
    *   Service discovery (ports, protocols, service names).
14. When a Windows host is detected, the tool **must** automatically perform additional Windows-specific enumeration, including:
    *   SMB enumeration.
    *   NetBIOS enumeration.
    *   Active Directory information gathering (if applicable).
15. All tool output **must** be parsed using methods like regex to extract actionable, verified information.

### Report Generation
16. The tool **must** generate a report in Markdown (`.md`) format.
17. By default, the report **must** be saved in the current working directory.
18. The default report filename **must** follow the format `host_enumeration_report_YYYYMMDD_HHMM_UTC.md`, using the UTC time when the script started.
19. Each host in the report **must** have its own section with the following structure:
    *   **Verified Information Table:** A table containing the host's IP Address, Hostname, Domain, Active Services (with ports/protocols), and Operating System.
    *   **Unverified Information Section:** A section for probable but unconfirmed details (e.g., "OS version is likely...").
    *   **Command Outputs Section:** A section containing the exact commands executed for the host, each followed by the raw output in a code block.

## 5. Non-Goals (Out of Scope)

*   This tool will **not** actively exploit any discovered vulnerabilities.
*   This tool will **not** perform any form of denial-of-service (DoS) or stress testing.
*   This tool will **not** have a graphical user interface (GUI); it is a CLI-only application.

## 6. Design Considerations

*   The tool **must** be built with a modular, object-oriented design. It should not be a single, monolithic script.
*   The design should follow the example provided in the project description, such as separating logic into:
    *   A **handler class** for wrapping external tools (e.g., `NmapHandler`).
    *   A **parser class** for interpreting raw text output.
    *   **Result objects** for storing structured data from the scans.
    *   **Report builder class** that uses the result objects to generate the final Markdown report.

## 7. Technical Considerations

*   The Python 3.12 version is a strict requirement.
*   The application will depend on executing external command-line tools (e.g., `nmap`, `nbtscan`, `enum4linux-ng`) and capturing their standard output. The presence of these tools on the host system is a dependency.

## 8. Success Metrics

*   **Primary Metric:** The tool meets all criteria outlined in the course grading rubric, leading to a project grade of 90% or higher.
*   **Functional Metric:** The tool successfully runs against a test network of at least 5 hosts (including Windows and Linux) and generates a complete, accurate report.
*   **Code Quality Metric:** The codebase adheres to PEP 8 standards and the specified object-oriented design.

## 9. Open Questions

*   What specific external CLI tools (e.g., `nmap`, `nbtscan`, `enum4linux-ng`) are permitted or recommended for use to complete the enumeration tasks?
*   Are there any off-limit Python libraries?
