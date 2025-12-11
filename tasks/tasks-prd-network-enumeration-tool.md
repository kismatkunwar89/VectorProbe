## Relevant Files

- `main.py` - The main entry point for the CLI application. Will handle argument parsing and orchestrate the scan.
- `requirements.txt` - Lists all Python dependencies for the project.
- `net_enum_tool/` - Main package directory for the tool.
- `net_enum_tool/controller.py` - The main controller to manage the workflow: parsing inputs, running scans, and generating reports.
- `net_enum_tool/utils/target_parser.py` - A utility module to parse the complex target and exclusion strings.
- `net_enum_tool/utils/target_parser.test.py` - Unit tests for the target parser.
- `net_enum_tool/models/host.py` - Data class or model to store all information about a single host.
- `net_enum_tool/scanners/base_scanner.py` - An abstract base class for different scanner types.
- `net_enum_tool/scanners/nmap_scanner.py` - The implementation for running `nmap` commands for general enumeration.
- `net_enum_tool/scanners/windows_scanner.py` - The implementation for running Windows-specific enumeration tools.
- `net_enum_tool/parsers/nmap_parser.py` - Module to parse the raw output from `nmap` scans into structured data.
- `net_enum_tool/parsers/nmap_parser.test.py` - Unit tests for the nmap parser using sample `nmap` output.
- `net_enum_tool/reporting/report_generator.py` - The module responsible for creating the final Markdown report from the collected host data.
- `README.md` - Top-level documentation with installation and usage instructions.
- `contributions.md` - Documentation of individual partner contributions.
- `limitations.md` - Documentation of any known limitations or edge cases.
- `samples/` - Directory to hold sample output reports.

### Notes

- The project structure is modular to align with the PRD's design considerations.
- Testing should be done using Python's `unittest` or `pytest` framework. You can run tests with `python -m unittest discover`.

---

## Tasks

- [ ] 1.0 **Project Setup and Core Structure**
  - [ ] 1.1 Create a Python 3.12 virtual environment.
    > *__Why:__ This command creates a self-contained directory that holds a specific Python interpreter version and its libraries. It isolates your project's dependencies from other projects and the system's global Python, preventing version conflicts.*
  - [ ] 1.2 Initialize the project directory structure (`net_enum_tool/`, `tests/`, `samples/`).
    > *__Why:__ A clean, predictable directory structure is key to a scalable project. This separates your main application code (`net_enum_tool/`) from your tests (`tests/`) and other project artifacts.*
  - [ ] 1.3 Create the main package files (`net_enum_tool/__init__.py`, `main.py`).
    > *__Why:__ `main.py` will be the script's entry point that you run from the terminal. The `__init__.py` file tells Python to treat the `net_enum_tool/` directory as a "package," allowing you to import modules from it using dot notation (e.g., `from net_enum_tool.scanners import ...`).*
  - [ ] 1.4 Create the `requirements.txt` file and add initial libraries (e.g., `netaddr` for IP parsing).
    > *__Why:__ This file lists all the external Python libraries your project needs. It allows anyone (including the grader) to install the exact same dependencies with a single command (`pip install -r requirements.txt`), ensuring the environment is reproducible.*
  - [ ] 1.5 Set up a basic `logging` configuration for the application.
    > *__Why:__ Instead of using `print()` statements for debugging, the `logging` module provides a more powerful way to track events. It allows you to set different severity levels (DEBUG, INFO, ERROR) and control where the output goes, making debugging much easier.*
  - [ ] 1.6 Create the data model `net_enum_tool/models/host.py` to hold host information (IP, OS, services, etc.).
    > *__Why:__ This step involves creating a Python class (like a `Host` class) to act as a structured container for your data. Instead of passing around messy dictionaries, you'll have a clean `host` object with defined attributes (`host.ip`, `host.os`), which improves code readability and maintainability.*
  - [ ] 1.7 Set up testing framework (unittest or pytest) and create initial test structure.
    > *__Why:__ Establishing the testing framework early ensures consistent test patterns and makes it easier to implement unit tests as you build each component. This involves creating a `tests/` directory structure and configuring the test runner.*

- [ ] 2.0 **CLI and Input Processing**
  - [ ] 2.1 In `main.py`, implement `argparse` to handle all command-line arguments (`--targets`, `--exclude`, `-o`, `--help`).
    > *__Why:__ `argparse` is the standard Python library for creating a professional Command-Line Interface (CLI). It will parse the arguments you provide on the command line, automatically generate a helpful `--help` message, and make the inputs available to your script in a clean, accessible way.*
  - [ ] 2.2 Create `net_enum_tool/utils/target_parser.py` to handle the logic for parsing comma-separated lists of IPs, CIDR ranges, and DNS names.
    > *__Why:__ The input from the user can be complex. This module's job is to take that raw string and turn it into a clean list of IP addresses to scan. Separating this logic into its own file follows the "Single Responsibility Principle" and makes the code easier to test and manage.*
  - [ ] 2.3 Write unit tests in `target_parser.test.py` to validate the parsing logic.
    > *__Why:__ Unit tests verify that a small, isolated piece of code (a "unit") works as expected. For the target parser, you'll give it sample inputs (like "8.8.8.8, 192.168.1.0/30") and assert that it produces the correct list of IPs. This ensures your core logic is reliable.*
  - [ ] 2.4 Implement the DNS Safety feature: when a DNS name is provided, get the system's DNS server and prompt the user for confirmation before proceeding.
    > *__Why:__ This is a critical safety and ethics feature. It prevents you from accidentally scanning an out-of-scope target if your local DNS server resolves a name to an unexpected IP. It forces the operator to be deliberate and accountable.*

- [ ] 3.0 **General Enumeration Engine**
  - [ ] 3.1 Create a utility in a `utils` module to reliably execute external shell commands and capture their output.
    > *__Why:__ Your Python script will need to run command-line tools like `nmap`. This utility function (using Python's `subprocess` module) will be a reusable wrapper to run any external command, wait for it to finish, and capture its text output and any errors for later parsing.*
  - [ ] 3.2 In `net_enum_tool/scanners/nmap_scanner.py`, create a class to wrap `nmap` commands for host discovery, OS detection, and service scanning.
    > *__Why:__ This applies the Object-Oriented principle of "Abstraction". Instead of writing raw `nmap` commands in your main logic, you'll create a `NmapScanner` class with clean methods like `scanner.discover_hosts()`. This makes the main controller easier to read and separates the "how" (nmap commands) from the "what" (discovering hosts).*
  - [ ] 3.3 In `net_enum_tool/parsers/nmap_parser.py`, implement functions to parse the raw text output from nmap into the `Host` data model. Use regex as required.
    > *__Why:__ The raw text output from a tool is just a blob of text. This parser's job is to systematically go through that text, find the important details (like open ports, service versions, OS guesses), and put them into the structured `Host` object you created earlier. This is where you turn raw data into actionable information.*
  - [ ] 3.4 Write unit tests for the `nmap_parser` using saved `nmap` output as test fixtures.
    > *__Why:__ You'll save the real text output from a few `nmap` scans into files. Your unit tests will feed this saved text to your parser and check if it correctly extracts the information. This lets you perfect your parsing logic without having to run a slow `nmap` scan every time you test.*
  - [ ] 3.5 In `net_enum_tool/controller.py`, implement the main logic to iterate through targets, run the general scans, parse the results, and store them.
    > *__Why:__ The controller is the "brain" of the operation. It will take the list of targets from the CLI, use the `NmapScanner` to run scans against them, pass the output to the `NmapParser`, and store the resulting `Host` objects in a list, orchestrating the whole workflow.*

- [ ] 4.0 **Windows-Specific Enumeration**
  - [ ] 4.1 In the `controller`, add logic to check if a host's detected OS is "Windows".
    > *__Why:__ This is the decision-making step. After a general scan, the controller will inspect the `host.os` attribute. If it contains "Windows", it will trigger the next phase of specialized scanning.*
  - [ ] 4.2 Create `net_enum_tool/scanners/windows_scanner.py` to execute Windows-specific tools (e.g., `enum4linux-ng`, `nbtscan`).
    > *__Why:__ Similar to the `NmapScanner`, this class will abstract away the specific commands for Windows enumeration tools. This keeps your code organized and modular, making it easy to add more Windows scanning techniques later.*
  - [ ] 4.3 Create a corresponding parser module `net_enum_tool/parsers/windows_parser.py`.
    > *__Why:__ Just like the nmap parser, this module is responsible for turning the raw text output from Windows-specific tools into structured data that can be added to your `Host` object.*
  - [ ] 4.4 Integrate the Windows scanning step into the main controller, so it runs automatically for Windows hosts.
    > *__Why:__ This involves updating the controller's main loop. After a host is identified as Windows, the controller will now call the `WindowsScanner` and `WindowsParser` to gather and process additional details.*
  - [ ] 4.5 Update the `Host` model if necessary to store the additional Windows-specific information.
    > *__Why:__ Your `Host` class may need new attributes to store data that only comes from Windows scans, like NetBIOS names or SMB shares. This step ensures your data container can hold all the required information.*

- [ ] 5.0 **Report Generation**
  - [ ] 5.1 In `net_enum_tool/reporting/report_generator.py`, create the main report generation class.
    > *__Why:__ This class will be solely responsible for creating the final report. It will take the final list of rich `Host` objects and use that data to build the output, separating the reporting logic from the scanning and parsing logic.*
  - [ ] 5.2 Implement a function to generate the default UTC timestamped filename.
    > *__Why:__ This involves using Python's `datetime` library to get the current time, convert it to UTC for standardization, and format it into the string required by the project (`host_enumeration_report_YYYYMMDD_HHMM_UTC.md`).*
  - [ ] 5.3 Create a method that takes the list of `Host` objects and constructs the full Markdown report string.
    > *__Why:__ This is the core of the reporting module. The method will loop through each `Host` object, format its attributes into Markdown tables and code blocks, and assemble everything into one large string variable.*
  - [ ] 5.4 Ensure the report structure (Verified table, Unverified section, Command Outputs) is correctly implemented for each host.
    > *__Why:__ This is a detailed formatting task. You'll be building Markdown syntax in your Python code, making sure every header, table, and code block appears exactly as required by the project specification.*
  - [ ] 5.5 Implement the final step of writing the report string to the correct file path (either default or from the `-o` option).
    > *__Why:__ This final I/O (Input/Output) step involves opening a file for writing and saving the complete Markdown string you've built to the disk, which completes the tool's primary function.*

- [ ] 6.0 **Finalization and Documentation**
  - [ ] 6.1 Write the `README.md` file with clear installation instructions, dependencies, and usage examples for all CLI options.
    > *__Why:__ The README is the front door to your project. It's the first thing others will see. It must clearly explain what the project is, how to set it up, and how to use it. This is a critical piece of documentation.*
  - [ ] 6.2 Write the `contributions.md` file detailing individual contributions.
    > *__Why:__ This is a project requirement for ensuring accountability and fair grading. It's a simple text file that lists which partner worked on which components.*
  - [ ] 6.3 Write the `limitations.md` file documenting any discovered edge cases or limitations.
    > *__Why:__ Professional tools are honest about what they can't do. This file shows you've thought critically about your tool's boundaries, such as what happens if a host doesn't respond or if a tool provides unexpected output.*
  - [ ] 6.4 Run the tool against at least 5 different hosts (including Windows and Linux) and save the output reports in the `samples/` directory.
    > *__Why:__ This is the final validation step to prove your tool works in a variety of scenarios. The sample reports serve as tangible proof of functionality for your project submission.*
  - [ ] 6.5 Review all code for PEP 8 compliance and add comments/docstrings where necessary.
    > *__Why:__ PEP 8 is the official style guide for Python code. Adhering to it makes your code consistent and readable to other Python developers. Docstrings are special comments that explain what a function or class does, and they can be automatically pulled into documentation.*

- [ ] 7.0 **CLI User Experience Enhancements**
  - [ ] 7.1 Implement an ASCII art banner for tool startup, using `figlet`, `toilet`, `lolcat`, or `boxes`.
    > *__Why:__ While not functionally critical, an aesthetically pleasing command-line interface enhances the user experience. Using tools like `figlet` (for large text), `toilet` (similar to figlet with more effects), `lolcat` (for rainbow colors), or `boxes` (for framed text) can make the tool feel more polished and engaging. This step involves installing one or more of these external CLI tools and integrating their output into your Python script upon startup.*
