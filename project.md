# Ethical Hacking:

# Final Project

### Name Email

### Charles R Barone IV crbarone@newhaven.edu

### TA Not Assigned* To Be Determined

```
* - TA for Ethical Hacking.
```
```
This lab should be completed with your lab group.
```
### November 17, 2025


## 1 Project Summary

This project takes the place of a standard Final Exam for the course. This project is
to be completed with your “Final Project Partner” which you can find on Canvas. The
project consists of developing a sophisticated network enumeration tool that leverages the
various reconnaissance and enumeration techniques learned throughout the course. **This
final project is 25% of your final course grade!**

Your team will develop a Python-based enumeration script that automates the discovery
and documentation of network hosts, services, and vulnerabilities. The tool should inte-
grate multiple enumeration techniques and produce a comprehensive, professional report in
Markdown format.

## 2 Technical Requirements

### 2.1 Programming Requirements

- The script must be written in **Python 3.12** (specifically version 3.12)
- Include a requirements.txt file listing all Python dependencies
- Code should be well-commented and follow PEP 8 style guidelines
- Implement proper error handling and logging
- The script must be executable from the command line

### 2.2 Command-Line Interface

The tool must support the following command-line options:

- **Target Specification:**
    **-** Individual IPv4 addresses (e.g., 192.168.1.1)
    **-** DNS records (e.g., server.example.com)
    **-** Subnets in CIDR notation (e.g., 192.168.1.0/24)
    **-** Comma-separated lists of any combination of the above
- **Excluded Hosts Specification: Critical:** This option, while very similar to the
    above _Target Specification_ requirement, must exist to allow the operator to **exclude**
    out of scope hoststhat fall within the provided _Target Specification_.
       **-** Individual IPv4 addresses (e.g., 192.168.1.1)
       **-** DNS records (e.g., server.example.com)
       **-** Subnets in CIDR notation (e.g., 192.168.1.0/24)
       **-** Comma-separated lists of any combination of the above


- **Required Options:**
    **-** –help: Display comprehensive usage information and examples
    **-** -o <path>: Override the default output file name and location
- **DNS Safety Feature:** When DNS records are provided, the tool must:
    **-** Display the currently configured DNS server
    **-** Prompt for confirmation (y/N) before proceeding
    **-** Default to “No” if no input is provided
    **-** This prevents accidental scope violations due to DNS misconfiguration

### 2.3 Enumeration Capabilities

The tool must integrate and automate the following enumeration techniques:

**2.3.1 General Host Enumeration**

- Host discovery and availability verification
- Operating system detection (Windows/Linux/Unix/Unknown)
- Service discovery (ports, protocols, service names)
- Network topology mapping (if applicable)
- Use regex and parsing to extract actionable information

**2.3.2 Windows-Specific Enumeration**
When a Windows host is detected, the tool should additionally run:

- SMB enumeration tools
- NetBIOS enumeration
- Active Directory information gathering (if domain-joined)
- Windows-specific service enumeration
- As done in _General Host Enumeration_ , again use regex and parsing to extract actionable
    information

### 2.4 Report Generation

**2.4.1 Output File Requirements**

- **Format:** Markdown (.md)
- **Location:** Current working directory of shell (where the script is executed from, not
    the location of the script on the file-system)


- **Default Naming:** host_enumeration_report_YYYYMMDD_HHMM_UTC.md
    **-** Must include date and time the enumeration script **started**
    **-** Time must be converted to and displayed in UTC
    **-** Timezone (UTC) must be included in the filename
- **Custom Naming:** Support -o option for custom path/filename

**2.4.2 Report Structure**
Each enumerated host must have its own section containing:

1. **Verified Information Table**
    - IP Address
    - Hostname
    - Domain (if joined to Active Directory)
    - Active Services (service name, port, protocol)
    - Operating System Type
    - Windows-specific information (if applicable)
2. **Unverified Information Section**
    - Probable but unconfirmed details
    - Example: “OS Version is at least Windows Server 2008 R2 or Windows 7”
    - Potential vulnerabilities based on service versions
3. **Command Outputs Section**
    - Each command executed displayed in a single-line code block
    - Raw output in multi-line code blocks
    - Include all commands used to generate the report data
    - Example format:
       1 Command: ‘nmap −sV −sC −p− 192.168.1.1‘
       2 ‘‘‘
       3 [Raw nmap output here]
       4 ‘‘‘

## 3 Project Deliverables

### 3.1 Part 1: Tool Development (40% of project grade)

- Develop the enumeration script meeting all technical requirements


- Create comprehensive –help documentation
- Include a requirements.txt file
- Implement all required features and options
- Each partner should contribute specific modules/features (document individual contri-
    butions in a contributions.md file)
- The developed tool should not be one monolithic python file, The tool should leverage
    object oriented practices to divide the code into separate modules or components.
    This is one example of how part of the logic could be broken up into separate classes
    and files:
       **-** There could be an nmap handler class that creates functions for mapping each
          of the nmap command line operations to python functions which each return
          the raw nmap output as a string (e.g., a few examples could be: nmap_udp(),
          nmap_tcp_full(), and nmap_tcp_quick())
       **-** Then, a separate nmap parser class is created to interpret the returned results,
          which are then mapped to an nmap result class which is returned.
       **-** The returned nmap result class could then be stored in a dictionary that maps
          the dictionary index - which could be an IPv4 address - to said host’s nmap result
          object which holds the result of parsing the nmap responses for a given host, thus
          allowing for efficient access later in some form of report builder class.
       **-** You may also want to consider including a set of class member functions within
          the result classes so that during report generation your tool specific formatting is
          more streamlined and simple. It could prove useful to have something along the
          lines of nmap_results[host_ip].raw_command_output_markdown() which could
          return the raw command and output as markdown for that result with the correct
          formatting including the code blocks and labels (This can also be done for the
          other sections of the report as well).

### 3.2 Part 2: Testing and Validation (20% of project grade)

- Test the tool against a minimum of 5 different hosts/networks
- Include testing against both Windows and Linux systems
- Document any limitations or edge cases discovered in limitations.md
- Create sample output reports that demonstrate functionality (include these in the
    samples/ directory)

### 3.3 Part 3: Technical Documentation (20% of project grade)

- **README.md:** Installation instructions, dependencies, usage examples


- **User Guide:** Detailed usage instructions with examples in the
- **Code Documentation:** Inline comments and docstrings

### 3.4 Part 5: Presentation (20% of project grade)

- 15-minute demonstration of the tool’s capabilities
- Live demonstration against test targets
- Discussion of design decisions and challenges
- Q&A session
- **Penalty:** -2% for each minute over 15 minutes


## 4 Grading Rubric

```
Component Criteria Points
Part 1: Tool Development (40 points)
Target Parsing Correctly handles IPs, DNS, CIDR, and comma-separated
lists
```
#### 5

```
Exclusion Feature Properly implements host exclusion for out-of-scope targets 5
Host Enumeration Accurate OS detection, service discovery, and information
gathering with regex parsing
```
#### 7

```
Windows Features Implements Windows-specific enumeration when applica-
ble
```
#### 5

```
Report Generation Produces correctly formatted Markdown with all required
sections
```
#### 5

```
File Management Correct UTC timestamp, default naming, and -o option
support
```
#### 3

```
Modular Design Modular design that leverages Object-Oriented practices
with separate classes/modules (not one monolithic python
file)
```
#### 5

```
DNS Safety Implements DNS resolver confirmation prompt when DNS
records provided
```
#### 3

```
Error Handling Graceful handling of network errors, timeouts, and edge
cases
```
#### 2

```
Part 2: Testing and Validation (20 points)
Test Coverage Tests against minimum 5 hosts/networks including Win-
dows and Linux
```
#### 8

```
Sample Reports Provides sample output reports in samples/ directory 6
Limitations Doc Documents limitations and edge cases in limitations.md 6
Part 3: Technical Documentation (20 points)
–help Option Comprehensive, well-formatted help documentation 5
README.md Clear installation instructions, dependencies, and usage ex-
amples
```
#### 5

```
User Guide Detailed usage instructions with examples 4
requirements.txt Complete and functional dependency list 2
Code Documentation Quality inline comments and docstrings 2
contributions.md Clear documentation of individual partner contributions 2
Part 5: Presentation (20 points)
Live Demonstration Successfully demonstrates all major features against test
targets
```
#### 10

```
Design Discussion Clearly explains design decisions and challenges encoun-
tered
```
#### 5

```
Time Management Stays within 15-minute limit (-2% per minute over) 3
Q&A Knowledgeable responses to questions 2
Total: 100 points (25% of course grade)
```

## 5 Testing Requirements

For grading purposes, the following testing procedure will be used:

1. Create a fresh Python 3.12 virtual environment
2. Run pip install -r requirements.txt
3. Execute python [script_name] –help to review documentation
4. Test enumeration against a variety of hosts and networks
5. Verify report output format and content accuracy
6. Test all command-line options and error handling

## 6 Important Notes

- **Collaboration:** While this is a partner project, each student must be able to explain
    all aspects of the code
- **Academic Integrity:** Code must be original work. Cite any external libraries or code
    snippets used. (For external code snippets, a single line comment with a link to the
    source above the code will suffice)
- **Scope:** Only test against authorized targets. Never run this tool against systems you
    don’t own or have explicit permission to test.
- **Best Practices:** Follow industry-standard security testing methodologies and docu-
    mentation practices

## 7 Submission Requirements (High Level Overview)

Submit the following via Canvas by the deadline:

- Complete Python scripts
- requirements.txt file
- All documentation (README, Design Document, User Guide, any markdown files
    stated above, etc)
- Sample output reports from testing in samples/
- Individual contribution statement (who did what) in contributions.md.
    **IMPORTANT:** During your presentation, this file will be used to drive who is asked
    each technical question, so please ensure that the contribution statement is correct.
       **-** If you indicate claims to redirect questions during the presentation Q&A that
          conflict with your provided contributions.md your grade may be subject to ad-
          justment for providing inaccurate information in your submission.


**-** For instance, if you respond to a question claiming that the question would be
    better suited for your partner as they built said component, meanwhile your pro-
    vided contributions.md indicates you built said component, it will be assumed
    nothing in contributions.md was accurate...
**-** i.e., be prepared to talk about the things you claim to have contributed to...
**-** It is also not realistic to have each partner evenly contribute to every single compo-
    nent of the project, thus please do not attempt to circumvent the situation above
    by listing everyone on every component.
**-** Simply be honest about who contributed to each component of the project.
    **Help me help YOU!** I will be creating my questions in advance based upon
    your submission! The included contributions.md file allows me to ensure I am
    giving each of you the best chance for success on the presentation Q&A!

## 8 Questions

```
Any questions about the project should be directed to the instructor (Charles R Barone
```
### IV). Available by email at: crbarone@newhaven.edu


