─$ cat report_dc.md    
# Network Enumeration Report

**Generated on:** 2025-12-14 21:14:29 UTC

## Summary

- **Total Hosts:** 1
- **Scan Type:** Masscan + Nmap
- **SMB Enumeration:** Enabled
- **NetBIOS Enumeration:** Enabled

## Network Topology

### 10.248.1.0/24

| IP | Hostname | OS | Services | Status |
|-------|----------|----|---------|---------|
| 10.248.1.2 | None | Microsoft Windows Server 2016 or Server 2019 | domain (53/tcp), kerberos-sec (88/tcp), msrpc (135/tcp)... (+10) | 🟢 Online |

## Discovered Hosts

### Host: 10.248.1.2

#### Basic Information

| Property | Value |
|----------|-------|
| IP Address | 10.248.1.2 |
| Hostname | None |
| Domain | None |
| OS Type | Microsoft Windows Server 2016 or Server 2019 |

#### Active Services

| Port | Protocol | Service | Fingerprint | Exploits |
|------|----------|---------|-------------|----------|
| 53 | tcp | domain | Simple DNS Plus | 1 found |
| 88 | tcp | kerberos-sec | Microsoft Windows Kerberos (server time: 2025-12-14 21:14:13Z) | None |
| 135 | tcp | msrpc | Microsoft Windows RPC | None |
| 139 | tcp | netbios-ssn | Microsoft Windows netbios-ssn | None |
| 389 | tcp | ldap | Microsoft Windows Active Directory LDAP (Domain: fnn.local, Site: Default-First-Site-Name) | 1 found |
| 445 | tcp | microsoft-ds | Windows Server 2016 Datacenter 14393 microsoft-ds (workgroup: FNN) | None |
| 464 | tcp | kpasswd5? | Unknown | None |
| 593 | tcp | ncacn_http | Microsoft Windows RPC over HTTP 1.0 | None |
| 636 | tcp | tcpwrapped | Unknown | None |
| 3268 | tcp | ldap | Microsoft Windows Active Directory LDAP (Domain: fnn.local, Site: Default-First-Site-Name) | 1 found |
| 3269 | tcp | tcpwrapped | Unknown | None |
| 3389 | tcp | ms-wbt-server | Microsoft Terminal Services | None |
| 5985 | tcp | http | Microsoft HTTPAPI httpd  (SSDP/UPnP) 2.0 | None |

**Exploits for domain (1)**

- Simple DNS Plus 5.0/4.1 - Remote Denial of Service [EDB-6059] – /usr/share/exploitdb/exploits/windows/dos/6059.pl

**Exploits for ldap (1)**

- Microsoft Windows Server 2000 - Active Directory Remote Stack Overflow [EDB-22782] – /usr/share/exploitdb/exploits/windows/remote/22782.py

**Exploits for ldap (1)**

- Microsoft Windows Server 2000 - Active Directory Remote Stack Overflow [EDB-22782] – /usr/share/exploitdb/exploits/windows/remote/22782.py

#### SMB Enumeration

**Domain:** FNN

**OS:** Windows Server 2016 Datacenter 14393

**Null Sessions:** ALLOWED ⚠

#### NetBIOS Enumeration

---

## Command Outputs

All commands executed during the enumeration process:

### 1. Nmap

**Command:** `nmap -sS -sV -sC -O -Pn -oN - 10.248.1.2`

**Output:**

```
# Nmap 7.95 scan initiated Sun Dec 14 16:14:06 2025 as: /usr/lib/nmap/nmap --privileged -sS -sV -sC -O -Pn -oN - 10.248.1.2
Nmap scan report for 10.248.1.2
Host is up (0.00023s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-14 21:14:13Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fnn.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds  Windows Server 2016 Datacenter 14393 microsoft-ds (workgroup: FNN)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fnn.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-12-14T21:14:23+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: FNN
|   NetBIOS_Domain_Name: FNN
|   NetBIOS_Computer_Name: FNN-DC01
|   DNS_Domain_Name: fnn.local
|   DNS_Computer_Name: FNN-DC01.fnn.local
|   DNS_Tree_Name: fnn.local
|   Product_Version: 10.0.14393
|_  System_Time: 2025-12-14T21:14:15+00:00
| ssl-cert: Subject: commonName=FNN-DC01.fnn.local
| Not valid before: 2025-10-27T03:02:19
|_Not valid after:  2026-04-28T03:02:19
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
MAC Address: F0:DB:30:76:EE:EA (Yottabyte)
Device type: general purpose
Running: Microsoft Windows 2016|2019
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2019
OS details: Microsoft Windows Server 2016 or Server 2019
Network Distance: 1 hop
Service Info: Host: FNN-DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: FNN-DC01, NetBIOS user: <unknown>, NetBIOS MAC: f0:db:30:76:ee:ea (Yottabyte)
| smb-os-discovery: 
|   OS: Windows Server 2016 Datacenter 14393 (Windows Server 2016 Datacenter 6.3)
|   Computer name: FNN-DC01
|   NetBIOS computer name: FNN-DC01\x00
|   Domain name: fnn.local
|   Forest name: fnn.local
|   FQDN: FNN-DC01.fnn.local
|_  System time: 2025-12-14T16:14:14-05:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 59m59s, deviation: 2h14m09s, median: 0s
| smb2-time: 
|   date: 2025-12-14T21:14:15
|_  start_date: 2025-11-25T02:57:33
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Dec 14 16:14:23 2025 -- 1 IP address (1 host up) scanned in 17.21 seconds

```

### 2. Enum4linux-ng - Target: 10.248.1.2

**Command:** `enum4linux-ng -A 10.248.1.2`

**Output:**

```
ENUM4LINUX - next generation (v1.3.7)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.248.1.2
[*] Username ......... ''
[*] Random Username .. 'rgbrvhal'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ===================================
|    Listener Scan on 10.248.1.2    |
 ===================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ==================================================
|    Domain Information via LDAP for 10.248.1.2    |
 ==================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: fnn.local

 =========================================================
|    NetBIOS Names and Workgroup/Domain for 10.248.1.2    |
 =========================================================
[+] Got domain/workgroup name: FNN
[+] Full NetBIOS names information:
- FNN             <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name                                                                                          
- FNN-DC01        <00> -         B <ACTIVE>  Workstation Service                                                                                            
- FNN             <1c> - <GROUP> B <ACTIVE>  Domain Controllers                                                                                             
- FNN-DC01        <20> -         B <ACTIVE>  File Server Service                                                                                            
- FNN             <1b> -         B <ACTIVE>  Domain Master Browser                                                                                          
- MAC Address = F0-DB-30-76-EE-EA                                                                                                                           

 =======================================
|    SMB Dialect Check on 10.248.1.2    |
 =======================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                                                                         
  SMB 1.0: true                                                                                                                                             
  SMB 2.0.2: true                                                                                                                                           
  SMB 2.1: true                                                                                                                                             
  SMB 3.0: true                                                                                                                                             
  SMB 3.1.1: true                                                                                                                                           
Preferred dialect: SMB 3.0                                                                                                                                  
SMB1 only: false                                                                                                                                            
SMB signing required: true                                                                                                                                  

 =========================================================
|    Domain Information via SMB session for 10.248.1.2    |
 =========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: FNN-DC01                                                                                                                             
NetBIOS domain name: FNN                                                                                                                                    
DNS domain: fnn.local                                                                                                                                       
FQDN: FNN-DC01.fnn.local                                                                                                                                    
Derived membership: domain member                                                                                                                           
Derived domain: FNN                                                                                                                                         

 =======================================
|    RPC Session Check on 10.248.1.2    |
 =======================================
[*] Check for anonymous access (null session)
[-] Could not establish null session: STATUS_ACCESS_DENIED
[*] Check for guest access
[-] Could not establish session using 'rgbrvhal', password ''
[-] Sessions failed, neither null nor user sessions were possible

 =============================================
|    OS Information via RPC for 10.248.1.2    |
 =============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Skipping 'srvinfo' run, not possible with provided credentials
[+] After merging OS information we have the following result:
OS: Windows Server 2016 Datacenter 14393                                                                                                                    
OS version: '10.0'                                                                                                                                          
OS release: '1607'                                                                                                                                          
OS build: '14393'                                                                                                                                           
Native OS: Windows Server 2016 Datacenter 14393                                                                                                             
Native LAN manager: Windows Server 2016 Datacenter 6.3                                                                                                      
Platform id: null                                                                                                                                           
Server type: null                                                                                                                                           
Server type string: null                                                                                                                                    

[!] Aborting remainder of tests since sessions failed, rerun with valid credentials

Completed after 0.17 seconds

```

### 3. nmblookup - Target: 10.248.1.2

**Command:** `nmblookup -M 10.248.1.2`

**Output:**

```
name_query failed to find name 10.248.1.2#1d

```

## Notes

This report was generated by VectorProbe Network Enumeration Tool.
For more information, see the project documentation.
