cat host_enumeration_report_20251216_0217_UTC.md

# Network Enumeration Report

**Generated on:** 2025-12-16 02:17:31 UTC

## Summary

### Scan Summary

A total of **1** hosts were discovered.

**Common Open Ports (Top 10):**

| Port/Protocol | Count |
|---------------|-------|
| 135/tcp | 1 |
| 139/tcp | 1 |
| 445/tcp | 1 |
| 3389/tcp | 1 |
| 5985/tcp | 1 |

**Discovered Operating Systems:**

| Operating System | Count |
|------------------|-------|
| Microsoft Windows 10 1709 - 21H2 | 1 |

## Network Topology

### 10.248.1.0/24

| IP | Hostname | OS | Services | Status |
|-------|----------|----|---------|---------|
| 10.248.1.100 | FNN-WS1 | Microsoft Windows 10 1709 - 21H2 | msrpc (135/tcp), netbios-ssn (139/tcp), microsoft-ds (445/tcp)... (+2) | 🟢 Online |

## Discovered Hosts

### Host: 10.248.1.100

#### Verified Information

| Property | Value |
|----------|-------|
| IP Address | 10.248.1.100 |
| Hostname | FNN-WS1 |
| OS Type | Microsoft Windows 10 1709 - 21H2 |

#### Active Directory Information (Unauthenticated)

| Attribute | Value |
|-----------|-------|
| Domain | FNN |
| Probable Role | Member Server / Workstation |

**Active Services:**

| Port | Protocol | Service | Fingerprint | Exploits |
|------|----------|---------|-------------|----------|
| 135 | tcp | msrpc | Microsoft Windows RPC | None |
| 139 | tcp | netbios-ssn | Microsoft Windows netbios-ssn | None |
| 445 | tcp | microsoft-ds | Windows 10 | None |
| 3389 | tcp | ms-wbt-server | Microsoft Terminal Services | None |
| 5985 | tcp | http | Microsoft HTTPAPI httpd 2.0 | None |

#### SMB Enumeration

**OS:** Windows 10 Pro 18363

**Null Sessions:** Disabled

#### NetBIOS Enumeration

#### Unverified Information

No unverified information to display.

#### Command Outputs

**Command:** `enum4linux-ng -A 10.248.1.100`
```
ENUM4LINUX - next generation (v1.3.7)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.248.1.100
[*] Username ......... ''
[*] Random Username .. 'rzujnkds'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =====================================
|    Listener Scan on 10.248.1.100    |
 =====================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ===========================================================
|    NetBIOS Names and Workgroup/Domain for 10.248.1.100    |
 ===========================================================
[+] Got domain/workgroup name: FNN
[+] Full NetBIOS names information:
- FNN-WS1         <00> -         B <ACTIVE>  Workstation Service                                                                                            
- FNN             <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name                                                                                          
- FNN-WS1         <20> -         B <ACTIVE>  File Server Service                                                                                            
- FNN             <1e> - <GROUP> B <ACTIVE>  Browser Service Elections                                                                                      
- FNN             <1d> -         B <ACTIVE>  Master Browser                                                                                                 
- ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser                                                                                                 
- MAC Address = F0-DB-30-76-EE-ED                                                                                                                           

 =========================================
|    SMB Dialect Check on 10.248.1.100    |
 =========================================
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
SMB signing required: false                                                                                                                                 

 ===========================================================
|    Domain Information via SMB session for 10.248.1.100    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: FNN-WS1                                                                                                                              
NetBIOS domain name: FNN                                                                                                                                    
DNS domain: fnn.local                                                                                                                                       
FQDN: FNN-WS1.fnn.local                                                                                                                                     
Derived membership: domain member                                                                                                                           
Derived domain: FNN                                                                                                                                         

 =========================================
|    RPC Session Check on 10.248.1.100    |
 =========================================
[*] Check for anonymous access (null session)
[-] Could not establish null session: STATUS_ACCESS_DENIED
[*] Check for guest access
[-] Could not establish session using 'rzujnkds', password ''
[-] Sessions failed, neither null nor user sessions were possible

 ===============================================
|    OS Information via RPC for 10.248.1.100    |
 ===============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Skipping 'srvinfo' run, not possible with provided credentials
[+] After merging OS information we have the following result:
OS: Windows 10 Pro 18363                                                                                                                                    
OS version: '10.0'                                                                                                                                          
OS release: '1903'                                                                                                                                          
OS build: '18362'                                                                                                                                           
Native OS: Windows 10 Pro 18363                                                                                                                             
Native LAN manager: Windows 10 Pro 6.3                                                                                                                      
Platform id: null                                                                                                                                           
Server type: null                                                                                                                                           
Server type string: null                                                                                                                                    

[!] Aborting remainder of tests since sessions failed, rerun with valid credentials

Completed after 0.29 seconds
```

**Command:** `nmblookup -M 10.248.1.100`
```
name_query failed to find name 10.248.1.100#1d
```

---

## Notes

This report was generated by VectorProbe Network Enumeration Tool.
For more information, see the project documentation.
