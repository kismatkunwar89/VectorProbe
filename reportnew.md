(venv)─(kali㉿kali-3)-[~/VectorProbe]
└─$ cat vectorprobe_report_20251215_002605.md 

# Network Enumeration Report

**Generated on:** 2025-12-15 00:26:05 UTC

## Summary

### Scan Summary

A total of **5** hosts were discovered.

**Common Open Ports (Top 10):**

| Port/Protocol | Count |
|---------------|-------|
| 135/tcp | 3 |
| 139/tcp | 3 |
| 445/tcp | 3 |
| 3389/tcp | 3 |
| 5985/tcp | 3 |
| 53/tcp | 2 |
| 88/tcp | 1 |
| 389/tcp | 1 |
| 464/tcp | 1 |
| 593/tcp | 1 |

**Discovered Operating Systems:**

| Operating System | Count |
|------------------|-------|
| Microsoft Windows 10 1709 - 21H2 | 2 |
| Unknown | 1 |
| Microsoft Windows Server 2016 or Server 2019 | 1 |
| Linux 3.2 - 4.14, Linux 3.8 - 3.16 | 1 |

## Network Topology

### 10.248.1.0/24

| IP | Hostname | OS | Services | Status |
|-------|----------|----|---------|---------|
| 10.248.1.1 | None | Unknown | domain (53/tcp) | 🟢 Online |
| 10.248.1.100 | FNN-WS1 | Microsoft Windows 10 1709 - 21H2 | msrpc (135/tcp), netbios-ssn (139/tcp), microsoft-ds (445/tcp)... (+2) | 🟢 Online |
| 10.248.1.101 | FNN-WS2 | Microsoft Windows 10 1709 - 21H2 | msrpc (135/tcp), netbios-ssn (139/tcp), microsoft-ds (445/tcp)... (+2) | 🟢 Online |
| 10.248.1.108 | None | Linux 3.2 - 4.14, Linux 3.8 - 3.16 | ssh (22/tcp), postgresql (5432/tcp) | 🟢 Online |
| 10.248.1.2 | FNN-DC01 | Microsoft Windows Server 2016 or Server 2019 | domain (53/tcp), kerberos-sec (88/tcp), msrpc (135/tcp)... (+10) | 🟢 Online |

## Discovered Hosts

### Host: 10.248.1.1

#### Verified Information

| Property | Value |
|----------|-------|
| IP Address | 10.248.1.1 |
| Hostname | None |
| OS Type | Unknown |

**Active Services:**

| Port | Protocol | Service | Fingerprint | Exploits |
|------|----------|---------|-------------|----------|
| 53 | tcp | domain | dnsmasq 2.90 | None |

#### Unverified Information

No unverified information to display.

#### Command Outputs

No specific commands were run against this host.

---

### Host: 10.248.1.2

#### Verified Information

| Property | Value |
|----------|-------|
| IP Address | 10.248.1.2 |
| Hostname | FNN-DC01 |
| OS Type | Microsoft Windows Server 2016 or Server 2019 |

#### Active Directory Enumeration (Unauthenticated)

**AD Identity & Roles**

| Attribute | Value |
|-----------|-------|
| Domain (DNS) | fnn.local |
| Domain (NetBIOS) | FNN |
| DC Hostname | FNN-DC01.fnn.local |
| DC FQDN | FNN-DC01.fnn.local |
| AD Site | Default-First-Site-Name |
| Global Catalog | TRUE |
| DC Role | Domain Controller, Domain Master Browser |

**Functional Levels**

| Level Type | Value |
|------------|-------|
| Domain Functional Level | 7 (Windows Server 2016) |
| Forest Functional Level | 7 (Windows Server 2016) |
| DC Functional Level | 7 (Windows Server 2016) |

**Naming Contexts**

- DC=fnn,DC=local
- CN=Configuration,DC=fnn,DC=local
- CN=Schema,CN=Configuration,DC=fnn,DC=local
- DC=ForestDnsZones,DC=fnn,DC=local
- DC=DomainDnsZones,DC=fnn,DC=local

**LDAP Capabilities**

- Supported LDAP Versions: 3, 2
- Supported SASL Mechanisms: GSSAPI, GSS-SPNEGO, EXTERNAL, DIGEST-MD5
- Synchronization Status: TRUE

**SMB Security Posture**

- SMB 1.0 Message Signing: required
- SMB 2.0/3.0 Message Signing (SMB 3:1:1): enabled and required
- Authentication Level: user

*SMB signing is required, mitigating relay attacks*

**NetBIOS Information**

- NetBIOS Computer Name: FNN-DC01
- NetBIOS Domain: FNN
- NetBIOS Groups: Domain Controllers <1c>, Domain Master Browser <1b>
- MAC Address: F0-DB-30-76-EE-EA

**DNS SRV Records**

*DNS SRV enumeration returned NXDOMAIN for .local domain (expected behavior when querying external DNS servers)*

*All Active Directory information was obtained without authentication using LDAP Base DSE (authoritative), Nmap LDAP RootDSE (secondary), SMB security mode enumeration, NetBIOS role identification, and DNS SRV record queries.*

**Active Services:**

| Port | Protocol | Service | Fingerprint | Exploits |
|------|----------|---------|-------------|----------|
| 53 | tcp | domain | Simple DNS Plus | 1 found |
| 88 | tcp | kerberos-sec | Microsoft Windows Kerberos (server time: 2025 | None |
| 135 | tcp | msrpc | Microsoft Windows RPC | None |
| 139 | tcp | netbios-ssn | Microsoft Windows netbios-ssn | None |
| 389 | tcp | ldap | Microsoft Windows Active Directory LDAP (Domain: fnn.local, Site: Default-First-Site-Name) | 1 found |
| 445 | tcp | microsoft-ds | Windows Server 2016 | None |
| 464 | tcp | kpasswd5? | kpasswd5? | None |
| 593 | tcp | ncacn_http | Microsoft Windows RPC over HTTP 1.0 | None |
| 636 | tcp | tcpwrapped | tcpwrapped | None |
| 3268 | tcp | ldap | Microsoft Windows Active Directory LDAP (Domain: fnn.local, Site: Default-First-Site-Name) | 1 found |
| 3269 | tcp | tcpwrapped | tcpwrapped | None |
| 3389 | tcp | ms-wbt-server | Microsoft Terminal Services | None |
| 5985 | tcp | http | Microsoft HTTPAPI httpd 2.0 | None |

#### Unverified Information

No unverified information to display.

**Potential Vulnerabilities:**

**For Service 'domain' on port 53:**
- Simple DNS Plus 5.0/4.1 - Remote Denial of Service (EDB-6059)

**For Service 'ldap' on port 389:**
- Microsoft Windows Server 2000 - Active Directory Remote Stack Overflow (EDB-22782)

#### Command Outputs

**Command:** `enum4linux-ng -A 10.248.1.2`
```
ENUM4LINUX - next generation (v1.3.7)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.248.1.2
[*] Username ......... ''
[*] Random Username .. 'tuyrfljq'
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
[-] Could not establish session using 'tuyrfljq', password ''
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

Completed after 0.15 seconds
```

**Command:** `nmblookup -M 10.248.1.2`
```
name_query failed to find name 10.248.1.2#1d
```

**Command:** `ldapsearch -x -H ldap://10.248.1.2 -b  -s base`
```
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
currentTime: 20251215002603.0Z
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=fnn,DC=local
dsServiceName: CN=NTDS Settings,CN=FNN-DC01,CN=Servers,CN=Default-First-Site-N
 ame,CN=Sites,CN=Configuration,DC=fnn,DC=local
namingContexts: DC=fnn,DC=local
namingContexts: CN=Configuration,DC=fnn,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=fnn,DC=local
namingContexts: DC=ForestDnsZones,DC=fnn,DC=local
namingContexts: DC=DomainDnsZones,DC=fnn,DC=local
defaultNamingContext: DC=fnn,DC=local
schemaNamingContext: CN=Schema,CN=Configuration,DC=fnn,DC=local
configurationNamingContext: CN=Configuration,DC=fnn,DC=local
rootDomainNamingContext: DC=fnn,DC=local
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.473
supportedControl: 1.2.840.113556.1.4.528
supportedControl: 1.2.840.113556.1.4.417
supportedControl: 1.2.840.113556.1.4.619
supportedControl: 1.2.840.113556.1.4.841
supportedControl: 1.2.840.113556.1.4.529
supportedControl: 1.2.840.113556.1.4.805
supportedControl: 1.2.840.113556.1.4.521
supportedControl: 1.2.840.113556.1.4.970
supportedControl: 1.2.840.113556.1.4.1338
supportedControl: 1.2.840.113556.1.4.474
supportedControl: 1.2.840.113556.1.4.1339
supportedControl: 1.2.840.113556.1.4.1340
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 2.16.840.1.113730.3.4.9
supportedControl: 2.16.840.1.113730.3.4.10
supportedControl: 1.2.840.113556.1.4.1504
supportedControl: 1.2.840.113556.1.4.1852
supportedControl: 1.2.840.113556.1.4.802
supportedControl: 1.2.840.113556.1.4.1907
supportedControl: 1.2.840.113556.1.4.1948
supportedControl: 1.2.840.113556.1.4.1974
supportedControl: 1.2.840.113556.1.4.1341
supportedControl: 1.2.840.113556.1.4.2026
supportedControl: 1.2.840.113556.1.4.2064
supportedControl: 1.2.840.113556.1.4.2065
supportedControl: 1.2.840.113556.1.4.2066
supportedControl: 1.2.840.113556.1.4.2090
supportedControl: 1.2.840.113556.1.4.2205
supportedControl: 1.2.840.113556.1.4.2204
supportedControl: 1.2.840.113556.1.4.2206
supportedControl: 1.2.840.113556.1.4.2211
supportedControl: 1.2.840.113556.1.4.2239
supportedControl: 1.2.840.113556.1.4.2255
supportedControl: 1.2.840.113556.1.4.2256
supportedControl: 1.2.840.113556.1.4.2309
supportedLDAPVersion: 3
supportedLDAPVersion: 2
supportedLDAPPolicies: MaxPoolThreads
supportedLDAPPolicies: MaxPercentDirSyncRequests
supportedLDAPPolicies: MaxDatagramRecv
supportedLDAPPolicies: MaxReceiveBuffer
supportedLDAPPolicies: InitRecvTimeout
supportedLDAPPolicies: MaxConnections
supportedLDAPPolicies: MaxConnIdleTime
supportedLDAPPolicies: MaxPageSize
supportedLDAPPolicies: MaxBatchReturnMessages
supportedLDAPPolicies: MaxQueryDuration
supportedLDAPPolicies: MaxDirSyncDuration
supportedLDAPPolicies: MaxTempTableSize
supportedLDAPPolicies: MaxResultSetSize
supportedLDAPPolicies: MinResultSets
supportedLDAPPolicies: MaxResultSetsPerConn
supportedLDAPPolicies: MaxNotificationPerConn
supportedLDAPPolicies: MaxValRange
supportedLDAPPolicies: MaxValRangeTransitive
supportedLDAPPolicies: ThreadMemoryLimit
supportedLDAPPolicies: SystemMemoryLimitPercent
highestCommittedUSN: 91557
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
dnsHostName: FNN-DC01.fnn.local
ldapServiceName: fnn.local:fnn-dc01$@FNN.LOCAL
serverName: CN=FNN-DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Conf
 iguration,DC=fnn,DC=local
supportedCapabilities: 1.2.840.113556.1.4.800
supportedCapabilities: 1.2.840.113556.1.4.1670
supportedCapabilities: 1.2.840.113556.1.4.1791
supportedCapabilities: 1.2.840.113556.1.4.1935
supportedCapabilities: 1.2.840.113556.1.4.2080
supportedCapabilities: 1.2.840.113556.1.4.2237
isSynchronized: TRUE
isGlobalCatalogReady: TRUE
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

**Command:** `nmap -p 389 --script ldap-rootdse 10.248.1.2`
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-14 19:26 EST
Nmap scan report for 10.248.1.2
Host is up (0.00033s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       currentTime: 20251215002604.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=fnn,DC=local
|       dsServiceName: CN=NTDS Settings,CN=FNN-DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=fnn,DC=local
|       namingContexts: DC=fnn,DC=local
|       namingContexts: CN=Configuration,DC=fnn,DC=local
|       namingContexts: CN=Schema,CN=Configuration,DC=fnn,DC=local
|       namingContexts: DC=ForestDnsZones,DC=fnn,DC=local
|       namingContexts: DC=DomainDnsZones,DC=fnn,DC=local
|       defaultNamingContext: DC=fnn,DC=local
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=fnn,DC=local
|       configurationNamingContext: CN=Configuration,DC=fnn,DC=local
|       rootDomainNamingContext: DC=fnn,DC=local
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.840.113556.1.4.801
|       supportedControl: 1.2.840.113556.1.4.473
|       supportedControl: 1.2.840.113556.1.4.528
|       supportedControl: 1.2.840.113556.1.4.417
|       supportedControl: 1.2.840.113556.1.4.619
|       supportedControl: 1.2.840.113556.1.4.841
|       supportedControl: 1.2.840.113556.1.4.529
|       supportedControl: 1.2.840.113556.1.4.805
|       supportedControl: 1.2.840.113556.1.4.521
|       supportedControl: 1.2.840.113556.1.4.970
|       supportedControl: 1.2.840.113556.1.4.1338
|       supportedControl: 1.2.840.113556.1.4.474
|       supportedControl: 1.2.840.113556.1.4.1339
|       supportedControl: 1.2.840.113556.1.4.1340
|       supportedControl: 1.2.840.113556.1.4.1413
|       supportedControl: 2.16.840.1.113730.3.4.9
|       supportedControl: 2.16.840.1.113730.3.4.10
|       supportedControl: 1.2.840.113556.1.4.1504
|       supportedControl: 1.2.840.113556.1.4.1852
|       supportedControl: 1.2.840.113556.1.4.802
|       supportedControl: 1.2.840.113556.1.4.1907
|       supportedControl: 1.2.840.113556.1.4.1948
|       supportedControl: 1.2.840.113556.1.4.1974
|       supportedControl: 1.2.840.113556.1.4.1341
|       supportedControl: 1.2.840.113556.1.4.2026
|       supportedControl: 1.2.840.113556.1.4.2064
|       supportedControl: 1.2.840.113556.1.4.2065
|       supportedControl: 1.2.840.113556.1.4.2066
|       supportedControl: 1.2.840.113556.1.4.2090
|       supportedControl: 1.2.840.113556.1.4.2205
|       supportedControl: 1.2.840.113556.1.4.2204
|       supportedControl: 1.2.840.113556.1.4.2206
|       supportedControl: 1.2.840.113556.1.4.2211
|       supportedControl: 1.2.840.113556.1.4.2239
|       supportedControl: 1.2.840.113556.1.4.2255
|       supportedControl: 1.2.840.113556.1.4.2256
|       supportedControl: 1.2.840.113556.1.4.2309
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxPercentDirSyncRequests
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxBatchReturnMessages
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxDirSyncDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: MaxValRangeTransitive
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       highestCommittedUSN: 91557
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       dnsHostName: FNN-DC01.fnn.local
|       ldapServiceName: fnn.local:fnn-dc01$@FNN.LOCAL
|       serverName: CN=FNN-DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=fnn,DC=local
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       isSynchronized: TRUE
|       isGlobalCatalogReady: TRUE
|       domainFunctionality: 7
|       forestFunctionality: 7
|_      domainControllerFunctionality: 7
MAC Address: F0:DB:30:76:EE:EA (Yottabyte)
Service Info: Host: FNN-DC01; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.29 seconds
```

**Command:** `nmap -p 445 --script smb-security-mode,smb2-security-mode 10.248.1.2`
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-14 19:26 EST
Nmap scan report for 10.248.1.2
Host is up (0.00045s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: F0:DB:30:76:EE:EA (Yottabyte)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

Nmap done: 1 IP address (1 host up) scanned in 0.27 seconds
```

**Command:** `nmblookup -A 10.248.1.2`
```
Looking up status of 10.248.1.2
        FNN             <00> - <GROUP> B <ACTIVE> 
        FNN-DC01        <00> -         B <ACTIVE> 
        FNN             <1c> - <GROUP> B <ACTIVE> 
        FNN-DC01        <20> -         B <ACTIVE> 
        FNN             <1b> -         B <ACTIVE> 

        MAC Address = F0-DB-30-76-EE-EA

```

**Command:** `nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=FNN.LOCAL,userdb=/dev/null 10.248.1.2`
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-14 19:26 EST
Nmap scan report for 10.248.1.2
Host is up (0.00032s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec
MAC Address: F0:DB:30:76:EE:EA (Yottabyte)

Nmap done: 1 IP address (1 host up) scanned in 0.25 seconds
```

---

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
[*] Random Username .. 'iroxdnqx'
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
[-] Could not establish session using 'iroxdnqx', password ''
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

Completed after 0.37 seconds
```

**Command:** `nmblookup -M 10.248.1.100`
```
name_query failed to find name 10.248.1.100#1d
```

---

### Host: 10.248.1.101

#### Verified Information

| Property | Value |
|----------|-------|
| IP Address | 10.248.1.101 |
| Hostname | FNN-WS2 |
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

**Command:** `enum4linux-ng -A 10.248.1.101`
```
ENUM4LINUX - next generation (v1.3.7)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.248.1.101
[*] Username ......... ''
[*] Random Username .. 'qwsijdsg'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =====================================
|    Listener Scan on 10.248.1.101    |
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
|    NetBIOS Names and Workgroup/Domain for 10.248.1.101    |
 ===========================================================
[+] Got domain/workgroup name: FNN
[+] Full NetBIOS names information:
- FNN             <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name                                                                                          
- FNN-WS2         <00> -         B <ACTIVE>  Workstation Service                                                                                            
- FNN-WS2         <20> -         B <ACTIVE>  File Server Service                                                                                            
- FNN             <1e> - <GROUP> B <ACTIVE>  Browser Service Elections                                                                                      
- MAC Address = F0-DB-30-76-EE-EE                                                                                                                           

 =========================================
|    SMB Dialect Check on 10.248.1.101    |
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
|    Domain Information via SMB session for 10.248.1.101    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: FNN-WS2                                                                                                                              
NetBIOS domain name: FNN                                                                                                                                    
DNS domain: fnn.local                                                                                                                                       
FQDN: FNN-WS2.fnn.local                                                                                                                                     
Derived membership: domain member                                                                                                                           
Derived domain: FNN                                                                                                                                         

 =========================================
|    RPC Session Check on 10.248.1.101    |
 =========================================
[*] Check for anonymous access (null session)
[-] Could not establish null session: STATUS_ACCESS_DENIED
[*] Check for guest access
[-] Could not establish session using 'qwsijdsg', password ''
[-] Sessions failed, neither null nor user sessions were possible

 ===============================================
|    OS Information via RPC for 10.248.1.101    |
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

Completed after 0.49 seconds
```

**Command:** `nmblookup -M 10.248.1.101`
```
name_query failed to find name 10.248.1.101#1d
```

---

### Host: 10.248.1.108

#### Verified Information

| Property | Value |
|----------|-------|
| IP Address | 10.248.1.108 |
| Hostname | None |
| OS Type | Linux 3.2 - 4.14, Linux 3.8 - 3.16 |

**Active Services:**

| Port | Protocol | Service | Fingerprint | Exploits |
|------|----------|---------|-------------|----------|
| 22 | tcp | ssh | OpenSSH 5.9 | None |
| 5432 | tcp | postgresql | PostgreSQL DB 9.1.20 | None |

#### Unverified Information

No unverified information to display.

#### Command Outputs

No specific commands were run against this host.

---

## Notes

This report was generated by VectorProbe Network Enumeration Tool.
For more information, see the project documentation.
