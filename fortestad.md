──(venv)─(kali㉿kali-3)-[~/VectorProbe]
└─$ nmap -p 389 --script ldap-rootdse 10.248.1.2
nmap -p 445 --script smb-enum-domains,smb-security-mode,smb2-security-mode 10.248.1.2
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=FNN.LOCAL,userdb=/dev/null 10.248.1.2
dig SRV _ldap._tcp.dc._msdcs.fnn.local
dig SRV _kerberos._tcp.fnn.local
ldapsearch -x -H ldap://10.248.1.2 -b "" -s base
nmblookup -A 10.248.1.2

Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-14 19:00 EST
Nmap scan report for 10.248.1.2
Host is up (0.00039s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       currentTime: 20251215000037.0Z
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
|       highestCommittedUSN: 91555
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

Nmap done: 1 IP address (1 host up) scanned in 0.26 seconds
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-14 19:00 EST
Nmap scan report for 10.248.1.2
Host is up (0.00027s latency).

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

Nmap done: 1 IP address (1 host up) scanned in 0.26 seconds
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-14 19:00 EST
Nmap scan report for 10.248.1.2
Host is up (0.00023s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec
MAC Address: F0:DB:30:76:EE:EA (Yottabyte)

Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds

; <<>> DiG 9.20.9-1-Debian <<>> SRV _ldap._tcp.dc._msdcs.fnn.local
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 24822
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;_ldap._tcp.dc._msdcs.fnn.local.        IN      SRV

;; AUTHORITY SECTION:
.                       101     IN      SOA     a.root-servers.net. nstld.verisign-grs.com. 2025121401 1800 900 604800 86400

;; Query time: 0 msec
;; SERVER: 10.103.8.10#53(10.103.8.10) (UDP)
;; WHEN: Sun Dec 14 19:00:38 EST 2025
;; MSG SIZE  rcvd: 134


; <<>> DiG 9.20.9-1-Debian <<>> SRV _kerberos._tcp.fnn.local
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 10323
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;_kerberos._tcp.fnn.local.      IN      SRV

;; AUTHORITY SECTION:
.                       101     IN      SOA     a.root-servers.net. nstld.verisign-grs.com. 2025121401 1800 900 604800 86400

;; Query time: 0 msec
;; SERVER: 10.103.8.10#53(10.103.8.10) (UDP)
;; WHEN: Sun Dec 14 19:00:38 EST 2025
;; MSG SIZE  rcvd: 128

# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
currentTime: 20251215000038.0Z
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
highestCommittedUSN: 91555
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
Looking up status of 10.248.1.2
        FNN             <00> - <GROUP> B <ACTIVE> 
        FNN-DC01        <00> -         B <ACTIVE> 
        FNN             <1c> - <GROUP> B <ACTIVE> 
        FNN-DC01        <20> -         B <ACTIVE> 
        FNN             <1b> -         B <ACTIVE> 

        MAC Address = F0-DB-30-76-EE-EA
