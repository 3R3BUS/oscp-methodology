# AD Methodology — End-to-End Exam Walkthrough

*A linear, numbered sequence for the OSCP Active Directory set, written for the post-November-2024
"assumed compromise" exam format. This file is the **sequencing and decision-making layer** — it tells
you what to try, in what order, and why, and what "good enough to move on" looks like at each stage.
It deliberately does not re-paste command blocks that already live in the companion deep-dive files;
follow each pointer for the actual syntax. For authorized OSCP exam/lab use only.*

**How to use this document:** read it once end-to-end before exam day so the shape of the chain is in
your head, then keep it open as a checklist during the exam — work top to bottom, but jump straight to
whichever stage your current foothold calls for using the quick-reference at the bottom.

---

## 0. Exam Context Recap

The AD set is worth **40 of the exam's 100 points** and, since the November 1, 2024 restructure, starts
from **assumed compromise**: you are handed a low-privileged domain credential (a plain user/password
pair, not a shell) for a set of **one domain controller + two client machines**, and the set now awards
**partial credit per stage of the chain** rather than an all-or-nothing Domain Admin requirement.
Practical consequence for how you should work this document: **don't rush past intermediate footholds
to chase DA** — stop and capture proof at every stage you clear (initial LDAP access, a cracked hash,
local admin on a client box, a DCSync, etc.), because each of those stages can bank points independently
now. See [`EXAM-TIPS.md`](../EXAM-TIPS.md) §2 for the full scoring breakdown and §5 for exactly how
partial credit is described; §14 below revisits proof discipline once you're mid-chain.

---

## 1. First Commands With the Provided Breach Credential

You start authenticated, so start by pointing every enumeration tool you have at that credential before
touching an exploit. Two things run in parallel from minute one: (1) **LDAP enumeration** to map users,
groups, computers, SPNs, and delegation flags via `ldapsearch`/`windapsearch`/`nxc --users`/`--groups`,
and (2) **BloodHound collection** via `bloodhound-python` (or SharpHound if you land a Windows foothold
first) to get the same data into a graph you can query for paths, not just lists. Do both — LDAP gives
you a fast manual sanity-check and catches things BloodHound's default collection sometimes misses
(e.g., `userPassword`/description-field creds, raw ACL strings), while BloodHound turns the same data
into an actual attack path. "Success" at this stage is a completed BloodHound ingest plus a working
`nxc smb <DC_IP> -u user -p pass --shares` / `--users` sanity check confirming the credential is live and
you know the domain's base DN, DC hostname, and rough object counts. See
[`notes/service-enumeration-comprehensive.md`](service-enumeration-comprehensive.md) — the "LDAP
Enumeration" subsection under "RPC, NFS, and LDAP Enumeration" — for the manual query syntax, and
[`notes/ad-delegation-trust-bloodhound.md`](ad-delegation-trust-bloodhound.md) §1 ("BloodHound CE —
Attack Path Enumeration") for collector flags and the CE ingest workflow.

> **Fallback:** if LDAP queries fail (firewalled, channel binding), fall back to SAMR/LSARPC-based enumeration: `rpcclient -U '' -N <DC_IP>` (null session), `lookupsid.py`/`samrdump.py` (Impacket), or `nxc smb <DC_IP> --rid-brute` — these use a different protocol path (port 445 SMB/RPC, not 389 LDAP) and often work when LDAP is restricted.

---

## 2. If You're Starting Fully Unauthenticated Instead

The real Nov-2024 exam format hands you a credential, but treat this stage as your fallback if a
practice lab/box drops you with nothing, or if you lose the provided credential's usability (e.g., it's
locked out) and need to rebuild access. Order of operations: **unauthenticated username enumeration**
first (Kerbrute against a generated username list, RID cycling, or an LDAP anonymous-bind sweep) to
build a valid user list; then **AS-REP roasting that list** with no password required, since it costs
nothing to try and instantly yields crackable hashes for any account with Kerberos pre-auth disabled;
then, only if AS-REP roasting comes up empty, a **careful password spray** (one or two passwords across
the whole user list, respecting lockout thresholds) using seasonal/company-pattern guesses. Run
**Responder** and **mitm6** passively in the background throughout this phase regardless of what else
you're doing — LLMNR/NBT-NS poisoning and IPv6 DNS takeover cost nothing to leave running and often
hand you a crackable Net-NTLMv2 hash (or a relay target) while you're doing other enumeration. Success
here looks like: one valid credential, one cracked AS-REP hash, or one captured/relayed NTLM hash —
any one of these gets you back to Stage 1. See
[`notes/password-attacks-advanced.md`](password-attacks-advanced.md) for the Kerbrute enumeration/spray
syntax, the AS-REP roasting sweep, and the Responder/mitm6 setup.

---

## 3. BloodHound Path Analysis — Choosing a Path

Once you have a completed BloodHound ingest (Stage 1) or a second credential (Stage 2), stop running
tools for a moment and actually read the graph before acting. Workflow: mark every principal you
control as **Owned**, then run the built-in "Shortest Paths from Owned Objects" and "Shortest Path to
Domain Admins" queries to see if a direct route already exists. If nothing direct shows up, run "Find
Kerberoastable Users" and "Find AS-REP Roastable Users" — these are the highest-value, lowest-noise
next moves because they require no ACL abuse, just a ticket request. Prioritize edges in this rough
order of reliability/speed: **direct ACL edge to DA-adjacent group** > **Kerberoastable service
account with a weak/guessable password pattern** > **AS-REP roastable account** > **delegation edge
(unconstrained/constrained/RBCD)** > **coercion+relay chain** > **ADCS ESC path**. Pick the *shortest*
usable path, not the most interesting one — the exam rewards finishing the chain, not technique
variety. See [`notes/ad-delegation-trust-bloodhound.md`](ad-delegation-trust-bloodhound.md) §1, the
"Analysis — attack paths from collected data" subsection, for the exact built-in queries and the
Cypher for a custom shortest-path-from-owned query, and the "Key abusable ACL edges to look for"
list for what each edge on a path actually means.

---

## 4. Acting on What BloodHound Found

Translate the edge you picked in Stage 3 into a concrete command. If the path shows a **`GenericAll`/
`GenericWrite`/`WriteOwner`/`ForceChangePassword`/`AddMember`/`ReadGMSAPassword`/`ReadLAPSPassword`**
edge, that's ACL abuse — go straight to the matching worked recipe rather than improvising, since each
edge type has a specific right command (password reset vs. targeted-SPN Kerberoasting vs.
take-ownership-then-grant-yourself-rights vs. group-add). If BloodHound flagged Kerberoastable or
AS-REP-roastable users instead, request and crack those tickets now — Kerberoasting works against any
account with an SPN, no special ACL needed, so it's usually worth running opportunistically even
without a BloodHound edge pointing at it. Success at this stage is a new credential (a cracked
password, a reset password you control, or a newly-DA-adjacent group membership) — feed whatever you
land back into Stage 1's enumeration loop before deciding your next move, since a new principal often
opens BloodHound edges that weren't visible before. See
[`notes/ad-delegation-trust-bloodhound.md`](ad-delegation-trust-bloodhound.md), the "ACL Abuse —
Exploiting BloodHound Edges" section, for the per-edge worked commands, and
[`notes/password-attacks-advanced.md`](password-attacks-advanced.md) for the NetExec-based roasting
one-liners (`--kerberoasting`/`--asreproast`) if you'd rather batch-request tickets across every
eligible account instead of targeting one at a time.

---

## 5. Getting Local Admin on a Client Machine

If your current best foothold is a low-privileged shell on one of the two client machines (RDP/WinRM
with a domain user, or a webshell that landed you a low-priv process) rather than a domain-level ACL
win, pivot to **local** privilege escalation on that box before going back to AD enumeration — local
admin usually unlocks LSASS access (Stage 6) and a fresh set of cached credentials/sessions that feed
straight back into lateral movement. Run the standard automated enumeration script for the OS first
(WinPEAS or linPEAS) to surface low-hanging fruit, then work through the OS-specific checklist by
likelihood: on Windows, service/task misconfigurations and the SeImpersonate-family Potato exploits
are the most common OSCP-style wins; on Linux, sudo misconfigurations, SUID/capabilities, and
cron/PATH abuse are the most common. Don't reach for Metasploit's local-exploit-suggester or any
auto-exploit module here — it burns your one allowed non-AD Metasploit machine slot and AD-set boxes
are explicitly excluded from that allowance anyway; PrintSpoofer/GodPotato, PowerUp/PrivescCheck, and
manual GTFOBins-style checks cover the same ground natively. Success is `NT AUTHORITY\SYSTEM` or root
on the box. See [`notes/windows-privesc-scripts.md`](windows-privesc-scripts.md) for the enumeration
script reference and Potato-family exploitation, and
[`notes/linux-privesc-advanced.md`](linux-privesc-advanced.md) for the Linux-side technique matrix.

---

## 6. Credential Harvesting Once You Have Local Admin

The moment you have SYSTEM/root on any AD-joined box, dump everything before doing anything else with
that access — this is usually the highest-value five minutes in the whole chain, since a domain admin
or service-account session cached on a client machine can end the exam outright. On Windows: run
`secretsdump.py` (remote, no agent needed if you already have admin creds) or Mimikatz
`sekurlsa::logonpasswords` (in-session) to pull SAM hashes, cached domain credentials, and any
logged-on-user Kerberos tickets/NTLM secrets straight out of LSASS; also check DPAPI-protected
credential blobs and browser-saved passwords if the interactive route is blocked or EDR is a concern.
On Linux, sweep for flat-file/config creds, browser-saved passwords, and in-memory secrets using the
same priority order. Success looks like either a new, more-privileged domain credential (ideally a
domain admin's or a second machine's local admin), or confirmation there's nothing new here — in which
case move to Stage 7 with whatever admin access you already have. See
[`notes/credentials-harvesting-post-exploitation.md`](credentials-harvesting-post-exploitation.md) for
the full Mimikatz command reference, `secretsdump.py` usage, DPAPI decryption, and the Linux-side loot
checklist.

---

## 7. Lateral Movement to the Next Machine

Once you've harvested a credential or session that's valid on the *other* client machine or the DC,
move to it deliberately rather than re-running the whole enumeration cycle from scratch — you already
know the target from BloodHound's session/group data. Pick the lateral-movement technique based on
what you're carrying: a password or NTLM hash → WinRM (`evil-winrm`) or `wmiexec.py`/`psexec.py`
(pass-the-hash capable) if the account has local admin rights on the target; a Kerberos ticket only →
pass-the-ticket via Rubeus/Impacket rather than re-authenticating with a password. Prefer WMI/WinRM
over PsExec-style service creation when you have the choice — fewer artifacts, and WinRM in particular
gives you an interactive shell rather than a one-shot command execution. Once you land, immediately
loop back to Stage 6 on the new box — every new machine is a new LSASS to dump. Success is an
interactive session (not just command execution) on the next machine in the chain, with proof
captured per Stage 14 before you move on. See
[`notes/windows-lateral-movement-persistence.md`](windows-lateral-movement-persistence.md) Part 1 for
the DCOM/WMI/schtasks/PsExec/WinRM technique comparison and exact syntax for each.

### Overpass-the-Hash / Pass-the-Key
Use an NTLM hash or AES key to request a Kerberos TGT (distinct from Pass-the-Hash which uses NTLM auth directly). Useful when NTLM is disabled/monitored but Kerberos is accepted.
```bash
# Impacket — get a TGT using the NT hash, then use Kerberos auth for all tools
getTGT.py -hashes :NTHASH domain.local/user
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass domain.local/user@target.domain.local

# Rubeus (Windows)
Rubeus.exe asktgt /user:Administrator /rc4:<NTHASH> /ptt

# mimikatz
sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:<NTHASH> /run:powershell.exe
```

### Pass-the-Ticket (PtT)
Use a stolen Kerberos ticket (TGT or TGS) to authenticate as another user without knowing their password or hash.
```bash
# 1. Export tickets from memory (Windows — Rubeus or mimikatz)
Rubeus.exe dump /nowrap
# or:
mimikatz # sekurlsa::tickets /export

# 2. Convert .kirbi (Windows format) to .ccache (Linux/Impacket format)
ticketConverter.py ticket.kirbi ticket.ccache

# 3. Use the ticket with Impacket tools
export KRB5CCNAME=ticket.ccache
psexec.py -k -no-pass domain.local/admin@dc01.domain.local
secretsdump.py -k -no-pass domain.local/admin@dc01.domain.local

# Rubeus direct injection (Windows — no export/convert needed)
Rubeus.exe ptt /ticket:<base64-or-file>
```

---

## 8. Delegation / RBCD / Shadow Credentials Abuse

If BloodHound's path (Stage 3) runs through a delegation edge instead of a plain ACL — `AllowedToDelegate`
(constrained delegation), `AllowedToAct` (RBCD), unconstrained delegation on a computer object, or a
writable `msDS-KeyCredentialLink` (Shadow Credentials) — this is where you cash it in rather than
Stage 4's ACL recipes. Decision order: if the target already has a delegation edge configured
(constrained or unconstrained), abuse it directly with S4U2Self/S4U2Proxy or by coercing/waiting for a
privileged logon to an unconstrained-delegation box; if instead you merely hold *write* access to a
computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity` or `msDS-KeyCredentialLink` attribute
(common outcome of a GenericWrite/GenericAll edge on a computer, or of relaying to LDAP in Stage 9),
set up RBCD or Shadow Credentials yourself using a rogue machine account. Both end the same way: a
service ticket (RBCD) or a PKINIT-derived TGT/NT hash (Shadow Credentials) impersonating a privileged
user on the target. Success is a ticket or NT hash for an account with rights on the box you need.
See [`notes/ad-delegation-trust-bloodhound.md`](ad-delegation-trust-bloodhound.md) §2 ("Kerberos
Delegation Abuse") for the constrained/unconstrained/RBCD worked commands, and the standalone "ACL
Abuse — Exploiting BloodHound Edges" section's "ReadGMSAPassword"/Shadow Credentials-adjacent entries
for the write-access setup path.

---

## 9. Coercion + NTLM Relay When Direct Paths Are Blocked

If every path you've found so far requires an ACL edge or delegation right you don't hold, and SMB
signing is disabled on at least one relay-eligible target, force the issue: coerce a machine account
(DC or otherwise) to authenticate to you, then relay that authentication somewhere useful instead of
just cracking it. Check relay eligibility first (`nxc smb --gen-relay-list` or equivalent signing
sweep) before investing time in a coercion primitive — there's no point coercing if nothing on the
network will accept a relayed auth. Pick the coercion primitive by what's exposed: PetitPotam
(MS-EFSRPC) is the most reliable first try since it works pre-auth against a vulnerable spooler/EFS
config; PrinterBug/DFSCoerce/ShadowCoerce are the fallbacks if PetitPotam is patched or blocked. Pick
the relay target by what you need: **relay to LDAP** for RBCD or Shadow Credentials if you don't
already hold a delegation-write edge from Stage 8; **relay to ADCS HTTP enrollment (ESC8)** if
certificate services are present and web enrollment is enabled (jumps straight to Stage 10's payoff).
Success is either a machine account with RBCD rights, a Shadow Credential on a target, or a certificate
— any of which converts straight into a privileged ticket. See
[`notes/ad-coercion-and-relay.md`](ad-coercion-and-relay.md) for the PetitPotam/PrinterBug/
ShadowCoerce/DFSCoerce syntax, the signing-eligibility discovery commands, and the full
`ntlmrelayx` chains to RBCD, Shadow Credentials, and ADCS ESC8.

---

## 10. ADCS Abuse If Certificate Services Are Present

Check for ADCS early, independent of whichever other path you're pursuing — `certipy find` costs
seconds to run and a misconfigured template is often the single fastest route to Domain Admin on the
whole exam, frequently faster than chaining ACL edges. Run `certipy find -vulnerable` against the
domain as soon as you have any valid credential (this can happen in parallel with Stage 1) and read
the output for a named ESC class rather than guessing. Work the classic template-misconfiguration
paths first — ESC1 (enrollee-supplied SAN) and ESC3 (enrollment agent) are the most common and
directly yield a certificate you can turn into a TGT via `certipy auth`; ESC8 is your target if Stage
9's relay chain pointed here instead. If `certipy find` comes back clean on templates but the CA
itself looks old or oddly configured, work through the ESC9–ESC16 addendum (security-extension
bypass, weak certificate mapping, issuance-policy abuse) rather than assuming ADCS is a dead end.
Success is a certificate you can convert to a TGT/NT hash for a privileged account (frequently the
CA host's or a domain admin's). See
[`notes/adcs-certipy-cheatsheet.md`](adcs-certipy-cheatsheet.md) — the ESC1–ESC8 summary table and
worked ESC1/ESC3/ESC8 examples in §1–§3 for the classic paths, and §6 ("ESC9–ESC16 Reference
Addendum") for the newer template/CA-level abuse classes.

---

## 11. Domain-Privesc CVE Vectors as a Fallback/Fast-Path

If the client machines and DC turn out to be running an old, unpatched build — check `nxc smb <DC_IP>`
banner output and OS build numbers early, since this changes your whole strategy — a known CVE chain
can be faster than working the ACL/delegation graph at all, and worth trying opportunistically even
mid-chain if you spot the indicator. Check in roughly this order of blast-radius-to-effort ratio:
**ZeroLogon** (CVE-2020-1472) if the DC is unpatched pre-August 2020 — unauthenticated, DC-to-DA in
three commands, but remember the mandatory password restore step or you'll break the DC; **noPac**
(CVE-2021-42278/42287) if `ms-DS-MachineAccountQuota` lets you add a computer and the domain is
pre-Nov-2021 patch level — also unauthenticated-adjacent and very fast; **Certifried**
(CVE-2022-26923) if ADCS is present alongside a vulnerable AD CS/schema version, as an alternative
entry into Stage 10's territory; and opportunistically, **GPP cpassword** hits in SYSVOL and
**DNSAdmins** group membership, both of which cost nothing to check (a SYSVOL grep and a
`net group` lookup) and can be run in the background of any other stage. Treat this stage as a
parallel check you run once early and revisit if a later stage stalls, not a strict sequential gate.
Success is domain-admin-equivalent access via a documented CVE rather than a misconfiguration chain.
See [`notes/ad-domain-privesc-cves.md`](ad-domain-privesc-cves.md) for the full ZeroLogon/noPac/
Certifried/GPP/GPO/DNSAdmins command sequences, including ZeroLogon's mandatory cleanup step.

---

## 12. DCSync to Full Domain Compromise, Golden Ticket for Durable Re-Entry

Whatever path got you here — ACL abuse, Kerberoasting, delegation, relay, ADCS, or a CVE — the payoff
stage is the same: use your Domain-Admin-equivalent (or `DCSync`-rights-holding) credential to dump the
`krbtgt` hash and every domain account's secrets via `secretsdump.py -just-dc` or Mimikatz
`lsadump::dcsync`. This is the point that closes out the AD set's top-tier points, so document it
thoroughly (Stage 14) before doing anything else. Immediately afterward, forge a **Golden Ticket** with
the `krbtgt` hash you just pulled — this isn't optional flourish, it's insurance: if your foothold gets
reset, a service restarts and kills your session, or you need to re-enter the domain later in the exam
window without re-running the whole chain, a Golden Ticket gets you back to DA in one command. Keep the
domain SID and `krbtgt` hash noted somewhere durable the moment you have them. Success is a working
DCSync dump plus a tested Golden Ticket you've confirmed grants access (e.g., a clean `psexec.py` or
`secretsdump.py` run authenticating with the forged ticket). See
[`notes/credentials-harvesting-post-exploitation.md`](credentials-harvesting-post-exploitation.md), the
"Impacket secretsdump.py" and Mimikatz sections, for the DCSync commands, and
[`notes/ad-delegation-trust-bloodhound.md`](ad-delegation-trust-bloodhound.md), the standalone "Golden &
Silver Tickets" section (its own top-level section, separate from delegation/ACL abuse), for the
Golden Ticket forging syntax (both Mimikatz and Impacket `ticketer.py`) and the Silver Ticket
alternative when you only need access to one specific service rather than the whole domain.

---

## 13. Crossing a Trust Boundary If the Chain Spans Domains/Forests

Not every exam AD set involves a second domain, but if BloodHound shows a trust relationship (parent/
child, or a cross-forest trust) and your target user/machine sits on the other side, don't skip
straight to SID-history tricks — **enumerate the trust itself first** (direction, transitivity,
SID-filtering status) so you know which technique actually applies before you spend time on one that
won't work across a filtered trust. With a `krbtgt` hash for a child domain in an intra-forest,
SID-filtering-not-enforced trust, ExtraSIDs/Golden-Ticket-with-SID-History gets you from child DA to
parent Enterprise Admin in one forged ticket — the highest-value cross-trust move when it applies. If
SID filtering *is* enforced, or the trust is cross-forest, fall back to trust-key extraction and
inter-realm TGT forgery instead, which works regardless of filtering. Success is authenticated access
(ideally DA-equivalent) on the other side of the trust boundary. See
[`notes/ad-delegation-trust-bloodhound.md`](ad-delegation-trust-bloodhound.md) §3 ("Cross-Trust
Attacks"), which now leads with the trust-enumeration commands before the SID-history and trust-key
techniques — run that enumeration step first regardless of which forgery technique you end up using.

---

## 14. Proof Capture Discipline Per Stage/Machine

This is not a final step you do once at the end — treat it as a recurring checkpoint after **every**
stage above where you gain a new level of access on a new principal or machine, because the AD set now
awards partial credit per stage of the chain rather than only for full DA. Concretely: screenshot the
proof at initial LDAP/BloodHound access, at each cracked/roasted credential, at local admin on each
client machine, at each lateral hop, at the DCSync, and again if you cross a trust boundary — each of
those is a distinct, separately gradable stage under the Nov-2024 scoring model. Every proof screenshot
needs the same four things in one frame: the command run, its output, the current user context
(`whoami`/`id`), and confirmation of which host you're on (`ip addr`/`ipconfig` or hostname). For the
DC and client-machine `proof.txt`/`local.txt` files specifically, the read **must** happen via an
interactive shell on the target itself — reading it indirectly (through a relayed command, a webshell,
or copying it out over SMB without an interactive read) zeroes out that entire machine's points even if
you legitimately compromised it. See [`EXAM-TIPS.md`](../EXAM-TIPS.md) §3 for the full note-taking/
screenshot requirements and §5 for exactly how the per-stage partial-credit model is described —
re-read §5 before the exam if you're used to the older all-or-nothing AD scoring, since it changes how
aggressively you should stop and document mid-chain rather than pushing straight for DA.

---

## What Do I Try Next? — Quick Reference

Keyed off what you currently hold. Jump to the stage number for the full guidance and file pointers.

- **Only the provided breach credential, nothing else yet**
  → Stage 1 (LDAP enum + BloodHound collection), then Stage 3 (read the graph before acting).

- **No credential at all (fully unauthenticated)**
  → Stage 2 (user enum → AS-REP roast → spray, Responder/mitm6 running throughout).

- **A BloodHound graph but no clear next move**
  → Stage 3 (path analysis) — mark Owned, run the built-in queries, prioritize by edge reliability.

- **A Kerberoastable-user hash (cracked or not yet cracked)**
  → Crack it (Stage 4 / `notes/password-attacks-advanced.md`), then feed the resulting credential
    back into Stage 1's enumeration loop before picking the next edge.

- **An ACL edge (GenericAll/GenericWrite/WriteOwner/etc.) on some object**
  → Stage 4 (ACL abuse worked recipes, keyed by exact edge type).

- **Only a low-privileged shell on a client machine, no useful AD rights**
  → Stage 5 (local privesc), then Stage 6 (harvest creds from that box immediately).

- **Local admin / SYSTEM / root on one machine**
  → Stage 6 (dump LSASS/SAM/creds now), then Stage 7 (lateral movement) with whatever you found.

- **A delegation edge (AllowedToDelegate/AllowedToAct) or write access to a computer object**
  → Stage 8 (delegation/RBCD/Shadow Credentials abuse).

- **No usable ACL/delegation edge, but a target with SMB signing disabled**
  → Stage 9 (coercion + NTLM relay) — relay to LDAP for RBCD/Shadow Creds, or to ADCS for ESC8.

- **ADCS present (certipy find returns anything)**
  → Stage 10 (ADCS abuse) — check this in parallel with everything else, it's often the fastest path.

- **Old/unpatched DC or domain (pre-Aug-2020, pre-Nov-2021 builds)**
  → Stage 11 (ZeroLogon/noPac/Certifried/GPP/DNSAdmins) — check opportunistically, revisit if stuck.

- **Domain Admin (or DCSync rights) on one domain**
  → Stage 12 (DCSync everything, forge a Golden Ticket immediately for durable re-entry).

- **DA in a child domain, but the target is in the parent/another forest**
  → Stage 13 (enumerate the trust first, then ExtraSIDs or trust-key forgery as appropriate).

- **DC access / full domain compromise achieved**
  → Stage 14 — stop and confirm every stage along the way has proof captured correctly before
    moving to the next machine or calling the AD set done; partial credit only counts if it's
    documented per the interactive-shell proof-file rule.
