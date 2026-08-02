# OSCP (PEN-200) Resources

**Status:** Research phase — this is a curated, categorized collection of resources for building a
comprehensive OSCP methodology guide. It draws on three sources: (1) the user's personal OffSec
PEN-200 training notes, (2) the [`security-practitioners-guide`](https://github.com/3R3BUS/security-practitioners-guide)
CSKB reference library, and (3) live web research conducted August 2026. All content here is scoped
to **authorized** penetration testing education and OSCP exam preparation.

> **Ethics/scope note:** This document intentionally contains **no** OSCP exam-specific target
> information, flags, credentials, or answers. Reproducing real exam content violates OffSec's
> exam Non-Disclosure Agreement. Everything below is public, general-purpose methodology and
> tooling reference material — the kind of thing you're expected to know going *into* the exam,
> not anything from a specific exam attempt.

**Companion deep-dive files** (added in a second research pass, same repo):
[`CHEATSHEET.md`](CHEATSHEET.md) (command/flags quick reference) ·
[`EXAM-TIPS.md`](EXAM-TIPS.md) (proctoring, time budgeting, documentation rules) ·
[`MACHINES.md`](MACHINES.md) (this repo's own curated list of 107 OSCP-like HTB machines, matched to
0xdf writeups and ippsec videos) ·
[`notes/ad-methodology-end-to-end.md`](notes/ad-methodology-end-to-end.md) ·
[`notes/adcs-certipy-cheatsheet.md`](notes/adcs-certipy-cheatsheet.md) ·
[`notes/ad-coercion-and-relay.md`](notes/ad-coercion-and-relay.md) ·
[`notes/ad-delegation-trust-bloodhound.md`](notes/ad-delegation-trust-bloodhound.md) ·
[`notes/ad-domain-privesc-cves.md`](notes/ad-domain-privesc-cves.md) ·
[`notes/windows-lateral-movement-persistence.md`](notes/windows-lateral-movement-persistence.md) ·
[`notes/windows-privesc-scripts.md`](notes/windows-privesc-scripts.md) ·
[`notes/linux-privesc-advanced.md`](notes/linux-privesc-advanced.md) ·
[`notes/easy-lpe-cve-quickhits.md`](notes/easy-lpe-cve-quickhits.md) ·
[`notes/buffer-overflow-legacy.md`](notes/buffer-overflow-legacy.md) ·
[`notes/web-attack-techniques.md`](notes/web-attack-techniques.md) ·
[`notes/web-core-vulnerabilities.md`](notes/web-core-vulnerabilities.md) ·
[`notes/service-enumeration-comprehensive.md`](notes/service-enumeration-comprehensive.md) ·
[`notes/enum-automation-frameworks.md`](notes/enum-automation-frameworks.md) ·
[`notes/credentials-harvesting-post-exploitation.md`](notes/credentials-harvesting-post-exploitation.md) ·
[`notes/password-attacks-advanced.md`](notes/password-attacks-advanced.md) ·
[`notes/pivoting-tunneling.md`](notes/pivoting-tunneling.md) ·
[`notes/file-transfer-matrix.md`](notes/file-transfer-matrix.md)

> **Start here for the AD set:** [`notes/ad-methodology-end-to-end.md`](notes/ad-methodology-end-to-end.md)
> is the sequenced, numbered walkthrough of the whole AD attack chain (assumed-breach credential →
> BloodHound → domain compromise) — everything else AD-related in this repo (delegation/trust/ACL abuse,
> ADCS, coercion/relay, password attacks, credential harvesting, lateral movement, domain-privesc CVEs)
> is the command reference it links into at each stage. Read that file top to bottom once, then use it
> as an exam-day checklist; go to the individual notes files for actual syntax.

---

## 1. Official OffSec / OSCP Materials

| Resource | URL | Notes |
|---|---|---|
| PEN-200 Course Page | https://www.offsec.com/courses/pen-200/ | Official syllabus, lab access options (90-day/1-year), pricing. |
| OSCP Exam Guide | https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide | Official exam rules: 23h45m window, scoring, documentation requirements. |
| OSCP Exam with AD Preparation | https://help.offsec.com/hc/en-us/articles/4547917816468-OffSec-OSCP-Exam-with-AD-Preparation | Official guidance specific to the AD set; Challenge Labs 4–6 mirror the AD exam format. |
| PEN-200 2023 Course & Exam Update | https://www.offsec.com/blog/pen-200-2023/ | **Confirms Buffer Overflow was removed from the exam body of knowledge**; course rebalanced toward web, privesc, and AD. See §9 below. |
| OSCP Exam Structure Change | https://www.offsec.com/blog/oscp-exam-structure/ | Current point breakdown (see §1.1). |
| PWK Example Report (PDF) | https://www.offsec.com/pwk-online/PWK-Example-Report-v1.pdf | Official sample report — expected format/depth for findings. |
| OSCP Exam Report Template | https://www.offsec.com/pwk-online/OSCP-Exam-Report.docx · https://www.offsec.com/pwk-online/OSCP-Exam-Report.odt | **Verified:** OffSec provides both formats side-by-side (same pattern for OSEP/OSED/OSWE); [PEN-200 Reporting Requirements](https://help.offsec.com/hc/en-us/articles/360046787731-PEN-200-Reporting-Requirements) confirms Word + OpenOffice/LibreOffice options. The final submission must be a PDF inside a `.7z` archive regardless of which template you start from. |
| OffSec Help Center | https://help.offsec.com/hc/en-us | KB hub: exam logistics, proctoring, ID verification, connectivity issues. |
| Discord Access & Support Guide | https://help.offsec.com/hc/en-us/articles/4404373510164-Discord-Access-and-Support-Guide | How to link your OffSec account to the official Discord. |
| OffSec Official Discord | https://discord.com/invite/offsec | ~95k-member, staff-monitored community/help server. |
| OSCP Certification Preparation Guide | https://www.offsec.com/blog/offsec-certification-preparation-guide/ | Official study-planning advice blog post. |

### 1.1 Current Exam Structure (verified, post-Nov-1-2024 restructure)

> **Authoritative source:** [`EXAM-TIPS.md`](EXAM-TIPS.md) §2 and §5 — this section is a short summary;
> defer to that file (and the live OffSec Exam Guide) for exact current point-per-stage wording.

- **Total:** 100 points; **70 required to pass**. Exam window: **23 hours 45 minutes** + 24h to submit the report.
- **Active Directory set — 40 points:** "assumed compromise" — one DC + 2 client machines, chained via a
  provided low-privileged breach credential. As of the **November 1, 2024 restructure**, the AD set awards
  **partial credit per stage of the chain** (approx. 10/10/20 split across the chain per secondary sources)
  rather than requiring full Domain Admin / DC compromise for any points — this reverses the older
  all-or-nothing model that earlier guides (including earlier drafts of this file) described.
- **3 standalone machines — 20 points each** (10 for a low-privilege/local.txt shell, 10 for
  root/system/proof.txt).
- **Bonus points: removed.** The old +10 bonus points for ≥80% course-exercise completion and 30
  proof.txt submissions from Challenge Labs were eliminated in the Nov 1, 2024 restructure. The 70/100
  threshold must now be cleared purely from exam-day performance.
- **Buffer overflow is no longer a scored exam objective** (removed in the 2023 PEN-200 update —
  see §9). It's still taught in the course for foundational skill-building.
- **OSCP+ credential:** passing now issues both the lifetime **OSCP** certification and a separate
  **OSCP+** designation that expires 3 years from issuance — see [`EXAM-TIPS.md`](EXAM-TIPS.md) §2.

---

## 2. Practice Platforms

| Platform | URL | Notes |
|---|---|---|
| Hack The Box (HTB) | https://www.hackthebox.com/ | Largest library of retired/active machines; primary source for TJnull-style prep. |
| HTB Academy | https://academy.hackthebox.com/ | Structured guided modules, including a dedicated AD track. |
| TryHackMe (THM) | https://tryhackme.com/ | Beginner-friendly guided rooms; strong "Jr Penetration Tester" / AD fundamentals paths. |
| OffSec Proving Grounds — Play | https://www.offsec.com/products/proving-grounds/ | Free tier, 3 hrs/day, VulnHub-sourced boxes. |
| OffSec Proving Grounds — Practice | https://www.offsec.com/products/proving-grounds/ | ~$19/mo; OffSec-authored boxes closest to real exam conditions. |
| VulnHub | https://www.vulnhub.com/ | Free downloadable vulnerable VMs (source material for PG Play). |
| PentesterLab | https://pentesterlab.com/ | Web-focused exercises, useful for the web attack module. |

## 3. Curated OSCP-Like Machine Lists

| Resource | URL | Notes |
|---|---|---|
| TJnull's OSCP-like list ("NetSecFocus Trophy Room") | https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit | **Verified (medium-high confidence):** the list's actual title/location is the "NetSecFocus Trophy Room" Google Sheet — not a TJnull-branded domain. Multiple independent searches converge on this doc ID; could not visually confirm the live page renders (network policy blocked docs.google.com during verification) — spot-check before relying on it long-term. |
| TJnull's list mirror | https://0xdf.gitlab.io/cheatsheets/offsec | Reliable fallback mirror with linked writeups if the Sheet link ever rots. |
| awesome-oscp | https://github.com/0x4d31/awesome-oscp | Curated GitHub list of OSCP study resources, tools, and machine lists. |
| verylazytech/OSCP-Resources | https://github.com/verylazytech/OSCP-Resources | Actively maintained syllabus/exam-guide mirror + resource compilation; also mirrors the official Exam Guide text (useful since help.offsec.com blocks automated fetchers). |
| TJnull list sorted by difficulty | https://github.com/Shellshock9001/Tjs-Nulls-OSCP-list-in-order-from-easy-medium-hard-insane-more-challenging-and-alphabetical | Reorganizes TJnull's list by difficulty and alphabetically. |
| NetSecFocus | https://netsec-focus.github.io/ | Origin of the "Trophy Room" list culture. **Verified:** NetSecFocus's own Mattermost server has been down since ~late 2021 with no officially-announced replacement platform — treat "still down, no official successor" as current best answer, not a certainty (site itself was unreachable during verification). |

> **This repo's own curated list:** [`MACHINES.md`](MACHINES.md) — 107 HTB machines pulled from TJnull's
> list, grouped by community-voted difficulty (Easy/Medium/Hard/Insane/More Challenging), each matched
> against a 0xdf writeup and an ippsec video where one exists.

## 4. Methodology & Cheat-Sheet References

| Resource | URL | Notes |
|---|---|---|
| HackTricks | https://book.hacktricks.wiki/ | The single most comprehensive pentest methodology wiki; AD Methodology section is essential. |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Payload/technique reference for web + general pentest (AD content increasingly lives in InternalAllTheThings). |
| InternalAllTheThings | https://swisskyrepo.github.io/InternalAllTheThings/ | AD/internal-network-focused sibling of PayloadsAllTheThings. |
| The Hacker Recipes | https://www.thehacker.recipes/ | Structured, command-level catalogue of AD techniques by phase (recon → movement → credentials → privesc → persistence). |
| GTFOBins | https://gtfobins.github.io/ | Unix binary privesc/breakout reference. |
| LOLBAS | https://lolbas-project.github.io/ | Windows living-off-the-land binaries/scripts reference. |
| ired.team | https://www.ired.team/ | Deep AD/Kerberos abuse notes (Kerberoasting, ACL abuse, delegation, DCSync). |
| Orange Cyberdefense AD Mindmap | https://orange-cyberdefense.github.io/ocd-mindmaps/ | Visual, exhaustive AD attack-path mindmap, updated annually. |
| SecLists | https://github.com/danielmiessler/SecLists | Standard wordlist collection for enumeration/fuzzing/brute force. |
| Ivan Sincek's Pentest Cheat Sheet | https://github.com/ivan-sincek/penetration-testing-cheat-sheet | General pentest cheat sheet (also WiFi/Android/iOS variants). |
| 0xdf hacks stuff | https://0xdf.gitlab.io/ | Methodology-focused HTB writeups — strong for enumeration/exploitation thought process. |
| OWASP Web Security Testing Guide (WSTG) | https://owasp.org/www-project-web-security-testing-guide/ | De-facto test catalogue for web apps; 12 categories, numbered reproducible test cases. |
| OWASP ASVS | https://owasp.org/www-project-application-security-verification-standard/ | Tiered (L1/L2/L3) requirements defining "secure" per control area. |
| PortSwigger Web Security Academy | https://portswigger.net/web-security | Free, continuously updated labs for every major web vuln class. |

> **Deep-dive:** [`notes/web-attack-techniques.md`](notes/web-attack-techniques.md) covers file-upload bypass
> (extension/content-type/magic-byte/polyglot), insecure deserialization basics (PHP/Java/Python), WordPress
> enumeration/exploitation via wpscan, and a generic CMS/framework fingerprinting workflow.
>
> **Deep-dive:** [`notes/web-core-vulnerabilities.md`](notes/web-core-vulnerabilities.md) covers manual
> (pre-sqlmap) SQL injection (UNION/error/blind-boolean/blind-time-based), XSS (reflected/stored/DOM +
> cookie theft), LFI/RFI (path traversal, PHP wrapper abuse, log/session poisoning to RCE), OS command
> injection (detection + filter bypass), and SSRF/XXE primers.

## 5. Recon & External Enumeration

| Tool | URL | Purpose |
|---|---|---|
| Nmap (+ NSE docs) | https://nmap.org/book/ · https://nmap.org/nsedoc/ | Host discovery, port/service scanning, scripting engine (`--script vuln`, `http-enum`). |
| AutoRecon | https://github.com/Tib3rius/AutoRecon | Multi-threaded automated recon/service enumeration; very popular for OSCP initial enum. |
| enum4linux-ng | https://github.com/cddmp/enum4linux-ng | Modernized SMB/Samba enumeration with JSON/YAML export. |
| SMBMap / netexec (nxc) | https://github.com/Pennyw0rth/NetExec | SMB share enumeration, spraying, module execution; actively-maintained CrackMapExec successor. |
| feroxbuster | https://github.com/epi052/feroxbuster | Fast Rust-based recursive content discovery. |
| ffuf | https://github.com/ffuf/ffuf | Flexible, fast web fuzzer (dirs/vhosts/params). |
| Gobuster | https://github.com/OJ/gobuster | Dir/DNS/vhost brute-forcing. |
| OSINT Framework | https://osintframework.com/ | Categorized index of OSINT tools/techniques for external recon. |
| Michael Bazzell — OSINT Techniques | https://inteltechniques.com/book1.html | Authoritative OSINT practitioner reference (digital footprint, footprinting workflow). |

> **Deep-dive:** [`notes/enum-automation-frameworks.md`](notes/enum-automation-frameworks.md) covers
> automated enumeration framework selection/usage (AutoRecon, Legion, reconftw-style pipelines) and how to
> layer them with manual verification rather than trusting output blindly.

## 6. Active Directory

### 6.1 Core tooling

| Tool | URL | Purpose |
|---|---|---|
| Impacket | https://github.com/fortra/impacket | Python SMB/MSRPC/Kerberos/LDAP toolkit — `GetUserSPNs`, `GetNPUsers`, `secretsdump`, `ntlmrelayx`, `psexec.py`/`wmiexec.py`. |
| BloodHound (+ SharpHound) | https://github.com/SpecterOps/BloodHound | Graph-based AD attack-path mapping; ingests ACLs, sessions, group membership, trusts. |
| Rubeus (GhostPack) | https://github.com/GhostPack/Rubeus | C# raw Kerberos interaction/abuse: `asktgt`, `kerberoast`, `asreproast`, `s4u`, `golden`, `silver`. |
| Mimikatz | https://github.com/gentilkiwi/mimikatz | Credential/ticket extraction; pass-the-hash, pass-the-ticket, DCSync, golden/silver tickets. |
| PowerView / PowerSploit | https://github.com/PowerShellMafia/PowerSploit | PowerShell AD enumeration/exploitation (`Get-NetUser -SPN`, `Find-LocalAdminAccess`). |
| netexec (NXC) | https://github.com/Pennyw0rth/NetExec | Password spraying, module execution across SMB/WinRM/LDAP/MSSQL. |
| Certipy | https://github.com/ly4k/Certipy | ADCS enumeration/abuse — ESC1 through ESC16 attack paths. |
| Seatbelt (GhostPack) | https://github.com/GhostPack/Seatbelt | C# host situational-awareness/enumeration. |

### 6.2 Methodology & technique deep-dives

| Resource | URL | Covers |
|---|---|---|
| ADSecurity.org (Sean Metcalf) | https://adsecurity.org/ | Foundational AD attack/defense research — Kerberoasting, DCSync, delegation, trust attacks. |
| harmj0y's blog (Will Schroeder) | https://blog.harmj0y.net/ | Deep Kerberos delegation tradecraft — see "Another Word on Delegation." |
| wald0.com (Andy Robbins) | https://wald0.com/ | BloodHound co-creator; ACL/attack-path abuse theory. |
| SpecterOps Blog | https://specterops.io/blog/ | Leading source for novel AD/identity attack research. |
| Certified Pre-Owned (ADCS whitepaper) | https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf | The definitive ADCS ESC1–ESC8 escalation/persistence reference. |
| The Hacker Recipes — AS-REP Roasting | https://www.thehacker.recipes/ad/movement/kerberos/asreproast | Enumeration + roasting workflow (Rubeus, Impacket GetNPUsers). |
| The Hacker Recipes — DACL abuse | https://www.thehacker.recipes/ad/movement/dacl/ | GenericAll/WriteDACL/WriteOwner/ForceChangePassword abuse. |
| Roasting AS-REPs (harmj0y, 2017) | https://blog.harmj0y.net/activedirectory/roasting-as-reps/ | Original AS-REP roasting write-up. |
| Cracking Kerberos TGS Tickets (Metcalf) | https://adsecurity.org/?p=2293 | Kerberoasting walkthrough — RC4 vs AES ticket encryption. |
| Kerberos Golden Tickets (Metcalf) | https://adsecurity.org/?p=1640 | KRBTGT-key ticket forgery. |
| Kerberos Silver Tickets (Metcalf) | https://adsecurity.org/?p=2011 | Service-ticket forgery without contacting a DC. |
| Wagging the Dog: RBCD (Elad Shamir) | https://eladshamir.com/2019/01/28/Wagging-the-Dog.html | Resource-based constrained delegation abuse via DACL write access. |
| Shadow Credentials (SpecterOps) | https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab | `msDS-KeyCredentialLink` / PKINIT abuse; Whisker tool. |
| RFC 4120 — Kerberos v5 | https://www.rfc-editor.org/rfc/rfc4120 | Normative protocol spec (AS/TGS exchange, pre-auth, ticket model). |
| MS-SFU / RBCD delegation spec | https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/ | S4U2Self / S4U2Proxy extensions underlying constrained delegation. |
| MS-NLMP (NTLM spec) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/ | Normative NTLM challenge-response protocol reference. |
| MITRE ATT&CK — DCSync (T1003.006) | https://attack.mitre.org/techniques/T1003/006/ | MS-DRSR replication API abuse for credential extraction. |
| MITRE ATT&CK — Pass the Hash (T1550.002) | https://attack.mitre.org/techniques/T1550/002/ | NTLM hash reuse for authentication. |
| MITRE ATT&CK — Pass the Ticket (T1550.003) | https://attack.mitre.org/techniques/T1550/003/ | Stolen/forged Kerberos ticket reuse. |
| infosecn1nja — AD Attack & Defense | https://github.com/infosecn1nja/AD-Attack-Defense | AD kill-chain reference: Discovery → Privesc → Evasion → Cred Dumping → Lateral Movement → Persistence. |
| GPP credential abuse (KB2962486) | https://support.microsoft.com/kb/2962486 | Group Policy Preferences `cpassword` decryption background. |
| SharpGPOAbuse | https://github.com/FSecureLABS/SharpGPOAbuse | GPO write-permission abuse tooling. |

> **Deep-dive command references (added in the second research pass):**
> [`notes/adcs-certipy-cheatsheet.md`](notes/adcs-certipy-cheatsheet.md) — full Certipy `find`/`req`/`auth`/`shadow`/`account`
> syntax with worked ESC1/ESC3/ESC8 examples. [`notes/ad-coercion-and-relay.md`](notes/ad-coercion-and-relay.md) —
> PetitPotam/PrinterBug/ShadowCoerce/DFSCoerce + `ntlmrelayx` chains to RBCD/Shadow Credentials/ADCS ESC8
> (confirmed gap in `security-practitioners-guide` — no dedicated entry exists there yet).
> [`notes/windows-lateral-movement-persistence.md`](notes/windows-lateral-movement-persistence.md) — DCOM/WMI/schtasks/PsExec
> lateral movement plus AdminSDHolder/DCShadow/Skeleton Key persistence at reference level.
> [`notes/ad-delegation-trust-bloodhound.md`](notes/ad-delegation-trust-bloodhound.md) — unconstrained/constrained/RBCD
> delegation abuse paths, cross-forest/domain trust attacks, and BloodHound collection/query workflow
> (SharpHound flags, common Cypher queries for shortest-path-to-DA).
> [`notes/ad-domain-privesc-cves.md`](notes/ad-domain-privesc-cves.md) — targeted domain-privesc CVE/misconfig
> reference: ZeroLogon (CVE-2020-1472), noPac/sAMAccountName spoofing (CVE-2021-42278/42287), Certifried
> (CVE-2022-26923), GPP `cpassword` decryption, GPO write-permission abuse (SharpGPOAbuse/pyGPOAbuse), and
> DNSAdmins → DC RCE via `serverlevelplugindll`.

## 7. Windows Privilege Escalation

| Resource | URL | Notes |
|---|---|---|
| PEASS-ng (winPEAS) | https://github.com/peass-ng/PEASS-ng | Standard automated Windows LPE enumeration (AlwaysInstallElevated, token privs, unquoted paths, HiveNightmare checks). |
| PowerUp.ps1 (PowerSploit) | https://github.com/PowerShellMafia/PowerSploit | Service/permission misconfiguration scanner — `Get-ModifiableServiceFile`, `Get-UnquotedService`. |
| FuzzySecurity / g0tmi1k Windows PE references | https://www.fuzzysecurity.com/tutorials/16.html | Foundational manual-enumeration baseline: service misconfig, token impersonation, DLL hijacking, registry paths. |
| PrintSpoofer (itm4n) | https://github.com/itm4n/PrintSpoofer | SeImpersonatePrivilege → SYSTEM via spooler named-pipe hijack. |
| GodPotato | https://github.com/BeichenDream/GodPotato | Modern Potato variant (Server 2012–2022); most reliable current COM-coercion privesc. |
| JuicyPotato | https://github.com/ohpe/juicy-potato | Legacy COM-activation privesc for Windows 7 – Server 2019 (CLSID list by version). |
| LOLBAS | https://lolbas-project.github.io/ | Living-off-the-land Windows binaries — execution/download/UAC-bypass techniques. |
| MITRE ATT&CK — SMB Admin Shares (T1021.002) | https://attack.mitre.org/techniques/T1021/002/ | Lateral movement via C$/ADMIN$/IPC$ + PsExec pattern. |
| MITRE ATT&CK — WinRM (T1021.006) | https://attack.mitre.org/techniques/T1021/006/ | PowerShell remoting / evil-winrm lateral movement. |
| MITRE ATT&CK — WMI (T1047) | https://attack.mitre.org/techniques/T1047/ | WMI-based remote execution/lateral movement. |

> **Deep-dive:** [`notes/windows-privesc-scripts.md`](notes/windows-privesc-scripts.md) covers scripted/manual
> Windows privesc enumeration (winPEAS/PowerUp/Seatbelt flag reference plus manual registry/service/token checks)
> and how to cross-check automated tool output before acting on it.
>
> **Deep-dive:** [`notes/easy-lpe-cve-quickhits.md`](notes/easy-lpe-cve-quickhits.md) covers the Windows half
> of a curated known-CVE fast path for local privesc — PrintNightmare, HiveNightmare/SeriousSAM, and the
> recurring `win32k.sys`/`afd.sys`/`clfs.sys`/`ntoskrnl.exe` kernel LPE chain from 2021 through 2026 — to
> check against a fingerprinted build version before falling back to full manual enumeration.

## 8. Linux Privilege Escalation

| Resource | URL | Notes |
|---|---|---|
| PEASS-ng (linPEAS) | https://github.com/peass-ng/PEASS-ng | Standard automated Linux LPE enumeration. |
| linux-smart-enumeration (les) | https://github.com/diego-treitos/linux-smart-enumeration | Tiered-verbosity enum script, lighter than linPEAS. |
| pspy | https://github.com/DominicBreuker/pspy | Unprivileged process monitoring — catches cron jobs/privileged process activity. |
| GTFOBins | https://gtfobins.github.io/ | Unix binary privesc/breakout via `sudo -l`, SUID, capabilities. |
| unix-privesc-check | (bundled in Kali) | Legacy but still-useful automated Linux privesc checklist. |

> **Deep-dive:** [`notes/linux-privesc-advanced.md`](notes/linux-privesc-advanced.md) covers capabilities abuse,
> cron/PATH/wildcard injection, NFS `no_root_squash`, Docker/LXD group breakout, writable `/etc/passwd`,
> the kernel-exploit lookup workflow, and `LD_PRELOAD`/library hijacking — with detection + exploitation
> commands for each.
>
> **Deep-dive:** [`notes/easy-lpe-cve-quickhits.md`](notes/easy-lpe-cve-quickhits.md) covers the Linux half
> of a curated known-CVE fast path for local privesc — Dirty COW, PwnKit, Dirty Pipe, Baron Samedit, Looney
> Tunables, GameOver(lay), needrestart, sudo chroot/"chwoot", and more, one-command-or-one-tool PoCs only —
> to check against a fingerprinted kernel/package version before falling back to full manual enumeration.

## 9. Buffer Overflow / Exploit Development

> **Not scored on the current OSCP exam** (removed in the [2023 PEN-200 update](https://www.offsec.com/blog/pen-200-2023/)),
> still taught in the course and worth understanding for foundational exploit-dev skill.

| Resource | URL | Notes |
|---|---|---|
| TCM Security — "Buffer Overflows Made Easy" (free) | https://www.youtube.com/watch?v=qSnPayW6F7U | Classic free walkthrough using Vulnserver + Immunity Debugger; historically the most-recommended free OSCP-style BOF tutorial. |
| corelan.be Exploit Writing Tutorials | https://www.corelan.be/index.php/category/exploit-writing-tutorials/ | Canonical multi-part deep-dive (stack overflows, SEH, shellcode, egghunters). |
| Immunity Debugger + mona.py workflow | https://www.immunityinc.com/products/debugger/ | Standard fuzz → EIP offset → bad-char → JMP ESP → shellcode methodology (per the user's own course notes). |
| pwntools docs | https://docs.pwntools.com/en/stable/ | Python exploit-dev framework — ELF parsing, ROP, shellcraft, `cyclic` pattern offset-finding. |
| msfvenom | (part of Metasploit Framework) | Shellcode generation with bad-char exclusion (`-b`) and encoders. |

> **Deep-dive:** [`notes/buffer-overflow-legacy.md`](notes/buffer-overflow-legacy.md) — worked legacy
> stack-overflow methodology notes (fuzz → offset → bad-char → JMP ESP → shellcode), kept for reference-level
> exploit-dev familiarity even though BOF is no longer scored on the exam.

## 10. Password Attacks & Cracking

| Tool | URL | Purpose |
|---|---|---|
| hashcat | https://hashcat.net/hashcat/ | GPU-accelerated cracking; 350+ hash modes (`-m 13100` Kerberoast, `-m 18200` AS-REP). |
| John the Ripper | https://www.openwall.com/john/ | Strong for Unix crypt formats (`/etc/shadow`); Jumbo community edition. |
| RockYou + SecLists passwords | https://github.com/danielmiessler/SecLists/tree/master/Passwords | Baseline wordlists for cracking campaigns. |
| Hashcat rule-based attacks | https://hashcat.net/wiki/doku.php?id=rule_based_attack | Password mutation rule syntax (`best64.rule`, `dive.rule`). |
| Hydra | https://github.com/vanhauser-thc/thc-hydra | Multi-service and HTTP POST-form online brute force. |
| Responder | https://github.com/lgandx/Responder | LLMNR/NBT-NS/mDNS poisoning for hash capture. |
| Crunch | (Kali default) | Pattern-based wordlist generation. |

> **Deep-dive:** [`notes/password-attacks-advanced.md`](notes/password-attacks-advanced.md) covers password
> spraying strategy/lockout-avoidance, custom mangling-rule authoring, and NTLM/Kerberos hash-type-specific
> cracking workflow beyond the basic hashcat/John invocations above.

## 11. Pivoting & Tunneling

| Tool | URL | Purpose |
|---|---|---|
| The Hacker Recipes — Pivoting | https://www.thehacker.recipes/infra/pivoting | Reference covering SSH forwarding, SOCKS proxies, ligolo-ng, chisel, socat relay chains. |
| ligolo-ng | https://github.com/nicocha30/ligolo-ng | TUN-interface tunneling without proxychains; agent/proxy model. |
| sshuttle | https://github.com/sshuttle/sshuttle | VPN-like subnet routing over SSH. |
| chisel | https://github.com/jpillora/chisel | HTTP tunnel with SOCKS5 support, useful where only HTTP egress exists. |
| proxychains | (Kali default) | SOCKS5-wrap arbitrary tools (nmap, BloodHound, Impacket) through a pivot. |
| Metasploit routing/portfwd | https://docs.metasploit.com/ | `route add` + `auxiliary/server/socks_proxy`, `autoroute`, `portfwd`. |

> **Deep-dive:** [`notes/pivoting-tunneling.md`](notes/pivoting-tunneling.md) covers worked multi-hop
> pivot chains (dual-pivot ligolo-ng/chisel setups, SSH -R/-L/-D combinations, proxychains config gotchas)
> beyond the single-tool summaries in the table above.

## 12. Reporting & Note-Taking Tools

| Tool | URL | Notes |
|---|---|---|
| Obsidian | https://obsidian.md/ | Markdown linked-notes app; widely adopted for OSCP methodology tracking. |
| CherryTree | (Kali default) | Hierarchical rich-text notes — long the default OSCP note-taking tool. |
| SysReptor + OffSec-Reporting templates | https://github.com/Syslifters/sysreptor · https://github.com/Syslifters/OffSec-Reporting | Open-source markdown-driven reporting platform with an OSCP/OSEP/OSWP template pack. |
| PwnDoc-ng | https://github.com/pwndoc-ng/pwndoc-ng | Self-hosted report generator, customizable DOCX output. |
| noraj — OSCP Markdown Report Template | https://github.com/noraj/OSCP-Exam-Report-Template-Markdown | Markdown reimplementation of the official OffSec report template. |
| chvancooten — OSCP Markdown Templates | https://github.com/chvancooten/OSCP-MarkdownReportingTemplates | Widely-used markdown exam/lab report templates + enum script. |

## 13. Communities

| Community | URL | Notes |
|---|---|---|
| OffSec Official Discord | https://discord.com/invite/offsec | Largest official, staff-monitored hub. |
| r/oscp | https://www.reddit.com/r/oscp/ | Primary subreddit for OSCP discussion and exam-day advice. |
| NetSecFocus | https://netsec-focus.github.io/ | Origin of the "Trophy Room" tracking culture; **verified: its Mattermost chat has been down since ~2021 with no official successor announced** — treat as an archive/list source, not an active chat community. |
| InfoSec Prep Discord | https://discord.gg/infosecprep | Community-run Discord commonly cited as where OSCP-prep chat activity dispersed to after NetSecFocus's Mattermost went down (not an official NetSecFocus successor). |
| TechExams — OSCP forum | https://community.infosecinstitute.com/discussion/127097/discord-oscp-channel | Longstanding certification discussion forum. |

## 14. Methodology Video/Blog Channels

| Channel | URL | Notes |
|---|---|---|
| ippsec | https://www.youtube.com/@ippsec | Definitive HTB retired-box walkthrough channel — methodology and manual enumeration technique. |
| TCM Security / The Cyber Mentor | https://www.youtube.com/@TCMSecurityAcademy | Free long-form pentesting courses (Linux/Windows privesc, practical ethical hacking). |
| John Hammond | https://www.youtube.com/@_JohnHammond | CTFs, malware analysis, general offensive security education. |
| 0xdf hacks stuff | https://0xdf.gitlab.io/ | Methodology-driven retired-box writeups, cross-referenced against TJnull's list. |

---

## 15. Internal Cross-References

- **`security-practitioners-guide`** (this org's CSKB) — `content/offsec/ptext/`, `content/offsec/ptint/`,
  `content/offsec/redteam/`, `content/offsec/tradecraft/`, and `content/resources/` contain ~30+
  additional deep-dive reference entries on AD architecture, forest/trust attacks, LDAP hardening,
  GPO abuse, hash attacks, Windows lateral-movement forensics, and web testing methodology that
  informed this document — cross-reference that repo directly for the full annotated citations.
- **Personal Notion course notes** — the user's own PEN-200 training notes (Notes Structure &
  Methodology + Course Notes pages) supplied the working methodology order reflected in this
  document's structure and confirmed real, hands-on tool usage patterns (e.g., the repeated
  "compile with mingw-w64 → host via `python3 -m http.server` → `iwr`/`curl` pull" pattern used
  across multiple Windows privesc techniques). Exam-attempt-specific content (target IPs, flags,
  credentials) was deliberately excluded from this document per OffSec's exam NDA.

## 16. Open Items — Status

**Resolved in the second research pass (deep-dive workflow):**

- [x] TJnull spreadsheet URL and NetSecFocus chat platform — verified, see §3/§13 (medium-high
      confidence; both relied on WebSearch snippets since docs.google.com/netsecfocus.com blocked
      automated fetches during verification — spot-check periodically).
- [x] OSCP report template format — verified both `.docx` and `.odt` are officially provided, see §1.
- [x] ADCS command cheat-sheet — done, see [`notes/adcs-certipy-cheatsheet.md`](notes/adcs-certipy-cheatsheet.md)
      (ESC1–ESC8 summary table + worked ESC1/ESC3/ESC8 examples).
- [x] Wordlist/payload/command quick-reference appendix — done, see [`CHEATSHEET.md`](CHEATSHEET.md)
      (nmap, gobuster/feroxbuster/ffuf, SecLists paths, hashcat `-m` modes, msfvenom, reverse-shell
      one-liners).
- [x] Exam-day logistics (proctoring, time budgeting, documentation/proof-file rules, AI-tool policy) —
      done, see [`EXAM-TIPS.md`](EXAM-TIPS.md).
- [x] AD coercion/relay chain (PetitPotam/PrinterBug/ShadowCoerce/DFSCoerce → `ntlmrelayx` → RBCD/Shadow
      Credentials/ADCS ESC8) — done, see [`notes/ad-coercion-and-relay.md`](notes/ad-coercion-and-relay.md).
      **Confirmed as a genuine content gap in `security-practitioners-guide`** (no dedicated entry exists
      there for any of these four coercion primitives) — worth upstreaming into that repo separately.
- [x] Windows lateral movement beyond Kerberos tickets (DCOM/WMI/schtasks/PsExec) and reference-level AD
      persistence (AdminSDHolder/DCShadow/Skeleton Key) — done, see
      [`notes/windows-lateral-movement-persistence.md`](notes/windows-lateral-movement-persistence.md).
- [x] Targeted domain-privesc CVE/misconfig reference (ZeroLogon, noPac/sAMAccountName spoofing,
      Certifried, GPP `cpassword`, GPO abuse, DNSAdmins → DC RCE) — done, see
      [`notes/ad-domain-privesc-cves.md`](notes/ad-domain-privesc-cves.md).
- [x] Delegation/RBCD abuse paths, cross-forest/domain trust attacks, ACL-edge abuse, and BloodHound
      collection/query workflow — done, see
      [`notes/ad-delegation-trust-bloodhound.md`](notes/ad-delegation-trust-bloodhound.md).
- [x] Deeper Linux privesc (capabilities, cron/PATH/wildcard, NFS, Docker/LXD, kernel-exploit workflow,
      LD_PRELOAD) — done, see [`notes/linux-privesc-advanced.md`](notes/linux-privesc-advanced.md).
- [x] Deeper web attack techniques (upload bypass, deserialization, WordPress, CMS fingerprinting) — done,
      see [`notes/web-attack-techniques.md`](notes/web-attack-techniques.md).
- [x] Core manual web-vulnerability methodology (SQLi, XSS, LFI/RFI, command injection, SSRF, XXE) — this
      was a real gap (only sqlmap automation and incidental mentions existed; no worked manual technique) —
      done, see [`notes/web-core-vulnerabilities.md`](notes/web-core-vulnerabilities.md).
- [x] Per-service manual enumeration reference (FTP, SMB/NetBIOS, MSRPC, NFS, LDAP, SMTP, SNMP incl.
      v3, DNS, RDP, WinRM, SSH, and MySQL/MSSQL/Oracle/PostgreSQL/Redis) — done, see
      [`notes/service-enumeration-comprehensive.md`](notes/service-enumeration-comprehensive.md).
- [x] Credential-harvesting / post-exploitation loot reference, Linux and Windows — done, see
      [`notes/credentials-harvesting-post-exploitation.md`](notes/credentials-harvesting-post-exploitation.md).
- [x] File transfer / tool-staging technique matrix (netcat, SMB, HTTP(S), SCP, base64/`certutil`
      chunking, `/dev/tcp`, PowerShell cradles) — done, see
      [`notes/file-transfer-matrix.md`](notes/file-transfer-matrix.md); reverse/bind shell payloads
      themselves are in [`CHEATSHEET.md`](CHEATSHEET.md) §5–6.
- [x] Curated "easy" LPE CVE quick-reference — recent-ish, one-command-or-one-tool, broadly-applicable
      Windows and Linux local privesc CVEs to check against a fingerprinted OS/kernel/package version
      before falling back to full manual enumeration — done, see
      [`notes/easy-lpe-cve-quickhits.md`](notes/easy-lpe-cve-quickhits.md) (14 Linux + 11 Windows entries,
      each independently fact-checked against NVD/vendor advisories before inclusion, spanning
      CVE-2016-5195/Dirty COW through CVE-2026-46333, disclosed May 2026).
- [x] Build the full step-by-step **methodology document** (separate from this resource list) that
      sequences: recon → web → initial access → Windows/Linux privesc → AD enumeration → AD attack →
      lateral movement → reporting, using the flow captured in §15 and stitching together all the
      companion files above into one linear walkthrough — done, see
      [`notes/ad-methodology-end-to-end.md`](notes/ad-methodology-end-to-end.md). Scoped to the AD set
      specifically (the exam's assumed-breach-credential → DC+2-client-machine chain, worth 40 of the
      100 points) rather than the full recon→web→standalone-privesc surface, since that's where a single
      linear walkthrough adds the most value beyond the per-technique deep-dive files; it sequences and
      links every AD companion file above (BloodHound, ACL abuse, delegation/RBCD, coercion/relay, ADCS,
      domain-privesc CVEs, credential harvesting, lateral movement) into one numbered, decision-driven
      path plus a quick-reference keyed off current access level.
- [x] Consider a short ADCS ESC9–ESC16 addendum (current cheat sheet covers ESC1–ESC8 in depth; ESC9/10
      security-extension bypass and ESC13/15 issuance-policy abuse are newer and increasingly tested) —
      done, see [`notes/adcs-certipy-cheatsheet.md`](notes/adcs-certipy-cheatsheet.md) §6 ("ESC9–ESC16
      Reference Addendum"), covering ESC9 (no security extension), ESC10 (weak certificate mapping),
      ESC11 (NTLM relay to ICPR RPC), ESC12 (CA private key access), ESC13 (issuance policy → privileged
      group), ESC14 (explicit certificate mapping), ESC15/EKUwu (CVE-2024-49019), and ESC16 (security
      extension disabled CA-wide).

**Still open:**

- [ ] Upstream the AD coercion/relay content gap identified above into `security-practitioners-guide`
      (`content/offsec/ptint/` or a new `content/resources/` entry), since it's a real gap in that repo,
      not just this one.
- [ ] Re-verify the TJnull Google Sheet and NetSecFocus links with a direct (non-automated) browser check
      before treating them as stable long-term citations — verification this pass was search-snippet-only
      due to outbound network policy blocking docs.google.com/netsecfocus.com/help.offsec.com directly.
