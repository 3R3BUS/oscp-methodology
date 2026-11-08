# Standalone Box Methodology — End-to-End Exam Walkthrough

*A linear, numbered sequence for the three OSCP standalone machines — the counterpart to
[`ad-methodology-end-to-end.md`](ad-methodology-end-to-end.md), but for an independent box with no
assumed-breach credential. This is the **sequencing and decision-making layer**: what to try, in what
order, why, and what "good enough to move on" looks like at each stage. It does not re-paste command
blocks that already live in the deep-dive files; follow each pointer for syntax. For authorized OSCP
exam/lab use only.*

> **Helper scripts:** [`scripts/fast-nmap.sh`](../scripts/README.md) runs the whole nmap sequence in
> one command; [`scripts/web-recon.sh`](../scripts/README.md) does web enumeration; and
> [`scripts/privesc-launcher.sh`](../scripts/README.md) stages linPEAS/winPEAS once you have a shell.

**How to use this document:** read it once end-to-end before exam day, then keep it open as a checklist
during the exam — work top to bottom, and use the quick-reference at the bottom to jump to whichever
stage your current progress calls for.

---

## 0. Exam Context Recap

The **three standalone machines are worth 60 of the exam's 100 points** — 20 each, split **10 for
initial access (a low-priv shell) + 10 for privilege escalation to root/SYSTEM**. That split drives the
whole strategy: a foothold alone banks 10 points, so **capture `local.txt` and initial-access proof the
moment you land a shell**, before you start privesc — don't risk losing a confirmed 10 points by chasing
root first. Common timing: do one standalone first as a warm-up (~2–4 h), budget ~2–3 h for each of the
others, and treat a box that won't break after your time-box as a cue to switch rather than sink the
whole exam into it. See [`EXAM-TIPS.md`](../EXAM-TIPS.md) §2 for scoring and time strategy.

---

## 1. Full Port & Service Enumeration

Everything starts here, and a missed port is a missed box — so enumerate **all** of it, once,
thoroughly, before touching an exploit. Run the full sequence: fast all-ports TCP sweep → targeted
`-sC -sV` service/version scan on what's open → UDP top-100 in parallel → `nmap --script vuln` pass.
[`scripts/fast-nmap.sh`](../scripts/README.md) chains all of this into one command. "Success" at this
stage is a complete service/version map: every open TCP (and the common UDP) port, with the service,
version string, and any NSE-vuln hits captured to disk for your notes. Don't move on with a half-scan —
re-enumerating later because you rushed this is the single biggest standalone time sink. See
[`CHEATSHEET.md`](../CHEATSHEET.md) §1 for the manual nmap sequence and
[`notes/service-enumeration-comprehensive.md`](service-enumeration-comprehensive.md) for what each
service's banner is telling you.

---

## 2. Choose the Attack Surface

Stop and read the scan before acting. With the full service map in hand, pick the **most promising
single attack surface** rather than poking everything at once. Rough priority for an OSCP standalone:
**a web app** (80/443/8080/8443 — almost always the richest surface and the most common foothold) >
**a named, versioned service with a likely public exploit** (outdated SMB, an app with a CVE in its
banner) > **a login surface you can attack with discovered/guessable creds** (SSH, RDP, WinRM, MSSQL,
FTP) > **less common services** (NFS, SNMP, rsync, mail). Note every surface in your notes so you have
fallbacks, but commit to the highest-probability one first. A version string that looks exploitable is
your cue to jump to Stage 3's public-exploit path; a web port is your cue to Stage 3's web path.

---

## 3. Deep Enumeration of the Chosen Service

Enumerate the surface you picked until you understand it well enough to attack it deliberately.
- **Web:** run [`scripts/web-recon.sh`](../scripts/README.md) (whatweb, dir/file brute, vhost fuzzing,
  TLS SANs, robots), then manually explore — identify the stack/CMS/version, find input points, admin
  panels, uploads, and parameters. → [`notes/web-attack-techniques.md`](web-attack-techniques.md) and
  [`notes/web-core-vulnerabilities.md`](web-core-vulnerabilities.md).
- **A versioned service:** take the exact product + version to `searchsploit` and a CVE lookup. →
  [`notes/public-exploit-adaptation.md`](public-exploit-adaptation.md) for finding, reading, and
  **adapting** a public PoC (the OSCP tests whether you can fix an exploit's offsets/IPs/shellcode, not
  just run it).
- **Other services (SMB/FTP/SNMP/NFS/MSSQL/etc.):** → the matching section of
  [`notes/service-enumeration-comprehensive.md`](service-enumeration-comprehensive.md).

"Success" is a concrete, identified vulnerability or a credentialed login path — the specific thing
you're about to exploit for initial access. If the surface turns out to be a dead end, go back to
Stage 2 and take the next one rather than forcing it.

---

## 4. Initial Access — the First 10 Points

Turn the identified vuln into code execution or an interactive login. The route depends on Stage 3:
file-upload/LFI/RFI/command-injection/SQLi-to-shell on web; an adapted public exploit for a versioned
service; or authenticated access (SSH/WinRM/RDP/`psexec`-style) with discovered or reused credentials.
Keep it **manual and understood** — remember the exam's one Metasploit machine, so if you intend to use
that allowance, spend it deliberately (never on an AD-set box). "Success" is a shell or an interactive
session on the box. The moment you have it, go to Stage 5 and then **immediately Stage 6 to bank the
proof** — a foothold you can't prove is worth zero. See
[`notes/web-core-vulnerabilities.md`](web-core-vulnerabilities.md) for the web-to-RCE techniques and
[`notes/file-transfer-matrix.md`](file-transfer-matrix.md) for getting a payload/reverse shell onto the
target.

---

## 5. Stabilize the Shell

A raw reverse shell is fragile — stabilize it before you do anything you don't want to lose. Upgrade to
a full TTY (`python3 -c 'import pty;pty.spawn("/bin/bash")'` → `Ctrl-Z` → `stty raw -echo; fg` on
Linux), set `TERM`, and confirm you have a working interactive prompt with history and tab-completion.
On Windows, move to a more stable shell (an uploaded `nc`, a WinRM session, or a Meterpreter only if
this is your Metasploit box). "Success" is a shell that survives a mistyped command and lets you run an
editor/pager. → [`CHEATSHEET.md`](../CHEATSHEET.md) §6 (reverse-shell + TTY stabilization one-liners).

---

## 6. Capture Initial-Access Proof NOW

Before privesc, lock in the 10 points you just earned. Read `local.txt` **through the interactive shell
on the target** (never via an out-of-band file read), and capture a screenshot showing, in one frame:
the `local.txt` contents, your user context (`whoami`/`id`), and the host's IP (`ip addr`/`ipconfig`).
This is a distinct, separately-gradable stage — do it every box, every time, the instant you have the
shell, because you lose the shell the moment the exam window closes. → [`EXAM-TIPS.md`](../EXAM-TIPS.md)
§3 (proof/screenshot requirements) and [`notes/reporting-methodology.md`](reporting-methodology.md) §5
(the always-on logging + screenshot-checkpoint strategy).

---

## 7. Local Privilege-Escalation Enumeration

Now enumerate the box from the inside for a path to root/SYSTEM. Run the automated enumerator first to
surface low-hanging fruit — [`scripts/privesc-launcher.sh`](../scripts/README.md) stages linPEAS
(Linux) or winPEAS (Windows) — then read its output and work the OS-specific checklist by likelihood
rather than firing exploits blind. Also capture the basics by hand: OS/kernel build, current user's
privileges/groups, sudo rights, running services, scheduled tasks/cron, writable paths, and interesting
files. "Success" is a specific, identified escalation vector (a sudo misconfig, a SUID binary, a
writable service, a kernel/OS version with a known LPE, a stored credential). → full technique matrices
in [`notes/linux-privesc-advanced.md`](linux-privesc-advanced.md) and
[`notes/windows-privesc-scripts.md`](windows-privesc-scripts.md).

---

## 8. Privilege Escalation — the Second 10 Points

Execute the vector you found. Prioritize by reliability and blast radius:
- **Linux:** sudo rules (GTFOBins), SUID/`capabilities`, writable cron/PATH/service, then a
  kernel/OS-version LPE as a later resort (kernel exploits can panic the box — snapshot your notes
  first). → [`notes/linux-privesc-advanced.md`](linux-privesc-advanced.md).
- **Windows:** service/task misconfigurations, **SeImpersonate → PrintSpoofer/GodPotato**, unquoted
  service paths, AlwaysInstallElevated, stored credentials. →
  [`notes/windows-privesc-scripts.md`](windows-privesc-scripts.md).
- **Known-CVE fast path (either OS):** if the OS/kernel build is old, a documented LPE CVE may be
  faster than the misconfig hunt — check [`notes/easy-lpe-cve-quickhits.md`](easy-lpe-cve-quickhits.md)
  (which also notes where a public PoC is the exam-safe choice over a Metasploit module).

"Success" is `root`/`NT AUTHORITY\SYSTEM`. Don't reach for Metasploit's `local_exploit_suggester` or an
auto-exploit module unless this is your one designated Metasploit machine.

---

## 9. Capture Root Proof

Same discipline as Stage 6, now for the full compromise: read `proof.txt` through an interactive shell
as root/SYSTEM, and screenshot it in one frame with `whoami`/`id` and the host IP. That closes out the
box's remaining 10 points. Then move to the next machine — but only after confirming both this box's
proofs are captured correctly, because partial credit only counts if it's documented per the
interactive-shell rule. → [`EXAM-TIPS.md`](../EXAM-TIPS.md) §3.

---

## 10. When a Box Won't Break — Time-Box and Switch

Standalones are the least predictable part of the exam; a single stubborn box can eat hours. Guardrails:
- **Time-box each surface (~20–30 min of no progress → next surface), and each box (~2–3 h → move on).**
- When stuck, the fix is almost always **more enumeration, not more force** — re-read your scan output,
  re-run dir/file brute with a bigger wordlist or more extensions, check a port/service you skipped,
  revisit UDP, and re-examine version strings you dismissed.
- Rotate boxes deliberately: a fresh box after a break often reveals what you were staring past. Come
  back to the stubborn one with remaining time, not your last hour.
See [`EXAM-TIPS.md`](../EXAM-TIPS.md) for the rabbit-hole/time-management guidance in full.

---

## What Do I Try Next? — Quick Reference

Keyed off where you are on the current box.

- **Just connected, nothing scanned yet** → Stage 1 (full port/service enum; run `fast-nmap.sh`).
- **Scan done, don't know where to start** → Stage 2 (pick the surface — web first, then versioned
  services, then login surfaces).
- **A web port is open** → Stage 3 web path (`web-recon.sh` + manual) → Stage 4.
- **A versioned service with a likely exploit** → Stage 3 public-exploit path (`searchsploit`, adapt the
  PoC) → Stage 4.
- **Got a shell** → Stage 5 (stabilize) → **Stage 6 (capture `local.txt` proof NOW)** → Stage 7.
- **Shell + enumeration done, have a vector** → Stage 8 (escalate).
- **root/SYSTEM** → Stage 9 (capture `proof.txt`), then next box.
- **Stuck > 30 min** → Stage 10 (re-enumerate, or time-box and switch boxes).

*This doc sequences the standalone boxes; its AD-set counterpart is
[`ad-methodology-end-to-end.md`](ad-methodology-end-to-end.md), with the dense command catalog in
[`ad-assumed-breach-catalog.md`](ad-assumed-breach-catalog.md).*
