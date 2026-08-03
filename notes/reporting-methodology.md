# Report Structure & Writing Methodology

*Scope note: this file covers how to capture evidence, structure the report, and QA it before
submission. The hard **rules** on proof files and screenshot composition live in
[`EXAM-TIPS.md`](../EXAM-TIPS.md) §3 and are cross-referenced rather than repeated; §5–6 below cover
the **strategy and tooling** layer on top of them (what to shoot vs. log, how much, with what).
Proctoring rules stay in `EXAM-TIPS.md` §1. For authorized OSCP exam/lab use only; contains no
exam-specific target information.*

**Why this file exists:** [`RESOURCES.md`](../RESOURCES.md) §12 lists note-taking/reporting *tools*
(Obsidian, CherryTree, SysReptor, PwnDoc-ng, the noraj/chvancooten templates) but says nothing about
what to actually put in the document those tools produce. This file is that missing layer: report
skeleton, the live-capture-to-report pipeline, a severity reference table, and a pre-submission
checklist.

---

## 1. Report Structure — Matching OffSec's Official Template

Don't freelance the structure. OffSec grades against a specific template and the
[PEN-200 Reporting Requirements](https://help.offsec.com/hc/en-us/articles/360046787731-PEN-200-Reporting-Requirements)
page states the replication standard explicitly; the actual skeleton to fill in is the
[OSCP Exam Report Template](https://www.offsec.com/pwk-online/OSCP-Exam-Report.docx) (`.docx`/`.odt`,
both listed in [`RESOURCES.md`](../RESOURCES.md) §1) or one of its markdown reimplementations
(noraj's or chvancooten's, same §12). Open the real template before exam day — the section list below
is the standard shape every version of it follows; treat it as orientation, not a substitute for
reading the actual document.

| # | Section | Audience | What goes in it |
|---|---|---|---|
| 1 | Title/cover page | — | Candidate name/ID, exam date, document classification. Mechanical, don't overthink it. |
| 2 | Disclaimer / scope statement | Either | One paragraph: this report documents an authorized OSCP exam attempt against a controlled lab environment, not a real client engagement. Comes straight from the template — don't rewrite it. |
| 3 | **Executive summary** | Non-technical (imagine a manager who's never run nmap) | High-level narrative: what was tested, what was found in plain English, overall risk posture. **No command output, no CVE IDs, no tool names as the focus** — "an unauthenticated remote code execution vulnerability was identified on Host X, granting full administrative control" not "exploited CVE-2021-XXXX via a Python PoC against port 8080." This section is graded on whether a non-technical reader understands business impact. |
| 4 | High-level findings summary / recommendations table | Both | One table: target, vulnerability, severity, one-line remediation. This is the bridge between the exec summary and the technical detail — a manager skims this table, a technical reviewer uses it as an index into §6. |
| 5 | **Methodology narrative** | Technical | A general description of your *process*, not target-specific — information gathering → service enumeration → vulnerability identification → exploitation → privilege escalation → post-exploitation, described once at the conceptual level. This is where you demonstrate you followed a repeatable methodology rather than getting lucky. Keep it short (a paragraph or two per phase); the target-specific detail belongs in §6, not here. |
| 6 | **Detailed findings / attack narrative — per target** | Technical | The bulk of the report. One subsection per compromised (or partially compromised) host — see §1.1 below for the repeatable skeleton. |
| 7 | Post-exploitation / lateral movement (AD set) | Technical | If the AD chain crossed multiple hosts, a short narrative tying the per-host sections together into the overall attack path (credential harvested on host A → used on host B → DA on the DC), since the per-host sections alone can read as disconnected without this glue. |
| 8 | Conclusion / overall recommendations | Both | Restates the aggregate risk and top remediation priorities — short, mirrors the exec summary's tone. |
| 9 | Appendix (optional) | Technical | Long tool-output dumps, wordlists used, custom scripts written — anything too long to inline in §6 without breaking its flow. |

### 1.1 Executive Summary vs. Technical Findings — the actual split

The single most common structural mistake is bleeding technical detail into the executive summary or
vice versa. Test: if you removed every occurrence of a CVE ID, a filename, a port number, and a
command, would the executive summary still make sense and convey the right severity? If not, it's not
an executive summary. Conversely, the per-target technical sections should *not* re-explain business
risk in prose — that's what the findings-summary table (§1, row 4) and severity rating are for; §6
should read as "here is exactly what I ran and what happened," reproducible step by step.

### 1.2 Per-Target Section Skeleton

Use the same skeleton for every host — standalone or AD-chain member — so a reviewer can jump to any
target and immediately know where to look for each piece of evidence:

```
### <Hostname/IP> — <OS/role, e.g. "Windows Server 2019 — Domain Controller">

**Synopsis:** one paragraph — what this host is, how it was reached (fresh foothold vs. pivoted from
another host in the chain), and the end state (low-priv shell / root-SYSTEM / DA).

**Information Gathering**
  - Port scan command + full output (or a trimmed table if the raw nmap output is very long — full
    output still belongs in the appendix if trimmed here).
  - Service enumeration per open port, one subsection each.

**Vulnerability Identification**
  - What you noticed and why it looked exploitable (version banner, response behavior, misconfigured
    permission, etc.) — this is the "how did you find it" narrative the replication standard cares
    about, not just "and then I ran the exploit."

**Exploitation**
  - Exact command(s) run, full output, and the resulting shell/access level.
  - Proof-of-foothold screenshot (command + output + `whoami`/`id` + hostname + target IP in one frame
    — see [`EXAM-TIPS.md`](../EXAM-TIPS.md) §3 for the exact composition rule; not re-derived here).

**Privilege Escalation**
  - Enumeration that surfaced the privesc vector, the exploitation command, full output.
  - proof.txt/local.txt screenshot, same composition rule.

**Post-Exploitation / Loot** (if applicable)
  - Credentials harvested, files of interest, anything that fed into another host's compromise —
    explicitly note which downstream host/section it was used in.
```

Fill this skeleton in live during the exam (§2 below) rather than reconstructing it during the 24-hour
write-up window — the skeleton itself should live in your note-taking tool from minute one.

---

## 2. Exam-Day Note Capture → Report Pipeline

[`EXAM-TIPS.md`](../EXAM-TIPS.md) §3 already covers the hard rules — proof-file interactive-shell
requirement, IP-verification-in-frame, screenshot-everything, don't rely on shell history. This section
is the workflow layer on top of those rules: how to organize captures *as you take them* so assembling
the report is a copy-paste-and-clean-up pass, not a research project against your own scrollback.

### 2.1 Capture live vs. reconstruct after

| Capture live, verbatim, as it happens | Safe to write during the 24h report window |
|---|---|
| Every command run + its **full, untruncated** output | Executive summary prose |
| Timestamp (screenshot metadata or a manual note) — matters for the outage-documentation case in `EXAM-TIPS.md` §1 too | Methodology narrative (§1, row 5) — this is process description, not evidence |
| Context: what you were trying and why, one line, before the command block | Recommendations/remediation text per finding |
| Proof screenshots (foothold + privesc), composed per `EXAM-TIPS.md` §3 | The connective "post-exploitation/lateral movement" narrative tying hosts together (§1, row 7) — write this once the whole chain is done and you can see the shape of it |
| Failed attempts, briefly — they demonstrate methodology and matter for partial credit | Final severity ratings (§3 below) — can be assigned retrospectively once you know the full impact achieved, but the *evidence* for each must already be captured live |
| Every intermediate credential/hash the moment it's obtained, and which host it came from | Formatting/polish pass — spelling, section ordering, table alignment |

The rule of thumb: **anything that requires target access to reproduce must be captured live**
(command output, screenshots) — you lose all machine access the instant the exam window closes.
Anything that's pure writing/synthesis from evidence you already have can wait for the write-up window
without risk.

### 2.2 Structure your live notes to mirror the report

Whichever tool from [`RESOURCES.md`](../RESOURCES.md) §12 you use (CherryTree's hierarchy and
Obsidian's per-file notes both work well for this), create one note/page per target the moment you
start enumerating it, and paste the §1.2 skeleton into it immediately. Fill each subsection in as you
go rather than dumping everything into a single running scratch log — a flat chronological log is fast
to write during the exam but expensive to re-sort into per-host, per-phase sections during the 24-hour
window when you're tired and the clock is now on the *report*, not the boxes. The 10 minutes spent
per host organizing notes into the target skeleton live is cheaper than the hours it costs to
reconstruct structure from an undifferentiated log afterward.

Minimum fields per captured command block, non-negotiable:

```
[HH:MM] <one-line context: what you're trying and why>
$ <exact command>
<full output, unedited>
```

Screenshots get the same per-EXAM-TIPS-§3 composition, filed under the matching skeleton subsection
(Exploitation vs. Privilege Escalation) rather than a generic "screenshots" dump folder — misfiled
evidence is a common source of last-minute panic during the write-up window.

---

## 3. Severity Reference for Common OSCP Finding Types

The exam's 70/100 pass bar does **not** depend on formal CVSS scoring — you aren't graded on picking
the mathematically "correct" score. The report template does, however, ask for a severity rating per
finding (Critical/High/Medium/Low/Informational is the standard OffSec-template scale), and an
obviously-wrong rating (labeling an unauthenticated SYSTEM-level RCE "Low," or a missing security
header "Critical") reads as a lack of understanding and undermines an otherwise-solid write-up. Rate
based on **actual demonstrated impact** (what you achieved, not worst-case theory) combined with ease
of exploitation — that's the same logic CVSS v3.1's Impact + Exploitability metric groups encode, just
applied without needing to compute a formal vector string. Full metric definitions:
[FIRST.org CVSS v3.1 Specification](https://www.first.org/cvss/v3-1/specification-document).

| Finding type | Typical severity | Rough CVSS v3.1 range | Why |
|---|---|---|---|
| Unauthenticated RCE → root/SYSTEM | **Critical** | 9.0–10.0 | No auth barrier, remote, full host compromise. |
| Unauthenticated RCE → low-priv shell only | **High** | 8.0–8.9 | Same access barrier, but impact capped until privesc lands. |
| Authenticated RCE (valid creds required) | **High** | 7.5–8.9 | Real impact, but the AV:N/PR:L (or higher) requirement pulls it down from Critical. |
| Local privesc via service/permission misconfig (unquoted path, weak service ACL, writable binary) | **High** | 7.0–8.5 | Full host takeover from an existing low-priv foothold — very common OSCP privesc pattern. |
| Local privesc via known kernel/package CVE (Dirty Pipe, PwnKit, etc.) | **High** | 7.0–8.8 | Same impact tier as above; score varies with local-vs-remote precondition per the specific CVE's own listing. |
| Insecure file upload → RCE (unrestricted extension/content-type) | **Critical** | 9.0–9.8 | Functionally equivalent to unauthenticated RCE once the shell lands. |
| SQL injection → RCE (via `xp_cmdshell`, `INTO OUTFILE`, stacked queries, etc.) | **Critical** | 9.0–9.8 | Data-layer bug escalated to full command execution. |
| SQL injection → data extraction only (no RCE demonstrated) | **High** | 7.5–8.6 | Serious confidentiality impact, but don't inflate to Critical without a demonstrated RCE path. |
| Cleartext credential exposure (plaintext creds in a config/share/GPP `cpassword`) | **High** | 7.0–8.5, scope-dependent | Directly enables lateral movement/privesc; rate higher if the exposed account is privileged (DA, service account with wide reuse). |
| Weak/default/guessable credentials on an exposed service | **High** | 7.0–8.0 | Trivial exploitability drives this even when the "vulnerability" is really a policy gap. |
| Kerberoastable / AS-REP-roastable account with a crackable hash | **Medium**, escalate to **High** if the cracked password grants privileged access | 5.5–7.5 | Exploitability depends entirely on password strength — rate the *finding* (weak Kerberos config) moderate, then let the actual cracked-credential impact drive it higher if it lands you somewhere privileged. |
| Broken access control / IDOR exposing other users' data | **Medium–High**, by sensitivity of exposed data | 5.5–8.1 | Scale with what's actually reachable — PII/credentials push it to High; low-sensitivity data stays Medium. |
| SSRF reaching internal services or cloud metadata endpoint | **High** | 7.5–8.6 | Frequently a pivot point into internal-only attack surface, not just an info leak. |
| Reflected/stored XSS (no session-hijack chain demonstrated) | **Low–Medium** | 4.0–6.1 | Real but bounded impact without a demonstrated account-takeover chain; escalate if you chain it to session theft. |
| Missing patch / outdated software version identified, **no working exploit demonstrated** | **Informational–Low** | 0–3.9 (or unscored) | You found the exposure but didn't prove impact — say so plainly rather than implying exploitation that didn't happen. |
| Verbose error messages / directory listing / banner disclosure | **Informational–Low** | 0–3.9 | Real finding, minimal standalone impact — useful mainly as a supporting detail for how you found something else. |
| Weak organization-wide password policy (general finding, not tied to one exploited account) | **Low–Medium** | 3.0–5.5 | Systemic/preventive-control finding rather than a demonstrated compromise. |

**Don't rate what you didn't demonstrate.** If a finding is "this service *looks* vulnerable to X but I
didn't have time to confirm," say that explicitly and rate it Informational/Low with a note — inflating
an unconfirmed suspicion to Critical is a credibility problem, not a strength.

---

## 4. Pre-Submission QA Checklist

Run this pass **before** converting to PDF, ideally with an hour or two of buffer left in the 24-hour
write-up window — catching a missing screenshot with 20 minutes left is a bad time.

**Per-target evidence**
- [ ] Every target attempted has at least an initial-access/low-priv proof screenshot, even if privesc
      never landed (that's still bankable partial credit — see `EXAM-TIPS.md` §5).
- [ ] Every target's proof.txt/local.txt was read via an interactive shell on the target itself and
      screenshotted, per the non-negotiable rule in `EXAM-TIPS.md` §3 — not through a webshell, SMB
      pull, or any indirect read.
- [ ] Every proof/foothold screenshot shows, in one frame: the command, its output, current user
      context (`whoami`/`id`), hostname, and the target's IP address.
- [ ] Every target's IP is stated correctly and consistently everywhere it's referenced in that
      target's section — a copy-pasted IP from the wrong host is an easy, costly mistake to catch here
      and an impossible one to explain after submission.

**Per-command evidence**
- [ ] Every command block in the report has its **full** output attached — no "output omitted for
      brevity" on anything load-bearing to the exploit chain. Trim only genuinely repetitive noise
      (e.g., a 500-line linPEAS dump can be excerpted with the relevant finding highlighted and the
      full output moved to the appendix), never trim the actual exploit/privesc command's output.
- [ ] No screenshot is cropped in a way that cuts off the command, the output, or the terminal
      title/prompt showing user@host context.
- [ ] Screenshots are legible at the report's actual print/PDF size — zoom out and check, don't assume
      a screenshot that looked fine on your monitor survives being embedded at report scale.

**Replication-standard narrative** (per [PEN-200 Reporting Requirements](https://help.offsec.com/hc/en-us/articles/360046787731-PEN-200-Reporting-Requirements))
- [ ] For each target, a third party with no prior knowledge of the box could follow §6's steps in
      order and land the same shell/privesc — no skipped steps, no "and then I found the exploit"
      without showing how.
- [ ] Every non-obvious decision point is explained (why this port, why this parameter, why this
      technique over another) — not just the winning path, enough context that the *reasoning* is
      reproducible, not just the commands.
- [ ] Tool versions/exploit sources are cited where it matters for reproducibility (a specific PoC
      repo/commit, a specific exploit-DB ID) — matches the citation discipline used throughout this
      repo's other notes files.

**Document mechanics**
- [ ] Executive summary contains no command output, CVE IDs, or tool-name-driven prose — re-read it
      cold and confirm a non-technical reader would understand impact and risk.
- [ ] High-level findings/recommendations table (§1, row 4) lists every target and matches the severity
      ratings actually used in §6 — no drift between the summary table and the detailed section.
- [ ] Final document is exported to **PDF** and packaged in a **`.7z`** archive per the submission
      requirement — confirm this is the current required format against the live OffSec exam guide
      before exam day, since submission mechanics are the kind of detail OffSec updates independent of
      the scoring model.
- [ ] File naming follows whatever convention the current exam portal instructions specify (typically
      OSID-based) — check the portal instructions directly rather than assuming last year's convention
      still holds.
- [ ] Table of contents (if the template includes one) is regenerated/accurate after your final edits —
      page numbers drift after last-minute additions.
- [ ] A final top-to-bottom read-through for spelling/grammar and section-ordering consistency —
      sloppy presentation doesn't cost points directly, but it undermines confidence in a report whose
      whole job is to prove rigor.

---

## 5. Evidence Capture Strategy — Screenshots, Logs, and Recording

The most common question about exam documentation is some version of *"do I just hammer the
screenshot key all day?"* The answer is no, and the reason is worth understanding, because the
failure mode of over-screenshotting is as real as the failure mode of under-screenshotting.

### 5.1 Screenshots and text logs do different jobs

| | Screenshots | Text logs |
|---|---|---|
| **What they prove** | Identity — *this user, on this host, at this privilege level* | Reproduction — *these commands, this output, in this order* |
| **Good at** | Binding a claim to a machine; GUI state; the human grader's visual check | Full output, searchable, copy-pasteable into the report |
| **Bad at** | Long output (illegible at PDF scale), searching, copy-paste | Proving *which host* you were on, or that a shell was interactive |
| **Cost per capture** | Manual, interrupts flow | Zero — set up once, runs unattended |
| **Right volume** | ~6–12 per target, composed | Everything, always on |

The trap in "screenshot everything" is treating screenshots as the *primary* record. A screenshot of
200 lines of nmap output is worse than useless: unreadable when embedded, unsearchable at 3am, and it
displaced the text you actually needed to paste into §6. Meanwhile the shots that genuinely matter —
the composed proof frames — get lost in a folder of 400 unlabeled PNGs.

**So: log all text automatically, screenshot deliberately.**

### 5.2 The three approaches, and which fails

Candidates generally pick one of three postures. They are not equivalent.

**A. Screenshots as you go — ✅ yes, for proof moments.**
Composed shots at defined checkpoints: foothold, post-privesc, each proof file, plus anything
GUI-only. Roughly six to twelve per target. Each one framed to satisfy the five-element rule in
[`EXAM-TIPS.md`](../EXAM-TIPS.md) §3 in a single frame. This is the backbone of your evidence.

**B. Full recording — ✅ yes, as a safety net; ❌ no, as your evidence.**
Continuous terminal logging (§5.3) costs nothing and should always be running — it is what makes
"full, untruncated output" achievable without thinking about it. A **screen recording** is a
reasonable personal backstop on top of that, but understand its limits: you cannot embed video in a
PDF report, and scrubbing twenty hours of footage to find one frame at hour 23 is a worse position
than simply having taken the screenshot. Treat any recording as *disaster recovery for a capture you
missed*, never as the capture itself. Confirm current OffSec policy on local recording against the
live exam guide before relying on it.

**C. Go back for screenshots after completing the box — ❌ this is the one that fails people.**
It sounds efficient: root everything first, collect evidence at the end. It breaks for four reasons,
and they compound:

1. **The window closes and access is gone instantly.** Anything uncaptured at that moment is
   permanently uncapturable. There is no grace period.
2. **Re-establishing a shell costs time you won't have.** Going back means re-running the exploit
   chain at hour 20 while tired, on a box you've already stopped thinking about.
3. **Reverts destroy your foothold.** Reverting a stuck machine is normal during the exam. If you
   revert a box you rooted but didn't screenshot, that work is simply gone, and you may not
   reproduce it.
4. **Exploits are not always repeatable.** A service you crashed, a one-shot race, a password you
   changed, an account you locked out — plenty of footholds don't survive a second attempt.

The rule from §2.1 restated in operational terms: **capture proof at the moment you hold the shell,
not when you get around to it.** The thirty seconds it costs mid-exploit is the cheapest insurance
available.

### 5.3 What to screenshot — the checkpoint list

Take a composed screenshot at exactly these moments, and you will have covered every graded claim:

| # | Moment | Must show |
|---|---|---|
| 1 | Initial foothold | command, output, `whoami`/`id`, hostname, IP |
| 2 | `local.txt` read | interactive shell, original path, contents, IP |
| 3 | Privesc landed | elevated `whoami`, hostname, IP |
| 4 | `proof.txt` read | interactive shell, original path, contents, elevated user, IP |
| 5 | Any GUI-only step | Burp request/response, browser state, BloodHound path — no text equivalent exists |
| 6 | Anything surprising | the unusual thing you'll want to explain in prose later |

Everything else — enumeration output, failed attempts, the fifteen commands between foothold and
privesc — belongs in the **text log**, not in a screenshot.

**Bias slightly toward more rather than fewer**, but the extra shots should be *composed*, not
reflexive. A shot you can't identify later is not evidence.

### 5.4 Naming and filing, as you capture

Misfiled evidence is a top source of write-up-window panic. Impose structure at capture time:

```
~/exam/
├── 10.10.10.11/
│   ├── 01-foothold.png
│   ├── 02-localtxt.png
│   ├── 03-privesc.png
│   ├── 04-prooftxt.png
│   ├── session-1430.log
│   └── notes.md
├── 10.10.10.12/
└── ad/
    ├── bloodhound-path.png
    ├── da-proof.png
    └── credential-ledger.md
```

Numbered prefixes keep shots in chronological order in any file browser, and the number maps directly
onto the figure order in §6 of the report. One directory per target IP means you never have to
remember which host a capture came from.

---

## 6. Capture Tooling Setup

Set this up **before** exam day and rehearse it on a practice box. Fumbling with a screenshot tool
during the exam is exactly the kind of avoidable friction that costs a target.

### 6.1 Terminal logging (always on, zero effort)

```bash
# Simplest: script(1) with timing, one log per target session
mkdir -p ~/exam/10.10.10.11
script -f ~/exam/10.10.10.11/session-$(date +%H%M).log
# ...everything you type from here is logged, verbatim, including output...
exit                       # closes the log cleanly
```

`-f` flushes after every write, so the log survives a crash or a hard disconnect.

```bash
# tmux users: log a pane on demand, or bind it to a key
tmux pipe-pane -o "cat >> ~/exam/10.10.10.11/pane-$(date +%H%M).log"

# Persistent binding — prefix + H starts/stops logging the current pane
# (~/.tmux.conf)
bind H pipe-pane -o "cat >> ~/exam/pane-#S-#I-#P-$(date +%H%M).log" \; \
      display-message "logging toggled"
```

Strip ANSI colour codes before pasting log content into the report:

```bash
sed -r 's/\x1B\[[0-9;]*[mGKHJ]//g' session-1430.log > session-1430-clean.log
```

### 6.2 Screenshots

```bash
# Flameshot — interactive region select, then save. Best default on Kali.
flameshot gui -p ~/exam/10.10.10.11/

# scrot — whole screen, auto-named, no interaction
scrot ~/exam/10.10.10.11/'%H%M-%S.png'

# maim + slop — region select, no GUI dependency
maim -s ~/exam/10.10.10.11/01-foothold.png
```

Bind one of these to a key you can hit without thinking. The point is that taking a *composed* shot
should cost you two seconds, so you never skip one because it felt like an interruption.

### 6.3 Make every terminal self-documenting

The five-element rule is much easier to satisfy if the information is already on screen. Put the
context in your prompt and in a one-line banner you run on landing:

```bash
# On the target, immediately after landing a shell -- one frame, everything proven
echo "=== $(whoami) @ $(hostname) ===" ; id ; ip addr 2>/dev/null | grep 'inet '
```

```cmd
:: Windows equivalent
echo === %USERNAME% @ %COMPUTERNAME% === & whoami & ipconfig | findstr IPv4
```

Run that, then `cat` the proof file in the same terminal, and a single screenshot satisfies every
composition requirement at once. Consider aliasing it — the less it costs, the more consistently
you'll do it.

### 6.4 Rehearse the pipeline, not just the tools

On a practice box, do a full dry run: land a shell, run the banner, screenshot, read the proof file,
screenshot, close the log, and then **write that box up from your evidence alone** — no scrollback,
no memory. Whatever you find yourself missing is exactly what you'd have missed on exam day. This is
the single highest-value hour of report preparation available, and almost nobody does it.

---

## 7. The 24-Hour Write-Up Window

The window is generous *if* your live capture was disciplined and brutal if it wasn't. A workable
shape, assuming you finish the exam tired:

| Phase | Roughly | What |
|---|---|---|
| 1 | First hour | **Sleep-adjacent triage.** Before resting: copy all evidence off the VM, verify every proof screenshot exists and is legible, and confirm proof files were submitted through the control panel. This is the only irreversible-deadline work. |
| 2 | After rest | Assemble §6 per-target sections from your live notes. Mechanical if §1.2's skeleton was filled live. |
| 3 | Mid | Write the connective AD narrative, then the methodology section. |
| 4 | Late-mid | Executive summary and findings table — **last**, once you know the full shape of what you found. |
| 5 | Final 2h | QA checklist (§4), PDF export, archive, submit. Do not leave export to the final 20 minutes; PDF conversion surprises are common. |

Writing the executive summary first is a common mistake — you don't yet know what the report says.

---

## 8. What Actually Loses Points

Ranked by how often it bites, from community post-mortems and OffSec's stated requirements:

1. **Proof file read the wrong way.** Webshell, SMB pull, non-interactive read → zero for that target.
   The single most expensive documentation error, and entirely avoidable.
2. **Missing IP verification in the proof frame.** You owned the box; you just can't prove *which*
   box. Same category of loss, same trivial prevention.
3. **Truncated output on a load-bearing command.** "Output omitted for brevity" on the actual exploit
   or privesc command breaks the replication standard.
4. **Unreproducible narrative.** The commands are all there but the *reasoning* isn't — a reader can't
   tell why you tried that parameter, so they can't follow the path independently.
5. **Nothing recorded for boxes that didn't root.** Partial credit is real; a foothold you didn't
   screenshot is worth nothing.
6. **Severity/summary drift.** The findings table says High, §6 says Critical. Cheap to catch, reads
   as carelessness.
7. **Illegible screenshots.** Fine on a 1440p monitor, mush when embedded at report scale.
8. **Wrong submission format.** PDF-in-`.7z`, current naming convention — verify against the live
   exam guide, since OffSec updates submission mechanics independently of the scoring model.

Note that items 1, 2, 5, and 8 are *pure process* — they cost nothing technically and are entirely
preventable by the gate in [`templates/evidence-checklist.md`](../templates/evidence-checklist.md).

---

## 9. Drop-In Templates

Paste-ready scaffolding lives in [`templates/`](../templates/):

| Template | Use |
|---|---|
| [`target-note.md`](../templates/target-note.md) | Per-target live capture — mirrors §1.2's skeleton exactly |
| [`ad-set-note.md`](../templates/ad-set-note.md) | AD chain: credential ledger, host map, attack path |
| [`exam-report.md`](../templates/exam-report.md) | Full report skeleton with prose scaffolding |
| [`finding-blocks.md`](../templates/finding-blocks.md) | Pre-written description/impact/remediation for ~22 common OSCP findings |
| [`evidence-checklist.md`](../templates/evidence-checklist.md) | Per-target gate — run before leaving each box |

Start from OffSec's official `.docx`/`.odt` for the submitted document regardless; the templates
supply content, not the graded container.

---

## Sources

- [OSCP Exam Report Template (.docx)](https://www.offsec.com/pwk-online/OSCP-Exam-Report.docx) /
  [.odt](https://www.offsec.com/pwk-online/OSCP-Exam-Report.odt) — the official skeleton this file's
  §1 structure summarizes (`RESOURCES.md` §1).
- [PWK Example Report (PDF)](https://www.offsec.com/pwk-online/PWK-Example-Report-v1.pdf) — official
  worked example of expected format/depth.
- [PEN-200 Reporting Requirements](https://help.offsec.com/hc/en-us/articles/360046787731-PEN-200-Reporting-Requirements) —
  source of the replication standard cited in §4.
- [FIRST.org CVSS v3.1 Specification](https://www.first.org/cvss/v3-1/specification-document) —
  metric definitions underlying the severity table in §3.
- [`EXAM-TIPS.md`](../EXAM-TIPS.md) §3 — authoritative source for proof-file/screenshot rules,
  deliberately not re-derived here.
- [`RESOURCES.md`](../RESOURCES.md) §1 and §12 — official template/report-guidance links and
  note-taking/reporting tool links this file builds on.
