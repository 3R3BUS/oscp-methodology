# Report Structure & Writing Methodology

*Scope note: this file covers how to structure, write, and QA the actual submitted report — not
proctoring rules or live screenshot discipline, which are already covered in detail in
[`EXAM-TIPS.md`](../EXAM-TIPS.md) §3 and cross-referenced throughout rather than repeated here. For
authorized OSCP exam/lab use only; contains no exam-specific target information.*

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
