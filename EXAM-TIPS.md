# OSCP Exam-Day Logistics & Best Practices (2026)

*Research compiled August 2026. The official OffSec Exam Guide (help.offsec.com) returns HTTP 403 to automated fetchers (Cloudflare bot protection), so its content below is drawn from search-engine indexing of that page plus a maintained third-party mirror of the guide's text (verylazytech/OSCP-Resources on GitHub). Figures are cross-confirmed across multiple 2025/2026 sources.*

---

## 1. Proctoring Requirements

**Pre-exam verification (before the clock starts):**
- Proctor verifies your machine setup against OffSec's technical requirements.
- **ID verification**: show a **non-expired, government-issued photo ID** to the webcam so your name/photo are legible.
- You run a verification script (Windows or macOS variant) that the proctor supplies.
- **Room scan**: pan the webcam around your workspace and surroundings before connecting to the exam VPN.
- **Screen share**: you must share *all* monitors/screens and have all running programs visible before you begin.

**During the exam:**
- Webcam must stay on and visible (face, hands, workspace) for the full 23h45m window; you must **not** click "Stop sharing" on your screen share at any point.
- The proctor may periodically ask you to re-verify your internet connection, re-share your screen, or reposition/check your webcam.
- There is **no audio** feed — the proctor is a silent observer, not listening to you.
- A **"Pause Webcam"** control lets you request the proctor pause webcam viewing for a break (short or long); the VPN connection typically stays live so background processes can keep running.
- If you need to leave your room/change location, you must tell the proctor first — the exam VPN gets paused and a fresh room scan is done before it's reactivated.

**Tooling/conduct rules:**
- AI chatbots and LLM assistants (ChatGPT, Claude, Gemini, Copilot, DeepSeek, OffSec's own KAI, etc.) are **strictly prohibited** on OSCP — using one is treated as third-party assistance/exam-info sharing and can lead to a **permanent ban**, not just a fail. (OSEE/OSAI are the only OffSec exams that currently permit AI use.)
- Commercial/automated mass-exploitation tools and vulnerability scanners are restricted per the exam rules.
- Note-taking apps with background AI features (e.g., Notion) aren't required to be disabled, but you're responsible for knowing what any tool you use is doing under the hood.

---

## 2. Exam Structure & Time Budgeting (AD set vs. the 3 standalones)

- **Total time**: 23 hours 45 minutes practical exam, then **24 hours** afterward to submit the written report.
- **Passing score**: 70/100 points.
- **Scoring split**:
  - **3 standalone machines** — 20 points each (60 total): **10 for low-priv/initial access + 10 for privilege escalation to root/admin**, per machine.
  - **1 Active Directory set** (3 linked AD machines) — 40 points, broken out as 10 + 10 + 20 across the chain, but functionally **all-or-nothing**: you need the *full* domain compromise (initial foothold through Domain Admin) to bank those AD points — partial lateral movement inside the set without full domain compromise nets 0.

**Commonly recommended time allocation** (synthesized from multiple 2025/2026 candidate write-ups):
- Do **one standalone machine first** (budget ~2–4 hours) as a warm-up to get into a working rhythm — enumerate, exploit, escalate, document — before tackling the bigger prize.
- **Pivot to the AD set next** while fresh, since a well-prepared candidate can often clear the full AD chain efficiently, and it's worth nearly half the exam (40 pts) as a single well-understood attack path (rather than three separate unknown attack surfaces).
- Budget roughly **2–3 hours per remaining standalone** and treat AD as the highest-value target since AD methodology is more standardized than random independent-machine rabbit holes.
- Rationale repeated across sources: standalone machines are the least predictable part of the exam — a single missed foothold can cost a full 20 points and burn hours, whereas AD points are "worth more per hour invested" for candidates who drilled AD labs. Several posts explicitly recommend: get AD fully compromised early (closer to guaranteed points once you know the chain), then mop up standalones with remaining time, rather than grinding on a stubborn standalone box first and running out of runway for AD.
- A commonly cited passing benchmark: AD set (40) + 2 standalone full compromises (40) = 80, well above the 70 threshold — many strategies aim to "lock in" AD + 2 boxes rather than needing all three standalones.

---

## 3. Note-Taking / Screenshot Requirements for the Report

These are treated by virtually every source as **make-or-break** — more candidates reportedly fail from documentation gaps than from technical shortfalls.

**Mandatory proof-file rule:**
- Each target has a `proof.txt`/`local.txt` file you must retrieve **and submit through the exam control panel**, plus **screenshot** its contents.
- The proof file must be read via an **interactive shell on the target itself** using `type`/`cat` from its original file path. Reading it any other way (e.g., through a webshell, or copying it out via SMB without an interactive read) results in **zero points for that entire target**, even if you legitimately owned the box.
- Screenshots must also show **IP address verification** for the compromised host — e.g., `ip addr` / `ifconfig` / `ipconfig` output in the same or an adjacent shot — to prove which machine the proof came from.
- Best practice repeated across guides: every proof/privesc screenshot should show, in one frame, the **command run, its output, current user context (`whoami`/`id`), hostname, and target IP** — enough to remove any ambiguity about which box and which privilege level.

**General screenshot/note discipline recommended:**
- Screenshot **every meaningful command and its output** as you go — including failed attempts, since they demonstrate methodology and can matter for partial credit on standalone machines.
- Don't rely on shell history alone to reconstruct the report afterward — you lose all access to the exam machines the moment the exam window ends, so anything not captured live is gone.
- Keep terminals/scrollback and browser tabs **open until the report is fully submitted** — several write-ups explicitly warn: "leave everything open... you won't have machine access anymore, but your on-screen history is still there" as a fallback for filling gaps during the 24-hour writing window.
- Report must document, per target, "all steps, commands issued, and console output" in enough detail that a third party could reproduce the compromise (this replication standard is the official bar per OffSec's PEN-200 reporting requirements).

---

## 4. Break Advice

- Food, coffee, and even sleep breaks are explicitly permitted — use the "Pause Webcam" feature rather than disconnecting, and OffSec recommends keeping the proctoring session/VPN active through breaks so any long-running jobs (password cracking, scans) keep working.
- Candidate consensus: **take a real break after your warm-up standalone box**, before diving into AD, to reset focus rather than pushing straight through fatigued.
- Multiple pass write-ups mention deliberately sleeping **4–6 hours** partway through (commonly after most/all boxes are rooted, before the final documentation push) because fatigue-driven mistakes late in a 24-hour window are a recurring failure mode; one account describes sleeping ~5 hours after ~12 hours of active work once boxes were rooted, specifically to protect report-writing quality afterward.
- Because you must notify the proctor and get a room re-scan for any location change, candidates recommend **planning breaks rather than making sudden decisions to step away**, to avoid losing exam time to the pause/resume handshake.

---

## 5. Partial Credit for an Un-rooted Machine

- **Standalone machines**: partial credit is real and explicit — 10 of the 20 points on each standalone are earned just for **low-privileged/initial access**, independent of whether you ever escalate to root/admin. A machine you never fully root can still legitimately bank half its points, **provided you document the initial-access proof correctly** (the same proof-file screenshot rules above apply to whatever level you actually achieved).
- **AD set**: no such partial credit — the 40 AD points are tied to full domain compromise; compromising some but not all machines in the chain, or gaining access short of Domain Admin, is reported as **worth zero points** toward that 40.
- Practical implication candidates draw from this: it's rational to grab and *document* a low-priv shell on a standalone the moment you get it (rather than only screenshotting after full root), since that alone secures 10 guaranteed points if privesc doesn't pan out — but there's no equivalent "partial save" in the AD portion, so AD effort only pays off once the full chain is complete.

---

## Do This / Avoid This

**Do this**
- Show a valid, non-expired government photo ID and complete the room/screen scan calmly before the clock starts — rushing this wastes exam minutes.
- Warm up on one standalone machine, then pivot into the AD set while fresh; treat AD as your highest points-per-hour target once you're in rhythm.
- Screenshot **every** command + output as you go, including failed attempts — never plan to "reconstruct it later" from memory or shell history.
- Always read proof.txt/local.txt via an **interactive shell on the target itself** and pair the screenshot with IP-address verification output.
- Grab and document low-priv access on a standalone immediately — it locks in 10 points even if privesc later stalls.
- Use the proctor's "Pause Webcam" feature for planned breaks (food/sleep) instead of disconnecting, and keep the VPN/proctoring session alive through them.
- Plan a real sleep break once most boxes are down, to protect judgment during exploitation and clarity during report writing.
- Leave all terminals/browser tabs open until the report is fully submitted — gaps in captured evidence can sometimes be filled from on-screen scrollback during the 24-hour write-up window.
- Keep AI chatbots, KAI, ChatGPT, Claude, Gemini, Copilot, etc. completely away from the exam machine/session — treat this as a bright line, not a gray area.

**Avoid this**
- Don't sink hours into a stubborn standalone machine's privilege escalation before touching the AD set — a blown standalone box costs at most 20 points, but running out of time for AD costs 40.
- Don't ever pull proof-file contents through a webshell, file share, or any non-interactive-shell method — it zeroes that entire target regardless of how thorough your compromise was.
- Don't click "Stop sharing" or let your webcam go dark without first notifying the proctor — unexplained camera/screen drops are the kind of anomaly that gets flagged for review.
- Don't wait until "after I root it" to screenshot — capture proof of each privilege level (low-priv and root) the moment you have it.
- Don't assume partial credit exists in the AD set the way it does for standalones — partial AD compromise without reaching full domain compromise nets zero of the 40 points.
- Don't paste exam content, error messages, or code into any AI assistant "just to ask a general question" — OffSec treats this as equivalent to third-party collusion and it can result in a permanent ban rather than a simple exam fail.
- Don't change rooms/leave your setup without telling the proctor first — you'll burn time on VPN pause/room-rescan overhead you didn't plan for.

---

## Sources

**Official OffSec (help.offsec.com) — content retrieved via search-index caching / third-party mirror, since direct automated fetch returns HTTP 403:**
- [OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) — official source for exam duration, scoring breakdown, proof-file/report rules, partial-credit language.
- [Proctored Exam Requirements FAQ](https://help.offsec.com/hc/en-us/articles/15295546432148-Proctored-Exam-Requirements-FAQ) — ID verification, webcam/screen-share requirements.
- [General Proctoring FAQ](https://help.offsec.com/hc/en-us/articles/15299882976660-General-Proctoring-FAQ) — room scan, pre-exam verification flow.
- [Proctoring Tool Manual](https://help.offsec.com/hc/en-us/articles/360050299352-Proctoring-Tool-Manual) — pause-webcam mechanics, location-change process.
- [AI Usage Policy in OffSec Exams](https://help.offsec.com/hc/en-us/articles/35549468971156-AI-Usage-Policy-in-OffSec-Exams) — AI/LLM prohibition and ban consequences.
- [OSCP Exam Changes](https://help.offsec.com/hc/en-us/articles/29865898402836-OSCP-Exam-Changes) / [OSCP+ Exam FAQ](https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ) — current format context.
- [PEN-200 Reporting Requirements](https://help.offsec.com/hc/en-us/articles/360046787731-PEN-200-Reporting-Requirements) — report replication standard.

**Verified mirror of the official guide text:**
- [verylazytech/OSCP-Resources — OSCP-Exam-Guide.md](https://github.com/verylazytech/OSCP-Resources/blob/main/Syllabus/OSCP-Exam-Guide.md) (GitHub) — directly quotes the official guide's point breakdown (20/20/20 standalone, 10/10/20 AD), 70-point pass bar, and the proof-file zero-point rule.

**2025/2026 candidate write-ups and community summaries:**
- [Jess L., "Passing OSCP+ at 3rd attempt — journey and tips sharing 2026" (Medium)](https://medium.com/@onyuyu.loke/passing-oscp-at-3rd-attempts-journey-and-tips-sharing-2026-afe6d669b221)
- ["OSCP+ Exam 2026: Strategy, Reporting, Tips, and Lessons" (Medium)](https://medium.com/@contact.aryan.here/oscp-exam-2026-strategy-reporting-tips-and-lessons-484363f29f6c) — AD-first time-budgeting strategy, screenshot/timestamp discipline.
- [Matt Glass, "Challenge Complete: My Experience Passing the OSCP"](https://mattglass-it.com/passing-the-oscp/) — break/sleep strategy, warm-up-machine-first approach.
- ["My OSCP Experience — Tips and suggestions" (Equilibrium Security, Substack)](https://equilibriumsecurity.substack.com/p/my-oscp-experience-tips-and-suggestions) — proctoring experience and documentation habits.
- [Kioptrix, "OSCP Proof Screenshot: 7 Proven, Stress-Free Rules"](https://kioptrix.com/oscp-proof-screenshot/) — screenshot composition rules (command, output, whoami/hostname, IP).
- [FrostGuard Cybersecurity, "The 3 Ways to Fail at Your OSCP/OSCP+ Exam Report"](https://www.frostguardsec.com/blog/the-3-ways-to-fail-at-your-oscp-oscp-exam-report/) — documentation-driven failure modes.
- [AceFortis, "OSCP Certification: How to Pass Exam in 2026"](https://acefortis.com/2026/02/26/oscp-certification-guide-how-to-pass-2026/)
- [netguardia.com, "OSCP in 2026: Is It Still the Gold Standard, and Is the New Format Harder?"](https://netguardia.com/learning-development/certifications/oscp-in-2026-is-it-still-the-gold-standard-and-is-the-new-format-harder/)
- [IT Pro, "Offensive Security bans use of ChatGPT in cyber security certification exams"](https://www.itpro.com/technology/artificial-intelligence-ai/369785/offensive-security-bans-chatgpt-from-cyber-certification-exams)

*Note: Several of these blog URLs also returned 403 to direct automated fetch (Cloudflare/bot protection is common on WordPress/Medium/Substack); their content above reflects search-engine-indexed excerpts of those pages rather than a full manual read-through. Where possible, claims are cross-confirmed across 2+ independent sources before being stated as consensus advice.*
