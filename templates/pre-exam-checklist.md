# Pre-Exam Pre-Flight Checklist

Run this the **day before** (and the setup half again ~30 min before start). The goal: never lose exam
time to a tool that won't launch, a VPN that won't connect, or a screenshot tool you hadn't tested.
Tick every box before you start the clock. See [`../EXAM-TIPS.md`](../EXAM-TIPS.md) for the rules this
assumes and [`ad-assumed-breach-catalog.md`](../notes/ad-assumed-breach-catalog.md) §0.1 for the
AD-specific tooling list.

## Logistics (day before)

- [ ] Exam date/time confirmed; know your start time in **your** timezone
- [ ] Government photo ID ready for proctor check-in
- [ ] Proctoring software installed and **tested** (webcam, mic, screen-share all work)
- [ ] Primary internet stable; **backup** internet ready (phone hotspot) and tested
- [ ] Quiet, well-lit room; desk clear per proctoring rules; phone/second screen handling understood
- [ ] Sleep plan — a rested brain beats one more hour of cramming

## Kali / environment

- [ ] Kali updated (`apt update && apt full-upgrade`) **and a clean snapshot taken** (so you can roll
      back if you break the VM mid-exam)
- [ ] Exam VPN pack downloaded; `openvpn <pack>` **connects** and you can ping the gateway
- [ ] DNS resolution works through the VPN; no proxy/firewall surprises
- [ ] `/etc/hosts` ready to edit; you know how to add `IP hostname` entries fast

## Tooling smoke-test (launch each once — don't discover a breakage mid-box)

- [ ] `nmap` (+ run as the user you'll use; `sudo` works for SYN/`-sU`)
- [ ] `feroxbuster` / `ffuf` / `gobuster`, `whatweb`, SecLists present (`/usr/share/seclists`)
- [ ] `nxc` (NetExec), Impacket (`impacket-GetUserSPNs` etc.), `certipy`, `evil-winrm`
- [ ] **BloodHound CE + neo4j start cleanly and ingest a test zip** (the classic exam-day time sink —
      know the restart dance, and the fallback if it won't cooperate)
- [ ] `hashcat` runs, `rockyou.txt` is **gunzipped**, `OneRuleToRuleThemAll.rule` present
- [ ] `searchsploit` updated (`searchsploit -u`)
- [ ] Pivoting: `ligolo-ng` `proxy` + both `agent` (Linux) and `agent.exe` (Windows) downloaded;
      `chisel` as a backup — test [`../scripts/ligolo-setup.sh`](../scripts/README.md) once
- [ ] linPEAS / winPEASx64 / PrivescCheck.ps1 downloaded locally (so staging is instant)
- [ ] The repo's helper scripts run (`./scripts/fast-nmap.sh -h`, etc.)

## Note-taking & evidence (the part people underweight)

- [ ] Note tool chosen and open (CherryTree / Obsidian / Notion / plain Markdown)
- [ ] [`target-note.md`](target-note.md) and [`ad-set-note.md`](ad-set-note.md) copied, ready to clone
      per target
- [ ] Screenshot tool tested (Flameshot/`gnome-screenshot`) — you can capture + annotate in seconds
- [ ] **Always-on terminal logging ready**: `script`/`tmux` setup from
      [`../notes/reporting-methodology.md`](../notes/reporting-methodology.md) §6
- [ ] Exam folder structure created (e.g. `~/exam/{standalone1,standalone2,standalone3,ad}/`)
- [ ] Official **OSCP Exam Report template** (.docx) downloaded, plus
      [`exam-report.md`](exam-report.md) / [`finding-blocks.md`](finding-blocks.md) open for assembly

## Reference material offline

- [ ] This repo cloned locally (you can't rely on fetching it mid-exam);
      [`../CHEATSHEET.md`](../CHEATSHEET.md), the two methodology docs, and the AD catalog open in tabs
- [ ] Know the restricted-tool rules cold (no spoofing, no auto-exploit, one Metasploit machine) —
      [`../EXAM-TIPS.md`](../EXAM-TIPS.md)

## First five minutes of the exam (do these before any scanning)

- [ ] Start terminal logging (`script -f ~/exam/session-$(date +%H%M).log`)
- [ ] Note your exam start/end times and the report-submission deadline
- [ ] Read the control-panel instructions and **confirm which machine(s) are the AD set**
- [ ] Take a breath — one standalone first as a warm-up, bank each proof the moment you earn it
