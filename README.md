# OSCP / PEN-200 Methodology

A working methodology, command reference, and helper-script toolkit for the **OSCP (PEN-200) exam**,
written for the **post–November 2024 "OSCP+" format** (assumed-breach AD set, partial credit per
stage, bonus points removed). It's organised so the exam becomes *execution*, not research — you keep
the relevant note open and work down it.

> **Authorized use only.** Everything here is for the OSCP exam, OffSec labs, HTB/PG practice, and
> **authorized** penetration testing. Every technique that is restricted or banned on the exam is
> flagged at the point it appears — read [`EXAM-TIPS.md`](EXAM-TIPS.md) before exam day so you don't
> lose points (or get flagged) to a prohibited tool.

## Start here

| If you want… | Open |
|---|---|
| The exam-day rules, scoring, time budget, proctoring | [`EXAM-TIPS.md`](EXAM-TIPS.md) |
| A fast command lookup across every phase | [`CHEATSHEET.md`](CHEATSHEET.md) |
| **The standalone boxes** — what to do, in order, and why | [`notes/standalone-box-methodology.md`](notes/standalone-box-methodology.md) |
| **The AD set** — what to do, in order, and why | [`notes/ad-methodology-end-to-end.md`](notes/ad-methodology-end-to-end.md) |
| **The AD set** — every assumed-breach method as one-liners | [`notes/ad-assumed-breach-catalog.md`](notes/ad-assumed-breach-catalog.md) |
| One command per repeatable workflow (recon, AD enum, pivot…) | [`scripts/README.md`](scripts/README.md) |
| Drop-in report + live-note templates | [`templates/README.md`](templates/README.md) |
| Tools, platforms, wordlists, further reading | [`RESOURCES.md`](RESOURCES.md) |
| A curated OSCP-like practice box list | [`MACHINES.md`](MACHINES.md) |

## What's in here

```
.
├── CHEATSHEET.md      Fast command lookup, all phases (incl. hashcat modes, wordlist paths)
├── EXAM-TIPS.md       Exam rules, scoring, restricted tools, time strategy, proof requirements
├── RESOURCES.md       Tools, practice platforms, references, internal cross-reference index
├── MACHINES.md        Curated OSCP-like HTB/PG boxes matched to writeups
├── notes/   (27 files) The methodology: recon → web → privesc → AD → pivoting → reporting
├── scripts/  (7 + lib) Bash helpers that enumerate/harvest and stop before the exploit decision
└── templates/ (6 files) Paste-ready OSCP report skeleton, finding blocks, live-capture notes
```

The `notes/` files are the depth; the two AD files, `CHEATSHEET.md`, and `scripts/` are what you
actually keep open during the exam. `RESOURCES.md` §15 is a full internal cross-reference index if you
prefer to navigate from there.

## The helper scripts in 10 seconds

```bash
./scripts/fast-nmap.sh <target>                       # full nmap sequence, one command
./scripts/web-recon.sh <target> [--domain x.com]      # whatweb/ffuf/ferox, http+https
./scripts/ad-enum.sh <dc_ip> <domain> [-u u -p p]     # AD sweep → hashcat-ready files + users.txt
./scripts/crack.sh <hash-file-or-dir> [wordlist] --rules
./scripts/ligolo-setup.sh --route <subnet>/24 --serve # one command to a fully-routed pivot
```

They take targets as **arguments** (no IPs to edit), are safe to re-run, and are **enumeration/
harvesting only** — none fires an exploit or logs into a found credential on its own. See the
["are these exam-legal?" note](scripts/README.md) for exactly where the exam's automation line sits.

## Scope discipline (why this repo won't lose you points)

The OSCP exam prohibits **spoofing** (Responder/mitm6/arp-poisoning), **automatic exploitation**
(db_autopwn, SQLmap), and **mass vulnerability scanners** (Nessus/OpenVAS), and caps **Metasploit +
Meterpreter to a single machine** (never the AD set). Those tools still appear here because they're
valuable in labs and real engagements — but every one is flagged **exam-banned / one-machine-only at
the point it appears**, so a reference can't be mistaken for an exam-day instruction. The distinctions
that trip people up (coercion is legal, poisoning is not; `nmap --script vuln`/Nikto are fine, mass
scanners are not) are called out where they matter.

---

*For authorized OSCP exam preparation and penetration testing only.*
