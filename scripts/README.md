# OSCP Helper Scripts

Thin bash wrappers around the command sequences already documented (and independently
verified) across this repo's `notes/*.md` files and `CHEATSHEET.md`. Every script
**enumerates and harvests, it does not exploit** — nothing here cracks a hash automatically,
logs into a found credential without you asking it to, or fires an exploit. That framing
matches this repo's established scope discipline (see `EXAM-TIPS.md`): Kerberoasting,
AS-REP roasting, RID-brute, BloodHound collection, ADCS `find`, and Nikto/nmap-NSE-style
scanning are all standard, exam-safe OSCP techniques — these scripts just save you from
retyping fifteen commands by hand.

**Before running any of these against the real OSCP exam network**, re-read `EXAM-TIPS.md`.
The one genuinely gray area in this set is `web-recon.sh --nuclei-full` (full-template-set
Nuclei scanning) — see that script's own warning banner. Everything else here (nmap incl.
`--script vuln`, ffuf, feroxbuster, whatweb, enum4linux-ng, netexec, BloodHound, Certipy,
Timeroast, hashcat) is unambiguously fine as a primary technique per the official exam guide.

## Scripts

| Script | Purpose | Usage |
|---|---|---|
| `fast-nmap.sh` | Full recon sequence: fast TCP sweep → targeted `-sC`/`-sV` rescan → parallel UDP top-100 → `--script vuln` | `./fast-nmap.sh <target>` |
| `web-recon.sh` | whatweb fingerprint, TLS cert SAN grab, robots.txt/sitemap, ffuf vhost fuzzing, feroxbuster dirs/files, scoped nuclei | `./web-recon.sh <target> [--domain example.com] [--nuclei-full]` |
| `ad-enum.sh` | Post-foothold AD sweep: enum4linux-ng, Timeroast, AS-REP/Kerberoast, RID-brute, GPP/LAPS, delegation, ADCS triage, BloodHound collection — parses out `users.txt` and echoes the right `hashcat -m` mode per hash file found | `./ad-enum.sh <dc_ip> <domain> [-u user -p pass]` |
| `ligolo-setup.sh` | Attacker-side ligolo-ng TUN + proxy setup, prints the exact agent-side connect-back command to paste onto the pivot host | `./ligolo-setup.sh` (or `--teardown`) |
| `hashid-credcheck.sh` | `hash` subcommand identifies a hash format and echoes the hashcat mode; `cred` subcommand sweeps a found credential across smb/winrm/rdp/mssql/ssh/ftp | `./hashid-credcheck.sh hash <string-or-file>` / `./hashid-credcheck.sh cred <target> <user> <pass_or_hash>` |
| `privesc-launcher.sh` | Stages linPEAS or winPEAS (+ prints PrivescCheck one-liner) and the transfer options to get it onto target | `./privesc-launcher.sh <linux\|windows>` |
| `crack.sh` | hashcat wrapper — auto-detects mode via the shared lib, defaults to rockyou.txt (+ OneRuleToRuleThemAll with `--rules`), can crack an entire `ad-enum.sh` output directory in one pass | `./crack.sh <hash-file-or-dir> [wordlist] [--rules]` |

`lib/hashmodes.sh` is a shared library (not a standalone script) sourced by `hashid-credcheck.sh`
and `crack.sh` — the hash-format-detection logic lives in exactly one place. Its mode numbers
mirror `CHEATSHEET.md` §4; if you fix a mode number there, update `lib/hashmodes.sh` too rather
than letting the two drift.

## Dependencies

`nmap`, `ffuf`, `feroxbuster`, `whatweb`, `nuclei`, `curl`, `openssl` (all Kali defaults or one
`apt`/`go install` away), `enum4linux-ng`, `netexec`/`nxc`, `bloodhound-python`, `certipy-ad`,
`hashcat`, and [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)'s `timeroast.py`
(standalone script, no install — just clone/download it into your working directory or PATH).
Every script checks for its own dependencies up front and prints an install hint rather than
failing on a bare "command not found."

## Output convention

Each script writes into `./<scriptname>-out/<target>/`, preserving full raw tool output (matching
`notes/reporting-methodology.md`'s "capture full output live" rule) while printing a condensed
summary to the terminal. Nothing is silently discarded — quiet just means the terminal isn't
spammed, not that evidence isn't kept for your report.

## Suggested flow

1. `fast-nmap.sh <target>` — see what's open.
2. `web-recon.sh <target>` if 80/443 is open.
3. Land a foothold via whatever the recon above turned up (manual — not scripted here, this repo's
   `notes/*.md` files are the reference for that).
4. `privesc-launcher.sh <linux|windows>` once you have a shell, to stage local enumeration.
5. `ad-enum.sh <dc_ip> <domain>` as soon as network access to a DC exists (works even before you
   have creds — add `-u`/`-p` once you get a foothold credential to unlock the authenticated stages).
6. `crack.sh ad-enum-out/<dc_ip> --rules` to work through whatever hashes it harvested.
7. `hashid-credcheck.sh cred <range> <user> <cracked_pass_or_hash>` to see where else a cracked
   credential works.
8. `ligolo-setup.sh` once you need to reach a second network segment.
