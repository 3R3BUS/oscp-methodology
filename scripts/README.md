# OSCP Helper Scripts

Thin bash wrappers around the command sequences already documented (and independently
verified) across this repo's `notes/*.md` files and `CHEATSHEET.md`. These scripts
**enumerate, harvest, and crack offline** — none of them fires an exploit, and none logs into a
discovered credential unless you explicitly ask it to via `hashid-credcheck.sh cred`. That framing
matches this repo's established scope discipline (see `EXAM-TIPS.md`): Kerberoasting,
AS-REP roasting, RID-brute, BloodHound collection, ADCS `find`, and Nikto/nmap-NSE-style
scanning are all standard, exam-safe OSCP techniques — these scripts just save you from
retyping fifteen commands by hand.

**Before running any of these against the real OSCP exam network**, re-read `EXAM-TIPS.md`.
Everything in this set (nmap incl. `--script vuln`, ffuf, feroxbuster, whatweb, Nikto,
enum4linux-ng, netexec, BloodHound, Certipy, Timeroast, hashcat) is a standard, exam-safe
OSCP technique per the official exam guide. **Nuclei is deliberately absent** — it is an
automated vulnerability scanner, the category OffSec explicitly bans ("mass vulnerability
scanners e.g. Nessus, OpenVAS"), so no script here invokes it (see `web-recon.sh`'s header).

### "Automated exploitation is banned — do these scripts cross that line?" No.

OffSec bans automatic **exploitation** — a tool that finds a vulnerability *and fires the exploit /
drops a shell with no human decision in between* (`db_autopwn`, `browser_autopwn`, SQLmap
`--os-shell`). Enumeration automation is explicitly fine — that's why AutoRecon/nmapAutomator are
community-accepted. **The manual requirement attaches to the exploitation step, not to recon.** You
do not have to run nmap by hand; you *do* have to be the one who decides what to exploit and runs it
yourself, understanding each step.

Every script here is on the enumeration side of that line by design — each **harvests or scans and
then stops before the exploitation decision**:

- `fast-nmap.sh` / `web-recon.sh` — recon and vuln *detection* (`--script vuln` and Nikto are
  allowed; the banned "mass vuln scanners" are Nessus/OpenVAS **and nuclei**, so no script here
  runs nuclei at all). They find; they never exploit.
- `ad-enum.sh` — the one that matters most: it **collects** Kerberoast/AS-REP hashes, BloodHound data,
  and `certipy find` output, then hands *you* the decision to crack and the decision to run an ESC
  exploit. It never cracks, never authenticates with a found credential, never fires an ESC chain.
- `crack.sh` — hashcat on hashes you already have, offline, local data; never touches a target.
- `hashid-credcheck.sh` — hash-type ID (offline), or a reuse sweep with a credential *you* supply
  (using a known credential is normal OSCP work, not auto-exploitation).
- `privesc-launcher.sh` — stages an enumerator (linPEAS/winPEAS); doesn't remote-execute or escalate.
- `ligolo-setup.sh` — pivoting/tunnelling; not exploitation at all.

The OffSec test is *"the candidate is responsible for knowing what any chosen tool does internally."*
None of these need to be made "more manual" — they automate the part you're allowed to automate. The
one carve-out in the other direction: you *may* use fully automated exploitation (Metasploit modules +
Meterpreter) against **one** standalone machine of your choice — never the AD set.

## Scripts

| Script | Purpose | Usage |
|---|---|---|
| `fast-nmap.sh` | Full recon sequence: fast TCP sweep → targeted `-sC`/`-sV` rescan → parallel UDP top-100 → targeted UDP rescan → `--script vuln` | `./fast-nmap.sh <target>` |
| `web-recon.sh` | whatweb fingerprint, TLS cert SAN grab, robots.txt/sitemap, ffuf vhost fuzzing, feroxbuster dirs/files — probes `http://` and `https://` up front and runs every stage against whichever responds, so an HTTPS-only box is scanned fully | `./web-recon.sh <target> [--domain example.com]` |
| `ad-enum.sh` | Post-foothold AD sweep: enum4linux-ng, Timeroast, AS-REP/Kerberoast, RID-brute, GPP/LAPS, delegation, ADCS triage, BloodHound collection — parses out `users.txt` and echoes the right `hashcat -m` mode per hash file found | `./ad-enum.sh <dc_ip> <domain> [-u user -p pass]` |
| `ligolo-setup.sh` | Attacker-side ligolo-ng TUN + proxy setup in one command: auto-detects your VPN IP, pre-stages kernel routes (`--route`), optionally serves the agent binary over the VPN so transfer is one line (`--serve`), prints the exact agent connect-back + in-console steps | `./ligolo-setup.sh [--route CIDR]... [--port N] [--serve]` (or `--teardown`) |
| `hashid-credcheck.sh` | `hash` subcommand identifies a hash format and echoes the hashcat mode; `cred` subcommand sweeps a found credential across smb/winrm/rdp/mssql/ssh/ftp | `./hashid-credcheck.sh hash <string-or-file>` / `./hashid-credcheck.sh cred <target> <user> <pass_or_hash>` |
| `privesc-launcher.sh` | Stages linPEAS or winPEAS (+ prints PrivescCheck one-liner) and the transfer options to get it onto target | `./privesc-launcher.sh <linux\|windows>` |
| `crack.sh` | hashcat wrapper — auto-detects mode via the shared lib, defaults to rockyou.txt (+ OneRuleToRuleThemAll with `--rules`), can crack an entire `ad-enum.sh` output directory in one pass | `./crack.sh <hash-file-or-dir> [wordlist] [--rules]` |
| `exam-box-setup.sh` | One-shot VM provisioner — `apt` full-upgrade, installs the whole toolset (latest stable from Kali repos), Timeroast, SecLists + rockyou, sets terminator default, configures zsh (100k shared history + autosuggestions + syntax highlighting), creates the `targets` helper, enables terminal logging, symlinks these scripts onto PATH, prints a verification table. Idempotent — re-run to rebuild a dead VM. | `./exam-box-setup.sh [--dry-run] [--no-banned]` |

After running `exam-box-setup.sh`, set your box IPs once and reuse them everywhere (zsh
autosuggestions then complete them as you type): `targets set BOX1 10.10.10.5`,
`targets set dc 10.10.10.10`, `targets set DOMAIN corp.local`, then `targets hosts` to write the
AD names into `/etc/hosts`. The values come back as `$BOX1`, `$DC`, `$DOMAIN`, etc. in every new
shell — e.g. `fast-nmap.sh $BOX1`.

The setup also seeds your zsh history with ready-to-run, var-filled invocations of every helper
(`fast-nmap.sh $BOX1`, `ad-enum.sh $DC $DOMAIN -u <user> -p <pass>`, …). So you type fast,
autosuggestions complete the whole line, and you just flip the `1` to a `2` for the next box — no
flags to recall. Nothing has a hardcoded IP; the `$BOX*` vars resolve to whatever `targets set`.

`lib/hashmodes.sh` is a shared library (not a standalone script) sourced by **three** callers —
`hashid-credcheck.sh`, `crack.sh`, and `ad-enum.sh` (for its end-of-run "here's how to crack what I
found" summary) — so the hash-format-detection logic lives in exactly one place. Its mode numbers
mirror `CHEATSHEET.md` §4; if you fix a mode number there, update `lib/hashmodes.sh` too rather
than letting the two drift.

Two implementation notes for anyone editing it:

- `detect_hash_mode` both prints `<mode>|<label>` **and** sets `HASH_MODE`/`HASH_LABEL`/`HASH_IS_PWDUMP`.
  Callers that need `HASH_IS_PWDUMP` must call it directly and read the globals — capturing the printed
  value with `"$(detect_hash_mode ...)"` runs it in a subshell where those globals are discarded.
- Formats whose on-disk layout requires extra hashcat flags (currently Timeroast's mode 31300, which
  needs `--username`) get them from `hashcat_extra_flags`, so every emitted command and every actual
  invocation stay in step. Don't hardcode the flag at a call site.

## Dependencies

`nmap`, `ffuf`, `feroxbuster`, `whatweb`, `curl`, `openssl`, `jq`, `python3` (all Kali
defaults or one `apt`/`go install` away), `enum4linux-ng`, `netexec`/`nxc`, `bloodhound-python`,
`certipy-ad`, `hashcat`, [ligolo-ng](https://github.com/nicocha30/ligolo-ng) `proxy`/`agent`
binaries (download from releases), and [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)'s
`timeroast.py` (standalone script, no install — just clone/download it into your working directory
or PATH; see [`notes/ad-methodology-end-to-end.md`](../notes/ad-methodology-end-to-end.md) §2 for what
Timeroasting actually gets you and when it's worth the ten seconds). Every script checks for its own
dependencies up front and prints an install hint rather than failing on a bare "command not found."

## Output convention

The scanning scripts (`fast-nmap.sh`, `web-recon.sh`, `ad-enum.sh`) write into
`./<scriptname>-out/<target>/`; `privesc-launcher.sh` stages into `./privesc-launcher-out/` (no
per-target subdirectory, since it isn't target-specific). `crack.sh` and `hashid-credcheck.sh` work
against files you already have and create no output tree of their own — except that `crack.sh` writes
a `-nt.hash` sidecar next to any pwdump-format input it has to split. Output preserves full raw tool
output (matching
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
8. `ligolo-setup.sh --route <internal_subnet>/24 --serve` once you need to reach a second network
   segment — pass the subnet you found on the first box and it's routed the moment you `start` in the
   console; `--serve` hosts the agent so getting it onto the pivot is a single `wget`/`certutil` line.
