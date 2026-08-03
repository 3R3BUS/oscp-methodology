# Per-Target Evidence Gate

**Run this before you move on from any box.** Not at the end of the exam — the whole point is to
catch a missing capture while you still have the shell. Ninety seconds per target.

Print it, or keep it open in a pane. The question this answers is: *if I lost access to this host
right now, could I still submit it for full points?*

---

## Hard gates — a "no" here costs the entire target

- [ ] `proof.txt` / `local.txt` was read via an **interactive shell on the target itself**, using
      `cat`/`type` against its **original path**.
      *Not* through a webshell. *Not* via SMB copy. *Not* by any indirect read.
      → A "no" is **zero points for this target**, regardless of how legitimately you owned it.
- [ ] The proof file was **submitted through the exam control panel** — this is separate from, and
      additional to, the screenshot.
- [ ] The proof screenshot shows the target's **IP address** in the same frame (`ip addr` / `ifconfig`
      / `ipconfig`), proving which host the proof came from.

## Screenshot composition — each proof shot, one frame

- [ ] Command run
- [ ] Its output
- [ ] Current user context (`whoami` / `id`)
- [ ] Hostname
- [ ] Target IP

If all five aren't in one frame, take it again **now**, while you still have the shell.

## Coverage

- [ ] **Foothold** screenshot exists (initial access, pre-escalation)
- [ ] **Post-privesc** screenshot exists (elevated `whoami`)
- [ ] **local.txt** screenshot exists
- [ ] **proof.txt** screenshot exists
- [ ] GUI-only evidence captured where relevant (Burp request/response, browser state, BloodHound
      path) — these have no text-log equivalent, so if you didn't screenshot it, it doesn't exist

## Text log

- [ ] Terminal logging was **running** for this target's session (`~/exam/<IP>/session-*.log` is
      non-empty and recent)
- [ ] The exploit command and its **full** output are in the log
- [ ] The privesc command and its **full** output are in the log
- [ ] Any credential/hash obtained is written into the credential ledger with its source host

## Notes

- [ ] `target-note.md` for this host has its Synopsis, Vulnerability Identification, and Exploitation
      sections filled — not left as `<...>` placeholders to reconstruct later
- [ ] Failed attempts noted, one line each
- [ ] Every credential found is recorded **with which host it came from**

## Before the window closes (all targets)

- [ ] Every attempted target has at least a foothold screenshot, even the ones that never rooted —
      that's bankable partial credit
- [ ] Terminals and browser tabs **left open** — on-screen scrollback survives the window closing
      even though machine access does not
- [ ] Evidence directories copied somewhere safe off the exam VM
- [ ] Screenshots spot-checked for legibility at report scale (zoom out to ~50% — if you can't read
      it there, it won't survive PDF embedding)
