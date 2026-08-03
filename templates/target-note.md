# Target: <IP> — <hostname> — <OS/role>

> Copy this file per target the moment you start enumerating it. Fill sections in as you go.
> Delete this blockquote. Sections mirror the report's per-target skeleton exactly, so the write-up
> is copy-paste, not re-organization.

**Status:** ☐ enumerating ☐ foothold ☐ local.txt ☐ privesc ☐ proof.txt ☐ evidence complete
**Points:** ___ / ___
**Evidence dir:** `~/exam/<IP>/`

---

## Synopsis

<One paragraph, written LAST. What this host is, how it was reached (fresh foothold vs. pivoted from
which host), and end state (low-priv / root-SYSTEM / DA).>

---

## Information Gathering

**Port scan**

```
[HH:MM] Initial full TCP sweep
$ <command>
<full output>
```

| Port | Proto | Service | Version | Notes |
|---|---|---|---|---|
|  |  |  |  |  |

**Service enumeration**

```
[HH:MM] <what you're checking and why>
$ <command>
<full output>
```

---

## Vulnerability Identification

<What you noticed and WHY it looked exploitable — the version banner, the response behavior, the
misconfigured permission. This is the "how did you find it" narrative the replication standard
grades on. Not "I ran the exploit" but "the banner showed X, which I looked up and found Y.">

**Candidate vectors considered:**

| Vector | Why considered | Outcome |
|---|---|---|
|  |  | ☐ ruled out ☐ worked ☐ untried |

---

## Exploitation

```
[HH:MM] <context>
$ <exact command>
<full output>
```

**Shell obtained:** user `<user>` via `<method>` at `<HH:MM>`

📷 **SCREENSHOT — foothold** — must show in one frame: command, output, `whoami`/`id`, hostname,
target IP. File: `~/exam/<IP>/01-foothold.png`

**local.txt**

```
$ type C:\Users\<user>\Desktop\local.txt      # or: cat /home/<user>/local.txt
<contents>
```

📷 **SCREENSHOT — local.txt** — interactive shell, original path, IP visible.
File: `~/exam/<IP>/02-localtxt.png`
☐ **Submitted to the exam control panel** ← separate from the screenshot, both required

---

## Privilege Escalation

**Enumeration that surfaced the vector**

```
[HH:MM] <context>
$ <command>
<relevant excerpt — full output in evidence dir>
```

**Exploitation**

```
[HH:MM] <context>
$ <command>
<full output>
```

**Escalated to:** `<root/SYSTEM/Administrator>` via `<technique>` at `<HH:MM>`

📷 **SCREENSHOT — post-privesc** — `whoami` showing the elevated context, hostname, IP.
File: `~/exam/<IP>/03-privesc.png`

**proof.txt**

```
$ type C:\Users\Administrator\Desktop\proof.txt    # or: cat /root/proof.txt
<contents>
```

📷 **SCREENSHOT — proof.txt** — interactive shell, original path, elevated user, IP visible.
File: `~/exam/<IP>/04-prooftxt.png`
☐ **Submitted to the exam control panel**

---

## Post-Exploitation / Loot

| Item | Value | Where found | Used against |
|---|---|---|---|
| credential |  |  |  |
| hash |  |  |  |
| SSH key |  |  |  |

<Anything that fed into another host — state explicitly which downstream target section uses it.>

---

## Failed attempts / ruled out

<Brief. Demonstrates methodology and matters for partial credit. One line each — what you tried,
why it didn't work. Don't write essays here, but don't leave it empty either.>

- Tried `<X>` — <why it failed>

---

## Report-writing notes to self

<Things you want to remember when writing this up that aren't evidence: "the exploit needed the
port changed to 4444", "mention that the first PoC I found was broken and I patched line 42".>
