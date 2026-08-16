# AD Set — Domain: <domain.local>

> One copy for the whole AD chain. The per-host detail still goes in `target-note.md` copies — this
> file is the connective tissue: what credential came from where, what it unlocked, and the shape of
> the path. It becomes the report's "post-exploitation / lateral movement" section.

**Provided credential:** `<user>` / `<pass>` (given at exam start)
**Domain:** `<domain.local>`  **DC:** `<ip>` `<hostname>`

**Chain status:** ☐ MS01 foothold ☐ MS01 local admin ☐ creds harvested ☐ MS02 ☐ DC ☐ DA proof

---

## Host map

| IP | Hostname | Role | Access achieved | proof.txt | Note file |
|---|---|---|---|---|---|
|  |  | DC |  | ☐ | `<IP>-note.md` |
|  |  | MS01 |  | ☐ | `<IP>-note.md` |
|  |  | MS02 |  | ☐ | `<IP>-note.md` |

---

## Credential ledger

**Every credential gets a row the moment you obtain it.** This table is the single most useful thing
you will write during the AD set — it is what stops you re-cracking a hash you already cracked, and
it is what the lateral-movement narrative gets written from.

| # | Principal | Secret (pass / NT hash / ticket) | Type | Obtained from | Obtained how | Works on | Privilege |
|---|---|---|---|---|---|---|---|
| 1 |  |  | pass | (given) | exam start |  | domain user |
| 2 |  |  | NT hash |  |  |  |  |
| 3 |  |  | pass |  |  |  |  |

**Sprayed / reused:** <which credential against which hosts and protocols, and the result — so you
don't repeat sweeps.>

---

## Attack path

<Update as it develops. This becomes the report narrative — write it as a chain, not a list.>

```
<domain user, given>
   └─► MS01 : <how you got the foothold>
         └─► local admin via <technique>
               └─► harvested <credential> from <source>
                     └─► MS02 : <how that credential was used>
                           └─► <next step>
                                 └─► DC : <final technique> → Domain Admin
```

**Written narrative** (draft during the exam, polish in the write-up window):

<One paragraph per hop. "Using the credential recovered from X, authenticated to Y over Z, which
granted ... From there ...">

---

## BloodHound

- Collection run: `<command>` at `<HH:MM>` → `<zip path>`
- Key edges found:
  - `<principal>` --`<edge>`--> `<target>`
- Path chosen and why: <...>
- Paths ruled out: <...>

📷 **SCREENSHOT — BloodHound path** — the graph view showing the path you actually used. This is
GUI-only evidence; there is no text-log equivalent. File: `~/exam/ad/bloodhound-path.png`

---

## Domain compromise proof

> This section is the canonical DA proof capture for the AD set. The DC's own `target-note.md` copy
> covers the DC as an individual host (its local foothold, privesc, proof.txt); the DA-level proof
> here covers the domain-wide compromise and lives only in this file.

📷 **SCREENSHOT — DA context** — `whoami /groups` showing Domain Admins membership, on the DC,
with command + output + `whoami` + hostname + IP all in one frame. File: `~/exam/ad/da-proof.png`

**DC proof.txt**

```
$ type C:\Users\Administrator\Desktop\proof.txt
<contents>
```

☐ Submitted to control panel  ☐ Screenshotted

---

## AD-set-specific failed attempts

<Kerberoast returned nothing crackable, ADCS had no vulnerable templates, etc. Worth recording —
"I checked and it wasn't there" is methodology, and it stops you re-checking at hour 18.>
