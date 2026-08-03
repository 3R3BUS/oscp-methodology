# OSCP Exam Report Skeleton

> **Start from OffSec's official template**
> ([`.docx`](https://www.offsec.com/pwk-online/OSCP-Exam-Report.docx) /
> [`.odt`](https://www.offsec.com/pwk-online/OSCP-Exam-Report.odt)) — they grade against their
> document. This file is the *content* to pour into it, with the prose you'd otherwise be composing
> at hour 20 already written. Replace every `<...>`. Delete every instructional blockquote.
>
> Section numbering below matches the structure described in
> [`notes/reporting-methodology.md`](../notes/reporting-methodology.md) §1.

---

# Offensive Security Certified Professional Exam Report

**Candidate:** <Full Name>
**OSID:** <OS-XXXXX>
**Exam date:** <YYYY-MM-DD>
**Report date:** <YYYY-MM-DD>
**Classification:** Confidential

---

## 1. Disclaimer / Scope

> Take this verbatim from the official template rather than rewriting it. The paragraph below is a
> placeholder to remind you the section exists — replace it with the template's own wording.

This document details an authorized penetration test performed against the Offensive Security
certification exam environment as part of an OSCP examination attempt. All activity was conducted
against a controlled lab environment expressly provisioned for this purpose. This is not a report of
an engagement against a production or client environment.

---

## 2. Executive Summary

> **Audience: a manager who has never run nmap.** No CVE IDs. No tool names as the focus. No command
> output. No port numbers. If you deleted every technical token and it stopped making sense, it is
> not an executive summary.
>
> Three paragraphs is plenty.

An authorized penetration test was performed against <N> hosts in the examination environment,
comprising <N> standalone systems and an Active Directory domain of <N> machines. The objective was
to identify security weaknesses, demonstrate their practical impact by exploiting them, and document
the results to a standard that permits independent reproduction.

<N> of <N> hosts were compromised. On <N> of these, the highest level of administrative control was
obtained. Within the Active Directory environment, a chain of weaknesses permitted escalation from a
standard domain user account to full domain administrative control — meaning complete authority over
every user, computer, and resource in the domain.

The most significant issues identified were <plain-English one-liners: "software running with known
public flaws that had not been updated", "accounts protected by easily guessed passwords",
"credentials stored in readable configuration files">. These are not exotic weaknesses; each is
well-understood and each has a straightforward remediation. Detailed findings and prioritized
recommendations follow.

---

## 3. High-Level Findings Summary

> Bridge between the exec summary and the technical detail. A manager skims this; a technical
> reviewer uses it as an index. Severities here **must** match §5.

| # | Host | Finding | Severity | Remediation summary |
|---|---|---|---|---|
| 1 | `<IP>` | <finding> | Critical | <one line> |
| 2 | `<IP>` | <finding> | High | <one line> |
| 3 | `<IP>` | <finding> | High | <one line> |

---

## 4. Methodology

> **Process, not targets.** Describe your approach once, at the conceptual level. This is where you
> show you followed a repeatable method rather than got lucky. A paragraph per phase. No IPs here.

**Information gathering.** Each in-scope host was subjected to a full TCP port sweep followed by
targeted service and version detection on discovered ports, with a parallel sweep of the most common
UDP services. <...>

**Service enumeration.** Each identified service was enumerated according to its protocol — <...>

**Vulnerability identification.** Identified software versions were checked against public
vulnerability databases; services were assessed for common misconfigurations <...>

**Exploitation.** Candidate vulnerabilities were validated by controlled exploitation <...>

**Privilege escalation.** Following initial access, each host was enumerated for local privilege
escalation vectors <...>

**Post-exploitation.** Compromised hosts were examined for credentials and other material enabling
lateral movement <...>

---

## 5. Detailed Findings

> One subsection per host, same skeleton every time. Full command output. Every screenshot captioned
> with what it proves. See `templates/finding-blocks.md` for pre-written description/impact/
> remediation prose for common findings.

### 5.1 `<IP>` — `<hostname>` — <OS / role>

**Severity:** <Critical/High/Medium/Low>
**Result:** <root / SYSTEM / Domain Admin / low-privilege only>

#### Synopsis

<One paragraph: what the host is, how it was reached, end state.>

#### Information Gathering

```
$ <scan command>
<full output>
```

| Port | Service | Version |
|---|---|---|
|  |  |  |

#### Vulnerability Identification

<What you observed and why it looked exploitable. The reasoning, not just the result.>

#### Exploitation

```
$ <exact command>
<full output>
```

**Figure 1 — Initial foothold as `<user>` on `<hostname>` (`<IP>`).**
`<screenshot>`

**local.txt**

```
$ <cat/type command with full original path>
<contents>
```

**Figure 2 — Contents of `local.txt` read from an interactive shell on `<IP>`.**
`<screenshot>`

#### Privilege Escalation

<Enumeration that surfaced the vector, then the exploitation.>

```
$ <command>
<full output>
```

**Figure 3 — Elevated context as `<root/SYSTEM>` on `<hostname>` (`<IP>`).**
`<screenshot>`

**proof.txt**

```
$ <cat/type command with full original path>
<contents>
```

**Figure 4 — Contents of `proof.txt` read from an interactive elevated shell on `<IP>`.**
`<screenshot>`

#### Remediation

<See finding-blocks.md — paste and adapt.>

---

### 5.2 `<IP>` — `<hostname>` — <OS / role>

<Repeat the 5.1 skeleton verbatim. Same headings, same order, every host.>

---

## 6. Active Directory — Attack Path

> Only if the AD set was attempted. The per-host sections above cover each machine; this section is
> the glue that makes them read as one chain instead of three disconnected compromises. Built from
> `templates/ad-set-note.md`.

**Domain:** `<domain.local>`  **Starting position:** <provided credential / unauthenticated>
**End state:** <Domain Admin / partial>

### 6.1 Path summary

```
<domain user>
   └─► <MS01> : <foothold technique>
         └─► local admin via <technique>
               └─► <credential> harvested from <source>
                     └─► <MS02> : <technique>
                           └─► <DC> : <technique> → Domain Admin
```

### 6.2 Narrative

<One paragraph per hop, in order. Each paragraph names the credential/artifact carried forward and
cross-references the per-host section where the underlying detail lives (§5.x).>

### 6.3 Domain compromise proof

**Figure N — Domain Administrator context on the domain controller.**
`<screenshot>`

---

## 7. Conclusion

> Short. Mirrors the exec summary's tone and audience. Aggregate risk plus top priorities.

The examination environment contained multiple weaknesses that, individually and in combination,
permitted complete compromise of <N> of <N> hosts and full administrative control of the
`<domain.local>` domain. The underlying causes cluster into <N> themes: <unpatched software /
weak credentials / excessive privilege / credentials stored in readable locations>.

Prioritized recommendations:

1. <highest-impact remediation>
2. <next>
3. <next>

---

## 8. Appendix

> Anything too long to inline without breaking §5's flow. Full linPEAS dumps, full nmap output where
> §5 showed a trimmed table, custom scripts you wrote, wordlists you generated.

### A. Full scan output — `<IP>`

```
<...>
```

### B. Custom scripts / exploit modifications

```python
<...>
```
