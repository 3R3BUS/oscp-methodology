# Drop-In Finding Blocks

Pre-written **description / impact / remediation** prose for the findings that actually show up on
OSCP boxes. Paste the block, replace the `<...>`, adjust severity if your demonstrated impact differs
from the default.

Severities match [`notes/reporting-methodology.md`](../notes/reporting-methodology.md) §3 — that file
explains the rating logic; this one just gives you the words.

**Two rules when using these:**

1. **Rate what you demonstrated, not what was theoretically possible.** If you found the SQLi but
   never got RCE, use the data-extraction block, not the RCE one.
2. **Don't paste a block for a finding you didn't actually exploit.** "Version looks vulnerable" is
   the *Outdated Software* block at Informational/Low, not the exploitation block at Critical.

---

## Contents

| # | Finding | Default severity |
|---|---|---|
| [1](#1-unauthenticated-remote-code-execution) | Unauthenticated RCE | Critical |
| [2](#2-authenticated-remote-code-execution) | Authenticated RCE | High |
| [3](#3-unrestricted-file-upload--rce) | Unrestricted file upload → RCE | Critical |
| [4](#4-sql-injection--command-execution) | SQL injection → RCE | Critical |
| [5](#5-sql-injection--data-extraction) | SQL injection → data extraction | High |
| [6](#6-local-privilege-escalation--service-misconfiguration) | LPE via service misconfig | High |
| [7](#7-local-privilege-escalation--sudo-misconfiguration) | LPE via sudo misconfig | High |
| [8](#8-local-privilege-escalation--suid-binary) | LPE via SUID binary | High |
| [9](#9-local-privilege-escalation--kernel--package-cve) | LPE via kernel/package CVE | High |
| [10](#10-local-privilege-escalation--windows-token-privilege) | LPE via Windows token privilege | High |
| [11](#11-weak--default-credentials) | Weak/default credentials | High |
| [12](#12-cleartext-credentials-in-accessible-files) | Cleartext credentials on disk | High |
| [13](#13-group-policy-preferences-cpassword) | GPP cpassword | High |
| [14](#14-kerberoastable-service-account) | Kerberoastable account | Medium→High |
| [15](#15-as-rep-roastable-account) | AS-REP roastable account | Medium→High |
| [16](#16-excessive-active-directory-privileges-acl-abuse) | AD ACL abuse | High |
| [17](#17-active-directory-certificate-services-misconfiguration) | ADCS misconfiguration | Critical |
| [18](#18-password-reuse-across-hosts) | Password reuse | High |
| [19](#19-anonymous--guest-accessible-share) | Anonymous share access | Medium→High |
| [20](#20-outdated-software-no-exploitation-demonstrated) | Outdated software (unexploited) | Informational–Low |
| [21](#21-directory-listing--verbose-error-disclosure) | Info disclosure | Informational–Low |
| [22](#22-smb-signing-not-required) | SMB signing not required | Medium |

---

## 1. Unauthenticated Remote Code Execution

**Severity:** Critical

**Description.** The `<service>` service running on port `<port>` of `<IP>` is affected by
`<CVE-XXXX-XXXXX / vulnerability class>`, which permits an unauthenticated remote attacker to execute
arbitrary operating system commands. The vulnerability arises because `<root cause — unsanitized
input passed to a system call / insecure deserialization / template injection / etc.>`.

**Impact.** Exploitation grants command execution in the context of the `<user>` account with no
credentials required, from any host able to reach port `<port>`. On this system the resulting access
was `<escalated to full administrative control / limited to the service account until further
escalation>`. An attacker requires no prior foothold, no valid account, and no user interaction.

**Remediation.** Upgrade `<software>` to version `<X>` or later, in which this issue is corrected.
Where immediate patching is not possible, restrict network access to port `<port>` to trusted
management networks only, and run the service under a dedicated low-privilege account so that
successful exploitation does not immediately yield administrative access.

---

## 2. Authenticated Remote Code Execution

**Severity:** High

**Description.** An authenticated user of `<application>` on `<IP>` can execute arbitrary operating
system commands via `<feature/parameter>`. `<Explain whether this is intended-but-dangerous
functionality exposed to under-privileged users, or a genuine flaw.>`

**Impact.** Any user holding valid `<application>` credentials — including the low-privileged
`<user>` account used during this test — can execute commands as `<service account>`. Combined with
the weak credentials described in finding `<#>`, the authentication requirement provided no
meaningful barrier.

**Remediation.** `<Patch to version X / restrict the feature to administrative roles / disable it
where not required.>` Enforce strong, unique credentials on all application accounts and apply the
principle of least privilege to the account the service runs as.

---

## 3. Unrestricted File Upload → RCE

**Severity:** Critical

**Description.** The upload function at `<URL/path>` on `<IP>` does not adequately restrict uploaded
file types. Server-side validation `<is absent entirely / relies only on the client-supplied
Content-Type header / checks only the file extension, which can be bypassed with <technique>>`.
Uploaded files are written to `<path>`, which is served by the web server and configured to execute
`<.php/.aspx/.jsp>` content.

**Impact.** An attacker can upload a web shell and execute arbitrary commands as the web server
account (`<user>`). This provided the initial foothold on this host.

**Remediation.** Validate uploads against a server-side allow-list of permitted extensions **and**
verify file content type independently of client-supplied headers. Store uploaded files outside the
web root, or in a location configured to serve content without executing it. Rename uploads to
server-generated identifiers rather than preserving user-supplied filenames.

---

## 4. SQL Injection → Command Execution

**Severity:** Critical

**Description.** The `<parameter>` parameter of `<endpoint>` on `<IP>` is concatenated directly into
a SQL query without parameterization, permitting injection of arbitrary SQL. The database service
account additionally holds privileges sufficient to reach the underlying operating system via
`<xp_cmdshell / SELECT ... INTO OUTFILE / stacked queries and a UDF>`.

**Impact.** Full compromise of both the database and the host. An attacker can read and modify all
database contents and execute operating system commands as `<database service account>`. Because the
database service runs as `<privileged account>`, this yielded `<administrative>` access to the host
directly.

**Remediation.** Rewrite all database access to use parameterized queries / prepared statements;
input validation and escaping are not a substitute. Separately, reduce the database service account's
privileges to the minimum the application requires and disable `<xp_cmdshell / file-write
privileges>` — this ensures a future injection flaw cannot escalate to host compromise.

---

## 5. SQL Injection → Data Extraction

**Severity:** High

**Description.** The `<parameter>` parameter of `<endpoint>` on `<IP>` is vulnerable to
`<union-based / error-based / blind boolean / time-based>` SQL injection. `<State what you enumerated
— database version, schema, table contents.>`

**Impact.** An attacker can read arbitrary data from the `<database>` database, including
`<credential hashes / user records / application configuration>`. During this test, `<what you
actually extracted>` was recovered; the extracted credentials were subsequently used to
`<downstream use>`. Command execution was not demonstrated from this vector.

**Remediation.** Rewrite affected queries using parameterized statements. Review the database
account's permissions and restrict it to only the tables and operations the application requires.
Ensure stored credentials use a modern, salted, computationally expensive hash.

---

## 6. Local Privilege Escalation — Service Misconfiguration

**Severity:** High

**Description.** The `<service name>` service on `<IP>` is configured such that a low-privileged user
can influence the executable it runs. Specifically: `<unquoted service path containing spaces /
the service binary is writable by <group> / the service's registry configuration is writable /
weak service DACL permits reconfiguration>`. The service runs as `<LocalSystem>`.

**Impact.** Any authenticated local user — including the `<user>` account obtained through finding
`<#>` — can cause arbitrary code to execute as `<SYSTEM>`, yielding complete control of the host.

**Remediation.** `<Quote the service's ImagePath / restrict write permissions on the binary and its
parent directories to administrators / correct the service DACL so non-administrative users cannot
reconfigure it.>` Audit all installed services for the same class of misconfiguration rather than
correcting this instance alone.

---

## 7. Local Privilege Escalation — sudo Misconfiguration

**Severity:** High

**Description.** The `<user>` account on `<IP>` is permitted by `/etc/sudoers` to execute
`<binary>` as `<root>` `<without a password (NOPASSWD)>`. `<binary>` provides `<a shell escape /
arbitrary file read / arbitrary file write / command execution>` functionality, so the grant is
effectively equivalent to full root access.

**Impact.** The `<user>` account can obtain a root shell, granting complete control of the host.
This defeats the privilege separation the sudo configuration was presumably intended to provide.

**Remediation.** Remove the `<binary>` entry from the sudoers configuration. Where users genuinely
require elevated use of specific functionality, grant the narrowest possible command with fully
qualified arguments, and verify the target binary has no documented escape technique — GTFOBins
catalogues these for common utilities. Require password re-authentication (remove `NOPASSWD`) for
any retained grants.

---

## 8. Local Privilege Escalation — SUID Binary

**Severity:** High

**Description.** The binary `<path>` on `<IP>` carries the setuid bit and is owned by `root`, causing
it to execute with root privileges regardless of the invoking user. `<It is a standard utility with a
documented shell-escape / it is a custom binary that invokes <command> without an absolute path,
permitting PATH hijacking / it passes user-controlled input to a shell.>`

**Impact.** Any local user can execute arbitrary code as root, yielding complete control of the host.

**Remediation.** Remove the setuid bit (`chmod u-s <path>`) unless it is genuinely required. If the
elevated behavior is required, `<rewrite the binary to invoke absolute paths and drop privileges as
early as possible / replace the mechanism with a narrowly-scoped sudo rule>`. Audit the filesystem
for other setuid binaries (`find / -perm -4000 -type f`) and justify each one.

---

## 9. Local Privilege Escalation — Kernel / Package CVE

**Severity:** High

**Description.** `<IP>` runs `<kernel/package version>`, which is affected by `<CVE-XXXX-XXXXX>`
(`<common name, e.g. PwnKit / Dirty Pipe>`). `<One sentence on the mechanism.>` The system has not
had the vendor patch applied.

**Impact.** Any local user can escalate to root/SYSTEM. Public, reliable exploit code exists for this
issue, making exploitation straightforward and requiring no specialist knowledge.

**Remediation.** Apply the vendor patch for `<CVE>` — `<specific package version or kernel release>`.
More broadly, the presence of a `<N>`-year-old unpatched local privilege escalation indicates the
host is not covered by a routine patching process; establish one and verify coverage of this host.

---

## 10. Local Privilege Escalation — Windows Token Privilege

**Severity:** High

**Description.** The `<service account>` context obtained on `<IP>` holds the `<SeImpersonatePrivilege
/ SeAssignPrimaryTokenPrivilege / SeBackupPrivilege / SeDebugPrivilege>` privilege. `<Explain the
abuse: SeImpersonate permits token-impersonation attacks against a coerced SYSTEM authentication;
SeBackup permits reading protected files including the SAM and SYSTEM hives; etc.>`

**Impact.** The privilege permits escalation to `SYSTEM`, granting complete control of the host.
Service accounts commonly hold `SeImpersonatePrivilege` by default, so any code execution as a
service account on an unpatched host should be treated as equivalent to SYSTEM.

**Remediation.** `<Apply current patches, which mitigate the specific coercion primitives used /
remove the privilege from accounts that do not require it / run the <service> under a less privileged
account.>` Review which accounts hold sensitive privileges (`whoami /priv`, group policy) and remove
grants that are not operationally justified.

---

## 11. Weak / Default Credentials

**Severity:** High

**Description.** The `<account>` account on `<service>` at `<IP>` was protected by the password
`<value>`, `<which is the vendor default / which appears in common password wordlists / which was
recovered by offline cracking in <time>>`. No account lockout was observed on repeated failures.

**Impact.** An attacker can authenticate as `<account>`, obtaining `<what that account grants>`.
Guessable credentials on a network-reachable service require no vulnerability in the software itself
and are among the most commonly exploited access vectors.

**Remediation.** Change the `<account>` password to a strong, unique value and change all vendor
default credentials across the estate. Enforce a password policy with sufficient minimum length,
implement account lockout or progressive delays on repeated authentication failures, and enable
multi-factor authentication on `<service>` where supported.

---

## 12. Cleartext Credentials in Accessible Files

**Severity:** High

**Description.** Credentials for `<account/service>` were stored in cleartext in `<path>` on `<IP>`.
The file is readable by `<the low-privileged <user> account / all authenticated users / all users on
the share>`.

**Impact.** Any user able to read `<path>` obtains valid credentials for `<what they authenticate
to>`. During this test these credentials were used to `<downstream action — escalate on this host /
authenticate to <other host> / access the domain>`, directly enabling `<outcome>`.

**Remediation.** Remove the cleartext credentials from `<path>`. Where an application must
authenticate non-interactively, use a secrets management system, an OS-provided credential store, or
a managed service account rather than a file on disk. Restrict read permissions on configuration
files to the account that requires them. Rotate the exposed credential — it must be treated as
compromised.

---

## 13. Group Policy Preferences cpassword

**Severity:** High

**Description.** A Group Policy Preferences file in `SYSVOL` on `<DC>` (`<path>`) contains a
`cpassword` attribute. GPP passwords are encrypted with an AES key that Microsoft published in 2012,
making them trivially reversible by any domain user. `SYSVOL` is readable by all authenticated domain
users by design.

**Impact.** Any domain user can recover the cleartext password for `<account>`, which held
`<privilege>`. This is a domain-user-to-`<privilege>` escalation requiring only a valid domain
account and no exploitation — any authenticated user in the domain can perform it, with no
vulnerability to exploit and nothing to crack.

**Remediation.** Delete the offending GPP file from `SYSVOL` and rotate the exposed account's
password immediately. Microsoft removed the ability to set passwords via GPP in MS14-025; audit
`SYSVOL` for any remaining legacy files containing `cpassword`. Use Local Administrator Password
Solution (LAPS) for managing local administrator passwords.

---

## 14. Kerberoastable Service Account

**Severity:** Medium (escalate to High if the cracked credential grants privileged access)

**Description.** The `<account>` account in `<domain>` has a Service Principal Name registered,
permitting any authenticated domain user to request a Kerberos service ticket encrypted with that
account's password hash. The ticket was requested and the account's password recovered offline in
`<time>` using a standard wordlist, indicating the password does not meet a sufficient strength
threshold.

**Impact.** The recovered credential granted `<what it granted>`. Because ticket requests are normal
Kerberos activity, this attack generates little anomalous logging. `<If the account was privileged:
the account is a member of <group>, so this single weak password results in <impact>.>`

**Remediation.** Set a long (25+ character) random password on `<account>`, or convert it to a Group
Managed Service Account (gMSA) so the password is machine-generated and rotated automatically.
Remove SPNs from accounts that do not require them, and ensure no service account is a member of a
privileged group such as Domain Admins.

---

## 15. AS-REP Roastable Account

**Severity:** Medium (escalate to High if the cracked credential grants privileged access)

**Description.** The `<account>` account in `<domain>` is configured with "Do not require Kerberos
pre-authentication." This allows any unauthenticated attacker who knows or guesses the username to
request an authentication response encrypted with the account's password hash, which can then be
cracked offline. The password was recovered in `<time>`.

**Impact.** `<What the credential granted.>` Unlike Kerberoasting, this attack requires **no** valid
domain credential — only knowledge of the username — making it available to a fully unauthenticated
attacker with network access to the domain controller.

**Remediation.** Enable Kerberos pre-authentication on `<account>` (clear the
`DONT_REQ_PREAUTH` flag). Audit the domain for other accounts with this setting, as it is rarely
required. Set a strong password on the affected account and treat it as compromised.

---

## 16. Excessive Active Directory Privileges (ACL Abuse)

**Severity:** High

**Description.** The `<principal>` principal holds `<GenericAll / GenericWrite / WriteDacl /
WriteOwner / ForceChangePassword / AddMember>` rights over `<target object>` in `<domain>`. `<Explain
what that specific right permits — e.g. GenericAll over a user permits resetting their password;
WriteDacl permits granting oneself any further right.>`

**Impact.** `<Principal>` — which was reachable from the initial foothold — can `<take control of
target>`, and by chaining this with `<subsequent edges>` ultimately obtain Domain Administrator
privileges. The path was identified through automated ACL analysis and required no software
vulnerability; the domain's permission model alone was sufficient.

**Remediation.** Remove the `<right>` grant from `<principal>` over `<target>`. Review the domain's
delegated permissions comprehensively — these grants accumulate over time and are rarely audited.
Adopt a tiered administration model so that compromise of a workstation-tier account cannot lead to
domain-tier control.

---

## 17. Active Directory Certificate Services Misconfiguration

**Severity:** Critical

**Description.** The certificate template `<template name>` published by the `<CA name>` certification
authority is misconfigured (`<ESC1: permits requester-supplied subject alternative name with a
client-authentication EKU and enrollment permitted to low-privileged users / ESC8: the CA web
enrollment endpoint accepts NTLM authentication without channel binding / etc.>`).

**Impact.** *(Use the branch matching the ESC you actually demonstrated — the mechanisms differ.)*

- **ESC1 / ESC6 (requester-supplied subject).** Any `<domain user>` permitted to enrol can request a
  certificate naming an *arbitrary* domain principal as its subject, including Domain Administrators.
- **ESC8 (NTLM relay to web enrolment).** An attacker who can coerce authentication from a privileged
  host relays it to the CA's HTTP enrolment endpoint and obtains a certificate for **that coerced
  principal specifically** — not an arbitrary one. Typically the domain controller's machine account,
  which is sufficient for DCSync.

In both cases the resulting authentication is cryptographically valid, so it succeeds regardless of
the target account's password, survives password rotation, and is difficult to distinguish from
legitimate certificate use.

**Remediation.** `<Remove the ENROLLEE_SUPPLIES_SUBJECT flag from <template> / require manager
approval for issuance / restrict enrollment permissions to accounts that require them / enable
Extended Protection for Authentication and disable NTLM on the CA web endpoints.>` Review all
published templates against current ADCS hardening guidance, and revoke any certificates issued from
the affected template.

---

## 18. Password Reuse Across Hosts

**Severity:** High

**Description.** The credential recovered from `<source host>` (finding `<#>`) was found to be valid
on `<other hosts>`. `<If local administrator: the same local administrator password is in use across
multiple systems, indicating a shared image or manual provisioning without per-host randomization.>`

**Impact.** Compromise of a single host yielded access to `<N>` additional systems with no further
exploitation required. Shared local administrator passwords in particular allow an attacker to move
laterally across the entire estate from one initial foothold, and enable pass-the-hash attacks that
do not require recovering the cleartext password at all.

**Remediation.** Deploy Local Administrator Password Solution (LAPS) or an equivalent so every host
has a unique, automatically rotated local administrator password. Rotate the exposed credential
everywhere it is in use. Where shared service credentials are unavoidable, scope each to the minimum
set of hosts required.

---

## 19. Anonymous / Guest-Accessible Share

**Severity:** Medium (High if sensitive content was recovered)

**Description.** The `<share name>` SMB share on `<IP>` permits `<anonymous (null session) / guest>`
access. The share contains `<what was found>`.

**Impact.** An unauthenticated attacker with network access to port 445 can enumerate and read
`<content>`. During this test the share yielded `<credentials / configuration data / information
enabling <next step>>`, which `<downstream impact>`.

**Remediation.** Disable anonymous and guest access to SMB shares on `<IP>`. Apply share and
NTFS permissions requiring authenticated, explicitly authorized access. Review the share's contents
and relocate any sensitive material to an appropriately restricted location.

---

## 20. Outdated Software (No Exploitation Demonstrated)

**Severity:** Informational–Low

> Use this when you identified a vulnerable version but did **not** demonstrate exploitation. Say so
> plainly — claiming impact you didn't prove is a credibility problem, and graders notice.

**Description.** `<IP>` is running `<software version>` on port `<port>`. This version is
`<N>` releases behind current and is publicly documented as affected by `<CVE(s)>`. Exploitation was
`<not attempted / attempted without success>` during this assessment, so the presence of an
exploitable condition on this specific host has not been confirmed.

**Impact.** Not demonstrated. If the host is affected as the version banner suggests, the referenced
issues would permit `<summary of the CVE's documented impact>`. This finding is reported as an
exposure requiring verification rather than a confirmed compromise path.

**Remediation.** Update `<software>` to a currently supported release. Establish a patch management
process covering internet- and network-reachable services, and verify version currency as part of
routine review.

---

## 21. Directory Listing / Verbose Error Disclosure

**Severity:** Informational–Low

**Description.** `<The web server at <IP> returns directory listings for <path> when no index
document is present / The application at <URL> returns unhandled exception messages containing
<stack traces / SQL query text / absolute filesystem paths / framework versions>.>`

**Impact.** Limited in isolation. The disclosed information reduces the effort required to identify
further attack surface — during this assessment it revealed `<what it revealed>`, which contributed
to `<which finding>`.

**Remediation.** `<Disable directory indexing / configure the application to return generic error
pages to clients and log detailed diagnostics server-side only.>` Ensure debug and development
configurations are not enabled in production.

---

## 22. SMB Signing Not Required

**Severity:** Medium

**Description.** The host `<IP>` does not require SMB message signing. Without required signing, SMB
sessions are susceptible to relay attacks in which an attacker who can coerce or intercept an
authentication attempt relays it to this host and authenticates as the coerced principal.

**Impact.** Combined with a mechanism for coercing authentication `<e.g. LLMNR/NBT-NS poisoning,
which was observed to be enabled on this network>`, an attacker can authenticate to `<IP>` as any
principal whose authentication can be induced — potentially including privileged accounts — without
recovering any password or hash.

**Remediation.** Require SMB signing on all hosts via Group Policy
(`Microsoft network server: Digitally sign communications (always)`). Disable LLMNR and NBT-NS to
remove the most common coercion primitive. Where legacy systems cannot support signing, isolate them
at the network level.
