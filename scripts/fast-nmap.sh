#!/usr/bin/env bash
# fast-nmap.sh -- operationalizes CHEATSHEET.md §1's "Recommended sequence": fast full-TCP sweep
# -> targeted -sC/-sV rescan on discovered ports -> UDP top-100 sweep in parallel -> --script vuln.
# nmap (incl. --script vuln) is explicitly allowed on the OSCP exam -- no scope caveat needed here.
#
# Usage: fast-nmap.sh <target>
set -uo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target>" >&2
    echo "  Runs: fast TCP sweep -> targeted -sC/-sV rescan (+ parallel UDP top-100) -> --script vuln" >&2
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "[!] nmap not found. Install: sudo apt install nmap" >&2
    exit 1
fi

OUT="./fast-nmap-out/${TARGET}"
if ! mkdir -p "$OUT"; then
    echo "[!] Failed to create output directory: $OUT" >&2
    exit 1
fi
echo "[*] Output directory: $OUT"

SUDO=""
if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        # Prime the sudo timestamp now, while we still own the terminal. Stages 1 and 2 both launch
        # into the background simultaneously; if sudo had to prompt from there, two background jobs
        # would fight over the tty and the password prompt would be invisible.
        if ! sudo -v; then
            echo "[!] sudo authentication failed -- SYN and UDP scans will fall back/fail." >&2
        fi
    else
        echo "[!] Not running as root and no sudo available -- UDP scan and SYN scan may fail/fallback." >&2
    fi
fi

# Initialized before the trap is installed: the handler can fire (Ctrl+C, early exit) before the
# background jobs are launched, and under `set -u` an unset var would crash the handler itself.
TCP_PID=""
UDP_PID=""
cleanup() {
    [[ -n "$TCP_PID" ]] && kill "$TCP_PID" 2>/dev/null
    [[ -n "$UDP_PID" ]] && kill "$UDP_PID" 2>/dev/null
    wait 2>/dev/null
    return 0
}
trap cleanup INT TERM EXIT

echo "[*] Stage 1/5: fast full-TCP port sweep (background)"
$SUDO nmap -p- --min-rate=1000 -T4 -oA "$OUT/tcp-all" "$TARGET" >"$OUT/tcp-all.log" 2>&1 &
TCP_PID=$!

echo "[*] Stage 2/5: UDP top-100 sweep (background, parallel with stage 1)"
$SUDO nmap -sU --top-ports 100 -T4 -oA "$OUT/udp-top100" "$TARGET" >"$OUT/udp-top100.log" 2>&1 &
UDP_PID=$!

echo "[*] Waiting on stage 1 (full TCP sweep)..."
wait "$TCP_PID"
TCP_RC=$?
if [[ $TCP_RC -ne 0 ]]; then
    echo "[!] Full TCP sweep exited non-zero ($TCP_RC) -- check $OUT/tcp-all.log" >&2
fi

TCP_PORTS="$(grep -oP '\d{1,5}(?=/open(\|filtered)?/tcp)' "$OUT/tcp-all.gnmap" 2>/dev/null | sort -nu | tr '\n' ',' | sed 's/,$//')"

if [[ -z "$TCP_PORTS" ]]; then
    echo "[!] No open TCP ports found in $OUT/tcp-all.gnmap -- skipping targeted rescan and vuln scan."
else
    echo "[*] Stage 3/5: targeted -sC/-sV rescan on: $TCP_PORTS"
    $SUDO nmap -p"$TCP_PORTS" -sC -sV -oA "$OUT/tcp-targeted" "$TARGET" >"$OUT/tcp-targeted.log" 2>&1
fi

echo "[*] Waiting on stage 2 (UDP top-100 sweep)..."
wait "$UDP_PID"
UDP_RC=$?
if [[ $UDP_RC -ne 0 ]]; then
    echo "[!] UDP sweep exited non-zero ($UDP_RC) -- check $OUT/udp-top100.log (needs root for -sU)" >&2
fi

UDP_PORTS="$(grep -oP '\d{1,5}(?=/open(\|filtered)?/udp)' "$OUT/udp-top100.gnmap" 2>/dev/null | sort -nu | tr '\n' ',' | sed 's/,$//')"
if [[ -n "$UDP_PORTS" ]]; then
    echo "[*] Stage 4/5: targeted UDP -sC/-sV rescan on: $UDP_PORTS"
    $SUDO nmap -sU -p"$UDP_PORTS" -sC -sV -oA "$OUT/udp-targeted" "$TARGET" >"$OUT/udp-targeted.log" 2>&1
else
    echo "[*] Stage 4/5: no open UDP ports in top-100 sweep -- skipping targeted UDP rescan."
fi

if [[ -n "$TCP_PORTS" ]]; then
    echo "[*] Stage 5/5: --script vuln pass on: $TCP_PORTS"
    $SUDO nmap -p"$TCP_PORTS" --script vuln -oA "$OUT/vuln" "$TARGET" >"$OUT/vuln.log" 2>&1
else
    echo "[*] Stage 5/5: skipped (no open TCP ports)."
fi

echo
echo "=================== SUMMARY: $TARGET ==================="
if [[ -f "$OUT/tcp-targeted.nmap" ]]; then
    grep -E '^[0-9]+/(tcp|udp)' "$OUT/tcp-targeted.nmap" 2>/dev/null
elif [[ -f "$OUT/tcp-all.nmap" ]]; then
    grep -E '^[0-9]+/tcp' "$OUT/tcp-all.nmap" 2>/dev/null
fi
if [[ -f "$OUT/udp-targeted.nmap" ]]; then
    grep -E '^[0-9]+/udp' "$OUT/udp-targeted.nmap" 2>/dev/null
fi
echo "==========================================================="
echo "[*] Full raw output saved under: $OUT/"
[[ -f "$OUT/vuln.nmap" ]] && echo "[*] Check $OUT/vuln.nmap for --script vuln findings."
