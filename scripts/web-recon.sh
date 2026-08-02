#!/usr/bin/env bash
# web-recon.sh -- whatweb fingerprint, TLS SAN grab, robots.txt/sitemap.xml, ffuf vhost fuzzing,
# feroxbuster dir/file discovery, and a scoped nuclei pass (full-template nuclei is opt-in only).
#
# Usage: web-recon.sh <target-ip-or-host> [--domain example.com] [--nuclei-full]
set -uo pipefail

TARGET=""
DOMAIN=""
NUCLEI_FULL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --nuclei-full) NUCLEI_FULL=1; shift ;;
        -h|--help)
            echo "Usage: $0 <target-ip-or-host> [--domain example.com] [--nuclei-full]" >&2
            exit 0 ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-ip-or-host> [--domain example.com] [--nuclei-full]" >&2
    exit 1
fi

for tool in whatweb feroxbuster ffuf curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[!] $tool not found -- some stages will be skipped. See CHEATSHEET.md §2 for install notes." >&2
    fi
done

OUT="./web-recon-out/${TARGET}"
mkdir -p "$OUT"
echo "[*] Output directory: $OUT"

# --- whatweb: tech fingerprint (always) ---
if command -v whatweb >/dev/null 2>&1; then
    echo "[*] whatweb fingerprint"
    whatweb -a 3 "http://$TARGET" 2>&1 | tee "$OUT/whatweb.txt"
fi

# --- TLS certificate SAN grab (cheap hostname discovery, only if 443 responds) ---
if command -v openssl >/dev/null 2>&1; then
    echo "[*] TLS certificate SAN check (port 443)"
    SANS="$(echo | timeout 5 openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null \
        | grep -A1 'Subject Alternative Name' | tail -n1)"
    if [[ -n "$SANS" ]]; then
        echo "$SANS" | tee "$OUT/tls-sans.txt"
    else
        echo "  (no cert on 443, or no SAN extension present)"
    fi
fi

# --- robots.txt / sitemap.xml (near-zero cost) ---
if command -v curl >/dev/null 2>&1; then
    echo "[*] robots.txt / sitemap.xml"
    curl -s "http://$TARGET/robots.txt" -o "$OUT/robots.txt" && \
        [[ -s "$OUT/robots.txt" ]] && echo "  robots.txt found ($(wc -l <"$OUT/robots.txt") lines) -> $OUT/robots.txt"
    curl -s "http://$TARGET/sitemap.xml" -o "$OUT/sitemap.xml" && \
        [[ -s "$OUT/sitemap.xml" ]] && echo "  sitemap.xml found -> $OUT/sitemap.xml"
fi

# --- ffuf VHost fuzzing (only meaningful with a domain to fuzz against; matches CHEATSHEET.md's
#     Host-header pattern -- this is vhost discovery on a single OSCP-style box, not authoritative
#     DNS subdomain brute-forcing, which ffuf doesn't natively do) ---
if [[ -n "$DOMAIN" ]] && command -v ffuf >/dev/null 2>&1; then
    WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    if [[ -f "$WORDLIST" ]]; then
        echo "[*] ffuf VHost fuzzing against $DOMAIN"
        BASELINE_SIZE="$(curl -s -o /dev/null -w '%{size_download}' -H "Host: definitely-not-a-real-vhost-$RANDOM.$DOMAIN" "http://$TARGET/" 2>/dev/null)"
        ffuf -u "http://$TARGET" -H "Host: FUZZ.$DOMAIN" -w "$WORDLIST" \
            -fs "${BASELINE_SIZE:-0}" -o "$OUT/vhosts.json" -of json -s
        if [[ -f "$OUT/vhosts.json" ]] && command -v jq >/dev/null 2>&1; then
            echo "  Vhost hits:"
            jq -r '.results[]?.input.FUZZ' "$OUT/vhosts.json" 2>/dev/null | sed 's/^/    /'
        else
            echo "  Raw results: $OUT/vhosts.json"
        fi
    else
        echo "[!] $WORDLIST not found -- skipping vhost fuzzing." >&2
    fi
else
    [[ -z "$DOMAIN" ]] && echo "[*] No --domain given -- skipping vhost fuzzing (pass --domain example.com to enable)."
fi

# --- feroxbuster: dirs/files ---
if command -v feroxbuster >/dev/null 2>&1; then
    FEROX_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    if [[ -f "$FEROX_WORDLIST" ]]; then
        echo "[*] feroxbuster directory/file discovery"
        feroxbuster -u "http://$TARGET" -w "$FEROX_WORDLIST" \
            -x php,txt,bak,html,asp,aspx,jsp -t 50 -d 2 -q -o "$OUT/ferox.txt"
    else
        echo "[!] $FEROX_WORDLIST not found -- skipping feroxbuster." >&2
    fi
fi

# --- nuclei: scoped by default, full template set only behind --nuclei-full ---
if command -v nuclei >/dev/null 2>&1; then
    if [[ $NUCLEI_FULL -eq 1 ]]; then
        cat >&2 <<'EOF'
[!] EXAM-SCOPE WARNING: --nuclei-full runs the entire default nuclei template repository
    (12,000+ templates spanning CVEs, misconfigs, exposures) against this target. Running
    the full template set is functionally a mass automated vulnerability scan -- the same
    category of tool ("mass vulnerability scanners e.g. Nessus, OpenVAS") the OSCP exam
    guide explicitly prohibits. Fine for HTB/labs/real engagements; do NOT use --nuclei-full
    on the actual OSCP exam. The scoped default run (no flag) stays within Nikto/NSE-vuln
    territory, which is explicitly allowed.
EOF
        echo "[*] nuclei (FULL template set, exam-risk -- see warning above)"
        nuclei -u "http://$TARGET" -o "$OUT/nuclei-full.txt"
    else
        echo "[*] nuclei (scoped: tech/panel/misconfig/default-login only, dos+fuzz excluded)"
        nuclei -u "http://$TARGET" -tags tech,exposed-panel,misconfig,default-login \
            -etags dos,fuzz -o "$OUT/nuclei-scoped.txt"
    fi
fi

echo
echo "=================== SUMMARY: $TARGET ==================="
[[ -f "$OUT/whatweb.txt" ]] && echo "-- whatweb --" && cat "$OUT/whatweb.txt"
if [[ -f "$OUT/ferox.txt" ]]; then
    echo "-- feroxbuster hits (2xx/3xx) --"
    grep -E ' (2[0-9]{2}|3[0-9]{2}) ' "$OUT/ferox.txt" 2>/dev/null | head -n 40
fi
for f in "$OUT/nuclei-scoped.txt" "$OUT/nuclei-full.txt"; do
    [[ -f "$f" && -s "$f" ]] && echo "-- $(basename "$f") --" && cat "$f"
done
echo "==========================================================="
echo "[*] Full raw output saved under: $OUT/"
