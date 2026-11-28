#!/usr/bin/env bash
# web-recon.sh -- whatweb fingerprint, TLS SAN grab, robots.txt/sitemap.xml, ffuf vhost fuzzing,
# and feroxbuster dir/file discovery.
#
# NO nuclei: nuclei is an automated vulnerability scanner, the category the OSCP/OSCP+ exam
# explicitly prohibits ("mass vulnerability scanners e.g. Nessus, OpenVAS"). It is intentionally
# not wired into this script at all -- not by default, not scoped, not behind a flag. For allowed,
# targeted vuln detection use Nikto or nmap --script vuln (see fast-nmap.sh) instead.
#
# NOTE: VulnX is intentionally NOT integrated here. It ships a separate auto-exploitation capability
# ("-e"/"--exploit") that its own docs describe as an "auto shell injector" -- independently finds a
# vuln and executes/drops a shell with no human decision point in between, which is exactly the
# OSCP exam's banned "automatic exploitation tools (e.g. db_autopwn, SQLmap)" category. Per this
# repo's exam-scope discipline, VulnX stays reference-only and is never wired into this script's
# default or opt-in behavior, even restricted to its non-exploit fingerprinting flags.
#
# Usage: web-recon.sh <target-ip-or-host> [--domain example.com]
set -uo pipefail

TARGET=""
DOMAIN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)
            if [[ $# -lt 2 ]]; then
                echo "[!] --domain requires an argument" >&2
                exit 1
            fi
            DOMAIN="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 <target-ip-or-host> [--domain example.com]" >&2
            exit 0 ;;
        *)
            if [[ -n "$TARGET" ]]; then
                echo "[!] Multiple targets given ('$TARGET' and '$1') -- only one target allowed." >&2
                exit 1
            fi
            TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-ip-or-host> [--domain example.com]" >&2
    exit 1
fi

for tool in whatweb feroxbuster ffuf curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[!] $tool not found -- some stages will be skipped." >&2
        echo "    Install: sudo apt install whatweb feroxbuster ffuf curl" >&2
    fi
done

OUT="./web-recon-out/${TARGET}"
if ! mkdir -p "$OUT"; then
    echo "[!] Failed to create output directory: $OUT" >&2
    exit 1
fi
echo "[*] Output directory: $OUT"

# Probe both schemes once, up front, and drive every later stage off the result -- a target that
# only serves HTTPS (443 open, 80 closed) would otherwise get a silently half-empty scan.
SCHEMES=()
if command -v curl >/dev/null 2>&1; then
    curl -s -o /dev/null --max-time 5 "http://$TARGET/" 2>/dev/null && SCHEMES+=("http")
    curl -sk -o /dev/null --max-time 5 "https://$TARGET/" 2>/dev/null && SCHEMES+=("https")
else
    SCHEMES=("http")
fi
if [[ ${#SCHEMES[@]} -eq 0 ]]; then
    echo "[!] Neither http:// nor https:// responded on $TARGET -- is a web server actually running?" >&2
    echo "    Continuing with http:// only; stages below will likely come back empty." >&2
    SCHEMES=("http")
fi
echo "[*] Responding schemes: ${SCHEMES[*]}"

# --- whatweb: tech fingerprint (always) ---
if command -v whatweb >/dev/null 2>&1; then
    : >"$OUT/whatweb.txt"
    for scheme in "${SCHEMES[@]}"; do
        echo "[*] whatweb fingerprint (${scheme^^})"
        whatweb -a 3 "$scheme://$TARGET" 2>&1 | tee -a "$OUT/whatweb.txt"
    done
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
    for scheme in "${SCHEMES[@]}"; do
        SFX=""
        [[ "$scheme" == "https" && ${#SCHEMES[@]} -gt 1 ]] && SFX="-https"
        for doc in robots.txt sitemap.xml; do
            # -f so a 404 is a failure rather than a saved error page; -k for self-signed certs,
            # which is the norm on lab/exam boxes.
            if curl -skf --max-time 10 "$scheme://$TARGET/$doc" -o "$OUT/${doc%.*}${SFX}.${doc##*.}" \
                && [[ -s "$OUT/${doc%.*}${SFX}.${doc##*.}" ]]; then
                echo "  [$scheme] $doc found -> $OUT/${doc%.*}${SFX}.${doc##*.}"
            else
                rm -f "$OUT/${doc%.*}${SFX}.${doc##*.}"
            fi
        done
    done
fi

# --- ffuf VHost fuzzing (only meaningful with a domain to fuzz against; matches CHEATSHEET.md's
#     Host-header pattern -- this is vhost discovery on a single OSCP-style box, not authoritative
#     DNS subdomain brute-forcing, which ffuf doesn't natively do) ---
if [[ -n "$DOMAIN" ]] && command -v ffuf >/dev/null 2>&1; then
    WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    if [[ -f "$WORDLIST" ]]; then
        for scheme in "${SCHEMES[@]}"; do
            SFX=""
            [[ "$scheme" == "https" && ${#SCHEMES[@]} -gt 1 ]] && SFX="-https"
            echo "[*] ffuf VHost fuzzing against $DOMAIN over $scheme"
            BASELINE_SIZE="$(curl -sk -o /dev/null -w '%{size_download}' --max-time 10 \
                -H "Host: definitely-not-a-real-vhost-$RANDOM.$DOMAIN" "$scheme://$TARGET/" 2>/dev/null)"
            ffuf -u "$scheme://$TARGET" -H "Host: FUZZ.$DOMAIN" -w "$WORDLIST" \
                -fs "${BASELINE_SIZE:-0}" -o "$OUT/vhosts${SFX}.json" -of json -s
            if [[ -f "$OUT/vhosts${SFX}.json" ]] && command -v jq >/dev/null 2>&1; then
                echo "  Vhost hits ($scheme):"
                jq -r '.results[]?.input.FUZZ' "$OUT/vhosts${SFX}.json" 2>/dev/null | sed 's/^/    /'
            else
                echo "  Raw results: $OUT/vhosts${SFX}.json"
            fi
        done
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
        for scheme in "${SCHEMES[@]}"; do
            SFX=""
            [[ "$scheme" == "https" && ${#SCHEMES[@]} -gt 1 ]] && SFX="-https"
            echo "[*] feroxbuster directory/file discovery (${scheme^^})"
            feroxbuster -u "$scheme://$TARGET" -w "$FEROX_WORDLIST" \
                -x php,txt,bak,html,asp,aspx,jsp -t 50 -d 2 -q -k -o "$OUT/ferox${SFX}.txt"
        done
    else
        echo "[!] $FEROX_WORDLIST not found -- skipping feroxbuster." >&2
    fi
fi

echo
echo "=================== SUMMARY: $TARGET ==================="
[[ -s "$OUT/whatweb.txt" ]] && echo "-- whatweb --" && cat "$OUT/whatweb.txt"
for f in "$OUT/ferox.txt" "$OUT/ferox-https.txt"; do
    if [[ -s "$f" ]]; then
        echo "-- $(basename "$f") hits (2xx/3xx) --"
        grep -E '^(2[0-9]{2}|3[0-9]{2})[[:space:]]' "$f" 2>/dev/null | head -n 40
    fi
done
echo "==========================================================="
echo "[*] Full raw output saved under: $OUT/"
