#!/usr/bin/env bash
# Shared hash-format -> hashcat -m mode detection, sourced by hashid-credcheck.sh and crack.sh.
# Single source of truth for mode numbers is CHEATSHEET.md §4 in this repo — this file mirrors
# that table for the formats that actually show up in this script set's own output (AD roasting,
# NTLM/SAM dumps, NetNTLMv2 captures, timeroast, JWT, common Unix crypt). It does not attempt to
# cover hashcat's full mode list — CHEATSHEET.md §4 is the exhaustive reference for anything else.

# detect_hash_mode <hash-string>
# Prints "<mode>|<label>" on stdout, or "unknown|" if nothing matched. Never fails the caller.
detect_hash_mode() {
    local h="$1"

    # secretsdump/SAM-dump line format: user:rid:lmhash:nthash:::  -> isolate the NT hash field
    if [[ "$h" =~ ^[^:]*:[0-9]+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}::: ]]; then
        h="$(cut -d: -f4 <<<"$h")"
    fi

    case "$h" in
        '$krb5tgs$23$'*)   echo "13100|Kerberos 5 TGS-REP etype 23 (Kerberoast)"; return ;;
        '$krb5tgs$17$'*)   echo "19600|Kerberos 5 TGS-REP etype 17 (AES128 Kerberoast)"; return ;;
        '$krb5tgs$18$'*)   echo "19700|Kerberos 5 TGS-REP etype 18 (AES256 Kerberoast)"; return ;;
        '$krb5asrep$23$'*) echo "18200|Kerberos 5 AS-REP etype 23 (AS-REP Roast)"; return ;;
        '$krb5pa$'*)       echo "7500|Kerberos 5 AS-REQ Pre-Auth etype 23"; return ;;
        *'$sntp-ms$'*)     echo "31300|MS-SNTP (Timeroast) -- crack with hashcat's --username flag, RID is embedded as the username field"; return ;;
        '$2a$'*|'$2b$'*|'$2y$'*) echo "3200|bcrypt"; return ;;
        '$1$'*)            echo '500|md5crypt ($1$, Unix)'; return ;;
        '$5$'*)            echo '7400|sha256crypt ($5$, Unix)'; return ;;
        '$6$'*)            echo '1800|sha512crypt ($6$, Unix, modern /etc/shadow)'; return ;;
        eyJ*.eyJ*.*)       echo "16500|JWT (HS256) -- crack the HMAC secret"; return ;;
    esac

    # NetNTLMv1/v2 (Responder/relay capture): USER::DOMAIN:LM_RESP:NTLM_RESP:CHALLENGE
    # Distinguish by response field length: v1 = 48 hex chars, v2 = 100+ hex chars
    if [[ "$h" == *"::"*":"*":"*":"* ]]; then
        local response_field="${h##*:}"
        if [[ ${#response_field} -le 48 ]]; then
            echo "5500|NetNTLMv1 (Responder capture)"
        else
            echo "5600|NetNTLMv2 (Responder/relay capture)"
        fi
        return
    fi

    # bare 32-hex: ambiguous between raw MD5 and NTLM -- default to NTLM since that's what every
    # AD-adjacent stage in this script set actually produces; note the ambiguity in the label.
    if [[ "$h" =~ ^[0-9a-fA-F]{32}$ ]]; then
        echo "1000|NTLM (or raw MD5 -- 32-hex is ambiguous; NTLM assumed since that's what this script set's own output produces, use -m 0 instead if you know it's MD5)"
        return
    fi

    if [[ "$h" =~ ^[0-9a-fA-F]{40}$ ]]; then
        echo "100|SHA1 (raw)"
        return
    fi

    echo "unknown|"
}

# hashmode_summary_line <file>
# Convenience for callers that just want the printable "hashcat -m N file wordlist" suggestion
# for the first non-empty line of a hash file.
hashmode_summary_line() {
    local file="$1"
    local first_line
    first_line="$(grep -v '^\s*$' "$file" 2>/dev/null | head -n1)"
    [[ -z "$first_line" ]] && return 1
    local result="${first_line}"
    IFS='|' read -r mode label <<<"$(detect_hash_mode "$result")"
    if [[ "$mode" == "unknown" ]]; then
        echo "  ! could not auto-detect hash type for $file -- check CHEATSHEET.md §4 manually"
    else
        echo "  hashcat -m $mode \"$file\" /usr/share/wordlists/rockyou.txt   # $label"
    fi
}
