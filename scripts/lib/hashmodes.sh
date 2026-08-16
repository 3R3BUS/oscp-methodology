#!/usr/bin/env bash
# Shared hash-format -> hashcat -m mode detection, sourced by hashid-credcheck.sh and crack.sh.
# Single source of truth for mode numbers is CHEATSHEET.md §4 in this repo — this file mirrors
# that table for the formats that actually show up in this script set's own output (AD roasting,
# NTLM/SAM dumps, NetNTLMv2 captures, timeroast, JWT, common Unix crypt). It does not attempt to
# cover hashcat's full mode list — CHEATSHEET.md §4 is the exhaustive reference for anything else.

# hashcat_extra_flags <mode>
# Prints any extra hashcat flags that a given mode's on-disk format requires, or nothing.
# Currently only Timeroast (31300) needs one: timeroast.py emits "<RID>:$sntp-ms$<hash>$<salt>", and
# hashcat rejects that line unless --username tells it to skip the leading RID field.
# pwdump/secretsdump input ("user:rid:lmhash:nthash:::") is NOT handled here -- --username alone does
# not make hashcat parse it, because three fields precede the NT hash. That case is flagged via
# HASH_IS_PWDUMP and resolved by extracting the NT column (see CHEATSHEET.md 4.1 and crack.sh).
hashcat_extra_flags() {
    case "$1" in
        31300) echo "--username" ;;
        *)     echo "" ;;
    esac
}

# detect_hash_mode <hash-string>
# Prints "<mode>|<label>" on stdout, or "unknown|" if nothing matched. Never fails the caller.
#
# Also sets three globals: HASH_MODE, HASH_LABEL, and HASH_IS_PWDUMP (1 when the input was a
# pwdump/secretsdump line). Callers that need HASH_IS_PWDUMP must invoke this function DIRECTLY --
# reading the printed value via "$(detect_hash_mode ...)" runs it in a subshell, where the globals
# are set and then discarded when that subshell exits. Use the globals, not command substitution:
#     detect_hash_mode "$line" >/dev/null
#     mode="$HASH_MODE"; label="$HASH_LABEL"
# Internal: record the result in the globals AND print it, so both calling styles work.
_hm_set() {
    HASH_MODE="$1"
    HASH_LABEL="$2"
    printf '%s|%s\n' "$1" "$2"
}

detect_hash_mode() {
    local h="$1"
    HASH_IS_PWDUMP=0
    HASH_MODE="unknown"
    HASH_LABEL=""

    # secretsdump/SAM-dump line format: user:rid:lmhash:nthash:::  -> isolate the NT hash field
    if [[ "$h" =~ ^[^:]*:[0-9]+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}::: ]]; then
        h="$(cut -d: -f4 <<<"$h")"
        HASH_IS_PWDUMP=1
    fi

    case "$h" in
        '$krb5tgs$23$'*)   _hm_set 13100 "Kerberos 5 TGS-REP etype 23 (Kerberoast)"; return ;;
        '$krb5tgs$17$'*)   _hm_set 19600 "Kerberos 5 TGS-REP etype 17 (AES128 Kerberoast)"; return ;;
        '$krb5tgs$18$'*)   _hm_set 19700 "Kerberos 5 TGS-REP etype 18 (AES256 Kerberoast)"; return ;;
        '$krb5asrep$23$'*) _hm_set 18200 "Kerberos 5 AS-REP etype 23 (AS-REP Roast)"; return ;;
        '$krb5pa$23$'*)    _hm_set 7500  "Kerberos 5 AS-REQ Pre-Auth etype 23"; return ;;
        '$krb5pa$17$'*)    _hm_set 19800 "Kerberos 5 AS-REQ Pre-Auth etype 17 (AES128)"; return ;;
        '$krb5pa$18$'*)    _hm_set 19900 "Kerberos 5 AS-REQ Pre-Auth etype 18 (AES256)"; return ;;
        *'$sntp-ms$'*)     _hm_set 31300 "MS-SNTP (Timeroast) -- needs --username, the RID is a leading field"; return ;;
        '$2a$'*|'$2b$'*|'$2y$'*) _hm_set 3200 "bcrypt"; return ;;
        '$1$'*)            _hm_set 500   'md5crypt ($1$, Unix)'; return ;;
        '$5$'*)            _hm_set 7400  'sha256crypt ($5$, Unix)'; return ;;
        '$6$'*)            _hm_set 1800  'sha512crypt ($6$, Unix, modern /etc/shadow)'; return ;;
        eyJ*.eyJ*.*)       _hm_set 16500 "JWT (HS256) -- crack the HMAC secret"; return ;;
    esac

    # NetNTLMv1/v2 (Responder/relay capture). Both share the shape
    # USER::DOMAIN:<field>:<field>:<field>, so key off the LAST colon-delimited field:
    #   v1 ends with the 16-hex server challenge  -> short
    #   v2 ends with the variable-length blob     -> long (hundreds of hex chars)
    if [[ "$h" == *"::"*":"*":"*":"* ]]; then
        local last_field="${h##*:}"
        if [[ ${#last_field} -le 48 ]]; then
            _hm_set 5500 "NetNTLMv1 (Responder capture)"
        else
            _hm_set 5600 "NetNTLMv2 (Responder/relay capture)"
        fi
        return
    fi

    # bare 32-hex: ambiguous between raw MD5 and NTLM -- default to NTLM since that's what every
    # AD-adjacent stage in this script set actually produces; note the ambiguity in the label.
    if [[ "$h" =~ ^[0-9a-fA-F]{32}$ ]]; then
        _hm_set 1000 "NTLM (or raw MD5 -- 32-hex is ambiguous; NTLM assumed since that's what this script set's own output produces, use -m 0 instead if you know it's MD5)"
        return
    fi

    if [[ "$h" =~ ^[0-9a-fA-F]{40}$ ]]; then
        _hm_set 100 "SHA1 (raw)"
        return
    fi

    _hm_set unknown ""
}

# hashmode_summary_line <file>
# Convenience for callers that just want the printable "hashcat -m N file wordlist" suggestion
# for the first non-empty line of a hash file.
hashmode_summary_line() {
    local file="$1"
    local first_line mode label extra
    first_line="$(grep -v '^\s*$' "$file" 2>/dev/null | head -n1)"
    [[ -z "$first_line" ]] && return 1
    # Direct call, not command substitution -- see detect_hash_mode's comment: the subshell a
    # "$(...)" creates would discard HASH_IS_PWDUMP before we could read it below.
    detect_hash_mode "$first_line" >/dev/null
    mode="$HASH_MODE"; label="$HASH_LABEL"
    if [[ "$mode" == "unknown" ]]; then
        echo "  ! could not auto-detect hash type for $file -- check CHEATSHEET.md §4 manually"
        return 0
    fi
    extra="$(hashcat_extra_flags "$mode")"
    echo "  hashcat -m $mode ${extra:+$extra }\"$file\" /usr/share/wordlists/rockyou.txt   # $label"
    if [[ "${HASH_IS_PWDUMP:-0}" -eq 1 ]]; then
        echo "    ^ this file is in pwdump format (user:rid:lm:nt:::) -- extract the NT column first:"
        echo "      cut -d: -f4 \"$file\" > ${file%.hash}-nt.hash"
    fi
}
