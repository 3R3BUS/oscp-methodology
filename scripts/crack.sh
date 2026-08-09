#!/usr/bin/env bash
# crack.sh -- thin hashcat wrapper: auto-detects hash type via lib/hashmodes.sh (shared with
# hashid-credcheck.sh), then runs hashcat with sensible OSCP defaults.
#
# Cracking hashes you already harvested yourself, with a wordlist you chose, is core expected
# OSCP technique -- not the same category as the banned "automatic exploitation tools" (which act
# on a live target, not on already-local data you're processing offline). No exam-scope gating
# needed here.
#
# Usage: crack.sh <hash-file-or-dir> [wordlist] [--rules]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/hashmodes.sh
source "$SCRIPT_DIR/lib/hashmodes.sh"

TARGET_PATH=""
WORDLIST="/usr/share/wordlists/rockyou.txt"
USE_RULES=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rules) USE_RULES=1; shift ;;
        -*)
            echo "[!] Unknown flag: $1" >&2
            echo "Usage: $0 <hash-file-or-ad-enum-out-dir> [wordlist] [--rules]" >&2
            exit 1 ;;
        *)
            if [[ -z "$TARGET_PATH" ]]; then
                TARGET_PATH="$1"
            else
                WORDLIST="$1"
            fi
            shift ;;
    esac
done

if [[ -z "$TARGET_PATH" ]]; then
    echo "Usage: $0 <hash-file-or-ad-enum-out-dir> [wordlist] [--rules]" >&2
    exit 1
fi

if ! command -v hashcat >/dev/null 2>&1; then
    echo "[!] hashcat not found. Install: sudo apt install hashcat" >&2
    exit 1
fi

if [[ "$WORDLIST" == "--rules" ]]; then
    WORDLIST="/usr/share/wordlists/rockyou.txt"
fi
if [[ ! -f "$WORDLIST" ]]; then
    echo "[!] Wordlist not found: $WORDLIST (default is rockyou.txt -- gunzip it first if needed)" >&2
    exit 1
fi

RULE_ARGS=()
if [[ $USE_RULES -eq 1 ]]; then
    for candidate in ./OneRuleToRuleThemAll.rule /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule /usr/share/hashcat/rules/best64.rule; do
        if [[ -f "$candidate" ]]; then
            RULE_ARGS=(-r "$candidate")
            echo "[*] Using rule file: $candidate"
            break
        fi
    done
    if [[ ${#RULE_ARGS[@]} -eq 0 ]]; then
        echo "[!] --rules requested but OneRuleToRuleThemAll.rule not found in cwd or /usr/share/hashcat/rules/." >&2
        echo "    git clone https://github.com/NotSoSecure/password_cracking_rules" >&2
    fi
fi

crack_one() {
    local hash_file="$1"
    [[ -s "$hash_file" ]] || { echo "[*] Skipping empty file: $hash_file"; return; }

    local first_line mode label extra extra_flags=()
    first_line="$(grep -v '^\s*$' "$hash_file" | head -n1)"
    # Direct call, not command substitution -- a "$(...)" subshell would discard HASH_IS_PWDUMP.
    detect_hash_mode "$first_line" >/dev/null
    mode="$HASH_MODE"; label="$HASH_LABEL"

    if [[ "$mode" == "unknown" ]]; then
        echo "[!] Could not auto-detect hash type for $hash_file -- skipping. Check CHEATSHEET.md §4 manually." >&2
        return
    fi

    # Format-mandated flags come from the shared lib so this stays in step with what
    # hashmode_summary_line prints -- the two must never suggest different invocations.
    extra="$(hashcat_extra_flags "$mode")"
    [[ -n "$extra" ]] && extra_flags+=("$extra")

    # pwdump/secretsdump lines carry three fields before the NT hash; hashcat can't consume them
    # directly, so split the NT column into its own file rather than handing hashcat a file it will
    # reject line by line.
    if [[ "${HASH_IS_PWDUMP:-0}" -eq 1 ]]; then
        local nt_file="${hash_file%.hash}-nt.hash"
        echo "[*] $hash_file is pwdump format -- extracting NT hash column -> $nt_file"
        cut -d: -f4 "$hash_file" | grep -E '^[0-9a-fA-F]{32}$' | sort -u > "$nt_file"
        if [[ ! -s "$nt_file" ]]; then
            echo "[!] No NT hashes extracted from $hash_file -- skipping." >&2
            return
        fi
        hash_file="$nt_file"
    fi

    echo "[*] Cracking $hash_file (mode $mode: $label)"
    hashcat -m "$mode" -a 0 ${extra_flags[@]+"${extra_flags[@]}"} "$hash_file" "$WORDLIST" ${RULE_ARGS[@]+"${RULE_ARGS[@]}"}
    echo "[*] Cracked results for $hash_file:"
    hashcat -m "$mode" ${extra_flags[@]+"${extra_flags[@]}"} "$hash_file" --show
    echo
}

if [[ -d "$TARGET_PATH" ]]; then
    echo "[*] $TARGET_PATH is a directory -- cracking every non-empty hash file found."
    FOUND=0
    while IFS= read -r -d '' f; do
        FOUND=1
        crack_one "$f"
    done < <(find "$TARGET_PATH" -maxdepth 1 -type f \( -name '*.hash' -o -name '*hashes*' \) -print0)
    if [[ $FOUND -eq 0 ]]; then
        echo "[!] No *.hash files found directly under $TARGET_PATH" >&2
    fi
elif [[ -f "$TARGET_PATH" ]]; then
    crack_one "$TARGET_PATH"
else
    echo "[!] Not a file or directory: $TARGET_PATH" >&2
    exit 1
fi

exit 0
