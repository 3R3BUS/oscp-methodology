#!/usr/bin/env bash
# hashid-credcheck.sh -- two small utilities in one:
#   hash <string-or-file>            identify hash format, echo the hashcat -m mode to use
#   cred <target_or_range> <u> <p>   sweep a found credential across smb/winrm/rdp/mssql/ssh/ftp
#                                     via nxc (notes/password-attacks-advanced.md's "Credential
#                                     Reuse" section) to see where else it works
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/hashmodes.sh
source "$SCRIPT_DIR/lib/hashmodes.sh"

usage() {
    cat >&2 <<EOF
Usage:
  $0 hash <string-or-file>
  $0 cred <target_or_range> <user> <pass_or_hash>
EOF
    exit 1
}

SUBCMD="${1:-}"
[[ -z "$SUBCMD" ]] && usage
shift

case "$SUBCMD" in
    hash)
        INPUT="${1:-}"
        [[ -z "$INPUT" ]] && usage
        if [[ -f "$INPUT" ]]; then
            echo "[*] Reading hashes from file: $INPUT"
            declare -A MODES_SEEN=()
            SAW_PWDUMP=0
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                # Direct call, not command substitution -- a "$(...)" subshell would discard the
                # HASH_IS_PWDUMP flag before the loop could accumulate it.
                detect_hash_mode "$line" >/dev/null
                mode="$HASH_MODE"; label="$HASH_LABEL"
                [[ "${HASH_IS_PWDUMP:-0}" -eq 1 ]] && SAW_PWDUMP=1
                if [[ "$mode" == "unknown" ]]; then
                    echo "  ? ${line:0:50}...  -- unrecognized format, check CHEATSHEET.md §4 manually"
                elif [[ -z "${MODES_SEEN[$mode]:-}" ]]; then
                    MODES_SEEN[$mode]="$label"
                    echo "  $mode  ${label}"
                fi
            done < "$INPUT"
            echo
            if [[ ${#MODES_SEEN[@]} -eq 1 ]]; then
                for mode in "${!MODES_SEEN[@]}"; do
                    EXTRA="$(hashcat_extra_flags "$mode")"
                    echo "hashcat -m $mode ${EXTRA:+$EXTRA }\"$INPUT\" /usr/share/wordlists/rockyou.txt"
                done
                if [[ "${SAW_PWDUMP:-0}" -eq 1 ]]; then
                    echo
                    echo "[!] This file is in pwdump format (user:rid:lm:nt:::) -- hashcat won't read it"
                    echo "    as-is. Extract the NT hash column first:"
                    echo "      cut -d: -f4 \"$INPUT\" > \"${INPUT%.*}-nt.hash\""
                fi
            elif [[ ${#MODES_SEEN[@]} -gt 1 ]]; then
                echo "[!] Multiple hash types found in this file -- split them into separate per-type"
                echo "    files before running hashcat (a single -m run rejects lines that don't match)."
                for mode in "${!MODES_SEEN[@]}"; do
                    echo "  mode $mode: grep -E '<pattern for this type>' \"$INPUT\" > mode_${mode}.hash"
                done
            fi
        else
            detect_hash_mode "$INPUT" >/dev/null
            mode="$HASH_MODE"; label="$HASH_LABEL"
            if [[ "$mode" == "unknown" ]]; then
                echo "[!] Could not identify this hash format. Check CHEATSHEET.md §4 manually." >&2
                exit 1
            fi
            echo "Mode: $mode ($label)"
            EXTRA="$(hashcat_extra_flags "$mode")"
            printf 'hashcat -m %s %s%q /usr/share/wordlists/rockyou.txt\n' \
                "$mode" "${EXTRA:+$EXTRA }" "$INPUT"
        fi
        ;;

    cred)
        TARGET="${1:-}"
        # Deliberately not named USER -- that is a standard environment variable, and overwriting it
        # here would export a bogus value into every nxc subprocess this script spawns.
        CRED_USER="${2:-}"
        SECRET="${3:-}"
        if [[ -z "$TARGET" || -z "$CRED_USER" || -z "$SECRET" ]]; then
            usage
        fi
        if ! command -v nxc >/dev/null 2>&1; then
            echo "[!] nxc (netexec) not found. pipx install git+https://github.com/Pennyw0rth/NetExec" >&2
            exit 1
        fi

        AUTH_FLAG="-p"
        PROTOS=(smb winrm rdp mssql ssh ftp)
        if [[ "$SECRET" =~ ^[0-9a-fA-F]{32}$ ]]; then
            AUTH_FLAG="-H"
            echo "[*] Input looks like an NTLM hash -- using pass-the-hash (-H)."
            # ssh and ftp don't do NTLM auth -- nxc has no -H/--hash flag for either protocol, so
            # including them here would just error out on an unrecognized argument every time.
            echo "[*] ssh/ftp don't support NTLM pass-the-hash in nxc -- excluding them from this sweep."
            PROTOS=(smb winrm rdp mssql)
        fi

        echo "[*] Sweeping $CRED_USER against $TARGET across ${PROTOS[*]}"
        for proto in "${PROTOS[@]}"; do
            echo "--- $proto ---"
            OUTPUT="$(nxc "$proto" "$TARGET" -u "$CRED_USER" "$AUTH_FLAG" "$SECRET" 2>&1)"
            echo "$OUTPUT"
            if grep -qi 'Pwn3d!' <<<"$OUTPUT"; then
                echo "  *** (Pwn3d!) admin-equivalent access on $proto -- prioritize this ***"
            fi
        done
        ;;

    *)
        usage
        ;;
esac
