#!/usr/bin/env bash
# exam-box-setup.sh -- make a fresh Kali install OSCP/PEN-200 exam-ready in one run.
#
# Goal: a dead VM -> one run -> exam-ready, every time. Idempotent (safe to re-run), and no single
# failure aborts the rest -- failures are collected and printed at the end.
#
# What it does, in order:
#   1. Full apt update + dist-upgrade (everything current)
#   2. Core tooling this repo's notes/scripts reference, from Kali's apt repos
#   3. The few things apt doesn't carry: timeroast.py, and (optionally) a newer ligolo-ng
#   4. SecLists + an uncompressed rockyou.txt
#   5. Terminator as the default terminal emulator
#   6. zsh config: 100k shared history + autosuggestions + syntax highlighting
#   7. targets helper + history seeded with var-filled script invocations (fast-nmap.sh $BOX1 ...)
#   8. Terminal session logging (reporting-methodology.md's "capture every command" rule)
#   9. Marks this repo's helper scripts executable and symlinks them onto PATH
#  10. Prints a verification table so you can see at a glance what's ready
#
# Run it from inside the repo, as your normal user (NOT root -- it uses sudo where needed):
#       cd ~/oscp-methodology
#       chmod +x scripts/exam-box-setup.sh
#       ./scripts/exam-box-setup.sh                 # full run
#       ./scripts/exam-box-setup.sh --dry-run       # print what it would do, change nothing
#       ./scripts/exam-box-setup.sh --no-banned     # skip the exam-banned tools (see below)
#
# EXAM-BANNED TOOLS: Responder, mitm6, and sqlmap are installed by default (they're useful in
# labs/HTB/PG) but are flagged exam-banned in EXAM-TIPS.md -- running them on the exam risks a
# PERMANENT ban, not just a fail. This script drops a visible warning file next to each. Use
# --no-banned to leave them off the box entirely, which is the safest choice for an exam machine.
#
# NOTE: this installs an attack toolkit for authorized OSCP prep and pentesting only.

set -uo pipefail   # not -e: one failed package shouldn't abort the whole setup; failures are collected

DRY_RUN=0
INSTALL_BANNED=1
for arg in "$@"; do
    case "$arg" in
        --dry-run)    DRY_RUN=1 ;;
        --no-banned)  INSTALL_BANNED=0 ;;
        -h|--help)    sed -n '2,36p' "$0"; exit 0 ;;
        *) echo "Unknown option: $arg (try --help)"; exit 2 ;;
    esac
done

if [[ $EUID -eq 0 ]]; then
    echo "Run this as your normal user, not root -- it calls sudo only where needed." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_BIN="$HOME/.local/bin"
OPT_DIR="$HOME/opt"              # where non-apt binaries/scripts go
FAILURES=()

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }
run()  { if [[ $DRY_RUN -eq 1 ]]; then echo "[dry-run] $*"; else "$@" || FAILURES+=("$*"); fi; }

# ---------------------------------------------------------------------------
say "1/10 System update (apt update + full-upgrade)"
run sudo apt-get update
run sudo apt-get -y full-upgrade

# ---------------------------------------------------------------------------
say "2/10 Core tooling from Kali apt repos"
# Grouped by phase so a missing package is easy to spot. All verified present in Kali's repos.
# kali-linux-default pulls the standard exam toolset; the rest are explicit so nothing is assumed.
apt_pkgs=(
    # meta + basics
    kali-linux-default git curl wget jq openssl python3 python3-pip pipx golang-go 7zip
    # shell / terminal experience
    terminator zsh zsh-autosuggestions zsh-syntax-highlighting
    # recon / web
    # NB: nuclei deliberately NOT installed -- it's an automated vuln scanner, exam-banned.
    nmap ffuf feroxbuster gobuster whatweb nikto wpscan
    # AD / SMB / LDAP (netexec pulls in bloodhound.py + certipy-ad as deps)
    netexec certipy-ad bloodhound.py bloodhound sharphound enum4linux-ng
    smbclient smbmap ldap-utils rpcbind krb5-user impacket-scripts evil-winrm
    # cracking
    hashcat john hydra
    # pivoting
    ligolo-ng proxychains4 sshuttle chisel
    # misc exam staples
    seclists netcat-traditional
)
run sudo apt-get install -y "${apt_pkgs[@]}"

# ---------------------------------------------------------------------------
say "2b/10 Exam-banned tools (see header)"
if [[ $INSTALL_BANNED -eq 1 ]]; then
    warn "Installing Responder, mitm6, sqlmap -- EXAM-BANNED. Do not run on the exam box."
    run sudo apt-get install -y responder mitm6 sqlmap
    if [[ $DRY_RUN -eq 0 ]]; then
        for t in responder mitm6 sqlmap; do
            p="$(command -v "$t" 2>/dev/null)" && \
            printf '%s is EXAM-BANNED (spoofing/auto-exploit). Running it on the OSCP can cause a PERMANENT ban. Lab/HTB/PG use only.\n' "$t" \
                | sudo tee "$(dirname "$p")/README-$t-EXAM-BANNED.txt" >/dev/null
        done
    fi
else
    say "Skipping exam-banned tools (--no-banned)."
fi

# ---------------------------------------------------------------------------
say "3/10 Tools apt doesn't carry"
run mkdir -p "$OPT_DIR" "$LOCAL_BIN"

# Timeroast (standalone script, no install -- just needs to be on PATH), per scripts/README.md.
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] clone SecuraBV/Timeroast -> $OPT_DIR/Timeroast, symlink timeroast.py onto PATH"
elif [[ ! -e "$OPT_DIR/Timeroast/timeroast.py" ]]; then
    git clone --depth 1 https://github.com/SecuraBV/Timeroast "$OPT_DIR/Timeroast" \
        && ln -sf "$OPT_DIR/Timeroast/timeroast.py" "$LOCAL_BIN/timeroast.py" \
        || FAILURES+=("timeroast clone")
else
    echo "Timeroast already present."
fi

# ligolo-ng: apt now ships it (installed above). Nothing extra to do -- the apt build is current
# enough for the exam. If you ever want the very latest proxy/agent, download from the releases
# page manually; this script intentionally doesn't scrape GitHub for a "latest" URL that rots.

# ---------------------------------------------------------------------------
say "4/10 Wordlists (SecLists + rockyou)"
# SecLists arrives via apt above at /usr/share/seclists. rockyou ships gzipped on Kali.
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] gunzip /usr/share/wordlists/rockyou.txt.gz if still compressed"
elif [[ -f /usr/share/wordlists/rockyou.txt.gz && ! -f /usr/share/wordlists/rockyou.txt ]]; then
    sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz || FAILURES+=("rockyou gunzip")
else
    echo "rockyou.txt already decompressed (or not found as .gz)."
fi

# ---------------------------------------------------------------------------
say "5/10  Terminator as default terminal"
# Installed via apt above. Register it as the system default so the taskbar launcher and
# any 'x-terminal-emulator' call open terminator. Xfce (Kali default) also keeps its own
# keybinding, which we point at terminator too. Both are no-ops if already set.
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] set x-terminal-emulator alternative to terminator; point Xfce launcher keybind at it; write ~/.config/terminator/config"
elif command -v terminator >/dev/null 2>&1; then
    tpath="$(command -v terminator)"
    sudo update-alternatives --set x-terminal-emulator "$tpath" >/dev/null 2>&1 \
        || warn "couldn't set x-terminal-emulator (non-fatal)"
    # Xfce keyboard shortcut: whatever currently launches a terminal, repoint to terminator.
    xconf="$HOME/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-keyboard-shortcuts.xml"
    if [[ -f "$xconf" ]] && grep -q 'exo-open --launch TerminalEmulator' "$xconf"; then
        sed -i 's#exo-open --launch TerminalEmulator#terminator#g' "$xconf" \
            && echo "Repointed Xfce terminal shortcut to terminator." \
            || warn "couldn't edit Xfce shortcut (non-fatal)"
    fi
    # Make exo (Xfce's 'preferred applications') open terminator too.
    run mkdir -p "$HOME/.config/xfce4"
    [[ $DRY_RUN -eq 0 ]] && printf 'TerminalEmulator=terminator\n' > "$HOME/.config/xfce4/helpers.rc" 2>/dev/null || true

    # Terminator profile: maximised window + transparent background. Written idempotently -- skipped
    # if it already matches, and an existing differing config is backed up once before overwrite.
    tcfg="$HOME/.config/terminator/config"
    mkdir -p "$HOME/.config/terminator"
    tmpcfg="$(mktemp)"
    cat > "$tmpcfg" <<'TCONF'
[global_config]
  window_state = maximise
[keybindings]
[profiles]
  [[default]]
    background_darkness = 0.9
    background_type = transparent
[layouts]
  [[default]]
    [[[window0]]]
      type = Window
      parent = ""
    [[[child1]]]
      type = Terminal
      parent = window0
[plugins]
TCONF
    if [[ -f "$tcfg" ]] && cmp -s "$tmpcfg" "$tcfg"; then
        echo "Terminator config already matches."
        rm -f "$tmpcfg"
    else
        if [[ -f "$tcfg" ]]; then
            cp "$tcfg" "$tcfg.bak-$(date +%Y%m%d-%H%M%S)" && warn "Backed up existing terminator config."
        fi
        mv "$tmpcfg" "$tcfg" && echo "Wrote $tcfg (maximise window + transparent background)."
    fi
else
    FAILURES+=("terminator not installed; default-terminal step skipped")
fi

# ---------------------------------------------------------------------------
say "6/10  zsh: big history + autosuggestions + syntax highlighting"
# zsh is already Kali's default login shell. This block is purely additive and idempotent:
# a single sourced file does the work, and .zshrc just sources it once.
ZSHRC="$HOME/.zshrc"
OSCP_ZSH="$HOME/.oscp-zsh.sh"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] write $OSCP_ZSH (100k shared history, autosuggest, highlighting, OSC7 cwd-tracking) and source it from $ZSHRC"
else
    # Plugin paths as Kali's apt packages install them.
    AUTOSUGGEST=/usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh
    HIGHLIGHT=/usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
    cat > "$OSCP_ZSH" <<ZEOF
# ~/.oscp-zsh.sh -- sourced from .zshrc by exam-box-setup.sh. Safe to delete + re-run setup.

# --- history: large, shared, de-duplicated ---
export HISTFILE="\$HOME/.zsh_history"
export HISTSIZE=100000           # lines kept in memory this session
export SAVEHIST=100000           # lines persisted to HISTFILE
setopt APPEND_HISTORY            # don't clobber the file on exit
setopt INC_APPEND_HISTORY        # write each command as it's run, not at shell exit
setopt SHARE_HISTORY             # all open terminals see each other's history live
setopt HIST_IGNORE_ALL_DUPS      # a repeated command moves up rather than duplicating
setopt HIST_REDUCE_BLANKS
setopt HIST_IGNORE_SPACE         # a command typed with a leading space is not recorded
setopt EXTENDED_HISTORY          # timestamp each entry

# --- autosuggestions: suggest from your own history as you type (accept with ->) ---
[ -f "$AUTOSUGGEST" ] && source "$AUTOSUGGEST"
ZSH_AUTOSUGGEST_STRATEGY=(history completion)

# --- your box targets (set once with 'targets', reused as \$BOX1 etc.) ---
[ -f "\$HOME/.oscp-targets" ] && source "\$HOME/.oscp-targets"

# --- OSC 7: advertise the real cwd to the terminal so terminator's Ctrl+Shift+E / O / T
#     split/tab open in the SAME directory you're standing in. Needed because the step-8
#     terminal-logging 'script' wrapper sits between zsh and terminator, so terminator can't
#     read our cwd from the process table and otherwise falls back to \$HOME on every split. ---
autoload -Uz add-zsh-hook
_osc7_cwd() {
    local enc="" i c
    for (( i = 1; i <= \${#PWD}; i++ )); do
        c="\${PWD[i]}"
        case "\$c" in
            [a-zA-Z0-9/._~-]) enc+="\$c" ;;
            *) enc+="\$(printf '%%%02X' "'\$c")" ;;
        esac
    done
    printf '\e]7;file://%s%s\a' "\$HOST" "\$enc"
}
add-zsh-hook chpwd _osc7_cwd
_osc7_cwd

# --- syntax highlighting: must be sourced LAST ---
[ -f "$HIGHLIGHT" ] && source "$HIGHLIGHT"
ZEOF
    if ! grep -q 'oscp-zsh.sh' "$ZSHRC" 2>/dev/null; then
        printf '\n[ -f "$HOME/.oscp-zsh.sh" ] && source "$HOME/.oscp-zsh.sh"\n' >> "$ZSHRC"
        echo "Wired $OSCP_ZSH into $ZSHRC."
    else
        echo "$ZSHRC already sources it."
    fi
fi

# ---------------------------------------------------------------------------
say "7/10  Targets helper (set box IPs once, reuse everywhere)"
# Writes ~/.oscp-targets (the var store) and a 'targets' command onto PATH. Because the vars
# are real shell vars and the commands you run land in history, zsh-autosuggestions completes
# them as you type -- which is the "little thought, no scrambling" workflow you asked for.
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] create ~/.oscp-targets (BOX1-3, DC, AD1-2, DOMAIN) and a 'targets' command"
else
    [[ -f "$HOME/.oscp-targets" ]] || cat > "$HOME/.oscp-targets" <<'TEOF'
# OSCP exam targets -- edit with 'targets set <slot> <ip>' or by hand, then open a new shell.
# Slots mirror the exam: 3 standalones + a 3-host AD set.
export BOX1=""      # standalone 1 (your warm-up box)
export BOX2=""      # standalone 2
export BOX3=""      # standalone 3
export DC=""        # AD: domain controller
export AD1=""       # AD: member host 1
export AD2=""       # AD: member host 2
export DOMAIN=""    # AD: domain FQDN, e.g. corp.local
TEOF
    cat > "$LOCAL_BIN/targets" <<'TEOF'
#!/usr/bin/env bash
# targets -- view/set your OSCP box IPs, and sync them into /etc/hosts.
#   targets                 show current slots
#   targets set BOX1 10.1.1.5   set a slot (persists to ~/.oscp-targets; open a new shell to use $BOX1)
#   targets hosts           write all named hosts into /etc/hosts (dc.$DOMAIN etc.)
STORE="$HOME/.oscp-targets"
[ -f "$STORE" ] || { echo "No $STORE -- run exam-box-setup.sh first."; exit 1; }
case "${1:-show}" in
    show|"")
        grep -E '^export ' "$STORE" | sed 's/^export //; s/""/<unset>/' ;;
    set)
        [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "usage: targets set <SLOT> <IP>"; exit 2; }
        slot="${2^^}"
        grep -q "^export $slot=" "$STORE" || { echo "Unknown slot '$slot'. Slots: BOX1 BOX2 BOX3 DC AD1 AD2 DOMAIN"; exit 2; }
        sed -i "s#^export $slot=.*#export $slot=\"$3\"#" "$STORE"
        echo "$slot = $3  (open a new shell, or: source ~/.oscp-targets)" ;;
    hosts)
        # shellcheck disable=SC1090
        source "$STORE"
        tmp="$(mktemp)"; grep -v ' # oscp$' /etc/hosts > "$tmp" 2>/dev/null
        add() { [ -n "$1" ] && printf '%s\t%s # oscp\n' "$1" "$2" >> "$tmp"; }
        [ -n "$DOMAIN" ] && { add "$DC" "dc.$DOMAIN $DOMAIN"; add "$AD1" "ad1.$DOMAIN"; add "$AD2" "ad2.$DOMAIN"; }
        sudo cp "$tmp" /etc/hosts && rm -f "$tmp" && echo "Wrote AD hosts into /etc/hosts (lines tagged '# oscp')." ;;
    *) echo "usage: targets [show|set <SLOT> <IP>|hosts]"; exit 2 ;;
esac
TEOF
    chmod +x "$LOCAL_BIN/targets"
    echo "Created ~/.oscp-targets and the 'targets' command."
fi

# Seed zsh history with ready-to-run invocations of the helper scripts, already filled with the
# $BOX1/$DC/$DOMAIN vars. Autosuggestions then complete e.g. "fast-nmap.sh $BOX1" as you type "fast"
# -- flip the 1 to a 2 for the next box. No placeholder IPs, so an accidental Enter runs a real,
# correctly-formed command against whatever that var is set to (empty until you set it).
HIST="$HOME/.zsh_history"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] seed $HIST with var-filled helper invocations (once)"
elif grep -q 'fast-nmap.sh \$BOX1' "$HIST" 2>/dev/null; then
    echo "History already seeded."
else
    # Most-useful-last: zsh suggests the most recent match, so the line you want first goes last.
    seed=(
        'ligolo-setup.sh --route 10.10.10.0/24 --serve'
        'crack.sh ./ad-enum-out/'
        'hashid-credcheck.sh cred $BOX1 <user> <pass_or_hash>'
        'hashid-credcheck.sh hash hash.txt'
        'privesc-launcher.sh windows'
        'privesc-launcher.sh linux'
        'ad-enum.sh $DC $DOMAIN -u <user> -p <pass>'
        'web-recon.sh $BOX1'
        'fast-nmap.sh $BOX1'
    )
    ts=$(date +%s)
    # EXTENDED_HISTORY line format: ": <start>:<elapsed>;<command>"
    for cmd in "${seed[@]}"; do printf ': %d:0;%s\n' "$ts" "$cmd" >> "$HIST"; ts=$((ts+1)); done
    echo "Seeded $HIST with ${#seed[@]} helper invocations."
fi

# ---------------------------------------------------------------------------
say "8/10  Terminal session logging"
# Logs every interactive shell's command+output to ~/engagements/logs/ via 'script', which
# reporting-methodology.md calls for. Guarded so it never double-logs or fires in non-interactive
# shells, and never inside tmux/vscode integrated terminals that manage their own history.
LOG_SNIPPET='
# --- OSCP terminal logging (added by exam-box-setup.sh) ---
if [[ -z "${SCRIPT_LOGGING:-}" ]] && [[ $- == *i* ]] && [[ -z "${VSCODE_INJECTION:-}" ]]; then
    export SCRIPT_LOGGING=1
    mkdir -p "$HOME/engagements/logs"
    script -qf -c "${SHELL:-/bin/bash}" "$HOME/engagements/logs/term-$(date +%Y%m%d-%H%M%S)-$$.log"
    exit
fi
# --- end OSCP terminal logging ---'
SHELL_RC="$HOME/.zshrc"; [[ -f "$HOME/.zshrc" ]] || SHELL_RC="$HOME/.bashrc"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] append session-logging snippet to $SHELL_RC (logs to ~/engagements/logs/)"
elif grep -q 'OSCP terminal logging' "$SHELL_RC" 2>/dev/null; then
    echo "Logging snippet already present in $SHELL_RC."
else
    printf '%s\n' "$LOG_SNIPPET" >> "$SHELL_RC" && echo "Added to $SHELL_RC."
fi

# ---------------------------------------------------------------------------
say "9/10  This repo's helper scripts onto PATH"
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] chmod +x $REPO_ROOT/scripts/*.sh and symlink into $LOCAL_BIN"
else
    chmod +x "$REPO_ROOT"/scripts/*.sh
    for s in "$REPO_ROOT"/scripts/*.sh; do ln -sf "$s" "$LOCAL_BIN/$(basename "$s")"; done
    case ":$PATH:" in
        *":$LOCAL_BIN:"*) : ;;
        *) printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$SHELL_RC"
           warn "Added ~/.local/bin to PATH in $SHELL_RC -- open a new terminal for it to take effect." ;;
    esac
fi
[[ $DRY_RUN -eq 0 ]] && pipx ensurepath >/dev/null 2>&1

# ---------------------------------------------------------------------------
say "10/10  Verification"
if [[ $DRY_RUN -eq 0 ]]; then
    check=(nmap ffuf feroxbuster whatweb nxc certipy-ad bloodhound-python hashcat john
           hydra evil-winrm impacket-secretsdump ligolo-proxy proxychains4 sshuttle chisel
           timeroast.py fast-nmap.sh ad-enum.sh)
    printf '\n%-22s %s\n' "TOOL" "STATUS"
    for c in "${check[@]}"; do
        if command -v "$c" >/dev/null 2>&1; then printf '\033[32m%-22s ok\033[0m\n' "$c"
        else printf '\033[31m%-22s MISSING\033[0m\n' "$c"; fi
    done
    echo
    echo "rockyou:   $( [[ -f /usr/share/wordlists/rockyou.txt ]] && echo ok || echo MISSING )"
    echo "SecLists:  $( [[ -d /usr/share/seclists ]] && echo ok || echo MISSING )"
    echo "terminator:$( command -v terminator >/dev/null && echo ' ok' || echo ' MISSING' )"
    echo "targets:   $( [[ -x $LOCAL_BIN/targets ]] && echo ok || echo MISSING )"
    echo "zsh cfg:   $( [[ -f $HOME/.oscp-zsh.sh ]] && echo ok || echo MISSING )"
fi

# ---------------------------------------------------------------------------
echo
if [[ ${#FAILURES[@]} -eq 0 ]]; then
    say "Done. Open a NEW terminal so PATH + logging take effect, then re-run the verification list."
else
    warn "Finished with ${#FAILURES[@]} failed step(s):"
    printf '    - %s\n' "${FAILURES[@]}"
    echo "Re-run the script after fixing these; it's safe to run again."
fi

cat <<'REMINDER'

Reminder for exam day (from EXAM-TIPS.md):
  * No AI assistants of any kind -- permanent-ban risk.
  * No Responder / mitm6 / other spoofing -- permanent-ban risk.
  * No sqlmap or mass vuln scanners (Nessus/OpenVAS).
  * Metasploit/Meterpreter: ONE standalone machine only, never the AD set.
REMINDER