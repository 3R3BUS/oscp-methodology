# Passive Information Gathering & OSINT (PEN-200 Module 3)

> **Exam context:** On the OSCP exam, passive recon is limited — you're given IPs, not domains, and most OSINT sources won't have data on lab/exam machines. The real value is in labs and real-world pentests. On exam day, check Shodan (`shodan host <IP>`) and TLS certs (`openssl s_client`) first (30 seconds, may reveal hidden vhosts/services), then move quickly to active scanning.

Passive recon collects intelligence without sending packets to the target — all queries hit third-party services, cached data, or public records. Do this first: it surfaces subdomains, email formats, technology stacks, and employee names that shape your active enumeration.

## 1. Whois & DNS Passive Lookup

```bash
# Domain registration data — registrant, nameservers, creation/expiry dates
whois example.com

# Reverse whois — find other domains registered by the same entity
# (use Whoxy, ViewDNS.info, or DomainTools in a browser)

# Passive DNS — historical A/AAAA/MX/NS records without querying the target's nameserver
dig +short example.com @8.8.8.8          # resolves via public DNS, not target's infra
host -t mx example.com
```

**Tools for passive DNS history:**
- https://securitytrails.com — historical DNS records, subdomains, associated IPs
- https://dnsdumpster.com — DNS recon and subdomain mapping
- https://viewdns.info — reverse IP, whois, port scan history

## 2. Google Dorking

Target-scoped Google queries to find exposed files, login portals, directory listings, and error pages.

```
# Restrict results to target domain
site:example.com

# Find exposed file types
site:example.com filetype:pdf
site:example.com filetype:doc OR filetype:docx OR filetype:xls
site:example.com filetype:conf OR filetype:env OR filetype:bak

# Directory listings
site:example.com intitle:"Index of /"
site:example.com intitle:"Index of" "parent directory"

# Login/admin pages
site:example.com inurl:admin OR inurl:login OR inurl:wp-admin
site:example.com intitle:"login" OR intitle:"dashboard"

# Error pages leaking stack info
site:example.com intext:"sql syntax" OR intext:"Warning:" OR intext:"Fatal error"
site:example.com intext:"server at" intext:"port"

# Exposed config/credentials
site:example.com ext:xml OR ext:json OR ext:yaml intext:password
site:example.com inurl:".git"
```

**GHDB (Google Hacking Database):** https://www.exploit-db.com/google-hacking-database — curated dork library, searchable by category.

## 3. theHarvester

Aggregates emails, subdomains, IPs, and URLs from multiple public sources in one pass.

```bash
# Run against common passive sources
theHarvester -d example.com -b google,bing,yahoo,dnsdumpster,crtsh,linkedin

# Broader sweep (all available sources)
theHarvester -d example.com -b all

# Limit results and output to file
theHarvester -d example.com -b all -l 200 -f theharvester-results
```

**Key sources to understand:**
| Source | What it returns |
|--------|----------------|
| `google` / `bing` | Email addresses, subdomains from search results |
| `crtsh` | Subdomains from Certificate Transparency logs |
| `dnsdumpster` | Subdomains, MX, NS records |
| `linkedin` | Employee names (useful for username enumeration) |

## 4. Certificate Transparency (CT) Logs

TLS certificates are publicly logged. Query CT logs to discover subdomains the target has issued certs for — including internal-facing ones that might not be in public DNS.

```bash
# crt.sh — the most common CT log search engine
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Filter for unique subdomains only
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

Also accessible via browser at https://crt.sh — search `%.example.com` to see all certificates.

## 5. Shodan / Censys

Internet-wide scan databases — query what ports/services/banners the target exposes without scanning it yourself.

```bash
# Shodan CLI (requires free API key: shodan init <API_KEY>)
shodan search hostname:example.com
shodan host <target_ip>

# Useful Shodan filters
hostname:example.com port:443
org:"Target Organization"
ssl.cert.subject.cn:example.com
```

**Shodan web:** https://www.shodan.io — browse results, view screenshots, filter by service/port/vuln.

**Censys web:** https://search.censys.io — similar to Shodan, sometimes indexes different hosts. Good for finding services on non-standard ports.

## 6. recon-ng

Modular OSINT framework with a Metasploit-like interface. Automates queries across dozens of data sources.

```bash
recon-ng
# Create a workspace for the engagement
workspaces create example-engagement

# Add seed domain
db insert domains
# enter: example.com

# Load and run modules
modules load recon/domains-hosts/hackertarget
run
modules load recon/domains-hosts/certificate_transparency
run
modules load recon/domains-contacts/whois_pocs
run
modules load recon/hosts-hosts/resolve
run

# View collected data
show hosts
show contacts

# Export results
modules load reporting/html
options set FILENAME /tmp/recon-report.html
run
```

**Useful module categories:**
- `recon/domains-hosts/*` — subdomain discovery
- `recon/domains-contacts/*` — email/contact harvesting
- `recon/hosts-ports/*` — port/service data from Shodan
- `recon/profiles-*` — social media enumeration

## 7. Email & Username Enumeration

Employee names and email formats feed into password attacks (spraying, credential stuffing) and social engineering.

```bash
# theHarvester for emails (see §3)
theHarvester -d example.com -b google,bing,linkedin -l 500

# linkedin2username — generates probable usernames from LinkedIn company page
# (requires valid LinkedIn session cookie)
python3 linkedin2username.py -c "company-name" -n "example.com"

# Common email format patterns to test:
# first.last@example.com, flast@example.com, firstl@example.com
# Once you find one valid email, the format applies to all employees
```

**Verify email format:** Use https://hunter.io or https://phonebook.cz to confirm the target's email naming convention before building a username list.

## 8. Metadata Extraction

Documents published on the target's website leak internal usernames, software versions, file paths, and printer names in their metadata.

```bash
# Download documents from the target
wget -r -l 1 -A pdf,doc,docx,xls,xlsx,ppt,pptx https://example.com/

# Extract metadata with exiftool
exiftool -r -common downloaded_files/
exiftool -r -Creator -Author -Producer -ModifyDate downloaded_files/

# Extract usernames specifically
exiftool -r -Creator -Author downloaded_files/ | \
  grep -iE "creator|author" | awk -F': ' '{print $2}' | sort -u
```

Extracted usernames become candidates for AD enumeration, password spraying, and brute-forcing.

## References

- PEN-200 Module 3: Information Gathering
- https://www.exploit-db.com/google-hacking-database
- https://github.com/laramies/theHarvester
- https://github.com/lanmaster53/recon-ng
- https://crt.sh
- https://www.shodan.io
