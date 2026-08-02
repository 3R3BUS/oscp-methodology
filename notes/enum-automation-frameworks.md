# Enumeration Automation Frameworks & Exam Tool-Use Policy

*For authorized pentest/exam prep only.*

AutoRecon, nmapAutomator, and reconFTW are script-based orchestration frameworks that chain already-approved utilities (Nmap, Nikto, Gobuster, etc.) to accelerate the *manual enumeration* phase — the phase OffSec generally tolerates automation on. This is distinct from automated *exploitation*, which is restricted on the exam (see policy section below).

---

## AutoRecon
```bash
# Install (pipx recommended)
sudo apt install -y python3-venv && python3 -m pip install --user pipx && python3 -m pipx ensurepath
pipx install autorecon

autorecon <TARGET_IP_OR_CIDR> [<TARGET2> ...] -o <output_dir>
```
**Reference:** https://github.com/Tib3rius/AutoRecon (canonical — an `AutoRecon/AutoRecon` org mirror also exists, same project)

## nmapAutomator
```bash
git clone https://github.com/21y4d/nmapAutomator.git && cd nmapAutomator
sudo ln -s $(pwd)/nmapAutomator.sh /usr/local/bin/nmapAutomator

nmapAutomator.sh -H <TARGET-IP> -t <TYPE>
# TYPE: Network|Port|Script|Full|UDP|Vulns|Recon|All
```
**Reference:** https://github.com/21y4d/nmapAutomator

## reconFTW
Built primarily for external/bug-bounty-style domain recon (subdomain enum, Nuclei-based web vuln modules) — heavier-weight than needed for typical single-host OSCP boxes.
```bash
git clone https://github.com/six2dez/reconftw.git && cd reconftw && ./install.sh

./reconftw.sh -d example.com -r    # passive/recon-only
./reconftw.sh -d example.com -a    # full scan incl. vuln checks
```
**Caution:** its active-vuln-scan modules (Nuclei-based) can cross into the exam's banned "vulnerability scanning" territory depending on flags — avoid `-a`/vuln-scan flags on exam day, or scope invocation carefully.
**Reference:** https://github.com/six2dez/reconftw (docs: https://docs.reconftw.com/)

---

## OSCP Exam Automation & AI Tool Policy (2026)

See also **EXAM-TIPS.md** for the full exam-day logistics reference — this section is the detailed tool-allowance backing for that doc's "Do/Avoid" lists.

- **Metasploit/Meterpreter — single-target lock-in.** Once you select one target machine, Metasploit modules (Auxiliary/Exploit/Post) and Meterpreter may be used against that machine only, as many times as needed — never against any other machine. You cannot test/`check` Metasploit against candidate targets before locking in your choice, and Metasploit cannot be used for pivoting (that would touch a second machine).
- **Banned fully-automated exploitation tools:** SQLmap in auto-exploit mode beyond its core function, SQLninja, `db_autopwn`, `browser_autopwn`, and "tools that perform similar functions." The candidate is responsible for knowing what any chosen tool does internally.
- **Banned mass/commercial vulnerability scanners:** Nessus, Nexpose, OpenVAS, Canvas, Core Impact, SAINT, and commercial tool tiers generally (Burp Suite Pro, Metasploit Pro).
- **Explicitly allowed:** Nmap (incl. NSE scripts), Nikto, Burp Suite Community/Free, DirBuster/Gobuster/Dirb, Netcat, and custom scripts you write yourself. Rationale: the exam evaluates the candidate's own skill at identifying/exploiting vulnerabilities, not their ability to run an automation pipeline.
- **AI/LLM chatbot ban:** any LLM or AI chatbot (OffSec's own "KAI," ChatGPT, Gemini, Claude, DeepSeek, Copilot, etc.) is strictly prohibited during both the exam window and report-writing — treated as third-party assistance/exam-info sharing, can result in a **permanent ban**, not just a fail. Passive AI features in general productivity tools (Notion AI, search AI overviews) don't need to be disabled since they aren't being directly prompted for exam assistance. (OSEE/OSAI are currently the only OffSec exams that permit AI use.)
- **Automation frameworks (AutoRecon/nmapAutomator/reconFTW):** because these only wrap already-approved reconnaissance tools rather than performing automated exploitation, community consensus treats them as permissible for the recon phase — but this is reasoned inference, not an explicit OffSec endorsement naming these tools. The burden is on the candidate to know exactly what any wrapped tool does under the hood.

**Sources:** https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide · https://help.offsec.com/hc/en-us/articles/35549468971156-AI-Usage-Policy-in-OffSec-Exams
