# Drop-In Report Templates

Paste-ready scaffolding for the OSCP report and for live note capture. These are **not** a substitute
for the official [OSCP Exam Report Template](https://www.offsec.com/pwk-online/OSCP-Exam-Report.docx) —
OffSec grades against their document, so start from theirs and use these to fill it faster.

| File | Use it for | When |
|---|---|---|
| [`target-note.md`](target-note.md) | One copy per target, opened the moment you start enumerating | Exam day, live |
| [`ad-set-note.md`](ad-set-note.md) | The AD chain as a whole — credential ledger, host map, path tracking | Exam day, live |
| [`exam-report.md`](exam-report.md) | The full report skeleton, section by section | Write-up window |
| [`finding-blocks.md`](finding-blocks.md) | Pre-written description + impact + remediation prose for 22 common OSCP findings | Write-up window |
| [`evidence-checklist.md`](evidence-checklist.md) | Per-target "can I still submit this?" gate | Before you leave each box |

## How these fit together

```
Exam day                                    Write-up window (24h)
────────────────────────────────────────    ─────────────────────────────────
target-note.md   ×6  ──┐
ad-set-note.md   ×1  ──┼──►  evidence-checklist.md  ──►  exam-report.md
terminal logs        ──┤          (gate)                      ▲
screenshots/         ──┘                                      │
                                            finding-blocks.md ┘
                                              (paste + tweak)
```

The point of the live templates is that the write-up window becomes **assembly**, not research. If
you're reading your own scrollback at 3am trying to remember which host a hash came from, the live
capture failed — not the report.

## The one rule that matters most

**Nothing that requires target access can be created after the exam window closes.** You lose every
shell the instant time expires. Capture proof *when you have the shell*, not when you get around to it.
See [`notes/reporting-methodology.md`](../notes/reporting-methodology.md) §2 and §5 for the capture
strategy these templates assume.
