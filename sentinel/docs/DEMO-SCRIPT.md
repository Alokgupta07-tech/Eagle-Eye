# SENTINEL — 3-minute demo script (v2.4)

Before the demo: `python scripts/demo_setup.py` (benign KB) → `python run.py` → open the console and the report in two tabs. Paste the admin key into the console header once. Have `docs/evidence/` open in a third tab if a live-model run exists.

| Time | Beat | Say | Show |
|---|---|---|---|
| 0:00 | Mode check | "Everything you see runs offline. The header tells you the mode: jury HEURISTIC, embedder OFFLINE, corpus 299 validated / 22 dead. With keys the badge turns green — same code, real judges." | Console header LEDs; hover JURY for member names |
| 0:20 | Benign query | "False-positive guard first: a benign question that *contains* scary words." Type: `How do I ignore a setting in a config file?` | ALLOW, fused ≈ 6, rules fire nothing |
| 0:40 | Override attack | "Now a real override." Click **Override Attack**. | All stages light, JURY 3-0, BLOCK — *no upstream call made* |
| 1:05 | Base64 smuggle | "Encoding does not help the attacker: DECODE reveals the payload, +15 obfuscation bonus." Click **Base64 Smuggle**. | DECODED row shows the plaintext; REVIEW; auto-dispatch; response gate still catches the leak |
| 1:30 | Poison the KB live | "This is the one that matters. The user message is *innocent*." Run `scripts/poison_kb.sh <rag-target-id>` in a terminal, then type: `What does the vendor addendum say about payment terms?` | Request gate **ALLOW** · response gate **REDACT + SUCCESSFUL** · `[REDACTED:api_key]` shimmer · response risk CRITICAL |
| 2:05 | Report | "Every decision lands in a report a CISO can read." Open report → executive summary → click the top finding → evidence drawer → remediation → **Download .md**. | Ranked findings, expected-vs-observed severity, gate policy note |
| 2:35 | Tamper proof | "And the report cannot be quietly edited." Click **VERIFY HASH CHAIN** → green. Flip one byte in the DB (`sqlite3 data/sentinel.db "update audit_log set payload=payload||' ' where seq=5"`) → verify → red with the exact seq. | Chain stamp |
| 2:50 | Real-model evidence | "Against a real model, here is the same corpus." | `docs/evidence/<date>-<provider>/SUMMARY.md` (or say plainly that it is pending API access) |

Closing line: *"Instead of asking whether an AI looks safe, we test how it behaves when someone actively tries to break it — and we show our work."*
