# Corpus provenance — how the SENTINEL attack corpus was authored

**Short version:** every attack in `seeds/attacks.json` was written by the SENTINEL team. None was copied from a dataset, and the corpus does not cite repositories or commit hashes it cannot stand behind. Each seed instead states three honest facts:

| Field | Meaning |
|---|---|
| `origin` | `hand_authored` — written by us; `adapted` — reworded from a public example, with the URL in `provenance_note` |
| `taxonomy_source` | the public classification whose *category definitions* the seed follows (OWASP Top 10 for LLM Applications; garak probe families; Lakera PINT benchmark categories; deepset prompt-injection dataset taxonomy; the Invariant Labs MCP tool-poisoning write-up) |
| `provenance_note` | one sentence a reviewer can check |

Every seed also carries `owasp_llm` (LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM06 Excessive Agency, LLM07 System Prompt Leakage) and `mitre_atlas` (AML.T0051 LLM Prompt Injection and sub-techniques, AML.T0054 LLM Jailbreak, AML.T0057 LLM Data Leakage) so findings are quotable in two industry vocabularies. Tool-definition poisoning has no dedicated ATLAS technique and is mapped to AML.T0051.000 per ATLAS mapping practice.

## Why this matters

An earlier build labelled seeds with `source_repo @ source_sha`. Those hashes were placeholders, not real commits. A security tool that fabricates provenance forfeits the trust it is asking for, so v2.4 removed the fields and replaced them with the honest scheme above (principle P8 in the as-built document).

## What "validated" means

Origin says *where an attack's idea came from*. `validation_status` says *whether it works*: each seed and every mutated variant is fired at the built-in vulnerable target and admitted only if it produced a leaked span, a success indicator, or a compliance phrase. Attacks that don't work are kept as `dead` and never run. With `CORPUS_VALIDATION_TARGET` pointing at a live provider, seeds are additionally checked against a real model and flagged `validated_live`.
