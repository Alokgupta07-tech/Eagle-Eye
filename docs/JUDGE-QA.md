# SENTINEL — anticipated judge questions (honest answers)

**"Isn't the mock target circular? Your detector and your target share the same regexes."**
Yes, by construction — and we say so in every report (`jury_mode: heuristic`) and in the README. The mock is a deterministic oracle with two jobs: validate that every corpus attack *can* work against a vulnerable app, and let the whole pipeline demo with no network. Mock-mode numbers prove pipeline correctness, not detection generality. Generality is shown by `scripts/evidence_run.py` against a real provider (`docs/evidence/`), and by two design choices that remove the circularity from the numbers: in batch mode an attack is never scored against its own corpus family (similarity self-match exclusion), and the response verdict is driven by leaked spans, indicators and the jury — not by the mock's regex.

**"Only N% of attacks were blocked at the request gate. Doesn't the proxy miss most attacks?"**
In batch mode the request gate deliberately *reports but does not enforce* (`gate_policy: permissive`) so every attack reaches the target and we measure the target's own resistance — that is the point of a security test. The response gate is the control, and it is the one that caught the compromises. Flip `enforce_request_block: true` and the same run blocks at the gate with live-proxy semantics; the report states which policy was used.

**"What if there are no API keys?"**
Everything still runs: SQLite, in-memory session store, hash embedder, three heuristic judges. The console header, `/healthz` and every report say `HEURISTIC` in amber. Nothing is hidden.

**"How do you handle indirect injection on a real target?"**
For our RAG mock we can demonstrate it end to end — poison a document live, ask a benign question, watch the response gate catch it. For an external target the proxy only sees HTTP in and out, so retrieval-side poisoning is invisible on the request side; the response gate is still in the path, and the report carries an explicit `INDIRECT_INJECTION_RISK` warning when the target declares RAG. We list this as a limitation rather than claim coverage.

**"What is novel here versus a prompt classifier?"**
Four things together: attacks are admitted to the corpus only if they demonstrably work; every request is inspected *and* every response is inspected regardless of the request verdict; the verdict is about the target's behaviour (RESISTED / SUCCESSFUL / INCONCLUSIVE with evidence and a ranked response-risk score), not about whether a prompt looks bad; and every decision is sealed in a hash chain so the report cannot be quietly edited.

**"How do you avoid false positives?"**
No single layer can block. Rules, similarity, obfuscation and jury are fused with weights; a high score with low confidence is capped into REVIEW; a 3-way jury dissent can never auto-block; the baseline includes benign-but-suspicious probes; and REVIEW-band decisions queue for labelling — a `false_positive` label discounts exactly the rules that fired, live, and the retune is sealed in the chain.

**"Where did the attacks come from?"**
They are hand-authored by the team following public taxonomies (OWASP LLM Top 10, garak probe families, Lakera PINT, the Invariant Labs tool-poisoning write-up), each tagged with OWASP and MITRE ATLAS ids. An earlier build printed fake commit hashes as provenance; we removed that. See `docs/CORPUS-PROVENANCE.md`.

**"What would you change for production?"**
See `docs/HARDENING.md`: Postgres + Redis, a real task queue, a network-level rate limiter, encrypted target credentials, restricted CORS, a proxy key, live judges from three model families, and continuous evidence runs.
