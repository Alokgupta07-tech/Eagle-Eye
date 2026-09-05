# SENTINEL v2.4 — changelog (one line per step, with the tests that cover it)

1. Honest provenance — `origin` / `taxonomy_source` / `provenance_note` replace placeholder repo@SHA; P8 rewritten; `docs/CORPUS-PROVENANCE.md`. Tests: `test_tags.py::test_every_seed_tagged`, `test_tags.py::test_tags_land_in_report`.
2. Similarity self-match exclusion — `parent_id`/`origin_kind`, `SimilarityEngine.score(exclude_ids)`, `second_best`, `known_corpus_match`. Tests: `test_similarity_exclusion.py` (2).
3. Real-model evidence path — `scripts/evidence_run.py`, `CORPUS_VALIDATION_TARGET` + `validated_live`, `jury_mode` everywhere. Tests: `test_jury_mode.py` (4).
4. RAG KB ships benign — `POISONED_ADDENDUM`, `poison_default_kb()`, `demo_setup.py --poison`, `scripts/poison_kb.sh`, retrieval requires a keyword hit. Test: `test_indirect_injection.py::test_kb_ships_benign_and_poisoning_is_explicit`.
5. Response-side risk score — `fuse_response`, `response_confidence`, `severity_for`, `FUSION_RESPONSE_W`, persisted `response_risk`/`response_confidence`/`derived_severity`/`source_severity`. Tests: `test_response_fusion.py` (5).
6. Markdown export + evidence drawer — `?format=md` for reports and leaderboards, `render_markdown`, executive summary, ranked findings, `response_excerpt`. Test: `test_report_export.py::test_markdown_export`.
7. Explicit gate policy — `enforce_request_block`, `test_runs.gate_policy`, `gate_would_block`, `gate_policy_note`. Test: `test_gate_policy.py::test_permissive_vs_enforcing`.
8. Detection edge cases — refusal grammar, Luhn, URL/data-URI-safe entropy, dead code removed, `refusal_suppression` rule + mock handler. Tests: `test_detection_edges.py` (4).
9. Genuine multi-turn corpus — `turns` seeds, `payload_parts`, `markdown_hidden_instruction`, `few_shot_poisoning`, mutators `split_3_turns`/`html_comment_wrap`/`staged_roleplay`, decode chain `zero_width`/`hidden_markup`. Tests: `test_multiturn.py` (5).
10. Console/report polish + docs — header mode badges, decoded payload, corpus match, response risk chip; `docs/DEMO-SCRIPT.md`, `docs/JUDGE-QA.md`. Covered by `test_api.py` (SSE contract unchanged).
11. Hardening — `CORS_ORIGINS`, `app/secrets.py` (mask + Fernet at rest), `SENTINEL_PROXY_KEY`, unpinned admin key, `docs/HARDENING.md`. Tests: `test_hardening.py` (6).
12. Final gate — 92 tests green; `demo_setup.py` clean on fresh `data/` with no keys; `--poison` restores the RAG kill-shot; `evidence_run.py` exits 0 without keys; ASBUILT §11.3 complete.
