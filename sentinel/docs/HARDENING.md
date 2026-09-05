# SENTINEL — what is demo-grade, and what production would change

SENTINEL is built to demo reliably in a room with no Wi-Fi. Several choices that make that possible are not what you would run in production. This page is the honest list.

| Area | Demo-grade today | Production |
|---|---|---|
| Storage | SQLite, single writer thread, `CREATE IF NOT EXISTS` + additive column migrations | PostgreSQL (same schema, `DATABASE_URL`), Alembic migrations, backups |
| Session window | In-memory `deque` per process | Redis (auto-adopted when reachable) shared across replicas |
| Embeddings | Deterministic char-3-gram hash embedder (`EMBEDDER=offline`) | `sentence-transformers` (`EMBEDDER=st`) or a hosted embedding API; re-index on model change |
| Jury | Three heuristic `MockJudge`s when no keys (reported as `jury_mode: heuristic` everywhere) | Three live providers from independent model families; provider outage degrades to `mixed` and is recorded |
| Rate limiting | Per-process sliding window in memory | Gateway/WAF or Redis-backed limiter; per-API-key quotas |
| Control-plane auth | Single admin key (`X-Sentinel-Admin-Key`), random per boot unless pinned | SSO/OIDC, per-user roles, audit of who labelled what |
| Data-plane auth | Open by default; `SENTINEL_PROXY_KEY` locks proxy chat | Always-on API keys or mTLS between the app and the proxy |
| Target credentials | Plaintext unless `SENTINEL_SECRET` + `cryptography` (then Fernet at rest); always masked in API responses | KMS/HSM-backed envelope encryption, rotation, never logged |
| CORS | Same-origin only; `CORS_ORIGINS` opt-in | Explicit allow-list, no `*` |
| Audit chain | sha256 hash chain in the same DB | Anchor chain heads to an external append-only store (object lock / transparency log) so a DB admin cannot rewrite history |
| Corpus validation | Against the built-in vulnerable mock (offline oracle) | `CORPUS_VALIDATION_TARGET` against real models on a schedule; `validated_live` gating for release corpora |
| Evidence | `scripts/evidence_run.py` on demand | Continuous evidence runs per model version, trend reports |
| Batch runner | `asyncio.Task` per run inside the API process | A real queue (Celery/RQ/Arq) with retries, cancellation and backpressure |
| Indirect injection | Demonstrated on the built-in RAG mock; external targets only observable via HTTP response | Instrument the target's retrieval/tool layer to feed retrieved content through the inspector (an SDK hook), or deploy SENTINEL as a sidecar around the retrieval step |
| Tool calls | Only detectable when surfaced in the HTTP response | Same SDK hook for tool-call arguments/results |
| Single process | API + console + mock targets in one uvicorn | Separate services, horizontal scale of the inspection engine, health-based routing |

None of these gaps affects what the judged artefact measures — attack variety, verdict reliability, report usefulness — but each is a real step between "works on stage" and "runs in a SOC".
