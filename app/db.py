"""Storage layer. Canonical: PostgreSQL (pgvector image). Universal default: SQLite.
Both share one query set; embeddings are stored as JSON text and compared in-process
with numpy (exact cosine; corpus is few-hundred rows — fast, zero infra). P1 holds:
the runtime never touches the network for data, only this store."""
from __future__ import annotations

import asyncio
import json
import os
import concurrent.futures
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

_JSON_COLS = {
    "targets": {"capabilities"},
    "target_baselines": {"topic_dist", "embedding_centroid"},
    "attack_patterns": {"success_indicators", "failure_indicators", "allowed_mutations"},
    "test_executions": {"request_scores", "response_scores", "jury"},
    "alerts": {"detail"},
    "audit_log": {"payload"},
}

SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS targets(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, endpoint_url TEXT NOT NULL,
  auth_header TEXT, capabilities TEXT NOT NULL DEFAULT '{}',
  canary_token TEXT, system_prompt_seeded INTEGER DEFAULT 0, created_at TEXT);
CREATE TABLE IF NOT EXISTS target_baselines(
  id TEXT PRIMARY KEY, target_id TEXT NOT NULL, version INTEGER NOT NULL,
  refusal_rate REAL, length_mean REAL, length_var REAL, topic_dist TEXT,
  embedding_centroid TEXT, drift_threshold REAL, probe_count INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS attack_patterns(
  id TEXT PRIMARY KEY, payload_hash TEXT UNIQUE NOT NULL, category TEXT NOT NULL,
  subcategory TEXT, payload TEXT NOT NULL, expected_safe_behavior TEXT,
  success_indicators TEXT, failure_indicators TEXT, severity TEXT, remediation TEXT,
  allowed_mutations TEXT, source_repo TEXT, source_sha TEXT,
  origin TEXT, taxonomy_source TEXT, provenance_note TEXT,
  parent_id TEXT, origin_kind TEXT, validated_live INTEGER,
  validation_status TEXT NOT NULL DEFAULT 'pending', validated_at TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS attack_embeddings(
  pattern_id TEXT PRIMARY KEY, embedding TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS detection_rules(
  id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, pattern TEXT NOT NULL,
  weight REAL NOT NULL, category TEXT, active INTEGER DEFAULT 1, updated_at TEXT);
CREATE TABLE IF NOT EXISTS test_runs(
  id TEXT PRIMARY KEY, target_id TEXT, baseline_version INTEGER,
  status TEXT DEFAULT 'running', started_at TEXT, finished_at TEXT,
  total INTEGER DEFAULT 0, resisted INTEGER DEFAULT 0, successful INTEGER DEFAULT 0,
  inconclusive INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0, redacted INTEGER DEFAULT 0,
  created_at TEXT);
CREATE TABLE IF NOT EXISTS test_executions(
  id TEXT PRIMARY KEY, run_id TEXT, pattern_id TEXT, variant_text TEXT,
  request_scores TEXT, response_scores TEXT, drift_score REAL, jury TEXT,
  fused_score REAL, confidence REAL, band TEXT, verdict TEXT, action TEXT,
  latency_ms INTEGER, audit_seq INTEGER, response_excerpt TEXT,
  response_risk REAL, response_confidence REAL, derived_severity TEXT, source_severity TEXT,
  created_at TEXT);
CREATE TABLE IF NOT EXISTS alerts(
  id TEXT PRIMARY KEY, execution_id TEXT, run_id TEXT, severity TEXT,
  title TEXT, detail TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS fp_review_labels(
  id TEXT PRIMARY KEY, audit_seq INTEGER, label TEXT, labeler TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS audit_log(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, prev_hash TEXT NOT NULL,
  payload TEXT NOT NULL, hash TEXT NOT NULL, created_at TEXT);
"""

SCHEMA_PG = """
CREATE TABLE IF NOT EXISTS targets(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, endpoint_url TEXT NOT NULL,
  auth_header TEXT, capabilities TEXT NOT NULL DEFAULT '{}',
  canary_token TEXT, system_prompt_seeded INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS target_baselines(
  id TEXT PRIMARY KEY, target_id TEXT NOT NULL, version INTEGER NOT NULL,
  refusal_rate REAL, length_mean REAL, length_var REAL, topic_dist TEXT,
  embedding_centroid TEXT, drift_threshold REAL, probe_count INTEGER,
  created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS attack_patterns(
  id TEXT PRIMARY KEY, payload_hash TEXT UNIQUE NOT NULL, category TEXT NOT NULL,
  subcategory TEXT, payload TEXT NOT NULL, expected_safe_behavior TEXT,
  success_indicators TEXT, failure_indicators TEXT, severity TEXT, remediation TEXT,
  allowed_mutations TEXT, source_repo TEXT, source_sha TEXT,
  origin TEXT, taxonomy_source TEXT, provenance_note TEXT,
  parent_id TEXT, origin_kind TEXT, validated_live INTEGER,
  validation_status TEXT NOT NULL DEFAULT 'pending', validated_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS attack_embeddings(
  pattern_id TEXT PRIMARY KEY, embedding TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS detection_rules(
  id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, pattern TEXT NOT NULL,
  weight REAL NOT NULL, category TEXT, active INTEGER DEFAULT 1,
  updated_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS test_runs(
  id TEXT PRIMARY KEY, target_id TEXT, baseline_version INTEGER,
  status TEXT DEFAULT 'running', started_at TIMESTAMPTZ DEFAULT now(),
  finished_at TIMESTAMPTZ,
  total INTEGER DEFAULT 0, resisted INTEGER DEFAULT 0, successful INTEGER DEFAULT 0,
  inconclusive INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0, redacted INTEGER DEFAULT 0,
  created_at TEXT);
CREATE TABLE IF NOT EXISTS test_executions(
  id TEXT PRIMARY KEY, run_id TEXT, pattern_id TEXT, variant_text TEXT,
  request_scores TEXT, response_scores TEXT, drift_score REAL, jury TEXT,
  fused_score REAL, confidence REAL, band TEXT, verdict TEXT, action TEXT,
  latency_ms INTEGER, audit_seq INTEGER, response_excerpt TEXT,
  response_risk REAL, response_confidence REAL, derived_severity TEXT, source_severity TEXT,
  created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS alerts(
  id TEXT PRIMARY KEY, execution_id TEXT, run_id TEXT, severity TEXT,
  title TEXT, detail TEXT, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS fp_review_labels(
  id TEXT PRIMARY KEY, audit_seq BIGINT, label TEXT, labeler TEXT,
  created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS audit_log(
  seq BIGSERIAL PRIMARY KEY, prev_hash TEXT NOT NULL,
  payload TEXT NOT NULL, hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uid() -> str:
    return uuid.uuid4().hex[:12]


class Store:
    def __init__(self, settings):
        self.s = settings
        self.backend = "postgres" if settings.is_postgres else "sqlite"
        self._lock = threading.Lock()
        self._alock = asyncio.Lock()       # serializes writes (single-writer audit chain)
        self._conn: sqlite3.Connection | None = None
        self._pool = None
        # sqlite worker: DEDICATED single thread per connection (the default executor's
        # threads outlive per-test event loops and crash on freed connections — SEGV fix)
        self._exec: concurrent.futures.ThreadPoolExecutor | None = None

    async def connect(self):
        if self.backend == "postgres":
            import asyncpg  # type: ignore
            dsn = (self.s.DATABASE_URL
                   .replace("postgresql+asyncpg://", "postgresql://"))
            self._pool = await asyncpg.create_pool(dsn, min_size=1, max_size=4)
            async with self._pool.acquire() as c:
                await c.execute(SCHEMA_PG)
                await self._ensure_columns()
        else:
            path = self.s.DATABASE_URL.split("sqlite:///", 1)[-1]
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self._exec = concurrent.futures.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="sentinel-sqlite")
            self._conn = await asyncio.get_running_loop().run_in_executor(
                self._exec, self._sqlite_connect, path)
            await self._write(SCHEMA_SQLITE, (), script=True)
            await self._ensure_columns()

    async def _ensure_columns(self):
        """Idempotent migrations for pre-existing databases."""
        upgrades = [("attack_patterns", "owasp_llm", "TEXT"),
                    ("attack_patterns", "mitre_atlas", "TEXT"),
                    ("attack_patterns", "origin", "TEXT"),
                    ("attack_patterns", "taxonomy_source", "TEXT"),
                    ("attack_patterns", "provenance_note", "TEXT"),
                    ("attack_patterns", "parent_id", "TEXT"),
                    ("attack_patterns", "origin_kind", "TEXT"),
                    ("attack_patterns", "validated_live", "INTEGER"),
                    ("test_executions", "response_excerpt", "TEXT"),
                    ("test_executions", "response_risk", "REAL"),
                    ("test_executions", "response_confidence", "REAL"),
                    ("test_executions", "derived_severity", "TEXT"),
                    ("test_executions", "source_severity", "TEXT"),
                    ("test_runs", "comparison_id", "TEXT"),
                    ("test_runs", "gate_policy", "TEXT")]
        for table, col, typ in upgrades:
            try:
                if self.backend == "postgres":
                    await self._write(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {typ}")
                else:
                    await self._write(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
            except Exception:  # noqa: BLE001 - duplicate column = already migrated
                pass

    def _sqlite_connect(self, path):
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    async def close(self):
        if self._pool:
            await self._pool.close()
        if self._conn:
            await asyncio.get_running_loop().run_in_executor(self._exec, self._conn.close)
            self._conn = None
        if self._exec:
            self._exec.shutdown(wait=True)
            self._exec = None

    # ---------- low level ----------
    def _pg(self, sql: str) -> str:
        n = 0
        out = []
        for ch in sql:
            if ch == "?":
                n += 1
                out.append(f"${n}")
            else:
                out.append(ch)
        return "".join(out)

    async def _write(self, sql: str, params: tuple = (), script: bool = False):
        async with self._alock:
            if self.backend == "postgres":
                async with self._pool.acquire() as c:
                    if script:
                        await c.execute(sql)
                    else:
                        await c.execute(self._pg(sql), *params)
            else:
                def run():
                    with self._lock:
                        if script:
                            self._conn.executescript(sql)
                        else:
                            self._conn.execute(sql, params)
                        self._conn.commit()
                await asyncio.get_running_loop().run_in_executor(self._exec, run)

    async def query(self, sql: str, params: tuple = ()) -> list[dict]:
        if self.backend == "postgres":
            async with self._pool.acquire() as c:
                rows = await c.fetch(self._pg(sql), *params)
                return [dict(r) for r in rows]
        def run():
            with self._lock:
                cur = self._conn.execute(sql, params)
                return [dict(r) for r in cur.fetchall()]
        return await asyncio.get_running_loop().run_in_executor(self._exec, run)

    async def query_one(self, sql: str, params: tuple = ()) -> dict | None:
        rows = await self.query(sql, params)
        return rows[0] if rows else None

    async def insert(self, table: str, data: dict) -> str:
        data = dict(data)
        data.setdefault("id", _uid())
        data.setdefault("created_at", _now())
        cols = list(data.keys())
        ph = ",".join("?" for _ in cols)
        sql = f"INSERT INTO {table}({','.join(cols)}) VALUES({ph})"
        await self._write(sql, tuple(self._ser(table, data[c]) for c in cols))
        return str(data["id"])

    def _ser(self, table: str, v):
        return v

    # ---------- typed helpers (handle JSON columns) ----------
    @staticmethod
    def _enc(table: str, row: dict) -> dict:
        row = dict(row)
        for col in _JSON_COLS.get(table, ()):
            if col in row and not isinstance(row[col], str):
                row[col] = json.dumps(row[col], default=str)
        return row

    @staticmethod
    def _dec(table: str, row: dict | None) -> dict | None:
        if row is None:
            return None
        row = dict(row)
        for col in _JSON_COLS.get(table, ()):
            if col in row and isinstance(row[col], str):
                try:
                    row[col] = json.loads(row[col])
                except (json.JSONDecodeError, TypeError):
                    pass
        return row

    # targets
    async def create_target(self, name, endpoint_url, auth_header=None,
                            capabilities=None, canary_token=None, seeded=False) -> dict:
        row = {"name": name, "endpoint_url": endpoint_url, "auth_header": auth_header,
               "capabilities": capabilities or {}, "canary_token": canary_token,
               "system_prompt_seeded": int(seeded)}
        tid = await self.insert("targets", self._enc("targets", row))
        return await self.get_target(tid)

    async def get_target(self, tid) -> dict | None:
        r = await self.query_one("SELECT * FROM targets WHERE id=?", (tid,))
        return self._dec("targets", r)

    async def list_targets(self) -> list[dict]:
        rows = await self.query("SELECT * FROM targets ORDER BY created_at")
        return [self._dec("targets", r) for r in rows]

    # baselines
    async def latest_baseline(self, target_id) -> dict | None:
        r = await self.query_one(
            "SELECT * FROM target_baselines WHERE target_id=? "
            "ORDER BY version DESC LIMIT 1", (target_id,))
        return self._dec("target_baselines", r)

    async def add_baseline(self, target_id, **kw) -> int:
        prev = await self.latest_baseline(target_id)
        version = (prev["version"] + 1) if prev else 1
        row = {"target_id": target_id, "version": version, **kw}
        await self.insert("target_baselines", self._enc("target_baselines", row))
        return version

    # patterns & embeddings
    async def upsert_pattern(self, p: dict) -> tuple[str, bool]:
        existing = await self.query_one(
            "SELECT id FROM attack_patterns WHERE payload_hash=?", (p["payload_hash"],))
        if existing:
            return existing["id"], False
        pid = await self.insert("attack_patterns", self._enc("attack_patterns", p))
        return pid, True

    async def set_pattern_status(self, pid, status):
        await self._write(
            "UPDATE attack_patterns SET validation_status=?, validated_at=? WHERE id=?",
            (status, _now(), pid))

    async def save_embedding(self, pid, vec):
        await self._write(
            "INSERT INTO attack_embeddings(pattern_id, embedding) VALUES(?,?) "
            "ON CONFLICT(pattern_id) DO NOTHING" if self.backend == "postgres" else
            "INSERT OR IGNORE INTO attack_embeddings(pattern_id, embedding) VALUES(?,?)",
            (pid, json.dumps(vec)))

    async def list_patterns(self, statuses=("validated",), categories=None,
                            limit=None) -> list[dict]:
        sql = "SELECT * FROM attack_patterns"
        cond, params = [], []
        if statuses:
            cond.append("validation_status IN (%s)" % ",".join("?" * len(statuses)))
            params.extend(statuses)
        if categories:
            cond.append("category IN (%s)" % ",".join("?" * len(categories)))
            params.extend(categories)
        if cond:
            sql += " WHERE " + " AND ".join(cond)
        sql += " ORDER BY category, created_at"
        if limit:
            sql += f" LIMIT {int(limit)}"
        rows = await self.query(sql, tuple(params))
        return [self._dec("attack_patterns", r) for r in rows]

    async def corpus_counts(self) -> dict:
        rows = await self.query(
            "SELECT validation_status s, COUNT(*) n FROM attack_patterns GROUP BY s")
        out = {r["s"]: r["n"] for r in rows}
        live = await self.query_one(
            "SELECT COUNT(*) n FROM attack_patterns WHERE validated_live=1")
        out["validated_live"] = int(live["n"]) if live else 0
        return out

    async def set_validated_live(self, pid, ok: bool):
        await self._write("UPDATE attack_patterns SET validated_live=? WHERE id=?",
                          (1 if ok else 0, pid))

    async def all_embeddings(self) -> list[tuple[str, list[float]]]:
        rows = await self.query(
            "SELECT e.pattern_id, e.embedding FROM attack_embeddings e "
            "JOIN attack_patterns p ON p.id=e.pattern_id "
            "WHERE p.validation_status != 'dead'")
        return [(r["pattern_id"], json.loads(r["embedding"])) for r in rows]

    # rules
    async def list_rules(self, active_only=True) -> list[dict]:
        sql = "SELECT * FROM detection_rules"
        if active_only:
            sql += " WHERE active=1"
        return await self.query(sql + " ORDER BY name")

    async def seed_rules(self, rules: list[dict]):
        for r in rules:
            await self._write(
                ("INSERT INTO detection_rules(name,pattern,weight,category,active) "
                 "VALUES(?,?,?,?,1) ON CONFLICT(name) DO NOTHING")
                if self.backend == "postgres" else
                ("INSERT OR IGNORE INTO detection_rules(name,pattern,weight,category,active) "
                 "VALUES(?,?,?,?,1)"),
                (r["name"], r["pattern"], r["weight"], r.get("category")))

    async def discount_rules(self, names: list[str], factor: float = 0.9, floor: float = 1.0):
        for n in names:
            await self._write(
                "UPDATE detection_rules SET weight=MAX(?, weight*?), updated_at=? WHERE name=?",
                (floor, factor, _now(), n))

    # runs & executions
    async def create_run(self, target_id, baseline_version, comparison_id=None,
                         gate_policy: str = "permissive") -> str:
        return await self.insert("test_runs", {
            "target_id": target_id, "baseline_version": baseline_version,
            "comparison_id": comparison_id, "gate_policy": gate_policy,
            "status": "running", "started_at": _now()})

    async def runs_by_comparison(self, cid) -> list[dict]:
        return await self.query(
            "SELECT * FROM test_runs WHERE comparison_id=? ORDER BY started_at", (cid,))

    async def incr_run(self, run_id, **fields):
        sets = ",".join(f"{k}={k}+1" for k in fields)
        await self._write(f"UPDATE test_runs SET {sets} WHERE id=?", (run_id,))

    async def finish_run(self, run_id):
        await self._write(
            "UPDATE test_runs SET status='done', finished_at=? WHERE id=?", (_now(), run_id))

    async def get_run(self, run_id) -> dict | None:
        return await self.query_one("SELECT * FROM test_runs WHERE id=?", (run_id,))

    async def latest_run(self) -> dict | None:
        return await self.query_one(
            "SELECT * FROM test_runs ORDER BY started_at DESC LIMIT 1")

    async def add_execution(self, run_id, **kw) -> str:
        kw["run_id"] = run_id
        return await self.insert("test_executions", self._enc("test_executions", kw))

    async def list_executions(self, run_id) -> list[dict]:
        rows = await self.query(
            "SELECT * FROM test_executions WHERE run_id=? ORDER BY created_at", (run_id,))
        return [self._dec("test_executions", r) for r in rows]

    async def review_queue(self) -> list[dict]:
        rows = await self.query(
            "SELECT * FROM test_executions WHERE band='REVIEW' AND audit_seq IS NOT NULL "
            "AND audit_seq NOT IN (SELECT audit_seq FROM fp_review_labels) "
            "ORDER BY created_at DESC LIMIT 100")
        return [self._dec("test_executions", r) for r in rows]

    # alerts
    async def add_alert(self, execution_id, run_id, severity, title, detail):
        return await self.insert("alerts", self._enc("alerts", {
            "execution_id": execution_id, "run_id": run_id,
            "severity": severity, "title": title, "detail": detail}))

    # audit chain (single-writer via _alock inside _write sequences)
    async def audit_append(self, payload: dict) -> int:
        async with self._alock:
            tail = await self.query_one(
                "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1")
            prev = tail["hash"] if tail else "0" * 64
            payload = dict(payload)
            payload.setdefault("ts", _now())
            from .textnorm import canonical_json, sha256_hex
            h = sha256_hex(prev + canonical_json(payload))
            if self.backend == "postgres":
                row = await self.query_one(
                    "INSERT INTO audit_log(prev_hash,payload,hash,created_at) "
                    "VALUES($1,$2,$3,$4) RETURNING seq",
                    (prev, json.dumps(payload, default=str), h, _now()))
                return int(row["seq"])
            def run():
                with self._lock:
                    cur = self._conn.execute(
                        "INSERT INTO audit_log(prev_hash,payload,hash,created_at) "
                        "VALUES(?,?,?,?)",
                        (prev, json.dumps(payload, default=str), h, _now()))
                    self._conn.commit()
                    return int(cur.lastrowid)
            return await asyncio.get_running_loop().run_in_executor(self._exec, run)

    async def audit_verify(self, run_id: str | None = None) -> dict:
        rows = await self.query("SELECT * FROM audit_log ORDER BY seq")
        from .textnorm import canonical_json, sha256_hex
        prev = "0" * 64
        first_bad = None
        run_records = 0
        for r in rows:
            payload = json.loads(r["payload"])
            expect = sha256_hex(prev + canonical_json(payload))
            if r["hash"] != expect or r["prev_hash"] != prev:
                if first_bad is None:
                    first_bad = r["seq"]
            prev = r["hash"]
            if run_id and payload.get("run_id") == run_id:
                run_records += 1
        out = {"valid": first_bad is None, "checked": len(rows),
               "first_bad_seq": first_bad}
        if run_id:
            out["run_id"] = run_id
            out["run_records"] = run_records
        return out

    async def audit_tail(self, n=1) -> list[dict]:
        rows = await self.query("SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?", (n,))
        return [self._dec("audit_log", r) for r in rows]

    # fp labels
    async def add_fp_label(self, audit_seq, label, labeler) -> str:
        return await self.insert("fp_review_labels", {
            "audit_seq": audit_seq, "label": label, "labeler": labeler})
