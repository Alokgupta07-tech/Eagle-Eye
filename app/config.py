"""SENTINEL configuration. Every field maps 1:1 to an env var (see .env.example)."""
from __future__ import annotations

import secrets
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

_GENERATED_ADMIN_KEY = secrets.token_urlsafe(24)  # per-boot random when not pinned


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = "sqlite:///./data/sentinel.db"
    REDIS_URL: str = "redis://localhost:6379/0"

    EMBEDDER: str = "auto"  # auto | st | offline

    JURY_MODELS: str = "anthropic/claude-sonnet-4-20250514,openai/gpt-4o,google/gemini-2.0-flash"
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    GOOGLE_API_KEY: str = ""

    SESSION_WINDOW: int = 20
    SESSION_TTL_S: int = 1800
    SIMILARITY_STRONG: float = 0.85
    BAND_REVIEW_LO: float = 30.0
    BAND_BLOCK_HI: float = 70.0
    CONF_MIN_BLOCK: float = 0.4
    FUSION_W: str = "rules:0.35,similarity:0.30,obfuscation:0.10,judge:0.25"
    FUSION_RESPONSE_W: str = "leakage:0.45,indicators:0.25,drift:0.10,judge:0.20"
    OBFUSCATION_BONUS: float = 15.0
    DRIFT_K: float = 2.5
    BASELINE_PROBES: int = 50
    RULE_REFRESH_S: int = 300

    CORPUS_VALIDATION_TARGET: str = "internal://mock"   # optionally a live provider target
    SENTINEL_ADMIN_KEY: str = ""          # empty -> random per boot (printed at startup)
    ENTROPY_THRESHOLD: float = 4.0        # Shannon bits/char for generic secret detection
    ENTROPY_MIN_LEN: int = 20
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PROXY_PER_MIN: int = 30    # per client IP, sliding 60s window
    RATE_LIMIT_RUNS_PER_MIN:  int = 6
    ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"
    OPENAI_MODEL: str = "gpt-4o-mini"

    VULN_EXTRACTION: bool = True
    VULN_ROLEPLAY: bool = True
    VULN_DELIMITER: bool = True
    VULN_LEAK_KEYS: bool = True
    VULN_DECODE: bool = True
    VULN_TOOL_POISON: bool = True     # v2.3: MCP-style tool-definition poisoning knob
    VULN_HIDDEN: bool = True          # v2.4: obey instructions hidden in markup/zero-width
    VULN_FEWSHOT: bool = True         # v2.4: continue fabricated few-shot compliance
    MOCK_CANARY: str = "CANARY-9F2A41C8"
    MOCK_API_KEY: str = "SK-DEMO-9F27KQZ41LX8M3H7T2V5B6N1"

    @property
    def fusion_weights(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for part in self.FUSION_W.split(","):
            k, v = part.split(":")
            out[k.strip()] = float(v)
        return out

    @property
    def response_weights(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for part in self.FUSION_RESPONSE_W.split(","):
            k, v = part.split(":")
            out[k.strip()] = float(v)
        return out

    @property
    def jury_specs(self) -> list[tuple[str, str]]:
        specs = []
        for part in self.JURY_MODELS.split(","):
            part = part.strip()
            if not part:
                continue
            provider, _, model = part.partition("/")
            specs.append((provider.strip(), model.strip()))
        return specs

    @property
    def admin_key(self) -> str:
        return self.SENTINEL_ADMIN_KEY or _GENERATED_ADMIN_KEY

    @property
    def is_postgres(self) -> bool:
        return self.DATABASE_URL.startswith("postgres")


@lru_cache
def get_settings() -> Settings:
    return Settings()
