"""Deterministic rule engine. Rules live in Postgres; an in-memory compiled cache
serves the hot path. Hot-reload via /admin/reload-rules + periodic refresh (stale-cache fix).
No single rule ever blocks alone — rules only contribute weighted score (P2)."""
from __future__ import annotations

import re

# (name, pattern, weight, category) — weights tuned so one benign keyword never convicts,
# and multi-signal composite attacks cross the BLOCK band when the jury concurs.
SEED_RULES = [
    {"name": "role_override", "weight": 35.0, "category": "direct_override",
     "pattern": r"\bignore\b\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+"
                r"(instructions?|rules?|prompts?|directions?)"},
    {"name": "forget_instructions", "weight": 30.0, "category": "direct_override",
     "pattern": r"\bforget\b[^.]{0,40}\b(everything|instructions?|rules?|training)\b"},
    {"name": "persona_hijack", "weight": 28.0, "category": "roleplay_persona",
     "pattern": r"\byou are now\b|\bact as\b[^.]{0,40}\b(unrestricted|uncensored|evil|dan|"
                r"no (rules|restrictions|limits))\b|\bDAN\b"},
    {"name": "developer_mode", "weight": 25.0, "category": "hierarchy_confusion",
     "pattern": r"\bdeveloper mode\b|\bjailbreak\b|\bgod mode\b"},
    {"name": "extraction_ask", "weight": 28.0, "category": "system_prompt_extraction",
     "pattern": r"\b(repeat|print|show|reveal|output|dump|display|tell me)\b[^.]{0,50}"
                r"\b(instructions?|system prompt|system message|configuration|"
                r"config|initial prompt|verbatim)\b"},
    {"name": "hierarchy_claim", "weight": 15.0, "category": "hierarchy_confusion",
     "pattern": r"\b(the admin|administrator|developer|the (openai|anthropic) team)\s+"
                r"(said|told|authorized|authori[sz]ed|allows?|instructs?)\b"},
    {"name": "fake_system_tag", "weight": 20.0, "category": "fake_delimiters",
     "pattern": r"<\s*/?\s*(system|im_start|im_end)\s*>|\[INST\]|\[SYSTEM\]|"
                r"```\s*(system|instruction)|###\s*instruction"},
    {"name": "secret_exfil_ask", "weight": 25.0, "category": "data_exfiltration",
     "pattern": r"\b(print|reveal|show|give|list|output|leak|disclose)\b[^.]{0,45}"
                r"\b(api ?keys?|secret keys?|credentials?|passwords?|tokens?|secrets?)\b"},
    {"name": "canary_probe", "weight": 18.0, "category": "system_prompt_extraction",
     "pattern": r"\bCANARY-[0-9A-Fa-f]{4,}\b"},
    {"name": "decode_follow", "weight": 15.0, "category": "encoded_payloads",
     "pattern": r"\bdecode\b[^.]{0,30}\b(follow|execute|obey|carry out|do)\b"},
    {"name": "tool_call_forge", "weight": 18.0, "category": "tool_call_abuse",
     "pattern": r"\"(name|function)\"\s*:\s*\"[a-z_]+\"|\bcall(ing)?\s+the\s+"
                r"(function|tool)\b|\bdelete_all_users\b"},
    {"name": "lang_switch_override", "weight": 30.0, "category": "language_switching",
     "pattern": r"\b(ignorez|oubliez)\b[^.]{0,50}\b(instructions?|consignes)\b|"
                r"\b(r[ée]v[ée]lez|affichez|r[ée]p[ée]tez)\b[^.]{0,45}\b(instructions?|syst[èe]me|configuration|prompt|jetons)\b"},
    {"name": "context_smuggle", "weight": 22.0, "category": "quoted_context_smuggling",
     "pattern": r"\boutput the word\b|\b(summari[sz]e|translate|tidy|review|draft)\b[^:]{0,60}:"
                r"\s*['\"][^'\"]{0,200}\b(ignore|instruction|output|obey|execute)\b"},
    {"name": "refusal_suppression", "weight": 20.0, "category": "direct_override",
     "pattern": r"\b(do not|don'?t|never)\s+(apologi[sz]e|refuse|say (you )?can'?t|"
                r"mention (your )?(policy|policies|guidelines)|add (a )?disclaimers?)\b|"
                r"\brespond only with\b|\bno disclaimers?\b|\bwithout (any )?(warnings?|caveats?)\b"},
    {"name": "override_generic", "weight": 12.0, "category": "direct_override",
     "pattern": r"\b(with no|without any|no)\s+(restrictions?|rules?|limits?|filters?)\b"},
]


class RuleEngine:
    def __init__(self):
        self.compiled: list[tuple[str, float, re.Pattern]] = []
        self.rule_count = 0

    async def reload(self, store):
        rows = await store.list_rules(active_only=True)
        self.compiled = [(r["name"], float(r["weight"]),
                          re.compile(r["pattern"], re.IGNORECASE | re.DOTALL))
                         for r in rows]
        self.rule_count = len(self.compiled)

    def check(self, texts: list[str]) -> dict:
        """Check every rule against every text variant. Each rule counted once (max signal)."""
        hits = []
        score = 0.0
        for name, weight, rx in self.compiled:
            for i, t in enumerate(texts):
                if rx.search(t):
                    hits.append({"name": name, "weight": weight, "variant": i})
                    score += weight
                    break
        return {"score": min(100.0, score), "hits": hits}

    def suspicious(self, text: str) -> bool:
        """Cheap boolean used by the obfuscation-bonus delta check."""
        return any(rx.search(text) for _, _, rx in self.compiled)
