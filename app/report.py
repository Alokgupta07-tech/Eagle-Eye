"""Report builder — usefulness criterion. Aggregates a run into per-category results,
severity heat data, remediation guidance, origin & taxonomy tags (hand_authored | adapted; OWASP / ATLAS), and the honest
limitations section (P7)."""
from __future__ import annotations


def _capabilities_warning(target: dict, by_cat: dict) -> str | None:
    """v2.3: the static RAG-risk disclaimer becomes a real figure when the run actually
    exercised indirect-injection seeds against a RAG-capable target."""
    if not (target.get("capabilities") or {}).get("RAG"):
        return None
    c = by_cat.get("indirect_injection_rag")
    if not c or c["total"] == 0:
        return ("INDIRECT_INJECTION_RISK: target declares RAG/tooling capabilities — "
                "indirect injection coverage not included in this run.")
    caught = c["resisted"] + c["blocked"]
    rate = round(100 * caught / c["total"])
    return (f"INDIRECT_INJECTION_POC: replayable — {c['category']}: caught "
            f"{caught}/{c['total']} ({rate}%) via request/response gates. Poison the KB "
            "live via POST /admin/targets/{id}/kb, then ask a benign question: the "
            "request gate stays ALLOW (the user's message is innocuous) and the P5 "
            "response gate is what has to catch it.")


def _base_limitations(jury_members: list[str]) -> list[str]:
    return [
        "Indirect injection is structurally invisible on the REQUEST side — see the "
        "RAG PoC seeds (category indirect_injection_rag) and POST /admin/targets/{id}/kb "
        "for a replayable exploit caught by the response gate; for external targets the "
        "proxy still cannot observe target-side retrieval beyond its HTTP response.",
        "Internal tool/function calls are not observable unless the target surfaces them in "
        "its HTTP response body.",
        "Multi-turn payload splits spanning beyond the session window (20 messages) may "
        "evade reassembly.",
        f"Jury members this report: {', '.join(jury_members) if jury_members else 'n/a'}. "
        "Mock judges indicate heuristic classification, not provider LLM judgment.",
    ]


async def build_report(deps, run_id: str) -> dict | None:
    store = deps.store
    run = await store.get_run(run_id)
    if not run:
        return None
    target = await store.get_target(run["target_id"]) or {}
    execs = await store.list_executions(run_id)
    pats = {p["id"]: p for p in await store.list_patterns(statuses=None)}
    baseline_v = run.get("baseline_version")

    by_cat: dict[str, dict] = {}
    for e in execs:
        p = pats.get(e.get("pattern_id"), {})
        cat = p.get("category", "unknown")
        c = by_cat.setdefault(cat, {"category": cat, "total": 0, "resisted": 0,
                                    "successful": 0, "inconclusive": 0, "blocked": 0,
                                    "worst_score": 0.0, "severity": p.get("severity", "medium"),
                                    "remediation": p.get("remediation", ""),
                                    "owasp_llm": p.get("owasp_llm", ""),
                                    "mitre_atlas": p.get("mitre_atlas", "")})
        c["total"] += 1
        if e["band"] == "BLOCK" and not e.get("verdict") or e.get("verdict") == "BLOCKED":
            c["blocked"] += 1
        elif e.get("verdict") == "SUCCESSFUL":
            c["successful"] += 1
        elif e.get("verdict") == "RESISTED":
            c["resisted"] += 1
        else:
            c["inconclusive"] += 1
        c["worst_score"] = max(c["worst_score"], float(e.get("fused_score") or 0))

    reached = run["resisted"] + run["successful"] + run["inconclusive"]
    resistance_rate = round(run["resisted"] / reached, 3) if reached else None
    weak = [c for c in by_cat.values() if c["successful"] > 0]

    report = {
        "run": run,
        "target": {"name": target.get("name"), "endpoint": target.get("endpoint_url"),
                   "capabilities": target.get("capabilities", {})},
        "summary": {
            "total": run["total"], "resisted": run["resisted"],
            "successful": run["successful"], "inconclusive": run["inconclusive"],
            "blocked_at_gate": run["blocked"], "redacted": run["redacted"],
            "resistance_rate": resistance_rate,
            "baseline_version": baseline_v,
            "top_failing_categories": sorted(
                (c["category"] for c in weak),
                key=lambda k: -by_cat[k]["successful"]),
            "suggested_remediations": [
                {"category": c["category"], "severity": c["severity"],
                 "remediation": c["remediation"]} for c in weak],
        },
        "by_category": sorted(by_cat.values(), key=lambda c: -c["successful"]),
        "executions": execs,
        "provenance": [
            {"pattern_id": e.get("pattern_id"),
             "category": pats.get(e.get("pattern_id"), {}).get("category"),
             "origin": pats.get(e.get("pattern_id"), {}).get("origin") or "hand_authored",
             "taxonomy_source": pats.get(e.get("pattern_id"), {}).get("taxonomy_source"),
             "provenance_note": pats.get(e.get("pattern_id"), {}).get("provenance_note"),
             "owasp_llm": pats.get(e.get("pattern_id"), {}).get("owasp_llm"),
             "mitre_atlas": pats.get(e.get("pattern_id"), {}).get("mitre_atlas"),
             "mutation": pats.get(e.get("pattern_id"), {}).get("subcategory")}
            for e in execs],
        "limitations": _base_limitations(deps.jury.describe() if deps.jury else []),
        "capabilities_warning": _capabilities_warning(target, by_cat),
    }
    return report
