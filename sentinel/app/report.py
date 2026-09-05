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


def _base_limitations(jury_members: list[str], jury_mode: str = "heuristic") -> list[str]:
    mode_line = {
        "heuristic": "JURY MODE: HEURISTIC — all three judges are offline keyword heuristics "
                     "(no API keys). Numbers demonstrate pipeline correctness, not "
                     "detection generality; see docs/evidence/ for live-model runs.",
        "mixed": "JURY MODE: MIXED — some judges are live providers, some heuristic.",
        "live": "JURY MODE: LIVE — three independent model families voted on every verdict.",
    }[jury_mode]
    return [
        mode_line,
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
                                    "worst_score": 0.0, "gate_flagged": 0,
                                    "severity": p.get("severity", "medium"),
                                    "remediation": p.get("remediation", ""),
                                    "owasp_llm": p.get("owasp_llm", ""),
                                    "mitre_atlas": p.get("mitre_atlas", "")})
        c["total"] += 1
        if e["band"] == "BLOCK":
            c["gate_flagged"] = c.get("gate_flagged", 0) + 1
        if e["band"] == "BLOCK" and not e.get("verdict") or e.get("verdict") == "BLOCKED":
            c["blocked"] += 1
        elif e.get("verdict") == "SUCCESSFUL":
            c["successful"] += 1
        elif e.get("verdict") == "RESISTED":
            c["resisted"] += 1
        else:
            c["inconclusive"] += 1
        c["worst_score"] = max(c["worst_score"], float(e.get("fused_score") or 0))

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for e in execs:
        ds = e.get("derived_severity") or _sev(e.get("response_risk"))
        if e.get("verdict") == "SUCCESSFUL" or e.get("response_risk") is not None:
            sev[ds] = sev.get(ds, 0) + 1
    execs = sorted(execs, key=lambda e: -(float(e.get("response_risk") or 0)
                                          + float(e.get("fused_score") or 0) / 1000))
    reached = run["resisted"] + run["successful"] + run["inconclusive"]
    resistance_rate = round(run["resisted"] / reached, 3) if reached else None
    weak = [c for c in by_cat.values() if c["successful"] > 0]

    policy = run.get("gate_policy") or "permissive"
    policy_label = "permissive (batch)" if policy == "permissive" else "enforcing"
    policy_note = ("In batch mode the request gate reports but does not enforce, so every "
                   "attack reaches the target and the target's own resistance is measured; "
                   "the response gate is the control."
                   if policy == "permissive" else
                   "Request-gate BLOCK verdicts were enforced: blocked attacks never reached "
                   "the target (live-proxy semantics).")
    report = {
        "run": run,
        "target": {"name": target.get("name"), "endpoint": target.get("endpoint_url"),
                   "capabilities": target.get("capabilities", {})},
        "summary": {
            "jury_mode": deps.jury.mode if deps.jury else "heuristic",
            "corpus_live_validated": (await store.corpus_counts()).get("validated_live", 0),
            "total": run["total"], "resisted": run["resisted"],
            "successful": run["successful"], "inconclusive": run["inconclusive"],
            "blocked_at_gate": run["blocked"] if policy != "permissive" else 0,
            "gate_would_block": run["blocked"],
            "gate_policy": policy_label, "gate_policy_note": policy_note,
            "redacted": run["redacted"],
            "resistance_rate": resistance_rate,
            "severity_breakdown": sev,
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
             "remediation": pats.get(e.get("pattern_id"), {}).get("remediation"),
             "severity": pats.get(e.get("pattern_id"), {}).get("severity"),
             "taxonomy_source": pats.get(e.get("pattern_id"), {}).get("taxonomy_source"),
             "provenance_note": pats.get(e.get("pattern_id"), {}).get("provenance_note"),
             "owasp_llm": pats.get(e.get("pattern_id"), {}).get("owasp_llm"),
             "mitre_atlas": pats.get(e.get("pattern_id"), {}).get("mitre_atlas"),
             "mutation": pats.get(e.get("pattern_id"), {}).get("subcategory")}
            for e in execs],
        "limitations": _base_limitations(deps.jury.describe() if deps.jury else [],
                                         deps.jury.mode if deps.jury else "heuristic"),
        "capabilities_warning": _capabilities_warning(target, by_cat),
    }
    return report


# ---------------------------------------------------------------------------
# Markdown export (v2.4 step 6) — the report a judge can hold.
# ---------------------------------------------------------------------------
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "low"
    return "critical" if s >= 85 else "high" if s >= 70 else "medium" if s >= 40 else "low"


def _fmt(v, nd=1):
    try:
        return f"{float(v):.{nd}f}"
    except (TypeError, ValueError):
        return "—"


def _excerpt(text, n=240):
    t = (text or "").replace("\n", " ").strip()
    return (t[:n] + "…") if len(t) > n else t


def render_markdown(rep: dict, audit: dict | None = None) -> str:
    run, s, tgt = rep["run"], rep["summary"], rep["target"]
    by_cat = rep["by_category"]
    execs = rep["executions"]
    pats = {p["pattern_id"]: p for p in rep["provenance"]}
    findings = sorted(execs, key=lambda e: -(float(e.get("response_risk") or 0)
                                            + float(e.get("fused_score") or 0) / 1000))
    crit = sum(1 for e in execs if (e.get("derived_severity") or _sev(e.get("response_risk")))
               == "critical" and e.get("verdict") == "SUCCESSFUL")
    worst = s["top_failing_categories"][0] if s["top_failing_categories"] else None
    top_fix = next((r["remediation"] for r in s["suggested_remediations"]), None)
    chain = ("VALID" if audit and audit.get("valid") else
             ("BROKEN at seq %s" % audit.get("first_bad_seq") if audit else "not verified"))
    rr = s["resistance_rate"]
    lines = [
        f"# SENTINEL security test report — {tgt.get('name')}",
        "",
        f"- **Run:** `{run['id']}` · started {run.get('started_at')} · status {run.get('status')}",
        f"- **Target:** {tgt.get('name')} (`{tgt.get('endpoint')}`) · capabilities {tgt.get('capabilities') or {}}",
        f"- **Jury mode:** {s.get('jury_mode', 'heuristic')} · **baseline:** v{s.get('baseline_version')} "
        f"· **gate policy:** {s.get('gate_policy', 'enforcing')}",
        f"- **Corpus:** {run['total']} attacks executed · {s.get('corpus_live_validated', 0)} live-validated",
        "",
        "## Executive summary",
        "",
        f"1. **Resistance rate {(_fmt(rr * 100, 0) + '%') if rr is not None else 'n/a'}** — "
        f"{s['resisted']} resisted, {s['successful']} compromised, {s['inconclusive']} inconclusive "
        f"out of {run['total']} attacks that reached the target.",
        f"2. **Worst category:** {worst or 'none — no successful attack'}.",
        f"3. **Critical findings:** {crit} (attack succeeded *and* observed severity ≥ 85/100).",
        f"4. **First fix:** {top_fix or 'no remediation required from this run'}",
        f"5. **Audit chain:** {chain} · {s.get('redacted', 0)} responses redacted · "
        f"{s.get('gate_would_block', s.get('blocked_at_gate', 0))} flagged by the request gate.",
        "",
    ]
    if s.get("gate_policy_note"):
        lines += [f"> {s['gate_policy_note']}", ""]
    lines += ["## Results by category", "",
              "| category | total | resisted | compromised | gate-flagged | worst score | OWASP | ATLAS |",
              "|---|---|---|---|---|---|---|---|"]
    for c in by_cat:
        lines.append(f"| {c['category']} | {c['total']} | {c['resisted']} | {c['successful']} | "
                     f"{c['blocked']} | {_fmt(c['worst_score'])} | {c.get('owasp_llm', '')} | "
                     f"{c.get('mitre_atlas', '')} |")
    lines += ["", "## Top findings (ranked by observed response risk)", ""]
    for i, e in enumerate(findings[:15], 1):
        p = pats.get(e.get("pattern_id"), {})
        rs, js = e.get("request_scores") or {}, e.get("jury") or {}
        rationale = next((m.get("explanation") for m in js.get("members", [])
                          if m.get("ok") and m.get("explanation")), None)
        kcm = rs.get("known_corpus_match") or {}
        lines += [
            f"### {i}. {p.get('category', '?')} — {e.get('verdict')} "
            f"({e.get('derived_severity') or _sev(e.get('response_risk'))})",
            "",
            f"- **Payload** ({p.get('mutation') or 'seed'}): `{_excerpt(e.get('variant_text'), 200)}`",
            f"- **Request gate:** {e.get('band')} · fused {_fmt(e.get('fused_score'))} · "
            f"confidence {e.get('confidence')} · rules {rs.get('rule_hits') or []}"
            + (f" · known corpus match cos {kcm.get('cos')}" if kcm else ""),
            f"- **Target response:** {_excerpt(e.get('response_excerpt') or e.get('sanitized') or '', 240) or '(blocked at gate / none)'}",
            f"- **Jury:** {js.get('agreement', 'n/a')} → {js.get('consensus') or 'n/a'}"
            + (f" — {rationale}" if rationale else ""),
            f"- **Drift:** {e.get('drift_score') if e.get('drift_score') is not None else '—'} · "
            f"**response risk:** {_fmt(e.get('response_risk'))} (conf {e.get('response_confidence', '—')})",
            f"- **Severity:** expected {p.get('severity') or (e.get('source_severity') or '—')} · "
            f"observed {e.get('derived_severity') or _sev(e.get('response_risk'))}",
            f"- **Remediation:** {p.get('remediation') or '—'}",
            f"- audit seq #{e.get('audit_seq')}",
            "",
        ]
    lines += ["## Remediation priorities", ""]
    if s["suggested_remediations"]:
        for r in s["suggested_remediations"]:
            lines.append(f"- **{r['category']}** ({r['severity']}): {r['remediation']}")
    else:
        lines.append("- No category was compromised in this run.")
    lines += ["", "## Limitations (declared, not hidden)", ""]
    lines += [f"- {l}" for l in rep["limitations"]]
    if rep.get("capabilities_warning"):
        lines += ["", f"> {rep['capabilities_warning']}"]
    seqs = [e.get("audit_seq") for e in execs if e.get("audit_seq") is not None]
    lines += ["", "---",
              f"Evidence: audit seq {min(seqs) if seqs else '—'}–{max(seqs) if seqs else '—'} · "
              f"chain {chain} · generated by SENTINEL v2.4", ""]
    return "\n".join(lines)


def render_leaderboard_markdown(board: dict) -> str:
    lines = [f"# SENTINEL leaderboard — comparison `{board['comparison_id']}`", "",
             "| # | target | resistance | compromised | inconclusive | gate-flagged | redacted | worst category | jury | gate |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for i, b in enumerate(board["leaderboard"], 1):
        rr = b.get("resistance_rate")
        lines.append(f"| {i} | {b['target_name']} | {(_fmt(rr * 100, 0) + '%') if rr is not None else 'n/a'} | "
                     f"{b['compromised']} | {b['inconclusive']} | {b['blocked_at_gate']} | {b['redacted']} | "
                     f"{b.get('top_failing_category') or '—'} | {b.get('jury_mode', '—')} | "
                     f"{b.get('gate_policy', '—')} |")
    return "\n".join(lines) + "\n"
