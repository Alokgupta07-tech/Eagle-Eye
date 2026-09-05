"""v2.4 step 3: jury_mode honesty + evidence_run behaviour."""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.jury import HTTPJudge, JuryPanel  # noqa: E402


def _panel(**keys):
    return JuryPanel(Settings(JURY_MODELS="anthropic/a,openai/b,google/c", **keys))


def test_jury_mode_heuristic_mixed_live():
    assert _panel().mode == "heuristic"
    assert _panel(ANTHROPIC_API_KEY="fake").mode == "mixed"
    assert _panel(ANTHROPIC_API_KEY="fake", OPENAI_API_KEY="fake",
                  GOOGLE_API_KEY="fake").mode == "live"


async def test_jury_mode_in_verdict_and_health(deps):
    v = await deps.jury._run("response", attack="x", response="I can't help with that.")
    assert v["mode"] == "heuristic"
    from app.main import create_app
    import httpx
    app = create_app(deps.settings)
    app.state.deps = deps
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as c:
        h = (await c.get("/healthz")).json()
    assert h["jury_mode"] == "heuristic"


async def test_evidence_run_without_keys_exits_zero(tmp_path, capsys):
    from scripts.evidence_run import main
    rc = await main(out_root=tmp_path, settings=Settings(
        DATABASE_URL=f"sqlite:///{tmp_path}/e.db"))
    assert rc == 0
    assert "no ANTHROPIC_API_KEY" in capsys.readouterr().out
    assert not list(tmp_path.glob("*-*"))


async def test_evidence_run_with_fake_provider_writes_files(tmp_path, monkeypatch):
    """A fake live target + fake judge stand in for the network; the four evidence
    files must be written and internally consistent."""
    import app.runner as runner
    import app.baseline as baseline
    from app import target_client

    real = target_client.call_target

    async def fake_call(target, messages, sid, settings, timeout=30.0, tools=None):
        if target["endpoint_url"] == "internal://anthropic":
            return "I'm sorry, but I can't help with that request."
        return await real(target, messages, sid, settings, timeout=timeout, tools=tools)

    monkeypatch.setattr(runner, "call_target", fake_call)
    monkeypatch.setattr(baseline, "call_target", fake_call)
    monkeypatch.setattr(target_client, "call_target", fake_call)

    async def fake_ask(self, prompt):
        return {"verdict": "RESISTED", "attack_type": "n/a", "risk_score": 5.0,
                "confidence": 0.9, "explanation": "fake live judge"}
    monkeypatch.setattr(HTTPJudge, "_ask", fake_ask)

    from scripts.evidence_run import main
    s = Settings(DATABASE_URL=f"sqlite:///{tmp_path}/e.db", ANTHROPIC_API_KEY="fake",
                 BASELINE_PROBES=5, JURY_MODELS="anthropic/a,openai/b,google/c")
    rc = await main(out_root=tmp_path, settings=s, limit=6)
    assert rc == 0
    out = next(p for p in tmp_path.iterdir() if p.is_dir() and p.name.endswith("-anthropic"))
    for f in ("report.json", "report.md", "leaderboard.json", "SUMMARY.md"):
        assert (out / f).exists(), f
    rep = json.loads((out / "report.json").read_text())
    assert rep["summary"]["jury_mode"] == "mixed"
    assert "Executive summary" in (out / "report.md").read_text()
    board = json.loads((out / "leaderboard.json").read_text())
    assert len(board["leaderboard"]) == 3
