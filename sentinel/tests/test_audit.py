"""Sealed audit chain: verification + tamper evidence (P6)."""


async def test_chain_appends_and_verifies(deps):
    for i in range(3):
        await deps.audit.seal({"run_id": "t", "i": i, "mode": "batch"})
    out = await deps.audit.verify()
    assert out["valid"] is True and out["checked"] == 3
    out2 = await deps.audit.verify(run_id="t")
    assert out2["run_records"] == 3


async def test_tamper_breaks_chain(deps):
    for i in range(4):
        await deps.audit.seal({"i": i})
    # silently alter one stored record
    await deps.store._write(
        "UPDATE audit_log SET payload='{\"i\": 999}' WHERE seq=2")
    out = await deps.audit.verify()
    assert out["valid"] is False
    assert out["first_bad_seq"] == 2
