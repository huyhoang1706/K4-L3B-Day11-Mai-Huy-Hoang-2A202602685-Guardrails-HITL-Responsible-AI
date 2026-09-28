"""Offline integration checks for the assignment suite and its artifacts."""
import asyncio
import json
from pathlib import Path

import jsonschema
import pytest

import assignment.pipeline as suite

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "schemas/results.schema.json").read_text())


def make_pipeline():
    audit, monitor = suite.build_observability()
    return {
        "plugins": suite.build_production_plugins(max_requests=2),
        "audit": audit,
        "monitor": monitor,
    }


def temporary_outputs(monkeypatch, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    monkeypatch.chdir(src)
    monkeypatch.setattr(suite, "__file__", str(src / "assignment" / "pipeline.py"))
    return tmp_path / "outputs"


def test_suite_callbacks_artifacts_and_repeatability(monkeypatch, tmp_path):
    output_dir = temporary_outputs(monkeypatch, tmp_path)
    pipeline = make_pipeline()
    result = asyncio.run(suite.run_assignment_suite(pipeline))
    jsonschema.validate(result, SCHEMA)
    assert result["execution_mode"] == "offline-fixtures"
    assert all(not row["blocked"] for row in result["safe_queries"])
    assert sum(row["blocked"] for row in result["attack_queries"]) >= 5
    assert result["attack_queries"][-2]["layer"] == "output_guardrail"
    assert "[REDACTED]" in result["attack_queries"][-2]["response_preview"]
    assert result["attack_queries"][-1]["layer"] == "egress"
    assert result["rate_limit"] == {
        "max_requests": 2, "window_seconds": 60,
        "sent": 4, "passed": 2, "blocked": 2, "rate_limit_hits": 2,
    }
    assert result["edge_cases"][0]["blocked"]
    assert all(not row["blocked"] for row in result["edge_cases"][1:])
    assert json.loads((output_dir / "results.json").read_text()) == result
    logs = json.loads((output_dir / "audit_log.json").read_text())
    metrics = json.loads((output_dir / "metrics.json").read_text())
    assert len(logs) == metrics["total_requests"] == 21
    assert metrics["blocked_requests"] == sum(row["blocked"] for row in logs)
    assert metrics["rate_limit_hits"] == 2
    assert metrics["judge_checks"] == 0
    assert len({row["request_id"] for row in logs}) == len(logs)
    assert all(row["latency"].endswith(" ms") for row in logs)
    assert all(float(row["latency"].removesuffix(" ms")) >= 0 for row in logs)
    assert not (tmp_path / "src" / "outputs").exists()

    second = asyncio.run(suite.run_assignment_suite(pipeline))
    assert all(not row["blocked"] for row in second["safe_queries"])
    assert second["rate_limit"] == result["rate_limit"]
    assert pipeline["monitor"].total_requests == 42
    assert not pipeline["audit"]._open


@pytest.mark.parametrize("asynchronous", [False, True])
def test_suite_uses_supplied_responder(monkeypatch, tmp_path, asynchronous):
    temporary_outputs(monkeypatch, tmp_path)
    pipeline = make_pipeline()
    calls = []

    def respond(text):
        calls.append(text)
        return "Please visit official banking channels for account assistance."

    async def async_respond(text):
        return respond(text)

    pipeline["respond"] = async_respond if asynchronous else respond
    result = asyncio.run(suite.run_assignment_suite(pipeline))
    assert result["execution_mode"] == "responder"
    assert calls
    assert len(calls) == pipeline["plugins"][2].total_count
    assert all(not row["blocked"] for row in result["safe_queries"])
    assert result["rate_limit"]["rate_limit_hits"] == 2
    assert all("response_fixture" not in row for row in result["safe_queries"])


def test_responder_errors_are_not_replaced_by_fixtures(monkeypatch, tmp_path):
    output_dir = temporary_outputs(monkeypatch, tmp_path)
    pipeline = make_pipeline()

    async def respond(text):
        raise RuntimeError("provider unavailable")

    pipeline["respond"] = respond
    with pytest.raises(RuntimeError, match="provider unavailable"):
        asyncio.run(suite.run_assignment_suite(pipeline))
    assert not (output_dir / "results.json").exists()


def test_audit_latency_is_formatted_in_milliseconds(monkeypatch):
    from datetime import datetime, timezone
    import assignment.audit_log as audit_module

    now = datetime(2026, 9, 28, tzinfo=timezone.utc)

    class FixedClock:
        @staticmethod
        def now(tz):
            return now

    monkeypatch.setattr(audit_module, "datetime", FixedClock)
    audit = audit_module.AuditLogPlugin()
    audit.record_input(user_id="user", text="input", request_id="request")
    audit._open["request/user"]["started_at"] -= 0.125
    audit.record_output(user_id="user", text="output", request_id="request")
    assert audit.logs[0]["latency"] == "125.00 ms"
