from __future__ import annotations

import json

from cyberorion.reporting import (
    build_report_context,
    finalize_task_report,
    generate_report_artifacts,
    render_report_tex,
    should_generate_report,
)
from cyberorion.reporting import _extract_agent_events
from cyberorion.verification_samples import (
    materialize_verification_samples,
    verification_sample_definitions,
)


def test_verification_samples_cover_all_requested_task_types() -> None:
    samples = verification_sample_definitions()
    assert {sample["task_type"] for sample in samples} == {
        "ctf",
        "attack_chain",
        "code_repair",
    }
    for sample in samples:
        transcript = "".join(frame["data"] for frame in sample["frames"])
        assert sample["source"] == "verification"
        assert sample["sample_kind"] == "official_verification"
        assert sample["frames"]
        assert sample["agent_events"]
        assert "任务接受" in transcript
        assert "验收" in transcript
        assert "交付报告" in transcript


def test_verification_samples_preserve_real_live_frames(tmp_path) -> None:
    source_frames = [
        {"t": 0.0, "data": "\\r\\n[CyberOrion] CAI 原生终端已连接。\\r\\n"},
        {"t": 0.2, "data": "Starting CAI framework...\\r\\n"},
        {
            "t": 0.4,
            "data": (
                "[[CYBERORION_AGENT_EVENT]]"
                '{"type":"agent_start","id":"agent-1","agent":"CTF Agent"}\\r\\n'
            ),
        },
        {"t": 0.5, "data": "cat /challenge/flag.txt\r\nacademy{s4n1ty_d0wnl04d3d}\r\n"},
        {"t": 0.6, "data": "[CyberOrion] Report Agent 已自动调用。\\r\\n"},
        {"t": 0.8, "data": "[CyberOrion] 最终 PDF 报告已生成。\\r\\n"},
    ]
    source = {
        "id": "run_live_ctf_fixture",
        "title": "真实 CTF 录制",
        "kind": "ctf",
        "task_type": "ctf",
        "ctf_name": "picoctf_static_flag",
        "challenge": "FLAG",
        "status": "success",
        "duration_sec": 1.0,
        "created_at": "2026-08-26T08:00:00Z",
        "ended_at": "2026-08-26T08:00:01Z",
        "summary": "live fixture",
        "source": "live",
        "exit_code": 0,
        "report_status": "ready",
        "frames": source_frames,
        "agent_events": [{"type": "agent_start", "id": "agent-1", "agent": "CTF Agent"}],
    }
    (tmp_path / "run_live_ctf_fixture.json").write_text(
        json.dumps(source, ensure_ascii=False),
        encoding="utf-8",
    )

    samples = verification_sample_definitions(tmp_path)
    sample = next(item for item in samples if item["task_type"] == "ctf")

    assert sample["source"] == "verification"
    assert sample["source_recording_id"] == "run_live_ctf_fixture"
    assert sample["frames"] == source_frames
    assert "Starting CAI framework" in "".join(frame["data"] for frame in sample["frames"])
    assert "最终 PDF 报告已生成" in "".join(frame["data"] for frame in sample["frames"])


def test_ctf_verification_sample_requires_exact_picoctf_source(tmp_path) -> None:
    common = {
        "title": "live",
        "kind": "ctf",
        "task_type": "ctf",
        "challenge": "FLAG",
        "status": "success",
        "report_status": "ready",
        "source": "live",
        "frames": [
            {"t": 0.0, "data": "Starting CAI framework...\r\n"},
            {
                "t": 0.1,
                "data": "[[CYBERORION_AGENT_EVENT]]{\"type\":\"agent_start\",\"agent\":\"CTF Agent\"}\r\n",
            },
            {"t": 0.2, "data": "cat /app/flag.txt -> academy{test_flag}\r\n"},
            {"t": 0.3, "data": "Report Agent report.pdf\r\n"},
        ],
        "agent_events": [{"type": "agent_start", "agent": "CTF Agent"}],
    }
    (tmp_path / "randsubware.json").write_text(
        json.dumps({**common, "id": "randsubware", "ctf_name": "randsubware"}),
        encoding="utf-8",
    )
    (tmp_path / "pico.json").write_text(
        json.dumps({**common, "id": "pico", "ctf_name": "picoctf_static_flag"}),
        encoding="utf-8",
    )

    sample = next(
        item for item in verification_sample_definitions(tmp_path) if item["task_type"] == "ctf"
    )

    assert sample["source_recording_id"] == "pico"
    assert sample["ctf_name"] == "picoctf_static_flag"


def test_production_samples_reject_stopped_or_timed_out_live_recordings(tmp_path) -> None:
    common = {
        "title": "live",
        "source": "live",
        "frames": [
            {"t": 0.0, "data": "Starting CAI framework...\r\n"},
            {
                "t": 0.1,
                "data": "[[CYBERORION_AGENT_EVENT]]"
                '{"type":"agent_start","agent":"CTF Agent"}\r\n',
            },
            {"t": 0.2, "data": "Report Agent report.pdf\r\n"},
        ],
        "agent_events": [{"type": "agent_start", "agent": "CTF Agent"}],
        "report_status": "ready",
    }
    (tmp_path / "stopped_ctf.json").write_text(
        json.dumps(
            {
                **common,
                "id": "stopped_ctf",
                "task_type": "ctf",
                "ctf_name": "picoctf_static_flag",
                "challenge": "FLAG",
                "status": "stopped",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (tmp_path / "timed_out_code.json").write_text(
        json.dumps(
            {
                **common,
                "id": "timed_out_code",
                "task_type": "code_repair",
                "status": "timeout",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    samples = {
        sample["task_type"]: sample
        for sample in verification_sample_definitions(tmp_path)
    }

    assert samples["ctf"]["status"] == "failed"
    assert samples["ctf"]["source_recording_id"] == ""
    assert "没有合格的 live recording" in samples["ctf"]["summary"]
    assert samples["code_repair"]["status"] == "failed"
    assert samples["code_repair"]["source_recording_id"] == ""


def test_materialized_sample_keeps_report_tail_in_replay_frames(tmp_path, monkeypatch) -> None:
    import cyberorion.verification_samples as samples_mod

    async def fake_report(_recording: dict, output_dir) -> dict:
        (output_dir / "report.pdf").write_bytes(b"%PDF-1.4 test")
        (output_dir / "report_status.json").write_text('{"status":"ready"}', encoding="utf-8")
        (output_dir / "report_context.json").write_text("{}", encoding="utf-8")
        return {"status": "ready", "agent_called": True, "pdf": str(output_dir / "report.pdf")}

    monkeypatch.setattr(samples_mod, "finalize_task_report", fake_report)

    frames = [
        {"t": 0.0, "data": "CAI 原生终端已连接\\r\\n"},
        {"t": 1.0, "data": "Agent tool call: cat /challenge/flag.txt\\r\\n"},
        {"t": 2.0, "data": "Report Agent 将读取完整日志。\\r\\n"},
        {"t": 3.0, "data": "最终 PDF 报告已生成。\\r\\n"},
    ]
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "run_live_ctf.json").write_text(
        json.dumps(
            {
                "id": "run_live_ctf",
                "title": "live",
                "kind": "ctf",
                "task_type": "ctf",
                "ctf_name": "picoctf_static_flag",
                "challenge": "FLAG",
                "status": "success",
                "duration_sec": 3.0,
                "created_at": "2026-08-26T08:00:00Z",
                "ended_at": "2026-08-26T08:00:03Z",
                "source": "live",
                "report_status": "ready",
                "frames": frames,
                "agent_events": [],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    output_root = tmp_path / "output"
    result = __import__("asyncio").run(materialize_verification_samples(output_root, source_dir))

    assert all(row["status"] in {"success", "failed"} for row in result)
    recording = json.loads(
        (output_root / "verification_ctf_picoctf_static_flag.json").read_text(encoding="utf-8")
    )
    assert recording["frames"] == frames
    assert recording["frames"][-1]["data"] == "最终 PDF 报告已生成。\\r\\n"


def test_extract_agent_events_reads_jsonl_and_deduplicates(tmp_path) -> None:
    event = {"type": "agent_start", "id": "agent-1", "agent": "Knowledge Agent"}
    events_path = tmp_path / "agent_events.jsonl"
    events_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    transcript = (
        "[[CYBERORION_AGENT_EVENT]]"
        + json.dumps(event)
        + "\n"
        + "[[CYBERORION_AGENT_EVENT]]"
        + json.dumps({"type": "agent_error", "id": "agent-1", "error": "provider unavailable"})
        + "\n"
    )

    extracted = _extract_agent_events(
        transcript,
        {"agent_events_path": str(events_path)},
    )

    assert [item["type"] for item in extracted] == ["agent_start", "agent_error"]


def test_only_systematic_tasks_trigger_final_report() -> None:
    assert should_generate_report("attack_chain")
    assert should_generate_report("purple_team")
    assert should_generate_report("ctf")
    assert should_generate_report("code_repair")
    assert not should_generate_report("general")
    assert not should_generate_report("")


def test_finalize_task_report_skips_simple_chat(tmp_path, monkeypatch) -> None:
    import asyncio
    import cyberorion.reporting as reporting

    async def unexpected_report_call(*_args, **_kwargs):
        raise AssertionError("simple chat must not call Report Agent")

    monkeypatch.setattr(reporting, "generate_report_artifacts", unexpected_report_call)

    result = asyncio.run(
        finalize_task_report(
            {"id": "chat_run", "task_type": "general", "status": "success"},
            tmp_path,
        )
    )

    assert result["status"] == "skipped"
    assert result["reason"] == "non_systematic_task"


def test_finalize_task_report_calls_report_agent_for_complex_tasks(tmp_path, monkeypatch) -> None:
    import asyncio
    import cyberorion.reporting as reporting

    async def fake_generate(recording, output_dir):
        assert recording["task_type"] == "attack_chain"
        assert output_dir == tmp_path
        return {"status": "ready", "agent_called": True, "pdf": str(tmp_path / "report.pdf")}

    monkeypatch.setattr(reporting, "generate_report_artifacts", fake_generate)

    result = asyncio.run(
        finalize_task_report(
            {"id": "chain_run", "task_type": "attack_chain", "status": "success"},
            tmp_path,
        )
    )

    assert result["status"] == "ready"
    assert result["agent_called"] is True


def test_failed_task_without_terminal_frames_still_calls_report_agent(tmp_path, monkeypatch) -> None:
    import asyncio
    import cyberorion.reporting as reporting

    calls = []

    async def fake_generate(recording, output_dir):
        calls.append((recording["status"], recording["frames"], output_dir))
        return {"status": "ready", "agent_called": True}

    monkeypatch.setattr(reporting, "generate_report_artifacts", fake_generate)

    result = asyncio.run(
        reporting.finalize_task_report(
            {"id": "failed_run", "task_type": "ctf", "status": "failed", "frames": []},
            tmp_path,
        )
    )

    assert result["agent_called"] is True
    assert calls == [("failed", [], tmp_path)]


def test_xelatex_is_preferred_over_latexmk(tmp_path, monkeypatch) -> None:
    import cyberorion.reporting as reporting

    calls = []
    monkeypatch.setattr(reporting.shutil, "which", lambda name: f"/usr/bin/{name}")

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(command, **_kwargs):
        calls.append(command)
        (tmp_path / "report.pdf").write_bytes(b"%PDF-1.4")
        return Completed()

    monkeypatch.setattr(reporting.subprocess, "run", fake_run)

    ok, error = reporting._compile_tex(tmp_path / "report.tex")

    assert ok is True
    assert error == ""
    assert calls[0][0].endswith("xelatex")


def test_report_contains_background_execution_usage_and_recommendations() -> None:
    context = build_report_context(
        {
            "id": "run_test",
            "task_type": "attack_chain",
            "status": "success",
            "summary": "攻击链分析",
            "frames": [{"data": "tool_call dispatch_agent\n最终结果"}],
        }
    )

    tex = render_report_tex(context)

    assert "CyberOrion 安全分析报告" in tex
    assert "本质结论" in tex
    assert "任务背景与范围" in tex
    assert "任务完成故事线" in tex
    assert "Agent 与工具活动" in tex
    assert "知识背景与关键证据" in tex
    assert "安全人员建议" in tex
    assert context["usage"]["context_tokens_estimated"] > 0


def test_report_context_uses_complete_terminal_log_file(tmp_path) -> None:
    full_log = tmp_path / "terminal_full.log"
    full_log.write_text(
        "\n".join(
            [
                "主 Agent 开始复原攻击链条。",
                "[[CYBERORION_AGENT_EVENT]]{\"type\":\"agent_start\",\"id\":\"agent-1\",\"agent\":\"Knowledge Agent\",\"title\":\"背景知识\"}",
                "[[CYBERORION_AGENT_EVENT]]{\"type\":\"agent_tool_call\",\"id\":\"agent-1\",\"tool\":\"online_security_search\",\"args\":\"{\\\"query\\\":\\\"web shell persistence\\\"}\"}",
                "[[CYBERORION_AGENT_EVENT]]{\"type\":\"agent_output\",\"id\":\"agent-1\",\"text\":\"确认 WebShell 持久化排查重点。\"}",
                "[[CYBERORION_AGENT_EVENT]]{\"type\":\"agent_done\",\"id\":\"agent-1\",\"result\":\"返回 ATT&CK 映射建议。\"}",
                "最终交付：时间线、证据表、修复建议。",
            ]
        ),
        encoding="utf-8",
    )

    context = build_report_context(
        {
            "id": "run_full_log",
            "task_type": "attack_chain",
            "status": "success",
            "full_log_path": str(full_log),
            "frames": [{"data": "主 Agent 开始复原攻击链条。"}],
        }
    )

    assert "online_security_search" in context["execution"]["transcript"]
    assert context["execution"]["agent_events"][0]["agent"] == "Knowledge Agent"
    assert context["artifacts"]["full_log_available"] is True
    assert context["artifacts"]["terminal_full_log"].endswith("terminal_full.log")


def test_report_context_exposes_agent_event_artifact(tmp_path) -> None:
    events = tmp_path / "agent_events.jsonl"
    events.write_text('{"type":"agent_error","agent":"Knowledge Agent"}\n', encoding="utf-8")

    context = build_report_context(
        {
            "id": "run_events",
            "task_type": "ctf",
            "status": "failed",
            "frames": [],
            "agent_events_path": str(events),
        }
    )

    assert context["artifacts"]["agent_events_available"] is True
    assert context["artifacts"]["agent_events"].endswith("agent_events.jsonl")


def test_report_tex_renders_fixed_structured_sections_without_markdown_tokens() -> None:
    context = build_report_context(
        {
            "id": "run_structured",
            "task_type": "code_repair",
            "status": "success",
            "frames": [{"data": "Tool: pytest tests/test_vulnerable_app.py\n2 passed"}],
        },
        json.dumps(
            {
                "executive_summary": ["漏洞已通过参数化查询修复，回归测试通过。"],
                "storyline": ["复现 SQL 注入。", "修改查询实现。", "运行回归测试。"],
                "agent_activity": ["CodeAgent 负责定位与补丁。", "Retester 负责复测。"],
                "completion_quality": ["测试覆盖注入与正常查询路径。"],
                "security_recommendations": ["将 SQL 拼接检查纳入代码审查清单。"],
                "remaining_risks": ["仍需在生产数据访问层做一次全量排查。"],
            },
            ensure_ascii=False,
        ),
    )

    tex = render_report_tex(context)

    assert "本质结论" in tex
    assert "任务完成故事线" in tex
    assert "Agent 与工具活动" in tex
    assert "安全人员建议" in tex
    assert "\\item ##" not in tex
    assert "```" not in tex


def test_reportlab_fallback_generates_pdf_when_latex_is_unavailable(
    tmp_path,
    monkeypatch,
) -> None:
    import cyberorion.reporting as reporting

    async def fake_report_agent(_context: dict, _context_dir=None) -> str:
        return "结论：已完成验证。\n证据：测试用例通过。\n建议：继续保留回归测试。"

    monkeypatch.setattr(reporting, "_call_report_agent", fake_report_agent)
    monkeypatch.setattr(
        reporting,
        "_compile_tex",
        lambda _tex_path: (False, "latexmk/xelatex not installed"),
    )

    result = __import__("asyncio").run(
        generate_report_artifacts(
            {
                "id": "run_reportlab",
                "task_type": "code_repair",
                "status": "success",
                "frames": [{"data": "[CyberOrion] dispatch_agent\n测试通过"}],
            },
            tmp_path,
        )
    )

    assert result["status"] == "ready"
    assert result["renderer"] == "reportlab"
    assert (tmp_path / "report.pdf").is_file()
    assert (tmp_path / "report_status.json").read_text(encoding="utf-8").find(
        '"renderer": "reportlab"'
    ) >= 0


def test_reportlab_fallback_paginates_long_report_body(tmp_path, monkeypatch) -> None:
    import cyberorion.reporting as reporting

    long_body = "\n".join(
        f"证据行 {i}: /opt/cyberorion/task_environments/attack_chain/evidence/timeline.jsonl "
        "dispatch_agent Network Security Analyzer Report Agent preserved raw output"
        for i in range(160)
    )

    async def fake_report_agent(_context: dict, _context_dir=None) -> str:
        return long_body

    monkeypatch.setattr(reporting, "_call_report_agent", fake_report_agent)
    monkeypatch.setattr(
        reporting,
        "_compile_tex",
        lambda _tex_path: (False, "latexmk/xelatex not installed"),
    )

    result = __import__("asyncio").run(
        generate_report_artifacts(
            {
                "id": "run_reportlab_long",
                "task_type": "attack_chain",
                "status": "success",
                "frames": [{"data": long_body}],
            },
            tmp_path,
        )
    )

    assert result["status"] == "ready"
    assert result["renderer"] == "reportlab"
    assert (tmp_path / "report.pdf").is_file()


def test_report_agent_failure_is_recorded_but_pdf_generation_continues(
    tmp_path,
    monkeypatch,
) -> None:
    import asyncio
    import cyberorion.reporting as reporting

    async def failing_report_agent(_context: dict, _context_dir=None) -> str:
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(reporting, "_call_report_agent", failing_report_agent)
    monkeypatch.setattr(
        reporting,
        "_compile_tex",
        lambda _tex_path: (False, "latex unavailable"),
    )

    result = asyncio.run(
        generate_report_artifacts(
            {
                "id": "run_report_agent_failure",
                "task_type": "attack_chain",
                "status": "success",
                "frames": [{"data": "evidence preserved"}],
            },
            tmp_path,
        )
    )

    status = json.loads((tmp_path / "report_status.json").read_text(encoding="utf-8"))
    assert result["status"] == "ready"
    assert status["agent_called"] is True
    assert status["agent_output_available"] is False
    assert "provider unavailable" in status["agent_error"]
