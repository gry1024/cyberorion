"""Final Report Agent integration and readable Chinese PDF generation."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

SYSTEMATIC_TASK_TYPES = frozenset(
    {
        "attack_chain",
        "ctf",
        "code_repair",
        "vulnerability_repair",
        "purple_team",
        "red_adversary",
        "blue_response",
        "traffic_analysis",
        "host_hardening",
    }
)
_AGENT_EVENT_PREFIX = "[[CYBERORION_AGENT_EVENT]]"
_REPORT_AGENT_TRANSCRIPT_LIMIT = 120_000


def should_generate_report(task_type: str | None) -> bool:
    return str(task_type or "").strip().lower() in SYSTEMATIC_TASK_TYPES


async def finalize_task_report(
    recording: dict[str, Any],
    output_dir: str | Path,
) -> dict[str, Any]:
    """Generate the final Report Agent artifact for systematic tasks only."""
    if not should_generate_report(recording.get("task_type")):
        return {
            "status": "skipped",
            "reason": "non_systematic_task",
            "agent_called": False,
        }
    return await generate_report_artifacts(recording, output_dir)


def _strip_terminal(text: str) -> str:
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(text or ""))
    # 终端排版专用字符清理：进度表 box-drawing / block / 几何符号在
    # 网页与 PDF 中易造成排版噪点，统一替换为可读形式。
    text = re.sub(r"[\u2500-\u257f]", "─", text)
    text = re.sub(r"[\u2580-\u259f]", "#", text)
    text = re.sub(r"[\u25a0-\u25ff]", "*", text)
    text = re.sub(r"\u2800\u2800", "  ", text)  # 双 Braille blank
    return text


def _latex_safe_text(value: Any) -> str:
    """Normalize terminal text before LaTeX escaping."""
    text = str(value if value is not None else "")
    text = re.sub(r"[\u2800-\u28ff]", "*", text)
    # 终端表格/进度条绘制字符（box-drawing、block、几何符号）在 PDF 中
    # 无法排版，替换为可读分隔符；保留中英文与常规标点。
    text = re.sub(r"[\u2500-\u257f]", "─", text)  # box-drawing -> 单横线
    text = re.sub(r"[\u2580-\u259f]", "#", text)  # block elements
    text = re.sub(r"[\u25a0-\u25ff]", "*", text)  # geometric shapes
    text = re.sub(r"[\u2190-\u21ff]", "->", text)  # arrows
    text = re.sub(r"[\u2460-\u24ff]", " ", text)  # enclosed alphanumerics
    text = re.sub(r"[│║╔╗╚╝╠╣╦╩╬═╬╪]", "", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # 连续横线压缩为单条（避免摘要框内出现长分隔线）
    text = re.sub(r"─{3,}", "──", text)
    return text


def _recording_transcript(recording: dict[str, Any]) -> str:
    frames = recording.get("frames") or []
    return _strip_terminal(
        "\n".join(str(frame.get("data") or "") for frame in frames if isinstance(frame, dict))
    ).strip()


def _read_text_file(path: str | Path, max_chars: int = _REPORT_AGENT_TRANSCRIPT_LIMIT) -> str:
    try:
        text = Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    head = text[: max_chars // 2]
    tail = text[-(max_chars // 2):]
    return f"{head}\n\n...（中间日志过长，已在上下文中折叠；完整文件仍保留在 terminal_full.log）...\n\n{tail}"


def _full_transcript(recording: dict[str, Any]) -> tuple[str, str]:
    inline = str(recording.get("full_transcript") or "").strip()
    if inline:
        return _strip_terminal(inline), "inline"
    for key in ("full_log_path", "terminal_full_log", "log_path"):
        raw_path = str(recording.get(key) or "").strip()
        if not raw_path:
            continue
        text = _read_text_file(raw_path)
        if text:
            return _strip_terminal(text).strip(), raw_path
    for item in recording.get("log_files") or []:
        raw_path = str(item.get("path") if isinstance(item, dict) else item).strip()
        if not raw_path:
            continue
        text = _read_text_file(raw_path)
        if text:
            return _strip_terminal(text).strip(), raw_path
    return _recording_transcript(recording), "frames"


def _extract_agent_events(transcript: str, recording: dict[str, Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen: set[str] = set()

    def append_event(item: Any) -> None:
        if isinstance(item, dict):
            payload = dict(item)
            key = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                events.append(payload)

    for item in recording.get("agent_events") or []:
        append_event(item)

    for key in ("agent_events_path", "agent_events_log"):
        raw_path = str(recording.get(key) or "").strip()
        if not raw_path:
            continue
        try:
            lines = Path(raw_path).expanduser().read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
        except Exception:
            continue
        for line in lines:
            raw = line.strip()
            if not raw:
                continue
            try:
                append_event(json.loads(raw))
            except json.JSONDecodeError:
                continue

    for line in transcript.splitlines():
        if _AGENT_EVENT_PREFIX not in line:
            continue
        raw = line.split(_AGENT_EVENT_PREFIX, 1)[1].strip()
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        append_event(payload)
    return events


def _clean_report_text(value: Any) -> str:
    text = _strip_terminal(str(value if value is not None else "")).strip()
    text = re.sub(r"```[a-zA-Z0-9_-]*", "", text)
    text = text.replace("```", "")
    text = re.sub(r"^\s{0,3}#{1,6}\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    return text.strip()


def _as_text_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        result: list[str] = []
        for line in value.splitlines():
            cleaned = _clean_report_text(line.strip(" \t-•"))
            if cleaned:
                result.append(cleaned)
        return result
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if isinstance(item, dict):
                item = item.get("text") or item.get("summary") or item.get("result") or item
            cleaned = _clean_report_text(item)
            if cleaned:
                result.append(cleaned)
        return result
    cleaned = _clean_report_text(value)
    return [cleaned] if cleaned else []


def _parse_report_sections(report_agent_output: str) -> dict[str, list[str]]:
    raw = str(report_agent_output or "").strip()
    if not raw:
        return {}
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, flags=re.S)
    candidate = fenced.group(1) if fenced else raw
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return {"executive_summary": [_clean_report_text(raw)]}
    if not isinstance(parsed, dict):
        return {"executive_summary": [_clean_report_text(raw)]}
    keys = (
        "executive_summary",
        "storyline",
        "agent_activity",
        "completion_quality",
        "security_recommendations",
        "remaining_risks",
        "evidence",
    )
    sections: dict[str, list[str]] = {}
    for key in keys:
        values = _as_text_list(parsed.get(key))
        if values:
            sections[key] = values
    return sections


def _estimate_tokens(text: str) -> int:
    try:
        import tiktoken

        return max(1, len(tiktoken.get_encoding("cl100k_base").encode(text)))
    except Exception:
        return max(1, (len(text) + 3) // 4)


def build_report_context(recording: dict[str, Any], report_agent_output: str = "") -> dict[str, Any]:
    transcript, transcript_source = _full_transcript(recording)
    agent_events = _extract_agent_events(transcript, recording)
    # 报告 Agent 上下文精简：丢弃流式 agent_output 分块（其文本已由 terminal
    # transcript 全文覆盖）。traffic_analysis 等重任务会产生数千条流式片段，
    # 若全量塞给模型会超 MiniMax 上下文上限导致 400。结构化事件(start/done/
    # error/tool_call/tool_output)与截断 transcript 已足够支撑高质量报告。
    agent_events = [
        e for e in agent_events if str(e.get("type") or "") != "agent_output"
    ]
    task_type = str(recording.get("task_type") or "general")
    full_log_path = str(recording.get("full_log_path") or recording.get("terminal_full_log") or "")
    return {
        "task": {
            "id": recording.get("id", ""),
            "type": task_type,
            "title": recording.get("title", ""),
            "status": recording.get("status", ""),
            "created_at": recording.get("created_at", ""),
            "ended_at": recording.get("ended_at", ""),
            "duration_sec": recording.get("duration_sec", 0),
        },
        "background": {
            "task_type": task_type,
            "summary": recording.get("summary", ""),
            "ctf_name": recording.get("ctf_name", ""),
            "challenge": recording.get("challenge", ""),
        },
        "knowledge": recording.get("knowledge_report") or {
            "status": "not_recorded",
            "note": "本次记录未提供独立知识报告。",
        },
        "execution": {
            "transcript": transcript,
            "tool_calls": recording.get("tool_calls") or [],
            "agent_dispatches": recording.get("agent_dispatches") or [],
            "events": recording.get("events") or [],
            "agent_events": agent_events,
        },
        "result": {
            "final_output": report_agent_output or transcript[-12000:],
            "exit_code": recording.get("exit_code"),
            "status": recording.get("status", "unknown"),
        },
        "report": {
            "agent_output_raw": report_agent_output,
            "sections": _parse_report_sections(report_agent_output),
        },
        "artifacts": {
            "terminal_full_log": full_log_path,
            "full_log_available": bool(full_log_path and Path(full_log_path).expanduser().is_file()),
            "agent_events": str(recording.get("agent_events_path") or ""),
            "agent_events_available": bool(
                recording.get("agent_events_path")
                and Path(str(recording["agent_events_path"])).expanduser().is_file()
            ),
            "transcript_source": transcript_source,
        },
        "usage": {
            "input_tokens": recording.get("input_tokens"),
            "output_tokens": recording.get("output_tokens") or _estimate_tokens(transcript),
            "context_chars": len(transcript),
            "context_tokens_estimated": _estimate_tokens(transcript),
            "basis": "CAI terminal recording estimate"
            if recording.get("output_tokens") is None
            else "runtime usage",
        },
        "recommendations": recording.get("recommendations") or [
            "由安全人员复核报告中的证据、时间线和未决问题。",
            "对未验证结论补充原始日志、流量或端点证据后再执行处置。",
        ],
    }


def _latex_escape(value: Any) -> str:
    text = _latex_safe_text(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
        "<": r"\textless{}",
        ">": r"\textgreater{}",
    }
    return "".join(replacements.get(char, char) for char in text)


def _short_text(value: Any, limit: int = 2400) -> str:
    text = str(value if value is not None else "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n...（已截断，完整执行记录见 report_context.json）"


def _interesting_lines(transcript: str, limit: int = 90) -> list[str]:
    keywords = (
        "dispatch_agent",
        "knowledge",
        "tool",
        "agent",
        "result",
        "error",
        "final",
        "recommend",
        "证据",
        "结论",
        "漏洞",
        "攻击链",
        "修复",
        "报告",
    )
    lines = [
        line.strip()
        for line in transcript.splitlines()
        if line.strip() and _AGENT_EVENT_PREFIX not in line
    ]
    picked = [line for line in lines if any(k.lower() in line.lower() for k in keywords)]
    return (picked or lines)[-limit:]


def _knowledge_summary(knowledge: dict[str, Any]) -> str:
    if not knowledge:
        return "本次记录没有独立知识库报告。"
    lines = [
        f"检索状态：{'有命中' if knowledge.get('matches') else '无直接命中'}",
        f"置信度：{knowledge.get('confidence', '未提供')}",
    ]
    matches = knowledge.get("matches") or []
    if matches:
        lines.append("关键命中：")
        for item in matches[:8]:
            lines.append(
                f"- {item.get('id', '未标识')} · {item.get('name', '未命名')} · "
                f"{item.get('source', '来源未提供')}：{item.get('evidence', '')}"
            )
    mappings = knowledge.get("attack_mapping") or []
    if mappings:
        lines.append("ATT&CK 映射：")
        lines.extend(f"- {item.get('id', '')}：{item.get('reason', '')}" for item in mappings[:8])
    risks = knowledge.get("risk_notes") or []
    if risks:
        lines.append("边界说明：")
        lines.extend(f"- {item}" for item in risks[:5])
    return "\n".join(lines)


def _agent_event_line(event: dict[str, Any]) -> str:
    event_type = str(event.get("type") or "")
    agent = str(event.get("agent") or event.get("agent_name") or "子 Agent")
    if event_type == "agent_start":
        title = str(event.get("title") or event.get("task") or "开始执行")
        return f"{agent} 启动：{title}"
    if event_type == "agent_tool_call":
        tool = str(event.get("tool") or "工具")
        args = _short_text(event.get("args") or event.get("arguments") or "", 260)
        return f"{agent} 调用工具 {tool}：{args}".rstrip("：")
    if event_type == "agent_tool_output":
        return f"{agent} 工具返回：{_short_text(event.get('output') or event.get('text') or '', 320)}"
    if event_type == "agent_output":
        return f"{agent} 输出：{_short_text(event.get('text') or event.get('output') or '', 320)}"
    if event_type in {"agent_done", "agent_error"}:
        status = "完成" if event_type == "agent_done" else "失败"
        return f"{agent} {status}：{_short_text(event.get('result') or event.get('error') or '', 360)}"
    return ""


def _dispatch_summary(execution: dict[str, Any], transcript: str) -> list[str]:
    rows: list[str] = []
    for event in execution.get("agent_events") or []:
        if isinstance(event, dict):
            line = _agent_event_line(event)
            if line:
                rows.append(line)
    for item in execution.get("agent_dispatches") or []:
        if isinstance(item, dict):
            rows.append(
                f"{item.get('agent') or item.get('agent_name') or 'Agent'}："
                f"{item.get('task') or item.get('result') or '已调度'}"
            )
    if not rows:
        rows = [
            line for line in _interesting_lines(transcript, 35)
            if any(marker in line.lower() for marker in ("dispatch_agent", "agent result", "skill"))
        ]
    return rows[:35]


def _latex_items(items: list[str], fallback: str = "未记录。", numbered: bool = False) -> str:
    cleaned = [_clean_report_text(item) for item in items if _clean_report_text(item)]
    if not cleaned:
        cleaned = [fallback]
    env = "enumerate" if numbered else "itemize"
    body = "\n".join(r"\item " + _latex_escape(_short_text(item, 760)) for item in cleaned[:18])
    return rf"\begin{{{env}}}" "\n" + body + "\n" + rf"\end{{{env}}}"


def _report_sections(context: dict[str, Any]) -> dict[str, list[str]]:
    sections = dict(((context.get("report") or {}).get("sections") or {}))
    execution = context.get("execution") or {}
    result = context.get("result") or {}
    recommendations = context.get("recommendations") or []
    transcript = str(execution.get("transcript") or "")
    if not sections.get("executive_summary"):
        final = _clean_report_text(result.get("final_output") or "")
        sections["executive_summary"] = [
            _short_text(final, 900)
            if final
            else "本报告基于 CyberOrion 完整终端日志和结构化 Agent 事件生成，只陈述可复核事实。"
        ]
    if not sections.get("storyline"):
        sections["storyline"] = _interesting_lines(transcript, 8) or [
            "终端日志未提供足够时间线事件，需回到 terminal_full.log 复核原始过程。"
        ]
    if not sections.get("agent_activity"):
        sections["agent_activity"] = _dispatch_summary(execution, transcript) or [
            "未发现独立子 Agent 调度记录；如任务预期需要协作，应复核主 Agent 是否发起调度。"
        ]
    if not sections.get("completion_quality"):
        sections["completion_quality"] = [
            f"最终状态：{result.get('status') or 'unknown'}；退出码："
            f"{result.get('exit_code') if result.get('exit_code') is not None else '未记录'}。",
            "报告依据完整终端日志、结构化 Agent 事件和任务元数据生成；缺失证据不作事实补写。",
        ]
    if not sections.get("security_recommendations"):
        sections["security_recommendations"] = _as_text_list(recommendations)
    if not sections.get("remaining_risks"):
        sections["remaining_risks"] = [
            "若日志中存在被截断或外部系统未采集的工具输出，需以 terminal_full.log、测试输出和生产日志进行二次核验。"
        ]
    if not sections.get("evidence"):
        sections["evidence"] = _interesting_lines(transcript, 18)
    return sections


def _latex_paragraphs(text: str) -> str:
    chunks = [part.strip() for part in str(text or "").splitlines() if part.strip()]
    if not chunks:
        return r"\textcolor{Muted}{未记录。}"
    return "\n\n".join(_latex_escape(chunk) for chunk in chunks)


def _metric_row(label: str, value: Any) -> str:
    return r"\textbf{" + _latex_escape(label) + r"} & " + _latex_escape(value) + r" \\"


def _evidence_block(lines: list[str]) -> str:
    if not lines:
        return r"\textcolor{Muted}{未捕获关键过程行。}"
    escaped = []
    for line in lines:
        escaped.append(
            r"\noindent\hangindent=1.2em\hangafter=1 "
            r"\textcolor{Muted}{\footnotesize " + _latex_escape(_short_text(line, 420)) + r"}\\[-0.15em]"
        )
    return "\n".join(escaped)


def render_report_tex(context: dict[str, Any]) -> str:
    task = context.get("task") or {}
    background = context.get("background") or {}
    knowledge = context.get("knowledge") or {}
    execution = context.get("execution") or {}
    result = context.get("result") or {}
    usage = context.get("usage") or {}
    artifacts = context.get("artifacts") or {}
    sections = _report_sections(context)

    transcript = str(execution.get("transcript") or "")
    knowledge_text = _knowledge_summary(knowledge)
    evidence_lines = sections.get("evidence") or _interesting_lines(transcript, 24)
    rows = "\n".join(
        [
            _metric_row("任务 ID", task.get("id", "")),
            _metric_row("任务类型", task.get("type", "")),
            _metric_row("任务状态", task.get("status", "")),
            _metric_row("开始时间", task.get("created_at", "")),
            _metric_row("结束时间", task.get("ended_at", "")),
            _metric_row("耗时", f"{task.get('duration_sec', '')} 秒"),
            _metric_row("上下文字符", usage.get("context_chars", "")),
            _metric_row("估算上下文 Token", usage.get("context_tokens_estimated", "")),
            _metric_row("输出 Token", usage.get("output_tokens", "")),
            _metric_row("完整日志", "已保留" if artifacts.get("full_log_available") else "未发现完整日志文件"),
        ]
    )
    status_color = "StatusOk" if str(result.get("status") or "").lower() == "success" else "StatusWarn"
    cover_line = f"任务 {task.get('id') or '未命名'} · {task.get('type') or 'unknown'} · {task.get('status') or 'unknown'}"
    return (
        r"\documentclass[UTF8,a4paper,11pt]{ctexart}" "\n"
        r"\usepackage[a4paper,margin=1.85cm,top=2.05cm,bottom=1.85cm]{geometry}" "\n"
        r"\usepackage{fontspec}" "\n"
        r"\usepackage{xcolor}" "\n"
        r"\usepackage{longtable}" "\n"
        r"\usepackage{array}" "\n"
        r"\usepackage{hyperref}" "\n"
        r"\usepackage{fancyhdr}" "\n"
        r"\IfFontExistsTF{Noto Serif CJK SC}{\setCJKmainfont{Noto Serif CJK SC}}{}" "\n"
        r"\IfFontExistsTF{Noto Sans CJK SC}{\setCJKsansfont{Noto Sans CJK SC}}{}" "\n"
        r"\IfFontExistsTF{Noto Serif CJK SC}{\setmainfont{Noto Serif CJK SC}}{}" "\n"
        r"\definecolor{OrionNavy}{HTML}{162033}" "\n"
        r"\definecolor{OrionCyan}{HTML}{00A6A6}" "\n"
        r"\definecolor{OrionGold}{HTML}{C98A18}" "\n"
        r"\definecolor{SoftPanel}{HTML}{F4F7FA}" "\n"
        r"\definecolor{SoftCyan}{HTML}{E8F7F6}" "\n"
        r"\definecolor{SoftGold}{HTML}{FFF4DD}" "\n"
        r"\definecolor{Muted}{HTML}{5B6777}" "\n"
        r"\definecolor{StatusOk}{HTML}{0E8F64}" "\n"
        r"\definecolor{StatusWarn}{HTML}{B86800}" "\n"
        r"\hypersetup{colorlinks=true,linkcolor=OrionCyan,urlcolor=OrionCyan}" "\n"
        r"\setlength{\parindent}{0pt}" "\n"
        r"\setlength{\parskip}{0.46em}" "\n"
        r"\setlength{\headheight}{14pt}" "\n"
        r"\setlength{\emergencystretch}{3em}" "\n"
        r"\renewcommand{\arraystretch}{1.28}" "\n"
        r"\pagestyle{fancy}" "\n"
        r"\fancyhf{}" "\n"
        r"\lhead{\textcolor{Muted}{CyberOrion Report Agent}}" "\n"
        r"\rhead{\textcolor{Muted}{完整日志 · 证据优先}}" "\n"
        r"\cfoot{\textcolor{Muted}{\thepage}}" "\n"
        r"\renewcommand{\headrulewidth}{0.35pt}" "\n"
        r"\renewcommand{\footrulewidth}{0pt}" "\n"
        r"\newcommand{\sectionrule}{\vspace{-0.2em}\textcolor{OrionCyan}{\rule{\linewidth}{0.8pt}}\vspace{0.2em}}" "\n"
        r"\newcommand{\orionsection}[2]{\vspace{0.9em}{\Large\bfseries\textcolor{OrionNavy}{#1}}\hfill{\small\textcolor{OrionCyan}{#2}}\\[-0.25em]\sectionrule}" "\n"
        r"\newcommand{\softbox}[3]{\par\noindent\fcolorbox{#1}{#2}{\begin{minipage}{0.965\linewidth}\vspace{0.35em}\raggedright\small #3\vspace{0.35em}\end{minipage}}\par\vspace{0.35em}}" "\n"
        r"\begin{document}" "\n"
        r"\begin{center}" "\n"
        r"{\fontsize{28}{34}\selectfont\bfseries\textcolor{OrionNavy}{CyberOrion 安全分析报告}}\\[0.45em]" "\n"
        r"{\large\textcolor{Muted}{Report Agent · 任务故事线 · Agent 活动 · 验证质量 · 安全建议}}\\[0.9em]" "\n"
        r"\textcolor{OrionGold}{\rule{0.78\linewidth}{1.4pt}}\\[0.7em]" "\n"
        r"{\small\textcolor{" + status_color + "}{" + _latex_escape(cover_line) + r"}}" "\n"
        r"\end{center}" "\n"
        r"\orionsection{一、本质结论}{Executive}" "\n"
        r"\softbox{OrionGold}{SoftGold}{" "\n" + _latex_items(sections.get("executive_summary", []), numbered=False) + "\n" r"}" "\n"
        r"\orionsection{二、任务背景与范围}{Scope}" "\n"
        r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.28\linewidth} >{\raggedright\arraybackslash}p{0.64\linewidth}}" "\n"
        + rows + "\n"
        r"\end{longtable}" "\n"
        r"\textbf{场景摘要：} " + _latex_escape(background.get("summary", "") or "未提供。") + r"\\" "\n"
        r"\textcolor{Muted}{统计口径：" + _latex_escape(usage.get("basis", "")) + "；完整日志来源：" + _latex_escape(artifacts.get("transcript_source", "")) + "。}" "\n"
        r"\orionsection{三、任务完成故事线}{Storyline}" "\n" + _latex_items(sections.get("storyline", []), numbered=True) + "\n"
        r"\orionsection{四、Agent 与工具活动}{Agent Frames}" "\n"
        r"\softbox{OrionCyan}{SoftCyan}{" "\n" + _latex_items(sections.get("agent_activity", []), numbered=False) + "\n" r"}" "\n"
        r"\orionsection{五、知识背景与关键证据}{Evidence}" "\n"
        r"{\small " + _latex_paragraphs(_short_text(knowledge_text, 2200)) + "}\n"
        r"\subsection*{关键证据摘录}" "\n" + _latex_items(evidence_lines, "未发现可摘录的关键证据；请复核 terminal_full.log。", numbered=False) + "\n"
        r"\orionsection{六、完成质量与剩余风险}{Quality}" "\n"
        "\\textbf{验证质量}\n" + _latex_items(sections.get("completion_quality", []), numbered=False) + "\n"
        "\\textbf{剩余风险}\n" + _latex_items(sections.get("remaining_risks", []), numbered=False) + "\n"
        r"\orionsection{七、安全人员建议}{Recommendations}" "\n"
        r"\softbox{OrionGold}{SoftPanel}{" "\n" + _latex_items(sections.get("security_recommendations", []), numbered=False) + "\n" r"}" "\n"
        r"\orionsection{八、附录：终端记录节选}{Appendix}" "\n"
        r"\begingroup\scriptsize\raggedright" "\n" + _evidence_block([line for line in transcript.splitlines() if line.strip()][-140:]) + "\n"
        r"\endgroup" "\n"
        r"\end{document}" "\n"
    )


def _context_for_report_agent(context: dict[str, Any]) -> dict[str, Any]:
    compact = json.loads(json.dumps(context, ensure_ascii=False, default=str))
    transcript = str(((compact.get("execution") or {}).get("transcript")) or "")
    if len(transcript) > 18_000:
        compact["execution"]["transcript_excerpt"] = (
            transcript[:9000]
            + "\n\n...（提示上下文中折叠；Report Agent 可用 read_task_log 读取完整日志）...\n\n"
            + transcript[-9000:]
        )
        compact["execution"].pop("transcript", None)
    return compact


async def _call_report_agent(context: dict[str, Any], context_dir: str | Path | None = None) -> str:
    """Ask the CAI Report Agent for the final structured narrative."""
    source_candidates = [
        os.getenv("CAI_SOURCE_DIR", ""),
        "/opt/cai-latest",
        "/tmp/cai-latest",
        str(Path(__file__).resolve().parents[2] / "cai-latest"),
    ]
    for candidate in source_candidates:
        if not candidate:
            continue
        cai_source = Path(candidate).expanduser() / "src"
        if cai_source.is_dir() and str(cai_source) not in sys.path:
            sys.path.insert(0, str(cai_source))
            break
    from cai.sdk.agents import Runner
    from cai.agents.report_agent import report_agent

    previous_context_dir = os.environ.get("CYBERORION_REPORT_CONTEXT_DIR")
    if context_dir is not None:
        os.environ["CYBERORION_REPORT_CONTEXT_DIR"] = str(Path(context_dir).resolve())
    try:
        result = await asyncio.wait_for(
            Runner.run(
                report_agent,
                (
                    "请先调用 list_task_artifacts；若 terminal_full.log 存在，再调用 read_task_log "
                    "读取完整任务日志，然后只基于事实输出 JSON。不要输出 Markdown。"
                    "JSON 字段固定为：executive_summary、storyline、agent_activity、"
                    "completion_quality、security_recommendations、remaining_risks、evidence；"
                    "每个字段都是中文字符串数组。context.report.agent_output_raw/sections 在本轮生成前为空是正常状态，不得把它写成任务证据缺口；只基于 terminal_full.log、agent_events、验证与部署事实评价任务。上下文如下：\n"
                    + json.dumps(_context_for_report_agent(context), ensure_ascii=False, default=str)
                ),
                max_turns=4,
            ),
            timeout=300,
        )
    finally:
        if previous_context_dir is None:
            os.environ.pop("CYBERORION_REPORT_CONTEXT_DIR", None)
        else:
            os.environ["CYBERORION_REPORT_CONTEXT_DIR"] = previous_context_dir
    return str(getattr(result, "final_output", "") or "").strip()


def _compile_tex(tex_path: Path) -> tuple[bool, str]:
    xelatex = shutil.which("xelatex")
    latexmk = shutil.which("latexmk")
    if xelatex:
        command = [xelatex, "-interaction=nonstopmode", "-halt-on-error", tex_path.name]
    elif latexmk:
        command = [latexmk, "-xelatex", "-interaction=nonstopmode", "-halt-on-error", tex_path.name]
    else:
        return False, "latexmk/xelatex not installed"
    try:
        completed = subprocess.run(
            command,
            cwd=tex_path.parent,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    pdf_path = tex_path.with_suffix(".pdf")
    if completed.returncode != 0 or not pdf_path.is_file():
        return False, (completed.stderr or completed.stdout or "LaTeX compilation failed")[-2000:]
    return True, ""


def _find_report_font(names: tuple[str, ...]) -> Path | None:
    configured = os.getenv("CYBERORION_REPORT_FONT", "").strip()
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser())
    roots = [
        Path("/usr/share/fonts"),
        Path("/usr/local/share/fonts"),
        Path("/root/.fonts"),
        Path("/home/groy/.fonts"),
        Path("/opt/cyberorion/assets/fonts"),
        Path("/mnt/c/Windows/Fonts"),
    ]
    for root in roots:
        for name in names:
            candidates.append(root / name)
    for candidate in candidates:
        try:
            if candidate.is_file():
                with candidate.open("rb"):
                    return candidate
        except OSError:
            continue
    return None


def _register_report_fonts() -> tuple[str, str]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    regular_path = _find_report_font(
        (
            "NotoSansCJK-Regular.ttf",
            "NotoSansCJKsc-Regular.ttf",
            "NotoSansSC-Regular.ttf",
            "NotoSansSC-VF.ttf",
            "simhei.ttf",
            "simsun.ttf",
        )
    )
    bold_path = _find_report_font(
        (
            "NotoSansCJK-Bold.ttf",
            "NotoSansCJKsc-Bold.ttf",
            "NotoSansSC-Bold.ttf",
            "NotoSansSC-VF.ttf",
            "simhei.ttf",
            "simsunb.ttf",
        )
    )
    if regular_path is None:
        raise RuntimeError(
            "未找到可嵌入的中文 TrueType 字体；请安装 fonts-noto-cjk，"
            "或设置 CYBERORION_REPORT_FONT"
        )
    bold_path = bold_path or regular_path
    regular_name = "CyberOrionCJK"
    bold_name = "CyberOrionCJKBold"
    if regular_name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(regular_name, str(regular_path)))
    if bold_name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(bold_name, str(bold_path)))
    return regular_name, bold_name


def _pdf_inline_text(value: Any) -> str:
    from xml.sax.saxutils import escape

    text = _strip_terminal(_latex_safe_text(value)).strip()
    if not text:
        return "未记录。"
    return "<br/>".join(escape(line) for line in text.splitlines())


def _pdf_bullets(values: list[Any], limit: int = 12) -> list[str]:
    result: list[str] = []
    for value in values[:limit]:
        text = _pdf_inline_text(value)
        if text != "未记录。":
            result.append(f"- {text}")
    return result or ["未记录。"]


def _render_report_pdf_reportlab(context: dict[str, Any], pdf_path: Path) -> tuple[bool, str]:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable,
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        regular_font, bold_font = _register_report_fonts()
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"

    task = context.get("task") or {}
    background = context.get("background") or {}
    knowledge = context.get("knowledge") or {}
    execution = context.get("execution") or {}
    result = context.get("result") or {}
    usage = context.get("usage") or {}
    recommendations = context.get("recommendations") or []
    transcript = str(execution.get("transcript") or "")
    dispatch_lines = _dispatch_summary(execution, transcript)
    evidence_lines = _interesting_lines(transcript, 70)
    report_body = str(result.get("final_output") or "").strip()

    navy = colors.HexColor("#17243A")
    cyan = colors.HexColor("#0E9F9A")
    gold = colors.HexColor("#C98A18")
    ink = colors.HexColor("#1F2937")
    muted = colors.HexColor("#637083")
    panel = colors.HexColor("#F3F6F8")
    line_color = colors.HexColor("#D7E0E6")
    code_bg = colors.HexColor("#101820")

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="OrionTitle",
            parent=styles["Title"],
            fontName=bold_font,
            fontSize=22,
            leading=28,
            alignment=TA_CENTER,
            textColor=navy,
            spaceAfter=4 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionSubtitle",
            parent=styles["Normal"],
            fontName=regular_font,
            fontSize=10,
            leading=15,
            alignment=TA_CENTER,
            textColor=muted,
            spaceAfter=5 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionSection",
            parent=styles["Heading1"],
            fontName=bold_font,
            fontSize=14,
            leading=19,
            textColor=navy,
            spaceBefore=5 * mm,
            spaceAfter=2 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionSubsection",
            parent=styles["Heading2"],
            fontName=bold_font,
            fontSize=10.5,
            leading=15,
            textColor=cyan,
            spaceBefore=3 * mm,
            spaceAfter=1.5 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionBody",
            parent=styles["BodyText"],
            fontName=regular_font,
            fontSize=9.5,
            leading=15,
            textColor=ink,
            wordWrap="CJK",
            spaceAfter=2.4 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionMuted",
            parent=styles["BodyText"],
            fontName=regular_font,
            fontSize=8,
            leading=12,
            textColor=muted,
            wordWrap="CJK",
            spaceAfter=1.5 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionBullet",
            parent=styles["BodyText"],
            fontName=regular_font,
            fontSize=9,
            leading=14,
            leftIndent=4 * mm,
            firstLineIndent=-3 * mm,
            textColor=ink,
            wordWrap="CJK",
            spaceAfter=1.2 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionCode",
            parent=styles["Code"],
            fontName=regular_font,
            fontSize=7.8,
            leading=11,
            textColor=colors.HexColor("#E6EDF3"),
            backColor=code_bg,
            borderPadding=3 * mm,
            wordWrap="CJK",
            spaceAfter=2 * mm,
        )
    )

    def paragraph(value: Any, style: str = "OrionBody") -> Paragraph:
        return Paragraph(_pdf_inline_text(value), styles[style])

    def add_section(story: list[Any], number: str, title: str) -> None:
        story.append(Paragraph(f"{number}  {title}", styles["OrionSection"]))
        story.append(HRFlowable(width="100%", thickness=0.8, color=cyan, spaceAfter=3 * mm))

    def add_bullets(story: list[Any], values: list[Any]) -> None:
        story.extend(Paragraph(text, styles["OrionBullet"]) for text in _pdf_bullets(values))

    def add_panel(story: list[Any], content: list[Any]) -> None:
        plain = "\n".join(
            item.getPlainText() if hasattr(item, "getPlainText") else str(item)
            for item in content
        )
        # ReportLab tables cannot split an oversized cell across pages. Large
        # report bodies and terminal excerpts must stay as normal flowables so
        # the PDF renderer can paginate them instead of failing with LayoutError.
        if len(plain) > 1800 or plain.count("\n") > 18:
            story.append(HRFlowable(width="100%", thickness=0.5, color=line_color, spaceAfter=2 * mm))
            story.extend(content)
            story.append(Spacer(1, 2 * mm))
            return
        table = Table([[content]], colWidths=[174 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), panel),
                    ("BOX", (0, 0), (-1, -1), 0.5, line_color),
                    ("LINEBEFORE", (0, 0), (0, -1), 2.2, gold),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5 * mm),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5 * mm),
                    ("TOPPADDING", (0, 0), (-1, -1), 4 * mm),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3 * mm),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 2 * mm))

    def draw_page(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setStrokeColor(line_color)
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, height - 14 * mm, width - 18 * mm, height - 14 * mm)
        canvas.setFont(regular_font, 7.5)
        canvas.setFillColor(muted)
        canvas.drawString(18 * mm, height - 10.5 * mm, "CyberOrion · 安全分析")
        canvas.drawRightString(width - 18 * mm, height - 10.5 * mm, "证据优先 · 可复核")
        canvas.line(18 * mm, 13 * mm, width - 18 * mm, 13 * mm)
        canvas.drawCentredString(width / 2, 8 * mm, f"{doc.page}")
        canvas.restoreState()

    metrics = [
        ["任务 ID", str(task.get("id") or "未记录")],
        ["任务类型", str(task.get("type") or "未记录")],
        ["任务状态", str(task.get("status") or "未记录")],
        ["开始时间", str(task.get("created_at") or "未记录")],
        ["结束时间", str(task.get("ended_at") or "未记录")],
        ["耗时", f"{task.get('duration_sec') or 0} 秒"],
        ["上下文字符", str(usage.get("context_chars") or 0)],
        ["估算上下文 Token", str(usage.get("context_tokens_estimated") or 0)],
        ["输出 Token", str(usage.get("output_tokens") or "未提供")],
    ]
    metric_table = Table(
        [[paragraph(row[0], "OrionMuted"), paragraph(row[1], "OrionBody")] for row in metrics],
        colWidths=[43 * mm, 131 * mm],
        repeatRows=0,
    )
    metric_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), panel),
                ("BOX", (0, 0), (-1, -1), 0.5, line_color),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, line_color),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3 * mm),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3 * mm),
                ("TOPPADDING", (0, 0), (-1, -1), 2 * mm),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1 * mm),
            ]
        )
    )

    story: list[Any] = [
        Spacer(1, 8 * mm),
        Paragraph("CyberOrion 安全分析报告", styles["OrionTitle"]),
        Paragraph("专家复盘 · 证据链 · Agent 调度 · 可执行建议", styles["OrionSubtitle"]),
        HRFlowable(width="70%", thickness=1.3, color=gold, spaceAfter=5 * mm),
    ]
    add_section(story, "一", "执行摘要")
    add_panel(
        story,
        [
            paragraph(
                report_body
                or "本报告基于 CyberOrion 的实际终端记录生成。报告只陈述记录中可复核的事实，"
                "并明确区分知识背景、现场证据、推断和未验证事项。"
            )
        ],
    )

    add_section(story, "二", "任务背景与范围")
    story.append(metric_table)
    story.append(Spacer(1, 2 * mm))
    story.append(paragraph(f"场景摘要：{background.get('summary') or '未提供。'}"))
    if background.get("ctf_name") or background.get("challenge"):
        story.append(
            paragraph(
                f"CTF：{background.get('ctf_name') or '未记录'}；"
                f"Challenge：{background.get('challenge') or '未记录'}",
                "OrionMuted",
            )
        )
    story.append(
        paragraph(
            f"统计口径：{usage.get('basis') or 'CAI 终端记录估算'}。",
            "OrionMuted",
        )
    )

    add_section(story, "三", "知识库与威胁背景")
    story.append(paragraph(_knowledge_summary(knowledge)))
    if knowledge.get("sources"):
        story.append(Paragraph("来源：" + "、".join(
            _pdf_inline_text(item) for item in knowledge.get("sources", [])[:12]
        ), styles["OrionMuted"]))

    add_section(story, "四", "执行链路与关键证据")
    story.append(
        paragraph(
            "以下内容按实际终端记录组织。Agent 返回为空、工具失败或证据不足时，报告保留该状态，"
            "不以推测替代缺失过程。",
            "OrionMuted",
        )
    )
    story.append(Paragraph("Agent 调度摘要", styles["OrionSubsection"]))
    add_bullets(story, dispatch_lines)
    story.append(Paragraph("关键过程与中间结果", styles["OrionSubsection"]))
    add_bullets(story, evidence_lines)

    add_section(story, "五", "任务结果与安全建议")
    add_panel(
        story,
        [
            paragraph(
                f"最终状态：{result.get('status') or '未记录'}；"
                f"进程退出码：{result.get('exit_code') if result.get('exit_code') is not None else '未记录'}。"
            ),
            paragraph(_short_text(result.get("final_output") or "", 4200)),
        ],
    )
    add_bullets(story, recommendations)

    add_section(story, "六", "附录：终端证据节选")
    appendix_lines = [line for line in transcript.splitlines() if line.strip()][-100:]
    if appendix_lines:
        for raw_line in appendix_lines:
            story.append(
                Paragraph(
                    _pdf_inline_text(_short_text(raw_line, 460)),
                    styles["OrionCode"],
                )
            )
    else:
        story.append(paragraph("未捕获终端证据。", "OrionMuted"))

    try:
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        document = SimpleDocTemplate(
            str(pdf_path),
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=20 * mm,
            bottomMargin=18 * mm,
            title="CyberOrion 安全分析报告",
            author="CyberOrion Report Agent",
        )
        document.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, ""


async def generate_report_artifacts(
    recording: dict[str, Any],
    output_dir: str | Path,
) -> dict[str, Any]:
    """Run Report Agent, write structured source artifacts, and compile a PDF."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    recording_for_report = dict(recording)
    transcript, source = _full_transcript(recording_for_report)
    terminal_log = output / "terminal_full.log"
    if transcript and not terminal_log.is_file():
        terminal_log.write_text(transcript, encoding="utf-8")
    if terminal_log.is_file():
        recording_for_report["full_log_path"] = str(terminal_log)
    context = build_report_context(recording_for_report)
    (output / "report_context_seed.json").write_text(
        json.dumps({"source": source, "context": context}, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    report_agent_output = ""
    agent_error = ""
    agent_called = True
    try:
        report_agent_output = await _call_report_agent(context, output)
    except Exception as exc:
        agent_error = f"{type(exc).__name__}: {exc}"
    if report_agent_output:
        context = build_report_context(recording_for_report, report_agent_output)
    (output / "report_context.json").write_text(
        json.dumps(context, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    tex_path = output / "report.tex"
    tex_path.write_text(render_report_tex(context), encoding="utf-8")
    compiled, error = await asyncio.to_thread(_compile_tex, tex_path)
    renderer = "latex" if compiled else ""
    fallback_error = ""
    if not compiled:
        fallback_pdf = output / "report.pdf"
        fallback_ok, fallback_error = await asyncio.to_thread(
            _render_report_pdf_reportlab,
            context,
            fallback_pdf,
        )
        if fallback_ok:
            compiled = True
            renderer = "reportlab"
        else:
            error = f"{error}; ReportLab fallback: {fallback_error}" if error else fallback_error
    status = "ready" if compiled else "unavailable"
    (output / "report_status.json").write_text(
        json.dumps(
            {
                "status": status,
                "agent_called": agent_called,
                "agent_output_available": bool(report_agent_output),
                "agent_error": agent_error,
                "error": error,
                "latex_error": error if renderer == "reportlab" else "",
                "renderer": renderer or None,
                "pdf": "report.pdf" if compiled else None,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return {
        "status": status,
        "agent_called": agent_called,
        "agent_output_available": bool(report_agent_output),
        "agent_error": agent_error,
        "pdf": str(output / "report.pdf") if compiled else None,
        "tex": str(tex_path),
        "error": error,
        "renderer": renderer or None,
    }
