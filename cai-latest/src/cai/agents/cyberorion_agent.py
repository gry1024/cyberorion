"""CyberOrion orchestration agent.

CyberOrion exposes bounded coordination tools. Knowledge Agent and every native
CAI specialist are selected through capability-based dispatchers.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import pkgutil
import sys
import uuid
from pathlib import Path
from typing import Any

from cai.sdk.agents import Agent, Runner, RunConfig, function_tool


_AGENT_EVENT_PREFIX = "[[CYBERORION_AGENT_EVENT]]"
_TASK_SKILLS = {
    "ctf": "ctf",
    "attack_chain": "attack-chain-reconstruction",
    "traffic_analysis": "traffic-analysis",
    "code_repair": "code-vulnerability-repair",
    "vulnerability_repair": "code-vulnerability-repair",
    "threat_analysis": "threat-analysis",
}


def _load_task_skill(task_type: str) -> tuple[str, str]:
    skill_name = _TASK_SKILLS.get((task_type or "").strip().lower(), "")
    if not skill_name:
        return "", ""
    _ensure_cyberorion_source()
    try:
        from cyberorion.skills import load_skill_document

        return skill_name, load_skill_document("cyberorion", skill_name)
    except Exception:
        return skill_name, ""


def build_cyberorion_instructions(task_type: str | None = None) -> str:
    """Build task-specific workflow guidance without turning task types into tools."""
    normalized = (task_type or os.getenv("CAI_TASK_TYPE") or "general").strip().lower()
    task_context = os.getenv("CAI_TASK_CONTEXT", "").strip()
    task_name = {
        "ctf": "CTF 安全挑战",
        "code_repair": "修复代码漏洞",
        "attack_chain": "复原攻击链条",
        "purple_team": "攻防演练",
    }.get(normalized, "通用安全任务")
    task_focus = {
        "ctf": (
            "围绕授权靶场与挑战目标进行推理、验证和总结。必须先调度 CTF agent（one_tool / "
            "CTF agent，带 generic_linux_command）在靶容器内真实执行命令：定位并读取 flag 文件"
            "（如 /app/flag.txt、/challenge/metadata.json、/root/flag.txt），把工具的真实输出"
            "原样带回；严禁仅凭推理或知识库内容占位交付 flag；Knowledge Agent 只提供背景参考，"
            "不构成完成依据；任务完成前可用 flag_discriminator 校验格式。"
        ),
        "code_repair": (
            "当前终端任务环境：修复代码漏洞。先复现或确认漏洞，再让 CodeAgent 检查并修复，"
            "再让 Retester 验证修复；只修改授权工作区，保留 diff 和测试输出。"
        ),
        "attack_chain": (
            "当前终端任务环境：复原攻击链条。attack_chain 是一个多 Agent 协作任务："
            "基于日志/流量数据构建时间线，从日志、流量和端点证据构建时间线，"
            "标注资产、来源、行为、ATT&CK 映射和证据，不得凭空补齐链条。"
            "优先调度 Network Security Analyzer、DFIR、Replay Attack Agent。"
        ),
        "purple_team": (
            "这是一个系统化攻防演练任务：按授权范围组织红蓝 Agent，"
            "记录调度、证据、检测、处置和复查结果。"
        ),
    }.get(normalized, "根据用户目标动态规划并调用匹配的专业 Agent。")
    skill_name, skill_text = _load_task_skill(normalized)
    skill_block = (
        f"\n当前按需加载 Skill：{skill_name}\n{skill_text}\n"
        if skill_text
        else ""
    )
    context_block = (
        f"\n任务工作区与事实材料：\n{task_context}\n"
        if task_context else ""
    )
    return f"""你是 CyberOrion，面向安全人员的安全 SuperAgent 和任务编排器。

当前任务类型：{task_name}
任务指导：{task_focus}

执行规则：
    1. 先理解目标、资产范围、约束、证据和最终产物；攻击链任务必须基于证据复原攻击链。
2. 在系统化任务开始阶段，先用 dispatch_agent 选择 Knowledge Agent 获取一次结构化知识背景；知识库是参考来源，不是当前环境事实。
3. 后续根据当前任务与所有可用 Agent 的能力匹配程度继续调用 dispatch_agent；相互独立的证据分析、代码复测、网络研判等子任务必须优先调用 dispatch_agents_parallel 并行执行，不要串行等待无依赖任务。
4. 对 attack_chain、purple_team 等系统化任务，必须通过多个专业 Agent 协作完成，持续记录调度和返回结果。
    5. 根据新证据重规划，区分事实、推断、失败和未验证事项；证据不足时明确说明。
6. 所有任务完成后输出结构化结果。系统化任务由系统自动调用 Report Agent 生成中文 PDF；普通聊天不触发报告生成。
{context_block}
过程记录要求：每一步先输出简短、可审计的 reasoning 摘要，再调用工具；工具返回后说明证据、结论和下一步。不要隐藏工具参数、工具结果、子 Agent 任务或最终交付物。
{skill_block}
"""


def _ensure_cyberorion_source() -> None:
    candidate = Path(__file__).resolve().parents[4] / "cyberorion"
    if candidate.is_dir() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))


def _discover_agent_instances() -> list[tuple[str, Agent[Any]]]:
    """Discover native CAI agents without exposing each one as a CyberOrion tool."""
    import cai.agents as agents_package

    found: list[tuple[str, Agent[Any]]] = []
    seen: set[int] = set()
    for _, module_name, is_package in pkgutil.iter_modules(
        agents_package.__path__, agents_package.__name__ + "."
    ):
        if is_package or module_name.rsplit(".", 1)[-1] == "cyberorion_agent":
            continue
        try:
            module = importlib.import_module(module_name)
        except Exception:
            continue
        for attr_name in dir(module):
            if attr_name.startswith("_"):
                continue
            try:
                candidate = getattr(module, attr_name)
            except Exception:
                continue
            if not isinstance(candidate, Agent) or id(candidate) in seen:
                continue
            seen.add(id(candidate))
            found.append((attr_name, candidate))
    return found


def _agent_catalog() -> list[tuple[str, Agent[Any]]]:
    return [
        (name, agent)
        for name, agent in _discover_agent_instances()
        if name not in {"cyberorion_agent", "report_agent"}
        and agent.name.lower()
        not in {"cyberorion", "cyberorion blue team", "report agent", "reporting agent"}
    ]


def _select_agent(task: str, preferred_agent: str = "") -> tuple[str, Agent[Any]] | None:
    catalog = _agent_catalog()
    if not catalog:
        return None
    preferred = preferred_agent.strip().lower()
    if preferred:
        for name, agent in catalog:
            if preferred in {name.lower(), agent.name.lower()}:
                return name, agent

    if any(
        marker in f"{task} {preferred_agent}".lower()
        for marker in ("knowledge", "知识库", "知识背景", "rag", "背景知识")
    ):
        for name, agent in catalog:
            if name.lower() == "knowledge_agent" or agent.name.lower() == "knowledge agent":
                return name, agent

    terms = {
        term
        for term in task.lower().replace("/", " ").replace("-", " ").split()
        if len(term) > 2
    }
    scored: list[tuple[int, str, Agent[Any]]] = []
    for name, agent in catalog:
        profile = f"{name} {agent.name} {agent.description} {agent.instructions}".lower()
        score = sum(1 for term in terms if term in profile)
        scored.append((score, name, agent))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return scored[0][1], scored[0][2]


def _dispatch_max_turns() -> int:
    raw = str(os.getenv("CAI_DISPATCH_MAX_TURNS") or "4").strip()
    try:
        value = int(raw)
    except ValueError:
        return 4
    return max(1, min(value, 8))


def _clip(value: Any, limit: int = 4200) -> str:
    text = str(value if value is not None else "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n...（已截断）"


def _emit_agent_event(payload: dict[str, Any]) -> None:
    print(
        _AGENT_EVENT_PREFIX + json.dumps(payload, ensure_ascii=False, default=str),
        flush=True,
    )


def _extract_message_text(item: Any) -> str:
    raw = getattr(item, "raw_item", None)
    if raw is None:
        return ""
    content = getattr(raw, "content", None) or []
    parts: list[str] = []
    for piece in content:
        text = getattr(piece, "text", None)
        if text:
            parts.append(str(text))
    return "\n".join(parts).strip()


def _extract_tool_call(item: Any) -> tuple[str, str]:
    raw = getattr(item, "raw_item", None)
    if raw is None:
        return "?", "{}"
    name = getattr(raw, "name", None) or getattr(raw, "type", None) or "?"
    arguments = getattr(raw, "arguments", "{}")
    if not isinstance(arguments, str):
        try:
            arguments = json.dumps(arguments, ensure_ascii=False, default=str)
        except Exception:
            arguments = str(arguments)
    return str(name), arguments


def _extract_reasoning_text(item: Any) -> str:
    raw = getattr(item, "raw_item", None)
    if raw is None:
        return ""
    summary = getattr(raw, "summary", None) or []
    parts: list[str] = []
    for piece in summary:
        text = getattr(piece, "text", None) or (piece if isinstance(piece, str) else None)
        if text:
            parts.append(str(text))
    return "\n".join(parts).strip()


def _stream_event_payloads(event: Any, dispatch_id: str, agent_name: str) -> list[dict[str, Any]]:
    event_type = getattr(event, "type", "")
    payloads: list[dict[str, Any]] = []
    if event_type == "raw_response_event":
        data = getattr(event, "data", None)
        data_type = getattr(data, "type", "")
        if data_type in {"response.output_text.delta", "response.reasoning_summary_text.delta"}:
            delta = getattr(data, "delta", "") or ""
            if delta:
                payloads.append(
                    {
                        "type": "agent_output",
                        "id": dispatch_id,
                        "agent": agent_name,
                        "kind": "reasoning" if "reasoning" in data_type else "text",
                        "text": _clip(delta, 1600),
                    }
                )
        elif data_type == "response.output_item.done":
            item = getattr(data, "item", None)
            if getattr(item, "type", "") == "function_call":
                name = str(getattr(item, "name", "?") or "?")
                args = getattr(item, "arguments", "{}")
                payloads.append(
                    {
                        "type": "agent_tool_call",
                        "id": dispatch_id,
                        "agent": agent_name,
                        "tool": name,
                        "args": _clip(args, 2200),
                    }
                )
        return payloads
    if event_type != "run_item_stream_event":
        return payloads
    name = getattr(event, "name", "")
    item = getattr(event, "item", None)
    if item is None:
        return payloads
    item_type = getattr(item, "type", "")
    if name == "tool_called" or item_type == "tool_call_item":
        tool, args = _extract_tool_call(item)
        payloads.append(
            {
                "type": "agent_tool_call",
                "id": dispatch_id,
                "agent": agent_name,
                "tool": tool,
                "args": _clip(args, 2200),
            }
        )
    elif name == "tool_output" or item_type == "tool_call_output_item":
        payloads.append(
            {
                "type": "agent_tool_output",
                "id": dispatch_id,
                "agent": agent_name,
                "output": _clip(getattr(item, "output", ""), 3200),
            }
        )
    elif name == "message_output_created" or item_type == "message_output_item":
        text = _extract_message_text(item)
        if text:
            payloads.append(
                {
                    "type": "agent_output",
                    "id": dispatch_id,
                    "agent": agent_name,
                    "kind": "message",
                    "text": _clip(text, 3200),
                }
            )
    elif name == "reasoning_item_created" or item_type == "reasoning_item":
        text = _extract_reasoning_text(item)
        if text:
            payloads.append(
                {
                    "type": "agent_output",
                    "id": dispatch_id,
                    "agent": agent_name,
                    "kind": "reasoning",
                    "text": _clip(text, 3200),
                }
            )
    return payloads


async def _run_selected_agent(
    name: str,
    agent: Agent[Any],
    task: str,
    context: str,
    phase: str = "",
) -> dict[str, Any]:
    prompt = (
        f"子任务：{task}\n"
        f"当前上下文与证据：{context}\n"
        "只基于提供的证据和授权范围工作，返回结构化结论、证据、未决问题和建议。"
    )
    dispatch_id = f"agent-{uuid.uuid4().hex[:10]}"
    dispatch_max_turns = _dispatch_max_turns()
    _emit_agent_event(
        {
            "type": "agent_start",
            "id": dispatch_id,
            "agent": agent.name,
            "agent_key": name,
            "title": task,
            "phase": phase or "-",
            "max_turns": dispatch_max_turns,
        }
    )
    try:
        result = Runner.run_streamed(
            agent,
            input=prompt,
            max_turns=dispatch_max_turns,
            run_config=RunConfig(tracing_disabled=True),
        )
        async for event in result.stream_events():
            for payload in _stream_event_payloads(event, dispatch_id, agent.name):
                _emit_agent_event(payload)
        output = str(getattr(result, "final_output", "") or "").strip()
        _emit_agent_event(
            {
                "type": "agent_done",
                "id": dispatch_id,
                "agent": agent.name,
                "agent_key": name,
                "result": _clip(output, 8000),
            }
        )
        return {"status": "completed", "agent": name, "agent_name": agent.name, "result": output}
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        _emit_agent_event(
            {
                "type": "agent_error",
                "id": dispatch_id,
                "agent": agent.name,
                "agent_key": name,
                "error": error,
            }
        )
        return {"status": "failed", "agent": name, "agent_name": agent.name, "result": error}


@function_tool(
    name_override="dispatch_agent",
    description_override=(
        "根据当前任务、阶段、证据和所有可用 Agent 的能力匹配度，选择并调用一个 Agent；"
        "Knowledge Agent 与其他 CAI 专业 Agent 使用同一个入口，返回结构化结果。"
    ),
)
async def dispatch_agent(
    task: str,
    context: str = "",
    preferred_agent: str = "",
    phase: str = "",
) -> str:
    """Select and run the best matching native CAI Agent."""
    if not preferred_agent and phase.strip().lower() in {"initial", "knowledge", "background"}:
        preferred_agent = "Knowledge Agent"
    selected = _select_agent(task, preferred_agent)
    if selected is None:
        return json.dumps(
            {"status": "unavailable", "agent": None, "result": "没有可用的专业 Agent。"},
            ensure_ascii=False,
        )
    name, agent = selected
    return json.dumps(
        await _run_selected_agent(name, agent, task, context, phase),
        ensure_ascii=False,
    )


@function_tool(
    name_override="dispatch_agents_parallel",
    description_override=(
        "并行调用多个相互独立的 CAI 专业 Agent。tasks_json 是 JSON 数组字符串；"
        "每个对象可包含 task、context、preferred_agent、phase。"
        "仅用于无依赖的并行证据分析、代码复测或网络研判。"
    ),
)
async def dispatch_agents_parallel(tasks_json: str) -> str:
    """Run independent native CAI Agents concurrently and return all results."""
    try:
        parsed_tasks = json.loads(tasks_json or "[]")
    except json.JSONDecodeError as exc:
        return json.dumps(
            {"status": "failed", "results": [], "result": f"tasks_json 不是有效 JSON：{exc}"},
            ensure_ascii=False,
        )
    if not isinstance(parsed_tasks, list):
        return json.dumps(
            {"status": "failed", "results": [], "result": "tasks_json 必须是 JSON 数组。"},
            ensure_ascii=False,
        )
    prepared: list[tuple[str, Agent[Any], str, str, str]] = []
    for item in parsed_tasks:
        if not isinstance(item, dict):
            continue
        task = str(item.get("task") or "").strip()
        if not task:
            continue
        context = str(item.get("context") or "")
        preferred_agent = str(item.get("preferred_agent") or "")
        phase = str(item.get("phase") or "parallel")
        if not preferred_agent and phase.strip().lower() in {"initial", "knowledge", "background"}:
            preferred_agent = "Knowledge Agent"
        selected = _select_agent(task, preferred_agent)
        if selected is None:
            continue
        name, agent = selected
        prepared.append((name, agent, task, context, phase))
    if not prepared:
        return json.dumps(
            {"status": "unavailable", "results": [], "result": "没有可并行调用的专业 Agent。"},
            ensure_ascii=False,
        )
    results = await asyncio.gather(
        *[
            _run_selected_agent(name, agent, task, context, phase)
            for name, agent, task, context, phase in prepared
        ],
        return_exceptions=True,
    )
    normalized: list[dict[str, Any]] = []
    for result in results:
        if isinstance(result, Exception):
            normalized.append({"status": "failed", "agent": None, "result": f"{type(result).__name__}: {result}"})
        else:
            normalized.append(result)
    return json.dumps({"status": "completed", "results": normalized}, ensure_ascii=False)


def _build_agent_tools() -> list[Any]:
    """Expose CyberOrion coordination tools."""
    _ensure_cyberorion_source()
    return [dispatch_agent, dispatch_agents_parallel]


cyberorion_agent = Agent(
    name="CyberOrion",
    description=(
        "CyberOrion 安全 SuperAgent：按需加载任务 Skill，通过 dispatch_agent 或 "
        "dispatch_agents_parallel 选择 Knowledge Agent 或 CAI 专业 Agent，并输出可审计结果。"
    ),
    instructions=build_cyberorion_instructions(),
    tools=_build_agent_tools(),
)


def transfer_to_cyberorion_agent(**kwargs: Any) -> Agent[Any]:
    """Return the CyberOrion agent."""
    del kwargs
    return cyberorion_agent
