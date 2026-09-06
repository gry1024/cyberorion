#!/usr/bin/env python3
"""无头驱动 CyberOrion /ws/cai 任务：连接 WebSocket，启动任务，流式打印，等待结束。

用法:
  python scripts/ws_task_driver.py --task code_repair [--host 127.0.0.1:8000]
                                  [--prompt "..."] [--workdir code_repair]
                                  [--ctf-name NAME] [--timeout 2000]
退出码: 0=success, 2=failed/timeout/异常
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time

import websockets


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1:8000")
    ap.add_argument("--task", default="code_repair")
    ap.add_argument("--prompt", default="")
    ap.add_argument("--workdir", default="")
    ap.add_argument("--ctf-name", default="")
    ap.add_argument("--ctf-inside", default="")
    ap.add_argument("--ctf-challenge", default="")
    ap.add_argument("--context", default="")
    ap.add_argument("--timeout", type=float, default=2000)
    args = ap.parse_args()

    payload: dict = {
        "type": "websocket.receive",
        "rows": 40,
        "cols": 140,
        "CAI_AGENT_TYPE": "cyberorion_agent",
        "CAI_TASK_TYPE": args.task,
    }
    if args.prompt:
        payload["prompt"] = args.prompt
    if args.workdir:
        payload["task_workdir"] = args.workdir
    if args.ctf_name:
        payload["CTF_NAME"] = args.ctf_name
    if args.ctf_inside:
        payload["CTF_INSIDE"] = args.ctf_inside
    if args.ctf_challenge:
        payload["CTF_CHALLENGE"] = args.ctf_challenge
    if args.context:
        payload["CAI_TASK_CONTEXT"] = args.context

    uri = f"ws://{args.host}/ws/cai"
    final_status = "unknown"
    deadline = time.monotonic() + args.timeout
    async with websockets.connect(uri, max_size=8 * 1024 * 1024) as ws:
        await ws.send(json.dumps(payload, ensure_ascii=False))
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
                try:
                    evt = json.loads(raw)
                except Exception:
                    sys.stdout.write(raw)
                    sys.stdout.flush()
                    continue
                etype = evt.get("type")
                if etype in ("agent_start", "agent_done", "agent_error"):
                    print(f"\n=== [{etype}] {evt.get('agent')} {evt.get('summary') or evt.get('error') or ''}")
                elif etype == "agent_output":
                    text = evt.get("text") or ""
                    sys.stdout.write(text[-2000:] if len(text) > 2000 else text)
                    sys.stdout.flush()
                elif etype in ("task_status", "status", "final"):
                    print(f"\n=== [status] {evt}")
                    final_status = str(evt.get("status") or final_status)
                    if str(evt.get("type")) == "final" or etype == "final":
                        break
                else:
                    print(f"\n=== [event] {json.dumps(evt, ensure_ascii=False)[:400]}")
        except (asyncio.TimeoutError, TimeoutError):
            print("\n=== driver timeout waiting for task to finish")
            return 2
        except websockets.ConnectionClosed as exc:
            print(f"\n=== ws closed: {exc.code} {exc.reason}")
    print(f"\n=== final_status={final_status}")
    return 0 if final_status == "success" else 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
