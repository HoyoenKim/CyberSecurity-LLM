#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import yaml
import argparse
from typing import Any, Dict, List, Tuple, Optional

from openai import OpenAI


# -------------------------------------------------------------------
# 1) OpenAI 키 로더 (사용자 코드 유지)
# -------------------------------------------------------------------
def load_openai_token(config_path: str = "./llm_token.yaml") -> str:
    """
    1) llm_token.yaml 의 openai.api_key 우선
    2) 없으면 마지막에 환경변수 OPENAI_API_KEY 사용
    """
    if os.path.exists(config_path):
        print(f"[DEBUG] Loading OpenAI API key from {config_path}")
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if isinstance(data, dict):
            oa_cfg = data.get("openai")
            if isinstance(oa_cfg, dict) and "api_key" in oa_cfg:
                key = oa_cfg["api_key"]
                print(f"[DEBUG] Loaded key from YAML (prefix={key[:6]}...)")
                return key

    env_key = os.getenv("OPENAI_API_KEY")
    if env_key:
        print("[DEBUG] Using OPENAI_API_KEY from environment "
              f"(prefix={env_key[:6]}...)")
        return env_key

    raise RuntimeError(
        f"OpenAI API 키를 찾을 수 없습니다. "
        f"{config_path}의 openai.api_key 또는 환경변수 OPENAI_API_KEY를 확인하세요."
    )


# -------------------------------------------------------------------
# 2) 로그(JSON)에서 "유의미 이벤트"만 뽑아 요약
#    - discovered node / discovered credential / infected node / flag / score-done
# -------------------------------------------------------------------
_RX_INFECT = re.compile(
    r"Infected node '([^']+)' from '([^']+)' via ([^ ]+) with credential '([^']+)'"
)
_RX_NODE = re.compile(r"discovered node:\s*([A-Za-z0-9_\.]+)")
_RX_CRED = re.compile(
    r"discovered credential:\s*CachedCredential\(node='([^']+)',\s*port='([^']+)',\s*credential='([^']+)'\)"
)
_RX_FLAG = re.compile(r"CTFFLAG:\s*([A-Za-z0-9_\-]+)")

def _trim(s: str, n: int = 240) -> str:
    s = (s or "").strip().replace("\n", " | ")
    return s if len(s) <= n else (s[: n - 3] + "...")

def load_episode_json(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, list):
        raise ValueError("입력 JSON은 step 리스트(list) 형태여야 합니다.")
    return obj

def summarize_episode(events: List[Dict[str, Any]], env_name: str) -> Dict[str, Any]:
    discovered_nodes: List[Dict[str, Any]] = []
    discovered_creds: List[Dict[str, Any]] = []
    infections: List[Dict[str, Any]] = []
    flags: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []

    final_score = None
    max_score = None
    done_any = False

    # step별 마지막 상태(점수/종료)
    for e in events:
        if isinstance(e.get("score"), (int, float)):
            final_score = e.get("score")
        if isinstance(e.get("max_score"), (int, float)):
            max_score = e.get("max_score")
        if e.get("done") is True:
            done_any = True

    # 유의미 이벤트 추출
    for e in events:
        step = e.get("step")
        action = e.get("action")
        reward = e.get("reward")
        score = e.get("score")
        env_log = e.get("env_log", "") or ""

        # discovered node
        for m in _RX_NODE.finditer(env_log):
            node = m.group(1).rstrip(".")
            discovered_nodes.append({
                "step": step,
                "node": node,
                "action": action,
            })
            evidence.append({
                "step": step, "kind": "discovered_node",
                "action": action, "log": _trim(env_log)
            })

        # discovered credential
        for m in _RX_CRED.finditer(env_log):
            node, port, cred = m.group(1).rstrip("."), m.group(2), m.group(3)
            discovered_creds.append({
                "step": step,
                "node": node,
                "port": port,
                "credential": cred,
                "action": action,
            })
            evidence.append({
                "step": step, "kind": "discovered_credential",
                "action": action, "log": _trim(env_log)
            })

        # infection
        m = _RX_INFECT.search(env_log)
        if m:
            target, src, proto, cred = m.group(1), m.group(2), m.group(3), m.group(4)
            infections.append({
                "step": step,
                "src": src,
                "dst": target,
                "protocol": proto,
                "credential": cred,
                "reward": reward,
                "score": score,
                "action": action,
            })
            evidence.append({
                "step": step, "kind": "infected_node",
                "action": action, "log": _trim(env_log)
            })

        # flag
        m = _RX_FLAG.search(env_log)
        if m:
            flags.append({"step": step, "flag": m.group(1), "action": action})
            evidence.append({
                "step": step, "kind": "flag",
                "action": action, "log": _trim(env_log)
            })

        # 목표 달성/종료 근거도 일부 남김
        if e.get("done") is True:
            evidence.append({
                "step": step, "kind": "done",
                "action": action,
                "log": _trim(env_log),
            })

    # hop 테이블(감염 경로 중심) 만들기: dst 기준으로 가장 먼저 발견/크리덴셜 step 매핑
    first_disc: Dict[str, int] = {}
    for d in discovered_nodes:
        node = d["node"]
        st = d["step"]
        if isinstance(st, int) and node not in first_disc:
            first_disc[node] = st

    first_cred: Dict[str, int] = {}
    for c in discovered_creds:
        node = c["node"]
        st = c["step"]
        if isinstance(st, int) and node not in first_cred:
            first_cred[node] = st

    hops: List[Dict[str, Any]] = []
    for i, inf in enumerate(infections, start=1):
        dst = inf["dst"]
        hops.append({
            "hop": i,
            "from": inf["src"],
            "to": dst,
            "discovery_step": first_disc.get(dst),
            "credential_step": first_cred.get(dst),
            "connect_step": inf["step"],
            "protocol": inf["protocol"],
            "credential": inf["credential"],
        })

    # evidence 너무 길면 자르기 (PoC 기준)
    # 감염/크리덴셜/노드발견/플래그 우선, 최대 40개
    priority = {"infected_node": 0, "flag": 1, "discovered_credential": 2, "discovered_node": 3, "done": 4}
    evidence_sorted = sorted(
        evidence,
        key=lambda x: (priority.get(x["kind"], 99), x.get("step", 10**9))
    )
    evidence_sorted = evidence_sorted[:40]

    summary = {
        "env": env_name,
        "stats": {
            "total_steps": len(events),
            "final_score": final_score,
            "max_score": max_score,
            "done": done_any,
            "flags": [f["flag"] for f in flags],
        },
        "attack_path": {
            "infections": infections,   # 원본(요약) 이벤트
            "hops": hops,               # 보고서/mermaid 생성에 쓰기 좋게 정리
        },
        "discoveries": {
            "nodes": discovered_nodes[:50],
            "credentials": discovered_creds[:50],
        },
        "evidence": evidence_sorted,
    }
    return summary


# -------------------------------------------------------------------
# 3) 프롬프트: Mermaid + 해당 경로 설명 보고서 생성
# -------------------------------------------------------------------
def build_messages(summary: Dict[str, Any]) -> List[Dict[str, str]]:
    developer = (
        "You are a security analyst. You will read a summarized CyberBattleSim episode log "
        "and produce an attack-path diagram and a report strictly grounded in the given log. "
        "Do not invent facts. Do not provide real-world exploitation instructions; keep it "
        "as a simulation report based only on the provided events."
    )

    user = (
        "The JSON below is a structured summary extracted from a single episode log.\n"
        "Using ONLY this JSON as evidence, generate a Markdown report with the sections and constraints below.\n\n"
        "Requirements:\n"
        "1) Include exactly ONE Mermaid code block under the section title 'Attack Path (Mermaid)'.\n"
        "   - The Mermaid block MUST start with: 'flowchart TB'\n"
        "   - Keep node labels short (e.g., AttackerLaptop, OBD, DCAN, GTW, CCAN)\n"
        "   - DO NOT use any HTML tags (no <br/>, <b>, etc.)\n"
        "   - Edge labels must be short and include the step number plus the key action\n"
        "   - Include only meaningful hops (infection/pivot). Limit to 8–12 edges maximum\n"
        "2) Under 'Attack Path Explanation', explain the Mermaid path hop-by-hop in order.\n"
        "   - For each hop, describe: objective, prerequisite (credential/access), and outcome (pivot/score)\n"
        "   - Mention the relevant step numbers from the provided hops table\n"
        "   - 2–4 sentences per hop\n"
        "3) Under 'Evidence', include a Markdown table with columns: step, kind, action, log (trimmed)\n"
        "   - Use only the provided evidence items\n"
        "4) No external citations. No assumptions beyond the JSON.\n\n"
        "Input (JSON summary):\n"
        "```json\n"
        f"{json.dumps(summary, ensure_ascii=False, indent=2)}\n"
        "```\n"
    )

    return [
        {"role": "developer", "content": developer},
        {"role": "user", "content": user},
    ]


# -------------------------------------------------------------------
# 4) Responses API 호출 (사용자 코드 흐름 유지, input 포맷만 단순화)
# -------------------------------------------------------------------
def chat(client: OpenAI, messages: List[Dict[str, str]], model: str, max_output_tokens: int) -> str:
    print("[DEBUG] chat() 호출됨")
    print(f"[DEBUG] model = {model}")
    resp = client.responses.create(
        model=model,
        input=messages,  # 공식 예시: [{role, content}, ...] 또는 string :contentReference[oaicite:1]{index=1}
        max_output_tokens=max_output_tokens,
    )
    text = getattr(resp, "output_text", "") or ""
    return text


# -------------------------------------------------------------------
# 5) CLI
# -------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input_json", required=True, help="에피소드 로그 JSON 경로")
    ap.add_argument("--env", default="unknown", help="환경 이름(보고서에 표시)")
    ap.add_argument("--model", default="gpt-5", help="모델 이름(예: gpt-5)")
    ap.add_argument("--max_output_tokens", type=int, default=1600)
    ap.add_argument("--output_md", default="", help="결과를 저장할 md 파일 경로(옵션)")
    args = ap.parse_args()

    key = load_openai_token()
    client = OpenAI(api_key=key)

    events = load_episode_json(args.input_json)
    summary = summarize_episode(events, env_name=args.env)

    messages = build_messages(summary)
    report_md = chat(client, messages, model=args.model, max_output_tokens=args.max_output_tokens)

    if args.output_md:
        with open(args.output_md, "w", encoding="utf-8") as f:
            f.write(report_md)
        print(f"[DEBUG] Saved: {args.output_md}")
    else:
        print(report_md)


if __name__ == "__main__":
    main()
