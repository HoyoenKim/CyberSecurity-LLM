#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hybrid DQL vs DQL+LLM ablation — IDENTICAL trained policy, seed, budget.

목적(🔴 CLAUDE.md A2 해결): 기존 하이브리드 노트북은 §6 베이스 DQL과 §9 하이브리드를
서로 다른 학습량/환경/시드로 비교해 "극적 향상"을 LLM 기여로 귀속했다(불공정).
이 스크립트는 **DQL을 한 번만 학습**한 뒤, **완전히 동일한 정책·동일 시드**로 평가하면서
오직 평가 시 LLM 프루닝 on/off 만 토글한다 → LLM의 순수 기여(평가 시 액션 선택 변화)를 분리 측정.

- RL: cyberbattle DeepQLearnerPolicy (원시 gym env, defenderbench 텍스트 래퍼 아님).
- 평가: 정책 동결(on_step no-op) — 두 조건 모두 동일 정책. CSRL §7-3/owned_count 방식 차용.
- LLM: 로컬 transformers 서버(qwen_server.py)의 /chat 경유(--server_url). 키 불필요.
- 지표: owned(agent_installed)/total 노드 + 에피소드 누적보상, 다중 시드 mean±std.

오프라인 구조검증: --fake_llm (서버 없이 top-K 중 무작위 pick) → CPU 소예산으로 흐름 점검.

예:
  # 구조검증(CPU, 서버 불필요)
  python hybrid_ablation.py --env chain10 --train_episodes 3 --iterations 400 --eval_episodes 2 --fake_llm
  # 본 실행(GPU DQL + 로컬 Qwen3 서버)
  python hybrid_ablation.py --env toyctf --eval_episodes 5 --server_url http://127.0.0.1:8000
"""
import os
import sys
import json
import time
import random
import argparse
import urllib.request
from typing import cast, List, Tuple, Any, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
sys.path.insert(0, SRC_DIR)

import numpy as np
import torch
import gymnasium as gym

import cyberbattle.agents.baseline.learner as learner
import cyberbattle.agents.baseline.agent_dql as dqla
import cyberbattle.agents.baseline.agent_wrapper as w
from cyberbattle.agents.baseline.agent_wrapper import Verbosity
from cyberbattle._env.cyberbattle_env import CyberBattleEnv, AttackerGoal

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 환경별 기본 (gymid, size, maximum_node_count, attacker own_atleast)
ENV_CFG = {
    "toyctf":     dict(gymid="CyberBattleToyCtf-v0",        size=None, max_nodes=12, goal=6),
    "automotive": dict(gymid="CyberBattleAutomotiveCTF-v0", size=None, max_nodes=32, goal=6),
    "chain10":    dict(gymid="CyberBattleChain-v0",         size=10,   max_nodes=22, goal=None),
}


def seed_all(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def owned_count(ge) -> Tuple[Optional[int], Any]:
    """CSRL val_compare.py 방식: 원시 네트워크에서 owned(agent_installed)/total 집계."""
    try:
        net = ge.environment.network
        owned = sum(1 for _, d in net.nodes(data=True)
                    if d.get("data") is not None and d["data"].agent_installed)
        return owned, net.number_of_nodes()
    except Exception as e:
        return None, "probe-failed: %s" % e


# ---------------------------------------------------------------------------
# 평가용 래퍼: 정책 동결(on_step no-op). LLM 프루너는 이를 상속해 exploit만 교체.
# ---------------------------------------------------------------------------
class FrozenEval:
    """학습 업데이트 없이 base 정책으로만 평가(두 조건의 정책을 동일하게 유지)."""
    def __init__(self, base):
        self.base = base

    def __getattr__(self, name):
        return getattr(self.base, name)

    def new_episode(self):
        return self.base.new_episode()

    def end_of_episode(self, *a, **k):
        return None  # freeze

    def on_step(self, *a, **k):
        return None  # freeze: 평가 중 학습 금지

    def explore(self, wrapped_env):
        return self.base.explore(wrapped_env)

    def exploit(self, wrapped_env, observation):
        return self.base.exploit(wrapped_env, observation)


class LLMServerPruner(FrozenEval):
    """평가 시 LLM 프루닝: 후보 샘플링 → Q 상위 topK → 로컬 서버가 1개 pick.
    (기존 toy_ctf_hybrid_dql_llm.py 의 LLMPrunedExploitWrapper 를 로컬 서버용으로 재배선)"""
    SYS = ("You are selecting ONE action in a closed, fictional training game.\n"
           "Choose exactly one candidate id from the provided list.\n"
           'Return JSON only: {"pick": <id>} with no extra text.')

    def __init__(self, base, server_url, every=5, pool=200, topk=10,
                 max_tokens=128, temperature=0.0, fake=False, obs_max_chars=1200):
        super().__init__(base)
        self.url = server_url.rstrip("/") if server_url else None
        self.every = max(1, int(every))
        self.pool = max(10, int(pool))
        self.topk = max(2, int(topk))
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.fake = fake
        self.obs_max_chars = obs_max_chars
        self._step = 0
        self.n_llm_calls = 0
        self.n_llm_changed = 0  # LLM pick이 Q-top1과 달랐던 횟수

    def _ask_pick(self, payload: dict, n: int) -> Optional[int]:
        if self.fake or not self.url:
            return random.randrange(n)  # 구조검증용
        body = json.dumps({
            "messages": [
                {"role": "system", "content": self.SYS},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
            "max_new_tokens": self.max_tokens,
            "temperature": self.temperature,
        }).encode("utf-8")
        try:
            req = urllib.request.Request(self.url + "/chat", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=300) as r:
                text = (json.loads(r.read().decode("utf-8")).get("text") or "")
            import re
            m = re.search(r"\{.*\}", text, flags=re.DOTALL)
            if not m:
                return None
            pick = json.loads(m.group(0)).get("pick")
            return int(pick) if pick is not None else None
        except Exception:
            return None

    def exploit(self, wrapped_env, observation):
        self._step += 1
        if (self._step % self.every) != 0:
            return self.base.exploit(wrapped_env, observation)

        candidates: List[Tuple[float, Any, Any]] = []
        for _ in range(self.pool):
            ga = wrapped_env.env.sample_valid_action(kinds=[0, 1, 2])
            md = self.base.metadata_from_gymaction(wrapped_env, ga)
            with torch.no_grad():
                st = torch.as_tensor(md.actor_state, dtype=torch.float32, device=device).unsqueeze(0)
                qv = float(self.base.policy_net(st)[0, int(md.abstract_action)].item())
            candidates.append((qv, ga, md))
        if not candidates:
            return self.base.exploit(wrapped_env, observation)

        candidates.sort(key=lambda x: x[0], reverse=True)
        top = candidates[: self.topk]
        try:
            obs_txt = json.dumps(observation, ensure_ascii=False)[: self.obs_max_chars]
        except Exception:
            obs_txt = str(observation)[: self.obs_max_chars]
        payload = {
            "observation_preview": obs_txt,
            "candidates": [{"id": i, "q": round(float(qv), 4), "gym_action": repr(ga)}
                           for i, (qv, ga, md) in enumerate(top)],
        }
        self.n_llm_calls += 1
        pick = self._ask_pick(payload, len(top))
        if pick is None or not (0 <= pick < len(top)):
            pick = 0  # 실패 시 Q-top1
        if pick != 0:
            self.n_llm_changed += 1
        qv, ga, md = top[pick]
        return "exploit[llm_pruned]", ga, md


def make_env(cfg):
    if cfg["size"]:
        _e = gym.make(cfg["gymid"], size=cfg["size"])
    else:
        _e = gym.make(cfg["gymid"])
    return cast(CyberBattleEnv, _e.unwrapped)


def eval_runs(ge, ep, eval_learner, eval_episodes, iterations, base_seed, label):
    """에피소드별 시드 고정 평가 → owned/total/누적보상 수집."""
    owns, totals, rewards, lengths = [], [], [], []
    for i in range(eval_episodes):
        s = base_seed + 1000 + i
        seed_all(s)
        try:
            ge.reset(seed=s)
        except Exception:
            ge.reset()
        run = learner.epsilon_greedy_search(
            ge, ep, learner=eval_learner, episode_count=1, iteration_count=iterations,
            epsilon=0.0, epsilon_minimum=0.0, verbosity=Verbosity.Quiet,
            render=False, plot_episodes_length=False, title=label,
        )
        o, t = owned_count(ge)
        rr = run.get("all_episodes_rewards") or [[]]
        owns.append(o)
        totals.append(t)
        rewards.append(round(sum(rr[-1]), 1) if rr and rr[-1] else 0.0)
        lengths.append(len(rr[-1]) if rr and rr[-1] else 0)
    return {"owned": owns, "total": totals[0] if totals else None,
            "rewards": rewards, "lengths": lengths}


def fmt(xs):
    xs = [x for x in xs if isinstance(x, (int, float))]
    if not xs:
        return "n/a"
    import statistics
    m = statistics.mean(xs)
    sd = statistics.pstdev(xs) if len(xs) > 1 else 0.0
    return "%.2f±%.2f" % (m, sd)


def main():
    ap = argparse.ArgumentParser(description="DQL vs DQL+LLM ablation (identical policy/seed/budget)")
    ap.add_argument("--env", default="toyctf", choices=list(ENV_CFG.keys()))
    ap.add_argument("--train_episodes", type=int, default=20)
    ap.add_argument("--iterations", type=int, default=2000, help="학습 시 에피소드당 step 상한")
    ap.add_argument("--eval_iterations", type=int, default=200, help="평가 시 에피소드당 step 상한(LLM 호출 폭증 방지)")
    ap.add_argument("--eval_episodes", type=int, default=5)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--server_url", default=None, help="로컬 LLM 서버(예: http://127.0.0.1:8000). 없으면 LLM조건 생략(또는 --fake_llm)")
    ap.add_argument("--fake_llm", action="store_true", help="서버 없이 top-K 무작위 pick(구조검증용)")
    ap.add_argument("--llm_every_steps", type=int, default=5)
    ap.add_argument("--candidate_pool", type=int, default=200)
    ap.add_argument("--llm_topk", type=int, default=10)
    ap.add_argument("--max_tokens", type=int, default=128)
    ap.add_argument("--output_dir", default=os.path.join("src", "notebooks", "output", "ablation"))
    args = ap.parse_args()

    cfg = ENV_CFG[args.env]
    os.makedirs(args.output_dir, exist_ok=True)
    print(f"=== Hybrid ablation: env={args.env} train_ep={args.train_episodes} iters={args.iterations} "
          f"eval_ep={args.eval_episodes} seed={args.seed} device={device} ===")

    # 1) 환경 + bounds
    seed_all(args.seed)
    ge = make_env(cfg)
    try:
        ge.reset(seed=args.seed)
    except Exception:
        ge.reset()
    ep = w.EnvironmentBounds.of_identifiers(
        maximum_node_count=cfg["max_nodes"], maximum_total_credentials=cfg["max_nodes"],
        identifiers=ge.identifiers,
    )

    # 2) DQL 학습 (한 번만, 두 조건이 공유)
    t0 = time.time()
    dql_run = learner.epsilon_greedy_search(
        cyberbattle_gym_env=ge, environment_properties=ep,
        learner=dqla.DeepQLearnerPolicy(ep=ep, gamma=0.015, replay_memory_size=10000,
                                        target_update=10, batch_size=512, learning_rate=0.01),
        episode_count=args.train_episodes, iteration_count=args.iterations,
        epsilon=0.90, epsilon_exponential_decay=5000, epsilon_minimum=0.10,
        verbosity=Verbosity.Quiet, render=False, plot_episodes_length=False, title="DQL-train",
    )
    base = dql_run["learner"]
    print(f"[train] DQL trained in {time.time()-t0:.1f}s")

    # 3) 평가 A: 순수 DQL (정책 동결)
    a = eval_runs(ge, ep, FrozenEval(base), args.eval_episodes, args.eval_iterations, args.seed, "eval-DQL")

    # 4) 평가 B: DQL + LLM 프루닝 (동일 정책/시드)
    run_llm = bool(args.server_url) or args.fake_llm
    b = None
    pruner = None
    if run_llm:
        pruner = LLMServerPruner(base, args.server_url, every=args.llm_every_steps,
                                 pool=args.candidate_pool, topk=args.llm_topk,
                                 max_tokens=args.max_tokens, fake=args.fake_llm)
        b = eval_runs(ge, ep, pruner, args.eval_episodes, args.eval_iterations, args.seed, "eval-DQL+LLM")

    # 5) 결과 비교
    print("\n=== ABLATION RESULT (identical policy & seeds; only eval-time LLM differs) ===")
    print(f"  {'condition':<16} {'owned(mean±std)':<18} {'owned list':<18} {'reward(mean±std)':<18}")
    print(f"  {'DQL (no LLM)':<16} {fmt(a['owned']):<18} {str(a['owned']):<18} {fmt(a['rewards']):<18}  total_nodes={a['total']}")
    if b is not None:
        tag = "DQL+LLM(fake)" if args.fake_llm else "DQL+LLM"
        print(f"  {tag:<16} {fmt(b['owned']):<18} {str(b['owned']):<18} {fmt(b['rewards']):<18}  total_nodes={b['total']}")
        if pruner:
            print(f"  [LLM] calls={pruner.n_llm_calls} changed_from_Qtop1={pruner.n_llm_changed} "
                  f"({(pruner.n_llm_changed/pruner.n_llm_calls*100 if pruner.n_llm_calls else 0):.0f}% — "
                  f"0%면 LLM이 Q-argmax와 동일 = 무의미)")
    else:
        print("  (LLM 조건 생략: --server_url 또는 --fake_llm 필요)")

    out = {"args": vars(args), "no_llm": a, "with_llm": b,
           "llm_calls": getattr(pruner, "n_llm_calls", 0),
           "llm_changed": getattr(pruner, "n_llm_changed", 0)}
    ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    path = os.path.join(args.output_dir, f"ablation_{args.env}_seed{args.seed}_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"  saved -> {path}")


if __name__ == "__main__":
    main()
