#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
"제대로 된 하이브리드" Stage 2/3: 학습(training) 단계에 LLM을 의미적 액션과 함께 주입.

기존 하이브리드(eval-only, 원시 인덱스 액션)의 한계(CLAUDE §10: LLM이 추론 못함·무의미)를 넘어:
  (1) 의미적 액션 디코딩: gym_action -> "connect IVI -> GTW via ETH_MGMT using gtw_admin_token"
      (관측의 _discovered_nodes + credential_cache + env.identifiers 로 인덱스를 이름으로)
  (2) 학습-시 LLM-guided 탐색: epsilon-greedy 의 explore 분기에서 LLM이 의미적 후보 중 하나를 선택
      → README §2.3의 "샘플 효율/수렴 가속" 주장을 실제로 검증.
  (3) 학습곡선 비교: DQL(무작위 explore) vs DQL+LLM-explore (동일 시드·config·예산).

비용 주의: 학습 중 LLM 호출은 비쌈(로컬 27B ~수초/회). throttle(--every) + 상한(--max_llm_calls) 필수.
오프라인 구조검증: --fake_llm (서버 없이 무작위 pick).

예:
  # 구조검증(CPU, 서버 불필요)
  python hybrid_train_llm.py --env chain10 --episodes 3 --iterations 300 --fake_llm
  # 본 실행(GPU + 로컬 Qwen3 서버)
  python hybrid_train_llm.py --env toyctf --episodes 10 --iterations 800 --every 4 --max_llm_calls 250 --server_url http://127.0.0.1:8000
"""
import os
import sys
import json
import time
import random
import argparse
import urllib.request
from typing import cast, List, Optional, Any

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
from cyberbattle._env.cyberbattle_env import CyberBattleEnv

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

ENV_CFG = {
    "toyctf":     dict(gymid="CyberBattleToyCtf-v0",        size=None, max_nodes=12),
    "automotive": dict(gymid="CyberBattleAutomotiveCTF-v0", size=None, max_nodes=32),
    "chain10":    dict(gymid="CyberBattleChain-v0",         size=10,   max_nodes=22),
}


def seed_all(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def owned_count(ge):
    try:
        net = ge.environment.network
        owned = sum(1 for _, d in net.nodes(data=True)
                    if d.get("data") is not None and d["data"].agent_installed)
        return owned, net.number_of_nodes()
    except Exception:
        return None, None


def decode_action(ga, obs, idents) -> str:
    """gym_action 인덱스를 사람이 읽는 이름으로. (Stage 1)"""
    disc = (obs or {}).get("_discovered_nodes", []) if isinstance(obs, dict) else []

    def node(i):
        i = int(i)
        return disc[i] if 0 <= i < len(disc) else ("node#%d" % i)

    def lvuln(i):
        try:
            return idents.local_vulnerabilities[int(i)]
        except Exception:
            return "lvuln#%d" % int(i)

    def rvuln(i):
        try:
            return idents.remote_vulnerabilities[int(i)]
        except Exception:
            return "rvuln#%d" % int(i)

    def port(i):
        try:
            return idents.ports[int(i)]
        except Exception:
            return "port#%d" % int(i)

    try:
        if "local_vulnerability" in ga:
            s, v = ga["local_vulnerability"]
            return "local_vuln on %s : %s" % (node(s), lvuln(v))
        if "remote_vulnerability" in ga:
            s, t, v = ga["remote_vulnerability"]
            return "remote_vuln %s -> %s : %s" % (node(s), node(t), rvuln(v))
        if "connect" in ga:
            s, t, p, c = ga["connect"]
            cache = (obs or {}).get("credential_cache", []) if isinstance(obs, dict) else []
            cred = cache[int(c)].credential if 0 <= int(c) < len(cache) else ("cred#%d" % int(c))
            return "connect %s -> %s via %s using %s" % (node(s), node(t), port(p), cred)
    except Exception:
        pass
    return repr(ga)


SYS_PROMPT = (
    "You are guiding the EXPLORATION of a red-team agent in a closed, fictional network "
    "intrusion simulation. Given candidate next actions (described by node/port/credential names), "
    "pick the ONE most likely to make new progress (discover a node, leak a credential, or compromise "
    "a node). Prefer actions that pivot toward new/unowned nodes over repeating dead ends.\n"
    'Return JSON only: {"pick": <id>} with no extra text.'
)


class LLMGuidedExplorer(dqla.DeepQLearnerPolicy):
    """DQL + 학습-시 LLM-guided 탐색. explore()에서만 LLM 개입(학습/Q-업데이트는 그대로)."""

    def __init__(self, ep, server_url=None, every=4, pool=8, max_tokens=64,
                 temperature=0.0, fake=False, max_llm_calls=250, obs_max_chars=1200, **dql_kwargs):
        super().__init__(ep=ep, **dql_kwargs)
        self.url = server_url.rstrip("/") if server_url else None
        self.every = max(1, int(every))
        self.pool = max(2, int(pool))
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.fake = fake
        self.max_llm_calls = int(max_llm_calls)
        self.obs_max_chars = obs_max_chars
        self._last_obs = None
        self._estep = 0
        self.n_calls = 0
        self.raw_samples = []

    def on_step(self, wrapped_env, observation, reward, done, truncated, info, action_metadata):
        self._last_obs = observation  # explore()가 다음 스텝에 쓸 현재 관측 stash
        return super().on_step(wrapped_env, observation, reward, done, truncated, info, action_metadata)

    def _ask(self, descs: List[str]) -> Optional[int]:
        if self.fake or not self.url:
            return random.randrange(len(descs))
        payload = {"candidates": [{"id": i, "action": d} for i, d in enumerate(descs)]}
        body = json.dumps({
            "messages": [{"role": "system", "content": SYS_PROMPT},
                         {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}],
            "max_new_tokens": self.max_tokens, "temperature": self.temperature,
        }).encode("utf-8")
        try:
            req = urllib.request.Request(self.url + "/chat", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=300) as r:
                text = (json.loads(r.read().decode("utf-8")).get("text") or "")
            if len(self.raw_samples) < 8:
                self.raw_samples.append(text[:160])
            import re
            m = re.search(r"\{.*\}", text, flags=re.DOTALL)
            if not m:
                return None
            pick = json.loads(m.group(0)).get("pick")
            return int(pick) if pick is not None else None
        except Exception:
            return None

    def explore(self, wrapped_env):
        self._estep += 1
        obs = self._last_obs
        use_llm = ((self.fake or self.url) and obs is not None
                   and (self._estep % self.every == 0) and (self.n_calls < self.max_llm_calls))
        if not use_llm:
            return super().explore(wrapped_env)

        idents = getattr(wrapped_env.env, "identifiers", None)
        if idents is None:
            idents = getattr(getattr(wrapped_env.env, "unwrapped", None), "identifiers", None)

        cands = [wrapped_env.env.sample_valid_action(kinds=[0, 1, 2]) for _ in range(self.pool)]
        descs = [decode_action(ga, obs, idents) for ga in cands]
        self.n_calls += 1
        pick = self._ask(descs)
        if pick is None or not (0 <= pick < len(cands)):
            pick = 0
        ga = cands[pick]
        md = self.metadata_from_gymaction(wrapped_env, ga)
        return "explore[llm]", ga, md


def make_env(cfg):
    _e = gym.make(cfg["gymid"], size=cfg["size"]) if cfg["size"] else gym.make(cfg["gymid"])
    return cast(CyberBattleEnv, _e.unwrapped)


DQL_HP = dict(gamma=0.015, replay_memory_size=10000, target_update=10, batch_size=512, learning_rate=0.01)
EPS = dict(epsilon=0.90, epsilon_exponential_decay=5000, epsilon_minimum=0.10)


def train(cfg, make_learner, episodes, iters, seed, label):
    seed_all(seed)
    ge = make_env(cfg)
    try:
        ge.reset(seed=seed)
    except Exception:
        ge.reset()
    ep = w.EnvironmentBounds.of_identifiers(
        maximum_node_count=cfg["max_nodes"], maximum_total_credentials=cfg["max_nodes"], identifiers=ge.identifiers)
    t0 = time.time()
    run = learner.epsilon_greedy_search(
        cyberbattle_gym_env=ge, environment_properties=ep, learner=make_learner(ep),
        episode_count=episodes, iteration_count=iters, **EPS,
        verbosity=Verbosity.Quiet, render=False, plot_episodes_length=False, title=label)
    curve = [round(sum(x), 1) for x in (run.get("all_episodes_rewards") or [])]
    lengths = [len(x) for x in (run.get("all_episodes_rewards") or [])]
    owned, total = owned_count(ge)
    return {"curve": curve, "lengths": lengths, "owned": owned, "total": total,
            "secs": round(time.time() - t0, 1), "learner": run["learner"]}


def main():
    ap = argparse.ArgumentParser(description="LLM-guided exploration during DQL training (sample-efficiency test)")
    ap.add_argument("--env", default="toyctf", choices=list(ENV_CFG.keys()))
    ap.add_argument("--episodes", type=int, default=10)
    ap.add_argument("--iterations", type=int, default=800)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--server_url", default=None)
    ap.add_argument("--fake_llm", action="store_true")
    ap.add_argument("--every", type=int, default=4, help="explore N회마다 1회 LLM 호출")
    ap.add_argument("--pool", type=int, default=8, help="LLM에 줄 후보 수")
    ap.add_argument("--max_llm_calls", type=int, default=250)
    ap.add_argument("--max_tokens", type=int, default=64)
    ap.add_argument("--output_dir", default=os.path.join("src", "notebooks", "output", "train_llm"))
    args = ap.parse_args()

    cfg = ENV_CFG[args.env]
    os.makedirs(args.output_dir, exist_ok=True)
    print(f"=== LLM-guided training: env={args.env} episodes={args.episodes} iters={args.iterations} "
          f"seed={args.seed} every={args.every} device={device} ===")

    # A) pure DQL (random exploration)
    a = train(cfg, lambda ep: dqla.DeepQLearnerPolicy(ep=ep, **DQL_HP),
              args.episodes, args.iterations, args.seed, "DQL")
    print(f"[A] pure DQL: {a['secs']}s | final owned={a['owned']}/{a['total']}")

    # B) DQL + LLM-guided exploration (same seed/budget)
    run_llm = bool(args.server_url) or args.fake_llm
    b = None
    if run_llm:
        def mk(ep):
            return LLMGuidedExplorer(ep, server_url=args.server_url, every=args.every, pool=args.pool,
                                     max_tokens=args.max_tokens, fake=args.fake_llm,
                                     max_llm_calls=args.max_llm_calls, **DQL_HP)
        b = train(cfg, mk, args.episodes, args.iterations, args.seed, "DQL+LLMexplore")
        print(f"[B] DQL+LLM-explore: {b['secs']}s | final owned={b['owned']}/{b['total']}")

    print("\n=== SAMPLE-EFFICIENCY (reward per training episode; same seed/budget) ===")
    print(f"  episode:        {list(range(1, args.episodes + 1))}")
    print(f"  A  DQL        : {a['curve']}")
    if b is not None:
        tag = "DQL+LLM(fake)" if args.fake_llm else "DQL+LLM-explore"
        print(f"  B  {tag:<12}: {b['curve']}")
        bl = b.get("learner")
        ncalls = getattr(bl, "n_calls", 0)
        print(f"  final owned: A={a['owned']}/{a['total']}  B={b['owned']}/{b['total']}  | LLM calls={ncalls}")
        for s in getattr(bl, "raw_samples", [])[:4]:
            print(f"    LLM raw: {s!r}")
        print("  해석: B의 보상곡선이 A보다 더 빨리/높이 오르면 LLM-guided 탐색이 샘플효율↑ (README §2.3 주장 지지).")
    else:
        print("  (LLM 조건 생략: --server_url 또는 --fake_llm 필요)")

    out = {"args": vars(args),
           "A_dql": {k: a[k] for k in ("curve", "lengths", "owned", "total", "secs")},
           "B_llm": ({k: b[k] for k in ("curve", "lengths", "owned", "total", "secs")} if b else None),
           "llm_calls": getattr(b.get("learner"), "n_calls", 0) if b else 0,
           "llm_raw_samples": getattr(b.get("learner"), "raw_samples", []) if b else []}
    ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    path = os.path.join(args.output_dir, f"trainllm_{args.env}_seed{args.seed}_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"  saved -> {path}")


if __name__ == "__main__":
    main()
