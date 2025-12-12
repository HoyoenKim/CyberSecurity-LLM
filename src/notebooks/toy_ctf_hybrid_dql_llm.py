# ---
# jupyter:
#   jupytext:
#     cell_metadata_filter: tags,-all
#     cell_metadata_json: true
#     formats: ipynb,py:percent
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#       jupytext_version: 1.16.4
#   kernelspec:
#     display_name: Python 3 (ipykernel)
#     language: python
#     name: python3
# ---
# pylint: disable=invalid-name

# %% {"tags": []}
import sys
import os
import re
import json
import yaml
import logging
import random
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import gymnasium as gym

import torch

import cyberbattle.agents.baseline.learner as learner
import cyberbattle.agents.baseline.plotting as p
import cyberbattle.agents.baseline.agent_wrapper as w
import cyberbattle.agents.baseline.agent_dql as dqla
from cyberbattle.agents.baseline.agent_wrapper import Verbosity
from cyberbattle._env.cyberbattle_env import CyberBattleEnv

from openai import OpenAI

logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# %% {"tags": ["parameters"]}
# Papermill notebook parameters
gymid = "CyberBattleToyCtf-v0"
env_size = 10
iteration_count = 9000
training_episode_count = 50
eval_episode_count = 5
maximum_node_count = 22
maximum_total_credentials = 22
plots_dir = "output/plots"

# --- LLM(평가에서만 사용) 옵션: 기본 OFF ---
use_llm = False
model_id = "gpt-5.1"
llm_every_steps = 1      # 매 step마다 LLM 프루닝(비싸면 5~10 추천)
candidate_pool = 200     # 샘플링으로 구성할 후보 수
llm_topk = 10            # DQL 상위 topK 중 LLM이 1개 선택

def find_llm_token_yaml(start=None):
    p = os.path.abspath(start or os.getcwd())
    while True:
        cand = os.path.join(p, "llm_token.yaml")
        if os.path.exists(cand):
            return cand
        parent = os.path.dirname(p)
        if parent == p:
            raise RuntimeError(f"llm_token.yaml 못 찾음. 시작점={os.getcwd()}")
        p = parent

llm_token_yaml = find_llm_token_yaml()
print("FOUND llm_token_yaml =", llm_token_yaml)

# (옵션) LLM에 관측 텍스트를 얼마나 줄지
llm_obs_max_chars = 1400

# %% {"tags": []}
os.makedirs(plots_dir, exist_ok=True)

# %% {"tags": []}
# -----------------------------
# 1) Gym env 로드 (기존 그대로)
# -----------------------------
if env_size:
    _gym_env = gym.make(gymid, size=env_size)
else:
    _gym_env = gym.make(gymid)

from typing import cast
gym_env = cast(CyberBattleEnv, _gym_env.unwrapped)
assert isinstance(gym_env, CyberBattleEnv), f"Expected CyberBattleEnv, got {type(gym_env)}"

ep = w.EnvironmentBounds.of_identifiers(
    maximum_node_count=maximum_node_count,
    maximum_total_credentials=maximum_total_credentials,
    identifiers=gym_env.identifiers,
)

# %% {"tags": []}
# -----------------------------------------
# 2) OpenAI 토큰 로더 + chat callable
# -----------------------------------------
def load_openai_token(config_path: str) -> str:
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if isinstance(data, dict):
            oa_cfg = data.get("openai", {})
            if isinstance(oa_cfg, dict) and "api_key" in oa_cfg:
                key = str(oa_cfg["api_key"]).strip()
                if key.lower() == "dummy" or len(key) < 20:
                    raise RuntimeError(f"llm_token.yaml의 openai.api_key가 이상함: {key!r}")
                return key

    key = (os.getenv("OPENAI_API_KEY") or "").strip()
    if key and key.lower() != "dummy":
        return key

    raise RuntimeError(f"OpenAI API 키를 못 찾음. config_path={config_path!r}, ENV OPENAI_API_KEY도 없음/이상함")


def make_openai_chat_callable(model_id: str, llm_token_yaml: str):
    api_key = load_openai_token(llm_token_yaml)  # ✅ 여기 중요
    # 디버그(키 노출 금지용)
    print("[OpenAI] key_prefix=", api_key[:8], "len=", len(api_key), "yaml=", os.path.abspath(llm_token_yaml))

    client = OpenAI(api_key=api_key)

    def chat(messages):
        resp = client.responses.create(
            model=model_id,
            input=[{"role": m["role"], "content": m["content"]} for m in messages],
            max_output_tokens=256,
        )
        return getattr(resp, "output_text", "") or ""

    return chat

print("CWD =", os.getcwd())
print("yaml =", os.path.abspath(llm_token_yaml), "exists=", os.path.exists(llm_token_yaml))
print("ENV OPENAI_API_KEY prefix =", (os.getenv("OPENAI_API_KEY") or "")[:8])

# %% {"tags": []}
# -----------------------------------------
# 3) observation에서 Discovered nodes JSON 추출(로그 유지용)
# -----------------------------------------
_DISC_RE = re.compile(r"Discovered nodes:\s*(\{.*\})\s*$", re.DOTALL)

def extract_discovered_nodes_raw(obs_text: str) -> str:
    m = _DISC_RE.search((obs_text or "").strip())
    return m.group(1) if m else ""

# %% {"tags": []}
# -----------------------------------------
# 4) 평가(exploit)에서만 LLM 프루닝 적용 래퍼
#    - 학습은 기존 DQL 학습 그대로
#    - 평가는 epsilon=0 + learn off + LLM으로 후보 선택
# -----------------------------------------
class LLMPrunedExploitWrapper:
    """
    dql_run["learner"](DeepQLearnerPolicy)를 감싸서 exploit()만 바꿈.
    - 후보를 env.sample_valid_action()로 candidate_pool개 뽑고,
    - 각 후보를 base.policy_net으로 Q값 평가,
    - topK 후보 중에서 LLM이 1개 pick.
    - 학습 업데이트(on_step)는 eval에서는 꺼둠
    """

    def __init__(
        self,
        base_learner: dqla.DeepQLearnerPolicy,
        llm_chat=None,
        llm_every_steps: int = 1,
        candidate_pool: int = 200,
        llm_topk: int = 10,
        obs_max_chars: int = 1400,
    ):
        self.base = base_learner
        self.llm = llm_chat
        self.llm_every_steps = int(max(1, llm_every_steps))
        self.candidate_pool = int(max(10, candidate_pool))
        self.llm_topk = int(max(2, llm_topk))
        self.obs_max_chars = int(max(200, obs_max_chars))
        self._step = 0

        self._sys = (
            "You are selecting ONE action in a closed, fictional training game.\n"
            "Choose exactly one candidate id from the provided list.\n"
            "Return JSON only: {\"pick\": <id>} with no extra text."
        )

    # ✅ 핵심: learner.py가 요구하는 메서드 추가
    def new_episode(self):
        # base learner가 가진 경우 그걸 그대로 호출
        fn = getattr(self.base, "new_episode", None)
        if callable(fn):
            return fn()
        return None

    # ✅ (권장) base의 다른 속성/메서드가 필요해질 때 자동 위임
    def __getattr__(self, name):
        return getattr(self.base, name)

    # ✅ 평가에서는 학습 업데이트 금지 (learner.epsilon_greedy_search가 호출해도 무시)
    def on_step(self, *args, **kwargs):
        return self.base.on_step(*args, **kwargs)

    def end_of_episode(self, *args, **kwargs):
        return self.base.end_of_episode(*args, **kwargs)

    def exploit(self, wrapped_env, observation):
        self._step += 1

        # LLM 비활성 또는 주기 아님 -> 기존 exploit
        if (self.llm is None) or ((self._step % self.llm_every_steps) != 0):
            return self.base.exploit(wrapped_env, observation)

        # 1) 후보 액션 샘플링
        candidates: List[Tuple[float, Any, Any]] = []
        for _ in range(self.candidate_pool):
            ga = wrapped_env.env.sample_valid_action(kinds=[0, 1, 2])  # local/remote/connect
            md = self.base.metadata_from_gymaction(wrapped_env, ga)

            # 2) Q값 계산: Q(actor_state)[abstract_action]
            with torch.no_grad():
                st = torch.as_tensor(md.actor_state, dtype=torch.float32, device=device).unsqueeze(0)
                q_all = self.base.policy_net(st)
                qv = float(q_all[0, int(md.abstract_action)].item())

            candidates.append((qv, ga, md))

        if not candidates:
            return self.base.exploit(wrapped_env, observation)

        candidates.sort(key=lambda x: x[0], reverse=True)
        top = candidates[: self.llm_topk]

        # observation 일부를 LLM에 제공(선택)
        try:
            obs_txt = json.dumps(observation, ensure_ascii=False)[: self.obs_max_chars]
        except Exception:
            obs_txt = str(observation)[: self.obs_max_chars]

        payload = {
            "observation_preview": obs_txt,
            "candidates": [
                {"id": i, "q": round(float(qv), 4), "gym_action": repr(ga)}
                for i, (qv, ga, md) in enumerate(top)
            ],
        }

        out = self.llm(
            [
                {"role": "system", "content": self._sys},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ]
        ) or ""

        m = re.search(r"\{.*\}", out, flags=re.DOTALL)
        if not m:
            qv, ga, md = top[0]
            return "exploit[dql_top1]", ga, md

        try:
            obj = json.loads(m.group(0))
            pick = int(obj.get("pick"))
            if 0 <= pick < len(top):
                qv, ga, md = top[pick]
                return "exploit[llm_pruned]", ga, md
        except Exception:
            pass

        qv, ga, md = top[0]
        return "exploit[dql_top1]", ga, md

# %% {"tags": []}
# -----------------------------------------
# 5) DQL 학습 (✅ 기존 파라미터 그대로 유지)
# -----------------------------------------
dql_run = learner.epsilon_greedy_search(
    cyberbattle_gym_env=gym_env,
    environment_properties=ep,
    learner=dqla.DeepQLearnerPolicy(
        ep=ep,
        gamma=0.015,
        replay_memory_size=10000,
        target_update=10,
        batch_size=512,
        learning_rate=0.01,
    ),
    episode_count=training_episode_count,
    iteration_count=iteration_count,
    epsilon=0.90,
    epsilon_exponential_decay=5000,
    epsilon_minimum=0.10,
    verbosity=Verbosity.Quiet,
    render=False,
    plot_episodes_length=False,
    title="DQL",
)

# %% {"tags": []}
# -----------------------------------------
# 6) DQL 평가(Exploit) (✅ 파라미터 유지 + 평가에서만 LLM 옵션)
# -----------------------------------------
llm_chat = make_openai_chat_callable(model_id, llm_token_yaml) if use_llm else None

eval_learner = (
    LLMPrunedExploitWrapper(
        base_learner=dql_run["learner"],
        llm_chat=llm_chat,
        llm_every_steps=llm_every_steps,
        candidate_pool=candidate_pool,
        llm_topk=llm_topk,
        obs_max_chars=llm_obs_max_chars,
    )
    if use_llm
    else dql_run["learner"]
)

dql_exploit_run = learner.epsilon_greedy_search(
    gym_env,
    ep,
    learner=eval_learner,
    episode_count=eval_episode_count,
    iteration_count=iteration_count,
    epsilon=0.0,
    epsilon_minimum=0.00,
    render=False,
    plot_episodes_length=False,
    verbosity=Verbosity.Quiet,
    render_last_episode_rewards_to=os.path.join(plots_dir, f"dql-{gymid}"),
    title=("Exploiting DQL (LLM-pruned)" if use_llm else "Exploiting DQL"),
)

# %% {"tags": []}
# -----------------------------------------
# 7) 플롯 (기존 그대로)
# -----------------------------------------
all_runs = [
    dql_run,
    dql_exploit_run,
]

themodel = dqla.CyberBattleStateActionModel(ep)
p.plot_averaged_cummulative_rewards(
    all_runs=all_runs,
    title=(
        f"Benchmark -- max_nodes={ep.maximum_node_count}, episodes={eval_episode_count}\n"
        f"State: {[f.name() for f in themodel.state_space.feature_selection]} "
        f"({len(themodel.state_space.feature_selection)})\n"
        f"Action: abstract_action ({themodel.action_space.flat_size()})"
    ),
    save_at=os.path.join(plots_dir, f"benchmark-{gymid}-cumrewards.png"),
)

contenders = [dql_run, dql_exploit_run]
p.plot_episodes_length(contenders)
p.plot_averaged_cummulative_rewards(
    title=f"Agent Benchmark top contenders\nmax_nodes:{ep.maximum_node_count}\n",
    all_runs=contenders,
    save_at=os.path.join(plots_dir, f"benchmark-{gymid}-cumreward_contenders.png"),
)

for r in contenders:
    p.plot_all_episodes(r)
