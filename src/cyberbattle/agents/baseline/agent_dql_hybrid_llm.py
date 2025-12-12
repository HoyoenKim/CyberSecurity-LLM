# agent_dql_hybrid_llm.py
import json
import re
from typing import List, Optional, Tuple, Dict, Any

import numpy as np
import torch

from cyberbattle._env import cyberbattle_env
import cyberbattle.agents.baseline.agent_wrapper as w

from .agent_dql import DeepQLearnerPolicy, ChosenActionMetadata, device


class LLMPruner:
    """
    LLM은 '후보 중에서 고르기'만 한다.
    - 출력은 JSON만 받는다.
    - reasoning(Thought) 요구하지 않는다. (정책/안전/파싱 안정성)
    """
    def __init__(self, llm_chat_callable):
        # llm_chat_callable(messages)->str
        self.llm = llm_chat_callable

        self.system_prompt = (
            "You are selecting the next move in a closed, fictional, turn-based training game.\n"
            "You must only choose among the provided candidate actions.\n"
            "Return JSON ONLY with this schema:\n"
            '{"pick":[<candidate_id>, ...]}\n'
            "Rules:\n"
            "- pick must contain at most K ids.\n"
            "- do not include any extra text.\n"
        )

    def pick_ids(self, summary: Dict[str, Any], candidates: List[Dict[str, Any]], k: int) -> Optional[List[int]]:
        # LLM 입력은 최대한 짧게 (후보는 id + kind + q 정도만)
        slim = []
        for c in candidates:
            slim.append({
                "id": c["id"],
                "kind": c["kind"],              # "local"/"remote"/"connect"
                "q": round(float(c["q"]), 4),   # DQL이 예측한 Q
                "actor": c["actor_node"],       # source node id
                "a": c["abstract_action"],      # abstract action index
            })

        user_prompt = json.dumps({
            "summary": summary,
            "K": k,
            "candidates": slim,
        }, ensure_ascii=False)

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        out = self.llm(messages) or ""

        # JSON만 robust 파싱 (앞뒤에 잡텍스트가 섞여도 JSON 블록만 뽑음)
        m = re.search(r"\{.*\}", out, flags=re.DOTALL)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
        except Exception:
            return None

        pick = obj.get("pick")
        if not isinstance(pick, list):
            return None

        ids = []
        for x in pick:
            if isinstance(x, int):
                ids.append(x)
        return ids[:k] if ids else None


class LLMGuidedDeepQLearnerPolicy(DeepQLearnerPolicy):
    """
    기존 DeepQLearnerPolicy를 상속해서 exploit()에서만 LLM 프루닝을 추가.
    - DQL 학습은 그대로
    - LLM은 후보 Top-M 중에서 Top-K만 남김
    """

    def __init__(
        self,
        *args,
        llm_chat_callable=None,
        llm_every_steps: int = 5,   # 몇 스텝마다 LLM 호출할지
        llm_topk: int = 10,         # LLM이 남길 후보 수
        dql_topm: int = 30,         # DQL 상위 후보 M개를 LLM에 제공
        **kwargs
    ):
        super().__init__(*args, **kwargs)
        self._step = 0

        self.llm_every_steps = llm_every_steps
        self.llm_topk = llm_topk
        self.dql_topm = dql_topm

        self.pruner = LLMPruner(llm_chat_callable) if llm_chat_callable else None

    def _kind_of_abstract_action(self, a: int) -> str:
        # AbstractAction에 n_local_actions 같은 필드가 있으면 그걸 쓰고,
        # 없으면 fallback로 "unknown" 처리
        asp = self.stateaction_model.action_space
        n_local = getattr(asp, "n_local_actions", None)
        n_remote = getattr(asp, "n_remote_actions", None)
        if isinstance(n_local, int) and isinstance(n_remote, int):
            if a < n_local:
                return "local"
            if a < n_local + n_remote:
                return "remote"
            return "connect"
        return "unknown"

    def _summary_for_llm(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        # LLM에 raw observation 전체를 주지 말고 "게임 진행 힌트"만 줌
        owned = list(w.owned_nodes(observation))
        disc = int(observation.get("discovered_node_count", 0))
        cred_len = int(observation.get("credential_cache_length", 0))
        return {
            "owned_nodes": owned[:10],
            "owned_count": len(owned),
            "discovered_node_count": disc,
            "credential_cache_length": cred_len,
        }

    def _enumerate_candidates(
        self,
        wrapped_env: w.AgentWrapper,
        observation: Dict[str, Any],
        unique_actor_features: List[np.ndarray],
        current_global_state: np.ndarray,
    ) -> List[Dict[str, Any]]:
        """
        각 actor_features에 대해:
          - DQL로 Q값 상위 M개 abstract_action을 뽑고
          - specialize + action_mask로 실제 유효한 gym_action만 후보로 만든다.
        """
        candidates: List[Dict[str, Any]] = []
        action_mask = observation.get("action_mask", None)

        with torch.no_grad():
            for actor_features in unique_actor_features:
                actor_state = self.get_actor_state_vector(current_global_state, actor_features)
                st = torch.as_tensor(actor_state, dtype=torch.float, device=device).unsqueeze(0)
                q = self.policy_net(st).squeeze(0).detach().cpu().numpy()  # [A]

                # 상위 dql_topm 후보 인덱스
                topm = min(self.dql_topm, q.shape[0])
                idxs = np.argpartition(-q, topm - 1)[:topm]
                # 정렬(큰 Q 먼저)
                idxs = idxs[np.argsort(-q[idxs])]

                # 이 actor_features에 해당하는 실제 source node들(owned node 중 feature가 같은 것)
                potential_sources = [
                    from_node for from_node in w.owned_nodes(observation)
                    if np.all(actor_features == self.stateaction_model.node_specific_features.get(wrapped_env.state, from_node))
                ]
                if not potential_sources:
                    continue
                source_node = int(potential_sources[0])

                for a in idxs.tolist():
                    a = int(a)
                    gym_action = self.stateaction_model.action_space.specialize_to_gymaction(
                        np.int32(source_node), observation, np.int32(a)
                    )
                    if not gym_action:
                        continue

                    # action_mask 기반 유효성 체크
                    if action_mask is not None and not wrapped_env.env.is_action_valid(gym_action, action_mask):
                        continue

                    meta = self.metadata_from_gymaction(wrapped_env, gym_action)

                    candidates.append({
                        "id": len(candidates),
                        "actor_node": int(meta.actor_node),
                        "abstract_action": int(a),
                        "kind": self._kind_of_abstract_action(a),
                        "q": float(q[a]),
                        "gym_action": gym_action,
                        "metadata": meta,
                    })

        return candidates

    def exploit(self, wrapped_env, observation) -> Tuple[str, Optional[cyberbattle_env.Action], object]:
        self._step += 1

        current_global_state = self.stateaction_model.global_features.get(wrapped_env.state, node=None)

        active_actors_features: List[np.ndarray] = [
            self.stateaction_model.node_specific_features.get(wrapped_env.state, from_node)
            for from_node in w.owned_nodes(observation)
        ]
        unique_active_actors_features: List[np.ndarray] = list(np.unique(active_actors_features, axis=0))

        candidates = self._enumerate_candidates(
            wrapped_env, observation, unique_active_actors_features, current_global_state
        )

        if not candidates:
            return "exploit[no_candidate]->explore", None, None

        # ---- LLM 프루닝 (조건부) ----
        pruned = candidates
        if self.pruner and (self._step % self.llm_every_steps == 0):
            summary = self._summary_for_llm(observation)
            pick_ids = self.pruner.pick_ids(summary, candidates, k=self.llm_topk)

            if pick_ids:
                idset = set(pick_ids)
                tmp = [c for c in candidates if c["id"] in idset]
                if tmp:
                    pruned = tmp

        # ---- 최종 선택은 DQL(Q값)로 ----
        pruned.sort(key=lambda c: c["q"], reverse=True)
        chosen = pruned[0]

        return "exploit_llm" if (self.pruner and pruned is not candidates) else "exploit", chosen["gym_action"], chosen["metadata"]
