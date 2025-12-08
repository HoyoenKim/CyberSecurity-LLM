# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Deep Recurrent Q-learning (DRQN) agent applied to chain network.

DQN 버전을 LSTM 기반 DRQN으로 변경한 구현.
epsilon_greedy_search의 Learner 인터페이스(new_episode, on_step, exploit)를 이용해서
에피소드마다 hidden을 초기화하고, step마다 hidden을 carry 한다.
"""

from numpy import ndarray
from cyberbattle._env import cyberbattle_env
import numpy as np
from typing import List, NamedTuple, Optional, Tuple, Union
import random

# deep learning packages
from torch import Tensor
import torch.nn.functional as F
import torch.optim as optim
import torch.nn as nn
import torch
import torch.cuda
from torch.nn.utils.clip_grad import clip_grad_norm_

from .learner import Learner
from .agent_wrapper import EnvironmentBounds
import cyberbattle.agents.baseline.agent_wrapper as w
from .agent_randomcredlookup import CredentialCacheExploiter

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# =====================================================================
# 1. 상태/액션 모델
# =====================================================================


class CyberBattleStateActionModel:
    """Define an abstraction of the state and action space
    for a CyberBattle environment, to be used to train a Q-function.
    """

    def __init__(self, ep: EnvironmentBounds):
        self.ep = ep

        # 전역 feature (여기서는 '발견되었지만 owned가 아닌 노드 수'만 사용)
        self.global_features = w.ConcatFeatures(
            ep,
            [
                w.Feature_discovered_notowned_node_count(ep, None),
            ],
        )

        # 노드별 feature (성공/실패 액션, 활성 property, age 등)
        self.node_specific_features = w.ConcatFeatures(
            ep,
            [
                w.Feature_success_actions_at_node(ep),
                w.Feature_failed_actions_at_node(ep),
                w.Feature_active_node_properties(ep),
                w.Feature_active_node_age(ep),
            ],
        )

        self.state_space = w.ConcatFeatures(
            ep,
            self.global_features.feature_selection + self.node_specific_features.feature_selection,
        )

        self.action_space = w.AbstractAction(ep)

    def get_state_astensor(self, state: w.StateAugmentation):
        state_vector = self.state_space.get(state, node=None)
        state_vector_float = np.array(state_vector, dtype=np.float32)
        state_tensor = torch.from_numpy(state_vector_float).unsqueeze(0)
        return state_tensor

    def implement_action(
        self,
        wrapped_env: w.AgentWrapper,
        actor_features: ndarray,
        abstract_action: np.int32,
    ) -> Tuple[str, Optional[cyberbattle_env.Action], Optional[int]]:
        """Specialize an abstract model action into a CyberBattle gym action.

        actor_features -- the desired features of the actor to use (source CyberBattle node)
        abstract_action -- the desired type of attack (connect, local, remote).
        """

        observation = wrapped_env.state.observation

        # Pick source node at random (owned and with the desired feature encoding)
        potential_source_nodes = [
            from_node
            for from_node in w.owned_nodes(observation)
            if np.all(actor_features == self.node_specific_features.get(wrapped_env.state, from_node))
        ]

        if len(potential_source_nodes) > 0:
            source_node = np.random.choice(potential_source_nodes)

            gym_action = self.action_space.specialize_to_gymaction(
                source_node,
                observation,
                np.int32(abstract_action),
            )

            if not gym_action:
                return "exploit[undefined]->explore", None, None

            elif wrapped_env.env.is_action_valid(gym_action, observation["action_mask"]):
                return "exploit", gym_action, source_node
            else:
                return "exploit[invalid]->explore", None, None
        else:
            return "exploit[no_actor]->explore", None, None


# =====================================================================
# 2. Transition / Episode 기반 Replay Memory (DRQN 용)
# =====================================================================


class Transition(NamedTuple):
    """One taken transition and its outcome (with done flag)"""

    state: Tensor          # [1, state_dim]
    action: Tensor         # [1, 1] long
    next_state: Tensor     # [1, state_dim]
    reward: Tensor         # [1] float
    done: Tensor           # [1] float 0.0 (not done) or 1.0 (done)


class EpisodeReplayMemory:
    """Episode-based replay memory for DRQN.
    에피소드 단위로 Transition을 저장하고,
    길이 seq_len인 시퀀스를 샘플링해서 학습에 사용.
    """

    def __init__(self, capacity: int, seq_len: int):
        self.capacity = capacity
        self.seq_len = seq_len
        self.episodes: List[List[Transition]] = []
        self.current_episode: List[Transition] = []
        self.num_steps: int = 0

    def push(self, *args):
        transition = Transition(*args)
        self.current_episode.append(transition)
        self.num_steps += 1

        done = bool(transition.done.item() > 0.5)
        if done:
            if self.current_episode:
                self.episodes.append(self.current_episode)
            self.current_episode = []

        # ✅ capacity 초과 시: 과거 episode부터 제거
        # ✅ episode가 하나도 없고 current만 길어지는 경우도 잘라줌
        while self.num_steps > self.capacity:
            if self.episodes:
                removed = self.episodes.pop(0)
                self.num_steps -= len(removed)
            elif self.current_episode:
                self.current_episode.pop(0)
                self.num_steps -= 1
            else:
                break

    def __len__(self):
        return self.num_steps

    def sample(self, batch_size: int):
        eligible_episodes = [ep for ep in self.episodes if len(ep) >= self.seq_len]

        # ✅ 진행 중 에피소드도 길이가 충분하면 샘플 후보에 포함
        if len(self.current_episode) >= self.seq_len:
            eligible_episodes.append(self.current_episode)

        if not eligible_episodes:
            raise ValueError("Not enough episodes with length >= seq_len to sample from.")

        batch_episodes = random.choices(eligible_episodes, k=batch_size)

        state_seqs, action_seqs, reward_seqs, next_state_seqs, done_seqs = [], [], [], [], []
        for ep in batch_episodes:
            max_start = len(ep) - self.seq_len
            start_idx = random.randint(0, max_start)
            window = ep[start_idx : start_idx + self.seq_len]

            s_seq  = torch.cat([tr.state for tr in window], dim=0)       # [T, D]
            a_seq  = torch.cat([tr.action for tr in window], dim=0)      # [T, 1]
            r_seq  = torch.cat([tr.reward for tr in window], dim=0)      # [T]
            ns_seq = torch.cat([tr.next_state for tr in window], dim=0)  # [T, D]
            d_seq  = torch.cat([tr.done for tr in window], dim=0)        # [T]

            state_seqs.append(s_seq)
            action_seqs.append(a_seq)
            reward_seqs.append(r_seq)
            next_state_seqs.append(ns_seq)
            done_seqs.append(d_seq)

        state_batch      = torch.stack(state_seqs, dim=0).to(device)       # [B, T, D]
        action_batch     = torch.stack(action_seqs, dim=0).to(device)      # [B, T, 1]
        reward_batch     = torch.stack(reward_seqs, dim=0).to(device)      # [B, T]
        next_state_batch = torch.stack(next_state_seqs, dim=0).to(device)  # [B, T, D]
        done_batch       = torch.stack(done_seqs, dim=0).to(device)        # [B, T]

        return state_batch, action_batch, reward_batch, next_state_batch, done_batch


# =====================================================================
# 3. DRQN 네트워크
# =====================================================================


class DRQN(nn.Module):
    """LSTM 기반 Deep Recurrent Q-Network"""

    def __init__(self, ep: EnvironmentBounds, hidden_size: int = 256):
        super(DRQN, self).__init__()

        model = CyberBattleStateActionModel(ep)
        self.output_dim = model.action_space.flat_size()
        self.hidden_size = hidden_size

        # ✅ 입력차원 자동 추론
        self.fc_in = nn.LazyLinear(hidden_size)

        self.lstm = nn.LSTM(
            input_size=hidden_size,
            hidden_size=hidden_size,
            num_layers=1,
            batch_first=True,
        )
        self.fc_out = nn.Linear(hidden_size, self.output_dim)

    def forward(self, x: Tensor, hidden: Optional[Tuple[Tensor, Tensor]] = None):
        """x shape:
           - [B, input_dim]  또는
           - [B, T, input_dim]
        반환:
           - q_values: [B, T, output_dim]
           - hidden: (h_n, c_n)
        """
        if x.dim() == 2:
            # [B, D] → [B, 1, D]
            x = x.unsqueeze(1)

        x = F.relu(self.fc_in(x))             # [B, T, hidden]
        out, hidden = self.lstm(x, hidden)    # [B, T, hidden]
        q = self.fc_out(out)                  # [B, T, output_dim]
        return q, hidden


def random_argmax(array):
    """Just like `argmax` but if there are multiple elements with the max
    return a random index to break ties instead of returning the first one."""
    max_value = np.max(array)
    max_index = np.where(array == max_value)[0]

    if max_index.shape[0] > 1:
        max_index = int(np.random.choice(max_index, size=1))
    else:
        max_index = int(max_index)

    return max_value, max_index


class ChosenActionMetadata(NamedTuple):
    """Additional info about the action chosen by the DRQN-induced policy"""

    abstract_action: np.int32
    actor_node: int
    actor_features: ndarray
    actor_state: ndarray

    def __repr__(self) -> str:
        return f"[abstract_action={self.abstract_action}, actor={self.actor_node}, state={self.actor_state}]"


# =====================================================================
# 4. DRQN Learner 구현 (epsilon_greedy_search에 꽂히는 부분)
# =====================================================================


class DeepQLearnerPolicy(Learner):
    """Deep Recurrent Q-Learning (DRQN) on CyberBattle environments.

    DQN 버전을 LSTM 기반 DRQN으로 변경.
    - 에피소드마다 new_episode()에서 hidden 초기화
    - on_step()에서 실제 transition을 따라 hidden 업데이트
    - 학습은 EpisodeReplayMemory에서 시퀀스를 뽑아서 BPTT
    """

    def __init__(
        self,
        ep: EnvironmentBounds,
        gamma: float,
        replay_memory_size: int,
        target_update: int,
        batch_size: int,
        learning_rate: float,
        seq_len: int = 8,          # 시퀀스 길이 (DRQN용)
        drqn_hidden_size: int = 256,
    ):
        self.stateaction_model = CyberBattleStateActionModel(ep)
        self.batch_size = batch_size
        self.gamma = gamma
        self.learning_rate = learning_rate
        self.seq_len = seq_len
        self._nets_initialized = False

        # DRQN 네트워크 (policy / target)
        self.policy_net = DRQN(ep, hidden_size=drqn_hidden_size).to(device)
        self.target_net = DRQN(ep, hidden_size=drqn_hidden_size).to(device)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()
        self.target_update = target_update

        self.optimizer = optim.RMSprop(self.policy_net.parameters(), lr=learning_rate)  # type: ignore
        self.memory = EpisodeReplayMemory(replay_memory_size, seq_len=seq_len)

        self.credcache_policy = CredentialCacheExploiter()

        # ★ 에피소드별 hidden state (행동에 사용)
        self.hidden_policy: Optional[Tuple[Tensor, Tensor]] = None

    # ------------------------------------------------------------------
    # Learner interface helper
    # ------------------------------------------------------------------

    def new_episode(self) -> None:
        """에피소드 시작마다 hidden 초기화"""
        self.hidden_policy = None

    @torch.no_grad()
    def _ensure_nets_initialized(self, state_dim: int) -> None:
        if self._nets_initialized:
            return

        dummy = torch.zeros(1, 1, state_dim, device=device)

        # LazyLinear 파라미터 실제 생성
        self.policy_net(dummy, None)
        self.target_net(dummy, None)

        # ✅ 생성 직후 타깃 동기화
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()

        self._nets_initialized = True

    @torch.no_grad()
    def _advance_hidden_with_state(self, actor_state: ndarray) -> None:
        state_dim = int(np.asarray(actor_state).shape[0])
        self._ensure_nets_initialized(state_dim)

        x = torch.as_tensor(actor_state, dtype=torch.float32, device=device).view(1, 1, -1)  # [1,1,D]
        _, h = self.policy_net(x, self.hidden_policy)
        # 안전하게 detach
        self.hidden_policy = (h[0].detach(), h[1].detach())

    def parameters_as_string(self):
        return (
            f"γ={self.gamma}, lr={self.learning_rate}, replaymemory={self.memory.capacity},\n"
            f"batch={self.batch_size}, target_update={self.target_update}, seq_len={self.seq_len}"
        )

    def all_parameters_as_string(self) -> str:
        model = self.stateaction_model
        return (
            f"{self.parameters_as_string()}\n"
            f"dimension={model.state_space.flat_size()}x{model.action_space.flat_size()}, "
            f"Q={[f.name() for f in model.state_space.feature_selection]} "
            f"-> 'abstract_action'"
        )

    # =================================================================
    # 4-1. DRQN 학습 루프
    # =================================================================

    def optimize_model(self, norm_clipping: bool = False):
        # 충분한 step이 쌓이지 않았으면 학습 안 함
        # quick 모드에서도 학습이 돌아가도록 기준을 완화
        if len(self.memory) < self.batch_size:
            return

        try:
            (
                state_batch,      # [B, T, state_dim]
                action_batch,     # [B, T, 1]
                reward_batch,     # [B, T]
                next_state_batch, # [B, T, state_dim]
                done_batch,       # [B, T]
            ) = self.memory.sample(self.batch_size)
        except ValueError:
            return

        # Q(s_t, a_t)
        q_values, _ = self.policy_net(state_batch, None)          # [B, T, A]
        q_taken = q_values.gather(2, action_batch.long()).squeeze(2)  # [B, T]

        # V(s_{t+1}) = max_a' Q_target(s_{t+1}, a')
        with torch.no_grad():
            next_q_values, _ = self.target_net(next_state_batch, None)  # [B, T, A]
            next_max_q = next_q_values.max(2)[0]                         # [B, T]

            done_mask = done_batch  # [B, T], 1.0 if done else 0.0
            # y_t = r_t + γ * max_a' Q_target(s_{t+1}, a') * (1 - done)
            target = reward_batch + self.gamma * next_max_q * (1.0 - done_mask)

        # Huber loss
        loss = F.smooth_l1_loss(q_taken, target)

        # Optimize the model
        self.optimizer.zero_grad()
        loss.backward()

        # Gradient clipping
        if norm_clipping:
            clip_grad_norm_(self.policy_net.parameters(), 1.0)
        else:
            for param in self.policy_net.parameters():
                if param.grad is not None:
                    param.grad.data.clamp_(-1, 1)
        self.optimizer.step()

    # ====== Q 업데이트에 쓰는 state vector 헬퍼 ======

    def get_actor_state_vector(self, global_state: ndarray, actor_features: ndarray) -> ndarray:
        return np.concatenate(
            (
                np.array(global_state, dtype=np.float32),
                np.array(actor_features, dtype=np.float32),
            )
        )

    def update_q_function(
        self,
        reward: float,
        actor_state: ndarray,
        abstract_action: np.int32,
        next_actor_state: Optional[ndarray],
    ):
        """Transition을 replay memory에 넣고 DRQN optimize 호출."""
        reward_tensor = torch.tensor([reward], device=device, dtype=torch.float)  # [1]
        action_tensor = torch.tensor([[np.int_(abstract_action)]], device=device, dtype=torch.long)  # [1, 1]
        current_state_tensor = torch.as_tensor(actor_state, dtype=torch.float, device=device).unsqueeze(0)  # [1, D]

        if next_actor_state is None:
            # 에피소드 종료
            done_tensor = torch.tensor([1.0], device=device, dtype=torch.float)  # [1]
            # done이면 next_state는 아무 값이나 상관 없으나, shape 맞추기 위해 현재 state 재사용
            next_state_tensor = current_state_tensor.clone()
        else:
            done_tensor = torch.tensor([0.0], device=device, dtype=torch.float)  # [1]
            next_state_tensor = torch.as_tensor(next_actor_state, dtype=torch.float, device=device).unsqueeze(0)  # [1, D]

        self.memory.push(
            current_state_tensor,  # [1, D]
            action_tensor,         # [1, 1]
            next_state_tensor,     # [1, D]
            reward_tensor,         # [1]
            done_tensor,           # [1]
        )

        # optimize the DRQN
        self.optimize_model()

    # =================================================================
    # 4-2. Learner 인터페이스 구현
    # =================================================================

    def on_step(
        self,
        wrapped_env: w.AgentWrapper,
        observation,
        reward: float,
        done: bool,
        truncated: bool,
        info,
        action_metadata,
    ):
        """환경에서 한 step 진행된 뒤 호출됨."""
        agent_state = wrapped_env.state
        terminal = done or truncated

        if terminal:
            self.update_q_function(
                reward,
                actor_state=action_metadata.actor_state,
                abstract_action=action_metadata.abstract_action,
                next_actor_state=None,
            )
        else:
            next_global_state = self.stateaction_model.global_features.get(agent_state, node=None)
            next_actor_features = self.stateaction_model.node_specific_features.get(agent_state, action_metadata.actor_node)
            next_actor_state = self.get_actor_state_vector(next_global_state, next_actor_features)

            self.update_q_function(
                reward,
                actor_state=action_metadata.actor_state,
                abstract_action=action_metadata.abstract_action,
                next_actor_state=next_actor_state,
            )

        # ✅ hidden 업데이트는 여기서 하지 않음 (exploit/explore에서만 1회)

    def end_of_episode(self, i_episode, t):
        # Update the target network, copying all weights and biases in DRQN
        if i_episode % self.target_update == 0:
            self.target_net.load_state_dict(self.policy_net.state_dict())

    # =================================================================
    # 4-3. DRQN 기반 action lookup / exploit / explore
    # =================================================================

    def lookup_dqn(self, states_to_consider: List[ndarray]) -> Tuple[List[np.int32], List[float]]:
        """Given a set of possible current states return:
        - for each state: best action (argmax Q)
        - and 그때의 max Q값

        DRQN hidden을 이용하기 위해 states_to_consider를 하나의 시퀀스로 보고
        [1, T, D] 형태로 넣되, hidden_policy는 건드리지 않고 복사본으로 쓴다.
        """
        if not states_to_consider:
            return [], []
        self._ensure_nets_initialized(int(np.asarray(states_to_consider[0]).shape[0]))
        with torch.no_grad():
            B = len(states_to_consider)
            x = torch.tensor(states_to_consider, dtype=torch.float32, device=device).unsqueeze(1)  # [B,1,D]

            h0 = None
            if self.hidden_policy is not None:
                h, c = self.hidden_policy
                # batch 크기에 맞춰 복제
                h0 = (h.detach().repeat(1, B, 1), c.detach().repeat(1, B, 1))

            q, _ = self.policy_net(x, h0)  # [B,1,A]
            q = q.squeeze(1)              # [B,A]

            max_q, max_idx = q.max(1)     # [B]
            action_lookups = [np.int32(i) for i in max_idx.tolist()]
            expectedq_lookups = max_q.tolist()

        return action_lookups, expectedq_lookups

    def metadata_from_gymaction(self, wrapped_env, gym_action):
        current_global_state = self.stateaction_model.global_features.get(wrapped_env.state, node=None)
        actor_node = cyberbattle_env.sourcenode_of_action(gym_action)
        actor_features = self.stateaction_model.node_specific_features.get(wrapped_env.state, actor_node)
        abstract_action = self.stateaction_model.action_space.abstract_from_gymaction(gym_action)
        return ChosenActionMetadata(
            abstract_action=abstract_action,
            actor_node=actor_node,
            actor_features=actor_features,
            actor_state=self.get_actor_state_vector(current_global_state, actor_features),
        )

    def explore(self, wrapped_env: w.AgentWrapper) -> Tuple[str, cyberbattle_env.Action, object]:
        """Random exploration that avoids repeating actions previously taken in the same state"""
        gym_action = wrapped_env.env.sample_valid_action(kinds=[0, 1, 2])
        metadata = self.metadata_from_gymaction(wrapped_env, gym_action)

        # ✅ 현재 관측(선택된 actor_state) 1회 반영
        self._advance_hidden_with_state(metadata.actor_state)
        return "explore", gym_action, metadata

    def try_exploit_at_candidate_actor_states(self, wrapped_env, current_global_state, actor_features, abstract_action):
        actor_state = self.get_actor_state_vector(current_global_state, actor_features)

        action_style, gym_action, actor_node = self.stateaction_model.implement_action(
            wrapped_env,
            actor_features,
            abstract_action,
        )

        if gym_action:
            assert actor_node is not None
            return (
                action_style,
                gym_action,
                ChosenActionMetadata(
                    abstract_action=abstract_action,
                    actor_node=actor_node,
                    actor_features=actor_features,
                    actor_state=actor_state,
                ),
            )

        # ✅ 가짜 transition 학습 제거
        return "exploit[undefined]->explore", None, None

    def exploit(self, wrapped_env, observation) -> Tuple[str, Optional[cyberbattle_env.Action], object]:
        current_global_state = self.stateaction_model.global_features.get(wrapped_env.state, node=None)

        active_actors_features: List[ndarray] = [
            self.stateaction_model.node_specific_features.get(wrapped_env.state, from_node)
            for from_node in w.owned_nodes(observation)
        ]
        unique_active_actors_features: List[ndarray] = list(np.unique(active_actors_features, axis=0))

        candidate_actor_state_vector: List[ndarray] = [
            self.get_actor_state_vector(current_global_state, node_features)
            for node_features in unique_active_actors_features
        ]

        remaining_action_lookups, remaining_expectedq_lookups = self.lookup_dqn(candidate_actor_state_vector)
        remaining_candidate_indices = list(range(len(candidate_actor_state_vector)))

        while remaining_candidate_indices:
            _, remaining_candidate_index = random_argmax(remaining_expectedq_lookups)
            actor_index = remaining_candidate_indices[remaining_candidate_index]
            abstract_action = remaining_action_lookups[remaining_candidate_index]
            actor_features = unique_active_actors_features[actor_index]

            action_style, gym_action, metadata = self.try_exploit_at_candidate_actor_states(
                wrapped_env,
                current_global_state,
                actor_features,
                abstract_action,
            )

            if gym_action:
                # ✅ 선택된 상태를 1회만 hidden에 반영
                self._advance_hidden_with_state(metadata.actor_state)
                return action_style, gym_action, metadata

            remaining_candidate_indices.pop(remaining_candidate_index)
            remaining_expectedq_lookups.pop(remaining_candidate_index)
            remaining_action_lookups.pop(remaining_candidate_index)

        return "exploit[undefined]->explore", None, None

    def stateaction_as_string(self, action_metadata) -> str:
        return ""
