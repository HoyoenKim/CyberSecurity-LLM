# CLAUDE.md

이 문서는 향후 Claude(및 기여자)가 이 저장소에서 작업할 때 참고하는 가이드입니다.
프로젝트에서 **실제로 진행된 내용**을 정리하고, 코드를 **비판적으로 검토한 개선점**을 함께 담았습니다.

---

## 1. 프로젝트 개요

Microsoft **CyberBattleSim**(공격자 RL 시뮬레이터) + Microsoft **DefenderBench**(LLM 에이전트 벤치마크)를
포크/통합하여, 자동차 도메인 침투 테스트를 위한 세 종류의 공격 에이전트를 비교하는 연구 프로젝트.

진행된 핵심 기여(README 및 git 히스토리 기준):

1. **자동차 CTF 환경 신규 구현** (`CyberBattleAutomotiveCTF-v0`)
   - IVI / Telematics / OTA / Gateway(GTW) / OBD / DCAN / CAN·LIN 버스 / ECU 노드를 가진 차량 내부망 토폴로지
   - 포트·방화벽·크리덴셜 게이팅으로 세그먼테이션과 피벗 제약을 모델링
2. **네이티브 LLM 에이전트** (ReAct 스타일, 학습 없음)
   - HuggingFace 모델(Llama 3.1 8B 등) 러너 + OpenAI 모델(GPT-5.1/5.2) 러너
3. **하이브리드 RL+LLM 에이전트**
   - DQL(Deep Q-Learning)에 LLM 액션 프루닝/선택을 결합
4. **LLM 기반 자동 보안 리포트 생성**
   - 에피소드 JSON 로그 → Mermaid 공격 경로 다이어그램 + 서술형 리포트(TARA 지향)

상세 배경·결과·표는 루트의 [README.md](README.md)에 정리되어 있습니다. 본 문서는 README가 다루지 않는
**구현 실태와 그 한계**에 집중합니다.

---

## 2. 실제 코드 위치 (README 구조도와 다른 부분 주의)

| 구성요소 | 실제 경로 |
| --- | --- |
| 자동차 환경 시나리오 정의 | [src/cyberbattle/samples/toyctf/automotive_ctf.py](src/cyberbattle/samples/toyctf/automotive_ctf.py) |
| 자동차 환경 gym 등록/래퍼 | [src/cyberbattle/_env/cyberbattle_automotive_ctf.py](src/cyberbattle/_env/cyberbattle_automotive_ctf.py) |
| DefenderBench 텍스트 환경 래퍼 | [src/defenderbench/cyberbattlesim/cyberbattlesim_env.py](src/defenderbench/cyberbattlesim/cyberbattlesim_env.py) |
| 네이티브 LLM 러너 (OpenAI) | [src/notebooks/run_openai_llm.py](src/notebooks/run_openai_llm.py), `run_openai_llm2.py` |
| 네이티브 LLM 러너 (HF) | [src/notebooks/run_huggingface_llm.py](src/notebooks/run_huggingface_llm.py) |
| 하이브리드 노트북 (실사용) | `src/notebooks/{chain10,toy_ctf,automotive_ctf}_hybrid_dql_llm.py` |
| 자동 리포트 생성 | [src/notebooks/run_llm_report.py](src/notebooks/run_llm_report.py) |
| 베이스 DQL 정책 | [src/cyberbattle/agents/baseline/agent_dql.py](src/cyberbattle/agents/baseline/agent_dql.py) |

> ⚠️ README §3.3 구조도는 LLM 에이전트를 `src/cyberbattle/agents/llm_agents/`로 표기하지만
> 실제 경로는 `src/cyberbattle/llm_agents/`이며, **그 디렉터리는 현재 어떤 러너에서도 사용되지 않습니다**(아래 §5 참조).

---

## 3. 실행 방법

```bash
# 환경 구성 (Linux/WSL 기준)
bash install-conda.sh && bash init.sh && conda activate cybersimllm

# 토큰: 루트에 llm_token.yaml 생성 (gitignore 됨)
#   openai:
#     api_key: "sk-..."        # ← 코드가 읽는 키 이름은 api_key (README 예시의 api_token 아님)
#   huggingface:
#     api_token: "hf_..."

# 네이티브 LLM (단일 에피소드 실행 + JSON/TXT 로그)
python3 ./src/notebooks/run_openai_llm.py --env toyctf --model_id gpt-5.1 --max_steps 100 --output_dir <dir>
python3 ./src/notebooks/run_huggingface_llm.py --env chain10 --model_id meta-llama/Llama-3.1-8B-Instruct --max_steps 100 --output_dir <dir>

# 하이브리드 (papermill로 노트북 실행, use_llm=true 등 파라미터 주입)
./src/notebooks/run_toy_ctf_hybrid_dql_llm.sh python3
./src/notebooks/run_automotive_ctf_hybrid_dql_llm.sh python3

# 자동 리포트 (LLM 에피소드 JSON → Markdown 리포트)
python3 ./src/notebooks/run_llm_report.py --input_json <log>.json --env toyctf --model gpt-5.1 --output_md <out>.md

# 기존 CyberBattleSim 테스트(상속분만 존재)
pytest src/cyberbattle
```

---

## 4. 평가 지표의 의미 (해석 시 주의)

- 네이티브 LLM 러너의 `Final Score: X/Y`는 [cyberbattlesim_env.py:312](src/defenderbench/cyberbattlesim/cyberbattlesim_env.py#L312)에서
  - `score = count_owned_nodes` = **admin/system 권한으로 소유한 노드 수**
  - `max_score = node_count = attacker_goal.own_atleast` (ToyCTF·Automotive는 **6**, Chain10은 전체 노드 수 12)
- 즉 ToyCTF/Automotive의 "/6"은 전체 노드가 아니라 **목표 노드 수**다. 환경마다 분모 의미가 달라 직접 비교 시 주의.
- 환경은 LLM에게 매 스텝 **유효 액션 전체 목록**을 만들어 주지만([`_build_action_list`](src/defenderbench/cyberbattlesim/cyberbattlesim_env.py#L116)),
  러너는 그중 **앞 20개만 프롬프트에 예시로 노출**한다([run_openai_llm.py:311](src/notebooks/run_openai_llm.py#L311)). 노드가 많아지면 정답 액션이 힌트에서 누락될 수 있다.

---

## 5. 코드 구조상 반드시 알아야 할 함정

### 5.1 하이브리드 구현이 **두 개**이고, 하나는 죽은 코드
- `src/cyberbattle/agents/baseline/agent_dql_hybrid_llm.py`의 `LLMGuidedDeepQLearnerPolicy`는
  **어떤 노트북·러너에서도 import되지 않는다**(grep으로 확인). 즉 사용되지 않는 코드.
- 실제 결과를 만든 것은 각 하이브리드 노트북 안에 **인라인으로 정의된** `LLMPrunedExploitWrapper`
  (예: [toy_ctf_hybrid_dql_llm.py:164](src/notebooks/toy_ctf_hybrid_dql_llm.py#L164)).
- 두 구현의 동작이 다르므로, "하이브리드 = agent_dql_hybrid_llm.py"로 읽으면 안 된다.

### 5.2 `src/cyberbattle/llm_agents/`는 사실상 레거시
- `react_agent.py`, `tree_of_thoughts_agent.py`, `actor_critic.py`, `base_agent.py`는 DefenderBench 잔재.
- 실제 러너들은 이를 쓰지 않고 **자체 `ReActAgent`를 파일마다 새로 정의**한다.
- `actor_critic.py`는 `from src.cyberbattle.llm_agents.base_agent import ...`처럼 패키지 레이아웃과 맞지 않는
  절대 import를 사용 → 현재 구조에서 import 시 깨질 가능성이 높다.

### 5.3 `llm_config.yaml` vs `llm_token.yaml`
- 러너 코드는 `llm_token.yaml`만 읽는다. 루트의 `llm_config.yaml`(Azure gpt-4o 템플릿)은 **현재 코드가 참조하지 않는** 오래된 설정.

---

## 6. 비판적 검토 및 개선점

심각도 순으로 정리. (🔴 결과 신뢰성에 직접 영향 / 🟠 재현성·품질 / 🟡 위생·문서)

### 🔴 A. 결과 신뢰성 / 연구 방법론

1. **하이브리드의 LLM이 "학습"이 아니라 "평가"에만 적용됨 — 핵심 주장과 구현 불일치**
   - README §2.3/§9/§10은 "RL 학습은 유지하되 LLM이 탐색 중 무효 액션을 줄여 **샘플 효율·수렴 속도**를 높인다"고 반복 주장한다.
   - 그러나 실제 코드에서 학습 단계(`dql_run`)는 **순수 DQL**이고, LLM은 평가 롤아웃(`exploit`)에서만 후보를 추린다
     ([toy_ctf_hybrid_dql_llm.py:284](src/notebooks/toy_ctf_hybrid_dql_llm.py#L284) 학습 / [#L215](src/notebooks/toy_ctf_hybrid_dql_llm.py#L215) 평가).
   - 즉 **"학습 가속/샘플 효율" 주장은 구현으로 뒷받침되지 않는다.** 측정된 것은 평가 시 액션 선택 변화뿐이다.
   - 개선: (a) 주장을 "평가 시 액션 프루닝"으로 정정하거나, (b) 실제로 학습 루프의 행동 선택에 LLM을 넣고
     학습 곡선(수렴 속도)을 LLM on/off로 비교하라.

2. **`§6 베이스 DQL`과 `§9 하이브리드`의 비교가 동일 조건이 아님 (apples-to-apples 아님)**
   - 하이브리드 노트북은 `training_episode_count=20, iteration_count=500, maximum_node_count=32`(automotive)로
     학습량이 매우 작고 환경 파라미터도 베이스 RL 실험과 다르다([run_automotive_ctf_hybrid_dql_llm.sh:34](src/notebooks/run_automotive_ctf_hybrid_dql_llm.sh#L34)).
   - 그런데 §6은 DQN 8/21 발견·4/6 익스플로잇, §9는 21/21·6/6으로 극적 향상을 보고한다.
   - LLM은 평가에서 **5스텝마다 1회**, 그것도 Q값 상위 10개 중 1개를 고르는 수준이라 영향이 제한적이다.
     → 이 극적 차이를 **LLM 기여로 귀속하기 어렵다.** 학습량·환경설정 차이가 교란변수일 가능성이 크다.
   - 개선: 동일 시드·동일 학습량·동일 환경에서 `DQL` vs `DQL+LLM(평가)`만 바꿔 ablation 하라.

3. **`Nodes Found / Nodes Exploited` 지표의 산출 출처가 불명확**
   - 하이브리드 노트북은 누적 보상 곡선만 plot 하고, §9 표의 "21/21, 6/6" 같은 수치를 출력하는 코드가 보이지 않는다.
   - 표가 GIF/플롯에서 수기로 읽은 값인지, 자동 집계인지 불분명 → **재현 경로 부재.**
   - 개선: 평가 종료 시 발견/소유 노드 수를 명시적으로 로깅·집계하는 코드를 추가하라.

4. **단일 에피소드·시드 미고정 (LLM의 높은 분산을 무시)**
   - 네이티브 LLM 러너는 `run_episode`를 **딱 1회** 호출한다([run_openai_llm.py:481](src/notebooks/run_openai_llm.py#L481)). 평균·분산·신뢰구간 없음.
   - 온도/샘플링에 따라 결과가 흔들리는 LLM에서 1회 점수(예: 3/6)는 통계적으로 약하다. README §10.3도 이를 future work로 인정.
   - 개선: 다중 시드·다중 에피소드 평균과 분산을 보고하라.

5. **평가 비교 예산 불일치**
   - Llama/GPT-5.1은 `max_steps=100`, GPT-5.2는 `max_steps=200`([README §7.3](README.md))으로 스텝 예산이 다르다.
   - 개선: 모든 모델·환경에서 동일 스텝 예산으로 통제하라.

6. **평가 중 정책이 동결되지 않음 (주석과 코드 불일치)**
   - `LLMPrunedExploitWrapper.on_step`은 "평가에서 학습 업데이트 금지"라는 주석과 달리 `base.on_step`을 그대로 호출한다
     ([toy_ctf_hybrid_dql_llm.py:209](src/notebooks/toy_ctf_hybrid_dql_llm.py#L209)). 평가 롤아웃에서도 가중치가 갱신될 수 있다.
   - 개선: 평가 시 `torch.no_grad`/업데이트 차단으로 정책을 동결하라.

### 🟠 B. 코드 품질 / 유지보수

7. **죽은 코드 / 중복 코드**
   - `agent_dql_hybrid_llm.py`(미사용, §5.1), `src/cyberbattle/llm_agents/*`(레거시, §5.2) 제거 또는 명시.
   - `run_openai_llm.py`와 `run_openai_llm2.py`가 거의 동일 → `--model_id`로 통합 가능.
   - `ReActAgent`가 러너마다 복붙됨 → 공용 모듈로 추출.
   - `run_openai_llm.py`에 폐기된 시스템 프롬프트 3종(`original/try1/try2`)이 사문으로 남아 있음([run_openai_llm.py:116-245](src/notebooks/run_openai_llm.py#L116)).

8. **`agent_dql_hybrid_llm.py`의 프루닝은 설계상 거의 무효(no-op)**
   - LLM이 후보를 추린 뒤 다시 **Q값 최대값**을 고른다([agent_dql_hybrid_llm.py:223](src/cyberbattle/agents/baseline/agent_dql_hybrid_llm.py#L223)).
     LLM이 Q 최상위 후보만 남기면 결과는 순수 DQL과 동일 → LLM이 사실상 무의미.
   - (미사용 코드지만) 향후 사용 시 LLM 선택이 Q-argmax에 의해 무력화되지 않도록 설계해야 한다.

9. **신규 기여 코드에 대한 테스트 전무**
   - 존재하는 `*_test.py`는 전부 CyberBattleSim/DefenderBench 상속분. 자동차 환경·LLM 러너·하이브리드·리포트 생성에 대한 테스트가 없다.
   - 개선: 최소한 (a) 자동차 환경이 정상 reset/step 되는지, (b) `_parse_action`/`summarize_episode` 단위 테스트 추가.

10. **CI 부재**
    - `.pre-commit-config.yaml`은 있으나 `.github/workflows`가 없어 자동 검증이 없다. 최소 lint/test 워크플로 추가 권장.

### 🟡 C. 저장소 위생 / 문서

11. **생성 산출물이 대량 커밋됨**
    - 추적 파일 286개 중 **174개가 `src/notebooks/output/`**, 실행된 `.ipynb` 6개는 각 3만~3.9만 라인.
    - 저장소 비대화·diff 노이즈·리뷰 곤란. 개선: 산출물은 gitignore 후 릴리스 아티팩트/외부 스토리지로 분리하거나 핵심 결과만 보존.

12. **문서 ↔ 코드 불일치(정정 필요)**
    - 토큰 예시: README §3.1은 `openai: api_token`이라 적었지만 코드는 `openai.api_key`를 읽는다([run_openai_llm.py:42](src/notebooks/run_openai_llm.py#L42)).
    - 경로: README §3.3의 `agents/llm_agents/`는 실제 `llm_agents/`(§5.2).
    - 테스트 파일 경로(README §3.1의 `./src/notebooks/test_huggingface.py`)와 import 가능 여부 점검 필요.
    - 오타: `install_conda.sh`(README) vs `install-conda.sh`(실제 파일), "environmen", "Inompatible" 등.

### 🟢 D. 보안 (대체로 양호)

13. 비밀키 관리: `llm_token.yaml`은 `.gitignore`에 포함되어 있고 추적되는 비밀 파일은 없음(확인 완료). **양호.**
    - 다만 디버그 로그가 키 prefix를 출력(`key[:8]`, `key[:6]`)하므로 운영 환경에선 마스킹 권장.

---

## 7. 잘 되어 있는 점

- 문제 정의(POMDP, 자동차 TARA 동기)와 결과 서술이 README에 체계적으로 정리됨.
- **자동차 CTF 환경**은 포트/방화벽/크리덴셜 게이팅/디코이를 갖춘 실질적 신규 기여.
- DefenderBench 텍스트 래퍼로 RL/LLM이 **동일 액션 인터페이스**를 공유하도록 한 설계는 비교 실험에 적합.
- LLM 자동 리포트는 로그에서 이벤트만 추출해 환각을 줄이는 grounding 프롬프트를 사용(좋은 방향).
- 비밀키 gitignore, troubleshooting 문서화 등 운영 디테일이 챙겨져 있음.

---

## 8. 개선 우선순위 요약

1. (🔴 A1·A2) 하이브리드의 LLM 적용 지점을 명확히 하고, **동일 조건 ablation**으로 LLM 기여를 분리 측정.
2. (🔴 A3·A4) 평가 지표 자동 집계 + 다중 시드/에피소드 평균·분산 보고.
3. (🟠 B7·B9) 죽은 코드 정리, 공용 `ReActAgent` 추출, 신규 코드 테스트 추가.
4. (🟡 C11·C12) 산출물 분리(gitignore) 및 README의 키 이름/경로/오타 정정.

---

## 9. 진행 중 작업 — Agentic 러너 & 원격 실행(newport) (2026-06-01)

### 9.1 배경 / 가설
기존 LLM harness의 ToyCTF **3/6 천장은 모델 능력이 아니라 harness 한계**일 가능성이 크다.
근거: GPT-5.2(steps 2배)도 GPT-5.1과 동일하게 3/6 → 모델을 키워도 개선이 없었다.
식별된 병목: ① 유효 액션 20개만 노출 ② `Action:` 정규식 파싱 ③ 작은 토큰 예산 ④ 메모리/반성 부재 ⑤ 단일 에피소드.

### 9.2 신규 러너: [src/notebooks/run_agentic_llm.py](src/notebooks/run_agentic_llm.py)
위 병목을 제거한 "제대로 된" agentic 러너:
- **전체 유효 액션을 번호 메뉴로 노출** → `take_action(index=N)` (20개 제한 제거)
- **tool-calling**(구조화 출력) → 정규식 파싱 실패 0
- **명시적 메모리**: (시도→결과) 추적 + "무진전/무효 액션 반복 금지" 목록 주입
- 토큰 예산 ↑, **다중 에피소드** 집계(best/mean/solved, invalid_ratio)
- `--provider openai|anthropic|random` — `random`은 **API 키 없이** env/배선 검증용
- 검증: `py_compile` + 오프라인 로직 테스트 + **newport 실제 ToyCTF random 드라이런** 통과(파이프라인 정상).

```bash
# 무키 배선 검증
python src/notebooks/run_agentic_llm.py --env toyctf --provider random --episodes 1
# 본 실행(키/엔드포인트 필요)
python src/notebooks/run_agentic_llm.py --env toyctf --provider openai --model <model> --episodes 3
```

### 9.3 원격 실행 워크플로우 (newport.yonsei.ac.kr)
- 접속: `ssh newport.yonsei.ac.kr` (user `hyeon12`). GPU: H100 NVL 95GB(+T1000 4GB는 사용 불가).
- 코드 반입: **GitHub clone**(scp 아님) → `~/hykim_ect/CyberSecurity-LLM`.
- 환경: `hykim_ect` conda env(py3.10, torch cu124). 활성화(전역설정 없이):
  `export PYTHONNOUSERSITE=1; source ~/miniconda3/etc/profile.d/conda.sh; conda activate hykim_ect`
- ⚠️ 같은 env에 CSRL이 `cyberbattlesim`을 editable로 설치해 두었으나, 러너의 `sys.path.insert(0, src)`가
  **repo의 cyberbattle/defenderbench를 우선**시킴(검증 완료). CSRL 설치는 건드리지 않음. 추가 설치는 `termcolor`, `openai`뿐.

### 9.4 모델 결정 & 현재 상태 — **GPU 대기 중**
- gpt-5.1은 구버전 → **로컬 오픈웨이트 모델**로 전환(키 불필요·재현 가능·비용 0).
- 선정: **`Qwen2.5-Coder-32B-Instruct`** — 공유 캐시 `/data/shared/huggingface/hub/`에 이미 존재(62GB, 읽기 가능), tool-calling 깔끔.
  (`google/codegemma-7b`는 chat_template 없는 base라 제외. llm4decompile류도 특화 모델이라 제외.)
- 실행 계획: **vLLM을 별도 env에 격리** 설치 → OpenAI 호환 서버 + `guided_json` structured output으로
  모델별 tool-parser 의존 제거. 러너에 `--base_url` 추가 예정.
- **현재 상태: H100 점유 중(타 사용자 ~51GB, util ~100% → 44GB만 여유)이라 32B(~64GB) 불가. GPU가 ~70GB 비면 32B로 ToyCTF agentic 테스트 실행 → 기존 3/6과 비교.**
- 🔒 **보안 원칙: 서버/공유에 존재하는 Claude API 키는 이 프로젝트에서 사용하지 않는다(사이드 프로젝트).** LLM 호출은 로컬 vLLM 또는 별도 키로만.
