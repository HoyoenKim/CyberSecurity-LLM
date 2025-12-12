import os
import yaml
from openai import OpenAI


def load_openai_token(config_path: str = "./llm_token.yaml") -> str:
    """
    1) llm_token.yaml 의 openai.api_key 우선
    2) 없으면 마지막에 환경변수 OPENAI_API_KEY 사용
    """
    if os.path.exists(config_path):
        print(f"[DEBUG] Loading OpenAI API key from {config_path}")
        with open(config_path, "r") as f:
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


OPENAI_API_KEY = load_openai_token()
client = OpenAI(api_key=OPENAI_API_KEY)


def chat(messages, model: str = "gpt-5.1"):
    """
    messages: [{"role": "system"/"user"/"assistant", "content": "..."}]

    GPT-5.1 은 Responses API 사용 권장이라,
    messages를 Responses용 input 포맷으로 변환해서 호출.
    """
    print("[DEBUG] chat() 호출됨")
    print(f"[DEBUG] model = {model}")
    print(f"[DEBUG] messages = {messages}")

    # Responses API는 input을 이런 식으로 받음:
    # [{"role": "...", "content": [{"type": "input_text", "text": "..."}]}]
    input_items = []
    for m in messages:
        input_items.append({
            "role": m["role"],
            "content": [
                {"type": "input_text", "text": m["content"]},
            ],
        })

    resp = client.responses.create(
        model=model,
        input=input_items,
        # 필요하면 reasoning / text 옵션도 조정 가능
        # reasoning={"effort": "none"},  # 기본값 none
        # text={"verbosity": "low"},     # 답변 길이 조절
        max_output_tokens=512,
    )

    print("[DEBUG] API 호출 완료")
    if hasattr(resp, "usage"):
        print("[DEBUG] usage:", resp.usage)

    # Responses API는 output_text 라는 편의 프로퍼티 제공
    text = resp.output_text or ""
    return text


if __name__ == "__main__":
    print("[DEBUG] test_openai.py 시작")

    msgs = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "강화학습에서 Q-learning이랑 DQN 차이 설명해줘."},
    ]

    answer = chat(msgs)
    print("\n[ANSWER]")
    print(answer)
    print("[DEBUG] 스크립트 종료")
