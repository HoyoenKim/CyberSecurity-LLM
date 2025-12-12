import os
import yaml
from huggingface_hub import InferenceClient

def load_hf_token(
    config_path: str = "./llm_token.yaml"
) -> str:
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            data = yaml.safe_load(f) or {}

        if isinstance(data, dict):
            hf_cfg = data.get("huggingface")
            if isinstance(hf_cfg, dict) and "api_token" in hf_cfg:
                return hf_cfg["api_token"]
    
    raise RuntimeError(
        f"HF API 토큰을 찾을 수 없습니다. {config_path}를 확인하세요."
    )


HF_TOKEN = load_hf_token()

client = InferenceClient(
    model="meta-llama/Llama-3.1-8B-Instruct",
    token=HF_TOKEN,
)

def chat(messages):
    """
    messages: [{"role": "system"/"user"/"assistant", "content": "..."}]
    -> HuggingFace chat_completion을 그대로 사용
    """
    resp = client.chat_completion(
        messages=messages,
        max_tokens=512,
        temperature=0.7,
    )

    # OpenAI 스타일과 동일하게 처리
    return resp.choices[0].message.content

if __name__ == "__main__":
    msgs = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "강화학습에서 Q-learning이랑 DQN 차이 설명해줘."},
    ]
    print(chat(msgs))
