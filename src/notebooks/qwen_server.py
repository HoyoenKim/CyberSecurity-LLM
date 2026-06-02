#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal transformers HTTP server for a local chat model (e.g. Qwen3.6-27B).

목적: 모델은 transformers 가 깔린 env(예: ~/.conda/envs/qwen, transformers 5.x +
flash-linear-attention)에서 1회 로드해 서빙하고, agentic 러너(run_agentic_llm.py)는
cyberbattle 이 깔린 다른 env(hykim_ect)에서 돌리며 localhost HTTP 로 호출한다.
→ 두 env 를 건드리지 않고 분리. vLLM 이 못 띄우는 비표준 아키텍처(qwen3_5)도 OK.

의존성: transformers, torch (해당 env 에 이미 존재) + 파이썬 표준 라이브러리뿐.

엔드포인트
  GET  /health -> {"status":"ok","model":<path>}
  POST /chat   {"messages":[{role,content}...], "max_new_tokens":int?, "temperature":float?}
               -> {"text": <assistant 응답>, "gen_time": float, "input_tokens": int, "output_tokens": int}

실행(예, qwen env):
  export PYTHONNOUSERSITE=1; source ~/miniconda3/etc/profile.d/conda.sh; conda activate qwen
  python qwen_server.py --model_path /data/shared/huggingface/hub/Qwen3.6-27B --port 8000
"""
import os
import json
import time
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

# 전역(로드된 모델/토크나이저)
tokenizer = None
model = None
MODEL_PATH = ""


def load_model(model_path: str, cuda_visible: str):
    global tokenizer, model, MODEL_PATH
    os.environ["CUDA_VISIBLE_DEVICES"] = cuda_visible
    import torch  # noqa: F401
    from transformers import AutoModelForCausalLM, AutoTokenizer
    MODEL_PATH = model_path
    t0 = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        device_map="auto",
        torch_dtype="auto",
    )
    model.eval()
    print(f"[qwen_server] loaded {model_path} in {time.perf_counter()-t0:.1f}s", flush=True)


def generate(messages, max_new_tokens: int, temperature: float):
    import torch
    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
        enable_thinking=False,   # qwen_test.py 와 동일: thinking 비활성
    )
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    input_len = inputs.input_ids.shape[1]

    gen_kwargs = dict(max_new_tokens=max_new_tokens, repetition_penalty=1.0)
    if temperature and temperature > 0:
        gen_kwargs.update(do_sample=True, temperature=float(temperature))
    else:
        gen_kwargs.update(do_sample=False)  # greedy/deterministic

    if torch.cuda.is_available():
        torch.cuda.synchronize()
    t0 = time.perf_counter()
    with torch.no_grad():
        out = model.generate(**inputs, **gen_kwargs)
    if torch.cuda.is_available():
        torch.cuda.synchronize()
    gen_time = time.perf_counter() - t0

    out_ids = out[0][input_len:].tolist()
    ans = tokenizer.decode(out_ids, skip_special_tokens=True).strip()
    if "</think>" in ans:
        ans = ans.split("</think>", 1)[1].strip()
    return {
        "text": ans,
        "gen_time": round(gen_time, 2),
        "input_tokens": int(input_len),
        "output_tokens": len(out_ids),
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 조용히
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok", "model": MODEL_PATH})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/chat":
            self._send(404, {"error": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n).decode("utf-8"))
            messages = body["messages"]
            max_new = int(body.get("max_new_tokens", 512))
            temperature = float(body.get("temperature", 0.0) or 0.0)
            result = generate(messages, max_new, temperature)
            self._send(200, result)
        except Exception as e:
            self._send(500, {"error": f"{type(e).__name__}: {e}"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model_path", default="/data/shared/huggingface/hub/Qwen3.6-27B")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--cuda", default="0", help="CUDA_VISIBLE_DEVICES")
    args = ap.parse_args()

    load_model(args.model_path, args.cuda)
    srv = HTTPServer((args.host, args.port), Handler)
    print(f"[qwen_server] serving on http://{args.host}:{args.port} (POST /chat, GET /health)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
