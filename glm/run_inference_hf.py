#!/usr/bin/env python3
"""
STIG benchmark inference for GLM/CodeGeeX models using HuggingFace transformers directly.
No vLLM required — works on any CUDA version.

Usage:
    python3 run_inference_hf.py --model THUDM/codegeex4-all-9b --out predictions_codegeex4_9b.jsonl
    python3 run_inference_hf.py --limit 5 ...   # smoke test
"""
import argparse
import json
import os
import re
import sys
import time

DATASET_DEFAULT = os.path.join(os.path.dirname(__file__), "..", "benchmark", "dataset.jsonl")


def strip_think_blocks(text):
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def extract_bash(response_text):
    if not response_text:
        return ""
    text = strip_think_blocks(response_text)
    m = re.findall(r"```(?:bash|sh)\s*\n(.*?)```", text, re.DOTALL)
    if m:
        return max(m, key=len).strip()
    m = re.findall(r"```\s*\n?(.*?)```", text, re.DOTALL)
    if m:
        return max(m, key=len).strip()
    return text.strip()


def load_model(model_id, hf_token):
    try:
        import torch
        from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer
    except ImportError:
        sys.exit("pip install transformers torch accelerate")

    print(f"Loading tokenizer: {model_id}", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(
        model_id, trust_remote_code=True, token=hf_token
    )

    # CodeGeeX4/ChatGLM custom code uses config.max_length; patch if missing
    config = AutoConfig.from_pretrained(model_id, trust_remote_code=True, token=hf_token)
    if not hasattr(config, "max_length"):
        config.max_length = getattr(config, "seq_length", 8192)

    print(f"Loading model: {model_id} (BF16, auto device map)...", flush=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        config=config,
        trust_remote_code=True,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        token=hf_token,
    )
    model.eval()
    print("Model loaded.", flush=True)
    return model, tokenizer


def generate(model, tokenizer, prompt, max_new_tokens, temperature):
    import torch

    messages = [{"role": "user", "content": prompt}]
    text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True
    )
    inputs = tokenizer([text], return_tensors="pt").to(model.device)

    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            temperature=temperature if temperature > 0 else None,
            do_sample=temperature > 0,
            pad_token_id=tokenizer.eos_token_id,
        )

    # decode only the newly generated tokens
    generated = out[0][inputs["input_ids"].shape[1]:]
    return tokenizer.decode(generated, skip_special_tokens=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=DATASET_DEFAULT)
    ap.add_argument("--model", default="THUDM/codegeex4-all-9b")
    ap.add_argument("--hf-token", default=os.environ.get("HF_TOKEN", ""))
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--max-new-tokens", type=int, default=2048)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    safe_name = re.sub(r"[^a-z0-9]+", "_", args.model.lower()).strip("_")
    out_path = args.out or f"predictions_{safe_name}.jsonl"

    rows = [json.loads(l) for l in open(args.dataset)]
    rows = [r for r in rows if r.get("prompt")]
    if args.limit:
        rows = rows[:args.limit]
    print(f"{len(rows)} gradeable prompts", flush=True)

    done = set()
    if os.path.exists(out_path):
        for l in open(out_path):
            try:
                done.add(json.loads(l)["rule_id"])
            except Exception:
                pass
    todo = [r for r in rows if r["rule_id"] not in done]
    if done:
        print(f"Resuming: {len(done)} done, {len(todo)} remaining.", flush=True)

    model, tokenizer = load_model(args.model, args.hf_token or None)

    out_f = open(out_path, "a")
    try:
        for i, r in enumerate(todo, 1):
            t0 = time.time()
            raw = ""
            for attempt in range(3):
                try:
                    raw = generate(model, tokenizer, r["prompt"],
                                   args.max_new_tokens, args.temperature)
                    break
                except Exception as e:
                    if attempt == 2:
                        print(f"  ! failed {r['rule_id']}: {e}", flush=True)
                    else:
                        time.sleep(3)

            script = extract_bash(raw)
            fenced = "```" in strip_think_blocks(raw)
            has_think = bool(re.search(r"<think>", raw))
            elapsed = time.time() - t0

            pred = {
                "rule_id": r["rule_id"],
                "stig_id": r.get("stig_id", ""),
                "model": args.model,
                "generated_script": script,
                "extracted_ok": bool(script) and fenced,
                "has_think_block": has_think,
                "raw_response": raw,
            }
            out_f.write(json.dumps(pred) + "\n")
            out_f.flush()
            print(
                f"[{len(done)+i}/{len(rows)}] {r.get('stig_id','')} {r['rule_id']}: "
                f"extracted {len(script)} chars (fenced={fenced}, think={has_think}, {elapsed:.1f}s)",
                flush=True,
            )
    finally:
        out_f.close()

    ok = sum(1 for l in open(out_path) for p in [json.loads(l)] if p.get("extracted_ok"))
    print(f"\nDone. Total: {len(done)+len(todo)} | cleanly extracted: {ok}", flush=True)
    print(f"Predictions -> {out_path}", flush=True)


if __name__ == "__main__":
    main()
