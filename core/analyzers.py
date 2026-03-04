import math
import re
import os
import ollama
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from core.fuzzy_logic import calculate_fuzzy_risk

# ── Load fine-tuned CodeBERT ──────────────────────────
CODEBERT_PATH      = "models/codebert-vuln"
codebert_model     = None
codebert_tokenizer = None


def load_codebert():
    global codebert_model, codebert_tokenizer
    if codebert_model is None and os.path.exists(CODEBERT_PATH):
        print("Loading fine-tuned CodeBERT...")
        codebert_tokenizer = AutoTokenizer.from_pretrained(CODEBERT_PATH)
        codebert_model     = AutoModelForSequenceClassification.from_pretrained(CODEBERT_PATH)
        codebert_model.eval()
        if torch.cuda.is_available():
            codebert_model = codebert_model.cuda()
        print("✓ CodeBERT loaded!")
    return codebert_model, codebert_tokenizer


def scan_with_codebert(code_snippet):
    """Returns vulnerability probability using fine-tuned CodeBERT."""
    model, tokenizer = load_codebert()
    if model is None:
        return None  # fallback to CodeLlama

    inputs = tokenizer(
        code_snippet[:512],
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True
    )
    if torch.cuda.is_available():
        inputs = {k: v.cuda() for k, v in inputs.items()}

    with torch.no_grad():
        outputs   = model(**inputs)
        probs     = torch.softmax(outputs.logits, dim=1)
        vuln_prob = probs[0][1].item()

    return vuln_prob


def calculate_shannon_entropy(code_snippet):
    if not code_snippet:
        return 0
    entropy     = 0
    length      = len(code_snippet)
    frequencies = {c: code_snippet.count(c) / length for c in set(code_snippet)}
    for freq in frequencies.values():
        entropy -= freq * math.log2(freq)
    return round(entropy, 4)


def is_unsafe_call(func, code):
    """Match function calls only, not substrings like strncpy containing strcpy."""
    pattern = rf'\b{func}\s*\('
    return bool(re.search(pattern, code))


def scan_with_ai_model(code_snippet):
    try:
        # ── 1. HARD RULES FIRST ───────────────────────────────
        unsafe_functions = [
            "strcpy", "gets", "strcat", "sprintf", "vsprintf",
            "scanf", "sscanf", "system", "popen", "memcpy", "memmove",
        ]
        found_unsafe = [f for f in unsafe_functions if is_unsafe_call(f, code_snippet)]
        if found_unsafe:
            print(f"⚠️ Hard Rule: {found_unsafe} — skipping AI")
            return 0.95, f"CWE-242: Use of Inherently Unsafe Function ({found_unsafe[0]})"

        # ── 2. CodeBERT (fine-tuned) ──────────────────────────
        bert_prob = scan_with_codebert(code_snippet)
        if bert_prob is not None:
            print(f"CodeBERT prob: {bert_prob:.3f}")
            if bert_prob > 0.4:
                return bert_prob, "Vulnerability Detected (CodeBERT)"
            if bert_prob < 0.15:
                return bert_prob, "Safe / No Vulnerability"
            print("CodeBERT uncertain — calling CodeLlama...")

        # ── 3. CodeLlama (only for uncertain 0.3–0.7 range) ───
        prompt_text = f"""Classify this C/C++ code. Reply with ONE line only.
If safe: SAFE
If vulnerable: CWE-ID: Name|probability

Examples:
SAFE
CWE-121: Stack Buffer Overflow|0.95
CWE-242: Use of Inherently Unsafe Function|0.90

Code:
{code_snippet[:1500]}

Reply:"""

        response  = ollama.generate(model='codellama:7b', prompt=prompt_text)
        ai_reply  = response['response'].strip()
        print(f"AI Raw Reply: {ai_reply}")

        prob      = bert_prob if bert_prob is not None else 0.3
        vuln_name = "Potential Vulnerability"

        first_line = ai_reply.split('\n')[0].strip().upper()
        if first_line == "SAFE" or "STATUS: SAFE" in ai_reply:
            print("AI determined SAFE.")
            if bert_prob is not None:
                prob = bert_prob * 0.6
            else:
                prob = 0.0
            return prob, "Safe / No Vulnerability"

        if "|" in ai_reply:
            parts = ai_reply.split("|")
            if len(parts) >= 2:
                match = re.search(r"0\.\d+|1\.0", parts[1])
                if match:
                    llm_prob = float(match.group())
                    # Weighted ensemble: 60% CodeBERT + 40% CodeLlama
                    if bert_prob is not None:
                        prob = (bert_prob * 0.6) + (llm_prob * 0.4)
                    else:
                        prob = llm_prob
                vuln_name = parts[0].strip()
        else:
            lower = ai_reply.lower()
            if "buffer overflow" in lower:
                vuln_name, prob = "CWE-121: Buffer Overflow", 0.8
            elif "sql injection" in lower:
                vuln_name, prob = "CWE-89: SQL Injection", 0.8
            elif "use after free" in lower:
                vuln_name, prob = "CWE-416: Use After Free", 0.8
            elif "null" in lower and "deref" in lower:
                vuln_name, prob = "CWE-476: NULL Pointer Dereference", 0.75

        # ── 4. False positive filters ─────────────────────────
        if is_unsafe_call("system", code_snippet):
            is_safe_system = re.search(
                r'system\s*\(\s*["\'](pause|cls)["\']\s*\)',
                code_snippet, re.IGNORECASE
            )
            if is_safe_system:
                print("FP Fix: system('pause') is safe.")
                prob      = 0.1
                vuln_name = "Info: system() safe in this context"

        if "loop" in vuln_name.lower() or "iteration" in vuln_name.lower():
            has_loop = any(kw in code_snippet.lower()
                           for kw in ["for", "while", "do"])
            if not has_loop:
                print("FP Fix: No loop found, reducing confidence.")
                prob     *= 0.4
                vuln_name += " (Confidence Reduced: No loop found)"

        return prob, vuln_name

    except Exception as e:
        print(f"AI Error: {e}")
        return 0.3, "AI Unavailable — Manual Review Recommended"


def apply_fuzzy_logic(ai_prob, entropy):
    return calculate_fuzzy_risk(ai_prob, entropy)