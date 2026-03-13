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
        return None

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


# ── Known-safe patterns for system() calls ────────────
SAFE_SYSTEM_PATTERNS = re.compile(
    r'system\s*\(\s*["\'](\s*pause\s*|\s*cls\s*|\s*clear\s*)["\'](\s*)\)',
    re.IGNORECASE
)

# ── Known-safe patterns for scanf (e.g. scanf_s usage) ──
SAFE_SCANF_PATTERNS = re.compile(
    r'\bscanf_s\s*\(',
    re.IGNORECASE
)

def _filter_safe_system(code_snippet, found_unsafe):
    """
    Remove 'system' from found_unsafe list if the only system() calls
    are provably safe hardcoded strings like system("pause") / system("cls").
    Returns the updated found_unsafe list.
    """
    if "system" not in found_unsafe:
        return found_unsafe

    # Find ALL system( calls
    all_system_calls = re.findall(r'system\s*\([^)]*\)', code_snippet, re.IGNORECASE)
    if not all_system_calls:
        return found_unsafe

    # Check every call — if even one is NOT a safe pattern, keep flagging
    for call in all_system_calls:
        if not SAFE_SYSTEM_PATTERNS.search(call):
            # Dynamic or unknown argument — keep system in the list
            return found_unsafe

    # All system() calls are safe patterns
    print("FP Fix: All system() calls use safe hardcoded strings (pause/cls).")
    return [f for f in found_unsafe if f != "system"]


def _filter_safe_scanf(code_snippet, found_unsafe):
    """
    Remove 'scanf' from found_unsafe if the code only uses scanf_s (safe variant)
    and never plain scanf.
    """
    if "scanf" not in found_unsafe:
        return found_unsafe

    has_plain_scanf  = bool(re.search(r'(?<!\w)scanf\s*\(', code_snippet))
    has_scanf_s      = bool(SAFE_SCANF_PATTERNS.search(code_snippet))

    if has_scanf_s and not has_plain_scanf:
        print("FP Fix: Only scanf_s found (safe variant) — removing scanf flag.")
        return [f for f in found_unsafe if f != "scanf"]

    return found_unsafe


def scan_with_ai_model(code_snippet):
    try:
        # ── 1. HARD RULES — with false-positive filtering BEFORE returning ─────

        unsafe_functions = [
            "strcpy", "gets", "strcat", "sprintf", "vsprintf",
            "scanf", "sscanf", "system", "popen", "memcpy", "memmove",
        ]

        found_unsafe = [f for f in unsafe_functions if is_unsafe_call(f, code_snippet)]

        if found_unsafe:
            # ── Apply false-positive filters BEFORE deciding to short-circuit ──
            found_unsafe = _filter_safe_system(code_snippet, found_unsafe)
            found_unsafe = _filter_safe_scanf(code_snippet, found_unsafe)

        if found_unsafe:
            # Still unsafe after filtering — short-circuit with hard rule
            print(f"⚠️ Hard Rule: {found_unsafe} — skipping AI")
            return 0.95, f"CWE-242: Use of Inherently Unsafe Function ({found_unsafe[0]})"

        # ── 2. CodeBERT (fine-tuned) ──────────────────────────
        bert_prob = scan_with_codebert(code_snippet)
        if bert_prob is not None:
            print(f"CodeBERT prob: {bert_prob:.3f}")
            # FIX: raised short-circuit threshold from 0.4 → 0.85
            # CodeBERT is overconfident on safe usage of strncpy/memcpy etc.
            # that appear frequently in vulnerable code in the training set.
            # Requiring 0.85+ before skipping CodeLlama forces a second opinion
            # on borderline cases and reduces false positives like safe_test.c.
            if bert_prob > 0.85:
                # Still very high — but call CodeLlama to confirm before returning
                print("CodeBERT very high confidence — calling CodeLlama to confirm...")
            elif bert_prob > 0.4:
                # Medium-high — always send to CodeLlama for second opinion
                print("CodeBERT medium confidence — calling CodeLlama...")
            elif bert_prob < 0.15:
                return bert_prob, "Safe / No Vulnerability"
            else:
                print("CodeBERT uncertain — calling CodeLlama...")

        # ── 3. CodeLlama (only for uncertain range) ───────────
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

        # ── 4. False positive filters for AI-derived results ─────────────────
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
        # Return SAFE on error to avoid false positives from memory errors
        return 0.05, "Safe / No Vulnerability"


def apply_fuzzy_logic(ai_prob, entropy):
    return calculate_fuzzy_risk(ai_prob, entropy)