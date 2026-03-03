import math
import re
import ollama
from core.fuzzy_logic import calculate_fuzzy_risk


def calculate_shannon_entropy(code_snippet):
    if not code_snippet:
        return 0
    entropy     = 0
    length      = len(code_snippet)
    frequencies = {c: code_snippet.count(c) / length for c in set(code_snippet)}
    for freq in frequencies.values():
        entropy -= freq * math.log2(freq)
    return round(entropy, 4)


def scan_with_ai_model(code_snippet):
    try:
        # ── 1. Strict prompt ──────────────────────────────────
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

        response = ollama.generate(model='codellama:7b', prompt=prompt_text)
        ai_reply  = response['response'].strip()
        print(f"AI Raw Reply: {ai_reply}")

        # ── 2. Parse ──────────────────────────────────────────
        prob      = 0.3   # lean safe when uncertain
        vuln_name = "Potential Vulnerability (See Logs)"

        # Check SAFE — exact match only
        first_line = ai_reply.split('\n')[0].strip().upper()
        if first_line == "SAFE" or "STATUS: SAFE" in ai_reply:
            print("AI determined this code is SAFE.")
            return 0.0, "Safe / No Vulnerability"

        # Parse CWE format
        if "|" in ai_reply:
            parts = ai_reply.split("|")
            if len(parts) >= 2:
                match = re.search(r"0\.\d+|1\.0", parts[1])
                if match:
                    prob = float(match.group())
                vuln_name = parts[0].strip()
        else:
            lower = ai_reply.lower()
            if "buffer overflow" in lower:
                vuln_name = "CWE-121: Buffer Overflow"
                prob      = 0.8
            elif "sql injection" in lower:
                vuln_name = "CWE-89: SQL Injection"
                prob      = 0.8
            elif "use after free" in lower:
                vuln_name = "CWE-416: Use After Free"
                prob      = 0.8
            elif "null" in lower and "deref" in lower:
                vuln_name = "CWE-476: NULL Pointer Dereference"
                prob      = 0.75

        # ── 3. Hard rules — expanded list ────────────────────
        unsafe_functions = [
            "strcpy", "gets", "strcat", "sprintf", "vsprintf",
            "scanf", "sscanf",
            "system", "popen",
            "memcpy", "memmove",
        ]
        found_unsafe = [f for f in unsafe_functions if f in code_snippet]

        if found_unsafe:
            print(f"⚠️ Hard Rule: {found_unsafe}")
            prob      = max(prob, 0.95)
            vuln_name = f"CWE-242: Use of Inherently Unsafe Function ({found_unsafe[0]})"

        # ── 4. False positive filters ─────────────────────────
        # system('pause') / system('cls') is safe
        if "system" in code_snippet:
            is_safe_system = re.search(
                r'system\s*\(\s*["\'](pause|cls)["\']\s*\)',
                code_snippet, re.IGNORECASE
            )
            if is_safe_system:
                print("FP Fix: system('pause') is safe.")
                prob      = 0.1
                vuln_name = "Info: system() safe in this context"

        # Hallucination: claims loop error but no loop exists
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