from google import genai
import os
from dotenv import load_dotenv
import gradio as gr
import time

load_dotenv()

GENAI_API_KEY = os.getenv("GEMINI_API_KEY")

# ── Constants ─────────────────────────────────────────────────────────────────
# Aligned with scanner.py HIGH_RISK_THRESHOLD — change in one place only
REMEDIATION_RISK_THRESHOLD = 40
MAX_REMEDIATION_FILES       = 3
RETRY_WAIT_SECONDS          = 5 

MODELS_TO_TRY = [
    "gemini-2.5-flash",       # best quality
    "gemini-2.0-flash-lite",  # fallback if quota exhausted
]


def _build_client() -> genai.Client:
    """Create Gemini client once per call, not per retry."""
    return genai.Client(api_key=GENAI_API_KEY)


def get_ai_fix_suggestion(code_snippet: str, vuln_name: str, max_retries: int = 3) -> str:
    """
    Ask Gemini to explain the vulnerability and provide a fixed code snippet.
    Tries each model in MODELS_TO_TRY before giving up.
    """
    if not GENAI_API_KEY:
        return "❌ Error: ไม่พบ API Key"

    # FIX: create client once, reuse across retries and model fallbacks
    client = _build_client()

    prompt_text = f"""Act as a Senior Cyber Security Specialist.
I have detected a vulnerability: "{vuln_name}" in the following C/C++ code.

VULNERABLE CODE:
```c
{code_snippet[:2000]}
```

YOUR TASK:
1. Explain briefly why this is dangerous.
2. Provide the FIXED code snippet (Secure version).
3. Use Markdown formatting."""

    for model_name in MODELS_TO_TRY:
        for attempt in range(max_retries):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt_text
                )

                if response and response.text:
                    return response.text

                return "⚠️ Gemini returned an empty response."

            except Exception as e:
                error_msg = str(e)
                is_quota  = "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg

                if is_quota:
                    if attempt < max_retries - 1:
                        # FIX: short sleep — don't freeze Gradio for 45s
                        print(f"⏳ Quota hit on {model_name} (attempt {attempt + 1}), "
                              f"waiting {RETRY_WAIT_SECONDS}s...")
                        time.sleep(RETRY_WAIT_SECONDS)
                        continue
                    else:
                        # Exhausted retries for this model — try next
                        print(f"Quota exhausted for {model_name}, trying next model...")
                        break
                else:
                    # Non-quota error — no point retrying same model
                    return f"❌ API Error: {error_msg}"

    return "⚠️ All models quota exhausted — try again later."


def generate_remediation_report(df, files_to_scan) -> str:
    """
    Generate a Gemini-powered remediation report for the riskiest files.

    Parameters
    ----------
    df : pd.DataFrame
        Scan results (already filtered above RISK_THRESHOLD by scanner.py).
    files_to_scan : dict
        Mapping of {filename: code_content} — as produced by dict(files_to_scan)
        in scanner.py.
    """
    report_text = "### Remediation Suggestions (Powered by Gemini)\n"

    # FIX: filter by named constant, not a magic number
    risky_files = df[df["Risk Score"] > REMEDIATION_RISK_THRESHOLD]

    if risky_files.empty:
        report_text += "\nGreat job! No significant vulnerabilities detected."
        return report_text

    # FIX: sort so we always show the genuinely top-N riskiest files
    risky_files = risky_files.sort_values("Risk Score", ascending=False)

    count = 0
    for _, row in risky_files.iterrows():
        if count >= MAX_REMEDIATION_FILES:
            report_text += f"\n*(Showing top {MAX_REMEDIATION_FILES} risky files only)*"
            break

        fname = row["Filename"]
        vname = row["Type"]
        risk  = row["Risk Score"]

        # FIX: files_to_scan is now a dict — simple key lookup, no loop needed
        original_code = files_to_scan.get(fname, "")

        if original_code:
            gr.Info(f"Asking Gemini to fix: {fname}...")
            fix_advice = get_ai_fix_suggestion(original_code, vname)

            report_text += f"\n#### 🔥 File: `{fname}` (Risk: {risk}%)\n"
            report_text += f"**Issue:** {vname}\n\n"
            report_text += f"{fix_advice}\n"
            report_text += "---\n"
            count += 1
        else:
            print(f"⚠️ Remediator: source code not found for '{fname}' — skipping.")

    return report_text