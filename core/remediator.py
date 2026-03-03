from google import genai
import os
from dotenv import load_dotenv
import gradio as gr
import time

load_dotenv()

GENAI_API_KEY = os.getenv("GEMINI_API_KEY")

def get_ai_fix_suggestion(code_snippet, vuln_name, max_retries=3):
    if not GENAI_API_KEY:
        return "❌ Error: ไม่พบ API Key"

    models_to_try = [
        "gemini-2.5-flash",       # best quality
        "gemini-2.0-flash-lite",  # fallback if quota exhausted
    ]

    for model_name in models_to_try:
        for attempt in range(max_retries):
            try:
                prompt_text = f"""
                Act as a Senior Cyber Security Specialist.
                I have detected a vulnerability: "{vuln_name}" in the following C/C++ code.

                VULNERABLE CODE:
```c
                {code_snippet[:2000]}
```

                YOUR TASK:
                1. Explain briefly why this is dangerous.
                2. Provide the FIXED code snippet (Secure version).
                3. Use Markdown formatting.
                """

                client   = genai.Client(api_key=GENAI_API_KEY)
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt_text
                )

                if response and response.text:
                    return response.text
                else:
                    return "⚠️ Gemini returned an empty response."

            except Exception as e:
                error_msg = str(e)
                if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
                    if attempt < max_retries - 1:
                        time.sleep(45)
                        continue
                    else:
                        print(f"Quota exhausted for {model_name}, trying next model...")
                        break  # try next model
                return f"API Error: {error_msg}"

    return "⚠️ All models quota exhausted — try again later."

def generate_remediation_report(df, files_to_scan):
    report_text = "### Remediation Suggestions (Powered by Gemini)\n"

    risky_files = df[df["Risk Score"] > 40]

    if risky_files.empty:
        report_text += "\nGreat job! No significant vulnerabilities detected."
        return report_text

    count = 0
    for index, row in risky_files.iterrows():
        if count >= 3:
            report_text += "\n*(Showing top 3 risky files only)*"
            break

        fname = row["Filename"]
        vname = row["Type"]
        risk  = row["Risk Score"]

        original_code = ""
        for name, content in files_to_scan:
            if name == fname:
                original_code = content
                break

        if original_code:
            gr.Info(f"Asking Gemini to fix: {fname}...")
            fix_advice = get_ai_fix_suggestion(original_code, vname)

            report_text += f"#### 🔥 File: `{fname}` (Risk: {risk}%)\n"
            report_text += f"**Issue:** {vname}\n\n"
            report_text += f"{fix_advice}\n"
            report_text += "---\n"
            count += 1

    return report_text