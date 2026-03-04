import re
import time
import os
import zipfile
import pandas as pd
import gradio as gr
from core.analyzers import calculate_shannon_entropy, scan_with_ai_model
from core.fuzzy_logic import calculate_fuzzy_risk
from core.remediator import generate_remediation_report
from core.git_loader import clone_and_read_repo
from core.rate_limiter import check_rate_limit

# Risk threshold — lower = catch more vulnerabilities (fewer FN)
RISK_THRESHOLD      = 25
HIGH_RISK_THRESHOLD = 60
MAX_FILE_SIZE_MB    = 5
MAX_FILES_IN_ZIP    = 20
MAX_CODE_LENGTH     = 50000


def hybrid_scanning_system(file_obj, git_url):

    # ── 1. Validate input ─────────────────────────────────────
    if file_obj is None and not git_url:
        gr.Warning("กรุณาอัปโหลดไฟล์ หรือใส่ลิงก์ Git ก่อนกดสแกน")
        return "Waiting for input...", pd.DataFrame(), ""

    # ── 1.5 Rate limit check ──────────────────────
    allowed, message = check_rate_limit()
    if not allowed:
        return message, pd.DataFrame(), ""

    source_name   = file_obj.name if file_obj else git_url
    files_to_scan = []
    print(f"DEBUG: Processing... {source_name}")

    # ── 2. Handle file upload ─────────────────────────────────
    if file_obj is not None:
        real_path = file_obj.name

        # ── File size check ──
        file_size_mb = os.path.getsize(real_path) / (1024 * 1024)
        if file_size_mb > MAX_FILE_SIZE_MB:
            return f"❌ File too large ({file_size_mb:.1f}MB). Maximum is {MAX_FILE_SIZE_MB}MB.", pd.DataFrame(), ""

        if real_path.endswith('.zip'):
            try:
                with zipfile.ZipFile(real_path, 'r') as zip_ref:

                    # ── Zip bomb check ──
                    total_uncompressed = sum(info.file_size for info in zip_ref.infolist())
                    if total_uncompressed > 50 * 1024 * 1024:
                        return "❌ Zip file expands too large (possible zip bomb). Maximum is 50MB.", pd.DataFrame(), ""

                    # ── Zip file count check ──
                    c_files = [f for f in zip_ref.namelist()
                               if f.endswith(('.c', '.cpp', '.h', '.hpp'))]
                    if len(c_files) > MAX_FILES_IN_ZIP:
                        return f"❌ Too many files in zip ({len(c_files)}). Maximum is {MAX_FILES_IN_ZIP} files.", pd.DataFrame(), ""

                    for file_name in c_files:
                        with zip_ref.open(file_name) as f:
                            content = f.read().decode('utf-8', errors='ignore')
                            if len(content) > MAX_CODE_LENGTH:
                                content = content[:MAX_CODE_LENGTH]
                                print(f"⚠️ Truncated {file_name} to {MAX_CODE_LENGTH} chars")
                            files_to_scan.append((file_name, content))

            except Exception as e:
                return f"❌ Error reading zip: {str(e)}", pd.DataFrame(), ""
        else:
            try:
                filename = os.path.basename(real_path)
                with open(real_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                if len(content) > MAX_CODE_LENGTH:
                    content = content[:MAX_CODE_LENGTH]
                    print(f"⚠️ Truncated {filename} to {MAX_CODE_LENGTH} chars")
                files_to_scan.append((filename, content))
            except Exception as e:
                return f"❌ Error reading file: {str(e)}", pd.DataFrame(), ""

    # ── 3. Handle Git URL ─────────────────────────────────────
    if git_url:
        git_url = git_url.strip()
        match   = re.match(r"(https?://github\.com/[^/]+/[^/]+)", git_url)
        if match:
            git_url = match.group(1).replace('.git', '') + '.git'
        try:
            print(f"🚀 DEBUG: Cloning {git_url}")
            git_files = clone_and_read_repo(git_url)
            if not git_files:
                return "❌ Git Clone สำเร็จ แต่ไม่พบไฟล์ .c/.cpp ใน Repo นั้น", pd.DataFrame(), ""
            files_to_scan.extend(git_files)
        except Exception as e:
            return f"❌ Git Error: {str(e)}", pd.DataFrame(), ""

    # ── 4. Guard — nothing to scan ────────────────────────────
    if not files_to_scan:
        return "❌ No scannable files found (.c, .cpp, .h, .hpp)", pd.DataFrame(), ""

    # ── 5. Scan loop ──────────────────────────────────────────
    results = []

    for filename, code_content in files_to_scan:
        entropy                             = calculate_shannon_entropy(code_content)
        ai_prob, vuln_name                  = scan_with_ai_model(code_content)
        risk_score, severity, prob_label, _ = calculate_fuzzy_risk(ai_prob, entropy)

        results.append([
            filename,
            vuln_name,
            f"{ai_prob:.2f}",
            f"{entropy:.2f}",
            risk_score,
            severity
        ])
        print(f"   > {filename}: Risk={risk_score}%  Severity={severity}")

    # ── 6. Build report ───────────────────────────────────────
    df = pd.DataFrame(
        results,
        columns=["Filename", "Type", "AI Prob.", "Entropy", "Risk Score", "Severity"]
    )
    filtered_df    = df[df["Risk Score"] > RISK_THRESHOLD]
    high_df        = filtered_df[filtered_df["Risk Score"] > HIGH_RISK_THRESHOLD]

    critical_count = len(df[df["Severity"] == "Critical"])
    high_count     = len(df[df["Severity"] == "High"])
    medium_count   = len(df[df["Severity"] == "Medium"])
    low_count      = len(df[df["Severity"] == "Low"])

    summary_text = f"""### Scanning Complete
- **Source:** {git_url if git_url else 'Uploaded File'}
- **Files Analyzed:** {len(files_to_scan)}
---
- 🔴 **Critical:** {critical_count}
- 🟠 **High:** {high_count}
- 🟡 **Medium:** {medium_count}
- 🟢 **Low / Safe:** {low_count}
"""

    # ── 7. Remediation ────────────────────────────────────────
    remediation_text = "✅ No significant issues found."

    if not filtered_df.empty:
        try:
            print("🚀 DEBUG: Sending to Gemini...")
            remediation_text = generate_remediation_report(filtered_df, files_to_scan)
            print("✅ DEBUG: Gemini done!")
        except Exception as e:
            print(f"❌ Remediation Error: {e}")
            remediation_text = f"⚠️ Error generating remediation: {e}"

    return summary_text, df, remediation_text