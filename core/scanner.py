import time
import os
import zipfile
import pandas as pd
import gradio as gr
from core.analyzers import calculate_shannon_entropy, scan_with_ai_model
from core.fuzzy_logic import calculate_fuzzy_risk 
from core.remediator import generate_remediation_report
from core.git_loader import clone_and_read_repo 

# ==========================================
# Main System
# ==========================================

def hybrid_scanning_system(file_obj, git_url):
    """
    ฟังก์ชันหลัก: รับไฟล์ -> อ่านไฟล์ -> ส่งให้ AI วิเคราะห์
    """
    # 1. เช็ค Input
    if file_obj is None and not git_url:
        gr.Warning("กรุณาอัปโหลดไฟล์ หรือใส่ลิงก์ Git ก่อนกดสแกน") 
        return "Waiting for input...", pd.DataFrame(), ""

    # Display Debug Info
    source_name = file_obj.name if file_obj else git_url
    print(f"DEBUG: Processing... {source_name}")
    
    files_to_scan = [] # ลิสต์เก็บไฟล์ที่จะสแกน (ชื่อไฟล์, โค้ด)

    # ---------------------------------------------------------
    # 2. จัดการไฟล์ UPLOAD (Zip / Source Code)
    # ---------------------------------------------------------
    if file_obj is not None:
        real_path = file_obj.name # Gradio ส่ง path ของไฟล์ temp มาให้
        
        # กรณี A: อัปโหลดเป็น .zip
        if real_path.endswith('.zip'):
            try:
                with zipfile.ZipFile(real_path, 'r') as zip_ref:
                    for file_name in zip_ref.namelist():
                        if file_name.endswith(('.c', '.cpp', '.h', '.hpp')):
                            with zip_ref.open(file_name) as f:
                                content = f.read().decode('utf-8', errors='ignore')
                                files_to_scan.append((file_name, content))
            except Exception as e:
                return f"❌ Error reading zip: {str(e)}", pd.DataFrame(), ""

        # กรณี B: อัปโหลดไฟล์ Code โดยตรง
        else:
            try:
                filename = os.path.basename(real_path)
                with open(real_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    files_to_scan.append((filename, content))
            except Exception as e:
                return f"❌ Error reading file: {str(e)}", pd.DataFrame(), ""

# ---------------------------------------------------------
    # 3. จัดการ GIT URL (🟢 ดักกรองลิงก์ให้สะอาดตั้งแต่หน้าประตู)
    # ---------------------------------------------------------
    if git_url:
        import re
        
        # ลบช่องว่างที่อาจเผลอก๊อปปี้ติดมา
        git_url = git_url.strip() 
        
        # ตัดลิงก์ไฟล์ทิ้ง ให้เหลือแค่โฟลเดอร์โปรเจกต์
        match = re.match(r"(https?://github\.com/[^/]+/[^/]+)", git_url)
        if match:
            git_url = match.group(1)
            # ลบ .git ออกถ้ามี แล้วเติมเข้าไปใหม่ให้ชัวร์
            git_url = git_url.replace('.git', '') + '.git'
            
        try:
            print(f"🚀 DEBUG: Starting Git Clone process for Cleaned URL: {git_url}")
            git_files = clone_and_read_repo(git_url) 
            
            if not git_files:
                return "❌ Git Clone สำเร็จ แต่ไม่พบไฟล์ .c/.cpp ใน Repo นั้น", pd.DataFrame(), ""
                
            files_to_scan.extend(git_files) 
            
        except Exception as e:
            return f"❌ Git Error: {str(e)}", pd.DataFrame(), ""

    # ---------------------------------------------------------
    # 4. สแกน (SCANNING LOOP) - เหมือนเดิม
    # ---------------------------------------------------------
    results = []
    
    for filename, code_content in files_to_scan:
        # A. Entropy
        entropy = calculate_shannon_entropy(code_content)
        # B. AI Scan
        ai_prob, vuln_name = scan_with_ai_model(code_content) 
        # C. Fuzzy Risk
        risk_score, severity, prob_label, ent_label = calculate_fuzzy_risk(ai_prob, entropy)

        results.append([
            filename, 
            vuln_name,
            f"{ai_prob:.2f}", 
            f"{entropy:.2f}", 
            risk_score, 
            severity
        ])
        print(f"   > Analyzed {filename}: Risk={risk_score}%")

    # ---------------------------------------------------------
    # 5. สร้าง Report
    # ---------------------------------------------------------
    df = pd.DataFrame(results, columns=["Filename", "Type", "AI Prob.", "Entropy", "Risk Score", "Severity"])
    filtered_df = df[df["Risk Score"] > 40]

    summary_text = f"""
    ### ✅ Scanning Complete
    - **Source:** {git_url if git_url else 'Uploaded File'}
    - **Files Analyzed:** {len(files_to_scan)}
    - **Issues Found:** {len(filtered_df)}
    - **High/Critical Severity:** {len(filtered_df[filtered_df['Risk Score'] > 60])}
    """
    
    remediation_text = "No significant issues found."
    if not filtered_df.empty:
        try:
            print("🚀 DEBUG: Sending High Risk files to Gemini...")
            remediation_text = generate_remediation_report(df, files_to_scan)
            print("✅ DEBUG: Gemini response received!")
        except Exception as e:
            print(f"❌ Remediation Error: {e}")
            remediation_text = f"Error generating remediation: {e}"

    return summary_text, df, remediation_text