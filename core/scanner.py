import time
import os
import zipfile
import pandas as pd
import gradio as gr
from core.analyzers import calculate_shannon_entropy, scan_with_ai_model, apply_fuzzy_logic
from core.remediator import generate_remediation_report

# ==========================================
# Main System (ระบบหลัก)
# ==========================================

def hybrid_scanning_system(file_obj, git_url):
    """
    ฟังก์ชันหลัก: รับไฟล์ -> อ่านไฟล์ -> ส่งให้ AI วิเคราะห์
    """
    # 1. เช็ค Input
    if file_obj is None and not git_url:
        gr.Warning("⚠️ กรุณาอัปโหลดไฟล์ หรือใส่ลิงก์ Git ก่อนกดสแกนครับ!") 
        return "Waiting for input...", pd.DataFrame(), ""

    file_path = file_obj.name if file_obj else "Git URL"
    print(f"DEBUG: Processing... {file_path}")
    
    files_to_scan = [] #ลิสต์เก็บไฟล์ที่จะสแกน (ชื่อไฟล์, โค้ด)

    # 2.ขั้นตอนการอ่านไฟล์ (READ FILES)
    # ---------------------------------------------------------
    if file_obj is not None:
        real_path = file_obj # Gradio ส่ง path ของไฟล์ temp มาให้
        
        # กรณีที่ 1: อัปโหลดเป็น .zip
        if real_path.endswith('.zip'):
            try:
                with zipfile.ZipFile(real_path, 'r') as zip_ref:
                    # วนลูปหาไฟล์ .c / .cpp ใน zip
                    for file_name in zip_ref.namelist():
                        if file_name.endswith(('.c', '.cpp', '.h', '.hpp')):
                            with zip_ref.open(file_name) as f:
                                # อ่าน content ออกมา (decode เป็น string)
                                content = f.read().decode('utf-8', errors='ignore')
                                files_to_scan.append((file_name, content))
            except Exception as e:
                return f"❌ Error reading zip: {str(e)}", pd.DataFrame(), ""

        # กรณีที่ 2: อัปโหลดไฟล์ Code โดยตรง (.c, .cpp)
        else:
            try:
                filename = os.path.basename(real_path)
                with open(real_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    files_to_scan.append((filename, content))
            except Exception as e:
                return f"❌ Error reading file: {str(e)}", pd.DataFrame(), ""

    # TODO: ส่วนของ Git Clone ยังไม่ได้ทำ (ข้ามไปก่อน)

    # เช็คว่าเจอไฟล์ไหม?
    if not files_to_scan:
        gr.Warning("ไม่พบไฟล์ Source Code (.c/.cpp) ที่อ่านได้!") 
        return "please upload .c/.cpp file", pd.DataFrame(), ""

    # 3.ขั้นตอนการสแกน (SCANNING LOOP)
    # ---------------------------------------------------------
    results = []
    
    # วนลูปไฟล์จริงๆ ที่อ่านมาได้
    for filename, code_content in files_to_scan:
        
        # A. คำนวณ Entropy
        entropy = calculate_shannon_entropy(code_content)
        
        # B. ให้ AI ตรวจ (ส่งโค้ดจริงไปให้ Ollama)
        ai_prob, vuln_name = scan_with_ai_model(code_content) 
        
        # C. ประเมินความเสี่ยง
        risk_score, severity = apply_fuzzy_logic(ai_prob, entropy)
        
        results.append([
            filename, 
            vuln_name,  #ใส่ชื่อช่องโหว่ที่ AI บอก แทนคำว่า "Unknown"
            f"{ai_prob:.2f}", 
            f"{entropy:.2f}", 
            risk_score, 
            severity
        ])
        print(f"   > Analyzed {filename}: Risk={risk_score}%") # Debug ใน Terminal

    # 4.สร้าง Report
    df = pd.DataFrame(results, columns=["Filename", "Type", "AI Prob.", "Entropy", "Risk Score", "Severity"])
    
    #กรองเฉพาะตัวที่มีปัญหา
    filtered_df = df[df["Risk Score"] > 40]

    summary_text = f"""
    ### ✅ Scanning Complete
    - **Files Analyzed:** {len(files_to_scan)} files
    - **Issues Found:** {len(filtered_df)}
    - **High/Critical Severity:** {len(filtered_df[filtered_df['Risk Score'] > 60])}
    """
    remediation_text = generate_remediation_report(df, files_to_scan)

    return summary_text, df, remediation_text