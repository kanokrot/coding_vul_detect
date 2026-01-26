import ollama
import pandas as pd
import gradio as gr

def get_ai_fix_suggestion(code_snippet, vuln_name):
    """
    ฟังก์ชันภายใน: ส่งโค้ดไปถามวิธีแก้จาก Ollama
    """
    try:
        prompt_text = f"""
        You are a security expert. The following C/C++ code has a vulnerability identified as "{vuln_name}".
        
        Code:
        {code_snippet[:1500]} 
        
        Task:
        1. Explain briefly how to fix it.
        2. Provide the CORRECTED code snippet.
        3. Keep the answer concise.
        """
        
        # เรียก AI
        response = ollama.generate(model='codellama:7b', prompt=prompt_text)
        return response['response'].strip()
    except Exception as e:
        return f"Could not generate fix: {str(e)}"

def generate_remediation_report(df, files_to_scan):
    """
    ฟังก์ชันหลัก: สร้างข้อความแนะนำการแก้ไข (Remediation Report)
    รับค่า:
      - df: ตารางผลลัพธ์ (DataFrame)
      - files_to_scan: ลิสต์ข้อมูลไฟล์เดิม [(name, code), ...]
    คืนค่า:
      - ข้อความ String ที่จัด Format แล้ว
    """
    report_text = "### 🛠️ Remediation Suggestions\n"
    
    # 1. หาไฟล์ที่มีความเสี่ยงระดับ Critical หรือ High
    critical_files = df[df["Severity"].isin(["Critical", "High"])]
    
    if critical_files.empty:
        report_text += "\nGreat job! No critical vulnerabilities detected."
        return report_text

    # 2. เลือกมา 1 ไฟล์ที่หนักที่สุดเพื่อแนะนำ (เพื่อไม่ให้รอนานเกินไป)
    # เรียงลำดับตาม Risk Score มากไปน้อย
    top_risk_file = critical_files.sort_values(by="Risk Score", ascending=False).iloc[0]
    
    fname = top_risk_file["Filename"]
    vname = top_risk_file["Type"]
    risk = top_risk_file["Risk Score"]
    
    report_text += f"#### 🔥 Priority Fix: {fname} (Risk: {risk}%)\n"
    report_text += f"**Detected Issue:** {vname}\n\n"
    
    # 3. ค้นหา Source Code เดิมของไฟล์นั้น
    original_code = ""
    for name, content in files_to_scan:
        if name == fname:
            original_code = content
            break
    
    if original_code:
        # แจ้งเตือนผู้ใช้ว่า AI กำลังคิด (ผ่าน Gradio)
        gr.Info(f"🤖 AI is generating a fix for {fname}...")
        
        # เรียกฟังก์ชันขอวิธีแก้
        fix_advice = get_ai_fix_suggestion(original_code, vname)
        
        report_text += f"**💡 AI Recommendation:**\n\n{fix_advice}\n"
        report_text += "\n---\n"
    else:
        report_text += "⚠️ Error: Could not find original source code."

    return report_text