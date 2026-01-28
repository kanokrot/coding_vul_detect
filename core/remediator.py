import google.generativeai as genai
import gradio as gr
import os

# ==========================================
# CONFIGURATION
# ==========================================
# 🔑 ไปเอา Key จาก aistudio.google.com มาใส่ตรงนี้
GENAI_API_KEY = "AIzaSyDxxxx_ใส่คีย์ของคุณตรงนี้_xxxx"

def get_ai_fix_suggestion(code_snippet, vuln_name):
    """
    ฟังก์ชันภายใน: ส่งโค้ดไปถามวิธีแก้จาก Google Gemini
    """
    try:
        # ตั้งค่าโมเดล
        genai.configure(api_key=GENAI_API_KEY)
        model = genai.GenerativeModel('gemini-1.5-flash') # ใช้รุ่น Flash (ฟรี & เร็ว)

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
        
        # เรียก AI (Gemini)
        response = model.generate_content(prompt_text)
        return response.text
        
    except Exception as e:
        return f"⚠️ API Error: {str(e)} (Check your Internet or API Key)"

def generate_remediation_report(df, files_to_scan):
    """
    ฟังก์ชันหลัก: สร้าง Report แนะนำวิธีแก้
    """
    report_text = "### 🛠️ Remediation Suggestions (Powered by Gemini)\n"
    
    # 1. กรองเฉพาะไฟล์ที่มีความเสี่ยง (Risk Score > 40)
    # เราไม่จำเป็นต้องเอาแค่ Top 1 แล้ว เพราะ Gemini ทำงานเร็วมาก สแกนทุกไฟล์ที่เสี่ยงได้เลย
    risky_files = df[df["Risk Score"] > 40]
    
    if risky_files.empty:
        report_text += "\n✅ Great job! No significant vulnerabilities detected."
        return report_text

    # 2. วนลูปสร้างคำแนะนำทีละไฟล์
    count = 0
    for index, row in risky_files.iterrows():
        # จำกัดจำนวน (เผื่อเจอ 100 ไฟล์ เดี๋ยว Token หมด) เอาแค่ 3 ไฟล์ที่หนักสุด
        if count >= 3: 
            report_text += "\n*(Showing top 3 risky files only)*"
            break
            
        fname = row["Filename"]
        vname = row["Type"]
        risk = row["Risk Score"]
        
        # ค้นหา Source Code
        original_code = ""
        for name, content in files_to_scan:
            if name == fname:
                original_code = content
                break
        
        if original_code:
            # แจ้งเตือนใน UI ว่ากำลังถาม AI
            gr.Info(f"🤖 Asking Gemini to fix: {fname}...")
            
            fix_advice = get_ai_fix_suggestion(original_code, vname)
            
            report_text += f"#### 🔥 File: `{fname}` (Risk: {risk}%)\n"
            report_text += f"**Issue:** {vname}\n\n"
            report_text += f"{fix_advice}\n"
            report_text += "---\n"
            count += 1
            
    return report_text