import math
import re
import ollama
from core.fuzzy_logic import calculate_fuzzy_risk 

# ==========================================
# Analysis Logic
# ==========================================

def calculate_shannon_entropy(code_snippet):
    """คำนวณค่า Entropy (เหมือนเดิม ไม่ต้องแก้)"""
    if not code_snippet:
        return 0
    
    entropy = 0
    length = len(code_snippet)
    frequencies = {c: code_snippet.count(c) / length for c in set(code_snippet)}
    
    for freq in frequencies.values():
        entropy -= freq * math.log2(freq)
    
    return round(entropy, 4)

def scan_with_ai_model(code_snippet):
    """
    สั่ง AI + Hard Rules + Sanity Checks (แก้ False Positive)
    """
    try:
        # -------------------------------------------------------
        # 🟢 1. Prompt AI (อัปเดต: เพิ่มทางออก SAFE และข้อห้ามมโน)
        # -------------------------------------------------------
        prompt_text = f"""
        You are a Senior Security Analyst. Analyze this C/C++ code.
        
        STRICT RULES:
        1. If the code is completely safe, or just performs basic UI/graphics/math operations without taking unchecked user input, you MUST reply with exactly: "STATUS: SAFE".
        2. DO NOT invent or hallucinate vulnerabilities.
        3. If and ONLY IF a real vulnerability exists, reply STRICTLY in this format:
           CWE-XXX: Vulnerability Name|Score
        
        Example of real vulnerability: "CWE-121: Stack Buffer Overflow|0.95"
        
        Code:
        {code_snippet[:2000]} 
        """

        response = ollama.generate(model='codellama:7b', prompt=prompt_text)
        ai_reply = response['response'].strip()
        print(f"🤖 AI Raw Reply: {ai_reply}") 

        # -------------------------------------------------------
        # 2. Parsing Logic
        # -------------------------------------------------------
        prob = 0.5
        vuln_name = "Potential Vulnerability (See Logs)"

        # 🟢 ดักจับคำว่า SAFE ก่อนเลย
        if "STATUS: SAFE" in ai_reply or "SAFE" in ai_reply.upper():
            print("✅ AI determined this code is SAFE.")
            prob = 0.0
            vuln_name = "Safe / No Vulnerability"
        else:
            # พยายามดึงค่าตาม Format เดิมของคุณ
            if "|" in ai_reply:
                parts = ai_reply.split("|")
                if len(parts) >= 2: # กัน error กรณีไม่มีค่าหลัง |
                    match = re.search(r"0\.\d+|1\.0|0", parts[1])
                    if match:
                        prob = float(match.group())
                    vuln_name = parts[0].strip()
            else:
                score_match = re.search(r"Probability:\s*(0\.\d+|1\.0)", ai_reply, re.IGNORECASE)
                name_match = re.search(r"Vulnerability Name:\s*(.+)", ai_reply, re.IGNORECASE)
                
                if score_match: prob = float(score_match.group(1))
                if name_match: vuln_name = name_match.group(1).strip()
                
                lower_reply = ai_reply.lower()
                if "buffer overflow" in lower_reply: vuln_name = "CWE-121: Buffer Overflow"
                elif "sql injection" in lower_reply: vuln_name = "CWE-89: SQL Injection"

        # -------------------------------------------------------
        # 3. HARD RULE OVERRIDE (ยังคงไว้ ทับสิทธิ์ AI ได้ถ้าเจอฟังก์ชันอันตรายจริง)
        # -------------------------------------------------------
        unsafe_functions = ["strcpy", "gets", "strcat", "sprintf", "vsprintf"]
        found_unsafe = [func for func in unsafe_functions if f"{func}" in code_snippet]
        
        if found_unsafe:
            print(f"⚠️ HARD RULE DETECTED: Found unsafe functions {found_unsafe}")
            if prob < 0.95: prob = 0.95
            vuln_name = f"CWE-242: Use of Inherently Unsafe Function ({found_unsafe[0]})"

        # =======================================================
        # 4. SANITY CHECK / FALSE POSITIVE FILTER
        # =======================================================
        if "system" in code_snippet:
            is_safe_system = re.search(r'system\s*\(\s*["\'](pause|cls)["\']\s*\)', code_snippet, re.IGNORECASE)
            if is_safe_system and ("CWE-78" in vuln_name or "Command" in vuln_name):
                print("False Positive Fix: system('pause') is safe here.")
                prob = 0.1 
                vuln_name = "Info: Use of system() is discouraged but safe in this context"

        code_lower = code_snippet.lower()
        vuln_lower = vuln_name.lower()
        
        if ("loop" in vuln_lower or "iteration" in vuln_lower):
            has_loop = "for" in code_lower or "while" in code_lower or "do" in code_lower
            if not has_loop:
                print("Hallucination Fix: AI claims loop error but no loop found.")
                prob = prob * 0.4
                vuln_name += " (AI Confidence Reduced: No loop found in code)"

        return prob, vuln_name

    except Exception as e:
        print(f"AI Error: {e}") 
        return 0.0, "AI Error"

def apply_fuzzy_logic(ai_prob, entropy):
    """
    ส่งต่อให้ Fuzzy Logic Engine คำนวณ
    """
    return calculate_fuzzy_risk(ai_prob, entropy)