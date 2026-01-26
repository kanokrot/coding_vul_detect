import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl

def calculate_fuzzy_risk(ai_prob, entropy):
    """
    Final Balanced Version: ความสมดุลระหว่างความปลอดภัยและลด False Positive
    """
    try:
        # 1. สร้างตัวแปร
        ai_conf = ctrl.Antecedent(np.arange(0, 1.1, 0.1), 'ai_conf')
        code_ent = ctrl.Antecedent(np.arange(0, 8.5, 0.5), 'code_ent')
        risk = ctrl.Consequent(np.arange(0, 101, 1), 'risk')

        # 2. ปรับกราฟ (Membership Functions)       
        # AI Confidence
        ai_conf['low'] = fuzz.trimf(ai_conf.universe, [0, 0, 0.5])
        ai_conf['medium'] = fuzz.trimf(ai_conf.universe, [0, 0.5, 1.0])
        ai_conf['high'] = fuzz.trimf(ai_conf.universe, [0.5, 1.0, 1.0])

        # Entropy (ใช้ trapmf เพื่อครอบคลุม Normal ให้กว้างขึ้น)
        code_ent['normal'] = fuzz.trapmf(code_ent.universe, [0, 0, 4.5, 6.0]) 
        code_ent['suspicious'] = fuzz.trimf(code_ent.universe, [5.0, 6.5, 7.5])
        code_ent['high'] = fuzz.trimf(code_ent.universe, [6.5, 8, 8])

        # Risk Score (เพิ่มระดับ High เข้ามา เพื่อความละเอียด)
        risk['safe'] = fuzz.trimf(risk.universe, [0, 0, 40])
        risk['warning'] = fuzz.trimf(risk.universe, [30, 50, 70])  # Medium
        risk['high'] = fuzz.trimf(risk.universe, [50, 75, 90])     # ✅ New: High (Orange)
        risk['critical'] = fuzz.trimf(risk.universe, [80, 100, 100]) # Critical (Red)

        # 3. กำหนดกฎ (Rules) - ปรับจูนใหม่
        # -------------------------------------------
        rules = [
            # --- กรณี AI มั่นใจสูง (High) ---
            # AI มั่นใจ + โค้ดมั่ว (Entropy High/Suspicious) -> อันตรายแน่นอน
            ctrl.Rule(ai_conf['high'] & code_ent['high'], risk['critical']),
            ctrl.Rule(ai_conf['high'] & code_ent['suspicious'], risk['critical']), 

            # [จุดตัดสินใจ] AI มั่นใจ + โค้ดดูปกติ (Normal) -> ให้เป็น High (75%)
            # (Buffer Overflow มักตกเคสนี้ คือร้ายแรงแต่คะแนน Entropy ไม่สูง)
            # (Piggybank ก็จะตกเคสนี้ ซึ่งยอมรับได้ว่าเป็น False Positive แบบ Safe)
            ctrl.Rule(ai_conf['high'] & code_ent['normal'], risk['high']),

            # --- กรณี AI กลางๆ (Medium) ---
            ctrl.Rule(ai_conf['medium'] & code_ent['high'], risk['high']),
            ctrl.Rule(ai_conf['medium'] & code_ent['suspicious'], risk['warning']),
            ctrl.Rule(ai_conf['medium'] & code_ent['normal'], risk['warning']),

            # --- กรณี AI ไม่มั่นใจ (Low) ---
            ctrl.Rule(ai_conf['low'] & code_ent['high'], risk['warning']),
            ctrl.Rule(ai_conf['low'] & code_ent['suspicious'], risk['safe']),
            ctrl.Rule(ai_conf['low'] & code_ent['normal'], risk['safe']),
        ]

        # 4. ประมวลผล
        risk_ctrl = ctrl.ControlSystem(rules)
        risk_sim = ctrl.ControlSystemSimulation(risk_ctrl)

        risk_sim.input['ai_conf'] = float(ai_prob)
        risk_sim.input['code_ent'] = float(entropy)
        
        risk_sim.compute()
        final_score = risk_sim.output['risk']

    except Exception as e:
        print(f"⚠️ Fuzzy Error: {e}")
        final_score = (ai_prob * 0.7 + (min(entropy/8, 1) * 0.3)) * 100

    # แปลงตัวเลขเป็นคำ (ปรับเกณฑ์ให้เข้ากับกราฟใหม่)
    severity = "Low"
    if final_score >= 80: severity = "Critical"
    elif final_score >= 60: severity = "High"   # ✅ 60-79 เป็น High
    elif final_score >= 40: severity = "Medium"
    
    return round(final_score, 2), severity