import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl
from core.data_processor import discretize_data

def calculate_fuzzy_risk(ai_prob, entropy):
    """
    คำนวณความเสี่ยงด้วย Fuzzy Logic และคืนค่า Label ประกอบ
    โดยเรียกใช้ Data Discretization จากอีกไฟล์
    """
    try:
        # --- 1. สร้างตัวแปร (Antecedent & Consequent) ---
        ai_conf = ctrl.Antecedent(np.arange(0, 1.1, 0.1), 'ai_conf')
        code_ent = ctrl.Antecedent(np.arange(0, 8.5, 0.5), 'code_ent')
        risk = ctrl.Consequent(np.arange(0, 101, 1), 'risk')

        # --- 2. Membership Functions ---
        ai_conf['low'] = fuzz.trimf(ai_conf.universe, [0, 0, 0.5])
        ai_conf['medium'] = fuzz.trimf(ai_conf.universe, [0, 0.5, 1.0])
        ai_conf['high'] = fuzz.trimf(ai_conf.universe, [0.5, 1.0, 1.0])

        code_ent['normal'] = fuzz.trapmf(code_ent.universe, [0, 0, 4.5, 6.0]) 
        code_ent['suspicious'] = fuzz.trimf(code_ent.universe, [5.0, 6.5, 7.5])
        code_ent['high'] = fuzz.trimf(code_ent.universe, [6.5, 8, 8])

        risk['safe'] = fuzz.trimf(risk.universe, [0, 0, 40])
        risk['warning'] = fuzz.trimf(risk.universe, [30, 50, 70])
        risk['high'] = fuzz.trimf(risk.universe, [50, 75, 90])
        risk['critical'] = fuzz.trimf(risk.universe, [80, 100, 100])

        # --- 3. กำหนดกฎ (Rules) ---
        rules = [
            ctrl.Rule(ai_conf['high'] & code_ent['high'], risk['critical']),
            ctrl.Rule(ai_conf['high'] & code_ent['suspicious'], risk['critical']), 
            ctrl.Rule(ai_conf['high'] & code_ent['normal'], risk['high']),
            ctrl.Rule(ai_conf['medium'] & code_ent['high'], risk['high']),
            ctrl.Rule(ai_conf['medium'] & code_ent['suspicious'], risk['warning']),
            ctrl.Rule(ai_conf['medium'] & code_ent['normal'], risk['warning']),
            ctrl.Rule(ai_conf['low'] & code_ent['high'], risk['warning']),
            ctrl.Rule(ai_conf['low'] & code_ent['suspicious'], risk['safe']),
            ctrl.Rule(ai_conf['low'] & code_ent['normal'], risk['safe']),
        ]

        # --- 4. ประมวลผล ---
        risk_ctrl = ctrl.ControlSystem(rules)
        risk_sim = ctrl.ControlSystemSimulation(risk_ctrl)
        
        # ใส่ค่า Input
        risk_sim.input['ai_conf'] = float(ai_prob)
        risk_sim.input['code_ent'] = float(entropy)
        
        # คำนวณ
        risk_sim.compute()
        final_score = risk_sim.output['risk']

    except Exception as e:
        print(f"⚠️ Fuzzy Error: {e}")
        # กรณี Error ให้คำนวณแบบ Manual
        final_score = (ai_prob * 0.7 + (min(entropy/8, 1) * 0.3)) * 100

    # แปลง Score เป็น Severity (String)
    severity = "Low"
    if final_score >= 80: severity = "Critical"
    elif final_score >= 60: severity = "High" 
    elif final_score >= 40: severity = "Medium"
    
    prob_label, entropy_label = discretize_data(ai_prob, entropy)

    # ส่งคืนค่าทั้งหมด 4 ค่า กลับไปให้ไฟล์หลัก (App)
    return round(final_score, 2), severity, prob_label, entropy_label