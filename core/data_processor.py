def discretize_data(ai_prob, entropy):
    """
    ฟังก์ชันสำหรับทำ Data Discretization
    แปลงค่าตัวเลข (Continuous) -> เป็นกลุ่มคำ (Categorical/Labels)
    """
    
    # 1. จัดกลุ่ม Entropy (ความซับซ้อน)
    # อิงตามกราฟ Fuzzy: Normal(<4.5), Suspicious(4.5-6.5), High(>6.5)
    entropy_label = "Normal"
    if entropy >= 6.5:
        entropy_label = "High Complexity"
    elif entropy >= 4.5:
        entropy_label = "Suspicious"
    else:
        entropy_label = "Normal"

    # 2. จัดกลุ่ม AI Confidence (ความมั่นใจ)
    # อิงตามค่า Probability: Low(<0.4), Medium(0.4-0.7), High(>0.7)
    prob_label = "Low"
    if ai_prob >= 0.7:
        prob_label = "High Confidence"
    elif ai_prob >= 0.4:
        prob_label = "Medium Confidence"
    else:
        prob_label = "Low Confidence"

    return prob_label, entropy_label