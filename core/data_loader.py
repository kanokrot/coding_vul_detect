import pandas as pd
import json
import os

def load_vulnerability_dataset(filepath):
    if not os.path.exists(filepath):
        print(f"ไม่พบไฟล์: {filepath}")
        return pd.DataFrame()

    data_list = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            count = 0  # ตัวนับจำนวนแถว
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    data_list.append(entry)
                    
                    count += 1
                    if count >= 100:  #หยุดเมื่อครบ 100 แถว
                        break
        
        # สร้าง DataFrame จาก list ที่เราตัดมาแล้ว
        df = pd.DataFrame(data_list)

        # ถ้าไม่มีข้อมูลเลย ให้ return ว่าง
        if df.empty:
            return pd.DataFrame()

        # เลือกเฉพาะ Column ที่เราจะใช้โชว์
        if 'cwe' in df.columns:
            # ตรวจสอบว่าเป็น list หรือไม่ ก่อนแก้
            df['cwe'] = df['cwe'].apply(lambda x: x if isinstance(x, list) and x else ["Unknown"])

        # แปลง target 1/0 เป็นข้อความให้อ่านง่าย
        if 'target' in df.columns:
            df['Label'] = df['target'].map({1: "🔴 Vulnerable", 0: "🟢 Safe"})

        return df

    except Exception as e:
        print(f"Error loading data: {e}")
        return pd.DataFrame()