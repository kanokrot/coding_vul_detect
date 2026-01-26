# coding_vul_detect

**Code Vulnerability Detection System**

ระบบตรวจสอบช่องโหว่ทางความปลอดภัยในซอร์สโค้ด (Source Code Vulnerability Detection) พัฒนาด้วยภาษา Python โดยใช้ข้อมูลจาก DiverseVul dataset

## โครงสร้างโปรเจกต์

```text
code_vul_detect/
├── app.py                 # ไฟล์หลักสำหรับรันโปรแกรม (Main entry point)
├── core/                  # โมดูลหลักสำหรับการประมวลผล
│   ├── scanner.py         # ส่วนสแกนโค้ด
│   ├── analyzers.py       # ส่วนวิเคราะห์หาช่องโหว่
│   ├── remediator.py      # ส่วนแนะนำวิธีการแก้ไข
│   ├── fuzzy_logic.py     # ตรรกะ Fuzzy สำหรับการตรวจจับ
│   └── data_loader.py     # ตัวจัดการข้อมูล
├── data/                  # โฟลเดอร์เก็บ Dataset (ถูก exclude จาก git)
└── README.md              # เอกสารอธิบายโปรเจกต์

