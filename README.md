# coding_vul_detect

**Code Vulnerability Detection System**

## 📂 โครงสร้างโปรเจกต์

```text
code_vul_detect/
├── app.py                 # ไฟล์หลักสำหรับรัน Gradio Interface
├── requirements.txt       # รายชื่อไลบรารีที่ต้องติดตั้ง
├── core/                  # โมดูลหลักสำหรับการประมวลผล
│   ├── scanner.py
│   ├── analyzers.py
│   ├── remediator.py
│   ├── fuzzy_logic.py
│   └── data_loader.py
├── data/                  # โฟลเดอร์เก็บ Dataset
└── README.md              
```

## ติดตั้ง Library ที่จำเป็น

``` text
pip install -r requirements.txt
```
## เตรียมข้อมูล (Data Setup)

นำไฟล์ diversevul_20230702.json ไปวางไว้ในโฟลเดอร์ data/

## รันโปรแกรม

``` text
python app.py
```



