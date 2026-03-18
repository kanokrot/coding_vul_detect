# VulnDetect AI 🛡️
### C/C++ Vulnerability Detection System
> Powered by CodeBERT + CodeLlama + Shannon Entropy + Fuzzy Logic + Gemini AI

---

## 📌 Overview

VulnDetect AI is a **Hybrid AI Ensemble** vulnerability detection system for C/C++ source code. It combines multiple analysis layers to detect security vulnerabilities, calculate risk scores, and generate AI-powered remediation suggestions automatically.

The system is based on the research paper:

> *"Data Discretization and Decision Boundary Data Point Analysis for Unknown Attack Detection"*  
> Shin et al., IEEE Access 2022 — applied to source code vulnerability detection using the DiverseVul dataset.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Hybrid Scanner** | Hard Rules → CodeBERT (Fine-tuned) → CodeLlama Ensemble |
| 🧠 **Fuzzy Logic Risk Engine** | Risk Score 0–100 with severity levels (Low / Medium / High / Critical) |
| 📊 **Data Discretization** | Converts continuous AI probability and Entropy into discrete severity levels |
| 🤖 **AI Remediation** | Gemini 2.5 Flash generates fix suggestions with secure code examples |
| 📈 **Benchmark Evaluation** | Measures Accuracy, Precision, Recall, F1-Score against DiverseVul |
| 📂 **Multi-Input Support** | Upload .c, .cpp, .h, .hpp, .zip files or clone from GitHub/GitLab/Bitbucket |
| 🔒 **Security Protection** | Rate limiting, Zip bomb protection, file size limits |
| 🌙 **Dark / Light Mode** | Toggle between themes |
| 🗂️ **Knowledge Base** | Browse the DiverseVul training dataset |

---

## 📊 Detection Pipeline

```
User Input (File / ZIP / Git URL)
        │
        ▼
Rate Limiter (Max 6 scans/min)
        │
        ▼
Backend Processing
(Unzip / Git Clone / Filter .c .cpp .h .hpp)
        │
        ▼
Layer 1: Hard Rules
(strcpy, gets, memcpy, sprintf... → CWE-242, prob=0.95)
        │
        ▼
Layer 1.5: Safe Pattern Check
(strncpy size-1, fgets, short safe code → Safe immediately)
        │
        ▼
Layer 2: CodeBERT (Fine-tuned)
(prob > 0.4 → Vulnerable | prob < 0.13 → Safe)
        │
        ▼
Layer 3: CodeLlama-7b (Uncertain cases only: 0.13–0.4)
(Semantic analysis + Weighted Ensemble 60/40)
        │
        ▼
Shannon Entropy (Code complexity score)
        │
        ▼
Fuzzy Logic Engine
(AI Prob + Entropy → Risk Score 0–100)
        │
        ▼
Data Discretization
(Low / Medium / High / Critical)
        │
        ▼
OUTPUT
Verified Vulnerabilities + CWE + Risk Score + Gemini Remediation
```

---

## 📈 Benchmark Results

Evaluated on DiverseVul dataset — **1,000 balanced samples** (500 vulnerable + 500 safe):

| Metric | CodeLlama Only (Baseline) | Proposed Hybrid Ensemble |
|---|---|---|
| Accuracy | ~56% | **85.6%** ✅ |
| Precision | ~63% | **93.2%** ✅ |
| Recall | ~28% | **76.8%** ✅ |
| F1-Score | ~38% | **84.21%** ✅ |
| False Positive Rate | ~37% | **5.6%** ✅ |

> Target: F1-Score > 80% ✅

---

## 🔍 Supported Vulnerability Types

| CWE | Description | Detected By |
|---|---|---|
| CWE-242 | Use of Inherently Unsafe Function | Hard Rules |
| CWE-121 | Stack-based Buffer Overflow | CodeBERT / CodeLlama |
| CWE-401 | Memory Leak | CodeBERT |
| CWE-416 | Use After Free | CodeBERT / CodeLlama |
| CWE-476 | NULL Pointer Dereference | CodeLlama |
| CWE-190 | Integer Overflow | CodeBERT |
| CWE-78 | OS Command Injection | Hard Rules / CodeLlama |
| CWE-89 | SQL Injection | CodeLlama |

---

## 🏗️ Project Structure

```
code_vul_detect/
├── app.py                      # Main entry point — Gradio UI
├── train_model.py              # Fine-tune CodeBERT on DiverseVul
├── requirements.txt            # Python dependencies
├── .env                        # API keys (not committed to git)
│
├── styles/                     # CSS files (split by component)
│   ├── base.css                # Fonts, variables, reset
│   ├── layout.css              # Header, tabs, inputs
│   ├── scanner.css             # Table, button, remediation
│   ├── summary_cards.css       # Severity summary cards
│   └── theme.css               # Dark/light theme toggle
│
├── core/
│   ├── analyzers.py            # CodeBERT + CodeLlama + Hard Rules
│   ├── fuzzy_logic.py          # Fuzzy Logic risk engine (skfuzzy)
│   ├── scanner.py              # Main scanning pipeline
│   ├── remediator.py           # Gemini AI remediation report
│   ├── benchmark.py            # Benchmark evaluation engine
│   ├── rate_limiter.py         # Rate limiting protection
│   ├── data_loader.py          # DiverseVul dataset loader
│   ├── data_processor.py       # Data discretization
│   └── git_loader.py           # GitHub/GitLab/Bitbucket repo cloner
│
├── ui/
│   ├── components.py           # Reusable HTML components
│   ├── tab_scanner.py          # Scanner Engine tab
│   ├── tab_benchmark.py        # Benchmark tab
│   └── tab_knowledge.py        # Knowledge Base tab
│
├── data/
│   └── diversevul_20230702.json  # DiverseVul dataset (download separately)
│
└── models/
    └── codebert-vuln/          # Fine-tuned CodeBERT model (after training)
```

---

## ⚙️ Requirements

- Python **3.11** (PyTorch does not support Python 3.13+)
- NVIDIA GPU with **CUDA 12.4+** (recommended for training)
- **Ollama** with `codellama:7b` model
- **Gemini API Key** from [Google AI Studio](https://aistudio.google.com)

---

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/kanokrot/code_vul_detect.git
cd code_vul_detect
```

### 2. Set up Python 3.11 virtual environment

**Windows:**
```powershell
C:\Python311\python.exe -m venv venv311
.\venv311\Scripts\activate
```

**macOS / Linux:**
```bash
python3.11 -m venv venv311
source venv311/bin/activate
```

### 3. Install PyTorch with CUDA support
```bash
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
```

### 4. Install project dependencies
```bash
pip install -r requirements.txt
```

### 5. Set up environment variables
Create a `.env` file in the project root:
```
GEMINI_API_KEY=your_gemini_api_key_here
```

### 6. Download and install Ollama + CodeLlama
```bash
# Install Ollama from https://ollama.com
ollama pull codellama:7b
```

### 7. Prepare the dataset
Download `diversevul_20230702.json` and place it in the `data/` folder:
```
data/diversevul_20230702.json
```

---

## ▶️ Running the App

**Windows:**
```powershell
.\venv311\Scripts\activate
python app.py
```

**macOS / Linux:**
```bash
source venv311/bin/activate
python app.py
```

Open your browser at: **http://127.0.0.1:7860**

---

## 🧪 Training CodeBERT (Optional but Recommended)

Fine-tuning CodeBERT on DiverseVul significantly improves detection accuracy:

```bash
python train_model.py
```

| Setting | Value |
|---|---|
| Dataset | DiverseVul — 5,000 samples (balanced) |
| Train / Validation | 80% / 20% (4,000 / 1,000) |
| Epochs | 5 |
| Batch Size | 4 (safe for ≤ 8GB VRAM) |
| Learning Rate | 2e-5 |
| Estimated Time | ~40 min on NVIDIA RTX GPU |

The trained model is saved to `models/codebert-vuln/`.

> ⚠️ **Backup your best model** before retraining:
> ```powershell
> # Windows
> Copy-Item -Recurse models\codebert-vuln models\codebert-vuln-backup
> 
> # macOS / Linux
> cp -r models/codebert-vuln models/codebert-vuln-backup
> ```

---

## 🔒 Security Features

| Feature | Limit |
|---|---|
| Rate Limiting | Max 6 scans/minute, 10s cooldown |
| File size limit | 5MB per upload |
| Zip bomb protection | Max 50MB uncompressed |
| File count limit | Max 20 files per ZIP |
| Code length limit | 50,000 characters per file |
| Execution protection | Uploaded code is never executed |

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| UI Framework | Gradio |
| Primary AI Model | CodeBERT (microsoft/codebert-base) Fine-tuned |
| Secondary AI Model | CodeLlama-7b (via Ollama) |
| Remediation AI | Google Gemini 2.5 Flash (fallback: Gemini 2.0 Flash Lite) |
| Risk Engine | scikit-fuzzy (Fuzzy Logic) |
| Dataset | DiverseVul (diversevul_20230702.json) |
| Language | Python 3.11 |
| GPU Acceleration | CUDA 12.4 |

---

## 📝 License

This project is for **academic and research purposes**.  
Based on: *Shin et al., "Data Discretization and Decision Boundary Data Point Analysis for Unknown Attack Detection", IEEE Access 2022.*

---

## 🙏 Acknowledgements

- [DiverseVul Dataset](https://github.com/wagner-group/diversevul) — Chen et al., RAID 2023
- [CodeBERT](https://github.com/microsoft/CodeBERT) — Microsoft Research
- [CodeLlama](https://github.com/meta-llama/codellama) — Meta AI
- [Google Gemini API](https://aistudio.google.com)
- [Ollama](https://ollama.com)