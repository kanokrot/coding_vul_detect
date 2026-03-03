# VulnDetect AI 🛡️

> **C/C++ Vulnerability Detection System**  
> Powered by CodeLlama + Shannon Entropy + Fuzzy Logic + Gemini AI

---

## 📌 Overview

VulnDetect AI is a hybrid vulnerability detection system for C/C++ source code. It combines multiple analysis techniques to detect security vulnerabilities, calculate risk scores, and generate AI-powered remediation suggestions.

The system is based on the research paper:
> *"Data Discretization and Decision Boundary Data Point Analysis for Unknown Attack Detection"*  
> Shin et al., IEEE Access 2022 — applied to source code vulnerability detection using the DiverseVul dataset.

---

## ✨ Features

- 🔍 **Hybrid Scanner** — CodeLlama AI + Hard Rule Detection + Shannon Entropy Analysis
- 🧠 **Fuzzy Logic Risk Engine** — Calculates risk scores with severity levels (Low / Medium / High / Critical)
- 🤖 **AI Remediation** — Gemini 2.5 Flash generates fix suggestions for vulnerable code
- 📊 **Benchmark Evaluation** — Measures Accuracy, Precision, Recall, F1-Score against DiverseVul dataset
- 📂 **Multi-Input Support** — Upload `.c`, `.cpp`, `.h`, `.hpp`, `.zip` files or clone from GitHub
- 🌙 **Dark / Light Mode** — Toggle between themes
- 🗂️ **Knowledge Base** — Browse the DiverseVul training dataset

---

## 🏗️ Project Structure

```text
code_vul_detect/
├── app.py                      # Main entry point — Gradio UI
├── train_model.py              # Fine-tune CodeBERT on DiverseVul
├── styles.css                  # Custom UI styles (dark/light theme)
├── requirements.txt            # Python dependencies
├── .env                        # API keys (not committed to git)
│
├── core/
│   ├── analyzers.py            # Shannon Entropy + CodeLlama scanner
│   ├── fuzzy_logic.py          # Fuzzy Logic risk engine (skfuzzy)
│   ├── scanner.py              # Main scanning pipeline
│   ├── remediator.py           # Gemini AI remediation report
│   ├── benchmark.py            # Benchmark evaluation engine
│   ├── data_loader.py          # DiverseVul dataset loader
│   ├── data_processor.py       # Data discretization
│   └── git_loader.py           # GitHub repo cloner
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

- Python **3.11** (PyTorch does not support Python 3.14+)
- NVIDIA GPU with CUDA 12.1+ (recommended for training)
- [Ollama](https://ollama.com) with `codellama:7b` model
- Gemini API Key from [Google AI Studio](https://aistudio.google.com)

---

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/code_vul_detect.git
cd code_vul_detect
```

### 2. Set up Python 3.11 virtual environment
```powershell
# Windows
C:\Python311\python.exe -m venv venv311
.\venv311\Scripts\activate
```

```bash
# Linux / macOS
python3.11 -m venv venv311
source venv311/bin/activate
```

### 3. Install PyTorch with CUDA support
```powershell
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
```

### 4. Install project dependencies
```powershell
pip install -r requirements.txt
```

### 5. Set up environment variables
Create a `.env` file in the project root:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```

### 6. Download and install Ollama + CodeLlama
```powershell
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

```powershell
.\venv311\Scripts\activate
python app.py
```

Open your browser at: `http://127.0.0.1:7860`

---

## 🧪 Training CodeBERT (Optional but Recommended)

Fine-tuning CodeBERT on DiverseVul significantly improves detection accuracy (Recall: ~28% → 80%+):

```powershell
python train_model.py
```

Training takes approximately **30–45 minutes** on an NVIDIA RTX GPU.  
The trained model is saved to `models/codebert-vuln/`.

---

## 📊 Detection Pipeline

```
Input Code
    │
    ├── Hard Rule Check     → Detects unsafe functions (strcpy, gets, system...)
    │                          Returns immediately if found
    │
    ├── CodeLlama AI        → Zero-shot CWE classification
    │                          Only runs if hard rules don't trigger
    │
    ├── Shannon Entropy     → Measures code complexity
    │
    └── Fuzzy Logic Engine  → Combines AI prob + Entropy → Risk Score + Severity
                                        │
                                        └── Gemini AI → Remediation Report
```

---

## 🔍 Supported Vulnerability Types

| CWE | Description |
|-----|-------------|
| CWE-121 | Stack-based Buffer Overflow |
| CWE-242 | Use of Inherently Unsafe Function |
| CWE-416 | Use After Free |
| CWE-476 | NULL Pointer Dereference |
| CWE-190 | Integer Overflow |
| CWE-78  | OS Command Injection |
| CWE-134 | Uncontrolled Format String |
| CWE-89  | SQL Injection |

---

## 📈 Benchmark Results

Evaluated on DiverseVul dataset (balanced sampling — 50% vulnerable, 50% safe):

| Metric | Current (CodeLlama zero-shot) | Target (CodeBERT fine-tuned) |
|--------|-------------------------------|------------------------------|
| Accuracy | ~56% | 85%+ |
| Precision | ~63% | 80%+ |
| Recall | ~28% | 80%+ |
| F1-Score | ~38% | 82%+ |

---

## 🔒 Security Features

- **File size limit:** 5MB per upload
- **Zip bomb protection:** Max 50MB uncompressed
- **File count limit:** Max 20 files per zip
- **Code length limit:** 50,000 characters per file

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| UI Framework | Gradio |
| AI Model | CodeLlama-7b (via Ollama) |
| Fine-tuned Model | CodeBERT (microsoft/codebert-base) |
| Remediation AI | Google Gemini 2.5 Flash |
| Risk Engine | scikit-fuzzy (Fuzzy Logic) |
| Dataset | DiverseVul (diversevul_20230702.json) |
| Language | Python 3.11 |

---

## 📝 License

This project is for academic and research purposes.  
Based on: *Shin et al., "Data Discretization and Decision Boundary Data Point Analysis for Unknown Attack Detection", IEEE Access 2022.*

---

## 🙏 Acknowledgements

- [DiverseVul Dataset](https://github.com/wagner-group/diversevul)
- [CodeLlama by Meta](https://github.com/facebookresearch/codellama)
- [CodeBERT by Microsoft](https://github.com/microsoft/CodeBERT)
- [Google Gemini API](https://ai.google.dev)