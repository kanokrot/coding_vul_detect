import gradio as gr
import os
from pathlib import Path
from core.data_loader import load_vulnerability_dataset
from ui.components import HEADER_HTML, SYSTEM_STATUS_HTML, THEME_TOGGLE_HTML
from ui.tab_scanner import build_scanner_tab
from ui.tab_benchmark import build_benchmark_tab
from ui.tab_knowledge import build_knowledge_tab

# ── Config ────────────────────────────────────────────────────────────────────
DATASET_PATH = "data/diversevul_20230702.json"
CSS_DIR      = "styles"
CSS_FILES    = [
    "base.css",
    "layout.css",
    "scanner.css",
    "summary_cards.css",
    "theme.css",
]

# ── Load dataset ──────────────────────────────────────────────────────────────
try:
    df_dataset = load_vulnerability_dataset(DATASET_PATH)
    print(f"✓ Dataset loaded: {len(df_dataset)} records")
except FileNotFoundError:
    print(f"⚠️  Dataset not found at '{DATASET_PATH}' — Knowledge Base tab will be empty.")
    df_dataset = None
except Exception as e:
    print(f"⚠️  Failed to load dataset: {e} — Knowledge Base tab will be empty.")
    df_dataset = None

# ── Load CSS ──────────────────────────────────────────────────────────────────
custom_css = ""
for css_file in CSS_FILES:
    path = os.path.join(CSS_DIR, css_file)
    try:
        custom_css += Path(path).read_text(encoding="utf-8") + "\n"
    except FileNotFoundError:
        print(f"⚠️  '{path}' not found — skipping.")

# เพิ่ม CSS สำหรับ System Status Bar ใหม่
custom_css += """
.system-status-bar {
    display: flex;
    align-items: center;
    gap: 0;
    padding: 8px 16px;
    background: rgba(0, 212, 255, 0.04);
    border: 1px solid rgba(0, 212, 255, 0.12);
    border-radius: 6px;
    margin: 10px 0 4px 0;
    flex-wrap: nowrap;
    overflow-x: auto;
    font-family: 'JetBrains Mono', monospace;
    white-space: nowrap;
}
.status-item {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 0;
    flex-shrink: 0;
}
.status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
}
.dot-cyan   { background: #00d4ff; box-shadow: 0 0 6px #00d4ff88; }
.dot-green  { background: #00ff88; box-shadow: 0 0 6px #00ff8888; }
.dot-orange { background: #ff8c42; box-shadow: 0 0 6px #ff8c4288; }
.dot-red    { background: #ff3b5c; box-shadow: 0 0 6px #ff3b5c88; }
.status-label {
    font-size: 10px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #7a82a0;
}
.status-value {
    font-size: 11px;
    color: #b0b8d0;
    margin-left: 2px;
}
.status-divider {
    width: 1px;
    height: 14px;
    background: #2e3347;
    margin: 0 14px;
    flex-shrink: 0;
}
"""

# ── Build UI ──────────────────────────────────────────────────────────────────
with gr.Blocks(
    title="VulnDetect AI",
    css=custom_css,
    theme=gr.themes.Base(),
) as demo:

    with gr.Row(elem_classes="app-header"):
        with gr.Column():
            gr.HTML(HEADER_HTML)
            gr.HTML(SYSTEM_STATUS_HTML)   # ← status bar รวมทุกอย่างอยู่ตรงนี้
        gr.HTML(THEME_TOGGLE_HTML)

    with gr.Tabs():
        build_scanner_tab()
        build_benchmark_tab()
        build_knowledge_tab(df_dataset, DATASET_PATH)

# ── Launch ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    demo.launch(
        server_name="127.0.0.1",
        server_port=7860,
        show_error=True,
    )