import gradio as gr
from pathlib import Path
from core.data_loader import load_vulnerability_dataset
from ui.components import HEADER_HTML, THEME_TOGGLE_HTML
from ui.tab_scanner import build_scanner_tab
from ui.tab_benchmark import build_benchmark_tab
from ui.tab_knowledge import build_knowledge_tab

# ── Config ────────────────────────────────────────────
DATASET_PATH = "data/diversevul_20230702.json"

# ── Load data ─────────────────────────────────────────
df_dataset = load_vulnerability_dataset(DATASET_PATH)

# ── Load styles ───────────────────────────────────────
custom_css = Path("styles.css").read_text(encoding="utf-8")

# ── Build UI ──────────────────────────────────────────
with gr.Blocks(title="VulnDetect AI", css=custom_css) as demo:

    with gr.Row(elem_classes="app-header"):
        gr.HTML(HEADER_HTML)

        gr.HTML(THEME_TOGGLE_HTML)

    with gr.Tabs():
        build_scanner_tab()
        build_benchmark_tab()
        build_knowledge_tab(df_dataset, DATASET_PATH)

# ── Launch ────────────────────────────────────────────
if __name__ == "__main__":
    try:
        demo.launch(theme=gr.themes.Base())
    except TypeError:
        demo.launch()