import gradio as gr
from pathlib import Path
from core.data_loader import load_vulnerability_dataset
from ui.components import HEADER_HTML, THEME_TOGGLE_HTML
from ui.tab_scanner import build_scanner_tab
from ui.tab_benchmark import build_benchmark_tab
from ui.tab_knowledge import build_knowledge_tab

# ── Config ────────────────────────────────────────────────────────────────────
DATASET_PATH = "data/diversevul_20230702.json"
CSS_PATH     = "styles.css"

# ── Load dataset — graceful fallback if file is missing ──────────────────────
# FIX: a missing/malformed dataset no longer crashes the whole app at startup.
# The knowledge tab will be empty but the scanner and benchmark still work.
try:
    df_dataset = load_vulnerability_dataset(DATASET_PATH)
    print(f"✓ Dataset loaded: {len(df_dataset)} records")
except FileNotFoundError:
    print(f"⚠️  Dataset not found at '{DATASET_PATH}' — Knowledge Base tab will be empty.")
    df_dataset = None
except Exception as e:
    print(f"⚠️  Failed to load dataset: {e} — Knowledge Base tab will be empty.")
    df_dataset = None

# ── Load CSS — graceful fallback if file is missing ──────────────────────────
# FIX: missing styles.css no longer raises FileNotFoundError at startup.
try:
    custom_css = Path(CSS_PATH).read_text(encoding="utf-8")
except FileNotFoundError:
    print(f"⚠️  '{CSS_PATH}' not found — running without custom styles.")
    custom_css = ""

# ── Build UI ──────────────────────────────────────────────────────────────────
# FIX: theme belongs on gr.Blocks(), not demo.launch() — the old try/except
# TypeError workaround was masking an API misuse.
with gr.Blocks(
    title="VulnDetect AI",
    css=custom_css,
    theme=gr.themes.Base(),
) as demo:

    with gr.Row(elem_classes="app-header"):
        gr.HTML(HEADER_HTML)
        gr.HTML(THEME_TOGGLE_HTML)

    with gr.Tabs():
        build_scanner_tab()
        build_benchmark_tab()
        build_knowledge_tab(df_dataset, DATASET_PATH)

# ── Launch ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    demo.launch(
        # FIX: bind to all interfaces so the app works in Docker / cloud deployments.
        # Change to server_name="127.0.0.1" to restrict to localhost only.
        server_name="0.0.0.0",
        server_port=7860,
        show_error=True,
    )