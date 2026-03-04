import gradio as gr
import pandas as pd
from core.benchmark import run_benchmark, load_cached_results, records_to_dataframe
from ui.components import (
    build_metrics_html, build_cache_info_html,
    build_progress_html, METRIC_GUIDE_HTML
)


# ─── Callbacks ────────────────────────────────────────────────────────────────

def load_saved_benchmark():
    metrics, records, timestamp = load_cached_results()
    if not metrics:
        return (
            '<div style="color:#ff8c42;font-family:\'JetBrains Mono\',monospace;'
            'font-size:13px;padding:16px;">No saved results found. Run the benchmark first.</div>',
            pd.DataFrame(),
            ""
        )
    df   = records_to_dataframe(records)
    info = build_cache_info_html(timestamp, len(records))
    return build_metrics_html(metrics), df, info


def run_live_benchmark(n_samples: int):
    for pct, msg, metrics, records in run_benchmark(int(n_samples)):
        df = records_to_dataframe(records)
        yield build_metrics_html(metrics), build_progress_html(pct, msg), df


def on_run_click(mode, n_samples):
    if mode == "Load Saved Results":
        metrics_h, df, info = load_saved_benchmark()
        yield metrics_h, "", df, info
    else:
        for metrics_h, prog_h, df in run_live_benchmark(n_samples):
            yield metrics_h, prog_h, df, ""


def toggle_mode(mode):
    is_live = mode == "Run Live"
    return (
        gr.update(visible=is_live),
        gr.update(value="⬡  Run Benchmark" if is_live else "⬡  Load Results")
    )


# ─── Tab Builder ──────────────────────────────────────────────────────────────

def build_benchmark_tab():
    with gr.TabItem("Benchmark"):
        gr.HTML('<div class="section-heading">Model Performance Evaluation</div>')

        with gr.Row():

            # ── Left: Controls ─────────────────────────
            with gr.Column(scale=1, min_width=280):
                gr.HTML('<div class="section-heading">Mode</div>')

                mode_toggle = gr.Radio(
                    choices=["Load Saved Results", "Run Live"],
                    value="Load Saved Results",
                    label="Benchmark Mode",
                    interactive=True
                )

                with gr.Group(visible=False) as live_controls:
                    sample_slider = gr.Slider(
                        minimum=50, maximum=1000, value=100, step=50,
                        label="Number of Samples",
                        info="More samples = more accurate but slower"
                    )

                run_btn = gr.Button("⬡  Load Results", variant="primary", size="lg")
                gr.HTML(METRIC_GUIDE_HTML)

            # ── Right: Results ──────────────────────────
            with gr.Column(scale=2):
                cache_info = gr.HTML("")
                metrics_display = gr.HTML(
                    '<div style="color:#3d4460;font-family:\'JetBrains Mono\','
                    'monospace;font-size:13px;padding:20px;">Press the button to load results.</div>'
                )
                progress_display = gr.HTML("")

        gr.HTML('<div class="section-heading" style="margin-top:24px;">Per-Sample Results</div>')

        benchmark_table = gr.Dataframe(
            headers=["Project", "CWE", "Ground Truth", "Prediction",
                     "Correct", "Severity", "Risk Score", "AI Prob", "Entropy"],
            datatype=["str", "str", "str", "str", "str", "str", "number", "number", "number"],
            label="Detailed Results",
            interactive=False,
            wrap=False
        )

        # ── Events ────────────────────────────────────
        mode_toggle.change(
            fn=toggle_mode,
            inputs=[mode_toggle],
            outputs=[live_controls, run_btn]
        )

        run_btn.click(
            fn=on_run_click,
            inputs=[mode_toggle, sample_slider],
            outputs=[metrics_display, progress_display, benchmark_table, cache_info]
        )