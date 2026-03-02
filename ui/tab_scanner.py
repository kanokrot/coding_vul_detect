"""
ui/tab_scanner.py — Scanner Engine tab
"""

import gradio as gr
from core.scanner import hybrid_scanning_system


def build_scanner_tab():
    with gr.TabItem("Scanner Engine"):
        with gr.Row(equal_height=False):

            # ── Left: Input ────────────────────────────
            with gr.Column(scale=1, min_width=320):
                gr.HTML('<div class="section-heading">Input Source</div>')

                with gr.Tabs():
                    with gr.TabItem("Upload File"):
                        file_input = gr.File(
                            label="Source Code (.c  .cpp  .zip)",
                            file_count="single",
                            file_types=[".c", ".cpp", ".h", ".hpp", ".zip"]
                        )
                    with gr.TabItem("Git Repo"):
                        url_input = gr.Textbox(
                            label="Git URL",
                            placeholder="https://github.com/..."
                        )

                scan_btn = gr.Button("⬡  Start Scanning", variant="primary", size="lg")

                with gr.Accordion("System Status", open=False):
                    gr.Markdown(
                        "- **Model:** `CodeLlama-7b-hf`\n"
                        "- **Device:** `cuda:0`\n"
                        "- **Entropy Threshold:** `4.5`"
                    )

            # ── Right: Output ──────────────────────────
            with gr.Column(scale=2):
                gr.HTML('<div class="section-heading">Analysis Result</div>')

                status_output = gr.Markdown(
                    "Waiting for input...",
                    elem_classes="status-box"
                )
                table_output = gr.Dataframe(
                    headers=["Filename", "Type", "AI Prob.", "Entropy", "Risk Score", "Severity"],
                    datatype=["str", "str", "str", "str", "number", "str"],
                    label="Detected Issues"
                )

                gr.HTML('<div class="section-heading" style="margin-top:8px;">Remediation</div>')

                remediation_output = gr.Markdown(
                    "Remediation advice will appear here.",
                    elem_classes="remediation-box"
                )

        # ── Events ────────────────────────────────────
        scan_btn.click(
            fn=hybrid_scanning_system,
            inputs=[file_input, url_input],
            outputs=[status_output, table_output, remediation_output]
        )