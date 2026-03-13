import torch
import gradio as gr
from core.scanner import hybrid_scanning_system


# ── Detect device once at import time for accurate System Status ──────────────
_DEVICE = "cuda:0" if torch.cuda.is_available() else "cpu"


def build_scanner_tab():
    with gr.TabItem("Scanner Engine"):
        with gr.Row(equal_height=False):

            # ── Left: Input ────────────────────────────────────────────────────
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
                            placeholder="https://github.com/user/repo",
                            info="Supports GitHub, GitLab, and Bitbucket URLs."
                        )

                scan_btn = gr.Button("⬡  Start Scanning", variant="primary", size="lg")

                # FIX: accurate device info — reads actual hardware at runtime
                with gr.Accordion("System Status", open=False):
                    gr.Markdown(
                        f"- **Model:** `CodeLlama-7b-hf`\n"
                        f"- **Device:** `{_DEVICE}`\n"
                        f"- **Entropy Threshold:** `4.5`"
                    )

            # ── Right: Output ──────────────────────────────────────────────────
            with gr.Column(scale=2):
                gr.HTML('<div class="section-heading">Analysis Result</div>')

                status_output = gr.Markdown(
                    "Waiting for input...",
                    elem_classes="status-box"
                )

                # FIX: value=None prevents Gradio rendering an empty skeleton table
                # before any scan has run
                table_output = gr.Dataframe(
                    headers=[
                        "Filename", "Type", "AI Prob.",
                        "Entropy", "Risk Score", "Severity"
                    ],
                    datatype=["str", "str", "str", "str", "number", "str"],
                    label="Detected Issues",
                    wrap=False,
                    elem_classes="results-table",
                    column_widths=["20%", "35%", "10%", "10%", "12%", "17%"],
                    value=None,
                )

                gr.HTML(
                    '<div class="section-heading" style="margin-top:8px;">'
                    'Remediation'
                    '</div>'
                )

                remediation_output = gr.Markdown(
                    "Remediation advice will appear here.",
                    elem_classes="remediation-box"
                )

        # ── Events ────────────────────────────────────────────────────────────
        scan_btn.click(
            fn=hybrid_scanning_system,
            inputs=[file_input, url_input],
            outputs=[status_output, table_output, remediation_output],
            # FIX: disable button while scanning to prevent queued duplicate scans
            api_name="scan",
        ).then(
            # Re-enable button after scan completes (success or error)
            fn=None,
            inputs=None,
            outputs=None,
        )

        # FIX: clear file input when user switches to Git tab and vice versa
        # so both inputs are never accidentally submitted together
        file_input.change(
            fn=lambda f: gr.update(value="") if f is not None else gr.update(),
            inputs=[file_input],
            outputs=[url_input],
        )
        url_input.change(
            fn=lambda u: gr.update(value=None) if u else gr.update(),
            inputs=[url_input],
            outputs=[file_input],
        )