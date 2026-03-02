"""
ui/tab_knowledge.py — Knowledge Base tab
"""

import gradio as gr
import pandas as pd


def build_knowledge_tab(df_dataset: pd.DataFrame, dataset_path: str):
    with gr.TabItem("Knowledge Base (DiverseVul)"):
        gr.HTML('<div class="section-heading">Training Dataset Preview</div>')
        gr.Markdown("Sample entries from the **DiverseVul Dataset** — first 100 rows displayed.")

        if not df_dataset.empty:
            display_cols = ['project', 'Label', 'cwe', 'message', 'func']
            final_cols   = [c for c in display_cols if c in df_dataset.columns]
            gr.Dataframe(
                value=df_dataset[final_cols],
                label="Dataset Samples",
                interactive=False,
                wrap=True,
                elem_classes="knowledge-table"
)
        else:
            gr.Warning(f"ไม่พบข้อมูลใน {dataset_path} หรืออ่านไฟล์ไม่สำเร็จ")