import gradio as gr
import pandas as pd
from core.scanner import hybrid_scanning_system
from core.data_loader import load_vulnerability_dataset

# ==========================================
#CONFIGURATION
# ==========================================
DATASET_PATH = "data/diversevul_20230702.json" 

# ==========================================
#LOAD DATA
# ==========================================
df_dataset = load_vulnerability_dataset(DATASET_PATH)

# ==========================================
#UI (GRADIO)
# ==========================================
with gr.Blocks(title="VulnDetect AI") as demo:
    
    # --- 1. Header ---
    with gr.Row(variant="panel"):
        with gr.Column(scale=1):
            gr.Markdown("""
            # Hybrid Vulnerability Detection System
            **Detect C/C++ Vulnerabilities using Code Llama + Shannon Entropy + Fuzzy Logic**
            """)

    # --- 2. Main Tabs ---
    with gr.Tabs():
        
        # === Tab 1: Scanner ===
        with gr.TabItem("Scanner Engine"):
            with gr.Row():
                # Input Zone
                with gr.Column(scale=1):
                    gr.Markdown("### Input Source")
                    with gr.Tab("Upload File"):
                        file_input = gr.File(
                            label="Upload Source Code (.c, .cpp, .zip)",
                            file_count="single",
                            file_types=[".c", ".cpp", ".h", ".hpp", ".zip"]
                            )
                    with gr.Tab("Git Repo"):
                        url_input = gr.Textbox(label="Git URL", placeholder="https://github.com/...")
                    
                    scan_btn = gr.Button("Start Scanning", variant="primary", size="lg")
                    
                    with gr.Accordion("System Status", open=False):
                        gr.Markdown("- **Model:** CodeLlama-7b-hf\n- **Device:** cuda:0\n- **Entropy Threshold:** 4.5")

                # Output Zone
                with gr.Column(scale=2):
                    gr.Markdown("###Analysis Result")
                    status_output = gr.Markdown("Waiting for input...")
                    
                    # ตารางผลลัพธ์
                    table_output = gr.Dataframe(
                    headers=["Filename", "Type", "AI Conf.", "Entropy", "Risk Score", "Severity"],
                    datatype=["str", "str", "str", "str", "number", "str"], 
                    label="Detected Issues"
                    )
                    
                    remediation_output = gr.Markdown("Remediation advice will appear here.")

            # Event Trigger
            scan_btn.click(
                fn=hybrid_scanning_system,
                inputs=[file_input, url_input],
                outputs=[status_output, table_output, remediation_output]
            )

        # === Tab 2: Knowledge Base ===
        with gr.TabItem("Knowledge Base (DiverseVul)"):
            gr.Markdown(f"###Training Data Preview")
            gr.Markdown("ตัวอย่างข้อมูลจาก **DiverseVul Dataset** (โหลดมาแสดงผล 100 ตัวอย่างแรก)")
            
            if not df_dataset.empty:
                display_cols = ['project', 'Label', 'cwe', 'message', 'func']
                final_cols = [c for c in display_cols if c in df_dataset.columns]
                
                gr.Dataframe(
                    value=df_dataset[final_cols],
                    label="Dataset Samples",
                    interactive=False,
                    wrap=True
                )
            else:
                gr.Warning(f"ไม่พบข้อมูลใน {DATASET_PATH} หรืออ่านไฟล์ไม่สำเร็จ")

# --- Launch ---
if __name__ == "__main__":
    try:
        demo.launch(theme=gr.themes.Soft()) 
    except TypeError:
        demo.launch()