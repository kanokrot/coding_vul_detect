
def format_metric_card(label, value, unit="%", color="cyan") -> str:
    colors = {
        "cyan":   ("#00d4ff", "rgba(0,212,255,0.08)",  "rgba(0,212,255,0.25)"),
        "green":  ("#00ff88", "rgba(0,255,136,0.08)",  "rgba(0,255,136,0.25)"),
        "red":    ("#ff3b5c", "rgba(255,59,92,0.08)",   "rgba(255,59,92,0.25)"),
        "orange": ("#ff8c42", "rgba(255,140,66,0.08)",  "rgba(255,140,66,0.25)"),
    }
    fg, bg, border = colors.get(color, colors["cyan"])
    return f"""
    <div style="background:{bg};border:1px solid {border};border-radius:8px;
                padding:20px 16px;text-align:center;flex:1;min-width:120px;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:10px;
                    letter-spacing:0.15em;text-transform:uppercase;
                    color:{fg};opacity:0.7;margin-bottom:8px;">{label}</div>
        <div style="font-family:'Syne',sans-serif;font-size:32px;font-weight:800;
                    color:{fg};line-height:1;">{value}<span style="font-size:16px;
                    opacity:0.6;">{unit}</span></div>
    </div>"""


def build_metrics_html(m: dict) -> str:
    if not m:
        return (
            '<div style="color:#3d4460;font-family:\'JetBrains Mono\',monospace;'
            'font-size:13px;padding:20px;">No results yet.</div>'
        )
    cards = (
        format_metric_card("Accuracy",  m.get("accuracy",  0), color="cyan")   +
        format_metric_card("Precision", m.get("precision", 0), color="green")  +
        format_metric_card("Recall",    m.get("recall",    0), color="orange") +
        format_metric_card("F1-Score",  m.get("f1",        0), color="cyan")
    )
    tp, fp = m.get("tp", 0), m.get("fp", 0)
    tn, fn = m.get("tn", 0), m.get("fn", 0)
    fpr    = m.get("fpr", 0)
    confusion = f"""
    <div style="margin-top:24px;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:10px;
                    letter-spacing:0.15em;text-transform:uppercase;
                    color:#3d4460;margin-bottom:12px;">Confusion Matrix</div>
        <table style="border-collapse:collapse;width:100%;max-width:400px;
                      font-family:'JetBrains Mono',monospace;font-size:12px;">
            <tr>
                <td style="padding:8px 12px;color:#3d4460;"></td>
                <td style="padding:8px 12px;color:#00d4ff;text-align:center;
                           font-size:10px;letter-spacing:0.1em;">PRED VULN</td>
                <td style="padding:8px 12px;color:#7a8099;text-align:center;
                           font-size:10px;letter-spacing:0.1em;">PRED SAFE</td>
            </tr>
            <tr>
                <td style="padding:8px 12px;color:#ff3b5c;font-size:10px;
                           letter-spacing:0.1em;">ACTUAL VULN</td>
                <td style="padding:10px;text-align:center;background:rgba(0,255,136,0.08);
                           border:1px solid rgba(0,255,136,0.2);border-radius:4px;
                           color:#00ff88;font-size:18px;font-weight:700;">
                    TP<br><span style="font-size:22px;">{tp}</span></td>
                <td style="padding:10px;text-align:center;background:rgba(255,59,92,0.08);
                           border:1px solid rgba(255,59,92,0.2);border-radius:4px;
                           color:#ff3b5c;font-size:18px;font-weight:700;">
                    FN<br><span style="font-size:22px;">{fn}</span></td>
            </tr>
            <tr>
                <td style="padding:8px 12px;color:#00ff88;font-size:10px;
                           letter-spacing:0.1em;">ACTUAL SAFE</td>
                <td style="padding:10px;text-align:center;background:rgba(255,140,66,0.08);
                           border:1px solid rgba(255,140,66,0.2);border-radius:4px;
                           color:#ff8c42;font-size:18px;font-weight:700;">
                    FP<br><span style="font-size:22px;">{fp}</span></td>
                <td style="padding:10px;text-align:center;background:rgba(0,212,255,0.08);
                           border:1px solid rgba(0,212,255,0.2);border-radius:4px;
                           color:#00d4ff;font-size:18px;font-weight:700;">
                    TN<br><span style="font-size:22px;">{tn}</span></td>
            </tr>
        </table>
        <div style="margin-top:12px;font-family:'JetBrains Mono',monospace;
                    font-size:12px;color:#7a8099;">
            False Positive Rate: <span style="color:#ff8c42;">{fpr}%</span>
            &nbsp;·&nbsp; Higher FPR = more false alarms
        </div>
    </div>"""
    return f'<div style="display:flex;gap:12px;flex-wrap:wrap;">{cards}</div>{confusion}'


def build_cache_info_html(timestamp: str, n: int) -> str:
    if not timestamp:
        return ""
    return f"""
    <div style="font-family:'JetBrains Mono',monospace;font-size:11px;
                color:#3d4460;padding:10px 0;">
        ⬡ Last run: <span style="color:#7a8099;">{timestamp}</span>
        &nbsp;·&nbsp; Samples: <span style="color:#7a8099;">{n}</span>
    </div>"""


def build_progress_html(pct: int, msg: str) -> str:
    return f"""
    <div style="font-family:'JetBrains Mono',monospace;font-size:12px;
                color:#7a8099;margin-bottom:8px;">{msg}</div>
    <div style="background:#1e2330;border-radius:4px;height:6px;overflow:hidden;">
        <div style="background:#00d4ff;height:100%;width:{pct}%;
                    transition:width 0.3s;box-shadow:0 0 8px rgba(0,212,255,0.5);">
        </div>
    </div>"""


HEADER_HTML = """
<div>
    <div class="header-eyebrow">Static Analysis Engine v2.0</div>
    <div class="header-title">Vuln<span>Detect</span> AI</div>
    <div class="header-subtitle">C/C++ Vulnerability Detection · Code Llama + Shannon Entropy + Fuzzy Logic</div>
    <div class="header-badges">
        <span class="badge badge-cyan">⬡ CodeLlama-7b-hf</span>
        <span class="badge badge-green">⬡ cuda:0</span>
        <span class="badge badge-red">⬡ DiverseVul Dataset</span>
    </div>
</div>
"""

METRIC_GUIDE_HTML = """
<div style="margin-top:16px;padding:14px;background:#13161e;
            border:1px solid #1e2330;border-radius:6px;
            font-family:'JetBrains Mono',monospace;font-size:11px;
            color:#3d4460;line-height:1.8;">
    <div style="color:#7a8099;margin-bottom:6px;">Metric Guide</div>
    <div><span style="color:#00d4ff;">Accuracy</span> — Overall correct rate</div>
    <div><span style="color:#00ff88;">Precision</span> — Alarm accuracy</div>
    <div><span style="color:#ff8c42;">Recall</span> — Threat catch rate</div>
    <div><span style="color:#00d4ff;">F1-Score</span> — Precision × Recall balance</div>
    <div style="margin-top:6px;color:#7a8099;">Target: F1 &gt; 80%</div>
</div>
"""

THEME_TOGGLE_HTML = """
<button class="theme-toggle" onclick="
    const body = document.body;
    const isDark = body.getAttribute('data-theme') !== 'light';
    body.setAttribute('data-theme', isDark ? 'light' : 'dark');
    this.innerHTML = isDark ? '☀︎ LIGHT' : '⏾ DARK';
    localStorage.setItem('theme', isDark ? 'light' : 'dark');
" id="theme-btn">⏾ DARK</button>

<script>
    // Restore saved theme on page load
    const saved = localStorage.getItem('theme') || 'dark';
    document.body.setAttribute('data-theme', saved);
    setTimeout(() => {
        const btn = document.getElementById('theme-btn');
        if (btn) btn.innerHTML = saved === 'light' ? '☀︎ LIGHT' : '⏾ DARK';
    }, 100);
</script>
"""