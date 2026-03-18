import json
import os
import time
import warnings
import random
import pandas as pd

warnings.filterwarnings("ignore")

DATASET_PATH        = "data/diversevul_20230702.json"
SAVED_RESULTS_PATH  = "data/benchmark_cache.json"
SAFE_LABELS         = {"SAFE", "Safe", "safe", "LOW", "Low", "low"}


# ─── Data Loading ─────────────────────────────────────────────────────────────

def load_samples(n: int) -> list:
    """
    Load a BALANCED sample — equal vulnerable and safe.
    Fixes TN=0 caused by dataset being sorted by label.
    """
    vulnerable = []
    safe       = []
    half       = (n // 2) if n != -1 else 999999

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            label = int(entry.get("target", 0))

            if label == 1 and len(vulnerable) < half:
                vulnerable.append(entry)
            elif label == 0 and len(safe) < half:
                safe.append(entry)

            if len(vulnerable) >= half and len(safe) >= half:
                break

    samples = vulnerable + safe
    random.shuffle(samples)
    return samples

# ─── Scanner Call ──────────────────────────────────────────────────────────────

def run_scanner_on_code(code: str):
    from core.analyzers import calculate_shannon_entropy, scan_with_ai_model
    from core.fuzzy_logic import calculate_fuzzy_risk
    try:
        entropy              = calculate_shannon_entropy(code)
        ai_prob, vuln_name   = scan_with_ai_model(code)
        risk_score, severity, _, _ = calculate_fuzzy_risk(ai_prob, entropy)
        return severity, risk_score, ai_prob, entropy
    except Exception as e:
        return "SAFE", 0.0, 0.0, 0.0


def severity_to_prediction(severity: str) -> int:
    return 0 if severity in SAFE_LABELS else 1


# ─── Metrics ──────────────────────────────────────────────────────────────────

def compute_metrics(tp, fp, tn, fn) -> dict:
    precision = tp / (tp + fp)   if (tp + fp) > 0   else 0.0
    recall    = tp / (tp + fn)   if (tp + fn) > 0   else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    accuracy  = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0.0
    fpr       = fp / (fp + tn)   if (fp + tn) > 0   else 0.0
    return dict(
        precision=round(precision * 100, 2),
        recall=round(recall    * 100, 2),
        f1=round(f1        * 100, 2),
        accuracy=round(accuracy  * 100, 2),
        fpr=round(fpr       * 100, 2),
        tp=tp, fp=fp, tn=tn, fn=fn,
    )

# ─── Main Runner (yields progress updates) ────────────────────────────────────

def run_benchmark(n_samples: int = 100):
    """
    Generator — yields (progress_pct, status_msg, partial_metrics, records)
    so Gradio can update the UI in real time.
    Final yield has complete data.
    """
    if not os.path.exists(DATASET_PATH):
        yield 0, gr.Warning(f"Dataset not found: {DATASET_PATH}"), {}, []
        return

    samples    = load_samples(n_samples)
    total      = len(samples)
    tp = fp = tn = fn = 0
    records    = []
    start      = time.time()

    for i, sample in enumerate(samples, 1):
        code         = sample.get("func", "")
        ground_truth = int(sample.get("target", 0))
        project      = sample.get("project", "unknown")
        cwe          = sample.get("cwe", ["Unknown"])
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else "Unknown"

        severity, risk_score, ai_prob, entropy = run_scanner_on_code(code)
        prediction = severity_to_prediction(severity)

        if   ground_truth == 1 and prediction == 1: tp += 1
        elif ground_truth == 0 and prediction == 1: fp += 1
        elif ground_truth == 0 and prediction == 0: tn += 1
        elif ground_truth == 1 and prediction == 0: fn += 1

        records.append({
            "project":      project,
            "cwe":          cwe,
            "ground_truth": ground_truth,
            "prediction":   prediction,
            "severity":     severity,
            "risk_score":   round(risk_score, 2),
            "ai_prob":      round(float(ai_prob), 4),
            "entropy":      round(float(entropy), 4),
            "correct":      ground_truth == prediction,
        })

        if i % 5 == 0 or i == total:
            elapsed   = time.time() - start
            remaining = (elapsed / i) * (total - i)
            pct       = int(i / total * 100)
            msg       = (f"Scanning {i}/{total} — "
                         f"~{remaining:.0f}s remaining")
            yield pct, msg, compute_metrics(tp, fp, tn, fn), records

    # Save cache
    cache = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "n_samples": total,
        "metrics":   compute_metrics(tp, fp, tn, fn),
        "records":   records,
    }
    os.makedirs("data", exist_ok=True)
    with open(SAVED_RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)

    yield 100, f"✅ Done — {total} samples in {time.time()-start:.1f}s", cache["metrics"], records


# ─── Load Cache ───────────────────────────────────────────────────────────────

def load_cached_results() -> tuple[dict, list, str]:
    """Returns (metrics_dict, records_list, timestamp_str)"""
    if not os.path.exists(SAVED_RESULTS_PATH):
        return {}, [], None
    with open(SAVED_RESULTS_PATH, "r", encoding="utf-8") as f:
        cache = json.load(f)
    return cache.get("metrics", {}), cache.get("records", []), cache.get("timestamp", "")


def records_to_dataframe(records: list) -> pd.DataFrame:
    if not records:
        return pd.DataFrame()
    df = pd.DataFrame(records)
    df["ground_truth"] = df["ground_truth"].map({1: "🔴 Vulnerable", 0: "🟢 Safe"})
    df["prediction"]   = df["prediction"].map({1: "🔴 Vulnerable", 0: "🟢 Safe"})
    df["correct"]      = df["correct"].map({True: "✅", False: "❌"})
    return df[[
        "project", "cwe", "ground_truth", "prediction",
        "correct", "severity", "risk_score", "ai_prob", "entropy"
    ]]