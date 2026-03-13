import json
import random
import torch
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from torch.utils.data import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback
)

# ── Config ────────────────────────────────────────────────────────────────────
MODEL_NAME    = "microsoft/codebert-base"
DATASET_PATH  = "data/diversevul_20230702.json"
OUTPUT_DIR    = "models/codebert-vuln"
MAX_LENGTH    = 512
EPOCHS        = 5
LEARNING_RATE = 2e-5
RANDOM_SEED   = 42

# FIX: batch size reduced to 4 as a safe default for GPUs with < 16 GB VRAM.
# CodeBERT at MAX_LENGTH=512 needs ~12–14 GB at batch=8.
# Increase back to 8 if you have a 24 GB+ card (A100, RTX 4090, etc.)
BATCH_SIZE    = 4

# FIX: max_samples defined once here — no need to pass it at the call site too
MAX_SAMPLES   = 5000


# ── Reproducibility ───────────────────────────────────────────────────────────
# FIX: seed torch and numpy in addition to sklearn's random_state so
# results are fully reproducible across runs
def set_seed(seed: int = RANDOM_SEED) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


# ── 1. Load Dataset ───────────────────────────────────────────────────────────
def load_data(path: str, max_samples: int = MAX_SAMPLES) -> list[dict]:
    """
    Load a balanced dataset from DiverseVul (JSONL format).
    Warns if the dataset cannot provide the requested class balance.
    """
    vulnerable, safe = [], []
    half             = max_samples // 2

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            code  = entry.get("func", "")
            label = int(entry.get("target", 0))

            if not code:
                continue

            if label == 1 and len(vulnerable) < half:
                vulnerable.append({"code": code, "label": 1})
            elif label == 0 and len(safe) < half:
                safe.append({"code": code, "label": 0})

            if len(vulnerable) >= half and len(safe) >= half:
                break

    # FIX: warn explicitly if we couldn't fill both classes equally
    if len(vulnerable) < half:
        print(f"⚠️  Only found {len(vulnerable)} vulnerable samples "
              f"(requested {half}) — dataset will be imbalanced.")
    if len(safe) < half:
        print(f"⚠️  Only found {len(safe)} safe samples "
              f"(requested {half}) — dataset will be imbalanced.")

    data = vulnerable + safe
    print(f"✓ Loaded {len(data)} samples — "
          f"{len(vulnerable)} vulnerable, {len(safe)} safe")
    return data


# ── 2. Dataset Class ──────────────────────────────────────────────────────────
class VulnDataset(Dataset):
    def __init__(self, samples: list[dict], tokenizer, max_length: int):
        self.samples    = samples
        self.tokenizer  = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict:
        item = self.samples[idx]
        enc  = self.tokenizer(
            item["code"],
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt"
        )
        return {
            "input_ids":      enc["input_ids"].squeeze(),
            "attention_mask": enc["attention_mask"].squeeze(),
            "labels":         torch.tensor(item["label"], dtype=torch.long)
        }


# ── 3. Metrics ────────────────────────────────────────────────────────────────
def compute_metrics(eval_pred) -> dict:
    logits, labels = eval_pred
    predictions    = np.argmax(logits, axis=-1)
    report         = classification_report(
        labels, predictions,
        target_names=["Safe", "Vulnerable"],
        output_dict=True,
        zero_division=0,    # avoid warnings when a class has no predictions
    )
    return {
        "f1":        report["Vulnerable"]["f1-score"],
        "recall":    report["Vulnerable"]["recall"],
        "precision": report["Vulnerable"]["precision"],
        "accuracy":  report["accuracy"],
    }


# ── 4. Train ──────────────────────────────────────────────────────────────────
def train() -> None:
    set_seed(RANDOM_SEED)

    # ── GPU sanity check ──────────────────────────────────────────────────────
    # FIX: warn early if VRAM looks too small for the chosen batch size,
    # rather than silently OOMing mid-epoch after hours of setup.
    if torch.cuda.is_available():
        vram_gb = torch.cuda.get_device_properties(0).total_memory / 1e9
        print(f"✓ GPU: {torch.cuda.get_device_name(0)} ({vram_gb:.1f} GB VRAM)")
        if vram_gb < 12 and BATCH_SIZE > 4:
            print(
                f"⚠️  Only {vram_gb:.1f} GB VRAM detected but BATCH_SIZE={BATCH_SIZE}. "
                "Consider reducing BATCH_SIZE to 4 or enabling gradient_checkpointing."
            )
    else:
        print("⚠️  No GPU detected — training on CPU will be very slow.")

    print("Loading dataset...")
    # FIX: removed redundant max_samples=5000 at call site — uses module constant
    data = load_data(DATASET_PATH)

    train_data, val_data = train_test_split(
        data,
        test_size=0.2,
        random_state=RANDOM_SEED,
        stratify=[d["label"] for d in data]
    )
    print(f"Train: {len(train_data)} | Val: {len(val_data)}")

    print(f"Loading tokenizer: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    train_dataset = VulnDataset(train_data, tokenizer, MAX_LENGTH)
    val_dataset   = VulnDataset(val_data,   tokenizer, MAX_LENGTH)

    print("Loading model...")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME, num_labels=2
    )

    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        learning_rate=LEARNING_RATE,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        # FIX: optimise for f1 instead of raw recall — prevents the model
        # from learning to flag everything as vulnerable to maximise recall
        # at the cost of precision. Recall is still tracked in metrics.
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_steps=50,
        warmup_ratio=0.1,
        weight_decay=0.01,
        seed=RANDOM_SEED,
        fp16=torch.cuda.is_available(),
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)]
    )

    print("Training...")
    trainer.train()

    print(f"✓ Saving model to {OUTPUT_DIR}")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print("✓ Done!")


if __name__ == "__main__":
    train()