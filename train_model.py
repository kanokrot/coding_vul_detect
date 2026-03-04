import json
import torch
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
from torch.utils.data import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback
)

# ── Config ─────────────────────────────────────────
MODEL_NAME    = "microsoft/codebert-base"
DATASET_PATH  = "data/diversevul_20230702.json"
OUTPUT_DIR    = "models/codebert-vuln"
MAX_LENGTH    = 512
BATCH_SIZE    = 4
EPOCHS        = 10
LEARNING_RATE = 1e-5


# ── 1. Load Dataset ────────────────────────────────
def load_data(path: str, max_samples: int = 10000):
    """Load balanced dataset from DiverseVul."""
    vulnerable, safe = [], []

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

            if label == 1 and len(vulnerable) < max_samples // 2:
                vulnerable.append({"code": code, "label": 1})
            elif label == 0 and len(safe) < max_samples // 2:
                safe.append({"code": code, "label": 0})

            if len(vulnerable) >= max_samples // 2 and \
               len(safe) >= max_samples // 2:
                break

    data = vulnerable + safe
    print(f"Loaded {len(data)} samples — "
          f"{len(vulnerable)} vulnerable, {len(safe)} safe")
    return data


# ── 2. Dataset Class ───────────────────────────────
class VulnDataset(Dataset):
    def __init__(self, samples, tokenizer, max_length):
        self.samples    = samples
        self.tokenizer  = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        item  = self.samples[idx]
        enc   = self.tokenizer(
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


# ── 3. Metrics ─────────────────────────────────────
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions    = np.argmax(logits, axis=-1)
    report         = classification_report(
        labels, predictions,
        target_names=["Safe", "Vulnerable"],
        output_dict=True
    )
    return {
        "f1":        report["Vulnerable"]["f1-score"],
        "recall":    report["Vulnerable"]["recall"],
        "precision": report["Vulnerable"]["precision"],
        "accuracy":  report["accuracy"],
    }


# ── 4. Train ───────────────────────────────────────
def train():
    print("Loading dataset...")
    data = load_data(DATASET_PATH, max_samples=10000)

    train_data, val_data = train_test_split(
        data, test_size=0.2, random_state=42,
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
    metric_for_best_model="recall",
    greater_is_better=True,
    logging_steps=50,
    warmup_ratio=0.1,
    weight_decay=0.01,
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

    print(f"Saving model to {OUTPUT_DIR}")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print("Done!")


if __name__ == "__main__":
    train()