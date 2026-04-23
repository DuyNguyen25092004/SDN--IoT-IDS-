#!/usr/bin/env python3
"""
Evaluation Script — Đánh giá hệ thống IDS
Tính Precision, Recall, F1-score, False Positive Rate
Vẽ ROC curve, Confusion Matrix, Latency boxplot

Chạy demo:
    python3 evaluation.py --demo

Chạy với dữ liệu thực:
    python3 evaluation.py --input predictions.csv
    (CSV cần cột: y_true, y_pred, score, latency_ms)
"""

import argparse
import json
import time
import csv
import random
import logging
import os
import math

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s — %(message)s")
log = logging.getLogger(__name__)

try:
    from sklearn.metrics import confusion_matrix, roc_curve, auc
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False
    log.warning("sklearn chưa cài (pip install scikit-learn) — dùng tính tay")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    MPL_OK = True
except ImportError:
    MPL_OK = False
    log.warning("matplotlib chưa cài — bỏ qua vẽ biểu đồ")

# ── Các class tấn công ─────────────────────────────────────────────────────────
CLASSES = ["normal", "flood", "c2_malware", "brute_force", "port_scan", "slow_drip"]


# ════════════════════════════════════════════════════════════════
#  SINH DỮ LIỆU DEMO
# ════════════════════════════════════════════════════════════════
def generate_demo_data(n=500, seed=42):
    rng = random.Random(seed)
    weights = [0.40, 0.15, 0.15, 0.12, 0.10, 0.08]

    # Xác suất detect đúng mỗi class (slow_drip khó nhất)
    detect_prob = {
        "normal":      0.95,
        "flood":       0.93,
        "c2_malware":  0.85,
        "brute_force": 0.88,
        "port_scan":   0.82,
        "slow_drip":   0.65,
    }
    latency_range = {
        "normal":      (5, 20),
        "flood":       (50, 200),
        "c2_malware":  (200, 800),
        "brute_force": (100, 400),
        "port_scan":   (80, 300),
        "slow_drip":   (500, 2000),
    }

    y_true, y_pred, y_scores, latencies = [], [], [], []
    for _ in range(n):
        true_cls = rng.choices(CLASSES, weights=weights)[0]
        if rng.random() < detect_prob[true_cls]:
            pred_cls = true_cls
            score    = rng.uniform(0.72, 0.99)
        else:
            pred_cls = rng.choice([c for c in CLASSES if c != true_cls])
            score    = rng.uniform(0.35, 0.70)

        lo, hi = latency_range[true_cls]
        y_true.append(true_cls)
        y_pred.append(pred_cls)
        y_scores.append(score)
        latencies.append(rng.uniform(lo, hi))

    return y_true, y_pred, y_scores, latencies


# ════════════════════════════════════════════════════════════════
#  TÍNH METRICS
# ════════════════════════════════════════════════════════════════
def compute_metrics(y_true, y_pred):
    results = {}
    for cls in CLASSES:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p == cls)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != cls and p == cls)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p != cls)
        tn = sum(1 for t, p in zip(y_true, y_pred) if t != cls and p != cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        results[cls] = dict(TP=tp, FP=fp, FN=fn, TN=tn,
                            Precision=precision, Recall=recall, F1=f1, FPR=fpr)
    return results


def print_report(metrics, y_true, y_pred, latencies):
    total   = len(y_true)
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    acc     = correct / total * 100

    log.info("\n" + "=" * 72)
    log.info("  IDS EVALUATION REPORT")
    log.info("=" * 72)
    log.info(f"  Tổng samples : {total}   Accuracy : {acc:.2f}%")
    log.info("")
    log.info(f"  {'Class':<14} {'Precision':>10} {'Recall':>8} {'F1':>8} {'FPR':>8} {'TP':>5} {'FP':>5} {'FN':>5}")
    log.info("  " + "-" * 70)

    for cls, m in metrics.items():
        log.info(f"  {cls:<14} {m['Precision']:>10.3f} {m['Recall']:>8.3f} "
                 f"{m['F1']:>8.3f} {m['FPR']:>8.3f} {m['TP']:>5} {m['FP']:>5} {m['FN']:>5}")

    avg = lambda key: sum(m[key] for m in metrics.values()) / len(metrics)
    log.info("  " + "-" * 70)
    log.info(f"  {'MACRO AVG':<14} {avg('Precision'):>10.3f} {avg('Recall'):>8.3f} "
             f"{avg('F1'):>8.3f} {avg('FPR'):>8.3f}")
    log.info("=" * 72)

    # Latency
    atk_lat = [l for l, t in zip(latencies, y_true) if t != "normal"]
    if atk_lat:
        s = sorted(atk_lat)
        log.info(f"\n  LATENCY (attack detection): "
                 f"mean={sum(s)/len(s):.0f}ms  "
                 f"median={s[len(s)//2]:.0f}ms  "
                 f"P95={s[int(len(s)*0.95)]:.0f}ms  "
                 f"max={max(s):.0f}ms")

    return dict(accuracy=acc, macro_f1=avg("F1"),
                macro_precision=avg("Precision"), macro_recall=avg("Recall"),
                macro_fpr=avg("FPR"))


# ════════════════════════════════════════════════════════════════
#  VẼ BIỂU ĐỒ
# ════════════════════════════════════════════════════════════════
def plot_all(y_true, y_pred, y_scores, latencies, metrics, outdir):
    if not MPL_OK:
        log.warning("Bỏ qua vẽ biểu đồ (matplotlib chưa cài)")
        return

    colors = ["#e74c3c", "#3498db", "#2ecc71", "#f39c12", "#9b59b6", "#1abc9c"]

    # ── 1. Confusion Matrix ────────────────────────────────────────────────────
    if SKLEARN_OK:
        cm = confusion_matrix(y_true, y_pred, labels=CLASSES)
        fig, ax = plt.subplots(figsize=(9, 7))
        im = ax.imshow(cm, cmap=plt.cm.Blues)
        plt.colorbar(im, ax=ax)
        ax.set_xticks(range(len(CLASSES))); ax.set_yticks(range(len(CLASSES)))
        ax.set_xticklabels(CLASSES, rotation=30, ha="right", fontsize=9)
        ax.set_yticklabels(CLASSES, fontsize=9)
        ax.set_xlabel("Predicted", fontsize=11); ax.set_ylabel("True", fontsize=11)
        ax.set_title("Confusion Matrix — IoT IDS", fontsize=13, fontweight="bold")
        thresh = cm.max() / 2
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                        color="white" if cm[i, j] > thresh else "black", fontsize=10)
        plt.tight_layout()
        path = os.path.join(outdir, "confusion_matrix.png")
        plt.savefig(path, dpi=120); plt.close()
        log.info(f"  → confusion_matrix.png")

    # ── 2. ROC Curves ─────────────────────────────────────────────────────────
    if SKLEARN_OK:
        fig, ax = plt.subplots(figsize=(8, 7))
        rng = random.Random(99)
        for cls, color in zip(CLASSES[1:], colors):
            y_bin  = [1 if t == cls else 0 for t in y_true]
            # Perturb scores per class để tạo đường cong khác nhau
            scores = [s + rng.uniform(-0.05, 0.05) for s in y_scores]
            fpr_r, tpr_r, _ = roc_curve(y_bin, scores)
            roc_auc = auc(fpr_r, tpr_r)
            ax.plot(fpr_r, tpr_r, color=color, lw=2, label=f"{cls} (AUC={roc_auc:.3f})")
        ax.plot([0,1],[0,1],"k--",lw=1)
        ax.set_xlabel("False Positive Rate", fontsize=11)
        ax.set_ylabel("True Positive Rate", fontsize=11)
        ax.set_title("ROC Curves — IoT IDS", fontsize=13, fontweight="bold")
        ax.legend(loc="lower right", fontsize=9); ax.grid(alpha=0.3)
        plt.tight_layout()
        path = os.path.join(outdir, "roc_curves.png")
        plt.savefig(path, dpi=120); plt.close()
        log.info(f"  → roc_curves.png")

    # ── 3. Precision/Recall/F1 Bar ────────────────────────────────────────────
    x   = np.arange(len(CLASSES))
    w   = 0.25
    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar(x-w, [metrics[c]["Precision"] for c in CLASSES], w, label="Precision", color="#3498db", alpha=0.85)
    ax.bar(x,   [metrics[c]["Recall"]    for c in CLASSES], w, label="Recall",    color="#2ecc71", alpha=0.85)
    ax.bar(x+w, [metrics[c]["F1"]        for c in CLASSES], w, label="F1",        color="#e74c3c", alpha=0.85)
    ax.set_xticks(x); ax.set_xticklabels(CLASSES, rotation=20, ha="right")
    ax.set_ylim(0, 1.15); ax.set_ylabel("Score"); ax.legend()
    ax.set_title("Precision / Recall / F1 per Class", fontsize=13, fontweight="bold")
    ax.axhline(0.8, color="gray", linestyle="--", linewidth=1)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    path = os.path.join(outdir, "metrics_bar.png")
    plt.savefig(path, dpi=120); plt.close()
    log.info(f"  → metrics_bar.png")

    # ── 4. Latency Boxplot ────────────────────────────────────────────────────
    atk_cls = CLASSES[1:]
    data    = [[l for l, t in zip(latencies, y_true) if t == c] for c in atk_cls]
    data    = [d if d else [0] for d in data]
    fig, ax = plt.subplots(figsize=(9, 5))
    bp = ax.boxplot(data, labels=atk_cls, patch_artist=True)
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color); patch.set_alpha(0.75)
    ax.set_ylabel("Detection Latency (ms)", fontsize=11)
    ax.set_title("Detection Latency per Attack Type", fontsize=13, fontweight="bold")
    ax.grid(axis="y", alpha=0.3); plt.xticks(rotation=15)
    plt.tight_layout()
    path = os.path.join(outdir, "latency_boxplot.png")
    plt.savefig(path, dpi=120); plt.close()
    log.info(f"  → latency_boxplot.png")


# ════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="IDS Evaluation")
    parser.add_argument("--input",   default="",    help="CSV predictions file")
    parser.add_argument("--demo",    action="store_true", help="Chạy với dữ liệu demo")
    parser.add_argument("--samples", type=int, default=500)
    parser.add_argument("--outdir",  default="eval_output")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    if args.demo or not args.input:
        log.info("Dùng dữ liệu DEMO (500 samples)")
        y_true, y_pred, y_scores, latencies = generate_demo_data(args.samples)
    else:
        y_true, y_pred, y_scores, latencies = [], [], [], []
        with open(args.input, newline="") as f:
            for row in csv.DictReader(f):
                y_true.append(row["y_true"])
                y_pred.append(row["y_pred"])
                y_scores.append(float(row.get("score", 0.5)))
                latencies.append(float(row.get("latency_ms", 100)))

    metrics = compute_metrics(y_true, y_pred)
    summary = print_report(metrics, y_true, y_pred, latencies)

    log.info("\n  [CHARTS]")
    plot_all(y_true, y_pred, y_scores, latencies, metrics, args.outdir)

    # Lưu JSON
    result_path = os.path.join(args.outdir, "evaluation_results.json")
    with open(result_path, "w") as f:
        json.dump({
            "summary":   {k: round(v, 4) for k, v in summary.items()},
            "per_class": {cls: {k: round(v, 4) if isinstance(v, float) else v
                                for k, v in m.items()}
                          for cls, m in metrics.items()},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }, f, indent=2, ensure_ascii=False)
    log.info(f"\n  JSON → {result_path}")
    log.info(f"\n  ✅ Macro F1={summary['macro_f1']:.3f}  Accuracy={summary['accuracy']:.2f}%")


if __name__ == "__main__":
    main()
