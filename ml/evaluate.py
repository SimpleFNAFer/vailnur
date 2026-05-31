"""
Evaluate saved CSRF detector models and print metrics + timing.
Run from project root: python ml/evaluate.py
"""

import os
import time
import pickle
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report, roc_auc_score, accuracy_score,
    precision_score, recall_score, f1_score, confusion_matrix,
)
import tensorflow as tf
from tensorflow import keras

ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS = os.path.join(ROOT, "ml", "saved_models")

DATASET_PATHS = {
    "mitch":     os.path.join(ROOT, "assets", "mitch",     "dataset", "features_matrix.csv"),
    "dwvm":      os.path.join(ROOT, "assets", "dwvm",      "features_matrix.csv"),
    "hackerone": os.path.join(ROOT, "assets", "hackerone", "features_matrix.csv"),
}

FEATURE_COLS = [
    "numOfParams", "numOfBools", "numOfIds", "numOfBlobs", "reqLen",
    "createInPath",    "createInParams",
    "addInPath",       "addInParams",
    "setInPath",       "setInParams",
    "deleteInPath",    "deleteInParams",
    "updateInPath",    "updateInParams",
    "removeInPath",    "removeInParams",
    "friendInPath",    "friendInParams",
    "settingInPath",   "settingInParams",
    "passwordInPath",  "passwordInParams",
    "tokenInPath",     "tokenInParams",
    "changeInPath",    "changeInParams",
    "actionInPath",    "actionInParams",
    "payInPath",       "payInParams",
    "loginInPath",     "loginInParams",
    "logoutInPath",    "logoutInParams",
    "postInPath",      "postInParams",
    "commentInPath",   "commentInParams",
    "followInPath",    "followInParams",
    "subscribeInPath", "subscribeInParams",
    "signInPath",      "signInParams",
    "viewInPath",      "viewInParams",
    "isPUT", "isDELETE", "isPOST", "isGET", "isOPTIONS",
]


def load_csv(path):
    df = pd.read_csv(path)
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = (df["flag"] == "y").astype(np.int32).values
    return X, y


def load_models():
    def pkl(name):
        with open(os.path.join(MODELS, name), "rb") as f:
            return pickle.load(f)
    b_mitch = pkl("branch_mitch.pkl")
    b_dwvm  = pkl("branch_dwvm.pkl")
    b_h1    = pkl("branch_hackerone.pkl")
    meta    = keras.models.load_model(os.path.join(MODELS, "meta_classifier.keras"))
    return b_mitch, b_dwvm, b_h1, meta


def measure_branch(branch, X, name):
    """Evaluate one GBT branch: metrics + per-sample timing."""
    t0 = time.perf_counter()
    proba = branch.predict_proba(X)[:, 1]
    t1 = time.perf_counter()
    pred = (proba >= 0.5).astype(int)
    elapsed_ms = (t1 - t0) * 1000
    return proba, pred, elapsed_ms


def measure_meta(meta, X_meta):
    """Evaluate meta-classifier timing."""
    t0 = time.perf_counter()
    proba = meta.predict(X_meta, verbose=0).flatten()
    t1 = time.perf_counter()
    pred = (proba >= 0.5).astype(int)
    elapsed_ms = (t1 - t0) * 1000
    return proba, pred, elapsed_ms


def fmt_metrics(y_true, y_pred, y_proba, elapsed_ms, n_samples):
    auc  = roc_auc_score(y_true, y_proba)
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    ms_per = elapsed_ms / n_samples
    return dict(auc=auc, acc=acc, precision=prec, recall=rec, f1=f1,
                tp=int(tp), fp=int(fp), tn=int(tn), fn=int(fn),
                total_ms=elapsed_ms, ms_per_sample=ms_per)


def single_sample_timing(branch_mitch, branch_dwvm, branch_h1, meta, n=200):
    """Measure latency for a single inference (average over n calls)."""
    sample = np.zeros((1, 52), dtype=np.float32)
    # warm-up
    for _ in range(10):
        p1 = branch_mitch.predict_proba(sample)[0, 1]
        p2 = branch_dwvm.predict_proba(sample)[0, 1]
        p3 = branch_h1.predict_proba(sample)[0, 1]
        meta.predict(np.array([[p1, p2, p3]], dtype=np.float32), verbose=0)

    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        p1 = branch_mitch.predict_proba(sample)[0, 1]
        p2 = branch_dwvm.predict_proba(sample)[0, 1]
        p3 = branch_h1.predict_proba(sample)[0, 1]
        meta.predict(np.array([[p1, p2, p3]], dtype=np.float32), verbose=0)
        times.append((time.perf_counter() - t0) * 1000)

    return np.mean(times), np.median(times), np.percentile(times, 95)


def main():
    print("Loading datasets...")
    X_mitch, y_mitch = load_csv(DATASET_PATHS["mitch"])
    X_dwvm,  y_dwvm  = load_csv(DATASET_PATHS["dwvm"])
    X_h1,    y_h1    = load_csv(DATASET_PATHS["hackerone"])

    print("Loading models...")
    b_mitch, b_dwvm, b_h1, meta = load_models()

    print("\n" + "="*60)
    print("BRANCH METRICS (evaluated on own dataset)")
    print("="*60)

    branches = [
        ("mitch",     b_mitch, X_mitch, y_mitch),
        ("dwvm",      b_dwvm,  X_dwvm,  y_dwvm),
        ("hackerone", b_h1,    X_h1,    y_h1),
    ]

    branch_results = {}
    for name, branch, X, y in branches:
        proba, pred, ms = measure_branch(branch, X, name)
        m = fmt_metrics(y, pred, proba, ms, len(y))
        branch_results[name] = (proba, y)
        print(f"\n[{name}]  n={len(y)}")
        print(f"  AUC:       {m['auc']:.4f}")
        print(f"  Accuracy:  {m['acc']:.4f}")
        print(f"  Precision: {m['precision']:.4f}")
        print(f"  Recall:    {m['recall']:.4f}")
        print(f"  F1:        {m['f1']:.4f}")
        print(f"  TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
        print(f"  Total: {m['total_ms']:.1f} ms  |  {m['ms_per_sample']:.4f} ms/sample")

    print("\n" + "="*60)
    print("META-CLASSIFIER METRICS (all datasets combined)")
    print("="*60)

    # Build full meta input: each branch on all three datasets
    def proba(b, X): return b.predict_proba(X)[:, 1].astype(np.float32)

    p_mitch_col = np.concatenate([
        branch_results["mitch"][0],
        proba(b_mitch, X_dwvm),
        proba(b_mitch, X_h1),
    ])
    p_dwvm_col = np.concatenate([
        proba(b_dwvm, X_mitch),
        branch_results["dwvm"][0],
        proba(b_dwvm, X_h1),
    ])
    p_h1_col = np.concatenate([
        proba(b_h1, X_mitch),
        proba(b_h1, X_dwvm),
        branch_results["hackerone"][0],
    ])
    X_meta = np.stack([p_mitch_col, p_dwvm_col, p_h1_col], axis=1)
    y_all  = np.concatenate([y_mitch, y_dwvm, y_h1])

    meta_proba, meta_pred, meta_ms = measure_meta(meta, X_meta)
    mm = fmt_metrics(y_all, meta_pred, meta_proba, meta_ms, len(y_all))

    print(f"\n[meta]  n={len(y_all)}")
    print(f"  AUC:       {mm['auc']:.4f}")
    print(f"  Accuracy:  {mm['acc']:.4f}")
    print(f"  Precision: {mm['precision']:.4f}")
    print(f"  Recall:    {mm['recall']:.4f}")
    print(f"  F1:        {mm['f1']:.4f}")
    print(f"  TP={mm['tp']}  FP={mm['fp']}  TN={mm['tn']}  FN={mm['fn']}")
    print(f"  Total: {mm['total_ms']:.1f} ms  |  {mm['ms_per_sample']:.4f} ms/sample")
    print(classification_report(y_all, meta_pred, target_names=["safe", "csrf"]))

    print("\n" + "="*60)
    print("SINGLE-SAMPLE END-TO-END LATENCY (n=200 calls)")
    print("="*60)
    mean_ms, median_ms, p95_ms = single_sample_timing(b_mitch, b_dwvm, b_h1, meta)
    print(f"  Mean:   {mean_ms:.2f} ms")
    print(f"  Median: {median_ms:.2f} ms")
    print(f"  P95:    {p95_ms:.2f} ms")

    print("\nDone.")

    return {
        "branches": {
            name: fmt_metrics(
                branch_results[name][1],
                (branch_results[name][0] >= 0.5).astype(int),
                branch_results[name][0],
                0, len(branch_results[name][1])
            )
            for name in branch_results
        },
        "meta": mm,
        "latency": {"mean_ms": mean_ms, "median_ms": median_ms, "p95_ms": p95_ms},
    }


if __name__ == "__main__":
    main()
