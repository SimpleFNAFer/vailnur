"""
CSRF Vulnerability Detector — model training + inference

Architecture:
  - 3 sklearn GradientBoostingClassifier branches, each trained on its own dataset
    (mitch, dwvm, hackerone). All 52 features go into every branch.
  - 1 TensorFlow/Keras linear classifier that takes [p_mitch, p_dwvm, p_h1]
    and outputs the final CSRF probability.

Training uses stacked generalisation (out-of-fold predictions) to avoid
data leakage when fitting the meta-classifier.

Usage:
  python ml/model.py            # train + save
  python ml/model.py --infer   # load saved models and run demo inference

For crawler integration see CSRFDetector.from_request() at the bottom.
"""

import os
import sys
import argparse
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import tensorflow as tf
from tensorflow import keras

# ── Paths ─────────────────────────────────────────────────────────────────────

ROOT      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS    = os.path.join(ROOT, "assets")
MODELS    = os.path.join(ROOT, "ml", "saved_models")

DATASET_PATHS = {
    "mitch":     os.path.join(ASSETS, "mitch",     "dataset", "features_matrix.csv"),
    "dwvm":      os.path.join(ASSETS, "dwvm",      "features_matrix.csv"),
    "hackerone": os.path.join(ASSETS, "hackerone", "features_matrix.csv"),
}

# ── Feature schema (52 columns, same order as features_matrix.csv) ────────────

FEATURE_COLS = [
    # Numeric
    "numOfParams", "numOfBools", "numOfIds", "numOfBlobs", "reqLen",
    # Keyword-in-path flags
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
    # HTTP method flags
    "isPUT", "isDELETE", "isPOST", "isGET", "isOPTIONS",
]  # len == 52

# ── GBT hyperparameters ───────────────────────────────────────────────────────

GBT_PARAMS = dict(
    n_estimators=300,
    learning_rate=0.05,
    max_depth=4,
    subsample=0.8,
    min_samples_leaf=5,
    max_features="sqrt",
    random_state=42,
)

N_FOLDS = 5


# ── Data loading ──────────────────────────────────────────────────────────────

def load_csv(path: str):
    df = pd.read_csv(path)
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = (df["flag"] == "y").astype(np.int32).values
    return X, y


# ── Branch training with out-of-fold meta-features ───────────────────────────

def train_branch(name: str, X: np.ndarray, y: np.ndarray) -> tuple:
    """
    Train a GBT branch using K-fold cross-validation.

    Returns:
        final_model  — GBT trained on the full dataset (used at inference time)
        oof_proba    — out-of-fold probabilities for the stacking meta-dataset
    """
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=42)
    oof = np.zeros(len(y), dtype=np.float32)

    for fold, (tr_idx, val_idx) in enumerate(skf.split(X, y)):
        m = GradientBoostingClassifier(**GBT_PARAMS)
        m.fit(X[tr_idx], y[tr_idx])
        oof[val_idx] = m.predict_proba(X[val_idx])[:, 1]
        fold_auc = roc_auc_score(y[val_idx], oof[val_idx])
        print(f"    [{name}] fold {fold + 1}/{N_FOLDS}  AUC={fold_auc:.4f}")

    oof_auc = roc_auc_score(y, oof)
    print(f"  [{name}] OOF AUC = {oof_auc:.4f}\n")

    final = GradientBoostingClassifier(**GBT_PARAMS)
    final.fit(X, y)
    return final, oof


# ── Meta-dataset construction (stacked generalisation) ───────────────────────

def build_meta_dataset(
    X_mitch, y_mitch, oof_mitch, branch_mitch,
    X_dwvm,  y_dwvm,  oof_dwvm,  branch_dwvm,
    X_h1,    y_h1,    oof_h1,    branch_h1,
) -> tuple:
    """
    For every sample across all three datasets produce a meta-row [p1, p2, p3]:
      - When a branch predicts on its *own* training samples → use OOF (unbiased)
      - When a branch predicts on *another* dataset's samples → use the final
        model directly (also unbiased: those samples never touched that model's fit)

    The resulting meta-dataset is then used to train the TF linear classifier.
    """
    def proba(model, X):
        return model.predict_proba(X)[:, 1].astype(np.float32)

    # Column from each branch across [mitch, dwvm, h1] rows
    p_mitch_col = np.concatenate([oof_mitch,             proba(branch_mitch, X_dwvm), proba(branch_mitch, X_h1)])
    p_dwvm_col  = np.concatenate([proba(branch_dwvm, X_mitch), oof_dwvm,              proba(branch_dwvm, X_h1)])
    p_h1_col    = np.concatenate([proba(branch_h1, X_mitch),   proba(branch_h1, X_dwvm), oof_h1])

    X_meta = np.stack([p_mitch_col, p_dwvm_col, p_h1_col], axis=1)  # [N, 3]
    y_meta = np.concatenate([y_mitch, y_dwvm, y_h1]).astype(np.int32)
    return X_meta, y_meta


# ── TF linear meta-classifier ─────────────────────────────────────────────────

def build_meta_classifier() -> keras.Model:
    inp = keras.Input(shape=(3,), name="branch_probabilities")
    out = keras.layers.Dense(1, activation="sigmoid", name="csrf_output")(inp)
    model = keras.Model(inputs=inp, outputs=out, name="csrf_meta_classifier")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=5e-3),
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.AUC(name="auc")],
    )
    return model


# ── Training pipeline ─────────────────────────────────────────────────────────

def train_and_save():
    os.makedirs(MODELS, exist_ok=True)

    # 1. Load data
    print("Loading datasets...")
    X_mitch, y_mitch = load_csv(DATASET_PATHS["mitch"])
    X_dwvm,  y_dwvm  = load_csv(DATASET_PATHS["dwvm"])
    X_h1,    y_h1    = load_csv(DATASET_PATHS["hackerone"])

    for name, y in [("mitch", y_mitch), ("dwvm", y_dwvm), ("hackerone", y_h1)]:
        print(f"  {name:12s}: {len(y):5d} samples  ({y.sum()} csrf / {(~y.astype(bool)).sum()} safe)")
    print()

    # 2. Train three GBT branches
    print("Training branch: mitch")
    branch_mitch, oof_mitch = train_branch("mitch", X_mitch, y_mitch)

    print("Training branch: dwvm")
    branch_dwvm, oof_dwvm = train_branch("dwvm", X_dwvm, y_dwvm)

    print("Training branch: hackerone")
    branch_h1, oof_h1 = train_branch("hackerone", X_h1, y_h1)

    # 3. Build meta-dataset
    print("Building meta-dataset...")
    X_meta, y_meta = build_meta_dataset(
        X_mitch, y_mitch, oof_mitch, branch_mitch,
        X_dwvm,  y_dwvm,  oof_dwvm,  branch_dwvm,
        X_h1,    y_h1,    oof_h1,    branch_h1,
    )
    print(f"  Meta-dataset: {X_meta.shape}  CSRF rate: {y_meta.mean() * 100:.1f}%\n")

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_meta, y_meta, test_size=0.2, stratify=y_meta, random_state=42
    )

    # 4. Train TF linear classifier
    print("Training TF meta-classifier...")
    meta_clf = build_meta_classifier()
    meta_clf.summary()
    print()

    history = meta_clf.fit(
        X_tr.astype(np.float32), y_tr,
        validation_data=(X_val.astype(np.float32), y_val),
        epochs=200,
        batch_size=128,
        callbacks=[
            keras.callbacks.EarlyStopping(
                monitor="val_auc", patience=15,
                restore_best_weights=True, mode="max",
            ),
        ],
        verbose=1,
    )

    val_proba = meta_clf.predict(X_val.astype(np.float32), verbose=0).flatten()
    val_pred  = (val_proba >= 0.5).astype(int)
    val_auc   = roc_auc_score(y_val, val_proba)
    print(f"\nMeta-classifier — validation AUC: {val_auc:.4f}")
    print(classification_report(y_val, val_pred, target_names=["safe", "csrf"]))

    # 5. Save
    print("Saving models...")
    for fname, obj in [
        ("branch_mitch.pkl",     branch_mitch),
        ("branch_dwvm.pkl",      branch_dwvm),
        ("branch_hackerone.pkl", branch_h1),
    ]:
        with open(os.path.join(MODELS, fname), "wb") as f:
            pickle.dump(obj, f)

    meta_clf.save(os.path.join(MODELS, "meta_classifier.keras"))
    print(f"All models saved to {MODELS}/")


# ── Inference ─────────────────────────────────────────────────────────────────

class CSRFDetector:
    """
    Load trained models and classify HTTP requests.

    Typical usage from a crawler:
        detector = CSRFDetector.load()

        # From a feature dict (52 keys matching FEATURE_COLS):
        result = detector.predict(feature_dict)

        # From a raw request description (crawler integration helper):
        result = detector.from_request(method, url, params)

    Return value of predict():
        {
            "label":        "csrf" | "safe",
            "probability":  0.0–1.0,          # final output of meta-classifier
            "branch_probs": {
                "mitch":     float,            # branch 1 estimate
                "dwvm":      float,            # branch 2 estimate
                "hackerone": float,            # branch 3 estimate
            },
        }
    """

    def __init__(self, branch_mitch, branch_dwvm, branch_h1, meta_clf):
        self._branches = {
            "mitch":     branch_mitch,
            "dwvm":      branch_dwvm,
            "hackerone": branch_h1,
        }
        self._meta = meta_clf

    @classmethod
    def load(cls, models_dir: str = MODELS):
        def _pkl(name):
            with open(os.path.join(models_dir, name), "rb") as f:
                return pickle.load(f)

        b_mitch = _pkl("branch_mitch.pkl")
        b_dwvm  = _pkl("branch_dwvm.pkl")
        b_h1    = _pkl("branch_hackerone.pkl")
        meta    = keras.models.load_model(os.path.join(models_dir, "meta_classifier.keras"))
        return cls(b_mitch, b_dwvm, b_h1, meta)

    # ── Feature extraction from raw crawler data ──────────────────────────────

    @staticmethod
    def extract_features(method: str, url: str, params: dict) -> dict:
        """
        Convert a raw HTTP request to the 52-feature dict expected by predict().

        Args:
            method: "GET" | "POST" | "PUT" | "DELETE" | "OPTIONS"
            url:    full request URL string
            params: dict of {name: [value, ...]} (same format as mitch dataset)

        This mirrors the feature extraction used during dataset construction so
        that the feature distribution at inference matches the training distribution.
        """
        import re
        from urllib.parse import urlparse

        method  = method.upper()
        path    = urlparse(url).path.lower()
        all_val = " ".join(k + " " + v
                           for k, vals in params.items()
                           for v in vals).lower()

        bool_vals  = {"true", "false", "on", "off", "1", "0"}
        num_bools  = sum(1 for vals in params.values()
                         for v in vals if str(v).strip().lower() in bool_vals)
        num_ids    = sum(1 for vals in params.values()
                         for v in vals
                         if re.match(r"^\d+$", str(v).strip()) or
                            re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
                                     r"-[0-9a-f]{4}-[0-9a-f]{12}$",
                                     str(v).strip(), re.I))
        num_blobs  = sum(1 for vals in params.values()
                         for v in vals if len(str(v)) > 100)
        params_str = "&".join(f"{k}={v}"
                              for k, vals in params.items() for v in vals)
        req_len    = len(url) + len(params_str)

        kws = [
            "create", "add", "set", "delete", "update", "remove", "friend",
            "setting", "password", "token", "change", "action", "pay",
            "login", "logout", "post", "comment", "follow", "subscribe",
            "sign", "view",
        ]

        feat: dict = {
            "numOfParams": len(params),
            "numOfBools":  num_bools,
            "numOfIds":    num_ids,
            "numOfBlobs":  num_blobs,
            "reqLen":      req_len,
        }
        for kw in kws:
            feat[f"{kw}InPath"]   = int(kw in path)
            feat[f"{kw}InParams"] = int(kw in all_val)

        feat["isPUT"]     = int(method == "PUT")
        feat["isDELETE"]  = int(method == "DELETE")
        feat["isPOST"]    = int(method == "POST")
        feat["isGET"]     = int(method == "GET")
        feat["isOPTIONS"] = int(method == "OPTIONS")

        return feat

    # ── Core inference ────────────────────────────────────────────────────────

    def _vec(self, feature_dict: dict) -> np.ndarray:
        return np.array(
            [feature_dict.get(c, 0) for c in FEATURE_COLS],
            dtype=np.float32,
        ).reshape(1, -1)

    def predict(self, feature_dict: dict) -> dict:
        X = self._vec(feature_dict)
        bp = {name: float(b.predict_proba(X)[0, 1])
              for name, b in self._branches.items()}
        meta_in   = np.array([[bp["mitch"], bp["dwvm"], bp["hackerone"]]],
                              dtype=np.float32)
        final_p   = float(self._meta.predict(meta_in, verbose=0)[0, 0])
        return {
            "label":        "csrf" if final_p >= 0.5 else "safe",
            "probability":  final_p,
            "branch_probs": bp,
        }

    def from_request(self, method: str, url: str, params: dict) -> dict:
        """Convenience wrapper for crawler integration."""
        return self.predict(self.extract_features(method, url, params))

    def predict_batch(self, feature_dicts: list) -> list:
        """Classify a list of feature dicts in one forward pass."""
        X = np.array(
            [[fd.get(c, 0) for c in FEATURE_COLS] for fd in feature_dicts],
            dtype=np.float32,
        )
        bp_mat = np.stack(
            [b.predict_proba(X)[:, 1] for b in self._branches.values()],
            axis=1,
        ).astype(np.float32)
        finals = self._meta.predict(bp_mat, verbose=0).flatten()
        names  = list(self._branches.keys())
        return [
            {
                "label":        "csrf" if p >= 0.5 else "safe",
                "probability":  float(p),
                "branch_probs": {n: float(bp_mat[i, j])
                                 for j, n in enumerate(names)},
            }
            for i, p in enumerate(finals)
        ]


# ── Inference demo ────────────────────────────────────────────────────────────

def run_demo():
    print("Loading saved models...")
    detector = CSRFDetector.load()

    examples = [
        ("CSRF — password change (POST, no token)",
         "POST",
         "https://example.com/settings/password",
         {"current_password": ["<password>"], "new_password": ["<password>"],
          "confirm_password": ["<password>"]}),

        ("CSRF — follow user (POST, empty token)",
         "POST",
         "https://example.com/api/v1/follow",
         {"user_id": ["99999"], "authenticity_token": [""]}),

        ("Safe — read-only GET with ID param",
         "GET",
         "https://example.com/api/v1/posts",
         {"id": ["42"]}),

        ("Safe — OPTIONS preflight",
         "OPTIONS",
         "https://example.com/api/v1/user",
         {}),

        ("Safe — SQL injection attempt (flag=n in training data)",
         "POST",
         "https://dvwa.local/vulnerabilities/sqli/",
         {"id": ["1 OR 1=1"], "Submit": ["Submit"]}),
    ]

    print()
    for desc, method, url, params in examples:
        r = detector.from_request(method, url, params)
        bp = r["branch_probs"]
        print(f"  {desc}")
        print(f"    → {r['label'].upper():4s}  p={r['probability']:.3f}"
              f"  [mitch={bp['mitch']:.3f}  dwvm={bp['dwvm']:.3f}"
              f"  h1={bp['hackerone']:.3f}]")
        print()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSRF Detector")
    parser.add_argument("--infer", action="store_true",
                        help="Run demo inference on saved models (skip training)")
    args = parser.parse_args()

    if args.infer:
        run_demo()
    else:
        train_and_save()
        print("\n── Demo inference on freshly trained models ──")
        run_demo()
