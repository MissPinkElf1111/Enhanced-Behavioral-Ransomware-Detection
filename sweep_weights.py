"""
sweep_weights.py

Tests different storage : memory fusion weights for the combined score.

For each weight it:
  1. makes a temporary copy of 08_evaluate_models.py with the new weights
     (the original 08 file is never changed)
  2. runs 08, 09 and 10
  3. copies the evaluation, analysis and performance folders into
     weight_sweep/storageX_memoryY/
After all runs it builds weight_sweep/weight_sweep_summary.csv and prints
the ratio with the best combined result.

HOW TO RUN
  Put this file in the same folder as the numbered scripts (01 to 10),
  open a terminal there, and run:
      py sweep_weights.py
  Optional:
      py sweep_weights.py --skip-baseline     (do not re-run 0.5 : 0.5)
      py sweep_weights.py --include-extremes  (also test 1.0:0.0 and 0.0:1.0)
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

HERE = Path(__file__).resolve().parent
SWEEP_DIR = HERE / "weight_sweep"
RESULT_FOLDERS = ["evaluation", "analysis", "performance"]


def find_script(prefix):
    matches = sorted(glob.glob(str(HERE / f"{prefix}_*.py")))
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one script starting with {prefix}_, found: {matches}")
    return Path(matches[0])


def run_script(script, log_path):
    env = dict(os.environ)
    env["MPLBACKEND"] = "Agg"  # stops chart windows from opening and blocking the run
    result = subprocess.run(
        [sys.executable, str(script)], cwd=HERE, env=env,
        capture_output=True, text=True,
    )
    log_path.write_text(result.stdout + "\n" + result.stderr, encoding="utf-8")
    if result.returncode != 0:
        print(result.stderr[-2000:])
        raise SystemExit(f"{script.name} failed. See {log_path}")


def make_weighted_copy(script_08, storage_w):
    memory_w = round(1.0 - storage_w, 1)
    text = script_08.read_text(encoding="utf-8")
    text, n1 = re.subn(r"^(STORAGE_WEIGHT\s*=\s*)[0-9.]+", rf"\g<1>{storage_w}", text, flags=re.M)
    text, n2 = re.subn(r"^(MEMORY_WEIGHT\s*=\s*)[0-9.]+", rf"\g<1>{memory_w}", text, flags=re.M)
    if n1 != 1 or n2 != 1:
        raise SystemExit("Could not find STORAGE_WEIGHT and MEMORY_WEIGHT lines in script 08.")
    tmp = HERE / "_tmp_08_weighted.py"
    tmp.write_text(text, encoding="utf-8")
    return tmp, memory_w


def validation_auc():
    """ROC-AUC of the combined score on the VALIDATION executions (no test data used)."""
    path = HERE / "evaluation" / "combined_validation_execution_scores.csv"
    try:
        frame = pd.read_csv(path)
        if frame["label"].nunique() < 2:
            return float("nan")
        return float(roc_auc_score(frame["label"], frame["combined_score"]))
    except Exception:
        return float("nan")


def collect_row(storage_w, memory_w):
    metrics = pd.read_csv(HERE / "performance" / "classification_metrics.csv")
    row = metrics.loc[metrics["method"] == "DTBAD_combined"]
    if row.empty:
        raise SystemExit("No DTBAD_combined row in classification_metrics.csv")
    row = row.iloc[0]
    return {
        "storage_weight": storage_w, "memory_weight": memory_w,
        "accuracy": row["accuracy"], "precision": row["precision"],
        "recall": row["recall"], "f1_score": row["f1_score"],
        "test_roc_auc": row["roc_auc"],
        "validation_roc_auc": validation_auc(),
        "tn": row["tn"], "fp": row["fp"], "fn": row["fn"], "tp": row["tp"],
        "threshold": row["threshold"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-baseline", action="store_true")
    parser.add_argument("--include-extremes", action="store_true")
    args = parser.parse_args()

    script_08, script_09, script_10 = find_script("08"), find_script("09"), find_script("10")

    weights = [round(w / 10, 1) for w in range(1, 10)]
    if args.skip_baseline:
        weights.remove(0.5)
    if args.include_extremes:
        weights = [0.0] + weights + [1.0]

    SWEEP_DIR.mkdir(exist_ok=True)

    # keep a copy of whatever results exist before the sweep overwrites them
    backup = SWEEP_DIR / "backup_before_sweep"
    if not backup.exists():
        backup.mkdir()
        for folder in RESULT_FOLDERS:
            if (HERE / folder).is_dir():
                shutil.copytree(HERE / folder, backup / folder)

    rows = []
    for storage_w in weights:
        tmp, memory_w = make_weighted_copy(script_08, storage_w)
        name = f"storage{storage_w}_memory{memory_w}"
        out = SWEEP_DIR / name
        out.mkdir(exist_ok=True)
        print(f"\n=== Weight {storage_w} : {memory_w} ===")

        try:
            run_script(tmp, out / "log_08.txt")
        finally:
            tmp.unlink(missing_ok=True)
        run_script(script_09, out / "log_09.txt")
        run_script(script_10, out / "log_10.txt")

        for folder in RESULT_FOLDERS:
            if (HERE / folder).is_dir():
                shutil.copytree(HERE / folder, out / folder, dirs_exist_ok=True)

        row = collect_row(storage_w, memory_w)
        rows.append(row)
        print(f"F1 {row['f1_score']:.4f} | precision {row['precision']:.4f} | "
              f"recall {row['recall']:.4f} | test AUC {row['test_roc_auc']:.4f}")

    summary = pd.DataFrame(rows).sort_values(
        ["f1_score", "test_roc_auc"], ascending=False).reset_index(drop=True)
    summary.to_csv(SWEEP_DIR / "weight_sweep_summary.csv", index=False)

    pd.set_option("display.width", 200)
    print("\n=== All ratios, best first (F1, then test ROC-AUC) ===")
    print(summary[["storage_weight", "memory_weight", "precision", "recall",
                   "f1_score", "test_roc_auc", "validation_roc_auc",
                   "fp", "fn"]].to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    top = summary["f1_score"].max()
    tied = summary[np.isclose(summary["f1_score"], top)]
    best = summary.iloc[0]
    print(f"\nBest on the test set: {best['storage_weight']} : {best['memory_weight']} "
          f"(F1 {best['f1_score']:.4f}, ROC-AUC {best['test_roc_auc']:.4f})")
    if len(tied) > 1:
        print("Tied on F1:", ", ".join(f"{a}:{b}" for a, b in
              zip(tied["storage_weight"], tied["memory_weight"])))

    valid = summary.dropna(subset=["validation_roc_auc"])
    if not valid.empty:
        vb = valid.sort_values("validation_roc_auc", ascending=False).iloc[0]
        print(f"Best on validation ROC-AUC: {vb['storage_weight']} : {vb['memory_weight']} "
              f"(validation AUC {vb['validation_roc_auc']:.4f})")
    print(f"\nEverything is saved in: {SWEEP_DIR}")


if __name__ == "__main__":
    main()
