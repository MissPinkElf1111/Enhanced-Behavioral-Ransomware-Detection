"""
External DTBAD evaluation of single or multiple executions.

Input:
    test_dataset/ata_read.csv ... mem_exec.csv     (one execution)
OR:
    test_dataset/Application_01/*.csv              (multiple executions)
    test_dataset/Application_02/*.csv

Ground-truth mode:
    GROUND_TRUTH_MODE = "prompt": ask whether actual execution(s) are
        Benign (0), Ransomware (1), or Unknown. For multiple executions,
        the user can label all together or label each separately.
    GROUND_TRUTH_MODE = "automatic": read test_dataset/labels.csv first,
        then infer labels from Benign_*/Ransomware_* folder names.
"""

from pathlib import Path
import csv
import importlib.util
import json
import shutil

import joblib
import numpy as np
import pandas as pd

# Configuration
BASE = Path(__file__).resolve().parent
RAW = BASE / "external_dataset"
OUT = BASE / "external_evaluation"
PREP = OUT / "prepared"
FEATURES = OUT / "features"
PRED = OUT / "predictions"

STEP05 = BASE / "05_feature_engineering.py"
STEP08 = BASE / "08_evaluate_models.py"
MODELS = BASE / "models"
CALIBRATION = BASE / "evaluation"
PERFORMANCE = BASE / "performance"

DATASET = "External"
# "prompt" asks at runtime for both single and multiple execution layouts
# "automatic" uses labels.csv or folder-name prefixes; unknown if absent
GROUND_TRUTH_MODE = "prompt"  # "prompt" or "automatic"
CHUNK_SIZE = 100_000

# Feature-drift diagnostics: top features for each execution and modality
FEATURE_DRIFT_TOP_N = 5

STORAGE_WEIGHT = 0.50
MEMORY_WEIGHT = 0.50

# Experimental, conservative decision policy. Set to "original" to restore the single-threshold DTBAD prediction
FP_REDUCTION_POLICY = "dual_confirmation"  # "dual_confirmation" or "original"

REQUIRED = {
    "ata_read.csv": ["UNIX time in sec", "UNIX time in ns", "LBA", "size"],
    "ata_write.csv": ["UNIX time in sec", "UNIX time in ns", "LBA", "size", "entropy"],
    "mem_read.csv": ["UNIX time in sec", "UNIX time in ns", "GPA", "type"],
    "mem_write.csv": ["UNIX time in sec", "UNIX time in ns", "GPA", "size", "entropy", "type"],
    "mem_readwrite.csv": ["UNIX time in sec", "UNIX time in ns", "GPA", "size", "entropy", "type"],
    "mem_exec.csv": ["UNIX time in sec", "UNIX time in ns", "GPA", "type"]
}

OPERATIONS = {
    "ata_read.csv": ("storage", "read"),
    "ata_write.csv": ("storage", "write"),
    "mem_read.csv": ("memory", "read"),
    "mem_write.csv": ("memory", "write"),
    "mem_readwrite.csv": ("memory", "readwrite"),
    "mem_exec.csv": ("memory", "execute")
}

METHODS = {
    "storage_autoencoder": ("storage", "ae_mean_error"),
    "storage_temporal": ("storage", "temporal_mean_score"),
    "storage_isolation_forest": ("storage", "if_mean_score"),
    "memory_autoencoder": ("memory", "ae_mean_error"),
    "memory_temporal": ("memory", "temporal_mean_score"),
    "memory_isolation_forest": ("memory", "if_mean_score"),
    "DTBAD_combined": ("combined", "combined_score")
}

STEP05_API = ("discover_starts", "aggregate", "make_rows", "validate_output", "output_columns")

# Discover executions and ground-truth labels
def parse_label(value):
    text = str(value).strip().casefold()

    if text in ("0", "benign"):
        return 0

    if text in ("1", "ransomware"):
        return 1

    raise ValueError(f"Invalid label {value!r}; use 0/1 or Benign/Ransomware")


def load_label_map():
    path = RAW / "labels.csv"

    if not path.exists():
        return {}

    table = pd.read_csv(path, dtype=str, keep_default_na=False)

    if not {"execution_id", "label"}.issubset(table.columns):
        raise ValueError("labels.csv must have execution_id,label columns")

    labels = {}

    for row in table.itertuples(index=False):
        eid = str(row.execution_id).strip()

        if not eid or eid in labels:
            raise ValueError(f"Empty or duplicate execution_id in labels.csv: {eid!r}")

        labels[eid] = parse_label(row.label)

    return labels

def infer_label(folder_name):
    name = folder_name.casefold()

    if name == "benign" or name.startswith("benign_") or name.startswith("benign-"):
        return 0

    if name == "ransomware" or name.startswith("ransomware_") or name.startswith("ransomware-"):
        return 1

    return None

# Ask for verified ground truth; never guess from model output
def ask_label(prompt):
    while True:
        try:
            answer = input(prompt).strip().casefold()

        except EOFError as exc:
            raise RuntimeError(
                "Interactive input is unavailable. Run in a terminal/PyCharm "
                "Run console, or set GROUND_TRUTH_MODE = 'automatic' and provide test_dataset/labels.csv."
            ) from exc

        if answer in ("0", "b", "benign"):
            return 0

        if answer in ("1", "r", "ransomware"):
            return 1

        if answer in ("u", "unknown", "?"):
            return None

        print("Invalid input. Enter 0 (Benign), 1 (Ransomware), or U (Unknown).")

# Label one execution or several, with a batch or individual option
def prompt_ground_truth(executions):
    print("\nACTUAL APPLICATION TYPE (GROUND TRUTH)")
    print("Use verified labels. These answers do not change model predictions.")

    if len(executions) == 1:
        eid = executions[0]["execution_id"]
        executions[0]["label"] = ask_label(f"{eid} - actual type [0=Benign, 1=Ransomware, U=Unknown]: ")

        return

    print(f"Found {len(executions)} independent executions.")
    print("\t1. All are Benign")
    print("\t2. All are Ransomware")
    print("\t3. Enter the actual type for each execution")
    print("\t4. All are Unknown (predictions only, no evaluation metrics)")

    while True:
        try:
            choice = input("Choose [1/2/3/4]: ").strip()

        except EOFError as exc:
            raise RuntimeError(
                "Interactive input is unavailable. Set "
                "GROUND_TRUTH_MODE = 'automatic' and use labels.csv."
            ) from exc

        if choice in ("1", "2", "3", "4"):
            break

        print("Invalid input. Enter 1, 2, 3, or 4.")

    if choice == "3":
        for execution in executions:
            eid = execution["execution_id"]
            execution["label"] = ask_label(f"{eid} - actual type [0=Benign, 1=Ransomware, U=Unknown]: ")

    else:
        common_label = {"1": 0, "2": 1, "4": None}[choice]

        for execution in executions:
            execution["label"] = common_label

    print("\nGround-truth labels selected:")

    for execution in executions:
        print(f"  {execution['execution_id']}: {label_name(execution['label'])}")


def discover_executions():
    if not RAW.is_dir():
        raise FileNotFoundError(f"Missing input folder: {RAW}")

    if GROUND_TRUTH_MODE not in ("prompt", "automatic"):
        raise ValueError("GROUND_TRUTH_MODE must be 'prompt' or 'automatic'")

    root_has_raw = any((RAW / name).is_file() for name in REQUIRED)
    folders = [
        p for p in sorted(RAW.iterdir())
        if p.is_dir() and any((p / name).is_file() for name in REQUIRED)
    ]

    if root_has_raw and folders:
        raise ValueError("Use either root-level six CSVs OR execution subfolders, not both")

    if root_has_raw:
        folders = [RAW]

    if not folders:
        raise FileNotFoundError("No executions found under test_dataset/")

    executions = []
    for folder in folders:
        eid = "external_application" if folder == RAW else folder.name
        missing = [name for name in REQUIRED if not (folder / name).is_file()]

        if missing:
            raise FileNotFoundError(f"Execution {eid}: missing {', '.join(missing)}")

        executions.append({"execution_id": eid, "folder": folder, "label": None})

    if len({x["execution_id"].casefold() for x in executions}) != len(executions):
        raise ValueError("Execution folder names must be unique (case-insensitive)")

    if GROUND_TRUTH_MODE == "prompt":
        # Prompt even if a folder happens to start with Benign_ or Ransomware_
        prompt_ground_truth(executions)

    else:
        label_map = load_label_map()
        unknown = set(label_map) - {x["execution_id"] for x in executions}

        if unknown:
            raise ValueError(f"labels.csv refers to missing execution folders: {sorted(unknown)}")

        for execution in executions:
            eid = execution["execution_id"]
            folder = execution["folder"]
            inferred = None if folder == RAW else infer_label(eid)
            mapped = label_map.get(eid)

            if mapped is not None and inferred is not None and mapped != inferred:
                raise ValueError(f"Conflicting labels for {eid}: folder name vs labels.csv")

            execution["label"] = mapped if mapped is not None else inferred

    return executions

# Output helpers and script imports
def reset_outputs():
    # Only delete Step 11's dedicated generated subfolders.
    for folder in (PREP, FEATURES, PRED):
        if folder.exists():
            shutil.rmtree(folder)

        folder.mkdir(parents=True, exist_ok=True)

    for filename in ("11_cleaning_summary.csv", "11_detection_report.txt", "11_ground_truth_labels.csv"):
        (OUT / filename).unlink(missing_ok=True)

def append_csv(path, frame):
    if frame.empty:
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, mode="a", header=not path.exists(), index=False)


def import_script(path, name):
    if not path.is_file():
        raise FileNotFoundError(path)

    spec = importlib.util.spec_from_file_location(name, path)

    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot import {path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module

def load_step05():
    module = import_script(STEP05, "dtbad_step05")
    missing = [name for name in STEP05_API if not hasattr(module, name)]

    if missing:
        raise RuntimeError(
            f"{STEP05.name} is not the feature-extractor version Step 11 expects. "
            f"Missing functions: {missing}."
        )

    module.CHUNK_SIZE = CHUNK_SIZE
    print(f"Feature extractor: {STEP05.name}")

    return module


def load_resources(step08):
    step08.MODELS_DIR = MODELS
    resources = {}

    for category in ("storage", "memory"):
        path = CALIBRATION / f"{category}_calibration.joblib"

        if not path.is_file():
            raise FileNotFoundError(path)

        calibration = joblib.load(path)
        model, ae_bundle, if_bundle = step08.load_models(category)

        if "label" in ae_bundle["feature_columns"]:
            raise ValueError("Saved model must not use ground-truth label as a feature")

        resources[category] = (calibration, model, ae_bundle, if_bundle)

    return resources


def load_thresholds():
    # Prefer the filename written by the supplied Step 10 script.
    candidates = (PERFORMANCE / "10_detection_thresholds.json",
                  PERFORMANCE / "detection_thresholds.json")
    path = next((p for p in candidates if p.is_file()), None)

    if path is None:
        raise FileNotFoundError(f"Missing Step 10 detection thresholds in {PERFORMANCE}")

    methods = json.loads(path.read_text(encoding="utf-8"))["methods"]

    return methods, path

# Raw CSV parsing and cleaning, one execution at a time
def identify_columns(path, filename):
    with path.open(newline="", encoding="utf-8-sig") as handle:
        first = next((row for row in csv.reader(handle) if row), None)

    if first is None:
        return 0, 0, {}, []

    width = len(first)
    try:
        headerless = all(np.isfinite(float(x)) for x in first[:2])

    except (TypeError, ValueError):
        headerless = False

    if headerless:
        skiprows = 0

        if filename in ("mem_read.csv", "mem_exec.csv"):
            if width == 4:
                indices = (0, 1, 2, 3)

            elif width >= 6:
                indices = (0, 1, 2, 5)  # RanSMAP type field is sixth

            else:
                raise ValueError(f"{path}: ambiguous headerless layout")

        else:
            if width < len(REQUIRED[filename]):
                raise ValueError(f"{path}: too few columns")

            indices = tuple(range(len(REQUIRED[filename])))

        positions = dict(zip(REQUIRED[filename], indices))

    else:
        skiprows = 1
        lookup = {name.strip().casefold(): i for i, name in enumerate(first)}
        positions = {}

        for column in REQUIRED[filename]:
            aliases = [column.casefold()]

            if filename == "ata_write.csv" and column == "entropy":
                aliases.append("entropy #1")

            matches = [lookup[x] for x in aliases if x in lookup]

            if len(matches) != 1:
                raise ValueError(f"{path}: missing/ambiguous column {column}")

            positions[column] = matches[0]

    ignored = [first[i] if skiprows else f"column_{i+1}"
               for i in range(width) if i not in positions.values()]

    return width, skiprows, positions, ignored

def clean_execution(execution):
    eid, folder = execution["execution_id"], execution["folder"]
    prepared_folder = PREP / eid
    prepared_folder.mkdir(parents=True, exist_ok=True)
    records = []
    items = []

    for filename, required in REQUIRED.items():
        source = folder / filename
        width, skiprows, positions, ignored = identify_columns(source, filename)
        destination = prepared_folder / f"{DATASET}_{filename}"
        pd.DataFrame(columns=["source_file_id", "source_row"] + required).to_csv(destination, index=False)
        total = kept = 0

        if width:
            reader = pd.read_csv(
                source, header=None, names=[f"raw_{i}" for i in range(width)],
                skiprows=skiprows, dtype=str, chunksize=CHUNK_SIZE,
                encoding="utf-8-sig", on_bad_lines="error"
            )

            for chunk in reader:
                row_ids = np.arange(total + skiprows + 1,
                                    total + skiprows + len(chunk) + 1)
                total += len(chunk)
                clean = pd.DataFrame({
                    name: pd.to_numeric(chunk.iloc[:, index], errors="coerce")
                    for name, index in positions.items()
                })
                valid = np.isfinite(clean[required].to_numpy(dtype=float)).all(axis=1)
                clean = clean.loc[valid, required].copy()

                if clean.empty:
                    continue

                # Step 05 removes _ata_read.csv etc. to recover execution ID.
                clean.insert(0, "source_file_id", f"{eid}_{filename}")
                clean.insert(1, "source_row", row_ids[valid])
                clean.to_csv(destination, mode="a", header=False, index=False)
                kept += len(clean)

        records.append({
            "execution_id": eid, "actual_label": label_name(execution["label"]),
            "file": filename, "input_rows": total, "kept_rows": kept,
            "removed_rows": total - kept, "ignored_columns": ", ".join(ignored) or "None"
        })

        category, operation = OPERATIONS[filename]
        items.append({"path": destination, "dataset": DATASET,
                      "category": category, "operation": operation})

    for prefix in ("ata_", "mem_"):
        if sum(r["kept_rows"] for r in records if r["file"].startswith(prefix)) == 0:
            raise ValueError(f"{eid}: no valid {prefix} events; both modalities required")

    return items, records

# Feature extraction (same Step 05 definitions)
def extract_features(step05, items, execution_id):
    features = {}

    for category in ("storage", "memory"):
        starts = step05.discover_starts(items, category)

        if set(starts) != {(DATASET, execution_id)}:
            raise ValueError(f"{execution_id}: unexpected {category} execution keys: {list(starts)}")

        states, maximum = step05.aggregate(items, category, starts)
        frame = step05.make_rows(category, starts, states, maximum)
        expected = step05.STORAGE_COLUMNS if category == "storage" else step05.MEMORY_COLUMNS
        step05.validate_output(frame, expected, category)

        if frame.empty:
            raise ValueError(f"{execution_id}: no {category} feature windows")

        # Step 08's summarizer needs a label, but scoring NEVER uses it.
        frame["label"] = 0  # compatibility placeholder, not ground truth
        frame = frame.sort_values(["dataset", "execution_id", "window_start_ns"],
                                  kind="stable").reset_index(drop=True)
        operations = ("read", "write") if category == "storage" else (
            "read", "write", "readwrite", "execute"
        )

        for operation in operations:
            columns = step05.output_columns(category, operation)
            append_csv(FEATURES / f"{category}_{operation}_features.csv",
                       frame[columns].drop(columns="label", errors="ignore"))

        features[category] = frame

    return features

# Inference + optional feature-drift diagnostics
def label_name(label):
    return "Unknown" if label is None else ("Benign" if label == 0 else "Ransomware")

# Compare external features with the saved training scaler (no refitting)
def feature_drift(frame, ae_bundle, category, execution_id):
    names = list(ae_bundle["feature_columns"])
    missing = [name for name in names if name not in frame.columns]

    if missing:
        raise ValueError(f"{category}: external features missing from trained model: {missing}")

    values = frame[names].to_numpy(dtype=np.float64)
    means = np.asarray(ae_bundle["scaler_mean"], dtype=np.float64)
    scales = np.asarray(ae_bundle["scaler_scale"], dtype=np.float64)

    if values.shape[1] != len(means) or len(means) != len(scales):
        raise ValueError(f"{category}: scaler and feature dimensions differ")

    if not np.isfinite(values).all():
        raise ValueError(f"{category}: external features contain NaN or infinity")

    if not np.isfinite(means).all() or not np.isfinite(scales).all() or (scales <= 0).any():
        raise ValueError(f"{category}: invalid saved scaler parameters")

    # StandardScaler parameters are the ones Step 08 uses to score the model
    z = np.abs((values - means) / scales)

    return pd.DataFrame({
        "execution_id": execution_id,
        "modality": category,
        "feature": names,
        "external_mean": values.mean(axis=0),
        "external_min": values.min(axis=0),
        "external_max": values.max(axis=0),
        "training_mean": means,
        "training_scale": scales,
        "mean_abs_z": z.mean(axis=0),
        "max_abs_z": z.max(axis=0),
        "fraction_abs_z_gt_3": (z > 3).mean(axis=0),
    })

# Return the N largest feature deviations for each execution and modality
def top_feature_drift(drift):
    return (
        drift.sort_values(
            ["execution_id", "modality", "mean_abs_z"],
            ascending=[True, True, False],
            kind="stable",
        )
        .groupby(["execution_id", "modality"], sort=False, group_keys=False)
        .head(FEATURE_DRIFT_TOP_N)
        .reset_index(drop=True)
    )

# Print a compact per-application view of the most shifted features
def print_feature_drift_diagnostics(execution_id, drift):
    print(f"\n  FEATURE DRIFT DIAGNOSTICS: {execution_id}")
    print("  Comparing external feature values against saved training scaler.")

    for category in ("storage", "memory"):
        selected = top_feature_drift(
            drift.loc[drift["modality"] == category]
        )

        print(f"\n    {category.upper()} - TOP {len(selected)} FEATURES")

        if selected.empty:
            print("      No features available")
            continue

        columns = [
            "feature", "external_mean", "training_mean", "training_scale",
            "mean_abs_z", "fraction_abs_z_gt_3",
        ]

        print(selected[columns].to_string(
            index=False, float_format=lambda x: f"{x:.5g}"
        ))

def score_modality(step08, category, frame, resources, execution_id):
    calibration, model, ae_bundle, if_bundle = resources[category]
    step08.ROLLING_WINDOW = int(calibration["rolling_window"])

    windows = step08.calculate_window_scores(frame, model, ae_bundle, if_bundle)
    windows = step08.add_temporal_scores(windows)
    windows = step08.add_novelty_flags(windows, calibration["thresholds"])
    windows["normalized_temporal_score"] = step08.normalize_scores(
        windows["temporal_score"], calibration["normalizer"]
    )

    execution = step08.summarize_executions(windows, calibration["normalizer"])

    if len(execution) != 1 or execution.iloc[0]["execution_id"] != execution_id:
        raise ValueError(f"{execution_id}: invalid {category} execution summary")

    append_csv(PRED / f"11_{category}_window_scores.csv",
               windows.drop(columns="label", errors="ignore"))
    append_csv(PRED / f"11_{category}_execution_scores.csv",
               execution.drop(columns="label", errors="ignore"))

    return execution, feature_drift(frame, ae_bundle, category, execution_id)

# Show external scores on their saved calibration scales; do not change inference
def score_diagnostics(execution_id, summaries, resources, thresholds):
    print("\n  SCORE DIAGNOSTICS (no threshold changes)")

    rows = []

    for category in ("storage", "memory"):
        summary = summaries[category].iloc[0]
        raw = float(summary["temporal_mean_score"])
        normalized = float(summary["normalized_temporal_score"])
        threshold_info = thresholds.get(f"{category}_temporal", {})
        threshold = float(threshold_info["threshold"]) if "threshold" in threshold_info else np.nan
        normalizer = resources[category][0]["normalizer"]

        # Calibration formats can differ; never assume median/scale keys exist.
        if isinstance(normalizer, dict):
            parts = [
                f"{key}={float(value):.6g}"
                for key, value in normalizer.items()
                if isinstance(value, (int, float, np.number))
                and not isinstance(value, (bool, np.bool_))
            ]

            normalizer_details = ", ".join(parts) or f"keys={list(normalizer)}"

        else:
            normalizer_details = f"type={type(normalizer).__name__}"

        print(f"\t{category.capitalize()} raw temporal score: {raw:.6g}")
        print(f"\t{category.capitalize()} normalized score: {normalized:.6g}")
        print(f"\t{category.capitalize()} temporal threshold: {threshold:.6g}")
        print(f"\tSaved normalizer: {normalizer_details}")
        rows.append({
            "execution_id": execution_id,
            "modality": category,
            "temporal_mean_score": raw,
            "normalized_temporal_score": normalized,
            "temporal_threshold": threshold,
            "temporal_alarm": int(raw > threshold) if np.isfinite(threshold) else np.nan,
            "normalizer_details": normalizer_details
        })

    return rows


def fuse(storage, memory):
    combined = storage.merge(
        memory, on=["dataset", "execution_id"], how="inner",
        suffixes=("_storage", "_memory"), validate="one_to_one",
    )

    if len(combined) != 1:
        raise ValueError("Storage and memory execution IDs did not match")

    combined["combined_score"] = (
        STORAGE_WEIGHT * combined["normalized_temporal_score_storage"]
        + MEMORY_WEIGHT * combined["normalized_temporal_score_memory"]
    )

    return combined.drop(columns=["label_storage", "label_memory"], errors="ignore")

# Ground truth is used only AFTER the prediction is made
def classify_outcome(truth, predicted):
    if truth is None:
        return "Unlabeled"

    if truth == 1:
        return "TP" if predicted else "FN"

    return "FP" if predicted else "TN"

# Convert the model's binary prediction to a clear detection result
def detection_verdict(predicted):
    return "RANSOMWARE DETECTED" if int(predicted) == 1 else "NO RANSOMWARE DETECTED"

"""
Compare the original Step 10 DTBAD prediction against an optional,
conservative dual-confirmation policy. Neither rule reads the label.

Original: fused score > saved combined threshold.
Conservative: original AND storage temporal alarm AND memory temporal alarm.

A benign label never forces a Benign prediction. Both predictions are
saved so the change's FP/FN trade-off is auditable.
"""
def predict_execution(execution, summaries, thresholds):
    eid, truth = execution["execution_id"], execution["label"]
    combined = fuse(summaries["storage"], summaries["memory"])
    append_csv(PRED / "11_combined_execution_scores.csv", combined)
    summaries["combined"] = combined

    # Compute all original alarms first, independent of labels.
    original_alarms = {}
    scored = {}

    for method, (source, score_column) in METHODS.items():
        if method not in thresholds:
            continue

        settings = thresholds[method]

        if settings.get("score_column", score_column) != score_column:
            raise ValueError(f"{method}: Step 10 threshold score column mismatch")

        score = float(summaries[source].iloc[0][score_column])
        threshold = float(settings["threshold"])

        if not (np.isfinite(score) and np.isfinite(threshold)):
            raise ValueError(f"{eid}/{method}: invalid score or threshold")

        original_alarms[method] = int(score > threshold)
        scored[method] = (score, threshold)

    if FP_REDUCTION_POLICY not in ("dual_confirmation", "original"):
        raise ValueError("FP_REDUCTION_POLICY must be 'dual_confirmation' or 'original'")

    if "DTBAD_combined" in original_alarms and FP_REDUCTION_POLICY == "dual_confirmation":
        required = ("storage_temporal", "memory_temporal")
        missing = [name for name in required if name not in original_alarms]

        if missing:
            raise ValueError(f"Cannot apply dual confirmation; missing thresholds: {missing}")

    rows = []

    for method, (score, threshold) in scored.items():
        raw_prediction = original_alarms[method]
        predicted = raw_prediction
        policy = "original"

        if method == "DTBAD_combined":
            # Always retain the unmodified baseline for comparison
            rows.append({
                "execution_id": eid,
                "method": "DTBAD_original",
                "actual_label": label_name(truth),
                "ground_truth": np.nan if truth is None else truth,
                "score": score,
                "threshold": threshold,
                "margin_score_minus_threshold": score - threshold,
                "predicted_label": raw_prediction,
                "prediction": label_name(raw_prediction),
                "is_ransomware": raw_prediction,
                "detection_verdict": detection_verdict(raw_prediction),
                "outcome": classify_outcome(truth, raw_prediction),
                "decision_policy": "original",
                "raw_predicted_label": raw_prediction,
                "storage_temporal_alarm": original_alarms.get("storage_temporal", np.nan),
                "memory_temporal_alarm": original_alarms.get("memory_temporal", np.nan)
            })

            if FP_REDUCTION_POLICY == "dual_confirmation":
                predicted = int(
                    bool(raw_prediction)
                    and bool(original_alarms["storage_temporal"])
                    and bool(original_alarms["memory_temporal"])
                )

                policy = "dual_confirmation"

        rows.append({
            "execution_id": eid,
            "method": method,
            "actual_label": label_name(truth),
            "ground_truth": np.nan if truth is None else truth,
            "score": score,
            "threshold": threshold,
            "margin_score_minus_threshold": score - threshold,
            "predicted_label": predicted,
            "prediction": label_name(predicted),
            "is_ransomware": predicted,
            "detection_verdict": detection_verdict(predicted),
            "outcome": classify_outcome(truth, predicted),
            "decision_policy": policy,
            "raw_predicted_label": raw_prediction,
            "storage_temporal_alarm": original_alarms.get("storage_temporal", np.nan),
            "memory_temporal_alarm": original_alarms.get("memory_temporal", np.nan)
        })

    if not rows:
        raise ValueError("No usable Step 10 thresholds")
    return rows

# Aggregate evaluation across executions (not windows)
def safe_ratio(numerator, denominator, undefined=np.nan):
    return numerator / denominator if denominator else undefined

def evaluate_all(predictions):
    records = []

    for method in [*METHODS, "DTBAD_original"]:
        group = predictions.loc[predictions["method"] == method]

        if group.empty:
            continue

        known = group.loc[group["ground_truth"].notna()]
        tn = int((known["outcome"] == "TN").sum())
        fp = int((known["outcome"] == "FP").sum())
        fn = int((known["outcome"] == "FN").sum())
        tp = int((known["outcome"] == "TP").sum())
        benign_count, ransomware_count = tn + fp, tp + fn
        total = len(known)

        # Benign-class precision/recall/F1 (Benign treated as positive)
        benign_precision = safe_ratio(tn, tn + fn, 0.0) if benign_count else np.nan
        benign_recall = safe_ratio(tn, benign_count)
        benign_f1 = safe_ratio(2 * tn, 2 * tn + fn + fp) if benign_count else np.nan

        # Ransomware-class precision/recall/F1 (Ransomware is positive)
        ransomware_precision = safe_ratio(tp, tp + fp, 0.0) if ransomware_count else np.nan
        ransomware_recall = safe_ratio(tp, ransomware_count)
        ransomware_f1 = (safe_ratio(2 * tp, 2 * tp + fp + fn)
                         if ransomware_count else np.nan)

        # Primary F1 is ransomware F1 when ransomware is present, otherwise
        # benign F1 for a benign-only test. Both are always reported separately
        f1_class = ("Ransomware" if ransomware_count else
                    "Benign" if benign_count else "N/A")
        f1 = ransomware_f1 if ransomware_count else benign_f1
        macro_f1 = ((benign_f1 + ransomware_f1) / 2
                    if benign_count and ransomware_count else np.nan)
        records.append({
            "method": method, "evaluated_executions": total,
            "unlabeled_executions": len(group) - total,
            "benign_executions": benign_count,
            "ransomware_executions": ransomware_count,
            "TN": tn, "FP": fp, "FN": fn, "TP": tp,
            "accuracy": safe_ratio(tn + tp, total),
            "precision": ransomware_precision if ransomware_count else benign_precision,
            "recall": ransomware_recall if ransomware_count else benign_recall,
            "f1_score": f1, "f1_class": f1_class,
            "benign_precision": benign_precision, "benign_recall": benign_recall,
            "benign_f1": benign_f1,
            "ransomware_precision": ransomware_precision,
            "ransomware_recall": ransomware_recall,
            "ransomware_f1": ransomware_f1,
            "macro_f1": macro_f1,
            "specificity": safe_ratio(tn, benign_count),
            "false_positive_rate": safe_ratio(fp, benign_count)
        })

    return pd.DataFrame(records)

# Summarize each application's final model prediction, not its ground truth
def final_application_summary(predictions):
    final = predictions.loc[
        predictions["method"] == "DTBAD_combined"
    ]

    lines = ["\nFINAL APPLICATION CLASSIFICATION", "=" * 65]

    if final.empty:
        lines.append("No DTBAD_combined predictions available.")

    else:
        for row in final.itertuples(index=False):
            lines.append(
                f"{row.execution_id}: Predicted = {row.prediction} | "
                f"Actual = {row.actual_label} | Outcome = {row.outcome}"
            )

    return "\n".join(lines)

def write_report(executions, predictions, metrics, threshold_path, drift):
    final = predictions.loc[predictions["method"] == "DTBAD_combined"].copy()
    original = predictions.loc[predictions["method"] == "DTBAD_original"].copy()
    final_metrics = metrics.loc[metrics["method"] == "DTBAD_combined"]

    if not final_metrics.empty:
        fm = final_metrics.iloc[0]
        final_line = (f"DTBAD {fm['f1_class']} F1-score: "
                      f"{fm['f1_score']:.4f}" if pd.notna(fm["f1_score"])
                      else "DTBAD F1-score: N/A (no labeled executions)")

    else:
        final_line = "DTBAD combined: unavailable (no Step 10 combined threshold)"

    show_metrics = ["method", "evaluated_executions", "accuracy", "precision",
                    "recall", "f1_score", "f1_class", "benign_f1",
                    "ransomware_f1", "false_positive_rate"]

    report = [
        "DTBAD STEP 11 - MULTIPLE EXTERNAL EXECUTION EVALUATION\n",

        f"Executions discovered: {len(executions)}",
        f"Known benign: {sum(x['label'] == 0 for x in executions)}",
        f"Known ransomware: {sum(x['label'] == 1 for x in executions)}",
        f"Unknown ground truth: {sum(x['label'] is None for x in executions)}",
        f"Step 10 thresholds: {threshold_path}",
        "Models and thresholds were NOT retrained or recalibrated.",
        f"FP reduction policy: {FP_REDUCTION_POLICY} (experimental)",

        "\nORIGINAL DTBAD PREDICTION (BEFORE FP MITIGATION)",
        original[["execution_id", "actual_label", "detection_verdict", "outcome",
                  "score", "threshold"]].to_string(index=False, float_format=lambda x: f"{x:.5g}")
        if not original.empty else "Original DTBAD prediction unavailable.",

        "\nFINAL DTBAD RANSOMWARE DETECTION FOR EACH EXECUTION",
        final[["execution_id", "actual_label", "detection_verdict", "outcome",
               "score", "threshold"]].to_string(index=False, float_format=lambda x: f"{x:.5g}")
        if not final.empty else "DTBAD combined prediction unavailable.",

        "\nEVALUATION METRICS (ONE VOTE PER LABELED EXECUTION)",
        metrics[show_metrics].to_string(index=False, float_format=lambda x: f"{x:.4f}"),

        "\nORIGINAL VS CONSERVATIVE DTBAD METRICS",
        metrics.loc[metrics["method"].isin(["DTBAD_original", "DTBAD_combined"]),
                    ["method", "TN", "FP", "FN", "TP", "accuracy", "f1_score", "false_positive_rate"]]
        .to_string(index=False, float_format=lambda x: f"{x:.4f}"),

        "\nCONFUSION COUNTS",
        metrics[["method", "TN", "FP", "FN", "TP"]].to_string(index=False),
        "",
        final_line,
        f"\nTOP {FEATURE_DRIFT_TOP_N} FEATURE DRIFTS PER APPLICATION AND MODALITY (DIAGNOSTIC ONLY)",
        top_feature_drift(drift)[[
            "execution_id", "modality", "feature", "external_mean",
            "training_mean", "training_scale", "mean_abs_z", "fraction_abs_z_gt_3",
        ]].to_string(index=False, float_format=lambda x: f"{x:.4g}"),
        final_application_summary(predictions),
    ]

    text = "\n".join(report) + "\n"

    (OUT / "11_detection_report.txt").write_text(text, encoding="utf-8")

    print("\n" + text)

# Main
if __name__ == "__main__":
    if FP_REDUCTION_POLICY not in ("dual_confirmation", "original"):
        raise ValueError("Invalid FP_REDUCTION_POLICY")

    if not np.isclose(STORAGE_WEIGHT + MEMORY_WEIGHT, 1.0):
        raise ValueError("Storage and memory fusion weights must sum to 1")

    executions = discover_executions()

    # File title
    print(f"\nDTBAD: {len(executions)} external execution(s)\n")
    reset_outputs()

    # Keep a reproducible record of the actual labels supplied at runtime
    # These are evaluation labels, never model features or predictions
    pd.DataFrame([
        {"execution_id": item["execution_id"],
         "label": "" if item["label"] is None else item["label"],
         "actual_type": label_name(item["label"])}
        for item in executions
    ]).to_csv(OUT / "11_ground_truth_labels.csv", index=False)
    step05 = load_step05()
    step08 = import_script(STEP08, "dtbad_step08")
    resources = load_resources(step08)
    thresholds, threshold_path = load_thresholds()

    cleaning, prediction_rows, drift_frames, diagnostic_rows = [], [], [], []

    for index, execution in enumerate(executions, 1):
        eid = execution["execution_id"]
        print(f"\n[{index}/{len(executions)}] {eid} (actual: {label_name(execution['label'])})")

        items, records = clean_execution(execution)
        cleaning.extend(records)
        features = extract_features(step05, items, eid)
        summaries = {}
        execution_drift_frames = []

        for category in ("storage", "memory"):
            summaries[category], drift = score_modality(
                step08, category, features[category], resources, eid
            )

            drift_frames.append(drift)
            execution_drift_frames.append(drift)

        diagnostic_rows.extend(score_diagnostics(eid, summaries, resources, thresholds))
        print_feature_drift_diagnostics(eid, pd.concat(execution_drift_frames, ignore_index=True))
        rows = predict_execution(execution, summaries, thresholds)
        prediction_rows.extend(rows)
        final = next((r for r in rows if r["method"] == "DTBAD_combined"), None)

        if final:
            raw = next((r for r in rows if r["method"] == "DTBAD_original"), None)

            if raw:
                print(f"\tOriginal DTBAD: {raw['prediction']} ({raw['outcome']})")

            print(f"\tConservative DTBAD: {final['prediction']} ({final['outcome']})")
            print(f"\tDTBAD detection: {final['detection_verdict']}")
            print(f"\tActual type: {label_name(execution['label'])}")
            print(f"\tEvaluation outcome: {final['outcome']}")

    pd.DataFrame(cleaning).to_csv(OUT / "11_cleaning_summary.csv", index=False)
    pd.DataFrame(diagnostic_rows).to_csv(PRED / "11_score_diagnostics.csv", index=False)
    predictions = pd.DataFrame(prediction_rows)
    metrics = evaluate_all(predictions)

    if metrics.empty:
        raise ValueError("No detection methods were evaluated")

    # The F1 in this file is cohort-level, not a per-execution F1
    predictions = predictions.merge(
        metrics[["method", "f1_score", "f1_class"]].rename(
            columns={"f1_score": "overall_f1_score", "f1_class": "overall_f1_class"}
        ), on="method", how="left", validate="many_to_one"
    )

    predictions.to_csv(PRED / "11_classification_results.csv", index=False)
    metrics.to_csv(PRED / "11_evaluation_metrics.csv", index=False)
    metrics[["method", "TN", "FP", "FN", "TP"]].to_csv(
        PRED / "11_confusion_counts.csv", index=False
    )

    final = predictions.loc[predictions["method"] == "DTBAD_combined"]
    final.to_csv(PRED / "11_execution_predictions.csv", index=False)
    predictions.loc[predictions["method"] == "DTBAD_original"].to_csv(
        PRED / "11_original_execution_predictions.csv", index=False
    )

    drift = pd.concat(drift_frames, ignore_index=True)
    drift.to_csv(PRED / "11_feature_drift.csv", index=False)
    top_feature_drift(drift).to_csv(
        PRED / "11_top_feature_drift.csv", index=False
    )

    print(f"Results saved to: {OUT}")
    write_report(executions, predictions, metrics, threshold_path, drift)

    # Closure
    print("\nExternal Evaluation Complete")
