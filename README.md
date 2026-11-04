# Enhanced Behavioral Ransomware Detection

## Overview

This project implements an offline ransomware detection pipeline using low-level storage and memory access traces from the RanSAP and RanSMAP datasets.

The current experiment focuses on WannaCry ransomware and benign activity from Firefox, Microsoft Office, and Zip.

The pipeline extracts behavioural features, trains models on benign activity, and identifies executions with unusual behaviour. It includes:

- 26 storage features and 60 memory features.
- Separate storage and memory autoencoders.
- Isolation Forest comparison models.
- Temporal scoring of autoencoder reconstruction errors.
- Score-level fusion of storage and memory results.
- Execution-level detection evaluation.

## Necessary Datasets

Download and unzip the dataset for training and testing the models: -[Datasets](https://drive.google.com/drive/folders/1fiu80Yl4lMNHNa6HX0gEigzYfMX472Ox?usp=sharing).

## Repository Structure

| Script | Purpose | Output |
| --- | --- | --- |
| `01_inspect_data.py` | Check dataset folders and count storage and memory CSV files | Console summary |
| `02_analyze_data.py` | Examine source schemas, row counts, and missing values | Console summary |
| `03_combine_data.py` | Combine files by dataset and operation while preserving source metadata | `results/` |
| `04_prepare_data.py` | Remove unused columns and invalid records | `prepared/` |
| `05_feature_engineering.py` | Extract behavioural features in 0.1-second windows | `features/` |
| `05A_paper_feature_engineering.py` | Extract the 23-feature comparison set: 5 storage and 18 memory features | `features_paper/` |
| `06_split_data.py` | Create shared execution-level splits for the expanded features and, when available, the 23-feature comparison set | `splits/`, `splits_paper/` |
| `07_train_models.py` | Train storage and memory autoencoders and Isolation Forest models | `models/` |
| `08_evaluate_models.py` | Calculate window scores, execution summaries, and combined scores | `evaluation/` |
| `08A_ablation_study.py` | Compare the 23-feature and 86-feature configurations and evaluate three fusion-weight settings | `ablation/` |
| `09_analyze_evalutaion.py` | Analyse score distributions, novelty rates, outliers, and data quality | `analysis/` |
| `10_evaluate_detection.py` | Calibrate detection thresholds and calculate classification metrics | `performance/` |

### Supported Source Files

The scripts search recursively for headerless CSV files with these suffixes:

| Filename Suffix | Operation |
| --- | --- |
| `ata_read.csv` | Storage read |
| `ata_write.csv` | Storage write |
| `mem_read.csv` | Memory read |
| `mem_write.csv` | Memory write |
| `mem_readwrite.csv` | Memory read and write |
| `mem_exec.csv` | Memory execute |

The expected schemas are defined in `02_analyze_data.py`, `03_combine_data.py`, and `04_prepare_data.py`.

Fields include timestamp components, logical block addresses (LBA), guest physical addresses (GPA), access sizes, and entropy values where available. Column order differs between datasets and operations and must match the schemas in the code.

## Implementation

### Data Combination and Cleaning

`03_combine_data.py` combines traces separately by dataset and operation. It adds:

- `source_file_id`: the original file path relative to its dataset folder.
- `source_row`: the original row number.

These fields preserve the source information needed to identify executions.

`04_prepare_data.py` removes unused placeholder columns and rejects records with invalid source identifiers, missing retained values, or invalid numeric fields.

### Feature Extraction

`05_feature_engineering.py` aggregates access events into **0.1-second windows**.

| Modality | Feature Count | Main Feature Groups |
| --- | --- | --- |
| Storage | 26 | Operation counts, byte totals, throughput, request sizes, address variation, read/write ratios, and write entropy |
| Memory | 60 | Read/write/readwrite/execute activity, operation ratios, reported byte totals, access sizes, address behaviour, and entropy |
| Total | 86 | Separate storage and memory feature sets |

The following metadata is retained separately from the model features:

```text
dataset
execution_id
label
window_start_ns
window_end_ns
```

Features are written to six files:

```text
features/storage_read_features.csv
features/storage_write_features.csv
features/memory_read_features.csv
features/memory_write_features.csv
features/memory_readwrite_features.csv
features/memory_execute_features.csv
```

The training and evaluation scripts merge the operation-specific features using their shared execution and window keys.

### Feature-Set Comparison

`05A_paper_feature_engineering.py` extracts a comparison feature set based on the RanSMAP paper:

- 5 storage features: read throughput, write throughput, read and write LBA variance, and average write entropy.
- 18 memory features: write and readwrite entropy, 12 page-type access counts, and 4 GPA variances.

The files are saved in `features_paper/`. This provides a 23-feature configuration for comparison with the expanded 86-feature configuration.

`06_split_data.py` applies the original execution assignments and saves the comparison partitions in `splits_paper/`.

### Execution-Level Splitting

`06_split_data.py` uses target proportions of:

- 70% training.
- 15% validation.
- 15% testing.

The split is stratified by binary label and uses random seed `42`.

Each `(dataset, execution_id)` receives one shared assignment across feature files. All windows from that execution remain in the same partition, reducing the risk of data leakage between training and testing.

Assignments are saved in:

```text
splits/execution_split_assignments.csv
```

### Model Training

`07_train_models.py` trains four models:

1. Storage autoencoder.
2. Memory autoencoder.
3. Storage Isolation Forest.
4. Memory Isolation Forest.

Only benign training windows are used to fit the models. Benign validation windows are used for autoencoder early stopping and novelty calibration.

A `StandardScaler` is fitted on benign training features and reused for validation and test data.

#### Autoencoders

The autoencoders learn to reconstruct benign feature vectors. Mean squared reconstruction error is used as an anomaly score.

The architecture is:

```text
Input → Hidden Layer → Latent Layer → Hidden Layer → Reconstruction
```

| Model | Input Features | Hidden Units | Latent Units |
| --- | --- | --- | --- |
| Storage autoencoder | 26 | 13 | 6 |
| Memory autoencoder | 60 | 30 | 15 |

#### Isolation Forest

Separate Isolation Forest models provide comparison scores for storage and memory.

The implementation uses negative `score_samples` values so that higher scores indicate more unusual behaviour.

### Temporal Scoring

`08_evaluate_models.py` calculates a five-window rolling mean of autoencoder reconstruction errors within each execution.

Five complete windows represent 0.5 seconds of activity. Initial windows use the available shorter history.

Temporal scoring processes the autoencoder errors; it is not a separately trained model.

### Score-Level Fusion

The combined method, named `DTBAD_combined` in the code, integrates normalised storage and memory temporal scores:

```text
Combined score =
    0.50 × normalised storage temporal score
  + 0.50 × normalised memory temporal score
```

Normalisation uses benign validation statistics.

Fusion is performed on matching RanSMAP and Benign execution summaries. RanSAP is evaluated through storage models only because it does not contain memory traces.

### Ablation Study

**NOTICE: To run `08A_ablation_study.py`, please make sure that it has ran `05A_paper_feature_engineering.py` successfully!!!**

`08A_ablation_study.py` compares the 23-feature and 86-feature configurations using autoencoder, temporal, Isolation Forest, and combined scores.

It trains the 23-feature models on benign data and loads the expanded-feature execution scores from Step 08. Comparisons use matching executions and check that their window counts agree.

The script also evaluates three storage/memory fusion-weight settings:

- 40% storage and 60% memory.
- 50% storage and 50% memory.
- 60% storage and 40% memory.

The report identifies the preferred weight using validation F1 score. Results, training summaries, models, and plots are saved in `ablation/`.

### Fusion Weight Sweep

`sweep_weights.py` tests storage:memory fusion weights from 0.0:1.0 to 1.0:0.0 in steps of 0.1, extending the three weights in `08A_ablation_study.py`. For each weight it runs a temporary copy of `08_evaluate_models.py` with the new weights (the original file is not edited), then runs `09_analyze_evalutaion.py` and `10_evaluate_detection.py`. The models are not retrained, so only the fused score changes.

Main findings (35 combined test executions): from 0.7:0.3 upward the test results are identical (F1 87.50%, recall 100%, test ROC-AUC 100%, 2 false alarms). Storage alone (1.0:0.0) ties with the best combined weights on the same executions, and memory alone is weakest (F1 53.33%). `Zip_1866_16_05` is flagged at every weight. Details and the results table are in `weight_sweep_results/`.

### Detection Evaluation

`10_evaluate_detection.py` calibrates each execution-level threshold at the **95th percentile of benign validation execution scores**.

The decision rule is:

```text
Score > threshold → ransomware
Score ≤ threshold → benign
```

Test labels are used to evaluate predictions after threshold calibration.

The script calculates accuracy, precision, recall, F1 score, specificity, false positive rate, false negative rate, balanced accuracy, ROC-AUC, and confusion matrix counts.

Anomaly scores indicate deviation from learned benign behaviour. They are not ransomware probabilities.

## Main Configuration

Settings are defined as constants inside the scripts.

| Setting | Default | Script |
| --- | --- | --- |
| Feature window | 0.1 seconds | `05_feature_engineering.py` |
| Train / validation / test ratios | 70% / 15% / 15% | `06_split_data.py` |
| Random seed | 42 | `06_split_data.py`, `07_train_models.py` |
| Training batch size | 256 | `07_train_models.py` |
| Maximum epochs | 100 | `07_train_models.py` |
| Early stopping patience | 10 | `07_train_models.py` |
| Learning rate | 0.001 | `07_train_models.py` |
| Isolation Forest estimators | 200 | `07_train_models.py` |
| Temporal rolling window | 5 windows | `08_evaluate_models.py` |
| Storage / memory fusion weights | 0.50 / 0.50 | `08_evaluate_models.py` |
| Execution detection percentile | 95 | `10_evaluate_detection.py` |

After changing an upstream setting, rerun the affected stage and its downstream stages.

## Preliminary Results

The following results were reported:

### Data Partitions

| Partition | Executions |
| --- | --- |
| Training | 250 |
| Validation | 54 |
| Test | 56 |
| Total | 360 |

These are overall partition counts. Model fitting uses only the benign windows selected from the training partition.

### Test Set Composition

| Evaluation Set | Benign | Ransomware | Total |
| --- | --- | --- | --- |
| Storage | 28 | 28 | 56 |
| Memory | 28 | 7 | 35 |
| Combined | 28 | 7 | 35 |

The storage ransomware set contains 21 RanSAP and 7 RanSMAP executions. Memory and combined evaluation use the 7 RanSMAP ransomware executions.

### Detection Performance

Ransomware is the positive class.

| Method | Accuracy | Precision | Recall | F1 Score | ROC-AUC |
| --- | --- | --- | --- | --- | --- |
| Storage Autoencoder | 96.43% | 93.33% | 100.00% | 96.55% | 99.49% |
| Storage Temporal | 96.43% | 93.33% | 100.00% | 96.55% | 99.49% |
| Storage Isolation Forest | 92.86% | 96.15% | 89.29% | 92.59% | 98.47% |
| Memory Autoencoder | 88.57% | 71.43% | 71.43% | 71.43% | 94.39% |
| Memory Temporal | 80.00% | 50.00% | 57.14% | 53.33% | 91.84% |
| Memory Isolation Forest | 88.57% | 71.43% | 71.43% | 71.43% | 95.41% |
| Combined | 94.29% | 77.78% | 100.00% | 87.50% | 98.47% |

The storage autoencoder and temporal methods detected all 28 ransomware executions, with 2 false positives each.

The combined method detected all 7 ransomware executions and produced 2 false positives. Memory methods achieved lower F1 scores in this experiment.

Storage and combined methods use different test sets. Their relative performance must be assessed on the same executions before drawing conclusions about the benefit of fusion.

Training epochs and validation reconstruction losses are not reported in the midterm report. These values are printed by `07_train_models.py`.

## Output Files

| Directory | Contents |
| --- | --- |
| `results/` | Combined traces with source metadata |
| `prepared/` | Cleaned traces |
| `features/` | Operation-specific feature tables |
| `splits/` | Partitioned features and execution assignments |
| `models/` | Trained models and preprocessing information |
| `evaluation/` | Window scores, execution summaries, and combined scores |
| `analysis/` | Data quality checks, score statistics, outliers, and plots |
| `performance/` | Classification metrics, predictions, thresholds, and confusion matrices |
| `features_paper/` | The 5 storage and 18 memory comparison features |
| `splits_paper/` | Comparison features partitioned using the shared execution assignments |
| `ablation/` | Feature-set and fusion-weight comparisons, training summaries, reports, and plots |
| `ablation/models_paper/` | Models and calibration information for the 23-feature configuration |

### Saved Models

```text
models/storage_autoencoder.pt
models/memory_autoencoder.pt
models/storage_isolation_forest.joblib
models/memory_isolation_forest.joblib
```

### Final Evaluation Outputs

```text
performance/classification_metrics.csv
performance/execution_predictions.csv
performance/confusion_matrices.csv
performance/detection_thresholds.json
performance/performance_report.txt
performance/10_confusion_matrices.png
```

## Limitations and Planned Work

The current experiment covers WannaCry only and uses a small test set. Cross-dataset and cross-hardware generalisation have not yet been established.

The report also records variation in memory results between two laptop runs, which requires further investigation.

Planned work includes:

- Additional trace collection using BitVisor and Windows 10.
- Random Forest and 1D-CNN–LSTM comparison models.
- Cross-dataset and cross-hardware testing.
- Individual-feature, feature-group, and window-size ablation beyond the implemented 23-versus-86 feature comparison.
- Additional fusion methods beyond the implemented 40/60, 50/50, and 60/40 weight comparisons.
- Repeated experiments with multiple random seeds.
- Comparisons using the same execution sets.

The repository contains scripts 01–10, with additional scripts 05A and 08A for feature-set and fusion-weight comparisons. A separate cross-dataset and cross-hardware generalisation stage is not yet included.

## Authors

- Obianuju Maryann Anaebo
- Donghwan Jwa
- Kashmin N. Wijayasekara
- Junyi Yu

## Data Sources

- [RanSAP](https://github.com/manabu-hirano/RanSAP)
- [RanSMAP](https://github.com/manabu-hirano/RanSMAP)
