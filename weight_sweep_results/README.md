# Fusion weight sweep (storage : memory)

Results of testing different weights for combining the storage and memory scores in the combined detector (script 08). Everything here comes from the same trained models, so only the fusion weight changes between runs.

## What was tested

The combined score is `STORAGE_WEIGHT * storage_score + MEMORY_WEIGHT * memory_score`. The original setting was 0.5 : 0.5. Eleven weights were tested, from 0.0 : 1.0 (memory only) to 1.0 : 0.0 (storage only) in steps of 0.1.

## How it was done

1. `sweep_weights.py` makes a temporary copy of `08_evaluate_models.py` with the new weights. The original 08 file is never edited.
2. For each weight it runs 08, 09 and 10 in order.
3. After each run it copies the `evaluation`, `analysis` and `performance` folders into `weight_sweep/storageX_memoryY/` (for example `storage0.7_memory0.3`), together with a log of each script.
4. The storage and memory models are not retrained. Script 08 loads the saved models, so there is no run-to-run training noise. Any difference comes from the weight only.
5. The 0.5 : 0.5 baseline was re-run as part of the sweep, and the earlier results were backed up first in `weight_sweep/backup_before_sweep`. The two extreme weights (0.0 : 1.0 and 1.0 : 0.0) were run in a second pass with `--include-extremes --skip-baseline`.
6. Chart windows were turned off during the runs so nothing blocked the loop. The confusion matrix images are still saved.

## Folder layout

```
sweep_weights.py                         runner script (repository root)
weight_sweep_results/
    README.md                            this file
    weight_sweep_all_ratios.csv          one row per ratio, all columns
    Weight_Sweep_Results.docx            written summary with tables
    ratios/storageX_memoryY/performance/ metrics, predictions, thresholds and confusion matrices for each ratio
```

Only the `performance` folder of each ratio is in this repository, to keep it small. The full `evaluation` and `analysis` folders for every ratio, and the original 0.5 : 0.5 results, are in the shared Google Drive folder: https://drive.google.com/drive/folders/12Bp7la8mbBcStTs9ZQR9EXAn0qw8R7LN?usp=sharing

## Results (combined result, 35 test executions: 28 benign, 7 ransomware)

| Storage : Memory | Precision | Recall | F1 | Test AUC | Validation AUC | False alarms | Missed |
|---|---|---|---|---|---|---|---|
| 0.0 : 1.0 (memory only) | 50.00% | 57.14% | 53.33% | 91.84% | 91.27% | 4 | 3 |
| 0.1 : 0.9 | 55.56% | 71.43% | 62.50% | 93.37% | 93.92% | 4 | 2 |
| 0.2 : 0.8 | 62.50% | 71.43% | 66.67% | 94.39% | 94.44% | 3 | 2 |
| 0.3 : 0.7 | 66.67% | 85.71% | 75.00% | 95.92% | 96.30% | 3 | 1 |
| 0.4 : 0.6 | 70.00% | 100% | 82.35% | 97.45% | 98.15% | 3 | 0 |
| 0.5 : 0.5 (baseline) | 77.78% | 100% | 87.50% | 98.47% | 99.47% | 2 | 0 |
| 0.6 : 0.4 | 70.00% | 100% | 82.35% | 99.49% | 100% | 3 | 0 |
| 0.7 : 0.3 | 77.78% | 100% | 87.50% | 100% | 100% | 2 | 0 |
| 0.8 : 0.2 | 77.78% | 100% | 87.50% | 100% | 100% | 2 | 0 |
| 0.9 : 0.1 | 77.78% | 100% | 87.50% | 100% | 100% | 2 | 0 |
| 1.0 : 0.0 (storage only) | 77.78% | 100% | 87.50% | 100% | 94.44% | 2 | 0 |

## Main findings

- Storage-heavy weights work best. From 0.7 : 0.3 upward the test results are identical (F1 87.50%, 100% recall, test AUC 100%, same two false alarms).
- Storage alone (1.0 : 0.0), scored on the same 35 executions, ties with the best combined weights on the test set. The combined result is not worse than storage alone. The lower F1 compared with the earlier storage-only result (96.55%) came from the different test set (56 executions with 28 ransomware, versus 35 with 7).
- The only sign that a little memory helps is validation AUC: 100% at 0.7 : 0.3 to 0.9 : 0.1, but 94.44% at 1.0 : 0.0.
- Memory-heavy weights are worse. Memory alone misses 3 of 7 ransomware executions.
- `Zip_1866_16_05` is flagged as ransomware at every weight, so the weights cannot fix it. Memory-heavy weights also flag Firefox runs, and storage-heavy weights flag `Zip_1866_16_01`. The false alarm pair at 0.5 : 0.5 (`FireFox_2133_16_32` and `Zip_1866_16_05`) is different from the pair at 0.7 : 0.3 and above (`Zip_1866_16_01` and `Zip_1866_16_05`).

## What to check

Checked in this sweep:
- Whether the combined result is worse than storage alone on the same executions (it is not, on this test set).
- Which executions are wrong at each ratio (see `performance/execution_predictions.csv` in each ratio folder).

Still to check:
- The detection threshold (95th percentile of benign validation scores). Test AUC is 100% from 0.7 : 0.3 upward, so every ransomware execution scores above every benign one, and the remaining false alarms come from where the line is drawn.
- Why `Zip_1866_16_05` scores high at every weight.
- A larger test set or repeated splits. With only 7 ransomware executions, the tied weights cannot be separated.
- Choosing the weight from validation data only, since the weight was picked here using test results, which is optimistic.

## How to reproduce

From the project folder (the one with scripts 01 to 10):

```
py sweep_weights.py --skip-baseline
py sweep_weights.py --include-extremes --skip-baseline
```

Copy `sweep_weights.py` next to scripts 01 to 10 and run 06 and 07 first if the models do not exist yet. Each run overwrites the main `evaluation`, `analysis` and `performance` folders, so restore them from `weight_sweep/backup_before_sweep` afterward.
