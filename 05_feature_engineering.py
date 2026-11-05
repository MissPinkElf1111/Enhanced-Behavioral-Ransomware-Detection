"""
Preserves feature definitions and window alignment of the uploaded script.

Initial time window: 0.1 seconds

Features: 26 storage + 60 memory

label = 0 for benign executions, label = 1 for ransomware executions
"""

from pathlib import Path
from collections import defaultdict
import numpy as np
import pandas as pd

# Configuration
PREPARED_DIR = Path("prepared")
FEATURES_DIR = Path("features")

# Memory limit per read
CHUNK_SIZE = 250_000

WINDOW_SIZE_NS = 100_000_000    # 0.1 Sec
WINDOW_SIZE_SECONDS = WINDOW_SIZE_NS / 1_000_000_000

STORAGE_COLUMNS = [
    # Identification / alignment
    "dataset",
    "execution_id",
    "label",
    "window_start_ns",
    "window_end_ns",

    # Activity counts
    "read_count",
    "write_count",
    "total_operation_count",

    # Amount of data accessed
    "bytes_read",
    "bytes_written",
    "total_bytes",

    # Throughput
    "read_throughput",
    "write_throughput",
    "total_throughput",

    # Request-size behavior
    "avg_read_size",
    "avg_write_size",
    "read_size_variance",
    "write_size_variance",
    "max_read_size",
    "max_write_size",

    # Storage-address behavior
    "read_lba_variance",
    "write_lba_variance",
    "read_lba_range",
    "write_lba_range",

    # Read/write behavioral proportions
    "read_ratio",
    "write_ratio",
    "read_write_ratio",

    # Write-entropy behavior
    "write_entropy_mean",
    "write_entropy_variance",
    "write_entropy_min",
    "write_entropy_max"
]

MEMORY_COLUMNS = [
    # Identification / alignment
    "dataset",
    "execution_id",
    "label",
    "window_start_ns",
    "window_end_ns",

    # Operation counts
    "read_count",
    "write_count",
    "readwrite_count",
    "execute_count",
    "total_operation_count",

    # Operation ratios
    "read_ratio",
    "write_ratio",
    "readwrite_ratio",
    "execute_ratio",

    # Bytes explicitly reported by the trace
    "bytes_read",
    "bytes_written",
    "bytes_readwrite",
    "bytes_execute",
    "total_bytes",

    # Access-size behavior
    "avg_read_size",
    "avg_write_size",
    "avg_readwrite_size",
    "avg_execute_size",

    "read_size_variance",
    "write_size_variance",
    "readwrite_size_variance",
    "execute_size_variance",

    "max_read_size",
    "max_write_size",
    "max_readwrite_size",
    "max_execute_size",

    # Memory-address behavior
    "read_gpa_variance",
    "write_gpa_variance",
    "readwrite_gpa_variance",
    "execute_gpa_variance",

    "read_gpa_range",
    "write_gpa_range",
    "readwrite_gpa_range",
    "execute_gpa_range",

    # Entropy behavior
    "write_entropy_mean",
    "write_entropy_variance",
    "write_entropy_max",

    "readwrite_entropy_mean",
    "readwrite_entropy_variance",
    "readwrite_entropy_max",

    # Memory-page-type counts
    "4kb_read_count",
    "4kb_write_count",
    "4kb_readwrite_count",
    "4kb_execute_count",

    "2mb_read_count",
    "2mb_write_count",
    "2mb_readwrite_count",
    "2mb_execute_count",

    "1gb_read_count",
    "1gb_write_count",
    "1gb_readwrite_count",
    "1gb_execute_count",

    "mmio_read_count",
    "mmio_write_count",
    "mmio_readwrite_count",
    "mmio_execute_count",

    # Memory-page-type ratios
    "4kb_ratio",
    "2mb_ratio",
    "1gb_ratio",
    "mmio_ratio"
]

# Identify files and datasets
# Identify the modality and operation from each prepared CSV filename
def identify_file(path):
    name = path.name

    # Check memory files before generic read/write suffixes
    if name.endswith("mem_readwrite.csv"):
        return "memory", "readwrite"

    if name.endswith("mem_read.csv"):
        return "memory", "read"

    if name.endswith("mem_write.csv"):
        return "memory", "write"

    if name.endswith("mem_exec.csv"):
        return "memory", "execute"

    if name.endswith("ata_read.csv"):
        return "storage", "read"

    if name.endswith("ata_write.csv"):
        return "storage", "write"

    return None, None

# Keep RanSAP, RanSMAP and Benign executions separate even when IDs overlap
def get_dataset(path):
    name = path.name

    if name.startswith("RanSAP_"):
        return "RanSAP"

    if name.startswith("RanSMAP_"):
        return "RanSMAP"

    if name.startswith("Benign_"):
        return "Benign"

    raise ValueError(f"Cannot identify dataset from: {path}")

# Discover every supported CSV in prepared/; no sampling or row limit
def find_prepared_files():
    if not PREPARED_DIR.exists():
        raise FileNotFoundError(f"Prepared folder not found: {PREPARED_DIR}")

    files = []

    for path in sorted(PREPARED_DIR.glob("*.csv")):
        category, operation = identify_file(path)

        if category is not None:
            files.append(
                {
                    "path": path,
                    "dataset": get_dataset(path),
                    "category": category,
                    "operation": operation
                }
            )

    if not files:
        raise FileNotFoundError("No prepared CSV files were found.")

    return files

# Remove the operation suffix so streams from one run share an ID
def normalize_execution_id(source_file_id, operation):
    file_name = Path(str(source_file_id)).name

    suffixes = {
        ("storage", "read"): "_ata_read.csv",
        ("storage", "write"): "_ata_write.csv",
        ("memory", "read"): "_mem_read.csv",
        ("memory", "write"): "_mem_write.csv",
        ("memory", "readwrite"): "_mem_readwrite.csv",
        ("memory", "execute"): "_mem_exec.csv"
    }

    category, operation_name = operation

    suffix = suffixes[(category, operation_name)]

    if file_name.endswith(suffix):
        return file_name[:-len(suffix)]

    # Handle source
    simple_suffix = suffix[1:]

    if file_name == simple_suffix:
        return Path(str(source_file_id)).parent.as_posix()

    raise ValueError(f"Cannot derive execution ID from {source_file_id}")

# Statistical calculations
# Each statistic maintains sufficient information across chunks
class Stats:
    __slots__ = ("n", "mean", "m2", "total", "minimum", "maximum")

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.total = 0.0
        self.minimum = float("inf")
        self.maximum = float("-inf")

    # Merge the next batch into running mean sample variance, sum, min and max
    def add(self, series):
        x = (
            pd.to_numeric(series, errors="coerce")
            .dropna()
            .to_numpy(dtype=np.float64)
        )

        if not len(x):
            return

        n = len(x)
        mean = float(np.mean(x))
        m2 = float(np.sum((x - mean) ** 2))
        delta = mean - self.mean
        new_n = self.n + n

        self.m2 += (m2 + delta * delta * self.n * n / new_n)

        self.mean += delta * n / new_n
        self.n = new_n
        self.total += float(np.sum(x))
        self.minimum = min(self.minimum, float(np.min(x)))
        self.maximum = max(self.maximum, float(np.max(x)))

    def avg(self):
        return self.mean if self.n else 0.0

    def var(self):
        return (
            self.m2 / (self.n - 1)
            if self.n > 1
            else 0.0
        )

    def high(self):
        return self.maximum if self.n else 0.0

    def low(self):
        return self.minimum if self.n else 0.0

    def spread(self):
        return (
            self.maximum - self.minimum
            if self.n > 1
            else 0.0
        )


# Use zero for ratios with a zero denominator
def ratio(a, b):
    return float(a / b) if b else 0.0

# Execution identification and CSV reading
# Normalize source filenames efficiently by mapping distinct values per chunk
def execution_ids(series, category, operation):
    values = series.astype(str)
    unique = values.unique()

    mapping = {
        value: normalize_execution_id(
            value,
            (category, operation)
        )
        for value in unique
    }

    return values.map(mapping)


# Stream the complete CSV in memory-bounded chunks
def read_chunks(item, columns):
    for chunk in pd.read_csv(
        item["path"],
        usecols=columns,
        chunksize=CHUNK_SIZE
    ):
        yield chunk

# Discover execution start times
# Pass 1: find earliest event per execution across all operations
def discover_starts(files, category):
    starts = {}

    chosen = [
        f for f in files
        if f["category"] == category
    ]

    for item in chosen:
        columns = [
            "source_file_id",
            "UNIX time in sec",
            "UNIX time in ns"
        ]

        count = 0

        for chunk in read_chunks(item, columns):
            chunk = chunk.dropna(subset=columns)

            if chunk.empty:
                continue

            ids = execution_ids(
                chunk["source_file_id"],
                category,
                item["operation"]
            )

            sec = pd.to_numeric(
                chunk["UNIX time in sec"],
                errors="coerce"
            ).astype("int64")

            ns = pd.to_numeric(
                chunk["UNIX time in ns"],
                errors="coerce"
            ).astype("int64")

            times = sec * 1_000_000_000 + ns

            mins = pd.DataFrame({
                "id": ids,
                "time": times
            }).groupby("id")["time"].min()

            for eid, time in mins.items():
                key = (item["dataset"], eid)

                starts[key] = min(
                    starts.get(key, int(time)),
                    int(time)
                )

            count += len(chunk)

        print(
            f"Start times: {item['path'].name} ({count:,} rows)",
            flush=True
        )

    return starts

# Select required numeric columns
def numeric_columns(category, operation, dataset):
    columns = [
        "source_file_id",
        "UNIX time in sec",
        "UNIX time in ns"
    ]

    if category == "storage":
        columns += ["size", "LBA"]

        if operation == "write":
            columns += [
                "Entropy #1"
                if dataset == "RanSAP"
                else "entropy"
            ]

    else:
        columns += ["GPA", "type"]

        if operation in ("write", "readwrite"):
            columns += ["size", "entropy"]

    return columns

# Aggregate time-window statistics
def aggregate(files, category, starts):
    # State is indexed by dataset/execution/window/operation
    states = defaultdict(
        lambda: {
            "count": 0,
            "stats": defaultdict(Stats),
            "pages": defaultdict(int)
        }
    )

    maximum = defaultdict(lambda: -1)

    chosen = [
        f for f in files
        if f["category"] == category
    ]

    for item in chosen:
        dataset = item["dataset"]
        operation = item["operation"]

        columns = numeric_columns(
            category,
            operation,
            dataset
        )

        processed = 0

        for chunk in read_chunks(item, columns):
            if chunk.empty:
                continue

            # Exclude missing source/time rows
            chunk = chunk.dropna(
                subset=columns[:3]
            ).copy()

            if chunk.empty:
                continue

            chunk["execution_id"] = execution_ids(
                chunk["source_file_id"],
                category,
                operation
            )

            sec = pd.to_numeric(
                chunk["UNIX time in sec"],
                errors="coerce"
            ).astype("int64")

            ns = pd.to_numeric(
                chunk["UNIX time in ns"],
                errors="coerce"
            ).astype("int64")

            absolute = sec * 1_000_000_000 + ns

            begin = chunk["execution_id"].map(
                lambda eid: starts[(dataset, eid)]
            ).astype("int64")

            relative = absolute - begin

            chunk = chunk.loc[
                relative >= 0
            ].copy()

            relative = relative.loc[
                relative >= 0
            ]

            if chunk.empty:
                continue

            # Assign each event to one 0.1-second window
            chunk["window_index"] = (
                relative // WINDOW_SIZE_NS
            ).astype("int64")

            # Group events by execution and time window
            for (eid, win), group in chunk.groupby(
                ["execution_id", "window_index"],
                sort=False
            ):
                win = int(win)

                key = (
                    dataset,
                    eid,
                    win,
                    operation
                )

                state = states[key]

                # Preserve all valid events
                state["count"] += len(group)

                maximum[(dataset, eid)] = max(
                    maximum[(dataset, eid)],
                    win
                )

                stat_columns = (
                    ["size", "LBA"]
                    if category == "storage"
                    else ["GPA"]
                )

                if (
                    category == "memory"
                    and operation in ("write", "readwrite")
                ):
                    stat_columns += [
                        "size",
                        "entropy"
                    ]

                if (
                    category == "storage"
                    and operation == "write"
                ):
                    stat_columns += [
                        "Entropy #1"
                        if dataset == "RanSAP"
                        else "entropy"
                    ]

                # UPDATED: Clean negative entropy measurements
                for col in stat_columns:
                    values = group[col]

                    # Negative entropy indicates unavailable data
                    if col in ("entropy", "Entropy #1"):
                        values = pd.to_numeric(
                            values,
                            errors="coerce"
                        )

                        values = values.where(
                            np.isfinite(values)
                            & (values >= 0)
                        )

                    state["stats"][
                        "entropy"
                        if col == "Entropy #1"
                        else col
                    ].add(values)

                # Count memory page types
                if category == "memory":
                    types = pd.to_numeric(
                        group["type"],
                        errors="coerce"
                    )

                    for t in (1, 2, 3, 4):
                        state["pages"][t] += int(
                            (types == t).sum()
                        )

            processed += len(chunk)

        print(
            f"Aggregated: {item['path'].name} ({processed:,} rows)",
            flush=True
        )

    return states, maximum

# Generate features from aggregated statistics
def make_rows(category, starts, states, maximum):
    rows = []

    operations = (
        ["read", "write"]
        if category == "storage"
        else ["read", "write", "readwrite", "execute"]
    )

    for dataset, eid in sorted(starts):
        last = maximum[(dataset, eid)]

        for win in range(last + 1):
            current = {
                op: states.get(
                    (dataset, eid, win, op)
                )
                for op in operations
            }

            def count(op):
                state = current[op]
                return state["count"] if state else 0

            def stat(op, col):
                state = current[op]
                return (
                    state["stats"].get(col)
                    if state
                    else None
                )

            def value(op, col, method):
                st = stat(op, col)

                return (
                    getattr(st, method)()
                    if st
                    else 0.0
                )

            counts = {
                op: count(op)
                for op in operations
            }

            total_count = sum(counts.values())

            row = {
                "dataset": dataset,
                "execution_id": eid,
                "label": 0 if dataset == "Benign" else 1,
                "window_start_ns": win * WINDOW_SIZE_NS,
                "window_end_ns": (win + 1) * WINDOW_SIZE_NS
            }

            # Storage features
            if category == "storage":
                read_bytes = (
                    stat("read", "size").total
                    if stat("read", "size")
                    else 0.0
                )

                write_bytes = (
                    stat("write", "size").total
                    if stat("write", "size")
                    else 0.0
                )

                total_bytes = read_bytes + write_bytes

                row.update({
                    "read_count": counts["read"],
                    "write_count": counts["write"],
                    "total_operation_count": total_count,

                    "bytes_read": read_bytes,
                    "bytes_written": write_bytes,
                    "total_bytes": total_bytes,

                    "read_throughput": read_bytes / WINDOW_SIZE_SECONDS,
                    "write_throughput": write_bytes / WINDOW_SIZE_SECONDS,
                    "total_throughput": total_bytes / WINDOW_SIZE_SECONDS,

                    "avg_read_size": value("read", "size", "avg"),
                    "avg_write_size": value("write", "size", "avg"),

                    "read_size_variance": value("read", "size", "var"),
                    "write_size_variance": value("write", "size", "var"),

                    "max_read_size": value("read", "size", "high"),
                    "max_write_size": value("write", "size", "high"),

                    "read_lba_variance": value("read", "LBA", "var"),
                    "write_lba_variance": value("write", "LBA", "var"),

                    "read_lba_range": value("read", "LBA", "spread"),
                    "write_lba_range": value("write", "LBA", "spread"),

                    "read_ratio": ratio(counts["read"], total_count),
                    "write_ratio": ratio(counts["write"], total_count),
                    "read_write_ratio": ratio(counts["read"], counts["write"]),

                    "write_entropy_mean": value("write", "entropy", "avg"),
                    "write_entropy_variance": value("write", "entropy", "var"),
                    "write_entropy_min": value("write", "entropy", "low"),
                    "write_entropy_max": value("write", "entropy", "high")
                })

            # Memory features
            else:
                row.update({
                    f"{op}_count": counts[op]
                    for op in operations
                })

                row["total_operation_count"] = total_count

                for op in operations:
                    row[f"{op}_ratio"] = ratio(
                        counts[op],
                        total_count
                    )

                    st = stat(op, "size")

                    byte_column = {
                        "read": "bytes_read",
                        "write": "bytes_written",
                        "readwrite": "bytes_readwrite",
                        "execute": "bytes_execute"
                    }[op]

                    row[byte_column] = (st.total if st else 0.0)
                    row[f"avg_{op}_size"] = value(op, "size", "avg")
                    row[f"{op}_size_variance"] = value(op, "size", "var")
                    row[f"max_{op}_size"] = value(op, "size", "high")
                    row[f"{op}_gpa_variance"] = value(op, "GPA", "var")
                    row[f"{op}_gpa_range"] = value(op, "GPA", "spread")

                row["total_bytes"] = sum(
                    row[x]
                    for x in (
                        "bytes_read",
                        "bytes_written",
                        "bytes_readwrite",
                        "bytes_execute"
                    )
                )

                # Memory entropy features
                for op in ("write", "readwrite"):
                    row[f"{op}_entropy_mean"] = value(op, "entropy", "avg")
                    row[f"{op}_entropy_variance"] = value(op, "entropy", "var")
                    row[f"{op}_entropy_max"] = value(op, "entropy", "high")

                # Memory page-type counts
                typed = 0
                totals = {}

                for label, typ in (
                    ("4kb", 1),
                    ("2mb", 2),
                    ("1gb", 3),
                    ("mmio", 4)
                ):
                    subtotal = 0

                    for op in operations:
                        state = current[op]

                        n = (
                            state["pages"].get(typ, 0)
                            if state
                            else 0
                        )

                        row[f"{label}_{op}_count"] = n
                        subtotal += n

                    totals[label] = subtotal
                    typed += subtotal

                # Memory page-type ratios
                for label in (
                    "4kb",
                    "2mb",
                    "1gb",
                    "mmio"
                ):
                    row[f"{label}_ratio"] = ratio(
                        totals[label],
                        typed
                    )

            rows.append(row)

    columns = (
        STORAGE_COLUMNS
        if category == "storage"
        else MEMORY_COLUMNS
    )

    return pd.DataFrame(
        rows,
        columns=columns
    )

# Validate feature output
def validate_output(df, columns, category):
    if df.empty:
        raise RuntimeError(f"{category} features are empty")

    if df.duplicated(
        [
            "dataset",
            "execution_id",
            "window_start_ns",
            "window_end_ns"
        ]
    ).any():
        raise RuntimeError(
            f"{category}: duplicate windows"
        )

    if (list(df.columns) != columns or df.isna().any().any()):
        raise RuntimeError(f"{category}: invalid feature output")

    numeric = df.drop(
        columns=[
            "dataset",
            "execution_id",
            "label"
        ]
    ).to_numpy(dtype=float)

    if not np.isfinite(numeric).all():
        raise RuntimeError(f"{category}: non-finite feature values")

# Feature output configuration
KEY_COLUMNS = [
    "dataset",
    "execution_id",
    "label",
    "window_start_ns",
    "window_end_ns"
]

STORAGE_SHARED = [
    "total_operation_count",
    "total_bytes",
    "total_throughput",
    "read_ratio",
    "write_ratio",
    "read_write_ratio"
]

MEMORY_SHARED = [
    "total_operation_count",
    "total_bytes",
    "read_ratio",
    "write_ratio",
    "readwrite_ratio",
    "execute_ratio",
    "4kb_ratio",
    "2mb_ratio",
    "1gb_ratio",
    "mmio_ratio"
]

# Select output columns
def output_columns(category, operation):
    original = (
        STORAGE_COLUMNS
        if category == "storage"
        else MEMORY_COLUMNS
    )

    if category == "storage":
        selected = set(STORAGE_SHARED)

        selected.update(
            {
                "read_count",
                "bytes_read",
                "read_throughput"
            }
            if operation == "read"
            else {
                "write_count",
                "bytes_written",
                "write_throughput"
            }
        )

        selected.update({
            f"avg_{operation}_size",
            f"{operation}_size_variance",
            f"max_{operation}_size",
            f"{operation}_lba_variance",
            f"{operation}_lba_range"
        })

        if operation == "write":
            selected.update({
                "write_entropy_mean",
                "write_entropy_variance",
                "write_entropy_min",
                "write_entropy_max"
            })

    else:
        selected = set(MEMORY_SHARED)

        selected.update({
            f"{operation}_count",
            f"{operation}_ratio",
            f"avg_{operation}_size",
            f"{operation}_size_variance",
            f"max_{operation}_size",
            f"{operation}_gpa_variance",
            f"{operation}_gpa_range"
        })

        selected.add(
            {
                "read": "bytes_read",
                "write": "bytes_written",
                "readwrite": "bytes_readwrite",
                "execute": "bytes_execute"
            }[operation]
        )

        selected.update(
            f"{page}_{operation}_count"
            for page in (
                "4kb",
                "2mb",
                "1gb",
                "mmio"
            )
        )

        if operation in ("write", "readwrite"):
            selected.update({
                f"{operation}_entropy_mean",
                f"{operation}_entropy_variance",
                f"{operation}_entropy_max"
            })

    result = KEY_COLUMNS + [
        col
        for col in original
        if col not in KEY_COLUMNS
        and col in selected
    ]

    return result

# Write operation-specific feature files
def write_six_files(category, dataframe):
    operations = (
        ("read", "write")
        if category == "storage"
        else (
            "read",
            "write",
            "readwrite",
            "execute"
        )
    )

    covered = set()

    for operation in operations:
        columns = output_columns(
            category,
            operation
        )

        covered.update(columns)

        output = (FEATURES_DIR / f"{category}_{operation}_features.csv")

        dataframe.to_csv(
            output,
            columns=columns,
            index=False
        )

        print(
            f"Saved {output.name}: {len(dataframe):,} windows, {len(columns) - len(KEY_COLUMNS)} features",
            flush=True
        )

    expected = set(
        STORAGE_COLUMNS
        if category == "storage"
        else MEMORY_COLUMNS
    )

    if covered != expected:
        raise RuntimeError(f"Feature projection mismatch: {sorted(expected - covered)}")

# Main
if __name__ == "__main__":
    # File title
    print("\nFeature Engineering\n")

    files = find_prepared_files()

    FEATURES_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    for category in ("storage", "memory"):
        selected = [
            item
            for item in files
            if item["category"] == category
        ]

        if not selected:
            continue

        print(
            f"\nProcessing {category}...",
            flush=True
        )

        starts = discover_starts(files, category)

        if not starts:
            continue

        states, maximum = aggregate(files, category, starts)

        df = make_rows(
            category,
            starts,
            maximum=maximum,
            states=states
        )

        columns = (
            STORAGE_COLUMNS
            if category == "storage"
            else MEMORY_COLUMNS
        )

        validate_output(df, columns, category)

        write_six_files(category, df)

        print(
            f"{category}: {len(starts)} executions, {len(df):,} windows",
            flush=True
        )

    # Closure
    print("\nFeature Engineering Complete")
