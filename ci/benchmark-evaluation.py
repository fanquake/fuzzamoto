#!/usr/bin/env python3
"""
fuzzamoto-libafl A/B Benchmark Evaluation Script

Performs a rigorous statistical comparison of two fuzzer versions (a baseline and a
experiment, e.g. a PR vs its base branch), inspired by the framework from Klees et al.
(2018). Each version is run N times for a fixed duration; this script aggregates those
runs and reports whether the experiment meaningfully changes coverage / exploration speed.

This is a port of the smite evaluation script
(https://github.com/Chand-ra/smite/blob/master/scripts/smite-evaluation.py): all of the
statistics, plots and the report are kept identical, only the input layer is changed to
read fuzzamoto's bench CSVs (`bench-cpu_NNN.csv`, emitted by the `bench` cargo feature via
`BenchStatsStage`) instead of AFL++ `plot_data`/`fuzzer_stats`/`fuzz_bitmap`.

bench-cpu_NNN.csv columns:
    elapsed_s,execs,execs_per_sec,coverage_pct,corpus_size,crashes

Multi-core: a campaign runs all cores, so each trial directory holds one CSV per core
(bench-cpu_000.csv, bench-cpu_001.csv, ...). They are aggregated into a single campaign
time series per trial - throughput (execs/s) is summed across cores, and coverage is the
element-wise max across cores (the cores share a corpus, so the max approximates the
campaign's union coverage).

Note vs. smite: true union coverage (smite's bitwise-AND over raw `fuzz_bitmap`s) is NOT
computed here - the bench CSV only carries a covered-edge *count* (`coverage_pct`), not
the raw coverage map. The cross-core max is used as a proxy. It can be made exact later by
dumping the map per run.

Requirements:
    pip install numpy pandas matplotlib seaborn scipy statsmodels tabulate

Expected directory structure:
    <root_dir>/
    ├── baseline/                 # config A
    │   └── ir/                    # target (scenario)
    │       ├── 1/                 # trial 1: one CSV per core
    │       │   ├── bench-cpu_000.csv
    │       │   └── bench-cpu_001.csv ...
    │       ├── 2/ ...
    │       └── ...                # any number of trials (automatically counted)
    └── experiment/                # config B
        └── ir/
            ├── 1/ ...
            └── ...

Output (written to --out, default <root_dir>/results):
    - evaluation_report.md   detailed Markdown report with summary stats, adjusted
                             p-values, effect sizes, an interpretation guide and plots
    - evaluation_metrics.csv full data table (raw p-values, IQRs, medians)
    - <target>_boxplot.png       box plots of final coverage distributions
    - <target>_auc_boxplot.png   box plots of AUC (exploration speed) distributions
    - <target>_time_series.png   median coverage over time with IQR bands

Usage:
    python benchmark-evaluation.py <root_dir> [--baseline baseline] [--experiment experiment]
                                   [--out <dir>] [--hours <hours>]

Examples:
    # Strict: requires all trials to have finished within 5% of each other
    python benchmark-evaluation.py results

    # Evaluate strictly up to 1 hour (fails if any trial ended before ~0.95h)
    python benchmark-evaluation.py results --hours 1

    # Force evaluation at the shortest common timeframe
    python benchmark-evaluation.py results --hours min
"""

import os
import glob
import argparse
import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")  # headless: no display in CI
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from statsmodels.stats.multitest import multipletests

# Apply clean visual styling for all generated plots
sns.set_style("whitegrid")

BENCH_GLOB = "bench-cpu_*.csv"  # one per core within a trial directory


def validate_and_find_data(root_dir, config_a, config_b):
    """
    Scans the root directory to find configs, targets, and trial paths.
    Throws errors if the structure doesn't match the expected layout.
    """
    if not os.path.exists(root_dir):
        raise FileNotFoundError(f"Root directory '{root_dir}' does not exist.")

    path_a = os.path.join(root_dir, config_a)
    path_b = os.path.join(root_dir, config_b)

    if not os.path.isdir(path_a):
        raise FileNotFoundError(
            f"Baseline configuration directory '{config_a}' not found in {root_dir}"
        )
    if not os.path.isdir(path_b):
        raise FileNotFoundError(
            f"Experiment configuration directory '{config_b}' not found in {root_dir}"
        )

    print(f"[*] Configurations: Baseline (A) = {config_a}, Experiment (B) = {config_b}")

    # Find targets
    targets_a = {d for d in os.listdir(path_a) if os.path.isdir(os.path.join(path_a, d))}
    targets_b = {d for d in os.listdir(path_b) if os.path.isdir(os.path.join(path_b, d))}

    if targets_a != targets_b:
        raise ValueError(
            f"Target mismatch! {config_a} has {targets_a}, but {config_b} has {targets_b}"
        )

    targets = sorted(targets_a)
    print(f"[*] Detected Targets: {targets}")

    data_paths = {config_a: {}, config_b: {}}

    # Validate trials and files
    for config in [config_a, config_b]:
        for target in targets:
            target_path = os.path.join(root_dir, config, target)
            trials = sorted(
                d
                for d in os.listdir(target_path)
                if os.path.isdir(os.path.join(target_path, d))
            )

            valid_trials = []
            for trial in trials:
                trial_dir = os.path.join(target_path, trial)
                if glob.glob(os.path.join(trial_dir, BENCH_GLOB)):
                    valid_trials.append(trial_dir)
                else:
                    print(
                        f"[!] Warning: no {BENCH_GLOB} in {trial_dir} "
                        f"(campaign may have died early). Skipping."
                    )

            data_paths[config][target] = valid_trials
            print(f"    - {config}/{target}: found {len(valid_trials)} valid trials")

    return targets, data_paths


def parse_core_csv(filepath):
    """
    Parses a single core's bench CSV.

    Returns (times_s, coverage_pct, execs, crashes) as arrays/scalar, or None if the file
    is empty/unreadable. Times are in seconds.
    """
    try:
        df = pd.read_csv(filepath)
    except Exception as e:  # noqa: BLE001 - tolerate truncated/empty CSVs
        print(f"[!] Warning: failed to read {filepath}: {e}")
        return None

    if len(df) == 0 or "elapsed_s" not in df.columns or "coverage_pct" not in df.columns:
        return None

    times = pd.to_numeric(df["elapsed_s"], errors="coerce").fillna(0).values
    coverage = pd.to_numeric(df["coverage_pct"], errors="coerce").fillna(0).values
    execs = pd.to_numeric(df["execs"], errors="coerce").fillna(0).values
    crashes = 0
    if "crashes" in df.columns:
        crashes = int(pd.to_numeric(df["crashes"], errors="coerce").fillna(0).values[-1])
    return times, coverage, execs, crashes


def parse_trial(trial_dir):
    """
    Aggregates all per-core CSVs in a trial directory into one campaign time series.

    Coverage is the element-wise max across cores (cores share a corpus, so the max
    approximates the campaign's union coverage); throughput is summed across cores.

    Returns (times_in_hours, coverage_pct, execs_per_sec, crashes) where execs_per_sec is
    the campaign-average total exec rate (sum over cores of total execs / elapsed) and
    crashes is the total final count across cores.
    """
    empty = (np.array([0.0]), np.array([0.0]), 0.0, 0)

    cores = []
    for f in sorted(glob.glob(os.path.join(trial_dir, BENCH_GLOB))):
        parsed = parse_core_csv(f)
        if parsed is not None and len(parsed[0]) > 0:
            cores.append(parsed)
    if not cores:
        return empty

    # Common time grid = sorted union of every core's snapshot times.
    grid = np.unique(np.concatenate([c[0] for c in cores]))

    # Coverage: max across cores (union proxy). Throughput: sum across cores.
    cov_stack = np.vstack(
        [np.interp(grid, times, cov, left=0.0) for (times, cov, _e, _c) in cores]
    )
    coverage = cov_stack.max(axis=0)

    total_execs_rate = 0.0
    total_crashes = 0
    for times, _cov, execs, crashes in cores:
        elapsed = times[-1]
        if elapsed > 0:
            total_execs_rate += execs[-1] / elapsed
        total_crashes += crashes

    return grid / 3600.0, coverage, total_execs_rate, total_crashes


def vargha_delaney_a12(u_stat, n_a, n_b):
    """Calculates the Vargha-Delaney A12 effect size."""
    if n_a == 0 or n_b == 0:
        return 0.5
    return u_stat / (n_a * n_b)


def resolve_eval_hours(
    target, global_min_hrs, global_max_hrs, requested_hours, tolerance=0.05
):
    """Enforces the tolerance limit and resolves the strict evaluation boundary."""
    threshold = 1.0 - tolerance
    tolerance_percentage = int(tolerance * 100)

    if requested_hours is None:
        if global_min_hrs < threshold * global_max_hrs:
            raise ValueError(
                f"[!] Fuzzer instability detected in target '{target}'. "
                f"Shortest trial ended at {global_min_hrs:.2f}h, max was {global_max_hrs:.2f}h. "
                f"This exceeds the {tolerance_percentage}% acceptable variance. "
                f"Run with --hours=min to force evaluation at the shortest common timeframe."
            )
        return global_min_hrs

    elif requested_hours.lower() == "min":
        return global_min_hrs

    else:
        try:
            target_hrs = float(requested_hours)
        except ValueError:
            raise ValueError(
                f"[!] Invalid --hours value: '{requested_hours}'. Must be a number or 'min'."
            )
        if global_min_hrs < threshold * target_hrs:
            raise ValueError(
                f"[!] Fuzzer instability detected in target '{target}'. "
                f"Shortest trial ended at {global_min_hrs:.2f}h, but requested evaluation time is {target_hrs:.2f}h. "
                f"This exceeds the {tolerance_percentage}% acceptable variance. "
                f"Run with --hours=min to force evaluation at the shortest common timeframe."
            )
        # Clamp to global_min_hrs to guarantee LOCF is never utilized
        return min(target_hrs, global_min_hrs)


def generate_plots(
    results_dir,
    target,
    eval_hours,
    grid_times,
    interpolated_series,
    cov_a,
    cov_b,
    auc_a,
    auc_b,
    config_a,
    config_b,
):
    """Generates and saves the Boxplots and Time Series charts for a target."""
    n_a, n_b = len(cov_a), len(cov_b)

    # --- Plotting 1: Final Coverage Boxplots ---
    plt.figure(figsize=(8, 6))
    sns.boxplot(data=[cov_a, cov_b], palette="Set2")
    plt.xticks([0, 1], [f"{config_a}\n(n={n_a})", f"{config_b}\n(n={n_b})"])
    plt.title(f"{target} - Final Coverage ({eval_hours:.2f}h)")
    plt.suptitle(
        "Box = Middle 50% (IQR), Line = Median, Whiskers = 1.5x IQR",
        fontsize=10,
        color="gray",
    )
    plt.ylabel("Coverage (%)")
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, f"{target}_boxplot.png"), dpi=300)
    plt.close()

    # --- Plotting 2: AUC Boxplots ---
    plt.figure(figsize=(8, 6))
    sns.boxplot(data=[auc_a, auc_b], palette="Set2")
    plt.xticks([0, 1], [f"{config_a}\n(n={n_a})", f"{config_b}\n(n={n_b})"])
    plt.title(f"{target} - Area Under Curve (AUC)")
    plt.suptitle(
        "Box = Middle 50% (IQR), Line = Median, Whiskers = 1.5x IQR",
        fontsize=10,
        color="gray",
    )
    plt.ylabel("Coverage (%) × Hours")
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, f"{target}_auc_boxplot.png"), dpi=300)
    plt.close()

    # --- Plotting 3: Median Coverage over Time with IQR Bands ---
    plt.figure(figsize=(10, 6))
    colors = {config_a: "blue", config_b: "orange"}

    for config in [config_a, config_b]:
        ts_matrix = np.array(interpolated_series[config])
        if ts_matrix.shape[0] == 0:
            continue

        med_line = np.median(ts_matrix, axis=0)
        p25 = np.percentile(ts_matrix, 25, axis=0)
        p75 = np.percentile(ts_matrix, 75, axis=0)

        label_str = f"{config} (n={len(interpolated_series[config])})"
        plt.plot(
            grid_times, med_line, label=label_str, color=colors[config], linewidth=2
        )
        plt.fill_between(grid_times, p25, p75, color=colors[config], alpha=0.2)

    plt.title(f"{target} - Median Coverage Over Time (with IQR bounds)")
    plt.xlabel("Time (Hours)")
    plt.ylabel("Coverage (%)")
    plt.xlim([0, eval_hours])
    plt.ylim(bottom=0)
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, f"{target}_time_series.png"), dpi=300)
    plt.close()


def write_evaluation_report(report_path, df_results, config_a, config_b, targets):
    """Writes the final comprehensive Markdown evaluation report."""

    def fmt(x, nd=3):
        """Format a numeric cell to nd decimals; pass non-numerics through unchanged."""
        if isinstance(x, bool):
            return str(x)
        if isinstance(x, (int, float, np.floating, np.integer)):
            return f"{float(x):.{nd}f}"
        return str(x)

    with open(report_path, "w") as f:
        f.write("# Fuzzing Evaluation Report\n\n")
        f.write(f"**Configuration A (Baseline):** `{config_a}`\n")
        f.write(f"**Configuration B (Experiment):** `{config_b}`\n\n")

        f.write("## 1. Summary Statistics\n\n")
        # A benchmark covers a single target, so a one-row-by-many-columns table reads
        # poorly. Present each target's metrics transposed, as a Baseline vs. Experiment
        # table, with the experiment-vs-baseline statistics in a second small table.
        for _, row in df_results.iterrows():
            if len(df_results) > 1:
                f.write(f"### {row['Target']}\n\n")
            f.write(
                f"Evaluation window: **{fmt(row['Duration (h)'])} h** · "
                f"trials: **{int(row['n (Baseline)'])}** baseline / "
                f"**{int(row['n (Exp.)'])}** experiment\n\n"
            )

            f.write("| Metric | Baseline | Experiment |\n")
            f.write("|---|---:|---:|\n")
            f.write(
                f"| Median final coverage (%) | {fmt(row['Median Cov. (Baseline)'])} "
                f"| {fmt(row['Median Cov. (Exp.)'])} |\n"
            )
            f.write(
                f"| Median AUC (coverage·h) | {fmt(row['Median AUC (Baseline)'])} "
                f"| {fmt(row['Median AUC (Exp.)'])} |\n"
            )
            f.write(
                f"| Median execs/s | {fmt(row['Execs/s (Baseline)'])} "
                f"| {fmt(row['Execs/s (Exp.)'])} |\n"
            )
            f.write(
                f"| Crashes (total) | {int(row['Crashes (Baseline)'])} "
                f"| {int(row['Crashes (Exp.)'])} |\n\n"
            )

            f.write("Experiment vs. baseline comparison:\n\n")
            f.write("| Statistic | Coverage | AUC (speed) |\n")
            f.write("|---|---:|---:|\n")
            f.write(
                f"| Adj. p-value | {fmt(row['Adj. p-value (Cov.)'])} "
                f"| {fmt(row['Adj. p-value (AUC)'])} |\n"
            )
            f.write(f"| Â12 | {fmt(row['Â12 (Cov.)'])} | {fmt(row['Â12 (AUC)'])} |\n\n")

        f.write(
            "*Raw P-values and Interquartile Ranges (IQRs) are available in "
            "`evaluation_metrics.csv`.*\n\n"
        )

        f.write("## 2. Interpretation Guide\n\n")
        f.write(
            "Use the comparison table above to objectively evaluate the experiment "
            "configuration.\n\n"
        )

        f.write("### Key Metrics\n\n")
        f.write(
            "- **`Adj. p-value`**: Mann-Whitney U test (Holm-Bonferroni adjusted). "
            "A value < 0.05 means the difference is unlikely to be noise.\n"
        )
        f.write(
            "- **`Â12`**: Probability that a random B (experiment) trial outperforms a random "
            "A (baseline) trial. `0.5` = no difference; `0.7` = B wins 70% of pairings. "
            "Always read alongside the p-value.\n"
        )
        f.write(
            "- **`IQR`**: Spread of the middle 50% of trials. A much larger IQR in B suggests "
            "a few outlier runs may be inflating the median.\n"
        )
        f.write(
            "- **`AUC`**: Coverage *speed* — how much was discovered and how early. "
            "Useful when final coverage is similar between configurations.\n"
        )
        f.write(
            "- **`Execs/s`**: A large drop in B without a coverage gain means the new feature "
            "is too expensive.\n"
        )
        f.write(
            "- **`Crashes`**: Total solutions saved across trials. Non-zero counts warrant "
            "manual inspection of the uploaded crash artifacts.\n\n"
        )

        f.write("### Reading the Results\n\n")
        f.write("| Adj. p | `Â12` | Conclusion |\n")
        f.write("|---|---|---|\n")
        f.write(
            "| < 0.05 | > 0.5 | Meaningful improvement. Check IQRs are comparable, then merge. |\n"
        )
        f.write(
            "| < 0.05 | ~0.5 | Significant but negligible. Check if worth the added complexity. |\n"
        )
        f.write(
            "| > 0.05 | > 0.6 | Promising but underpowered. Re-run with more trials (e.g., 50). |\n"
        )
        f.write(
            "| > 0.05 | ~0.5 | No effect. Try an advanced snapshot or ground-truth evaluation. |\n"
        )
        f.write(
            "| any | < 0.5 | B underperforms A. If significant, reject or redesign the feature. |\n\n"
        )

        f.write(
            "> **Time-series caveat:** If the IQR bands overlap for most of the campaign and "
            "only diverge near the end, treat the final-coverage result cautiously — late "
            "divergence may reflect noise rather than a sustained advantage.\n\n"
        )
        f.write(
            "> **Note:** Union coverage (the multi-core coverage ceiling) is not reported "
            "here, as the bench CSV records a covered-edge count rather than the raw coverage "
            "map.\n\n"
        )

        f.write("## 3. Visualizations\n\n")
        f.write(
            "*Note: In the box plots below, the central box represents the Interquartile Range (IQR, "
            "the middle 50% of trials), demonstrating the consistency of the fuzzer's performance. "
            "The internal line represents the median.*\n\n"
        )

        # Embed images directly into the markdown report
        for target in targets:
            f.write(f"### Target: {target}\n\n")

            f.write("#### Median Coverage Over Time\n\n")
            f.write(f"![{target} Time Series]({target}_time_series.png)\n\n")

            f.write("#### Distribution Comparisons\n\n")
            f.write("| Final Coverage | Area Under Curve (Speed) |\n")
            f.write("|:---:|:---:|\n")
            f.write(
                f"| ![{target} Boxplot]({target}_boxplot.png) | "
                f"![{target} AUC]({target}_auc_boxplot.png) |\n\n"
            )
            f.write("---\n\n")


def process_data(
    config_a, config_b, targets, data_paths, out_dir, requested_hours=None
):
    """Extracts metrics, computes statistics, and generates visualizations/reports."""
    results_dir = out_dir
    os.makedirs(results_dir, exist_ok=True)

    summary_stats = []
    p_values_cov_raw = []
    p_values_auc_raw = []

    for target in targets:
        print(f"\n[*] Processing Target: {target}")

        target_data = {config_a: {}, config_b: {}}
        raw_time_series = {config_a: [], config_b: []}

        global_max_hrs = 0.0
        global_min_hrs = float("inf")

        # Parse all data and find dynamic max and min times
        for config in [config_a, config_b]:
            target_data[config] = {
                "final_cov": [],
                "auc": [],
                "execs": [],
                "crashes": [],
            }

            for path in data_paths[config][target]:
                times, covs, execs, crashes = parse_trial(path)
                if len(times) > 0:
                    trial_end = times[-1]
                    global_max_hrs = max(global_max_hrs, trial_end)
                    global_min_hrs = min(global_min_hrs, trial_end)

                target_data[config]["execs"].append(execs)
                target_data[config]["crashes"].append(crashes)
                raw_time_series[config].append((times, covs))

        if global_min_hrs == float("inf"):
            print(f"[!] Insufficient data for {target}. Skipping stats.")
            continue

        # Enforce tolerance check and resolve eval_hours
        eval_hours = resolve_eval_hours(
            target, global_min_hrs, global_max_hrs, requested_hours, tolerance=0.05
        )

        grid_times = np.linspace(0, eval_hours, 1000)
        interpolated_series = {config_a: [], config_b: []}

        # Extract metrics, interpolate, and calculate standardized AUC
        for config in [config_a, config_b]:
            for times, covs in raw_time_series[config]:
                if len(times) == 0:
                    continue

                # Interpolate to standardize the time axis
                interp_cov = np.interp(grid_times, times, covs)
                interpolated_series[config].append(interp_cov)

                # Extract final coverage exactly at the normalized eval_hours boundary
                final_cov = interp_cov[-1]

                # Calculate standardized AUC over the uniform grid (coverage * hours)
                auc = np.trapezoid(y=interp_cov, x=grid_times)

                target_data[config]["final_cov"].append(final_cov)
                target_data[config]["auc"].append(auc)

        cov_a = target_data[config_a]["final_cov"]
        cov_b = target_data[config_b]["final_cov"]
        auc_a = target_data[config_a]["auc"]
        auc_b = target_data[config_b]["auc"]
        n_a, n_b = len(cov_a), len(cov_b)

        if n_a == 0 or n_b == 0:
            print(f"[!] Insufficient data for {target}. Skipping stats.")
            continue

        # Compute Statistics (Coverage)
        u_stat_cov, p_raw_cov = stats.mannwhitneyu(
            cov_b, cov_a, alternative="two-sided"
        )
        a12_cov = vargha_delaney_a12(u_stat_cov, n_b, n_a)
        p_values_cov_raw.append(p_raw_cov)

        # Compute Statistics (AUC)
        u_stat_auc, p_raw_auc = stats.mannwhitneyu(
            auc_b, auc_a, alternative="two-sided"
        )
        a12_auc = vargha_delaney_a12(u_stat_auc, n_b, n_a)
        p_values_auc_raw.append(p_raw_auc)

        summary_stats.append(
            {
                "Target": target,
                "Duration (h)": eval_hours,
                "n (Baseline)": n_a,
                "n (Exp.)": n_b,
                "Median Cov. (Baseline)": np.median(cov_a),
                "Median Cov. (Exp.)": np.median(cov_b),
                "IQR Cov. (Baseline)": stats.iqr(cov_a),
                "IQR Cov. (Exp.)": stats.iqr(cov_b),
                "Raw p-value (Cov.)": p_raw_cov,
                "Â12 (Cov.)": a12_cov,
                "Median AUC (Baseline)": np.median(auc_a),
                "Median AUC (Exp.)": np.median(auc_b),
                "IQR AUC (Baseline)": stats.iqr(auc_a),
                "IQR AUC (Exp.)": stats.iqr(auc_b),
                "Raw p-value (AUC)": p_raw_auc,
                "Â12 (AUC)": a12_auc,
                "Execs/s (Baseline)": np.median(target_data[config_a]["execs"]),
                "Execs/s (Exp.)": np.median(target_data[config_b]["execs"]),
                "Crashes (Baseline)": int(np.sum(target_data[config_a]["crashes"])),
                "Crashes (Exp.)": int(np.sum(target_data[config_b]["crashes"])),
            }
        )

        # Generate visual plots for this target
        generate_plots(
            results_dir,
            target,
            eval_hours,
            grid_times,
            interpolated_series,
            cov_a,
            cov_b,
            auc_a,
            auc_b,
            config_a,
            config_b,
        )

    # --- Multiple Comparisons Correction (Holm-Bonferroni) ---
    if len(p_values_cov_raw) > 0:
        reject_cov, p_adj_cov, _, _ = multipletests(
            p_values_cov_raw, alpha=0.05, method="holm"
        )
        reject_auc, p_adj_auc, _, _ = multipletests(
            p_values_auc_raw, alpha=0.05, method="holm"
        )

        for i, stat in enumerate(summary_stats):
            stat["Adj. p-value (Cov.)"] = p_adj_cov[i]
            stat["Sig_Cov"] = reject_cov[i]
            stat["Adj. p-value (AUC)"] = p_adj_auc[i]
            stat["Sig_AUC"] = reject_auc[i]

    # --- Generate Markdown Report & CSV Export ---
    if not summary_stats:
        print("[!] No data processed. Reports not generated.")
        return

    df_results = pd.DataFrame(summary_stats)

    # Save everything to CSV
    csv_path = os.path.join(results_dir, "evaluation_metrics.csv")
    df_results.to_csv(csv_path, index=False)

    report_path = os.path.join(results_dir, "evaluation_report.md")
    write_evaluation_report(report_path, df_results, config_a, config_b, targets)

    print(f"\n[*] Evaluation complete. Results saved to {results_dir}")
    print(f"    - Open {report_path} to interpret the campaign.")
    print(f"    - Metric data exported to {csv_path}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="fuzzamoto-libafl A/B Benchmark Evaluation Script"
    )
    parser.add_argument(
        "root_dir",
        type=str,
        help="Path to the evaluation root directory (contains the baseline/experiment subdirs).",
    )
    parser.add_argument(
        "--baseline",
        type=str,
        default="baseline",
        help="Name of the baseline configuration directory (default: 'baseline').",
    )
    parser.add_argument(
        "--experiment",
        type=str,
        default="experiment",
        help="Name of the experiment configuration directory (default: 'experiment').",
    )
    parser.add_argument(
        "--out",
        type=str,
        default=None,
        help="Output directory for the report/plots (default: <root_dir>/results).",
    )
    parser.add_argument(
        "--hours",
        type=str,
        default=None,
        help="Target duration in hours, or 'min' to enforce the shortest common timeframe.",
    )

    args = parser.parse_args()
    out_dir = args.out if args.out is not None else os.path.join(args.root_dir, "results")

    tgts, data = validate_and_find_data(args.root_dir, args.baseline, args.experiment)
    process_data(
        args.baseline,
        args.experiment,
        tgts,
        data,
        out_dir,
        args.hours,
    )
