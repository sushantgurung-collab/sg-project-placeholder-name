"""
Visualisation and Metric Plotting Module for Cybersecurity Vulnerability XML Parsing.
Analyses results/metrics.csv and outputs publication-quality figures to report-source/figures/
and formatted LaTeX table strings for the final project report.
"""

import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Configure British English plot aesthetics and style
sns.set_theme(style="whitegrid", palette="muted")
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "figure.titlesize": 13,
})


def get_paths():
    """Returns absolute paths for metrics CSV input and figure output directory."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    metrics_path = os.path.join(base_dir, "results", "metrics.csv")
    figures_dir = os.path.join(base_dir, "report-source", "figures")
    os.makedirs(figures_dir, exist_ok=True)
    return metrics_path, figures_dir


def load_metrics(metrics_path: str) -> pd.DataFrame:
    """Loads metrics CSV into Pandas DataFrame with type conversions."""
    if not os.path.exists(metrics_path):
        raise FileNotFoundError(
            f"Metrics file not found at {metrics_path}. Execute Day 5 first.")

    df = pd.read_csv(metrics_path)
    # Convert boolean indicators to float percentages (0.0 to 100.0)
    df["valid_xml_pct"] = df["valid_xml"].astype(int) * 100.0
    df["constraint_compliant_pct"] = df["constraint_compliant"].astype(
        int) * 100.0
    return df


def plot_f1_by_strategy(df: pd.DataFrame, output_dir: str):
    """Generates grouped bar chart of Entity F1 Score across Prompt Strategies and Models."""
    plt.figure(figsize=(9, 5))

    strategy_order = ["zero_shot", "system_constraint",
                      "few_shot_1", "few_shot_3", "cot"]
    strategy_labels = ["Zero-Shot", "System Constraint",
                       "1-Shot ICL", "3-Shot ICL", "Chain-of-Thought"]

    ax = sns.barplot(
        data=df,
        x="strategy",
        y="f1_score",
        hue="model_name",
        order=strategy_order,
        ci=None,
        edgecolor="black",
        linewidth=0.8
    )

    plt.title("Entity Extraction F1-Score by Prompt Strategy and Model Architecture")
    plt.xlabel("Prompt Engineering Strategy")
    plt.ylabel("Mean Entity F1-Score (%)")
    plt.ylim(0, 105)
    plt.xticks(ticks=range(len(strategy_order)), labels=strategy_labels)
    plt.legend(title="Model Architecture", frameon=True)
    plt.tight_layout()

    fig_path = os.path.join(output_dir, "f1_score_by_strategy.png")
    plt.savefig(fig_path, dpi=300)
    plt.close()
    print(f"Saved figure: {fig_path}")


def plot_stress_matrix_heatmap(df: pd.DataFrame, output_dir: str):
    """Generates 2x2 heatmap showing F1-Score degradation across Context Density and Schema Types."""
    plt.figure(figsize=(8, 6))

    pivot = df.pivot_table(
        values="f1_score",
        index="context_density",
        columns="schema_type",
        aggfunc="mean"
    )

    sns.heatmap(
        pivot,
        annot=True,
        fmt=".1f",
        cmap="Blues",
        cbar_kws={"label": "Mean F1-Score (%)"},
        linewidths=1.5,
        linecolor="white",
        square=True
    )

    plt.title("2x2 Structural & Contextual Stress Matrix Performance Heatmap")
    plt.xlabel("Target XML Schema Complexity")
    plt.ylabel("Context Density")
    plt.tight_layout()

    fig_path = os.path.join(output_dir, "stress_matrix_heatmap.png")
    plt.savefig(fig_path, dpi=300)
    plt.close()
    print(f"Saved figure: {fig_path}")


def generate_latex_summary_table(df: pd.DataFrame):
    """Prints a formatted LaTeX table string summarizing benchmark performance for main.tex."""
    summary = df.groupby(["model_name", "strategy"]).agg({
        "valid_xml_pct": "mean",
        "constraint_compliant_pct": "mean",
        "precision": "mean",
        "recall": "mean",
        "f1_score": "mean",
        "latency_seconds": "mean"
    }).reset_index()

    print("\n" + "="*80)
    print("GENERATED LATEX TABLE FOR REPORT (report-source/main.tex)")
    print("="*80)

    latex_str = """\\begin{table}[htbp]
\\centering
\\caption{Comparative Evaluation of Prompt Engineering Strategies for Text-to-XML CVE Parsing.}
\\label{tab:benchmark_results}
\\resizebox{\\textwidth}{!}{%
\\begin{tabular}{llcccccc}
\\hline
\\textbf{Model} & \\textbf{Strategy} & \\textbf{XML Parse (\\%)} & \\textbf{Constraint (\\%)} & \\textbf{Precision} & \\textbf{Recall} & \\textbf{F1-Score} & \\textbf{Latency (s)} \\\\
\\hline"""

    for _, row in summary.iterrows():
        latex_str += f"\n{row['model_name']} & {row['strategy']} & {row['valid_xml_pct']:.1f}\\% & {row['constraint_compliant_pct']:.1f}\\% & {row['precision']:.1f} & {row['recall']:.1f} & {row['f1_score']:.1f} & {row['latency_seconds']:.2f} \\\\"

    latex_str += """\n\\hline
\\end{tabular}%
}
\\end{table}"""

    print(latex_str)
    print("="*80 + "\n")


def main():
    """Main execution block for Day 6 visualization pipeline."""
    metrics_path, output_dir = get_paths()
    print(f"Loading metrics from: {metrics_path}")
    df = load_metrics(metrics_path)

    print(f"Loaded {len(df)} evaluation records.")
    print("Rendering evaluation plots...")

    plot_f1_by_strategy(df, output_dir)
    plot_stress_matrix_heatmap(df, output_dir)
    generate_latex_summary_table(df)

    print("Visualisation Module execution complete.")


if __name__ == "__main__":
    main()
