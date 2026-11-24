# Comparative Evaluation of Prompt Engineering Strategies for Automated Parsing of Cybersecurity Vulnerabilities into Standardised GRC XML Schemas

## Overview
This project investigates the capability of lightweight local Large Language Models (LLMs) to perform structured information extraction from unstructured cybersecurity vulnerability descriptions without modifying model parameters. Specifically, it benchmarks prompt engineering techniques for transforming Common Vulnerabilities and Exposures (CVE) text into standardised Governance, Risk, and Compliance (GRC) XML schemas.

## Models Evaluated
- **Main Model:** `Qwen/Qwen2.5-1.5B-Instruct`
- **Baseline Model:** `HuggingFaceTB/SmolLM2-1.7B-Instruct`

## Experimental Setup
All prompt strategies are benchmarked across a **2x2 Structural & Contextual Stress Matrix**:
1. **Advisory Context Density:** Short (<100 words) vs. Long/Dense (>100 words) vulnerability descriptions.
2. **Target Output Complexity:** Flat XML Schema vs. Nested/Hierarchical XML Schema.

### Prompt Engineering Strategies Benchmark
1. Naive Zero-Shot
2. System & Constraint Enforced Prompting
3. Few-Shot In-Context Learning (1-shot & 3-shot)
4. Structured Chain-of-Thought (CoT)

## Directory Structure
sg-project/
├── report.pdf
├── report-source/
│   ├── main.tex
│   ├── references.bib
│   └── figures/
├── code/
│   ├── data_loader.py
│   ├── dataset_curator.py
│   ├── prompts.py
│   ├── evaluator.py
│   ├── run_benchmarks.py
│   └── plot_results.py
└── data/
├── original/
└── processed/
└── dataset.json

## Setup Instructions
1. Create and activate a Python virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate


Execution Environment Note:

The modular codebase was developed in Python 3 using VS Code. Due to local CPU compute constraints during unquantised LLM token generation, model inference (code/run_benchmarks.py / code/project.ipynb) was executed using PyTorch CUDA on a cloud-hosted NVIDIA T4 GPU via Google Colab. The resulting numerical evaluations were exported to results/metrics.csv for local analysis.

## Reproducibility & Execution Instructions

### Option 1: Full GPU Execution via Google Colab (Recommended)
Open `code/project.ipynb` in Google Colab, set runtime to **T4 GPU**, and execute all cells. 
* **Full Benchmark Suite (100 samples / 2,000 runs):** ~4 hours total runtime on T4 GPU.
* **Quick Verification Run (`sample_limit=10` / 200 runs):** ~20–25 minutes.

### Option 2: Local Python Execution (CPU/GPU Fallback)
Run the script locally from the repository root:
```bash
python code/run_benchmarks.py

Note: Local execution on CPU will take significantly longer. Set sample_limit=2 in run_benchmarks.py for a local verification test.