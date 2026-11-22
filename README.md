# Comparative Evaluation of Prompt Engineering Strategies for Automated Parsing of Cybersecurity Vulnerabilities into Standardised GRC XML Schemas

**Student Name:** Sushant  
**Registration Number:** sg26581  
**Module:** CE893-7-AU-CO - Generative Artificial Intelligence (Academic Year 2026–27)  
**Instructor:** Giorgia Minello  

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
sg26581-project/
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