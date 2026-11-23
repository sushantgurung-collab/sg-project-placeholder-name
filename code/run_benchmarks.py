"""
Benchmark Execution Runner for Cybersecurity Vulnerability XML Parsing.
Executes prompt engineering strategies across local LLMs:
  - Main Model: Qwen/Qwen2.5-1.5B-Instruct
  - Baseline Model: SmolLM2-1.7B-Instruct
Evaluates performance across the 2x2 Structural & Contextual Stress Matrix
and exports granular metrics to results/metrics.csv.
"""

from evaluator import evaluate_output
from prompts import build_prompt
import csv
import json
import os
import sys
import time
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

# Ensure script directory is in Python path for local module imports
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.append(script_dir)


def get_paths():
    """Returns dataset input path and metrics CSV output path relative to script."""
    base_dir = os.path.dirname(script_dir)
    dataset_path = os.path.join(base_dir, "data", "processed", "dataset.json")
    results_dir = os.path.join(base_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    metrics_path = os.path.join(results_dir, "metrics.csv")
    return dataset_path, metrics_path


def load_model_and_tokenizer(model_id: str):
    """Loads tokenizer and CausalLM model onto available torch device."""
    print(f"Loading model: {model_id}...")
    device = "cuda" if torch.cuda.is_available() else "cpu"

    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    if device == "cuda":
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float16,
            device_map="cuda",
            trust_remote_code=True,
        )
    else:
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float32,
            trust_remote_code=True,
        )

    return model, tokenizer, device


def generate_response(
    model, tokenizer, device, prompt_text: str, max_new_tokens: int = 300
) -> str:
    """Generates completion text from model prompt."""
    inputs = tokenizer(prompt_text, return_tensors="pt").to(device)
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=0.0,
            pad_token_id=tokenizer.pad_token_id,
        )
    input_len = inputs["input_ids"].shape[1]
    generated_tokens = outputs[0][input_len:]
    return tokenizer.decode(generated_tokens, skip_special_tokens=True).strip()


def run_benchmark_suite(sample_limit: int = 100):
    """Executes full evaluation benchmark suite across models and 2x2 matrix combinations."""
    dataset_path, output_csv = get_paths()

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            f"Processed dataset not found at {dataset_path}. Run code/dataset_curator.py first."
        )

    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)[:sample_limit]

    models_to_evaluate = [
        "Qwen/Qwen2.5-1.5B-Instruct",
        "HuggingFaceTB/SmolLM2-1.7B-Instruct",
    ]

    strategies = ["zero_shot", "system_constraint",
                  "few_shot_1", "few_shot_3", "cot"]
    schemas = ["flat", "nested"]

    fieldnames = [
        "model_name",
        "strategy",
        "schema_type",
        "sample_id",
        "cve_id",
        "context_density",
        "word_count",
        "valid_xml",
        "constraint_compliant",
        "precision",
        "recall",
        "f1_score",
        "latency_seconds",
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        csvfile.flush()

        for model_id in models_to_evaluate:
            model_short = "Qwen2.5-1.5B" if "Qwen" in model_id else "SmolLM2-1.7B"
            try:
                model, tokenizer, device = load_model_and_tokenizer(model_id)
            except Exception as e:
                print(f"Error loading {model_id}: {e}. Skipping model.")
                continue

            for strategy in strategies:
                for schema_type in schemas:
                    print(
                        f"Benchmarking: Model={model_short} | Strategy={strategy} | Schema={schema_type}"
                    )

                    for sample in dataset:
                        description = sample["description"]
                        target_gt = (
                            sample["ground_truth_flat_xml"]
                            if schema_type == "flat"
                            else sample["ground_truth_nested_xml"]
                        )

                        prompt = build_prompt(
                            strategy, description, schema_type)

                        start_time = time.time()
                        try:
                            raw_output = generate_response(
                                model, tokenizer, device, prompt
                            )
                        except Exception as gen_err:
                            print(
                                f"Generation error on sample {sample['sample_id']}: {gen_err}"
                            )
                            raw_output = ""
                        latency = round(time.time() - start_time, 3)

                        eval_results = evaluate_output(
                            raw_output, target_gt, sample["metadata"]
                        )

                        writer.writerow(
                            {
                                "model_name": model_short,
                                "strategy": strategy,
                                "schema_type": schema_type,
                                "sample_id": sample["sample_id"],
                                "cve_id": sample["cve_id"],
                                "context_density": sample["context_density"],
                                "word_count": sample["word_count"],
                                "valid_xml": eval_results["valid_xml"],
                                "constraint_compliant": eval_results[
                                    "constraint_compliant"
                                ],
                                "precision": eval_results["precision"],
                                "recall": eval_results["recall"],
                                "f1_score": eval_results["f1_score"],
                                "latency_seconds": latency,
                            }
                        )
                        csvfile.flush()  # Force write each row to disk immediately

            del model
            del tokenizer
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

    print(
        f"Benchmark Execution Complete. Metrics successfully exported to: {output_csv}"
    )


if __name__ == "__main__":
    run_benchmark_suite(sample_limit=2)
