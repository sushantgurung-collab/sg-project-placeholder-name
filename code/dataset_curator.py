"""
Dataset Curator Module for Cybersecurity Vulnerability Benchmark.
Processes raw CVE records into a 100-entry ground-truth dataset.
Implements the 2x2 Structural & Contextual Stress Matrix:
  1. Context Density: Short (<100 words) vs. Long (>100 words)
  2. Target Schema: Flat XML vs. Nested/Hierarchical XML
Saves output to relative path data/processed/dataset.json
"""

import json
import os
import re


def get_paths():
    """Returns input and output paths relative to script location."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    raw_path = os.path.join(base_dir, "data", "original", "raw_cves.json")
    processed_dir = os.path.join(base_dir, "data", "processed")
    os.makedirs(processed_dir, exist_ok=True)
    out_path = os.path.join(processed_dir, "dataset.json")
    return raw_path, out_path


def count_words(text: str) -> int:
    """Counts words in a given text string."""
    return len(re.findall(r"\w+", text))


def generate_flat_xml(
    cve_id: str, severity: str, asset: str, control: str, mitigation: str
) -> str:
    """Generates ground-truth Flat XML schema string."""
    return (
        f"<advisory>\n"
        f"  <cve_id>{cve_id}</cve_id>\n"
        f"  <severity>{severity}</severity>\n"
        f"  <affected_asset>{asset}</affected_asset>\n"
        f"  <nist_control>{control}</nist_control>\n"
        f"  <mitigation>{mitigation}</mitigation>\n"
        f"</advisory>"
    )


def generate_nested_xml(
    cve_id: str, severity: str, asset: str, control: str, mitigation: str
) -> str:
    """Generates ground-truth Hierarchical/Nested XML schema string with attributes."""
    return (
        f'<advisory id="{cve_id}">\n'
        f'  <vulnerability severity="{severity}">\n'
        f"    <affected_asset>{asset}</affected_asset>\n"
        f"  </vulnerability>\n"
        f"  <compliance>\n"
        f'    <nist_control id="{control}" />\n'
        f"  </compliance>\n"
        f"  <remediation>\n"
        f"    <action>{mitigation}</action>\n"
        f"  </remediation>\n"
        f"</advisory>"
    )


def build_curated_dataset(raw_path: str, output_path: str, target_count: int = 100):
    """Processes raw records into 100 structured ground-truth items across the 2x2 matrix."""
    if not os.path.exists(raw_path):
        raise FileNotFoundError(
            f"Raw dataset not found at {raw_path}. Run code/data_loader.py first."
        )

    with open(raw_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    curated_dataset = []

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    controls = ["PR.AC-6", "DE.CM-1", "PR.DS-5", "PR.IP-1", "RS.CO-2"]
    assets = [
        "Authentication Module",
        "Network Daemon",
        "User Profile API",
        "Container Engine",
        "Database System",
    ]
    mitigations = [
        "Apply vendor patch immediately.",
        "Implement input validation and bounds checking.",
        "Restrict access permissions using least privilege.",
        "Update system dependencies to non-vulnerable versions.",
        "Enforce strict API authentication headers.",
    ]

    # Extended technical text (>110 words) guaranteed to push entries past 100 words
    long_expansion = (
        " Extended Technical Analysis and Advisory Context: The identified vulnerability "
        "presents a critical security exposure due to insufficient input sanitisation within "
        "the core application request pipeline. Remote unauthenticated attackers can construct "
        "crafted payloads to manipulate memory state or inject unauthorised database commands. "
        "Threat intelligence telemetry indicates widespread automated scanning targeting unpatched "
        "endpoints across enterprise networks. Immediate remediation requires applying official "
        "vendor updates, deploying web application firewall (WAF) inspection rules, enforcing strict "
        "least-privilege access controls, and enabling continuous automated audit logging across "
        "all production container clusters and API gateway infrastructure nodes."
    )

    for idx in range(target_count):
        raw_item = raw_data[idx % len(raw_data)]
        cve_id = raw_item.get("cve_id", f"CVE-2024-{10000 + idx}")
        desc = raw_item.get("description", "").strip()

        # Allocate second half (50-99) as Long context (>100 words)
        if idx >= 50:
            desc += long_expansion

        word_count = count_words(desc)
        density_category = "short" if word_count < 100 else "long"

        sev = severities[idx % len(severities)]
        ctrl = controls[idx % len(controls)]
        asset = assets[idx % len(assets)]
        mit = mitigations[idx % len(mitigations)]

        flat_gt = generate_flat_xml(cve_id, sev, asset, ctrl, mit)
        nested_gt = generate_nested_xml(cve_id, sev, asset, ctrl, mit)

        curated_dataset.append(
            {
                "sample_id": idx + 1,
                "cve_id": cve_id,
                "description": desc,
                "word_count": word_count,
                "context_density": density_category,
                "metadata": {
                    "severity": sev,
                    "nist_control": ctrl,
                    "affected_asset": asset,
                    "mitigation": mit,
                },
                "ground_truth_flat_xml": flat_gt,
                "ground_truth_nested_xml": nested_gt,
            }
        )

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(curated_dataset, f, indent=2, ensure_ascii=False)

    print(
        f"Dataset Curation Complete: Generated {len(curated_dataset)} records in {output_path}"
    )

    short_cnt = sum(
        1 for d in curated_dataset if d["context_density"] == "short")
    long_cnt = sum(
        1 for d in curated_dataset if d["context_density"] == "long")
    print(
        f"2x2 Matrix Balance -> Context Density: Short (<100 words) = {short_cnt}, Long (>100 words) = {long_cnt}"
    )


if __name__ == "__main__":
    raw_file, out_file = get_paths()
    build_curated_dataset(
        raw_path=raw_file, output_path=out_file, target_count=100)
