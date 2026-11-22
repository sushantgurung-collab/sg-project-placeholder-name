"""
Automated Evaluation Pipeline for Cybersecurity Vulnerability XML Parsing.
Evaluates model outputs across three core metrics:
  1. XML Syntactic Parse Rate (%) via xml.etree.ElementTree
  2. Entity Extraction F1 Score (%) comparing extracted tags to ground truth
  3. Constraint Compliance Rate (%) via regex checks for unwanted preambles
"""

import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, Tuple


def check_xml_syntax(raw_output: str) -> Tuple[bool, str]:
    """
    Parses raw LLM output using xml.etree.ElementTree to verify structural validity.
    Returns a tuple of (is_valid, cleaned_xml_str).
    """
    if not raw_output or not raw_output.strip():
        return False, ""

    # Extract content inside <advisory> tags if present
    match = re.search(
        r"<advisory[\s\S]*?</advisory>", raw_output, re.IGNORECASE)
    candidate_xml = match.group(0) if match else raw_output.strip()

    try:
        ET.fromstring(candidate_xml)
        return True, candidate_xml
    except ET.ParseError:
        return False, candidate_xml


def check_constraint_compliance(raw_output: str) -> bool:
    """
    Checks if output strictly complies with prompt formatting rules:
    - Zero conversational preambles/postambles outside XML/reasoning blocks
    - No markdown backtick markers (e.g. ```xml)
    """
    if re.search(r"```", raw_output):
        return False

    cleaned = re.sub(
        r"<(advisory|reasoning)[\s\S]*?</\1>", "", raw_output, flags=re.IGNORECASE
    ).strip()
    return len(cleaned) == 0


def extract_entities_from_xml(xml_str: str) -> Dict[str, str]:
    """
    Extracts key entity values from parsed XML string for comparison.
    Supports both Flat and Hierarchical/Nested XML schemas.
    """
    entities = {
        "cve_id": "UNKNOWN",
        "severity": "UNKNOWN",
        "affected_asset": "UNKNOWN",
        "nist_control": "UNKNOWN",
        "mitigation": "UNKNOWN",
    }

    try:
        root = ET.fromstring(xml_str)

        # Root attribute checks (Nested schema cve_id)
        if "id" in root.attrib:
            entities["cve_id"] = root.attrib["id"]

        # Tag searches (Flat & Nested schemas)
        for elem in root.iter():
            tag_name = elem.tag.lower()
            if tag_name == "cve_id" and elem.text:
                entities["cve_id"] = elem.text.strip()
            elif tag_name == "severity" and elem.text:
                entities["severity"] = elem.text.strip()
            elif tag_name == "vulnerability" and "severity" in elem.attrib:
                entities["severity"] = elem.attrib["severity"]
            elif tag_name == "affected_asset" and elem.text:
                entities["affected_asset"] = elem.text.strip()
            elif tag_name == "nist_control":
                if elem.text:
                    entities["nist_control"] = elem.text.strip()
                elif "id" in elem.attrib:
                    entities["nist_control"] = elem.attrib["id"]
            elif tag_name in ("mitigation", "action") and elem.text:
                entities["mitigation"] = elem.text.strip()

    except ET.ParseError:
        pass

    return entities


def compute_entity_f1(
    extracted: Dict[str, str], ground_truth: Dict[str, str]
) -> Tuple[float, float, float]:
    """
    Calculates Precision, Recall, and F1 score for extracted entities.
    """
    keys = ["cve_id", "severity", "affected_asset",
            "nist_control", "mitigation"]
    true_positives = 0
    false_positives = 0
    false_negatives = 0

    for key in keys:
        ext_val = extracted.get(key, "UNKNOWN").strip().lower()
        gt_val = ground_truth.get(key, "UNKNOWN").strip().lower()

        if ext_val != "unknown" and ext_val == gt_val:
            true_positives += 1
        elif ext_val != "unknown" and ext_val != gt_val:
            false_positives += 1
        elif ext_val == "unknown" and gt_val != "unknown":
            false_negatives += 1

    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0
        else 0.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if (true_positives + false_negatives) > 0
        else 0.0
    )
    f1 = (
        2 * (precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return round(precision * 100, 2), round(recall * 100, 2), round(f1 * 100, 2)


def evaluate_output(
    raw_output: str, ground_truth_xml: str, target_metadata: Dict[str, str]
) -> Dict[str, Any]:
    """
    Main evaluation pipeline function combining all 3 metrics.
    """
    is_valid_xml, cleaned_xml = check_xml_syntax(raw_output)
    is_compliant = check_constraint_compliance(raw_output)

    extracted_entities = (
        extract_entities_from_xml(cleaned_xml) if is_valid_xml else {}
    )
    precision, recall, f1 = compute_entity_f1(
        extracted_entities, target_metadata)

    return {
        "valid_xml": is_valid_xml,
        "constraint_compliant": is_compliant,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "extracted_entities": extracted_entities,
    }


if __name__ == "__main__":
    # Self-test evaluation pipeline with a sample output
    sample_output = (
        "<advisory>\n"
        "  <cve_id>CVE-2024-10000</cve_id>\n"
        "  <severity>CRITICAL</severity>\n"
        "  <affected_asset>Authentication Module</affected_asset>\n"
        "  <nist_control>PR.AC-6</nist_control>\n"
        "  <mitigation>Apply vendor patch immediately.</mitigation>\n"
        "</advisory>"
    )
    sample_meta = {
        "cve_id": "CVE-2024-10000",
        "severity": "CRITICAL",
        "affected_asset": "Authentication Module",
        "nist_control": "PR.AC-6",
        "mitigation": "Apply vendor patch immediately.",
    }

    results = evaluate_output(sample_output, sample_output, sample_meta)
    print("Evaluator Module Self-Test Output:")
    print(f"Valid XML Parse: {results['valid_xml']}")
    print(f"Constraint Compliant: {results['constraint_compliant']}")
    print(f"Entity F1 Score: {results['f1_score']}%")
