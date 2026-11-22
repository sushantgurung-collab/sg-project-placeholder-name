"""
Prompt Engineering Module for Cybersecurity Vulnerability XML Parsing.
Defines template generators for 4 distinct prompting strategies across 
Flat and Nested XML targets.
"""

from typing import Dict, Any


def get_naive_zero_shot_prompt(description: str, schema_type: str = "flat") -> str:
    """Generates a Naive Zero-Shot prompt."""
    if schema_type == "flat":
        schema_desc = (
            "Extract the following XML fields: <cve_id>, <severity>, "
            "<affected_asset>, <nist_control>, and <mitigation>. Wrap in <advisory>."
        )
    else:
        schema_desc = (
            "Extract into a nested XML schema: <advisory id='...'> containing "
            "<vulnerability severity='...'> with <affected_asset>, <compliance> with "
            "<nist_control id='...'>, and <remediation> with <action>."
        )

    return f"Convert the following cybersecurity advisory into XML.\n\n{schema_desc}\n\nAdvisory Text:\n{description}\n\nXML Output:"


def get_system_constraint_prompt(description: str, schema_type: str = "flat") -> str:
    """Generates a System & Constraint Enforced prompt."""
    if schema_type == "flat":
        schema_template = (
            "<advisory>\n"
            "  <cve_id>CVE-YYYY-XXXX</cve_id>\n"
            "  <severity>CRITICAL|HIGH|MEDIUM|LOW</severity>\n"
            "  <affected_asset>Asset Name</affected_asset>\n"
            "  <nist_control>CONTROL-ID</nist_control>\n"
            "  <mitigation>Mitigation step</mitigation>\n"
            "</advisory>"
        )
    else:
        schema_template = (
            '<advisory id="CVE-YYYY-XXXX">\n'
            '  <vulnerability severity="CRITICAL|HIGH|MEDIUM|LOW">\n'
            "    <affected_asset>Asset Name</affected_asset>\n"
            "  </vulnerability>\n"
            "  <compliance>\n"
            '    <nist_control id="CONTROL-ID" />\n'
            "  </compliance>\n"
            "  <remediation>\n"
            "    <action>Mitigation step</action>\n"
            "  </remediation>\n"
            "</advisory>"
        )

    return (
        "SYSTEM INSTRUCTION:\n"
        "You are an automated GRC cybersecurity information extraction parser. "
        "Your task is to transform unstructured text into valid XML strictly adhering to the schema below. "
        "CONSTRAINTS:\n"
        "1. Output RAW valid XML ONLY. Do not include markdown code block markers (```xml), preambles, or explanations.\n"
        "2. All tags must be correctly opened and closed.\n"
        "3. If a field is missing, use 'UNKNOWN'.\n\n"
        f"TARGET SCHEMA TEMPLATE:\n{schema_template}\n\n"
        f"INPUT ADVISORY:\n{description}\n\n"
        "PARSED XML:"
    )


def get_few_shot_prompt(
    description: str, schema_type: str = "flat", shot_count: int = 1
) -> str:
    """Generates a Few-Shot In-Context Learning prompt (1-shot or 3-shot)."""
    system_base = get_system_constraint_prompt(
        description="", schema_type=schema_type)

    shot_1 = (
        "EXAMPLE 1:\n"
        "Input: Critical flaw in authentication module allows privilege escalation. Reference CVE-2024-1001. Control PR.AC-6. Apply vendor patch.\n"
        "Output:\n"
        + (
            "<advisory>\n  <cve_id>CVE-2024-1001</cve_id>\n  <severity>CRITICAL</severity>\n  <affected_asset>Authentication Module</affected_asset>\n  <nist_control>PR.AC-6</nist_control>\n  <mitigation>Apply vendor patch.</mitigation>\n</advisory>"
            if schema_type == "flat"
            else '<advisory id="CVE-2024-1001">\n  <vulnerability severity="CRITICAL">\n    <affected_asset>Authentication Module</affected_asset>\n  </vulnerability>\n  <compliance>\n    <nist_control id="PR.AC-6" />\n  </compliance>\n  <remediation>\n    <action>Apply vendor patch.</action>\n  </remediation>\n</advisory>'
        )
    )

    shot_2 = (
        "\n\nEXAMPLE 2:\n"
        "Input: High severity buffer overflow in network daemon API endpoint. Tracking id CVE-2024-1002, control DE.CM-1. Restrict port access.\n"
        "Output:\n"
        + (
            "<advisory>\n  <cve_id>CVE-2024-1002</cve_id>\n  <severity>HIGH</severity>\n  <affected_asset>Network Daemon</affected_asset>\n  <nist_control>DE.CM-1</nist_control>\n  <mitigation>Restrict port access.</mitigation>\n</advisory>"
            if schema_type == "flat"
            else '<advisory id="CVE-2024-1002">\n  <vulnerability severity="HIGH">\n    <affected_asset>Network Daemon</affected_asset>\n  </vulnerability>\n  <compliance>\n    <nist_control id="DE.CM-1" />\n  </compliance>\n  <remediation>\n    <action>Restrict port access.</action>\n  </remediation>\n</advisory>'
        )
    )

    shot_3 = (
        "\n\nEXAMPLE 3:\n"
        "Input: Medium risk XSS in user profile API. CVE-2024-1003, control PR.DS-5. Enable input validation.\n"
        "Output:\n"
        + (
            "<advisory>\n  <cve_id>CVE-2024-1003</cve_id>\n  <severity>MEDIUM</severity>\n  <affected_asset>User Profile API</affected_asset>\n  <nist_control>PR.DS-5</nist_control>\n  <mitigation>Enable input validation.</mitigation>\n</advisory>"
            if schema_type == "flat"
            else '<advisory id="CVE-2024-1003">\n  <vulnerability severity="MEDIUM">\n    <affected_asset>User Profile API</affected_asset>\n  </vulnerability>\n  <compliance>\n    <nist_control id="PR.DS-5" />\n  </compliance>\n  <remediation>\n    <action>Enable input validation.</action>\n  </remediation>\n</advisory>'
        )
    )

    exemplars = shot_1 if shot_count == 1 else f"{shot_1}{shot_2}{shot_3}"

    return f"{system_base}\n\nEXEMPLARS:\n{exemplars}\n\nINPUT ADVISORY:\n{description}\n\nPARSED XML:"


def get_chain_of_thought_prompt(description: str, schema_type: str = "flat") -> str:
    """Generates a Structured Chain-of-Thought (CoT) prompt."""
    system_base = get_system_constraint_prompt(
        description="", schema_type=schema_type)
    return (
        f"{system_base}\n\n"
        "INSTRUCTION: Perform step-by-step entity extraction first inside a <reasoning> tag, "
        "identifying CVE ID, Severity, Affected Asset, NIST Control, and Mitigation. "
        "Then provide the final valid XML inside an <xml> tag block.\n\n"
        f"INPUT ADVISORY:\n{description}\n\n"
        "REASONING AND PARSED XML:"
    )


def build_prompt(
    strategy: str, description: str, schema_type: str = "flat"
) -> str:
    """Factory function routing strategy selection."""
    if strategy == "zero_shot":
        return get_naive_zero_shot_prompt(description, schema_type)
    elif strategy == "system_constraint":
        return get_system_constraint_prompt(description, schema_type)
    elif strategy == "few_shot_1":
        return get_few_shot_prompt(description, schema_type, shot_count=1)
    elif strategy == "few_shot_3":
        return get_few_shot_prompt(description, schema_type, shot_count=3)
    elif strategy == "cot":
        return get_chain_of_thought_prompt(description, schema_type)
    else:
        raise ValueError(f"Unknown prompting strategy: {strategy}")
