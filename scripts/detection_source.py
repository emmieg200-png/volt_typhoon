"""
Question answered: What telemetry should defenders collect to detect Volt Typhoon?

Process: 
Volt Typhoon Techniques
        ↓
Match against ATT&CK JSON
        ↓
Extract Data Sources
        ↓
Count Frequencies


"""


import os
import json
import pandas as pd
import plotly.express as px


def get_attack_id(obj):
    """
    Pull the ATT&CK technique ID from an ATT&CK STIX object.
    Example: T1087, T1021.001
    """
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def create_detection_source_chart():
    # File paths
    csv_file = "volt_typhoon_techniques.csv"
    json_file = "enterprise-attack.json"

    # Load Volt Typhoon techniques
    vt_df = pd.read_csv(csv_file)

    # Keep only techniques used by Volt Typhoon
    vt_df = vt_df[vt_df["Used_by_VT"] == "Yes"].copy()

    # Get the ATT&CK IDs used by Volt Typhoon
    vt_attack_ids = set(vt_df["ATTACK_ID"].dropna().astype(str))

    # Load Enterprise ATT&CK JSON
    with open(json_file, "r", encoding="utf-8") as f:
        attack_data = json.load(f)

    objects = attack_data["objects"]

    # Create lookup tables
    object_lookup = {
        obj["id"]: obj
        for obj in objects
        if "id" in obj
    }

    # Map ATT&CK technique ID to STIX object ID
    technique_id_to_stix_id = {}

    for obj in objects:
        if obj.get("type") == "attack-pattern":
            attack_id = get_attack_id(obj)

            if attack_id:
                technique_id_to_stix_id[attack_id] = obj["id"]

    # Convert Volt Typhoon ATT&CK IDs to STIX IDs
    vt_stix_ids = {
        technique_id_to_stix_id[attack_id]
        for attack_id in vt_attack_ids
        if attack_id in technique_id_to_stix_id
    }

    # Find detection strategies that detect Volt Typhoon techniques
    detection_strategy_ids = []

    for obj in objects:
        if obj.get("type") == "relationship":
            if obj.get("relationship_type") == "detects":
                target_ref = obj.get("target_ref")

                if target_ref in vt_stix_ids:
                    detection_strategy_ids.append(obj.get("source_ref"))

    # Pull analytics from each detection strategy
    analytic_ids = []

    for strategy_id in detection_strategy_ids:
        strategy_obj = object_lookup.get(strategy_id, {})

        analytic_refs = strategy_obj.get("x_mitre_analytic_refs", [])

        analytic_ids.extend(analytic_refs)

    # Pull data components from analytics
    data_component_ids = []

    for analytic_id in analytic_ids:
        analytic_obj = object_lookup.get(analytic_id, {})

        log_sources = analytic_obj.get("x_mitre_log_source_references", [])

        for log_source in log_sources:
            component_id = log_source.get("x_mitre_data_component_ref")

            if component_id:
                data_component_ids.append(component_id)

    # Convert data component IDs to readable names
    data_component_names = []

    for component_id in data_component_ids:
        component_obj = object_lookup.get(component_id, {})

        component_name = component_obj.get("name")

        if component_name:
            data_component_names.append(component_name)

    # Count data components
    source_counts = (
        pd.Series(data_component_names)
        .value_counts()
        .reset_index()
    )

    source_counts.columns = ["Detection Data Component", "Count"]

    # Keep top 15 so the chart stays readable
    source_counts = source_counts.head(15)

    # Sort for horizontal bar chart
    source_counts = source_counts.sort_values("Count", ascending=True)

    fig = px.bar(
        source_counts,
        x="Count",
        y="Detection Data Component",
        orientation="h",
        text="Count",
        title="Detection Data Sources for Volt Typhoon Techniques"
    )

    fig.update_traces(textposition="outside")

    fig.update_layout(
        template="plotly_white",
        height=650,
        xaxis_title="Number of Detection References",
        yaxis_title="Detection Data Component",
        showlegend=False,
        margin=dict(l=260, r=80, t=80, b=60)
    )

    return fig, source_counts


if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    fig, source_counts = create_detection_source_chart()

    fig.write_html(
        "outputs/volt_typhoon_detection_sources.html",
        include_plotlyjs="cdn"
    )

    source_counts.to_csv(
        "outputs/volt_typhoon_detection_sources.csv",
        index=False
    )

    fig.show()