"""
Research Question:
What telemetry sources should defenders collect to detect Volt Typhoon activity?

This script traces Volt Typhoon techniques through the ATT&CK framework
to identify which ATT&CK data components (telemetry sources) are most
commonly associated with detecting those techniques.

Workflow:
Volt Typhoon Techniques
        ↓
ATT&CK Techniques
        ↓
Detection Strategies
        ↓
Analytics
        ↓
Data Components
        ↓
Frequency Count
        ↓
Detection Sources Chart
"""

# Provides functions for creating folders and managing file paths.
import os

# Used to load the ATT&CK Enterprise JSON dataset.
import json

# Used for data manipulation, filtering, counting, and exporting results.
import pandas as pd

# Used to create the interactive horizontal bar chart.
import plotly.express as px


def get_attack_id(obj):
    """
    Extract the ATT&CK technique ID from a STIX attack-pattern object.

    Example:
        T1087
        T1021.001

    These IDs serve as the link between the Volt Typhoon CSV
    and the ATT&CK Enterprise dataset.
    """

    # Search through all external references attached to the object.
    for ref in obj.get("external_references", []):

        # ATT&CK technique IDs are stored in references whose
        # source name equals 'mitre-attack'.
        if ref.get("source_name") == "mitre-attack":

            # Return the ATT&CK ID.
            return ref.get("external_id")

    # Return None if no ATT&CK ID is found.
    return None


def create_detection_source_chart():

    # -----------------------------
    # Define Input Files
    # -----------------------------

    # CSV created earlier containing all ATT&CK techniques
    # and whether Volt Typhoon uses them.
    csv_file = "volt_typhoon_techniques.csv"

    # ATT&CK Enterprise JSON dataset containing relationships,
    # detection strategies, analytics, and data components.
    json_file = "enterprise-attack.json"


    # -----------------------------
    # Load Volt Typhoon Techniques
    # -----------------------------

    # Read the Volt Typhoon technique CSV into a dataframe.
    vt_df = pd.read_csv(csv_file)

    # Keep only techniques confirmed to be used by Volt Typhoon.
    # This narrows the analysis to the threat actor of interest.
    vt_df = vt_df[vt_df["Used_by_VT"] == "Yes"].copy()

    # Create a set of ATT&CK IDs used by Volt Typhoon.
    # Sets provide fast lookups later in the script.
    vt_attack_ids = set(
        vt_df["ATTACK_ID"]
        .dropna()
        .astype(str)
    )


    # -----------------------------
    # Load ATT&CK Enterprise Dataset
    # -----------------------------

    # Open ATT&CK JSON file.
    with open(json_file, "r", encoding="utf-8") as f:

        # Load JSON into a Python dictionary.
        attack_data = json.load(f)

    # Extract the list of ATT&CK STIX objects.
    objects = attack_data["objects"]


    # -----------------------------
    # Create Lookup Tables
    # -----------------------------

    # Create a dictionary where:
    #
    # key   = STIX object ID
    # value = full ATT&CK object
    #
    # This allows instant retrieval of objects later.
    object_lookup = {
        obj["id"]: obj
        for obj in objects
        if "id" in obj
    }


    # -----------------------------
    # Map ATT&CK IDs to STIX IDs
    # -----------------------------

    # ATT&CK techniques use human-readable IDs (T1078),
    # while ATT&CK relationships use STIX IDs.
    #
    # This dictionary links the two together.
    technique_id_to_stix_id = {}

    for obj in objects:

        # Only techniques are attack-pattern objects.
        if obj.get("type") == "attack-pattern":

            # Extract ATT&CK ID.
            attack_id = get_attack_id(obj)

            if attack_id:

                # Store mapping:
                #
                # T1078 → attack-pattern--xxxxx
                technique_id_to_stix_id[attack_id] = obj["id"]


    # -----------------------------
    # Convert Volt Typhoon IDs
    # -----------------------------

    # Convert Volt Typhoon ATT&CK IDs into STIX IDs.
    #
    # This is necessary because ATT&CK relationships
    # reference STIX IDs, not ATT&CK IDs.
    vt_stix_ids = {
        technique_id_to_stix_id[attack_id]
        for attack_id in vt_attack_ids
        if attack_id in technique_id_to_stix_id
    }


    # -----------------------------
    # Find Detection Strategies
    # -----------------------------

    # ATT&CK detection strategies describe how defenders
    # can identify a technique.
    detection_strategy_ids = []

    for obj in objects:

        # Relationships connect ATT&CK objects together.
        if obj.get("type") == "relationship":

            # We only care about "detects" relationships.
            if obj.get("relationship_type") == "detects":

                # The target is the technique being detected.
                target_ref = obj.get("target_ref")

                # If the relationship targets a Volt Typhoon technique,
                # keep the detection strategy.
                if target_ref in vt_stix_ids:

                    detection_strategy_ids.append(
                        obj.get("source_ref")
                    )


    # -----------------------------
    # Find Analytics
    # -----------------------------

    # Detection strategies reference analytics.
    #
    # Analytics are ATT&CK's specific detection logic
    # that describe what should be monitored.
    analytic_ids = []

    for strategy_id in detection_strategy_ids:

        # Retrieve detection strategy object.
        strategy_obj = object_lookup.get(strategy_id, {})

        # Extract referenced analytics.
        analytic_refs = strategy_obj.get(
            "x_mitre_analytic_refs",
            []
        )

        # Add analytics to master list.
        analytic_ids.extend(analytic_refs)


    # -----------------------------
    # Find Data Components
    # -----------------------------

    # Data components are the actual telemetry sources
    # required to implement the analytics.
    #
    # Examples:
    # Process Creation
    # Command Execution
    # Network Traffic Content
    # User Authentication

    data_component_ids = []

    for analytic_id in analytic_ids:

        # Retrieve analytic object.
        analytic_obj = object_lookup.get(analytic_id, {})

        # Extract ATT&CK log source references.
        log_sources = analytic_obj.get(
            "x_mitre_log_source_references",
            []
        )

        for log_source in log_sources:

            # Pull referenced data component.
            component_id = log_source.get(
                "x_mitre_data_component_ref"
            )

            if component_id:
                data_component_ids.append(component_id)


    # -----------------------------
    # Convert IDs to Names
    # -----------------------------

    # Data component IDs are not human-readable.
    # Convert them into names for chart labels.
    data_component_names = []

    for component_id in data_component_ids:

        # Retrieve data component object.
        component_obj = object_lookup.get(
            component_id,
            {}
        )

        # Extract readable name.
        component_name = component_obj.get("name")

        if component_name:
            data_component_names.append(component_name)


    # -----------------------------
    # Count Frequencies
    # -----------------------------

    # Count how many times each data component appears.
    #
    # Higher counts suggest telemetry sources that
    # support detection of a larger portion of
    # Volt Typhoon techniques.
    source_counts = (
        pd.Series(data_component_names)
        .value_counts()
        .reset_index()
    )

    # Rename columns for readability.
    source_counts.columns = [
        "Detection Data Component",
        "Count"
    ]


    # -----------------------------
    # Keep Top 15 Sources
    # -----------------------------

    # Limiting the chart prevents overcrowding and
    # highlights the most important telemetry sources.
    source_counts = source_counts.head(15)


    # -----------------------------
    # Sort for Horizontal Bar Chart
    # -----------------------------

    # Smallest values appear at bottom,
    # largest values at top.
    source_counts = source_counts.sort_values(
        "Count",
        ascending=True
    )


    # -----------------------------
    # Build Chart
    # -----------------------------

    # Create horizontal bar chart showing
    # the most important ATT&CK detection sources
    # for Volt Typhoon techniques.
    fig = px.bar(
        source_counts,
        x="Count",
        y="Detection Data Component",
        orientation="h",
        text="Count",
        title="Detection Data Sources for Volt Typhoon Techniques"
    )

    # Display count labels on each bar.
    fig.update_traces(textposition="outside")

    # Improve appearance and readability.
    fig.update_layout(
        template="plotly_white",
        height=650,
        xaxis_title="Number of Detection References",
        yaxis_title="Detection Data Component",
        showlegend=False,
        margin=dict(l=260, r=80, t=80, b=60)
    )

    # Return chart and underlying data.
    return fig, source_counts


# -----------------------------
# Main Program
# -----------------------------

if __name__ == "__main__":

    # Create output folder if it does not already exist.
    os.makedirs("outputs", exist_ok=True)

    # Generate chart and frequency table.
    fig, source_counts = create_detection_source_chart()

    # Save interactive HTML chart for Quarto website.
    fig.write_html(
        "outputs/volt_typhoon_detection_sources.html",
        include_plotlyjs="cdn"
    )

    # Save underlying frequency data for reproducibility.
    source_counts.to_csv(
        "outputs/volt_typhoon_detection_sources.csv",
        index=False
    )

    # Open chart in browser for quick inspection.
    fig.show()