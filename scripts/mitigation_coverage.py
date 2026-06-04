"""
Volt Typhoon Mitigation Coverage Analysis

Research Question:
Which MITRE ATT&CK mitigations provide the greatest coverage
against techniques attributed to Volt Typhoon?

Purpose:
This script analyzes the MITRE ATT&CK Enterprise knowledge base
to identify defensive controls that mitigate the largest number
of Volt Typhoon techniques. The resulting visualization helps
defenders prioritize security investments by highlighting the
mitigations that address the broadest portion of Volt Typhoon's
known tradecraft.

Methodology:
1. Load a CSV containing ATT&CK techniques associated with
   Volt Typhoon.
2. Load the MITRE ATT&CK Enterprise JSON dataset.
3. Identify ATT&CK techniques used by Volt Typhoon.
4. Convert ATT&CK technique IDs (e.g., T1078) into STIX IDs
   used by ATT&CK relationships.
5. Traverse ATT&CK "mitigates" relationships to find which
   mitigations apply to Volt Typhoon techniques.
6. Count how many Volt Typhoon techniques each mitigation
   addresses.
7. Rank mitigations by technique coverage.
8. Create a horizontal bar chart showing the top mitigations.
9. Export both the chart and underlying data for use in
   reports, dashboards, and the Quarto website.

Output:
- volt_typhoon_mitigation_coverage.html
    Interactive Plotly visualization.

- volt_typhoon_mitigation_coverage.csv
    Ranked mitigation coverage dataset.

Chart Interpretation:
Each bar represents a MITRE ATT&CK mitigation. The bar length
shows the number of Volt Typhoon techniques that mitigation
can help defend against. Larger values indicate defensive
controls that provide broader protection across Volt Typhoon's
observed tactics, techniques, and procedures (TTPs).

Operational Relevance:
This analysis helps Army, DoD, and cybersecurity defenders
identify high-impact defensive measures that can reduce risk
from Volt Typhoon activity and improve network resilience
against nation-state cyber threats.
"""

# Import os so the script can create an output folder for the chart and CSV.
import os

# Import json so the script can read the MITRE ATT&CK Enterprise JSON file.
import json

# Import pandas so the script can load, filter, organize, and export tabular data.
import pandas as pd

# Import Plotly Express so the script can create an interactive bar chart.
import plotly.express as px


# Define a class that groups all steps needed to create the mitigation coverage chart.
class VoltTyphoonMitigationCoverage:

    # Initialize the class with file names and output folder.
    def __init__(
        self,
        csv_file="volt_typhoon_techniques.csv",
        json_file="enterprise-attack.json",
        output_dir="outputs"
    ):
        # Store the CSV file containing Volt Typhoon technique information.
        self.csv_file = csv_file

        # Store the MITRE ATT&CK Enterprise JSON file.
        self.json_file = json_file

        # Store the folder where the chart and CSV outputs will be saved.
        self.output_dir = output_dir

        # Create an empty set that will later store Volt Typhoon ATT&CK technique IDs.
        self.vt_ids = set()

        # Create an empty list that will later store all ATT&CK STIX objects.
        self.attack_objects = []

        # Create an empty dictionary that will later map STIX object IDs to full objects.
        self.object_lookup = {}

        # Create a placeholder for the final mitigation frequency table.
        self.mitigation_counts = None

        # Create a placeholder for the final Plotly chart.
        self.fig = None


    # Define a helper method to pull ATT&CK technique IDs from ATT&CK objects.
    def get_attack_id(self, obj):

        # Loop through the external references attached to the ATT&CK object.
        for ref in obj.get("external_references", []):

            # Find the official MITRE ATT&CK reference.
            if ref.get("source_name") == "mitre-attack":

                # Return the human-readable ATT&CK ID, such as T1078.
                return ref.get("external_id")

        # Return None if no ATT&CK ID is found.
        return None


    # Load the Volt Typhoon CSV and MITRE ATT&CK JSON data.
    def load_data(self):

        # Read the CSV created earlier into a pandas DataFrame.
        vt_df = pd.read_csv(self.csv_file)

        # Keep only the techniques marked as used by Volt Typhoon.
        vt_df = vt_df[
            vt_df["Used_by_VT"] == "Yes"
        ]

        # Convert the Volt Typhoon ATT&CK IDs into a set for fast lookup.
        self.vt_ids = set(
            vt_df["ATTACK_ID"]
            .dropna()
            .astype(str)
        )

        # Open the MITRE ATT&CK Enterprise JSON file.
        with open(
            self.json_file,
            "r",
            encoding="utf-8"
        ) as f:

            # Load the JSON content into a Python dictionary.
            attack_data = json.load(f)

        # Store all ATT&CK STIX objects from the JSON file.
        self.attack_objects = attack_data["objects"]

        # Build a lookup dictionary where each STIX ID points to its full object.
        self.object_lookup = {
            obj["id"]: obj
            for obj in self.attack_objects
            if "id" in obj
        }


    # Build the mapping between mitigations and Volt Typhoon techniques.
    def build_mitigation_mapping(self):

        # Create an empty dictionary to connect ATT&CK IDs to STIX IDs.
        technique_lookup = {}

        # Loop through every ATT&CK object.
        for obj in self.attack_objects:

            # Only attack-pattern objects represent techniques and sub-techniques.
            if obj.get("type") == "attack-pattern":

                # Extract the human-readable ATT&CK ID.
                attack_id = self.get_attack_id(obj)

                # If the object has an ATT&CK ID, store the mapping.
                if attack_id:
                    technique_lookup[attack_id] = obj["id"]

        # Convert Volt Typhoon ATT&CK IDs into STIX IDs.
        # This is required because ATT&CK relationships use STIX IDs, not T-numbers.
        vt_stix_ids = {
            technique_lookup[x]
            for x in self.vt_ids
            if x in technique_lookup
        }

        # Create an empty dictionary to count how many Volt Typhoon techniques each mitigation covers.
        mitigation_counter = {}

        # Loop through every ATT&CK object again to find mitigation relationships.
        for obj in self.attack_objects:

            # Skip anything that is not a relationship object.
            if obj.get("type") != "relationship":
                continue

            # Skip relationships that are not mitigation relationships.
            if obj.get("relationship_type") != "mitigates":
                continue

            # The source is the mitigation control.
            mitigation_id = obj.get("source_ref")

            # The target is the technique being mitigated.
            technique_id = obj.get("target_ref")

            # Skip this relationship if it does not target a Volt Typhoon technique.
            if technique_id not in vt_stix_ids:
                continue

            # Retrieve the full mitigation object using its STIX ID.
            mitigation_obj = self.object_lookup.get(
                mitigation_id
            )

            # Skip if the mitigation object cannot be found.
            if mitigation_obj is None:
                continue

            # Get the readable mitigation name.
            # If no name exists, use the mitigation ID as a fallback.
            mitigation_name = mitigation_obj.get(
                "name",
                mitigation_id
            )

            # Increase the count for this mitigation by 1.
            # Each count means this mitigation addresses one Volt Typhoon technique.
            mitigation_counter[
                mitigation_name
            ] = (
                mitigation_counter.get(
                    mitigation_name,
                    0
                ) + 1
            )

        # Convert the mitigation count dictionary into a DataFrame.
        self.mitigation_counts = (
            pd.DataFrame(
                mitigation_counter.items(),
                columns=[
                    "Mitigation",
                    "Technique Coverage"
                ]
            )

            # Sort so the mitigations covering the most techniques appear first.
            .sort_values(
                "Technique Coverage",
                ascending=False
            )

            # Keep the top 15 mitigations so the chart stays readable.
            .head(15)
        )


    # Create the interactive Plotly bar chart.
    def create_chart(self):

        # Sort the data in ascending order for a horizontal bar chart.
        # This makes the largest bar appear at the top visually.
        chart_df = (
            self.mitigation_counts
            .sort_values(
                "Technique Coverage",
                ascending=True
            )
        )

        # Build the horizontal bar chart.
        self.fig = px.bar(
            chart_df,

            # The x-axis shows how many Volt Typhoon techniques each mitigation addresses.
            x="Technique Coverage",

            # The y-axis lists the mitigation controls.
            y="Mitigation",

            # Make the chart horizontal for easier reading of long mitigation names.
            orientation="h",

            # Display the count number on each bar.
            text="Technique Coverage",

            # Add a clear title explaining what the chart shows.
            title="ATT&CK Mitigations for Volt Typhoon Techniques"
        )

        # Move the text labels outside the bars so the values are easy to read.
        self.fig.update_traces(
            textposition="outside"
        )

        # Format the chart for readability and website display.
        self.fig.update_layout(

            # Use a clean white background.
            template="plotly_white",

            # Set chart height large enough for 15 horizontal bars.
            height=700,

            # Hide the legend because there is only one data series.
            showlegend=False,

            # Label the x-axis with what the numbers mean.
            xaxis_title="Volt Typhoon Techniques Addressed",

            # Label the y-axis with what the categories mean.
            yaxis_title="Defensive Control",

            # Add margins so long mitigation names and text labels do not get cut off.
            margin=dict(
                l=250,
                r=50,
                t=80,
                b=50
            )
        )


    # Save the chart and the data used to make it.
    def save_outputs(self):

        # Create the output folder if it does not already exist.
        os.makedirs(
            self.output_dir,
            exist_ok=True
        )

        # Save the interactive Plotly chart as an HTML file.
        # This is the file you can embed in your Quarto website.
        self.fig.write_html(
            f"{self.output_dir}/volt_typhoon_mitigation_coverage.html",
            include_plotlyjs="cdn"
        )

        # Save the mitigation coverage table as a CSV for documentation and reproducibility.
        self.mitigation_counts.to_csv(
            f"{self.output_dir}/volt_typhoon_mitigation_coverage.csv",
            index=False
        )


    # Run all steps in the correct order.
    def run(self):

        # Step 1: Load the Volt Typhoon CSV and ATT&CK JSON.
        self.load_data()

        # Step 2: Count how many Volt Typhoon techniques each mitigation addresses.
        self.build_mitigation_mapping()

        # Step 3: Build the horizontal bar chart from those counts.
        self.create_chart()

        # Step 4: Save the chart and CSV outputs.
        self.save_outputs()

        # Print the mitigation table so you can inspect the results in the terminal.
        print(
            self.mitigation_counts
        )

        # Display the interactive chart in your browser or notebook.
        self.fig.show()


# Only run this section when the script is executed directly.
if __name__ == "__main__":

    # Create an instance of the mitigation coverage chart class.
    chart = VoltTyphoonMitigationCoverage(
        csv_file="volt_typhoon_techniques.csv",
        json_file="enterprise-attack.json",
        output_dir="outputs"
    )

    # Run the full chart creation process.
    chart.run()