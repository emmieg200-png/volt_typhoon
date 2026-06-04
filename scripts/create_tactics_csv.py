"""
Create a CSV that merges MITRE ATT&CK Enterprise technique data
with the techniques listed on the Volt Typhoon MITRE page.

Final CSV columns:
Technique, ATTACK_ID, Tactic, Used_by_VT, group_id, group_name
"""

# Import json so Python can read the enterprise-attack.json file.
import json

# Import re so Python can search URLs for ATT&CK technique ID patterns.
import re

# Import pandas to store, clean, merge, and export the data as a CSV.
import pandas as pd

# Import BeautifulSoup to parse the HTML from the MITRE Volt Typhoon webpage.
from bs4 import BeautifulSoup

# Import requests to download the HTML from the MITRE webpage.
import requests


# -----------------------------
# 1. Load ATT&CK JSON file
# -----------------------------

# Store the name of the local MITRE ATT&CK Enterprise JSON file.
json_file = "enterprise-attack.json"

# Open the JSON file in read mode using UTF-8 encoding.
with open(json_file, "r", encoding="utf-8") as file:

    # Load the JSON file into a Python dictionary.
    attack_data = json.load(file)

# Convert the main list of ATT&CK STIX objects into a pandas DataFrame.
# This makes it easier to filter for only techniques.
objects_df = pd.DataFrame(attack_data["objects"])

# Print the first 10 rows so you can quickly check that the JSON loaded correctly.
print(objects_df.head(10))


# -----------------------------
# 2. Extract techniques from JSON
# -----------------------------

# Keep only rows where the STIX object type is "attack-pattern".
# In MITRE ATT&CK, techniques and sub-techniques are stored as attack-pattern objects.
techniques_df = objects_df[objects_df["type"] == "attack-pattern"].copy()

# If the dataset includes a "revoked" column, remove revoked techniques.
# Revoked techniques should not be included in the final CSV.
if "revoked" in techniques_df.columns:
    techniques_df = techniques_df[techniques_df["revoked"] != True]

# If the dataset includes a deprecated column, remove deprecated techniques.
# Deprecated techniques are outdated and should not be used in the final analysis.
if "x_mitre_deprecated" in techniques_df.columns:
    techniques_df = techniques_df[techniques_df["x_mitre_deprecated"] != True]


# Define a function that extracts the ATT&CK ID from external references.
def get_attack_id(external_refs):
    """Pull the ATT&CK ID, such as T1078, from external_references."""

    # Make sure the external references field is actually a list.
    if isinstance(external_refs, list):

        # Loop through each reference in the list.
        for ref in external_refs:

            # Find the official MITRE ATT&CK reference.
            if ref.get("source_name") == "mitre-attack":

                # Return the ATT&CK technique ID, such as T1059 or T1078.
                return ref.get("external_id")

    # Return None if no ATT&CK ID was found.
    return None


# Define a function that extracts tactics from the kill_chain_phases field.
def get_tactics(kill_chain_phases):
    """Pull tactic names from kill_chain_phases."""

    # Make sure the kill chain phases field is actually a list.
    if isinstance(kill_chain_phases, list):

        # Pull the raw tactic phase names from each phase.
        tactics = [phase.get("phase_name", "") for phase in kill_chain_phases]

        # Clean the tactic names by replacing hyphens with spaces and capitalizing words.
        tactics = [t.replace("-", " ").title() for t in tactics]

        # Join multiple tactics together into one comma-separated string.
        return ", ".join(tactics)

    # Return None if no tactics were found.
    return None


# Create a clean DataFrame with only the columns needed for the final CSV.
attack_techniques_df = pd.DataFrame({

    # Store the readable technique name.
    "Technique": techniques_df["name"],

    # Store the ATT&CK ID by applying the get_attack_id function.
    "ATTACK_ID": techniques_df["external_references"].apply(get_attack_id),

    # Store the tactic or tactics by applying the get_tactics function.
    "Tactic": techniques_df["kill_chain_phases"].apply(get_tactics),
})

# Print the first 10 cleaned technique rows to verify the data looks correct.
print(attack_techniques_df.head(10))

# Remove any rows where an ATT&CK ID could not be found.
# This keeps the final merge clean because ATT&CK ID is the key column.
attack_techniques_df = attack_techniques_df.dropna(subset=["ATTACK_ID"])


# -----------------------------
# 3. Web scrape Volt Typhoon page
# -----------------------------

# Store the MITRE ATT&CK page URL for Volt Typhoon.
url = "https://attack.mitre.org/groups/G1017/"

# Download the webpage HTML.
response = requests.get(url, timeout=20)

# Stop the program if the webpage request failed.
response.raise_for_status()

# Parse the downloaded HTML with BeautifulSoup.
soup = BeautifulSoup(response.text, "html.parser")

# Create an empty set to store unique Volt Typhoon technique IDs.
# A set is used so duplicate technique IDs are automatically removed.
volt_typhoon_ids = set()

# Loop through every hyperlink on the Volt Typhoon page.
for link in soup.find_all("a", href=True):

    # Get the URL path from the hyperlink.
    href = link["href"]

    # Search the URL for MITRE technique patterns.
    # This captures IDs like /techniques/T1078/ and sub-techniques like /techniques/T1059/001/.
    match = re.search(r"/techniques/(T\d{4})(?:/(\d{3}))?", href)

    # If the link contains a technique or sub-technique ID, process it.
    if match:

        # Store the main technique ID, such as T1059.
        technique_id = match.group(1)

        # Store the sub-technique number, such as 001, if it exists.
        subtechnique_id = match.group(2)

        # If there is a sub-technique, combine it into the format T1059.001.
        if subtechnique_id:
            full_id = f"{technique_id}.{subtechnique_id}"

        # If there is no sub-technique, keep the main technique ID.
        else:
            full_id = technique_id

        # Add the technique ID to the Volt Typhoon set.
        volt_typhoon_ids.add(full_id)


# Create a DataFrame listing every technique scraped from the Volt Typhoon page.
volt_typhoon_df = pd.DataFrame({

    # Store each scraped ATT&CK ID in sorted order.
    "ATTACK_ID": sorted(volt_typhoon_ids),

    # Mark each of these IDs as used by Volt Typhoon.
    "Used_by_VT": "Yes",

    # Add Volt Typhoon's MITRE group ID.
    "group_id": "G1017",

    # Add the group name for readability.
    "group_name": "Volt Typhoon",
})

# Print the first 10 Volt Typhoon rows to check the scraped data.
print(volt_typhoon_df.head(10))


# -----------------------------
# 4. Merge and create CSV
# -----------------------------

# Merge the full ATT&CK technique list with the Volt Typhoon technique list.
# The merge happens on ATTACK_ID because that is the shared identifier.
merged_df = attack_techniques_df.merge(

    # This is the smaller DataFrame containing only Volt Typhoon techniques.
    volt_typhoon_df,

    # Match rows where ATTACK_ID is the same in both DataFrames.
    on="ATTACK_ID",

    # Keep every ATT&CK technique, even if it is not used by Volt Typhoon.
    how="left"
)

# Any technique that did not match Volt Typhoon will have a blank Used_by_VT value.
# Fill those blanks with "No".
merged_df["Used_by_VT"] = merged_df["Used_by_VT"].fillna("No")

# For non-Volt Typhoon techniques, fill the blank group_id with an empty string.
merged_df["group_id"] = merged_df["group_id"].fillna("")

# For non-Volt Typhoon techniques, fill the blank group_name with an empty string.
merged_df["group_name"] = merged_df["group_name"].fillna("")

# Reorder the columns so the CSV has the exact structure needed for analysis.
merged_df = merged_df[[
    "Technique",
    "ATTACK_ID",
    "Tactic",
    "Used_by_VT",
    "group_id",
    "group_name",
]]

# Save the final DataFrame as a CSV file.
# index=False prevents pandas from adding an extra index column to the CSV.
merged_df.to_csv("volt_typhoon_techniques.csv", index=False)