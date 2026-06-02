"""
Create a CSV that merges MITRE ATT&CK Enterprise technique data
with the techniques listed on the Volt Typhoon MITRE page.

Output columns:
Technique, ATTACK_ID, Tactic, Used_by_VT, group_id, group_name
"""
import json
import re

import pandas as pd
from bs4 import BeautifulSoup
import requests

# -----------------------------
# 1. Load ATT&CK JSON file
# -----------------------------

json_file = "enterprise-attack.json" 

# read in the file!
with open(json_file, "r", encoding="utf-8") as file:
    attack_data = json.load(file)

# The main STIX content is stored under the "objects" key.
# Turning it into a dataframe makes it easier to filter and clean.
objects_df = pd.DataFrame(attack_data["objects"])

print(objects_df.head(10))

# -----------------------------
# 2. Extract techniques from JSON
# -----------------------------

# In ATT&CK STIX, techniques and sub-techniques are stored as "attack-pattern" objects.
techniques_df = objects_df[objects_df["type"] == "attack-pattern"].copy()

# Remove revoked or deprecated techniques if those columns exist.
if "revoked" in techniques_df.columns:
    techniques_df = techniques_df[techniques_df["revoked"] != True]
if "x_mitre_deprecated" in techniques_df.columns:
    techniques_df = techniques_df[techniques_df["x_mitre_deprecated"] != True]

def get_attack_id(external_refs):
    """Pull the ATT&CK ID, like T1078, from external_references."""
    if isinstance(external_refs, list):
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
    return None

def get_tactics(kill_chain_phases):
    """Pull tactic names from kill_chain_phases."""
    if isinstance(kill_chain_phases, list):
        tactics = [phase.get("phase_name", "") for phase in kill_chain_phases]
        tactics = [t.replace("-", " ").title() for t in tactics]
        return ", ".join(tactics)
    return None

# Create clean technique dataframe from the JSON.
attack_techniques_df = pd.DataFrame({
    "Technique": techniques_df["name"],
    "ATTACK_ID": techniques_df["external_references"].apply(get_attack_id),
    "Tactic": techniques_df["kill_chain_phases"].apply(get_tactics),
})

print(attack_techniques_df.head(10))

# Drop rows where no ATT&CK ID was found.
attack_techniques_df = attack_techniques_df.dropna(subset=["ATTACK_ID"])

# -----------------------------
# 3. Web scrape Volt Typhoon page
# -----------------------------

# This is the main web scrape section.
# It goes to MITRE's Volt Typhoon page and extracts every ATT&CK technique ID
# linked on the page, such as T1078 or T1046.

url = "https://attack.mitre.org/groups/G1017/"
response = requests.get(url, timeout=20)
response.raise_for_status()

soup = BeautifulSoup(response.text, "html.parser")

volt_typhoon_ids = set()

# MITRE technique links usually look like /techniques/T1078/ or /techniques/T1059/001/
for link in soup.find_all("a", href=True):
    href = link["href"]
    match = re.search(r"/techniques/(T\d{4})(?:/(\d{3}))?", href)


    if match:
        technique_id = match.group(1)
        subtechnique_id = match.group(2)

        if subtechnique_id:
            full_id = f"{technique_id}.{subtechnique_id}"
        else:
            full_id = technique_id

        volt_typhoon_ids.add(full_id)

# Make a dataframe of Volt Typhoon techniques from the scraped IDs.
volt_typhoon_df = pd.DataFrame({
    "ATTACK_ID": sorted(volt_typhoon_ids),
    "Used_by_VT": "Yes",
    "group_id": "G1017",
    "group_name": "Volt Typhoon",
})

print(volt_typhoon_df.head(10))

# -----------------------------
# 4. Merge and create CSV
# -----------------------------

merged_df = attack_techniques_df.merge(
    volt_typhoon_df,
    on="ATTACK_ID",
    how="left"
)

# Techniques not found on the Volt Typhoon page are marked No.
merged_df["Used_by_VT"] = merged_df["Used_by_VT"].fillna("No")
merged_df["group_id"] = merged_df["group_id"].fillna("")
merged_df["group_name"] = merged_df["group_name"].fillna("")

# Reorder columns exactly how we want them.
merged_df = merged_df[[
    "Technique",
    "ATTACK_ID",
    "Tactic",
    "Used_by_VT",
    "group_id",
    "group_name",
]]


# Save final CSV.
merged_df.to_csv("volt_typhoon_techniques.csv", index=False)

