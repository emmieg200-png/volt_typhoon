import os
import json
import pandas as pd
import plotly.express as px


class VoltTyphoonMitigationCoverage:

    def __init__(
        self,
        csv_file="volt_typhoon_techniques.csv",
        json_file="enterprise-attack.json",
        output_dir="outputs"
    ):
        self.csv_file = csv_file
        self.json_file = json_file
        self.output_dir = output_dir

        self.vt_ids = set()
        self.attack_objects = []
        self.object_lookup = {}

        self.mitigation_counts = None
        self.fig = None

    def get_attack_id(self, obj):

        for ref in obj.get("external_references", []):

            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")

        return None

    def load_data(self):

        vt_df = pd.read_csv(self.csv_file)

        vt_df = vt_df[
            vt_df["Used_by_VT"] == "Yes"
        ]

        self.vt_ids = set(
            vt_df["ATTACK_ID"]
            .dropna()
            .astype(str)
        )

        with open(
            self.json_file,
            "r",
            encoding="utf-8"
        ) as f:

            attack_data = json.load(f)

        self.attack_objects = attack_data["objects"]

        self.object_lookup = {
            obj["id"]: obj
            for obj in self.attack_objects
            if "id" in obj
        }

    def build_mitigation_mapping(self):

        technique_lookup = {}

        for obj in self.attack_objects:

            if obj.get("type") == "attack-pattern":

                attack_id = self.get_attack_id(obj)

                if attack_id:
                    technique_lookup[attack_id] = obj["id"]

        vt_stix_ids = {
            technique_lookup[x]
            for x in self.vt_ids
            if x in technique_lookup
        }

        mitigation_counter = {}

        for obj in self.attack_objects:

            if obj.get("type") != "relationship":
                continue

            if obj.get("relationship_type") != "mitigates":
                continue

            mitigation_id = obj.get("source_ref")
            technique_id = obj.get("target_ref")

            if technique_id not in vt_stix_ids:
                continue

            mitigation_obj = self.object_lookup.get(
                mitigation_id
            )

            if mitigation_obj is None:
                continue

            mitigation_name = mitigation_obj.get(
                "name",
                mitigation_id
            )

            mitigation_counter[
                mitigation_name
            ] = (
                mitigation_counter.get(
                    mitigation_name,
                    0
                ) + 1
            )

        self.mitigation_counts = (
            pd.DataFrame(
                mitigation_counter.items(),
                columns=[
                    "Mitigation",
                    "Technique Coverage"
                ]
            )
            .sort_values(
                "Technique Coverage",
                ascending=False
            )
            .head(15)
        )

    def create_chart(self):

        chart_df = (
            self.mitigation_counts
            .sort_values(
                "Technique Coverage",
                ascending=True
            )
        )

        self.fig = px.bar(
            chart_df,
            x="Technique Coverage",
            y="Mitigation",
            orientation="h",
            text="Technique Coverage",
            title="ATT&CK Mitigations for Volt Typhoon Techniques"
        )

        self.fig.update_traces(
            textposition="outside"
        )

        self.fig.update_layout(
            template="plotly_white",
            height=700,
            showlegend=False,
            xaxis_title="Volt Typhoon Techniques Addressed",
            yaxis_title="Defensive Control",
            margin=dict(
                l=250,
                r=50,
                t=80,
                b=50
            )
        )
        

    def save_outputs(self):

        os.makedirs(
            self.output_dir,
            exist_ok=True
        )

        self.fig.write_html(
            f"{self.output_dir}/volt_typhoon_mitigation_coverage.html",
            include_plotlyjs="cdn"
        )

        self.mitigation_counts.to_csv(
            f"{self.output_dir}/volt_typhoon_mitigation_coverage.csv",
            index=False
        )

    def run(self):

        self.load_data()
        self.build_mitigation_mapping()
        self.create_chart()
        self.save_outputs()

        print(
            self.mitigation_counts
        )

        self.fig.show()


if __name__ == "__main__":

    chart = VoltTyphoonMitigationCoverage(
        csv_file="volt_typhoon_techniques.csv",
        json_file="enterprise-attack.json",
        output_dir="outputs"
    )

    chart.run()