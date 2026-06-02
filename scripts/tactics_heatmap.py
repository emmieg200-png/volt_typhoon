import os
import pandas as pd
import plotly.express as px


class VoltTyphoonTacticHeatmap:
    def __init__(
        self,
        csv_file="volt_typhoon_techniques.csv",
        output_dir="outputs"
    ):
        self.csv_file = csv_file
        self.output_dir = output_dir
        self.df = None
        self.vt_df = None
        self.tactic_counts = None
        self.fig = None

        self.tactic_order = [
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact"
        ]

    def load_data(self):
        self.df = pd.read_csv(self.csv_file)

    def clean_data(self):
        self.vt_df = self.df[self.df["Used_by_VT"] == "Yes"].copy()

        self.vt_df["Tactic"] = self.vt_df["Tactic"].str.split(",")
        self.vt_df = self.vt_df.explode("Tactic")
        self.vt_df["Tactic"] = self.vt_df["Tactic"].str.strip()

    def count_tactics(self):
        self.tactic_counts = (
            self.vt_df.groupby("Tactic")
            .size()
            .reindex(self.tactic_order, fill_value=0)
            .reset_index()
        )

        self.tactic_counts.columns = ["Tactic", "Technique Count"]

    def create_heatmap(self):
        heatmap_df = self.tactic_counts.set_index("Tactic").T

        self.fig = px.imshow(
            heatmap_df,
            text_auto=True,
            aspect="auto",
            title="Where Volt Typhoon’s Documented Techniques Concentrate",
            labels={
                "x": "ATT&CK Tactic",
                "y": "",
                "color": "Documented Techniques"
            }
        )

        self.fig.update_layout(
            template="plotly_white",
            height=350,
            margin=dict(l=40, r=40, t=80, b=140),
            xaxis_tickangle=-45
        )

    def save_outputs(self):
        os.makedirs(self.output_dir, exist_ok=True)

        self.fig.write_html(
            f"{self.output_dir}/volt_typhoon_tactic_coverage_heatmap.html",
            include_plotlyjs="cdn"
        )

        self.tactic_counts.to_csv(
            f"{self.output_dir}/volt_typhoon_tactic_coverage_heatmap.csv",
            index=False
        )

    def run(self):
        self.load_data()
        self.clean_data()
        self.count_tactics()
        self.create_heatmap()
        self.save_outputs()

        print(self.tactic_counts)

        self.fig.show()


if __name__ == "__main__":
    heatmap = VoltTyphoonTacticHeatmap(
        csv_file="volt_typhoon_techniques.csv",
        output_dir="outputs"
    )

    heatmap.run()