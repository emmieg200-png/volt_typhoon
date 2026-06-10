import os
import pandas as pd
import plotly.express as px


def create_tactic_frequency_chart():
    csv_file = "volt_typhoon_techniques.csv"

    df = pd.read_csv(csv_file)

    # Keep only techniques used by Volt Typhoon
    vt_df = df[df["Used_by_VT"] == "Yes"].copy()

    # Some rows have multiple tactics separated by commas.
    # This splits them so each tactic gets counted separately.
    vt_df["Tactic"] = vt_df["Tactic"].str.split(",")

    tactic_df = vt_df.explode("Tactic")

    # Clean extra spaces
    tactic_df["Tactic"] = tactic_df["Tactic"].str.strip()

    # Count tactics
    tactic_counts = (
        tactic_df["Tactic"]
        .value_counts()
        .reset_index()
    )

    tactic_counts.columns = ["Tactic", "Count"]

    # Sort so largest bars appear at the top
    tactic_counts = tactic_counts.sort_values("Count", ascending=True)

    fig = px.bar(
        tactic_counts,
        x="Count",
        y="Tactic",
        orientation="h",
        text="Count",
        title="Volt Typhoon ATT&CK Tactic Frequency"
    )

    fig.update_traces(textposition="outside")

    fig.update_layout(
        template="plotly_white",
        height=650,
        xaxis_title="Number of Techniques",
        yaxis_title="ATT&CK Tactic",
        showlegend=False,
        margin=dict(l=180, r=80, t=80, b=60)
    )

    return fig, tactic_counts


if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    fig, tactic_counts = create_tactic_frequency_chart()

    fig.write_html(
        "outputs/volt_typhoon_tactic_frequency.html",
        include_plotlyjs="cdn"
    )

    tactic_counts.to_csv(
        "outputs/volt_typhoon_tactic_frequency.csv",
        index=False
    )

    fig.show()