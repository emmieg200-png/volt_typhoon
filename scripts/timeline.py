import os
import pandas as pd
import plotly.graph_objects as go


def create_volt_activity_timeline():
    events = [
        ["2021-01-01", "Active since 2021", "Volt Typhoon active since at least 2021", "Observed Activity"],
        ["2022-10-01", "KV Botnet begins", "KV Botnet Activity begins", "Campaign Activity"],
        ["2023-05-24", "Microsoft report", "Microsoft public disclosure", "Public Reporting"],
        ["2024-01-31", "KV Botnet ends", "KV Botnet Activity ends / DOJ-FBI disruption", "Government Response"],
        ["2024-02-07", "CISA advisory", "CISA/FBI Advisory AA24-038A", "Public Reporting"],
        ["2024-06-01", "Versa begins", "Versa Director zero-day exploitation begins", "Campaign Activity"],
        ["2024-08-31", "Versa ends", "Versa Director zero-day exploitation ends", "Campaign Activity"],
    ]

    df = pd.DataFrame(events, columns=["date", "short_label", "event", "category"])
    df["date"] = pd.to_datetime(df["date"])

    # Spread labels vertically to avoid overlap
    df["label_y"] = [1.4, -1.2, 1.2, -2, 2, -1.2, 1.2]

    fig = go.Figure()

    fig.add_trace(
        go.Scatter(
            x=df["date"],
            y=[0] * len(df),
            mode="lines",
            line=dict(width=4),
            showlegend=False,
            hoverinfo="skip"
        )
    )

    for category in df["category"].unique():
        subset = df[df["category"] == category]

        fig.add_trace(
            go.Scatter(
                x=subset["date"],
                y=[0] * len(subset),
                mode="markers",
                marker=dict(size=14),
                name=category,
                customdata=subset[["event", "category"]],
                hovertemplate=(
                    "<b>%{customdata[0]}</b><br>"
                    "Date: %{x|%b %d, %Y}<br>"
                    "Category: %{customdata[1]}<extra></extra>"
                )
            )
        )

    for _, row in df.iterrows():
        fig.add_annotation(
            x=row["date"],
            y=row["label_y"],
            text=row["short_label"],
            showarrow=True,
            arrowhead=2,
            ax=0,
            ay=-30 if row["label_y"] > 0 else 30,
            font=dict(size=11),
            align="center"
        )

    fig.update_layout(
        title="Volt Typhoon Activity Timeline",
        template="plotly_white",
        height=575,
        xaxis_title="Date",
        yaxis=dict(visible=False, range=[-5, 5]),
        xaxis=dict(
            tickformat="%Y",
            dtick="M12",
            range=["2020-11-01", "2025-03-01"],
            showgrid=True
        ),
        legend_title="Event Category",
        margin=dict(l=60, r=40, t=80, b=80)
    )

    return fig, df


if __name__ == "__main__":
    os.makedirs("outputs", exist_ok=True)

    fig, df = create_volt_activity_timeline()

    fig.write_html(
        "outputs/volt_typhoon_activity_timeline.html",
        include_plotlyjs="cdn"
    )

    df.to_csv(
        "outputs/volt_typhoon_activity_timeline.csv",
        index=False
    )

    fig.show()