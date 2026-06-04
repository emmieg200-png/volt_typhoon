"""
Volt Typhoon Activity Timeline

Research Question:
How has Volt Typhoon activity evolved over time, and what major
campaigns, disclosures, and government responses have occurred
throughout the group's known operational history?

Purpose:
This script creates an interactive timeline visualization of key
events associated with Volt Typhoon. The timeline combines observed
activity, cyber campaigns, public reporting, and government actions
into a single chronological view to help analysts understand the
development and exposure of the threat actor.

Methodology:
1. Define significant Volt Typhoon events from public reporting.
2. Organize events into categories.
3. Convert event dates into a format Plotly can graph.
4. Create a horizontal timeline.
5. Plot events as categorized markers.
6. Add labels and hover information.
7. Export both the visualization and underlying data.

Outputs:
- volt_typhoon_activity_timeline.html
- volt_typhoon_activity_timeline.csv

Operational Relevance:
This visualization helps analysts understand when major Volt Typhoon
activities occurred, how the threat evolved over time, and when
government or public responses were initiated.
"""

# Import os so we can create an output folder if it does not exist.
import os

# Import pandas for creating and manipulating tabular event data.
import pandas as pd

# Import Plotly Graph Objects for building a custom interactive timeline.
import plotly.graph_objects as go


def create_volt_activity_timeline():
    """
    Build an interactive timeline of major Volt Typhoon events.

    Returns:
        fig : Plotly Figure
            Interactive timeline visualization.

        df : pandas DataFrame
            Structured dataset containing all timeline events.
    """

    # Define major events associated with Volt Typhoon.
    #
    # Each event contains:
    # Date
    # Short label displayed on chart
    # Detailed event description for hover text
    # Event category for grouping and legend creation
    events = [
        ["2021-01-01", "Active since 2021", "Volt Typhoon active since at least 2021", "Observed Activity"],
        ["2022-10-01", "KV Botnet begins", "KV Botnet Activity begins", "Campaign Activity"],
        ["2023-05-24", "Microsoft report", "Microsoft public disclosure", "Public Reporting"],
        ["2024-01-31", "KV Botnet ends", "KV Botnet Activity ends / DOJ-FBI disruption", "Government Response"],
        ["2024-02-07", "CISA advisory", "CISA/FBI Advisory AA24-038A", "Public Reporting"],
        ["2024-06-01", "Versa begins", "Versa Director zero-day exploitation begins", "Campaign Activity"],
        ["2024-08-31", "Versa ends", "Versa Director zero-day exploitation ends", "Campaign Activity"],
    ]

    # Convert the event list into a pandas DataFrame.
    # This makes sorting, filtering, and plotting easier.
    df = pd.DataFrame(
        events,
        columns=[
            "date",
            "short_label",
            "event",
            "category"
        ]
    )

    # Convert text dates into datetime objects.
    # Plotly uses datetime objects to properly position points on a timeline.
    df["date"] = pd.to_datetime(df["date"])

    # Assign vertical positions for labels.
    # Alternating positions prevents labels from overlapping.
    df["label_y"] = [1.4, -1.2, 1.2, -2, 2, -1.2, 1.2]

    # Create an empty Plotly figure that will hold the timeline.
    fig = go.Figure()

    # Add the horizontal timeline backbone.
    #
    # This creates the central line that all events are attached to.
    fig.add_trace(
        go.Scatter(
            x=df["date"],

            # All points lie on the center line at y=0.
            y=[0] * len(df),

            # Draw a continuous line.
            mode="lines",

            # Increase thickness for visibility.
            line=dict(width=4),

            # No legend needed for the timeline line itself.
            showlegend=False,

            # Disable hover text on the timeline backbone.
            hoverinfo="skip"
        )
    )

    # Loop through each event category.
    #
    # This creates separate marker groups and legend entries
    # for Campaign Activity, Public Reporting, etc.
    for category in df["category"].unique():

        # Keep only rows belonging to the current category.
        subset = df[df["category"] == category]

        # Add event markers to the timeline.
        fig.add_trace(
            go.Scatter(
                x=subset["date"],

                # Place markers directly on the timeline.
                y=[0] * len(subset),

                # Display markers only.
                mode="markers",

                # Make markers large enough to be easily visible.
                marker=dict(size=14),

                # Use category name in the legend.
                name=category,

                # Store additional event information for hover text.
                customdata=subset[
                    ["event", "category"]
                ],

                # Display detailed information when user hovers.
                hovertemplate=(
                    "<b>%{customdata[0]}</b><br>"
                    "Date: %{x|%b %d, %Y}<br>"
                    "Category: %{customdata[1]}<extra></extra>"
                )
            )
        )

    # Add labels above and below the timeline.
    #
    # Labels identify major events without requiring users to hover.
    for _, row in df.iterrows():

        fig.add_annotation(

            # Position label at event date.
            x=row["date"],

            # Use assigned vertical offset.
            y=row["label_y"],

            # Display short event label.
            text=row["short_label"],

            # Draw an arrow from label to event point.
            showarrow=True,

            # Arrow style.
            arrowhead=2,

            # Keep arrow centered horizontally.
            ax=0,

            # Place arrows above or below timeline.
            ay=-30 if row["label_y"] > 0 else 30,

            # Label font size.
            font=dict(size=11),

            # Center text alignment.
            align="center"
        )

    # Format chart appearance.
    #
    # These settings improve readability and make the figure
    # suitable for inclusion in reports and Quarto websites.
    fig.update_layout(

        # Chart title.
        title="Volt Typhoon Activity Timeline",

        # Use clean white background.
        template="plotly_white",

        # Set figure height.
        height=575,

        # Label x-axis.
        xaxis_title="Date",

        # Hide y-axis since it has no analytical meaning.
        yaxis=dict(
            visible=False,
            range=[-5, 5]
        ),

        # Configure date axis.
        xaxis=dict(

            # Show years only.
            tickformat="%Y",

            # One tick every 12 months.
            dtick="M12",

            # Display timeline range.
            range=["2020-11-01", "2025-03-01"],

            # Show vertical gridlines.
            showgrid=True
        ),

        # Title for legend categories.
        legend_title="Event Category",

        # Add whitespace around chart.
        margin=dict(
            l=60,
            r=40,
            t=80,
            b=80
        )
    )

    # Return both the figure and event dataset.
    return fig, df


# Run this section only when the script is executed directly.
if __name__ == "__main__":

    # Create output folder if it does not already exist.
    os.makedirs("outputs", exist_ok=True)

    # Generate the timeline figure and event dataframe.
    fig, df = create_volt_activity_timeline()

    # Save interactive HTML version for the Quarto website.
    fig.write_html(
        "outputs/volt_typhoon_activity_timeline.html",
        include_plotlyjs="cdn"
    )

    # Save event data as CSV for reproducibility and documentation.
    df.to_csv(
        "outputs/volt_typhoon_activity_timeline.csv",
        index=False
    )

    # Open the timeline in a browser window for inspection.
    fig.show()