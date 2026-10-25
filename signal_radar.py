#!/usr/bin/env python3

"""
signal_radar.py

Circular Wi-Fi signal-strength radar for Kismet.

Uses:
    signal_manager.py
    signal_position.py
    Plotly

Features:
    - Concentric signal-strength rings
    - Individual AP markers
    - Signal-strength colour coding
    - Hover information
    - AP selection highlighting
    - Stable AP positions between refreshes
"""

import math

import plotly.graph_objects as go


# --------------------------------------------------
# RADAR CONFIGURATION
# --------------------------------------------------

RADAR_RADIUS = 1.0
SIGNAL_MIN = -100
SIGNAL_MAX = -20

# Signal strength colour thresholds
STRONG_SIGNAL = -60
MEDIUM_SIGNAL = -75

# Radar appearance
RADAR_BACKGROUND = "#000000"
RADAR_RING_COLOR = "#394252"
RADAR_TEXT_COLOR = "#FFFFFF"

# Marker colours
COLOR_STRONG = "#22C55E"
COLOR_MEDIUM = "#3B82F6"
COLOR_WEAK = "#F59E0B"


# --------------------------------------------------
# SIGNAL COLOUR
# --------------------------------------------------

def signal_colour(signal):
    """
    Return a colour based on average signal strength.
    """

    if signal is None:
        return COLOR_WEAK

    if signal >= STRONG_SIGNAL:
        return COLOR_STRONG

    if signal >= MEDIUM_SIGNAL:
        return COLOR_MEDIUM

    return COLOR_WEAK


# --------------------------------------------------
# RADAR RINGS
# --------------------------------------------------

def add_radar_rings(fig):
    """
    Draw concentric radar rings.

    Ring positions correspond to signal levels.
    """

    ring_signals = [-100, -85, -70, -55, -40]

    for signal in ring_signals:

        radius = (SIGNAL_MAX - signal) / (SIGNAL_MAX - SIGNAL_MIN)

        if radius <= 0:
            continue

        theta = [
            math.radians(angle)
            for angle in range(361)
        ]

        x = [
            radius * math.cos(angle)
            for angle in theta
        ]

        y = [
            radius * math.sin(angle)
            for angle in theta
        ]

        fig.add_trace(
            go.Scatter(
                x=x,
                y=y,
                mode="lines",
                line=dict(
                    color=RADAR_RING_COLOR,
                    width=1,
                    dash="dot"
                ),
                hoverinfo="skip",
                showlegend=False
            )
        )

        # Signal labels on the upper edge
        fig.add_annotation(
            x=0,
            y=radius,
            text=f"{signal} dBm",
            showarrow=False,
            font=dict(
                size=9,
                color=RADAR_TEXT_COLOR
            ),
            yshift=8
        )


# --------------------------------------------------
# RADAR AXES
# --------------------------------------------------

def add_radar_axes(fig):
    """
    Add horizontal and vertical reference lines.
    """

    fig.add_trace(
        go.Scatter(
            x=[-1, 1],
            y=[0, 0],
            mode="lines",
            line=dict(
                color=RADAR_RING_COLOR,
                width=1
            ),
            hoverinfo="skip",
            showlegend=False
        )
    )

    fig.add_trace(
        go.Scatter(
            x=[0, 0],
            y=[-1, 1],
            mode="lines",
            line=dict(
                color=RADAR_RING_COLOR,
                width=1
            ),
            hoverinfo="skip",
            showlegend=False
        )
    )


# --------------------------------------------------
# ACCESS POINT MARKERS
# --------------------------------------------------

def add_access_points(fig, aps, selected_mac=None):
    """
    Add AP markers to the radar.

    Each AP retains its coordinates supplied by
    signal_position.py.
    """

    for ap in aps:

        mac = ap.get("mac")
        name = ap.get("name") or "Unknown"

        x = ap.get("radar_x")
        y = ap.get("radar_y")

        average = ap.get("average_signal")
        latest = ap.get("last_signal")

        if x is None or y is None:
            continue

        colour = signal_colour(average)

        selected = mac == selected_mac

        marker_size = 15 if selected else 10

        hover_text = (
            f"<b>{name}</b><br>"
            f"MAC: {mac}<br>"
            f"Channel: {ap.get('channel')}<br>"
            f"Latest signal: {latest} dBm<br>"
            f"Average signal: {average:.2f} dBm<br>"
            f"Samples: {ap.get('history_samples', 0)}"
        )

        fig.add_trace(
            go.Scatter(
                x=[x],
                y=[y],
                mode="markers",
                name=name,
                text=[hover_text],
                hovertemplate="%{text}<extra></extra>",
                customdata=[mac],
                marker=dict(
                    size=marker_size,
                    color=colour,
                    line=dict(
                        color="#FFFFFF",
                        width=1.2
                    ),
                    opacity=0.95
                ),
                showlegend=False
            )
        )


# --------------------------------------------------
# MAIN RADAR FIGURE
# --------------------------------------------------

def create_radar_figure(aps, selected_mac=None):
    """
    Build the complete circular AP radar.

    Parameters:
        aps:
            Positioned AP dictionaries returned by
            signal_position.process_radar()["aps"]

        selected_mac:
            Optional MAC address to highlight.

    Returns:
        Plotly Figure
    """

    fig = go.Figure()

    # Radar background
    add_radar_rings(fig)
    add_radar_axes(fig)

    # AP markers
    add_access_points(
        fig,
        aps,
        selected_mac
    )

    # Centre marker
    fig.add_trace(
        go.Scatter(
            x=[0],
            y=[0],
            mode="markers",
            marker=dict(
                size=12,
                color="#FFFFFF",
                symbol="circle",
                line=dict(
                    color="#64748B",
                    width=2
                )
            ),
            hoverinfo="skip",
            showlegend=False
        )
    )

    # Layout
    fig.update_layout(
        title=dict(
            text=f"Wi-Fi Signal Radar ({len(aps)} APs)",
            font=dict(
                size=18,
                color=RADAR_TEXT_COLOR
            ),
            x=0.5
        ),

        paper_bgcolor=RADAR_BACKGROUND,
        plot_bgcolor=RADAR_BACKGROUND,

        font=dict(
            color=RADAR_TEXT_COLOR
        ),

        height=750,

        margin=dict(
            l=30,
            r=30,
            t=65,
            b=30
        ),

        showlegend=False,

        hovermode="closest",

        clickmode="event+select",

        xaxis=dict(
            range=[-1.08, 1.08],
            visible=False,

            constrain="domain"
        ),

        yaxis=dict(
            range=[-1.08, 1.08],
            visible=False,

            scaleanchor="x",
            scaleratio=1
        )
    )

    return fig
