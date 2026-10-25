"""Shared visual styling for the Kismet radar views."""

import math
import plotly.graph_objects as go


RING_SIGNALS = [-90, -80, -70, -60, -50, -40, -30, -20]
OUTER_BOUNDARY_RADIUS = 1.05


def add_radar_grid(fig):
    """Add the common signal rings, outer boundary, and compass axes."""

    theta = [math.radians(angle) for angle in range(361)]

    for signal in RING_SIGNALS:
        radius = (
            0.10 +
            ((-20.0 - signal) / 70.0) * 0.90
        )

        fig.add_trace(go.Scatter(
            x=[radius * math.cos(angle) for angle in theta],
            y=[radius * math.sin(angle) for angle in theta],
            mode="lines",
            line=dict(
                color="#CBD5E1",
                width=1,
                dash="dot"
            ),
            hoverinfo="skip",
            showlegend=False
        ))

        fig.add_annotation(
            x=0,
            y=radius,
            text=f"{signal} dBm",
            showarrow=False,
            font=dict(size=9, color="#475569"),
            yshift=8
        )

    fig.add_trace(go.Scatter(
        x=[
            OUTER_BOUNDARY_RADIUS * math.cos(angle)
            for angle in theta
        ],
        y=[
            OUTER_BOUNDARY_RADIUS * math.sin(angle)
            for angle in theta
        ],
        mode="lines",
        line=dict(
            color="#94A3B8",
            width=1.5,
            dash="solid"
        ),
        hoverinfo="skip",
        showlegend=False
    ))

    for x_values, y_values in (
        ([-1, 1], [0, 0]),
        ([0, 0], [-1, 1])
    ):
        fig.add_trace(go.Scatter(
            x=x_values,
            y=y_values,
            mode="lines",
            line=dict(color="#CBD5E1", width=1),
            hoverinfo="skip",
            showlegend=False
        ))


def apply_radar_layout(fig, uirevision=None, margin=None, clickmode=None, title=None):
    """Apply the common white, square radar layout."""

    layout = dict(
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
        font=dict(color="#1E293B"),
        autosize=True,
        margin=margin or dict(l=20, r=20, t=20, b=20),
        showlegend=False,
        hovermode="closest",
        xaxis=dict(
            range=[-1.08, 1.08],
            visible=False
        ),
        yaxis=dict(
            range=[-1.08, 1.08],
            visible=False,
            scaleanchor="x",
            scaleratio=1
        )
    )

    if uirevision is not None:
        layout["uirevision"] = uirevision

    if clickmode is not None:
        layout["clickmode"] = clickmode

    if title is not None:
        layout["title"] = dict(
            text=title,
            font=dict(size=18, color="#1F2937"),
            x=0.5
        )

    fig.update_layout(**layout)
