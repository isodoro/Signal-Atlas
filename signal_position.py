"""
signal_radar.py

Builds the Plotly Wi-Fi signal radar figure for the Dash interface.

Displays:
- Signal-strength reference rings.
- AP markers and signal-strength colours.
- Hover information for individual access points.
- Optional highlighting of a selected AP.

This module handles visualisation only.
"""

import hashlib
import math


# Signal range used for radar positioning
SIGNAL_MIN = -100
SIGNAL_MAX = -30

RADAR_RADIUS = 1.0

# Generate a deterministic angle from the AP MAC address.
def calculate_angle(mac):
    """
    Generate a stable angular position from an AP MAC.

    The same MAC always produces the same angle.
    """

    if not mac:
        return None

    digest = hashlib.sha256(
        mac.upper().encode("utf-8")
    ).hexdigest()

    value = int(digest[:12], 16)

    return (value / (16 ** 12)) * 360


# Convert average signal strength into a radar radius.
# Stronger signals are positioned closer to the centre.
def signal_to_radius(signal):
    """
    Convert dBm signal strength into radar radius.

    Stronger signals appear closer to the centre.
    Weaker signals appear closer to the outer edge.
    """

    if signal is None:
        return None

    signal = max(
        SIGNAL_MIN,
        min(SIGNAL_MAX, signal)
    )

    strength = (
        (signal - SIGNAL_MIN) /
        (SIGNAL_MAX - SIGNAL_MIN)
    )

    return (1.0 - strength) * RADAR_RADIUS


def calculate_positions(aps):
    """
    Calculate stable radar coordinates for APs.

    MAC addresses determine angular positions.
    Average signal determines radial positions.
    """

    positioned_aps = []

    for ap in aps:

        mac = ap.get("mac")
        average = ap.get("average_signal")

        if not mac or average is None:
            continue

        angle = calculate_angle(mac)
        radius = signal_to_radius(average)

        radians = math.radians(angle)

        x = radius * math.cos(radians)
        y = radius * math.sin(radians)

        positioned_aps.append({
            **ap,
            "radar_angle": angle,
            "radar_radius": radius,
            "radar_x": x,
            "radar_y": y
        })

    return positioned_aps


def process_radar(aps):
    """
    Prepare AP data for the circular radar.
    """

    positioned = calculate_positions(aps)

    return {
        "total_aps": len(positioned),
        "aps": positioned
    }
