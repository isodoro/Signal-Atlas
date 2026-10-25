"""
signal_manager.py

Retrieves and processes Wi-Fi access point signal information
from Kismet's REST API device data.

Responsibilities:
- Extract signal history from Kismet's RRD data.
- Ignore empty history buckets.
- Calculate average signal strength in the power domain.
- Return structured AP data for radar positioning.

This module does not communicate with the Dash interface.
"""

#!/usr/bin/env python3

import math

RRD_INTERVAL = 60

# Recalculate the RRD buckets into their correct chronological order.
def recalc_rrd(start, now, interval, data):
    """
    Adjust a circular RRD vector using its timestamps.
    """

    if not data:
        return []

    length = len(data)

    if (now - start) > (interval * length):
        return [0] * length

    start_bin = (math.floor(start / interval) % length) + 1
    now_bin = (math.floor(now / interval) % length) + 1

    adjusted = []

    for index in range(length):
        slot = (now_bin + index) % length

        if start_bin <= slot < now_bin:
            adjusted.append(0)
        else:
            adjusted.append(data[slot])

    return adjusted

# Calculate the logarithmic average of valid dBm readings.
# Signal values must be averaged in the power domain, not arithmetically.
def average_signal(vector, blank_val=0):
    """
    Calculate the power-based average of valid dBm readings.
    """

    samples = [
        value for value in vector
        if value != blank_val and value is not None
    ]

    if not samples:
        return None

    mean_power = sum(
        10 ** (value / 10) for value in samples
    ) / len(samples)

    return 10 * math.log10(mean_power)

# Extract the historical signal readings from an individual Kismet device.
def extract_signal_history(device):
    """
    Extract and adjust signal history from a Kismet API device.
    """

    signal = device.get("kismet.device.base.signal", {})
    rrd = signal.get("kismet.common.signal.signal_rrd", {})

    vector = rrd.get("kismet.common.rrd.minute_vec", [])

    if not vector:
        return []

    start = rrd.get("kismet.common.rrd.last_time")
    now = rrd.get("kismet.common.rrd.serial_time")

    if start is not None and now is not None:
        vector = recalc_rrd(
            start,
            now,
            RRD_INTERVAL,
            vector
        )

    return vector

# Convert one Kismet device into the structured AP data used by the radar.
def process_ap(device):
    """
    Convert one Kismet Wi-Fi AP device into structured signal data.
    """

    if device.get("kismet.device.base.type") != "Wi-Fi AP":
        return None

    signal = device.get("kismet.device.base.signal", {})

    history = extract_signal_history(device)

    blank_val = (
        signal.get("kismet.common.signal.signal_rrd", {})
        .get("kismet.common.rrd.blank_val", 0)
    )

    average = average_signal(history, blank_val)

    return {
        "mac": device.get("kismet.device.base.macaddr"),
        "name": device.get("kismet.device.base.name"),
        "channel": device.get("kismet.device.base.channel"),
        "last_signal": signal.get(
            "kismet.common.signal.last_signal"
        ),
        "average_signal": average,
        "min_signal": signal.get(
            "kismet.common.signal.min_signal"
        ),
        "max_signal": signal.get(
            "kismet.common.signal.max_signal"
        ),
        "signal_history": history,
        "history_samples": sum(
            value != blank_val and value is not None
            for value in history
        ),
        "last_seen": device.get("kismet.device.base.last_time")
    }

# Filter and process the complete Kismet device list into Wi-Fi AP records.
def process_devices(devices):
    """
    Process all Wi-Fi APs returned by Kismet.
    """

    results = []

    for device in devices:
        ap = process_ap(device)

        if ap is not None:
            results.append(ap)

    return results
