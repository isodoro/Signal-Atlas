import logging
import struct
import time
from datetime import datetime

import requests

import dash
from dash import html, dcc
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

from around_me import (
    VIEWS,
    create_around_me_radar,
    fetch_around_me_data
)


def fetch_timeline_device(credentials, uri, mac):

    api_url = (
        f"http://{credentials}@{uri}"
        "/devices/views/all/devices.json"
    )

    response = requests.get(
        api_url,
        verify=False,
        timeout=10
    )
    response.raise_for_status()

    devices = response.json()

    if isinstance(devices, dict):
        devices = devices.get("devices", [])

    target_mac = mac.upper()

    return next(
        (
            device for device in devices
            if device.get(
                "kismet.device.base.macaddr", ""
            ).upper() == target_mac
        ),
        None
    )



def _pcapng_options(block, offset, end, endian):
    """Read PCAP-NG options."""
    options = {}

    while offset + 4 <= end:
        code, length = struct.unpack_from(
            endian + "HH", block, offset
        )
        offset += 4

        if code == 0:
            break

        if offset + length > end:
            break

        options[code] = block[offset:offset + length]
        offset += (length + 3) & ~3

    return options


def _radiotap_signal(packet):
    """Extract the Radiotap dBm Antenna Signal value."""
    if len(packet) < 8 or packet[0] != 0:
        return None

    radiotap_length = struct.unpack_from("<H", packet, 2)[0]

    if radiotap_length < 8 or radiotap_length > len(packet):
        return None

    present_words = []
    offset = 4

    while True:
        if offset + 4 > radiotap_length:
            return None

        present = struct.unpack_from("<I", packet, offset)[0]
        present_words.append(present)
        offset += 4

        if not (present & 0x80000000):
            break

    # The signal field is bit 5 in the first present bitmap.
    if not (present_words[0] & (1 << 5)):
        return None

    # Skip only fields actually present before field 5.
    field_layout = {
        0: (8, 8),  # TSFT
        1: (1, 1),  # Flags
        2: (1, 1),  # Rate
        3: (2, 4),  # Channel
        4: (2, 2),  # FHSS
    }

    for field in range(5):
        if present_words[0] & (1 << field):
            alignment, size = field_layout[field]
            offset = (
                (offset + alignment - 1) & ~(alignment - 1)
            )
            offset += size

    if offset >= radiotap_length:
        return None

    signal = struct.unpack_from("b", packet, offset)[0]

    # Zero is treated as an unavailable reading.
    return signal if signal < 0 else None


def extract_timeline_signal(pcap_data, rewind_seconds=3600):
    """Extract timestamped RSSI observations from PCAP-NG data."""
    if not pcap_data or len(pcap_data) < 28:
        return []

    try:
        rewind_seconds = max(1, int(rewind_seconds))
    except (TypeError, ValueError):
        rewind_seconds = 3600

    cutoff = time.time() - rewind_seconds
    samples = []
    interfaces = []
    offset = 0
    endian = None

    while offset + 12 <= len(pcap_data):
        block_type_bytes = pcap_data[offset:offset + 4]

        # Section Header Block establishes byte order.
        if block_type_bytes == b"\x0a\x0d\x0d\x0a":
            byte_order = pcap_data[offset + 8:offset + 12]

            if byte_order == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                break

            interfaces = []

        if endian is None:
            break

        block_type, block_length = struct.unpack_from(
            endian + "II", pcap_data, offset
        )

        if (
            block_length < 12
            or offset + block_length > len(pcap_data)
        ):
            break

        block = pcap_data[offset:offset + block_length]
        block_end = block_length - 4

        if block_type == 1:  # Interface Description Block
            linktype = struct.unpack_from(
                endian + "H", block, 8
            )[0]

            interface = {
                "linktype": linktype,
                "resolution": 1e-6,
                "time_offset": 0
            }

            options = _pcapng_options(
                block, 16, block_end, endian
            )

            # if_tsresol option
            if 9 in options and len(options[9]) == 1:
                resolution = options[9][0]

                if resolution & 0x80:
                    interface["resolution"] = (
                        2 ** -(resolution & 0x7f)
                    )
                else:
                    interface["resolution"] = (
                        10 ** -resolution
                    )

            # if_tsoffset option
            if 14 in options and len(options[14]) == 8:
                interface["time_offset"] = struct.unpack(
                    endian + "q", options[14]
                )[0]

            interfaces.append(interface)

        elif block_type == 6:  # Enhanced Packet Block
            if block_length < 32:
                offset += block_length
                continue

            (
                interface_id,
                timestamp_high,
                timestamp_low,
                captured_length
            ) = struct.unpack_from(
                endian + "IIII", block, 8
            )

            packet_start = 28
            packet_end = packet_start + captured_length

            if (
                interface_id < len(interfaces)
                and packet_end <= block_end
                and interfaces[interface_id]["linktype"] == 127
            ):
                interface = interfaces[interface_id]

                ticks = (
                    (timestamp_high << 32) | timestamp_low
                )

                timestamp = (
                    ticks * interface["resolution"]
                    + interface["time_offset"]
                )

                if timestamp >= cutoff:
                    packet = block[packet_start:packet_end]
                    signal = _radiotap_signal(packet)

                    if signal is not None:
                        samples.append({
                            "timestamp": timestamp,
                            "value": signal
                        })

        offset += block_length

    samples.sort(key=lambda sample: sample["timestamp"])
    return samples


def fetch_timeline_signal(
    credentials, uri, mac, rewind_seconds=3600
):
    """Retrieve historical packets for one device from Kismet."""
    try:
        rewind_seconds = max(1, int(rewind_seconds))
    except (TypeError, ValueError):
        rewind_seconds = 3600

    end_time = int(time.time())
    start_time = end_time - rewind_seconds

    api_url = (
        f"http://{credentials}@{uri}"
        "/logging/kismetdb/pcap/timeline-history.pcapng"
    )

    response = requests.get(
        api_url,
        params={
            "address_source": mac,
            "timestamp_start": start_time,
            "timestamp_end": end_time
        },
        verify=False,
        timeout=30
    )
    response.raise_for_status()

    return extract_timeline_signal(
        response.content,
        rewind_seconds
    )




def timeline_bucket_seconds(rewind_seconds):
    """Choose a display bucket size for the selected Past window."""
    try:
        rewind_seconds = int(rewind_seconds)
    except (TypeError, ValueError):
        rewind_seconds = 3600

    if rewind_seconds <= 300:
        return 5
    if rewind_seconds <= 900:
        return 15
    if rewind_seconds <= 3600:
        return 60
    if rewind_seconds <= 21600:
        return 300
    if rewind_seconds <= 86400:
        return 600
    if rewind_seconds <= 604800:
        return 1800
    return 3600


def aggregate_timeline_signal(samples, rewind_seconds=3600):
    """
    Average packet RSSI into time buckets and apply a
    centred three-bucket moving average.

    Empty buckets remain gaps; no values are interpolated.
    """
    bucket_size = timeline_bucket_seconds(rewind_seconds)
    buckets = {}

    for sample in samples or []:
        value = sample.get("value")
        timestamp = sample.get("timestamp")

        if value is None or timestamp is None:
            continue

        try:
            value = float(value)
            timestamp = float(timestamp)
        except (TypeError, ValueError):
            continue

        bucket = int(timestamp // bucket_size)
        buckets.setdefault(bucket, []).append(value)

    if not buckets:
        return [], bucket_size

    averages = {
        bucket: sum(values) / len(values)
        for bucket, values in buckets.items()
    }

    ordered_buckets = sorted(averages)
    result = []
    runs = []
    current_run = []

    for bucket in ordered_buckets:
        if current_run and bucket != current_run[-1] + 1:
            runs.append(current_run)
            current_run = []

        current_run.append(bucket)

    if current_run:
        runs.append(current_run)

    for run_index, run in enumerate(runs):

        # Preserve a visible break between separate observation periods.
        if run_index:
            previous_bucket = runs[run_index - 1][-1]
            next_bucket = run[0]

            gap_timestamp = (
                (previous_bucket + next_bucket + 1)
                * bucket_size / 2
            )

            result.append({
                "timestamp": gap_timestamp,
                "value": None
            })

        # Smooth only within continuous runs. Never smooth across gaps.
        for position, bucket in enumerate(run):
            neighbours = run[
                max(0, position - 1):
                min(len(run), position + 2)
            ]

            smoothed_value = (
                sum(averages[item] for item in neighbours)
                / len(neighbours)
            )

            result.append({
                "timestamp": (
                    bucket * bucket_size + bucket_size / 2
                ),
                "value": smoothed_value
            })

    return result, bucket_size



def create_timeline_placeholder(
    selection=None,
    device=None,
    rewind_seconds=3600,
    samples=None,
    line_color="#16A34A",
    line_label=None
):
    """Render one device's signal history, with its label at the line end."""

    fig = go.Figure()

    if not selection:
        message = (
            "Select a device from the radar "
            "to view its timeline."
        )

    elif device is None:
        message = (
            f"Selected device: {selection['mac']}<br>"
            "Device data was not returned by Kismet."
        )

    else:
        display_samples, bucket_size = aggregate_timeline_signal(
            samples or [],
            rewind_seconds
        )

        valid_indices = [
            index for index, sample in enumerate(display_samples)
            if sample.get("value") is not None
        ]

        if not valid_indices:
            message = (
                f"Selected device: {selection['mac']}<br>"
                "No packet signal observations were found "
                "in the selected Past window."
            )

        else:
            name = (
                device.get("kismet.device.base.name")
                or selection["mac"]
            )

            timestamps = [
                datetime.fromtimestamp(sample["timestamp"])
                for sample in display_samples
            ]
            values = [
                sample.get("value")
                for sample in display_samples
            ]

            endpoint_label = line_label or selection["mac"]
            endpoint_text = [""] * len(display_samples)
            endpoint_text[valid_indices[-1]] = endpoint_label

            fig.add_trace(
                go.Scatter(
                    x=timestamps,
                    y=values,
                    mode="lines+text",
                    text=endpoint_text,
                    textposition="middle right",
                    textfont=dict(color=line_color, size=11),
                    showlegend=False,
                    cliponaxis=False,
                    connectgaps=True,
                    line=dict(color=line_color, width=2),
                    hovertemplate=(
                        "%{x|%Y-%m-%d %H:%M:%S}<br>"
                        "%{y:.1f} dBm"
                        "<extra></extra>"
                    )
                )
            )

            fig.update_layout(
                title=(
                    f"{name} — {selection['mac']}"
                    "<br><sup>"
                    f"Mean RSSI per {bucket_size}-second bucket "
                    "with 3-bucket smoothing"
                    "</sup>"
                ),
                xaxis_title="Time",
                yaxis_title="Signal strength (dBm)",
                yaxis=dict(autorange=True),
                hovermode="closest",
                showlegend=False,
                paper_bgcolor="#FFFFFF",
                plot_bgcolor="#FFFFFF",
                margin=dict(l=65, r=220, t=75, b=55)
            )

            return fig

    fig.add_annotation(
        x=0.5,
        y=0.5,
        xref="paper",
        yref="paper",
        text=message,
        showarrow=False,
        font=dict(size=15, color="#475569"),
        align="center"
    )

    fig.update_layout(
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
        showlegend=False,
        margin=dict(l=65, r=220, t=35, b=55),
        xaxis=dict(visible=False),
        yaxis=dict(visible=False)
    )

    return fig






def create_ap_clients_timeline(
    ap_selection,
    clients,
    selected_client_mac,
    samples_by_mac,
    rewind_seconds,
    label_mode="device",
    ap_device=None,
    ap_samples=None
):
    """Plot an AP and its associated clients' packet signal histories."""

    fig = go.Figure()
    selected_mac = str(selected_client_mac or "").upper()
    plotted = 0

    def add_series(mac, raw_samples, label, color, width):
        nonlocal plotted

        try:
            display_samples, _bucket_size = aggregate_timeline_signal(
                raw_samples or [],
                rewind_seconds
            )
        except Exception:
            logging.exception(
                "Unable to aggregate signal history for %s", mac
            )
            return

        valid_indices = [
            index for index, sample in enumerate(display_samples)
            if sample.get("value") is not None
        ]

        if not valid_indices:
            return

        timestamps = [
            datetime.fromtimestamp(sample["timestamp"])
            for sample in display_samples
        ]
        values = [
            sample.get("value")
            for sample in display_samples
        ]

        endpoint_text = [""] * len(display_samples)
        endpoint_text[valid_indices[-1]] = label

        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=values,
                mode="lines+text",
                text=endpoint_text,
                textposition="middle right",
                textfont=dict(color=color, size=11),
                showlegend=False,
                cliponaxis=False,
                connectgaps=True,
                line=dict(color=color, width=width),
                hovertemplate=(
                    "%{x|%Y-%m-%d %H:%M:%S}<br>"
                    "%{y:.1f} dBm"
                    "<extra>" + label + "</extra>"
                )
            )
        )
        plotted += 1

    ap_mac = ap_selection.get("mac", "") if ap_selection else ""

    # The AP is plotted first and always in black.
    if ap_selection and ap_samples is not None:
        ap_type = (
            ap_device.get("device_type")
            if ap_device else None
        ) or "Wi-Fi AP"

        add_series(
            ap_mac,
            ap_samples,
            f"{ap_type} - {ap_mac}",
            "#000000",
            2
        )

    # Selected client is green; other associated clients are grey.
    for client in clients:
        mac = str(client.get("mac", "")).upper()
        if not mac:
            continue

        is_selected = mac == selected_mac

        if label_mode == "mac":
            label = mac
        else:
            device_type = client.get("device_type") or "Wi-Fi Client"
            label = f"{device_type} - {mac}"

        add_series(
            mac,
            samples_by_mac.get(mac, []),
            label,
            "#16A34A" if is_selected else "#9CA3AF",
            3 if is_selected else 1.5
        )

    if not plotted:
        fig.add_annotation(
            x=0.5,
            y=0.5,
            xref="paper",
            yref="paper",
            text=(
                "No packet signal observations were returned "
                "for these devices in the selected Past window."
            ),
            showarrow=False,
            font=dict(size=14, color="#475569"),
            align="center"
        )

    if ap_selection:
        title = f"Signal history — AP {ap_mac}"
    else:
        title = "Device signal history"

    fig.update_layout(
        title=(
            title
            + "<br><sup>"
            "Selected client: green | Other associated clients: grey "
            "| AP: black"
            "</sup>"
        ),
        xaxis_title="Time",
        yaxis_title="Signal strength (dBm)",
        hovermode="closest",
        showlegend=False,
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
        margin=dict(l=65, r=220, t=75, b=55)
    )

    return fig



def create_timeline_device_details(selection, data, raw_device=None):
    """Build the compact device, AP and same-AP client information panel."""

    if not selection:
        return html.Div("Select a device to view its details.")

    mac = str(selection.get("mac", "")).upper()
    selection_type = selection.get("type", "client")

    current_devices = data.get("current", [])
    aps = data.get("aps", [])

    selected_client = next(
        (
            item for item in current_devices
            if str(item.get("mac", "")).upper() == mac
        ),
        None
    )

    selected_ap = next(
        (
            item for item in aps
            if str(item.get("mac", "")).upper() == mac
        ),
        None
    )

    if selection_type == "ap":
        ap_mac = mac
        subject = selected_ap
        heading = "Selected access point"
    else:
        ap_mac = (
            selected_client.get("associated_ap_mac")
            if selected_client else None
        )
        subject = selected_client
        heading = "Selected device"

    details = []

    if subject:
        details.append(
            html.Div([
                html.Strong(heading),
                html.Div(
                    subject.get("name")
                    or subject.get("ssid")
                    or subject.get("device_type")
                    or "Unknown device"
                ),
                html.Div(f"MAC: {mac}"),
                html.Div(
                    "First seen: "
                    + _timeline_format_observation_time(
                        raw_device,
                        "kismet.device.base.first_time"
                    )
                ),
                html.Div(
                    "Last seen: "
                    + _timeline_format_observation_time(
                        raw_device,
                        "kismet.device.base.last_time"
                    )
                )
            ], className="timeline-detail-section")
        )
    else:
        details.append(
            html.Div([
                html.Strong(heading),
                html.Div(f"MAC: {mac}"),
                html.Div("Device details were not returned in this view.")
            ], className="timeline-detail-section")
        )

    if ap_mac:
        ap = next(
            (
                item for item in aps
                if str(item.get("mac", "")).upper()
                == str(ap_mac).upper()
            ),
            None
        )

        ap_label = (
            (ap.get("ssid") or ap.get("name") or "Access point")
            if ap else "Access point"
        )

        details.append(
            html.Div([
                html.Strong("Associated access point"),
                html.Div(ap_label),
                html.Div(f"MAC: {ap_mac}")
            ], className="timeline-detail-section")
        )

        peers = [
            item for item in current_devices
            if str(item.get("associated_ap_mac", "")).upper()
            == str(ap_mac).upper()
            and str(item.get("mac", "")).upper() != mac
        ]

        details.append(
            html.Div([
                html.Strong(
                    f"Other currently associated clients ({len(peers)})"
                ),
                html.Ul([
                    html.Li(
                        f"{item.get('name') or item.get('device_type') or 'Device'}"
                        f" — {item.get('mac', '')}"
                    )
                    for item in peers
                ]) if peers else html.Div("No other clients recorded.")
            ], className="timeline-detail-section")
        )
    else:
        details.append(
            html.Div([
                html.Strong("Associated access point"),
                html.Div("No current AP association recorded.")
            ], className="timeline-detail-section")
        )

    return html.Div(details, className="timeline-details-content")




def _fetch_live_timeline_devices(credentials, uri):
    """Retrieve the current device records from the live Kismet API."""

    api_url = (
        f"http://{credentials}@{uri}"
        "/devices/views/all/devices.json"
    )

    response = requests.get(
        api_url,
        verify=False,
        timeout=10
    )
    response.raise_for_status()

    devices = response.json()

    if isinstance(devices, dict):
        devices = devices.get("devices", [])

    return devices if isinstance(devices, list) else []


def _timeline_device_ssid(device):
    dot11 = device.get("dot11.device", {})

    record = dot11.get(
        "dot11.device.last_beaconed_ssid_record",
        {}
    )

    ssid = record.get("dot11.advertisedssid.ssid")

    if not ssid:
        advertised = dot11.get(
            "dot11.device.advertised_ssid_map",
            []
        )

        if advertised:
            ssid = advertised[0].get(
                "dot11.advertisedssid.ssid"
            )

    return ssid


def _timeline_format_observation_time(device, field):
    """Format a Kismet first-seen or last-seen observation timestamp."""

    if not device:
        return "Not available"

    value = device.get(field)

    try:
        timestamp = float(value)
        if timestamp <= 0:
            return "Not available"

        return datetime.fromtimestamp(timestamp).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except (TypeError, ValueError, OverflowError, OSError):
        return "Not available"


def _timeline_normalise_device(device):
    """Convert a Kismet device record into the radar's item format."""

    signal = device.get(
        "kismet.device.base.signal",
        {}
    )

    mac = device.get("kismet.device.base.macaddr", "")

    return {
        "mac": mac,
        "name": device.get("kismet.device.base.name"),
        "device_type": device.get("kismet.device.base.type"),
        "manufacturer": device.get(
            "kismet.device.base.manuf"
        ),
        "ssid": _timeline_device_ssid(device),
        "average_signal": signal.get(
            "kismet.common.signal.last_signal"
        ),
        "last_signal": signal.get(
            "kismet.common.signal.last_signal"
        ),
    }


def _timeline_associated_macs(ap_device):
    """Extract client MAC addresses from Kismet's associated-client map."""

    dot11 = ap_device.get("dot11.device", {})
    associated = dot11.get(
        "dot11.device.associated_client_map",
        {}
    )

    found = set()

    def add_candidate(value):
        if isinstance(value, str):
            candidate = value.strip().upper()
            if candidate.count(":") == 5 and len(candidate) == 17:
                found.add(candidate)

        elif isinstance(value, dict):
            for key in (
                "kismet.device.base.macaddr",
                "mac",
                "macaddr",
                "dot11.client.mac"
            ):
                candidate = value.get(key)
                if isinstance(candidate, str):
                    add_candidate(candidate)

    if isinstance(associated, dict):
        for key, value in associated.items():
            add_candidate(key)
            add_candidate(value)

    elif isinstance(associated, list):
        for value in associated:
            add_candidate(value)

    return found


def fetch_ap_activity_data(credentials, uri, rewind_seconds, selected_mac):
    """Build the selected AP/Bridge and its currently associated clients."""

    devices = _fetch_live_timeline_devices(credentials, uri)
    cutoff = time.time() - int(rewind_seconds)

    detected = [
        device for device in devices
        if device.get("kismet.device.base.last_time", 0) >= cutoff
    ]

    lookup = {
        str(device.get("kismet.device.base.macaddr", "")).upper(): device
        for device in detected
        if device.get("kismet.device.base.macaddr")
    }

    selected = lookup.get(str(selected_mac).upper())

    if not selected:
        return {
            "selected": None,
            "devices": [],
            "clients": [],
            "client_count": 0
        }

    selected_item = _timeline_normalise_device(selected)
    selected_item["associated_ap_mac"] = None

    associated_macs = _timeline_associated_macs(selected)

    clients = []

    for mac in sorted(associated_macs):
        raw_client = lookup.get(mac)

        if not raw_client:
            continue

        client = _timeline_normalise_device(raw_client)
        client["associated_ap_mac"] = selected_item["mac"]
        client["associated_ap_ssid"] = selected_item.get("ssid")
        clients.append(client)

    return {
        "selected": selected_item,
        "devices": [selected_item] + clients,
        "clients": clients,
        "client_count": len(clients)
    }


def create_ap_activity_details(selection, activity, raw_device=None):
    """Details panel for the selected AP or bridged device."""

    selected = activity.get("selected")

    if not selection:
        return html.Div(
            "Search for an access point or bridge to view its activity."
        )

    if not selected:
        return html.Div(
            f"Selected device: {selection.get('mac', '')} — "
            "not present in the selected Past window."
        )

    sections = [
        html.Div([
            html.Strong("Selected AP / Bridge"),
            html.Div(selected.get("name") or "Unknown device"),
            html.Div(f"Type: {selected.get('device_type') or 'Unknown'}"),
            html.Div(f"MAC: {selected.get('mac', '')}"),
            html.Div(
                "First seen: "
                + _timeline_format_observation_time(
                    raw_device,
                    "kismet.device.base.first_time"
                )
            ),
            html.Div(
                "Last seen: "
                + _timeline_format_observation_time(
                    raw_device,
                    "kismet.device.base.last_time"
                )
            ),
            html.Div(f"SSID: {selected.get('ssid') or 'Not available'}"),
            html.Div(
                f"Manufacturer: {selected.get('manufacturer') or 'Not available'}"
            ),
            html.Div(
                f"Latest signal: {selected.get('average_signal')} dBm"
                if selected.get("average_signal") is not None
                else "Latest signal: Not available"
            )
        ], className="timeline-detail-section"),

        html.Div([
            html.Strong(
                f"Currently associated clients ({activity.get('client_count', 0)})"
            ),
            html.Ul([
                html.Li(
                    f"{client.get('name') or client.get('device_type') or 'Device'}"
                    f" — {client.get('mac', '')}"
                    f" — "
                    f"{client.get('average_signal')} dBm"
                    if client.get("average_signal") is not None
                    else
                    f"{client.get('name') or client.get('device_type') or 'Device'}"
                    f" — {client.get('mac', '')}"
                )
                for client in activity.get("clients", [])
            ]) if activity.get("clients") else html.Div(
                "No currently associated clients were returned in this Past window."
            )
        ], className="timeline-detail-section")
    ]

    return html.Div(sections, className="timeline-details-content")


def create_timeline_layout():

    return html.Div([

        dcc.Store(
            id="timeline_view_index",
            data=2
        ),

        dcc.Store(
            id="timeline_selection",
            data=None
        ),

        html.Div([

            # LEFT: DEVICE TIMELINE
            html.Div([

                html.Div([
                    html.Div(
                        "Timeline View",
                        className="timeline-control-label"
                    ),
                    dcc.Dropdown(
                        id="timeline_mode",
                        options=[
                            {
                                "label": "Device Activity",
                                "value": "device_activity"
                            },
                            {
                                "label": "AP Activity and Signal History",
                                "value": "ap_activity"
                            }
                        ],
                        value="device_activity",
                        clearable=False,
                        searchable=False,
                        className="timeline-mode-dropdown"
                    )
                ], className="timeline-controls"),

                html.Div([
                    dcc.Graph(
                        id="timeline_graph",
                        figure=create_timeline_placeholder(),
                        config={"responsive": True},
                        className="timeline-half-graph",
                        style={
                            "height": "50%",
                            "width": "100%"
                        }
                    ),
                    html.Div(
                        id="timeline_details",
                        className="timeline-details",
                        children=create_timeline_device_details(None, {})
                    )
                ], className="timeline-panel-content")

            ], className="around-me-panel"),

            # RIGHT: DEVICE RADAR AND ASSOCIATION VIEWS
            html.Div([

                html.Div([

                    dbc.Button(
                        "‹",
                        id="timeline_previous",
                        n_clicks=0,
                        color="secondary"
                    ),

                    html.Div([
                        html.Span(
                            VIEWS[2]["title"],
                            id="timeline_view_title",
                            style={"fontWeight": "bold"}
                        ),
                        html.Span(": "),
                        html.Span(
                            VIEWS[2]["question"],
                            id="timeline_question"
                        )
                    ], className="around-me-heading"),

                    dbc.Button(
                        "›",
                        id="timeline_next",
                        n_clicks=0,
                        color="secondary"
                    )

                ], className="around-me-navigation"),

                dcc.Graph(
                    id="timeline_devices_network",
                    figure=create_around_me_radar(
                        [],
                        VIEWS[2]["title"],
                        device_mode=True
                    ),
                    config={"responsive": True, "scrollZoom": True},
                    style={
                        "height": "100%",
                        "width": "100%"
                    }
                ),

                html.Div(
                    id="timeline_status",
                    className="around-me-status"
                )

            ], className="around-me-panel")

        ], className="around-me-grid")

    ], id="timeline_container")


def register_timeline_callbacks(app):

    @app.callback(
        Output("timeline_view_index", "data"),
        [
            Input("timeline_previous", "n_clicks"),
            Input("timeline_next", "n_clicks"),
            Input("timeline_mode", "value")
        ],
        State("timeline_view_index", "data")
    )
    def change_timeline_view(previous, next_click, mode, current):

        triggered = dash.callback_context.triggered

        if not triggered:
            return 2

        trigger_id = triggered[0]["prop_id"].split(".")[0]

        # Device Activity always opens on Currently Associated.
        if trigger_id == "timeline_mode":
            return 2

        if trigger_id == "timeline_previous":
            return (current - 1) % len(VIEWS)

        if trigger_id == "timeline_next":
            return (current + 1) % len(VIEWS)

        return current

    @app.callback(
        Output("timeline_selection", "data"),
        [
            Input("timeline_devices_network", "clickData"),
            Input("shared_device_selection", "data"),
            Input("timeline_mode", "value")
        ],
        State("timeline_selection", "data"),
        State("kismet_credentials", "value"),
        State("kismet_uri", "value"),
        State("rewind_seconds", "value")
    )
    def select_timeline_device(
        click_data,
        shared_selection,
        current_mode,
        current_selection,
        credentials,
        uri,
        rewind_seconds
    ):

        triggered = dash.callback_context.triggered

        if not triggered:
            raise dash.exceptions.PreventUpdate

        source_id = triggered[0]["prop_id"].split(".")[0]

        # Preserve the client selection when moving between modes.
        if source_id == "timeline_mode":

            # Device Activity -> AP Activity: carry the client's AP and MAC.
            if (
                current_mode == "ap_activity"
                and current_selection
                and current_selection.get("type") == "client"
            ):
                try:
                    live_data = fetch_around_me_data(
                        credentials,
                        uri,
                        rewind_seconds
                    )

                    selected_mac = str(
                        current_selection.get("mac", "")
                    ).upper()

                    selected_client = next(
                        (
                            item for item in live_data.get("current", [])
                            if str(item.get("mac", "")).upper()
                                == selected_mac
                        ),
                        None
                    )

                    associated_ap = (
                        selected_client.get("associated_ap_mac")
                        if selected_client else None
                    )

                    if associated_ap:
                        return {
                            "type": "ap",
                            "mac": associated_ap,
                            "selected_client_mac":
                                current_selection["mac"]
                        }

                except Exception:
                    logging.exception(
                        "Unable to resolve selected client's associated AP"
                    )

                return None

            # AP Activity -> Device Activity:
            # restore the previous client when one was carried over;
            # otherwise retain the AP as context for its grey client lines.
            if (
                current_mode == "device_activity"
                and current_selection
                and current_selection.get("type") == "ap"
            ):
                previous_client = current_selection.get(
                    "selected_client_mac"
                )

                if previous_client:
                    return {
                        "type": "client",
                        "mac": previous_client
                    }

                return {
                    "type": "ap",
                    "mac": current_selection["mac"]
                }

            return None

        if source_id == "shared_device_selection":

            if not shared_selection:
                return None

            mac = shared_selection.get("mac")
            if not mac:
                return None

            selection_type = shared_selection.get("type", "client")

        elif source_id == "timeline_devices_network":

            if not click_data or not click_data.get("points"):
                raise dash.exceptions.PreventUpdate

            point = click_data["points"][0]
            mac = point.get("customdata")

            if not mac:
                raise dash.exceptions.PreventUpdate

            # The right-hand graph is the AP radar in AP Activity mode,
            # and the associated-device radar in Device Activity mode.
            selection_type = (
                "ap" if current_mode == "ap_activity"
                else "client"
            )

        else:
            raise dash.exceptions.PreventUpdate

        new_selection = {
            "type": selection_type,
            "mac": mac
        }

        # Compare marker identity only; carried metadata must not
        # interfere with clicking the same AP again to clear selection.
        if (
            current_selection
            and current_selection.get("type") == new_selection["type"]
            and str(current_selection.get("mac", "")).upper()
                == str(new_selection["mac"]).upper()
        ):
            return None

        return new_selection

    @app.callback(
        [
            Output("timeline_graph", "figure"),
            Output("timeline_details", "children"),
            Output("timeline_devices_network", "figure"),
            Output("timeline_view_title", "children"),
            Output("timeline_question", "children"),
            Output("timeline_status", "children")
        ],
        [
            Input("graph_type", "value"),
            Input("update_graph", "n_clicks"),
            Input("timeline_view_index", "data"),
            Input("timeline_selection", "data"),
            Input("timeline_mode", "value"),
            Input("rewind_seconds", "value")
        ],
        [
            State("kismet_credentials", "value"),
            State("kismet_uri", "value")
        ]
    )
    def update_timeline(
        graph_type,
        n_clicks,
        view_index,
        selection,
        timeline_mode,
        rewind_seconds,
        credentials,
        uri
    ):

        if graph_type != "timeline":
            raise dash.exceptions.PreventUpdate

        view = VIEWS[view_index]

        try:

            # AP ACTIVITY AND SIGNAL HISTORY
            if timeline_mode == "ap_activity":

                # Use exactly the same AP collection as What's Around Me.
                data = fetch_around_me_data(
                    credentials,
                    uri,
                    rewind_seconds
                )

                ap_selection = (
                    selection
                    if selection and selection.get("type") == "ap"
                    else None
                )

                # The AP radar is the existing APs Detected radar.
                radar_figure = create_around_me_radar(
                    data["aps"],
                    "APs Detected",
                    selection=ap_selection
                )

                if ap_selection:
                    activity = fetch_ap_activity_data(
                        credentials,
                        uri,
                        rewind_seconds,
                        ap_selection["mac"]
                    )
                else:
                    activity = {
                        "selected": None,
                        "devices": [],
                        "clients": [],
                        "client_count": 0
                    }

                selected_client_mac = (
                    selection.get("selected_client_mac")
                    if selection and ap_selection
                    else None
                )

                if activity.get("selected"):
                    clients_for_plot = list(activity.get("clients", []))

                    known_macs = {
                        str(client.get("mac", "")).upper()
                        for client in clients_for_plot
                    }

                    selected_mac_upper = str(
                        selected_client_mac
                    ).upper()

                    # Ensure the selected client is included even if the
                    # AP association map omitted it in this API response.
                    if (
                        selected_client_mac
                        and selected_mac_upper not in known_macs
                    ):
                        try:
                            raw_selected = fetch_timeline_device(
                                credentials,
                                uri,
                                selected_client_mac
                            )
                            if raw_selected:
                                selected_item = _timeline_normalise_device(
                                    raw_selected
                                )
                                clients_for_plot.append(selected_item)
                        except Exception:
                            logging.exception(
                                "Unable to retrieve selected client details"
                            )

                    samples_by_mac = {}

                    for client in clients_for_plot:
                        client_mac = str(
                            client.get("mac", "")
                        ).upper()

                        if not client_mac:
                            continue

                        try:
                            samples_by_mac[client_mac] = fetch_timeline_signal(
                                credentials,
                                uri,
                                client_mac,
                                rewind_seconds
                            )
                        except Exception:
                            logging.exception(
                                "Unable to retrieve signal history for %s",
                                client_mac
                            )
                            samples_by_mac[client_mac] = []

                    ap_samples = fetch_timeline_signal(
                        credentials,
                        uri,
                        ap_selection["mac"],
                        rewind_seconds
                    )

                    timeline_figure = create_ap_clients_timeline(
                        ap_selection,
                        clients_for_plot,
                        selected_client_mac,
                        samples_by_mac,
                        rewind_seconds,
                        label_mode="device",
                        ap_device=activity.get("selected"),
                        ap_samples=ap_samples
                    )

                else:
                    # Preserve the existing AP-only timeline for direct
                    # AP selections and when no client was carried over.
                    timeline_device = (
                        fetch_timeline_device(
                            credentials,
                            uri,
                            ap_selection["mac"]
                        )
                        if ap_selection else None
                    )

                    timeline_samples = (
                        fetch_timeline_signal(
                            credentials,
                            uri,
                            ap_selection["mac"],
                            rewind_seconds
                        )
                        if ap_selection else []
                    )

                    ap_type = (
                        timeline_device.get("kismet.device.base.type")
                        if timeline_device else None
                    ) or "Wi-Fi AP"

                    timeline_figure = create_timeline_placeholder(
                        ap_selection,
                        timeline_device,
                        rewind_seconds,
                        timeline_samples,
                        line_color="#000000",
                        line_label=(
                            f"{ap_type} - {ap_selection['mac']}"
                            if ap_selection else None
                        )
                    )

                details = create_ap_activity_details(
                    ap_selection,
                    activity
                )

                title = "AP Activity and Signal History"
                question = (
                    "When was this AP or bridge transmitting, "
                    "and which clients are currently associated?"
                )

                if not ap_selection:
                    status = (
                        f"APs detected: {data['ap_count']} | "
                        "Select an AP from the radar to view its "
                        "signal history and associated clients."
                    )
                elif not activity["selected"]:
                    status = (
                        f"APs detected: {data['ap_count']} | "
                        "The selected AP was not detected within "
                        "the selected Past window."
                    )
                else:
                    status = (
                        f"APs detected: {data['ap_count']} | "
                        f"Associated clients: {activity['client_count']}"
                    )

                return (
                    timeline_figure,
                    details,
                    radar_figure,
                    title,
                    question,
                    status
                )

            # DEVICE ACTIVITY — retain the existing Stage 1 behaviour.
            data = fetch_around_me_data(
                credentials,
                uri,
                rewind_seconds
            )

            # Only client selections are highlighted on the device radar.
            # An AP selection is retained as timeline context instead.
            radar_selection = (
                dict(selection)
                if selection and selection.get("type") == "client"
                else None
            )

            selected_device = None

            if radar_selection:

                selected_device = next(
                    (
                        device for device in data["current"]
                        if device.get("mac", "").upper()
                        == radar_selection["mac"].upper()
                    ),
                    None
                )

                if selected_device:
                    radar_selection["associated_ap_mac"] = (
                        selected_device.get("associated_ap_mac")
                    )

            if view_index == 0:

                right_data = []

                view_status = (
                    "Historical association evidence is required "
                    "to classify this population."
                )

            elif view_index == 1:

                right_data = []

                view_status = (
                    "Historical association and explicit "
                    "disconnection evidence is required."
                )

            else:

                right_data = data["current"]

                view_status = (
                    f"Currently associated devices: "
                    f"{data['current_count']}"
                )

            radar_figure = create_around_me_radar(
                right_data,
                view["title"],
                device_mode=True,
                selection=radar_selection
            )

            if selection:
                clients_for_plot = []
                associated_activity = {
                    "selected": None,
                    "devices": [],
                    "clients": [],
                    "client_count": 0
                }

                if selection.get("type") == "ap":
                    associated_ap_mac = selection.get("mac")
                else:
                    associated_ap_mac = (
                        selected_device.get("associated_ap_mac")
                        if selected_device else None
                    )

                # Retrieve the AP's currently associated client population.
                if associated_ap_mac:
                    associated_activity = fetch_ap_activity_data(
                        credentials,
                        uri,
                        rewind_seconds,
                        associated_ap_mac
                    )
                    clients_for_plot = list(
                        associated_activity.get("clients", [])
                    )

                selected_mac_upper = str(
                    selection.get("mac", "")
                ).upper()

                known_macs = {
                    str(client.get("mac", "")).upper()
                    for client in clients_for_plot
                }

                # Ensure a selected client is always included.
                # An AP-context selection must not be added as a client.
                if (
                    selection.get("type") == "client"
                    and selected_mac_upper not in known_macs
                ):
                    if selected_device:
                        clients_for_plot.append(selected_device)
                    else:
                        raw_selected = fetch_timeline_device(
                            credentials,
                            uri,
                            selection["mac"]
                        )
                        if raw_selected:
                            selected_item = _timeline_normalise_device(
                                raw_selected
                            )
                            clients_for_plot.append(selected_item)

                samples_by_mac = {}

                for client in clients_for_plot:
                    client_mac = str(
                        client.get("mac", "")
                    ).upper()

                    if not client_mac:
                        continue

                    try:
                        samples_by_mac[client_mac] = fetch_timeline_signal(
                            credentials,
                            uri,
                            client_mac,
                            rewind_seconds
                        )
                    except Exception:
                        logging.exception(
                            "Unable to retrieve signal history for %s",
                            client_mac
                        )
                        samples_by_mac[client_mac] = []

                timeline_figure = create_ap_clients_timeline(
                    (
                        {"mac": associated_ap_mac}
                        if associated_ap_mac else None
                    ),
                    clients_for_plot,
                    (
                        selection["mac"]
                        if selection.get("type") == "client"
                        else None
                    ),
                    samples_by_mac,
                    rewind_seconds,
                    label_mode="mac"
                )

            else:
                timeline_figure = create_timeline_placeholder()

            raw_selected_for_details = None

            if selection:
                raw_selected_for_details = fetch_timeline_device(
                    credentials,
                    uri,
                    selection.get("mac", "")
                )

            if selection and selection.get("type") == "ap":
                timeline_details = create_ap_activity_details(
                    selection,
                    associated_activity,
                    raw_selected_for_details
                )
            else:
                timeline_details = create_timeline_device_details(
                    selection,
                    data,
                    raw_selected_for_details
                )

            return (
                timeline_figure,
                timeline_details,
                radar_figure,
                view["title"],
                view["question"],
                f"APs detected: {data['ap_count']} | {view_status}"
            )

        except Exception as error:

            logging.exception("Unable to update Timeline")

            if timeline_mode == "ap_activity":
                title = "AP Activity and Signal History"
                question = (
                    "When was this AP or bridge transmitting, "
                    "and which clients are currently associated?"
                )
                details = create_ap_activity_details(selection, {})
            else:
                title = view["title"]
                question = view["question"]
                details = create_timeline_device_details(selection, {})

            return (
                create_timeline_placeholder(selection),
                details,
                create_around_me_radar(
                    [],
                    title,
                    device_mode=True
                ),
                title,
                question,
                f"Kismet API error: {error}"
            )
