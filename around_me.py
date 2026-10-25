
import time
import logging
import requests
import math
import struct

import dash
from dash import html, dcc
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

from radar_style import add_radar_grid, apply_radar_layout

from signal_manager import process_devices
from signal_position import calculate_positions, SIGNAL_MIN, SIGNAL_MAX


DEVICE_COLOURS = {
    "Wi-Fi AP": "#000000",
    "Wi-Fi Bridged": "#808080",
    "Wi-Fi Device": "#008000",
    "Wi-Fi Client": "#008000",
    "Wi-Fi Device (Inferred)": "#808000",
    "Wi-Fi Ad-Hoc": "#800080",
    "Wi-Fi WDS Device": "#008080",
    "Wi-Fi WDS AP": "#C0C0C0",
}

NON_AP_TYPES = {
    "Wi-Fi Device",
    "Wi-Fi Device (Inferred)",
    "Wi-Fi WDS Device",
    "Wi-Fi Ad-Hoc",
    "Wi-Fi Bridged",
    "Wi-Fi Client",
}

def _frequency_band(frequency_mhz):
    """Classify a Wi-Fi frequency by technical band, not country allocation."""
    if frequency_mhz is None:
        return None
    if 2400 <= frequency_mhz < 2500:
        return "2.4 GHz"
    if 4900 <= frequency_mhz < 5925:
        return "5 GHz"
    if 5925 <= frequency_mhz <= 7125:
        return "6 GHz"
    return None


def _classify_security(records, fallback_crypt=None):
    """Return security categories explicitly evidenced by Kismet."""
    categories = set()
    texts = [
        str(record.get("dot11.advertisedssid.crypt_string", "") or "")
        for record in records
    ]

    if not any(texts) and fallback_crypt:
        texts = [str(fallback_crypt)]

    for text in texts:
        upper = text.upper()
        generations = set()

        # Exact protocol tokens prevent WPA matching WPA2 or WPA3.
        import re
        if re.search(r"(?<![A-Z0-9])WPA3(?![A-Z0-9])", upper):
            generations.add("wpa3")
        if re.search(r"(?<![A-Z0-9])WPA2(?![A-Z0-9])", upper):
            generations.add("wpa2")
        if re.search(r"(?<![A-Z0-9])WPA(?![A-Z0-9])", upper):
            generations.add("wpa")

        if generations:
            categories.update(generations)

        if "WEP" in upper:
            categories.add("wep")

        if "OWE" in upper:
            categories.add("owe")

        if upper.strip() in ("OPEN", "NONE", "NO ENCRYPTION"):
            categories.add("open")

        if len(generations) > 1:
            categories.add("mixed")

    return sorted(categories)


def _wps_version_label(value):
    try:
        version = int(value)
    except (TypeError, ValueError):
        return None

    known = {
        0x10: "1.0",
        0x20: "2.0",
        0x21: "2.0.1",
        0x22: "2.0.2",
    }
    return known.get(version, f"Other ({version:#04x})")


def _wps_methods_from_records(records):
    """Decode standard WPS Config Methods bits."""
    method_bits = {
        0x0001: "USB",
        0x0002: "Ethernet",
        0x0004: "Label",
        0x0008: "Display",
        0x0010: "External NFC",
        0x0020: "Integrated NFC",
        0x0040: "NFC Interface",
        0x0080: "Push Button",
        0x0100: "Keypad",
    }

    methods = set()
    observed = False

    for record in records:
        value = record.get("dot11.advertisedssid.wps_config_methods")
        if value is None:
            continue

        observed = True
        try:
            value = int(value)
        except (TypeError, ValueError):
            continue

        for bit, label in method_bits.items():
            if value & bit:
                methods.add(label)

    return sorted(methods), observed


def _wps_states_from_records(records):
    """Decode Kismet's WPS state bitfield."""
    CONFIGURED = 0x01
    NOT_CONFIGURED = 0x02
    LOCKED = 0x04

    states = set()
    observed = False

    for record in records:
        value = record.get("dot11.advertisedssid.wps_state")
        if value is None:
            continue

        try:
            value = int(value)
        except (TypeError, ValueError):
            continue

        if value == 0:
            continue

        observed = True
        configured = bool(value & CONFIGURED)
        not_configured = bool(value & NOT_CONFIGURED)
        locked = bool(value & LOCKED)

        if configured and locked:
            states.add("configured_locked")
        elif locked:
            states.add("locked")
        elif configured:
            states.add("configured")
        elif not_configured:
            states.add("not_configured")

    return sorted(states), observed


def filter_around_me_aps(
    aps,
    bands=None,
    channels=None,
    frequency_range=None,
    encryption=None,
    pmf=None,
    wps=None
):
    """Apply independent AP filters; selections within a filter are ORed."""
    bands = set(bands or [])
    channels = {str(value) for value in (channels or [])}
    encryption = set(encryption or [])
    pmf = set(pmf or [])
    wps = set(wps or [])

    if frequency_range and len(frequency_range) == 2:
        low, high = sorted(float(value) for value in frequency_range)
    else:
        low, high = None, None

    filtered = []

    for ap in aps:
        frequency = ap.get("frequency_mhz")
        channel = ap.get("channel")

        observed_bands = set(
            ap.get("frequency_bands")
            or ([ap.get("frequency_band")] if ap.get("frequency_band") else [])
        )
        observed_frequencies = ap.get("frequencies_mhz") or (
            [frequency] if frequency is not None else []
        )

        if bands and not bands.intersection(observed_bands):
            continue

        if channels and str(channel) not in channels:
            continue

        # Unknown frequencies remain visible when no radio filter is active.
        if frequency_range and not any(
            low <= value <= high for value in observed_frequencies
        ):
            continue

        if encryption and not encryption.intersection(ap.get("security_types", [])):
            continue

        supported = ap.get("pmf_supported")
        required = ap.get("pmf_required")

        if pmf:
            if required is True:
                pmf_state = "required"
            elif supported is True:
                pmf_state = "supported"
            elif supported is False and required is False:
                pmf_state = "unsupported"
            else:
                pmf_state = "unknown"

            if pmf_state not in pmf:
                continue

        if wps:
            observed = ap.get("wps_observed", False)
            versions = set(ap.get("wps_versions", []))
            methods = set(ap.get("wps_methods", []))
            states = set(ap.get("wps_states", []))

            matches = set()

            if observed:
                matches.add("advertised")
            else:
                matches.add("unknown")

            for version in versions:
                matches.add(f"version:{version}")

            if any(version != "1.0" for version in versions):
                matches.add("version:other")

            for state in states:
                matches.add(f"state:{state}")

            for method in methods:
                matches.add(f"method:{method}")

            if not wps.intersection(matches):
                continue

        filtered.append(ap)

    return filtered


VIEWS = [
    {
        "title": "Never Associated",
        "question": "Which devices have been detected without ever being observed associated with an access point during this period?"
    },
    {
        "title": "Previously Associated",
        "question": "Which devices have been observed connected to an access point but are no longer associated?"
    },
    {
        "title": "Currently Associated",
        "question": "Which devices are currently observed associated with an access point?"
    }
]


def signal_colour(signal):

    if signal is None:
        return "#F59E0B"

    # Clamp signal to the agreed range.
    signal = max(-90.0, min(-20.0, float(signal)))

    # Black at -20 dBm, light grey at -90 dBm.
    intensity = round(((-20.0 - signal) / 70.0) * 211)

    return f"#{intensity:02X}{intensity:02X}{intensity:02X}"




def position_around_me_devices(items):

    valid_items = [
        dict(item)
        for item in items
        if item.get("mac")
    ]

    signal_groups = {}

    # Validate signals and calculate radial positions.
    for item in valid_items:

        signal = item.get("average_signal")

        try:
            signal = float(signal)

            if not math.isfinite(signal) or signal >= 0:
                signal = None

        except (TypeError, ValueError):
            signal = None

        if signal is None:

            radius = 1.05
            group_key = None

        else:

            signal = max(-90.0, min(-20.0, signal))

            radius = (
                0.10 +
                ((-20.0 - signal) / 70.0) * 0.90
            )

            group_key = signal

        item["average_signal"] = signal
        item["radar_radius"] = radius

        signal_groups.setdefault(group_key, []).append(item)

    positioned = []

    # Give each signal group an independent angular offset.
    for group_index, group_key in enumerate(
        sorted(
            signal_groups,
            key=lambda value: (
                value is None,
                value if value is not None else 0
            )
        )
    ):

        group = signal_groups[group_key]

        group.sort(
            key=lambda item: item["mac"].upper()
        )

        count = len(group)

        # Rotate successive signal groups by a fixed offset.
        offset = (group_index * 17.0) % 360.0

        for index, item in enumerate(group):

            angle = (
                offset +
                (360.0 * index / count)
            ) % 360.0

            radians = math.radians(angle)
            radius = item["radar_radius"]

            item["radar_angle"] = angle
            item["radar_x"] = radius * math.cos(radians)
            item["radar_y"] = radius * math.sin(radians)

            positioned.append(item)

    return positioned



def create_around_me_radar(
    items,
    title,
    device_mode=False,
    selection=None
):

    positioned = position_around_me_devices(items)

    fig = go.Figure()

    # Shared radar grid and reference styling.
    add_radar_grid(fig)

    # Device/AP markers.
    x_values = []
    y_values = []
    colours = []
    hover_text = []
    labels = []
    marker_labels = []
    marker_macs = []

    for item in positioned:

        x_values.append(item["radar_x"])
        y_values.append(item["radar_y"])

        average = item.get("average_signal")

        if device_mode:
            colour = (
                "#F59E0B"
                if average is None
                else DEVICE_COLOURS.get(
                    item.get("device_type"),
                    "#800000"
                )
            )
        else:
            # AP markers are always black, independent of signal strength.
            colour = "#000000"

        colours.append(colour)

        mac = item.get("mac", "Unknown")
        marker_macs.append(mac)
        name = item.get("name") or "Unknown"

        labels.append(name if not device_mode else mac)

        marker_label = mac

        ssid = item.get("ssid")

        if ssid:
            marker_label += f"<br>{ssid}"

        marker_labels.append(marker_label)

        hover_text.append(
            f"<b>{name}</b><br>"
            f"MAC: {mac}<br>"
            f"Type: {item.get('device_type', 'Wi-Fi AP')}<br>"
            f"Signal: {average:.1f} dBm"
            if average is not None
            else f"MAC: {mac}<br>Signal unavailable"
        )

    if positioned:

        fig.add_trace(
            go.Scatter(
                x=x_values,
                y=y_values,
                customdata=marker_macs,
                mode="markers",
                text=hover_text,
                hovertemplate="%{text}<extra></extra>",
                marker=dict(
                    size=13,
                    color=colours,
                    line=dict(
                        color="#FFFFFF",
                        width=1.5
                    ),
                    opacity=0.95
                ),
                showlegend=False
            )
        )

    # Selection highlighting rings.
    if selection:

        selected_mac = selection.get("mac", "").upper()
        selected_ap_mac = (
            selection.get("associated_ap_mac")
            if selection.get("type") == "client"
            else selected_mac
        )

        red_x = []
        red_y = []
        amber_x = []
        amber_y = []

        for item in positioned:

            mac = item.get("mac", "").upper()
            associated_ap = item.get("associated_ap_mac", "").upper()

            if not device_mode:

                if mac == selected_ap_mac:
                    red_x.append(item["radar_x"])
                    red_y.append(item["radar_y"])

            else:

                if selection.get("type") == "ap":

                    if associated_ap == selected_ap_mac:
                        red_x.append(item["radar_x"])
                        red_y.append(item["radar_y"])

                else:

                    if mac == selected_mac:
                        red_x.append(item["radar_x"])
                        red_y.append(item["radar_y"])

                    elif associated_ap == selected_ap_mac:
                        amber_x.append(item["radar_x"])
                        amber_y.append(item["radar_y"])

        if red_x:

            fig.add_trace(
                go.Scatter(
                    x=red_x,
                    y=red_y,
                    mode="markers",
                    marker=dict(
                        size=19,
                        color="rgba(0,0,0,0)",
                        line=dict(
                            color="#FF0000",
                            width=3
                        )
                    ),
                    hoverinfo="skip",
                    showlegend=False
                )
            )

        if amber_x:

            fig.add_trace(
                go.Scatter(
                    x=amber_x,
                    y=amber_y,
                    mode="markers",
                    marker=dict(
                        size=19,
                        color="rgba(0,0,0,0)",
                        line=dict(
                            color="#F59E0B",
                            width=3
                        )
                    ),
                    hoverinfo="skip",
                    showlegend=False
                )
            )

    # Permanent MAC and SSID labels.
    if positioned:

        # Main label text.
        fig.add_trace(
            go.Scatter(
                x=x_values,
                y=[y + 0.01 for y in y_values],
                mode="text",
                text=marker_labels,
                textposition="top center",
                textfont=dict(
                    size=10,
                    color="#1E293B"
                ),
                hoverinfo="skip",
                showlegend=False
            )
        )

    # Centre marker.
    fig.add_trace(
        go.Scatter(
            x=[0],
            y=[0],
            mode="markers",
            marker=dict(
                size=12,
                color="#FFFFFF",
                line=dict(
                    color="#64748B",
                    width=2
                )
            ),
            hoverinfo="skip",
            showlegend=False
        )
    )

    apply_radar_layout(fig, uirevision=title)


    return fig


def create_around_me_layout():

    return html.Div([


        dcc.Store(
            id="around_me_selection",
            data=None
        ),

        html.Div(
            id="around_me_selection_debug",
            children="No device selected"
        ),

        html.Div([

            # LEFT PANEL: ACCESS POINTS
            html.Div([

                html.Div([
                    html.Span(
                        "APs Detected: ",
                        style={"fontWeight": "bold"}
                    ),
                    html.Span(
                        "Which access points are operating around me?"
                    )
                ], className="around-me-heading"),

                html.Div([

                    # RADIO FILTERS
                    html.Div([

                        html.Div([
                            html.Label("Frequency profile"),
                            dcc.Dropdown(
                                id="around_me_country_filter",
                                options=[
                                    {
                                        "label": "Kismet detected ranges",
                                        "value": "kismet"
                                    }
                                ],
                                value="kismet",
                                clearable=False,
                                searchable=False
                            )
                        ], className="around-me-filter-control"),

                        html.Div([
                            html.Label("Band"),
                            dcc.Dropdown(
                                id="around_me_band_filter",
                                options=[
                                    {"label": "2.4 GHz", "value": "2.4 GHz"},
                                    {"label": "5 GHz", "value": "5 GHz"},
                                    {"label": "6 GHz", "value": "6 GHz"}
                                ],
                                multi=True,
                                placeholder="All bands",
                                value=[]
                            )
                        ], className="around-me-filter-control"),

                        html.Div([
                            html.Label("Channel"),
                            dcc.Dropdown(
                                id="around_me_channel_filter",
                                options=[
                                    {"label": str(channel), "value": str(channel)}
                                    for channel in range(1, 234)
                                ],
                                multi=True,
                                placeholder="All channels",
                                value=[]
                            )
                        ], className="around-me-filter-control"),

                        html.Div([
                            html.Label("Frequency range (MHz)"),
                            dcc.RangeSlider(
                                id="around_me_frequency_filter",
                                min=2400,
                                max=7125,
                                step=5,
                                value=[2400, 7125],
                                marks=None,
                                tooltip={
                                    "placement": "bottom",
                                    "always_visible": False
                                }
                            )
                        ], className="around-me-filter-control around-me-frequency-control")

                    ], className="around-me-filter-row"),

                    # SECURITY FILTERS
                    html.Div([

                        html.Div([
                            html.Label("Encryption"),
                            dcc.Dropdown(
                                id="around_me_encryption_filter",
                                options=[
                                    {"label": "Open", "value": "open"},
                                    {"label": "WEP", "value": "wep"},
                                    {"label": "WPA", "value": "wpa"},
                                    {"label": "WPA2", "value": "wpa2"},
                                    {"label": "WPA3", "value": "wpa3"},
                                    {"label": "OWE", "value": "owe"},
                                    {"label": "Mixed", "value": "mixed"}
                                ],
                                multi=True,
                                placeholder="All encryption types",
                                value=[]
                            )
                        ], className="around-me-filter-control"),

                        html.Div([
                            html.Label("Protected Management Frames"),
                            dcc.Dropdown(
                                id="around_me_pmf_filter",
                                options=[
                                    {"label": "Required", "value": "required"},
                                    {"label": "Supported", "value": "supported"},
                                    {"label": "Unsupported", "value": "unsupported"},
                                    {"label": "Unknown", "value": "unknown"}
                                ],
                                multi=True,
                                placeholder="All PMF states",
                                value=[]
                            )
                        ], className="around-me-filter-control"),

                        html.Div([
                            html.Label("WPS"),
                            dcc.Dropdown(
                                id="around_me_wps_filter",
                                options=[
                                    {"label": "Advertised", "value": "advertised"},
                                    {"label": "Not observed", "value": "unknown"},
                                    {"label": "Version 1.0", "value": "version:1.0"},
                                    {"label": "Unknown / other version", "value": "version:other"},
                                    {"label": "Configured", "value": "state:configured"},
                                    {"label": "Not configured", "value": "state:not_configured"},
                                    {"label": "Locked", "value": "state:locked"},
                                    {"label": "Configured and locked", "value": "state:configured_locked"}
                                ],
                                multi=True,
                                placeholder="All WPS states",
                                value=[]
                            )
                        ], className="around-me-filter-control"),

                        html.Div([
                            html.Label("Configuration checks"),
                            dcc.Dropdown(
                                options=[],
                                placeholder="Not yet available",
                                disabled=True
                            )
                        ], className="around-me-filter-control"),

                        html.Div([
                            html.Label(" "),
                            dbc.Button(
                                "Clear filters",
                                id="around_me_clear_filters",
                                n_clicks=0,
                                color="secondary",
                                outline=True,
                                className="around-me-clear-button"
                            )
                        ], className="around-me-filter-control around-me-clear-control")

                    ], className="around-me-filter-row")

                ], className="around-me-filters"),

                dcc.Graph(
                    id="around_aps_network",
                    figure=create_around_me_radar(
                        [],
                        "APs Detected"
                    ),
                    config={"responsive": True, "scrollZoom": True},
                    style={
                        "height": "100%",
                        "width": "100%"
                    }
                )

            ], className="around-me-panel"),

            # RIGHT PANEL: ASSOCIATION VIEWS
            html.Div([

                html.Div([
                    html.Span(
                        "Currently Associated",
                        id="around_me_view_title",
                        style={"fontWeight": "bold"}
                    ),
                    html.Span(": "),
                    html.Span(
                        VIEWS[2]["question"],
                        id="around_me_question"
                    )
                ], className="around-me-heading"),

                dcc.Graph(
                    id="around_devices_network",
                    figure=create_around_me_radar(
                        [],
                        "Currently Associated",
                        device_mode=True
                    ),
                    config={"responsive": True, "scrollZoom": True},
                    style={
                        "height": "100%",
                        "width": "100%"
                    }
                ),

                html.Div(
                    id="around_me_status",
                    className="around-me-status"
                )

            ], className="around-me-panel")

        ], className="around-me-grid")

    ], id="around_me_container")

def extract_around_me_management_events(pcap_data):
    """
    Extract 802.11 association and disconnect management frames
    from Kismet PCAP-NG data containing Radiotap packets.
    """
    if not pcap_data or len(pcap_data) < 28:
        return []

    events = []
    interfaces = []
    offset = 0
    endian = None

    event_types = {
        0x00: "association_request",
        0x01: "association_response",
        0x02: "reassociation_request",
        0x03: "reassociation_response",
        0x0A: "disassociation",
        0x0C: "deauthentication",
    }

    while offset + 12 <= len(pcap_data):

        block_type_bytes = pcap_data[offset:offset + 4]

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

            option_offset = 16

            while option_offset + 4 <= block_end:
                code, length = struct.unpack_from(
                    endian + "HH", block, option_offset
                )
                option_offset += 4

                if code == 0:
                    break

                if option_offset + length > block_end:
                    break

                value = block[
                    option_offset:option_offset + length
                ]

                if code == 9 and length == 1:
                    resolution = value[0]

                    if resolution & 0x80:
                        interface["resolution"] = (
                            2 ** -(resolution & 0x7f)
                        )
                    else:
                        interface["resolution"] = (
                            10 ** -resolution
                        )

                elif code == 14 and length == 8:
                    interface["time_offset"] = struct.unpack(
                        endian + "q", value
                    )[0]

                option_offset += (length + 3) & ~3

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

                packet = block[packet_start:packet_end]

                # Radiotap header
                if len(packet) >= 8 and packet[0] == 0:

                    radiotap_length = struct.unpack_from(
                        "<H", packet, 2
                    )[0]

                    if (
                        radiotap_length >= 8
                        and radiotap_length + 24 <= len(packet)
                    ):
                        frame = packet[radiotap_length:]

                        frame_control = struct.unpack_from(
                            "<H", frame, 0
                        )[0]

                        frame_type = (frame_control >> 2) & 0x03
                        subtype = (frame_control >> 4) & 0x0f

                        # Management frames only
                        if frame_type == 0 and subtype in event_types:

                            destination = ":".join(
                                f"{value:02x}"
                                for value in frame[4:10]
                            ).upper()

                            source = ":".join(
                                f"{value:02x}"
                                for value in frame[10:16]
                            ).upper()

                            bssid = ":".join(
                                f"{value:02x}"
                                for value in frame[16:22]
                            ).upper()

                            status_code = None
                            reason_code = None

                            # Association/reassociation responses:
                            # capability (2), status (2), AID (2)
                            if subtype in (0x01, 0x03):
                                if len(frame) >= 30:
                                    status_code = struct.unpack_from(
                                        "<H", frame, 26
                                    )[0]

                            # Disassociation/deauthentication:
                            # reason code (2)
                            elif subtype in (0x0A, 0x0C):
                                if len(frame) >= 26:
                                    reason_code = struct.unpack_from(
                                        "<H", frame, 24
                                    )[0]

                            events.append({
                                "timestamp": timestamp,
                                "subtype": f"0x{subtype:04x}",
                                "event": event_types[subtype],
                                "source": source,
                                "destination": destination,
                                "bssid": bssid,
                                "status_code": status_code,
                                "reason_code": reason_code,
                                "direction": (
                                    "AP to client"
                                    if source == bssid
                                    else "client to AP"
                                    if destination == bssid
                                    else "other"
                                )
                            })

        offset += block_length

    events.sort(key=lambda event: event["timestamp"])
    return events


def fetch_around_me_data(credentials, uri, rewind_seconds):

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

    cutoff = time.time() - int(rewind_seconds)

    detected = [
        device for device in devices
        if device.get("kismet.device.base.last_time", 0) >= cutoff
    ]

    aps = [
        device for device in detected
        if device.get("kismet.device.base.type") == "Wi-Fi AP"
    ]

    # Existing AP signal-history processing.
    ap_data = process_devices(aps)

    # Match processed APs to their original Kismet records.
    ap_lookup = {
        device.get("kismet.device.base.macaddr"): device
        for device in aps
    }

    # Extract SSID and radio/security metadata from original Kismet records.
    for ap in ap_data:

        original = ap_lookup.get(ap.get("mac"), {})
        dot11 = original.get("dot11.device", {})

        advertised = dot11.get(
            "dot11.device.advertised_ssid_map",
            []
        )
        if not isinstance(advertised, list):
            advertised = []

        ssid_record = dot11.get(
            "dot11.device.last_beaconed_ssid_record",
            {}
        )

        ssid = (
            ssid_record.get("dot11.advertisedssid.ssid")
            if isinstance(ssid_record, dict)
            else None
        )

        if not ssid and advertised:
            ssid = advertised[0].get("dot11.advertisedssid.ssid")

        ap["ssid"] = ssid

        # Retain every frequency observed by Kismet during the selected window.
        # Kismet reports these frequencies in kHz.
        observed_frequencies = set()

        raw_frequency = original.get("kismet.device.base.frequency")
        raw_map = original.get("kismet.device.base.freq_khz_map", {})

        if isinstance(raw_map, dict):
            frequency_values = list(raw_map.keys())
        else:
            frequency_values = []

        frequency_values.append(raw_frequency)

        for raw_value in frequency_values:
            try:
                value = float(raw_value)
                frequency_mhz = (
                    value / 1000.0
                    if value > 100000
                    else value
                )
                if 2000 <= frequency_mhz <= 8000:
                    observed_frequencies.add(round(frequency_mhz, 3))
            except (TypeError, ValueError):
                continue

        frequencies_mhz = sorted(observed_frequencies)
        frequency_bands = sorted({
            band
            for frequency in frequencies_mhz
            if (band := _frequency_band(frequency))
        })

        ap["frequencies_mhz"] = frequencies_mhz
        ap["frequency_bands"] = frequency_bands
        ap["frequency_mhz"] = (
            frequencies_mhz[-1] if frequencies_mhz else None
        )
        ap["frequency_band"] = (
            frequency_bands[0] if len(frequency_bands) == 1 else None
        )

        channel = original.get("kismet.device.base.channel")
        if channel in (None, "") and advertised:
            channel = advertised[0].get("dot11.advertisedssid.channel")
        ap["channel"] = str(channel) if channel not in (None, "") else None

        ap["security_types"] = _classify_security(
            advertised,
            original.get("kismet.device.base.crypt")
        )

        def aggregate_flag(field):
            values = [
                record.get(field)
                for record in advertised
                if record.get(field) is not None
            ]
            if not values:
                return None
            return any(bool(value) for value in values)

        ap["pmf_supported"] = aggregate_flag(
            "dot11.advertisedssid.wpa_mfp_supported"
        )
        ap["pmf_required"] = aggregate_flag(
            "dot11.advertisedssid.wpa_mfp_required"
        )

        versions = {
            label
            for record in advertised
            if (label := _wps_version_label(
                record.get("dot11.advertisedssid.wps_version")
            ))
        }
        methods, methods_observed = _wps_methods_from_records(advertised)
        states, states_observed = _wps_states_from_records(advertised)

        ap["wps_versions"] = sorted(versions)
        ap["wps_methods"] = methods
        ap["wps_states"] = states
        ap["wps_observed"] = bool(
            versions or methods or methods_observed or states_observed
        )

    # Fall back to latest signal if no average is available.
    for ap in ap_data:

        if ap.get("average_signal") is None:
            ap["average_signal"] = ap.get("last_signal")

        ap["device_type"] = "Wi-Fi AP"

    # Build lookup of detected non-AP devices.
    device_lookup = {}

    for device in detected:

        mac = device.get("kismet.device.base.macaddr")

        if not mac:
            continue

        device_type = device.get("kismet.device.base.type")

        if device_type not in NON_AP_TYPES:
            continue

        signal_data = device.get(
            "kismet.device.base.signal",
            {}
        )

        latest_signal = signal_data.get(
            "kismet.common.signal.last_signal"
        )

        device_lookup[mac.upper()] = {
            "mac": mac,
            "name": device.get("kismet.device.base.name"),
            "device_type": device_type,
            "manufacturer": device.get(
                "kismet.device.base.manuf"
            ),
            "average_signal": latest_signal,
            "last_signal": latest_signal
        }

    # Current association evidence from AP associated_client_map.
    # Retain the AP identity and SSID for each associated client.

    ap_details = {
        ap["mac"].upper(): ap
        for ap in ap_data
        if ap.get("mac")
    }

    current_devices = {}

    for ap in aps:

        ap_mac = ap.get(
            "kismet.device.base.macaddr"
        )

        if not ap_mac:
            continue

        ap_mac = ap_mac.upper()

        ap_info = ap_details.get(ap_mac, {})

        ap_ssid = ap_info.get("ssid")

        dot11 = ap.get("dot11.device", {})

        associated_map = dot11.get(
            "dot11.device.associated_client_map",
            {}
        )

        if not isinstance(associated_map, dict):
            continue

        for client_mac in associated_map:

            client_mac = str(client_mac).upper()

            if client_mac not in device_lookup:
                continue

            client = dict(device_lookup[client_mac])

            client["associated_ap_mac"] = ap_mac
            client["associated_ap_ssid"] = ap_ssid

            current_devices[client_mac] = client

    current_devices = list(current_devices.values())

    return {
        "aps": ap_data,
        "current": current_devices,
        "ap_count": len(ap_data),
        "current_count": len(current_devices)
    }


def register_around_me_callbacks(app):


    @app.callback(
        Output("around_me_selection", "data"),
        [
            Input("around_aps_network", "clickData"),
            Input("around_devices_network", "clickData"),
            Input("shared_device_selection", "data")
        ],
        State("around_me_selection", "data")
    )
    def select_around_me_device(
        ap_click,
        device_click,
        shared_selection,
        current_selection
    ):

        triggered = dash.callback_context.triggered

        if not triggered:
            raise dash.exceptions.PreventUpdate

        graph_id = triggered[0]["prop_id"].split(".")[0]

        if graph_id == "shared_device_selection":

            if not shared_selection:
                return None

            new_selection = {
                "type": shared_selection.get("type", "client"),
                "mac": shared_selection.get("mac")
            }

            if not new_selection["mac"]:
                return None

            if current_selection == new_selection:
                raise dash.exceptions.PreventUpdate

            return new_selection

        if graph_id == "around_aps_network":
            click_data = ap_click
            selection_type = "ap"

        elif graph_id == "around_devices_network":
            click_data = device_click
            selection_type = "client"

        else:
            raise dash.exceptions.PreventUpdate

        if not click_data or not click_data.get("points"):
            raise dash.exceptions.PreventUpdate

        mac = click_data["points"][0].get("customdata")

        if not mac:
            raise dash.exceptions.PreventUpdate

        if selection_type == "ap":
            new_selection = {
                "type": "ap",
                "mac": mac
            }

        else:
            point_index = click_data["points"][0].get("pointIndex")

            if point_index is None:
                raise dash.exceptions.PreventUpdate

            new_selection = {
                "type": "client",
                "mac": mac
            }

        if current_selection == new_selection:
            return None

        return new_selection

    @app.callback(
        Output("around_me_selection_debug", "children"),
        Input("around_me_selection", "data")
    )
    def show_around_me_selection(selection):

        if not selection:
            return "No device selected"

        return (
            f"Selected: {selection['type']} — "
            f"{selection['mac']}"
        )

    @app.callback(
        [
            Output("around_me_country_filter", "value"),
            Output("around_me_band_filter", "value"),
            Output("around_me_channel_filter", "value"),
            Output("around_me_frequency_filter", "value"),
            Output("around_me_encryption_filter", "value"),
            Output("around_me_pmf_filter", "value"),
            Output("around_me_wps_filter", "value")
        ],
        Input("around_me_clear_filters", "n_clicks"),
        prevent_initial_call=True
    )
    def clear_around_me_filters(n_clicks):

        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        return (
            "kismet",
            [],
            [],
            [2400, 7125],
            [],
            [],
            []
        )

    @app.callback(
        [
            Output("around_aps_network", "figure"),
            Output("around_devices_network", "figure"),
            Output("around_me_view_title", "children"),
            Output("around_me_question", "children"),
            Output("around_me_status", "children")
        ],
        [
            Input("graph_type", "value"),
            Input("update_graph", "n_clicks"),
            Input("around_me_selection", "data"),
            Input("rewind_seconds", "value"),
            Input("around_me_country_filter", "value"),
            Input("around_me_band_filter", "value"),
            Input("around_me_channel_filter", "value"),
            Input("around_me_frequency_filter", "value"),
            Input("around_me_encryption_filter", "value"),
            Input("around_me_pmf_filter", "value"),
            Input("around_me_wps_filter", "value")
        ],
        [
            State("kismet_credentials", "value"),
            State("kismet_uri", "value")
        ]
    )

    def update_around_me(
        graph_type,
        n_clicks,
        selection,
        rewind_seconds,
        country_filter,
        band_filter,
        channel_filter,
        frequency_filter,
        encryption_filter,
        pmf_filter,
        wps_filter,
        credentials,
        uri
    ):

        if graph_type != "around_me":
            raise dash.exceptions.PreventUpdate

        view = VIEWS[2]

        try:

            data = fetch_around_me_data(
                credentials,
                uri,
                rewind_seconds
            )

            # The full slider span means no frequency restriction.
            # This keeps APs with unknown frequency visible by default.
            active_frequency_range = frequency_filter

            if (
                frequency_filter
                and len(frequency_filter) == 2
                and float(frequency_filter[0]) <= 2400
                and float(frequency_filter[1]) >= 7125
            ):
                active_frequency_range = None

            # Kismet detected ranges is the only currently available
            # profile. No country is assumed.
            filtered_aps = filter_around_me_aps(
                data["aps"],
                bands=band_filter,
                channels=channel_filter,
                frequency_range=active_frequency_range,
                encryption=encryption_filter,
                pmf=pmf_filter,
                wps=wps_filter
            )

            radar_selection = dict(selection) if selection else None

            if radar_selection and radar_selection.get("type") == "client":

                selected_mac = radar_selection["mac"].upper()

                selected_client = next(
                    (
                        client for client in data["current"]
                        if client.get("mac", "").upper() == selected_mac
                    ),
                    None
                )

                if selected_client:
                    radar_selection["associated_ap_mac"] = (
                        selected_client.get("associated_ap_mac")
                    )

            ap_figure = create_around_me_radar(
                filtered_aps,
                "APs Detected",
                selection=radar_selection
            )

            right_data = data["current"]

            status = (
                f"Currently associated devices: "
                f"{data['current_count']}"
            )

            right_figure = create_around_me_radar(
                right_data,
                view["title"],
                device_mode=True,
                selection=radar_selection
            )

            return (
                ap_figure,
                right_figure,
                view["title"],
                view["question"],
                (
                    f"APs shown: {len(filtered_aps)} / "
                    f"{data['ap_count']} | {status}"
                )
            )

        except Exception as error:

            logging.exception(
                "Unable to update What is around me dashboard"
            )

            empty_ap = create_around_me_radar(
                [],
                "APs Detected"
            )

            empty_devices = create_around_me_radar(
                [],
                view["title"],
                device_mode=True
            )

            return (
                empty_ap,
                empty_devices,
                view["title"],
                view["question"],
                f"Kismet API error: {error}"
            )
