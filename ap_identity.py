import time
import logging
from datetime import datetime

import requests
import dash
from dash import html, dcc, dash_table
from dash.dependencies import Input, Output, State


def _time_text(value):
    try:
        return datetime.fromtimestamp(float(value)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except (TypeError, ValueError, OSError):
        return "Unknown"


def _normalise(value):
    if value is None or value == "":
        return None
    return str(value)


def _yes_no(value):
    if value is None:
        return "Unknown"
    try:
        return "Yes" if int(value) else "No"
    except (TypeError, ValueError):
        return str(value)


def _record_value(record, field):
    if not isinstance(record, dict):
        return None

    return record.get(
        "dot11.advertisedssid." + field,
        record.get(field)
    )


def _device_value(device, dot11, field):
    value = dot11.get("dot11.device." + field)
    if value is None:
        value = device.get("dot11.device." + field)
    return value


def _as_records(value):
    if isinstance(value, dict):
        return list(value.values())
    if isinstance(value, list):
        return value
    return []


def fetch_ap_identity(credentials, uri, rewind_seconds):
    """Fetch AP identity and advertised SSID records from the live API."""

    api_url = (
        f"http://{credentials}@{uri}"
        "/devices/views/all/devices.json"
    )

    response = requests.get(
        api_url,
        verify=False,
        timeout=15
    )
    response.raise_for_status()

    devices = response.json()

    if isinstance(devices, dict):
        devices = devices.get("devices", [])

    cutoff = time.time() - int(rewind_seconds or 60)
    rows_by_key = {}

    for device in devices:

        if device.get("kismet.device.base.type") != "Wi-Fi AP":
            continue

        mac = device.get("kismet.device.base.macaddr")
        if not mac:
            continue

        dot11 = device.get("dot11.device", {})
        if not isinstance(dot11, dict):
            dot11 = {}

        records = _as_records(
            dot11.get("dot11.device.advertised_ssid_map")
        )

        if not records:
            last_record = dot11.get(
                "dot11.device.last_beaconed_ssid_record"
            )
            if isinstance(last_record, dict):
                records = [last_record]

        if not records:
            records = [{}]

        base_last_seen = device.get("kismet.device.base.last_time")
        base_first_seen = device.get("kismet.device.base.first_time")

        for record in records:

            if not isinstance(record, dict):
                continue

            ssid = _record_value(record, "ssid") or ""
            first_seen = _record_value(record, "first_time")
            last_seen = _record_value(record, "last_time")

            if last_seen is None:
                last_seen = base_last_seen

            try:
                last_timestamp = float(last_seen)
            except (TypeError, ValueError):
                continue

            if last_timestamp < cutoff:
                continue

            try:
                first_timestamp = float(
                    first_seen if first_seen is not None
                    else base_first_seen
                )
            except (TypeError, ValueError):
                first_timestamp = last_timestamp

            display_ssid = ssid if ssid else "Hidden / not advertised"

            # Hidden SSIDs are deliberately not grouped together.
            group_key = (
                ssid if ssid
                else "__hidden__" + mac.upper()
            )

            channel = _record_value(record, "channel")
            if channel is None:
                channel = device.get("kismet.device.base.channel")

            frequency = device.get("kismet.device.base.frequency")

            if frequency is not None:
                try:
                    frequency_mhz = float(frequency)
                    band = (
                        "2.4 GHz" if frequency_mhz < 3000
                        else "5 GHz" if frequency_mhz < 5925
                        else "6 GHz"
                    )
                    channel_text = f"{channel} ({band})"
                except (TypeError, ValueError):
                    channel_text = str(channel or "Unknown")
            else:
                channel_text = str(channel or "Unknown")

            encryption = _record_value(record, "crypt_string")
            if not encryption:
                encryption = device.get("kismet.device.base.crypt")

            beacon_fingerprint = _device_value(
                device, dot11, "beacon_fingerprint"
            )

            ie_checksum = _record_value(record, "ietag_checksum")

            mfp_supported = _record_value(
                record, "wpa_mfp_supported"
            )
            mfp_required = _record_value(
                record, "wpa_mfp_required"
            )

            country = _record_value(record, "dot11d_country")
            ht_mode = _record_value(record, "ht_mode")

            associated_clients = _device_value(
                device, dot11, "num_associated_clients"
            )

            row = {
                "ssid": display_ssid,
                "bssid": mac,
                "manufacturer": (
                    device.get("kismet.device.base.manuf") or "Unknown"
                ),
                "channel": channel_text,
                "encryption": encryption or "Unknown",
                "beacon_fingerprint": _normalise(beacon_fingerprint),
                "ie_checksum": _normalise(ie_checksum),
                "mfp_supported": _yes_no(mfp_supported),
                "mfp_required": _yes_no(mfp_required),
                "country": country or "Unknown",
                "ht_mode": ht_mode or "Unknown",
                "clients": (
                    associated_clients
                    if associated_clients is not None
                    else "Unknown"
                ),
                "first_seen": _time_text(first_timestamp),
                "last_seen": _time_text(last_timestamp),
                "_group": group_key,
                "_last_timestamp": last_timestamp
            }

            row_key = (mac.upper(), group_key)
            previous = rows_by_key.get(row_key)

            if (
                previous is None
                or last_timestamp > previous["_last_timestamp"]
            ):
                rows_by_key[row_key] = row

    rows = sorted(
        rows_by_key.values(),
        key=lambda row: (
            row["ssid"].lower(),
            row["bssid"].upper()
        )
    )

    # Keep only APs whose advertised SSID is shared by
    # at least two distinct access points.
    ssid_ap_counts = {}
    for row in rows:
        group = row["_group"]
        ssid_ap_counts.setdefault(group, set()).add(
            row["bssid"].upper()
        )

    rows = [
        row for row in rows
        if len(ssid_ap_counts[row["_group"]]) > 1
    ]

    return rows


COMPARISON_FIELDS = [
    ("Manufacturer", "manufacturer"),
    ("Channel / band", "channel"),
    ("Encryption", "encryption"),
    ("Beacon fingerprint", "beacon_fingerprint"),
    ("IE checksum", "ie_checksum"),
    ("MFP supported", "mfp_supported"),
    ("MFP required", "mfp_required"),
    ("Country", "country"),
    ("HT mode", "ht_mode"),
    ("Associated clients", "clients")
]


def build_identity_comparison(selected, all_rows):
    """Compare one AP with other APs advertising the same visible SSID."""

    peers = [
        row for row in all_rows
        if row["_group"] == selected["_group"]
        and row["bssid"].upper() != selected["bssid"].upper()
    ]

    comparison = []

    for label, field in COMPARISON_FIELDS:

        selected_value = selected.get(field)
        peer_values = [
            row.get(field)
            for row in peers
        ]

        known_peer_values = [
            value for value in peer_values
            if value not in (None, "", "Unknown")
        ]

        if not peers:
            result = "No peer APs"
        elif selected_value in (None, "", "Unknown"):
            result = "Unavailable"
        elif any(
            value not in (None, "", "Unknown")
            and str(value) != str(selected_value)
            for value in peer_values
        ):
            result = "Different"
        elif len(known_peer_values) != len(peers):
            result = "Unavailable"
        else:
            result = "Matching"

        peer_text = (
            " | ".join(
                f"{row['bssid']} ({row['manufacturer']}): "
                f"{row.get(field) if row.get(field) not in (None, '', 'Unknown') else 'Unknown'}"
                for row in peers
            )
            if peers else "No other APs advertise this SSID"
        )

        comparison.append({
            "field": label,
            "selected": selected_value if selected_value not in (None, "", "Unknown") else "Unknown",
            "others": peer_text,
            "result": result
        })

    return comparison, peers


def filter_ap_identity_rows(
    rows,
    prefix_octets=0,
    encryption_filter="any",
    manufacturer_filter="any"
):
    """Filter shared-SSID APs while retaining full comparison data."""

    if prefix_octets in (None, 0, "0"):
        octet_indexes = []
    elif str(prefix_octets) == "2,3":
        octet_indexes = [1, 2]
    else:
        try:
            count = max(1, min(5, int(prefix_octets)))
            octet_indexes = list(range(count))
        except (TypeError, ValueError):
            octet_indexes = []

    encryption_filter = encryption_filter or "any"
    manufacturer_filter = manufacturer_filter or "any"

    def normal(value):
        if value in (None, "", "Unknown"):
            return None
        return str(value).strip().casefold()

    def field_matches(row, peers, field, mode):
        if mode == "any":
            return True

        value = normal(row.get(field))
        if value is None:
            return False

        peer_values = [
            normal(peer.get(field))
            for peer in peers
        ]
        peer_values = [
            item for item in peer_values
            if item is not None
        ]

        if mode == "matching":
            return any(item == value for item in peer_values)

        if mode == "different":
            return any(item != value for item in peer_values)

        return True

    candidates = []

    for row in rows:
        peers = [
            peer for peer in rows
            if peer["_group"] == row["_group"]
            and peer["bssid"].upper() != row["bssid"].upper()
        ]

        if not field_matches(
            row, peers, "encryption", encryption_filter
        ):
            continue

        if not field_matches(
            row, peers, "manufacturer", manufacturer_filter
        ):
            continue

        candidates.append(row)

    if not octet_indexes:
        return candidates

    # A DIFFERENT setting is an anomaly condition.
    # Never collapse records when the user explicitly wants
    # to identify differences in encryption or manufacturer.
    if (
        encryption_filter == "different"
        or manufacturer_filter == "different"
    ):
        return candidates

    visible = []
    seen = {}

    for row in candidates:
        mac_parts = row["bssid"].upper().split(":")

        if len(mac_parts) != 6:
            visible.append(row)
            continue

        prefix = tuple(mac_parts[index] for index in octet_indexes)
        group_key = (row["_group"], prefix)

        previous_rows = seen.setdefault(group_key, [])
        collapse = False

        for previous in previous_rows:

            if (
                encryption_filter == "matching"
                and normal(row.get("encryption"))
                != normal(previous.get("encryption"))
            ):
                continue

            if (
                manufacturer_filter == "matching"
                and normal(row.get("manufacturer"))
                != normal(previous.get("manufacturer"))
            ):
                continue

            collapse = True
            break

        if not collapse:
            visible.append(row)
            previous_rows.append(row)

    return visible


def create_ap_identity_layout():

    return html.Div([

        dcc.Store(
            id="ap_identity_selection",
            data=None
        ),

        html.Div([
            html.Div([
                html.Div(
                    "Access Points",
                    className="ap-identity-heading"
                ),
                html.Div(
                    "Select an AP to compare its advertised identity "
                    "with other APs using the same SSID.",
                    className="ap-identity-description"
                ),
                html.Div([
                    html.Div([
                        html.Label("BSSID prefix matching"),
                        dcc.Dropdown(
                            id="ap_identity_bssid_prefix",
                            options=[
                                {"label": "No BSSID filtering", "value": 0},
                                {"label": "First octet", "value": 1},
                                {"label": "First 2 octets", "value": 2},
                                {"label": "2nd and 3rd octets", "value": "2,3"},
                                {"label": "First 3 octets", "value": 3},
                                {"label": "First 4 octets", "value": 4},
                                {"label": "First 5 octets", "value": 5}
                            ],
                            value=0,
                            clearable=False
                        )
                    ], style={"flex": "1", "minWidth": "145px"}),

                    html.Div([
                        html.Label("Encryption"),
                        dcc.Dropdown(
                            id="ap_identity_encryption_filter",
                            options=[
                                {"label": "Show all", "value": "any"},
                                {"label": "Matching", "value": "matching"},
                                {"label": "Different", "value": "different"}
                            ],
                            value="any",
                            clearable=False
                        )
                    ], style={"flex": "1", "minWidth": "130px"}),

                    html.Div([
                        html.Label("Manufacturer"),
                        dcc.Dropdown(
                            id="ap_identity_manufacturer_filter",
                            options=[
                                {"label": "Show all", "value": "any"},
                                {"label": "Matching", "value": "matching"},
                                {"label": "Different", "value": "different"}
                            ],
                            value="any",
                            clearable=False
                        )
                    ], style={"flex": "1", "minWidth": "130px"}),

                    html.Button(
                        "Clear filters",
                        id="ap_identity_clear_filters",
                        n_clicks=0,
                        style={
                            "padding": "8px 12px",
                            "cursor": "pointer"
                        }
                    )
                ], style={
                    "display": "flex",
                    "gap": "10px",
                    "alignItems": "end",
                    "flexWrap": "wrap",
                    "margin": "12px 0"
                }),

                dash_table.DataTable(
                    id="ap_identity_table",
                    columns=[
                        {"name": "SSID", "id": "ssid"},
                        {"name": "BSSID", "id": "bssid"},
                        {"name": "Manufacturer", "id": "manufacturer"},
                        {"name": "Channel", "id": "channel"},
                        {"name": "Encryption", "id": "encryption"}
                    ],
                    data=[],
                    active_cell=None,
                    page_size=15,
                    sort_action="native",
                    filter_action="native",
                    style_table={"overflowX": "auto"},
                    style_cell={
                        "backgroundColor": "#FFFFFF",
                        "color": "#1F2937",
                        "border": "1px solid #D1D5DB",
                        "padding": "7px",
                        "fontSize": "12px",
                        "textAlign": "left",
                        "minWidth": "90px",
                        "maxWidth": "220px",
                        "whiteSpace": "normal"
                    },
                    style_header={
                        "backgroundColor": "#F3F4F6",
                        "fontWeight": "bold",
                        "color": "#1F2937",
                        "border": "1px solid #D1D5DB"
                    },
                    style_data_conditional=[{
                        "if": {"state": "active"},
                        "backgroundColor": "#DBEAFE",
                        "border": "1px solid #60A5FA"
                    }]
                )
            ], className="ap-identity-panel"),

            html.Div([
                html.Div(
                    "AP Identity Comparison",
                    id="ap_identity_detail_heading",
                    className="ap-identity-heading"
                ),
                html.Div(
                    "Select an access point from the list.",
                    id="ap_identity_detail_description",
                    className="ap-identity-description"
                ),
                dash_table.DataTable(
                    id="ap_identity_comparison",
                    columns=[
                        {"name": "Identity field", "id": "field"},
                        {"name": "Selected AP", "id": "selected"},
                        {"name": "Other APs with this SSID", "id": "others"},
                        {"name": "Comparison", "id": "result"}
                    ],
                    data=[],
                    page_action="none",
                    style_table={
                        "overflowX": "auto",
                        "height": "100%",
                        "overflowY": "auto"
                    },
                    style_cell={
                        "backgroundColor": "#FFFFFF",
                        "color": "#1F2937",
                        "border": "1px solid #D1D5DB",
                        "padding": "8px",
                        "fontSize": "12px",
                        "textAlign": "left",
                        "minWidth": "100px",
                        "whiteSpace": "normal",
                        "height": "auto"
                    },
                    style_header={
                        "backgroundColor": "#F3F4F6",
                        "fontWeight": "bold",
                        "color": "#1F2937",
                        "border": "1px solid #D1D5DB"
                    },
                    style_data_conditional=[
                        {
                            "if": {
                                "filter_query": '{result} = "Different"',
                                "column_id": "result"
                            },
                            "backgroundColor": "#FEE2E2",
                            "color": "#991B1B",
                            "fontWeight": "bold"
                        },
                        {
                            "if": {
                                "filter_query": '{result} = "Matching"',
                                "column_id": "result"
                            },
                            "backgroundColor": "#DCFCE7",
                            "color": "#166534"
                        },
                        {
                            "if": {
                                "filter_query": '{result} = "Unavailable"',
                                "column_id": "result"
                            },
                            "backgroundColor": "#FEF3C7",
                            "color": "#92400E"
                        }
                    ]
                )
            ], className="ap-identity-panel")

        ], className="ap-identity-grid"),

        html.Div(
            id="ap_identity_status",
            className="around-me-status"
        )

    ], id="ap_identity_container", style={"display": "none"})


def register_ap_identity_callbacks(app):

    @app.callback(
        [
            Output("ap_identity_bssid_prefix", "value"),
            Output("ap_identity_encryption_filter", "value"),
            Output("ap_identity_manufacturer_filter", "value")
        ],
        Input("ap_identity_clear_filters", "n_clicks"),
        prevent_initial_call=True
    )
    def clear_ap_identity_filters(n_clicks):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        return 0, "any", "any"

    @app.callback(
        Output("ap_identity_selection", "data"),
        Input("ap_identity_table", "active_cell"),
        State("ap_identity_table", "derived_viewport_data")
    )
    def select_ap_identity(active_cell, viewport_data):

        if (
            not active_cell
            or not viewport_data
            or active_cell.get("row") is None
            or active_cell["row"] >= len(viewport_data)
        ):
            raise dash.exceptions.PreventUpdate

        return viewport_data[active_cell["row"]].get("bssid")

    @app.callback(
        [
            Output("ap_identity_table", "data"),
            Output("ap_identity_comparison", "data"),
            Output("ap_identity_detail_heading", "children"),
            Output("ap_identity_detail_description", "children"),
            Output("ap_identity_status", "children")
        ],
        [
            Input("graph_type", "value"),
            Input("update_graph", "n_clicks"),
            Input("rewind_seconds", "value"),
            Input("ap_identity_selection", "data"),
            Input("ap_identity_bssid_prefix", "value"),
            Input("ap_identity_encryption_filter", "value"),
            Input("ap_identity_manufacturer_filter", "value")
        ],
        [
            State("kismet_credentials", "value"),
            State("kismet_uri", "value")
        ]
    )
    def update_ap_identity(
        graph_type,
        n_clicks,
        rewind_seconds,
        selection,
        prefix_octets,
        encryption_filter,
        manufacturer_filter,
        credentials,
        uri
    ):

        if graph_type != "scenario20_ap_identity":
            raise dash.exceptions.PreventUpdate

        try:
            rows = fetch_ap_identity(
                credentials,
                uri,
                rewind_seconds
            )

            visible_rows = filter_ap_identity_rows(
                rows,
                prefix_octets,
                encryption_filter,
                manufacturer_filter
            )

            selected = next(
                (
                    row for row in visible_rows
                    if selection
                    and row["bssid"].upper() == selection.upper()
                ),
                None
            )

            if selected is None and visible_rows:
                selected = visible_rows[0]

            table_rows = [
                {
                    key: value
                    for key, value in row.items()
                    if not key.startswith("_")
                }
                for row in visible_rows
            ]

            if selected is None:
                return (
                    table_rows,
                    [],
                    "AP Identity Comparison",
                    "No APs match the selected filters.",
                    (
                        f"AP records: {len(rows)} | "
                        f"Visible: {len(visible_rows)} | "
                        f"Filtered out: {len(rows) - len(visible_rows)}"
                    )
                )

            # Compare against every AP in the original dataset,
            # including radios hidden from the left-hand list.
            comparison, peers = build_identity_comparison(
                selected,
                rows
            )

            description = (
                f"Selected: {selected['bssid']} | "
                f"SSID: {selected['ssid']} | "
                f"Manufacturer: {selected['manufacturer']} | "
                f"Other APs advertising this SSID: {len(peers)}"
            )

            status = (
                f"AP records: {len(rows)} | "
                f"Visible: {len(visible_rows)} | "
                f"Filtered out: {len(rows) - len(visible_rows)} | "
                f"Matching-SSID peers: {len(peers)} | "
                "Differences are observations, not proof of a rogue AP."
            )

            return (
                table_rows,
                comparison,
                f"Identity comparison: {selected['ssid']}",
                description,
                status
            )

        except Exception as error:
            logging.exception("Unable to update AP Identity Comparison")

            return (
                [],
                [],
                "AP Identity Comparison",
                "Unable to retrieve AP identity information.",
                f"Kismet API error: {error}"
            )
