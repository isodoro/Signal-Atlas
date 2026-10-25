import time
import logging
from datetime import datetime

import requests
import dash
from dash import html, dcc, dash_table
from dash.dependencies import Input, Output, State
import plotly.graph_objects as go

from radar_style import add_radar_grid, apply_radar_layout

from signal_position import calculate_angle, signal_to_radius


def fetch_probed_ssids(credentials, uri, rewind_seconds):
    """Fetch Wi-Fi clients and their per-client probed SSID records."""

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

    rows_by_pair = {}
    clients = {}

    for device in devices:

        if device.get("kismet.device.base.type") != "Wi-Fi Client":
            continue

        mac = device.get("kismet.device.base.macaddr")

        if not mac:
            continue

        dot11 = device.get("dot11.device", {})
        if not isinstance(dot11, dict):
            continue

        probe_map = dot11.get(
            "dot11.device.probed_ssid_map",
            []
        )

        if isinstance(probe_map, dict):
            probe_map = list(probe_map.values())

        if not isinstance(probe_map, list):
            continue

        signal_data = device.get(
            "kismet.device.base.signal",
            {}
        )

        last_signal = signal_data.get(
            "kismet.common.signal.last_signal"
        )

        for probe in probe_map:

            if not isinstance(probe, dict):
                continue

            ssid = probe.get("dot11.probedssid.ssid") or ""
            first_time = probe.get("dot11.probedssid.first_time")
            last_time = probe.get("dot11.probedssid.last_time")

            try:
                last_timestamp = float(last_time)
            except (TypeError, ValueError):
                continue

            # The Past window applies to this particular SSID relationship.
            if last_timestamp < cutoff:
                continue

            try:
                first_timestamp = float(first_time)
            except (TypeError, ValueError):
                first_timestamp = last_timestamp

            display_ssid = ssid if ssid else "Hidden / wildcard"

            bssid = probe.get(
                "dot11.probedssid.bssid",
                ""
            ) or ""

            pair_key = (mac.upper(), display_ssid)

            row = {
                "ssid": display_ssid,
                "mac": mac,
                "device": device.get(
                    "kismet.device.base.name"
                ) or "Unknown",
                "manufacturer": device.get(
                    "kismet.device.base.manuf"
                ) or "Unknown",
                "first_seen": datetime.fromtimestamp(
                    first_timestamp
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": datetime.fromtimestamp(
                    last_timestamp
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "bssid": bssid,
                "signal": (
                    f"{last_signal} dBm"
                    if last_signal is not None
                    else "Unknown"
                ),
                "_last_timestamp": last_timestamp
            }

            # Keep the most recently observed record for a client/SSID pair.
            previous = rows_by_pair.get(pair_key)

            if (
                previous is None
                or last_timestamp > previous["_last_timestamp"]
            ):
                rows_by_pair[pair_key] = row

            # One radar marker per client, regardless of SSID count.
            existing = clients.get(mac.upper())

            client_record = {
                "mac": mac,
                "name": device.get(
                    "kismet.device.base.name"
                ) or "Unknown",
                "manufacturer": device.get(
                    "kismet.device.base.manuf"
                ) or "Unknown",
                "last_signal": last_signal,
                "last_seen": last_timestamp
            }

            if (
                existing is None
                or last_timestamp > existing["last_seen"]
            ):
                clients[mac.upper()] = client_record

    rows = sorted(
        rows_by_pair.values(),
        key=lambda row: row["_last_timestamp"],
        reverse=True
    )

    for row in rows:
        row.pop("_last_timestamp", None)

    return rows, list(clients.values())


def create_probed_ssids_radar(clients, selected_mac=None):
    """Create a separate radar for clients sending SSID probes."""

    fig = go.Figure()

    add_radar_grid(fig)

    positioned_count = 0

    for client in clients:

        mac = client.get("mac")
        signal = client.get("last_signal")

        if not mac or signal is None:
            continue

        try:
            signal = float(signal)
        except (TypeError, ValueError):
            continue

        angle = calculate_angle(mac)
        radius = signal_to_radius(signal)

        if angle is None or radius is None:
            continue

        import math

        radians = math.radians(angle)
        x = radius * math.cos(radians)
        y = radius * math.sin(radians)

        selected = (
            selected_mac is not None
            and mac.upper() == selected_mac.upper()
        )

        name = client.get("name") or "Unknown"
        manufacturer = client.get("manufacturer") or "Unknown"

        hover_text = (
            f"<b>{name}</b><br>"
            f"MAC: {mac}<br>"
            f"Manufacturer: {manufacturer}<br>"
            f"Latest signal: {signal} dBm"
        )

        fig.add_trace(
            go.Scatter(
                x=[x],
                y=[y],
                mode="markers+text",
                text=[mac],
                textposition="top center",
                textfont=dict(
                    size=10,
                    color="#1F2937"
                ),
                hovertext=[hover_text],
                hovertemplate="%{hovertext}<extra></extra>",
                customdata=[mac],
                marker=dict(
                    size=15 if selected else 10,
                    color="#22C55E",
                    line=dict(
                        color="#FF0000" if selected else "#FFFFFF",
                        width=3 if selected else 1.2
                    ),
                    opacity=0.95
                ),
                showlegend=False
            )
        )

        positioned_count += 1

    fig.add_trace(
        go.Scatter(
            x=[0],
            y=[0],
            mode="markers",
            marker=dict(
                size=12,
                color="#1F2937",
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

    apply_radar_layout(
        fig,
        margin=dict(l=30, r=30, t=65, b=30),
        clickmode="event+select",
        title=f"Probe-requesting Clients ({positioned_count})"
    )

    return fig


def create_probed_ssids_layout():

    return html.Div([

        dcc.Store(
            id="probed_ssids_selection",
            data=None
        ),

        html.Div([
            html.Div([
                html.Div(
                    "Probed SSIDs",
                    style={
                        "fontWeight": "bold",
                        "fontSize": "18px",
                        "marginBottom": "8px"
                    }
                ),
                html.Div(
                    "Which network names have nearby Wi-Fi clients been probing for?",
                    style={"marginBottom": "12px"}
                ),
                html.Div([
                    html.Label(
                        "SSID visibility:",
                        style={"fontWeight": "bold", "marginRight": "10px"}
                    ),
                    dcc.Dropdown(
                        id="probed_ssids_visibility_filter",
                        options=[
                            {"label": "Named SSIDs only", "value": "named"},
                            {"label": "Include Hidden / wildcard", "value": "all"}
                        ],
                        value="named",
                        clearable=False,
                        searchable=False,
                        style={"width": "280px"}
                    )
                ], style={"marginBottom": "12px"}),
                html.Div([
                    dash_table.DataTable(
                        id="probed_ssids_table",
                        columns=[
                            {"name": "SSID", "id": "ssid"},
                            {"name": "Client MAC", "id": "mac"},
                            {"name": "Device", "id": "device"},
                            {"name": "Manufacturer", "id": "manufacturer"},
                            {"name": "First seen", "id": "first_seen"},
                            {"name": "Last seen", "id": "last_seen"},
                            {"name": "BSSID", "id": "bssid"},
                            {"name": "Signal", "id": "signal"}
                        ],
                        data=[],
                        row_selectable="single",
                        active_cell=None,
                        page_size=15,
                        sort_action="native",
                        filter_action="native",
                        style_table={
                            "overflowX": "auto",
                            "height": "100%",
                            "overflowY": "auto"
                        },
                        style_cell={
                            "backgroundColor": "#FFFFFF",
                            "color": "#1F2937",
                            "border": "1px solid #D1D5DB",
                            "padding": "7px",
                            "fontSize": "12px",
                            "textAlign": "left",
                            "minWidth": "90px",
                            "maxWidth": "240px",
                            "whiteSpace": "normal"
                        },
                        style_header={
                            "backgroundColor": "#F3F4F6",
                            "fontWeight": "bold",
                            "color": "#1F2937",
                            "border": "1px solid #D1D5DB"
                        },
                        style_data_conditional=[
                            {
                                "if": {"state": "selected"},
                                "backgroundColor": "#DBEAFE",
                                "color": "#1F2937",
                                "border": "1px solid #60A5FA"
                            }
                        ]
                    )
                ], className="probed-ssids-table")
            ], className="probed-ssids-panel"),

            html.Div([
                dcc.Graph(
                    id="probed_ssids_radar",
                    figure=create_probed_ssids_radar([]),
                    config={
                        "responsive": True,
                        "scrollZoom": True
                    },
                    style={
                        "height": "100%",
                        "width": "100%"
                    }
                )
            ], className="probed-ssids-panel probed-ssids-radar-panel")

        ], className="probed-ssids-grid"),

        html.Div(
            id="probed_ssids_status",
            className="around-me-status"
        )

    ], id="probed_ssids_container", style={"display": "none"})


def register_probed_ssids_callbacks(app):

    @app.callback(
        Output("probed_ssids_selection", "data"),
        [
            Input("probed_ssids_radar", "clickData"),
            Input("probed_ssids_table", "active_cell")
        ],
        [
            State("probed_ssids_table", "data"),
            State("probed_ssids_selection", "data")
        ]
    )
    def select_probed_client(
        radar_click,
        active_cell,
        table_data,
        current_selection
    ):

        triggered = dash.callback_context.triggered

        if not triggered:
            raise dash.exceptions.PreventUpdate

        source = triggered[0]["prop_id"].split(".")[0]

        mac = None

        if source == "probed_ssids_radar":

            if radar_click and radar_click.get("points"):
                mac = radar_click["points"][0].get("customdata")

        elif source == "probed_ssids_table":

            if (
                active_cell
                and table_data
                and active_cell.get("row") is not None
                and active_cell["row"] < len(table_data)
            ):
                mac = table_data[active_cell["row"]].get("mac")

        if not mac:
            raise dash.exceptions.PreventUpdate

        if (
            current_selection
            and current_selection.upper() == mac.upper()
        ):
            return None

        return mac

    @app.callback(
        [
            Output("probed_ssids_radar", "figure"),
            Output("probed_ssids_table", "data"),
            Output("probed_ssids_status", "children")
        ],
        [
            Input("graph_type", "value"),
            Input("update_graph", "n_clicks"),
            Input("rewind_seconds", "value"),
            Input("probed_ssids_selection", "data"),
            Input("probed_ssids_visibility_filter", "value")
        ],
        [
            State("kismet_credentials", "value"),
            State("kismet_uri", "value")
        ]
    )
    def update_probed_ssids(
        graph_type,
        n_clicks,
        rewind_seconds,
        selection,
        visibility_filter,
        credentials,
        uri
    ):

        if graph_type != "scenario20_probed_ssids":
            raise dash.exceptions.PreventUpdate

        try:

            rows, clients = fetch_probed_ssids(
                credentials,
                uri,
                rewind_seconds
            )

            # Apply the user-selected SSID visibility filter.
            if visibility_filter != "all":
                rows = [
                    row for row in rows
                    if row.get("ssid") != "Hidden / wildcard"
                ]

            # Keep radar clients only when they have a visible probe
            # relationship under the selected filter.
            visible_macs = {
                row["mac"].upper()
                for row in rows
                if row.get("mac")
            }

            clients = [
                client for client in clients
                if client.get("mac", "").upper() in visible_macs
            ]

            selected_mac = selection.upper() if selection else None

            if selected_mac:
                rows = [
                    row for row in rows
                    if row["mac"].upper() == selected_mac
                ]

            figure = create_probed_ssids_radar(
                clients,
                selected_mac
            )

            radar_count = sum(
                1 for client in clients
                if client.get("last_signal") is not None
            )

            status = (
                f"Probe relationships: {len(rows)} | "
                f"Unique probing clients: {len(clients)} | "
                f"Clients with signal positions: {radar_count}"
            )

            return figure, rows, status

        except Exception as error:

            logging.exception(
                "Unable to update Probed SSIDs view"
            )

            return (
                create_probed_ssids_radar([]),
                [],
                f"Kismet API error: {error}"
            )
