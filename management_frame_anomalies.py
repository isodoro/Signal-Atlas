import hashlib
import logging
import math
import time
from datetime import datetime

import dash
import requests
import plotly.graph_objects as go
from dash import html, dcc
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc


DISRUPTION_COLOUR = "#DC2626"
MFP_COLOUR = "#F59E0B"


def _mac_is_device(value):
    if not value:
        return False

    parts = str(value).upper().split(":")
    if len(parts) != 6:
        return False

    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return False

    if any(len(part) != 2 for part in parts):
        return False

    # Exclude multicast and broadcast addresses.
    return (octets[0] & 1) == 0


def _signal_for_device(device):
    signal_data = device.get("kismet.device.base.signal", {})
    if not isinstance(signal_data, dict):
        return None

    value = signal_data.get("kismet.common.signal.last_signal")

    try:
        value = float(value)
        if math.isfinite(value) and value < 0:
            return value
    except (TypeError, ValueError):
        pass

    return None


def _is_relevant_alert(alert):
    header = str(alert.get("kismet.alert.header", "")).upper()
    alert_class = str(alert.get("kismet.alert.class", "")).upper()

    if header == "NOCLIENTMFP":
        return True

    if alert_class == "DENIAL":
        return True

    return any(
        token in header
        for token in (
            "DEAUTH",
            "DISASSOC",
            "DISCON",
            "MFP"
        )
    )


def fetch_management_frame_data(credentials, uri, rewind_seconds):
    cutoff = int(time.time()) - int(rewind_seconds)
    base_url = f"http://{credentials}@{uri}"

    alerts_response = requests.get(
        f"{base_url}/alerts/last-time/{cutoff}/alerts.json",
        verify=False,
        timeout=10
    )
    alerts_response.raise_for_status()
    alerts = alerts_response.json()

    if isinstance(alerts, dict):
        alerts = alerts.get("alerts", [])

    if not isinstance(alerts, list):
        alerts = []

    device_response = requests.get(
        f"{base_url}/devices/views/all/devices.json",
        verify=False,
        timeout=10
    )
    device_response.raise_for_status()
    devices = device_response.json()

    if isinstance(devices, dict):
        devices = devices.get("devices", [])

    device_lookup = {}

    for device in devices:
        mac = device.get("kismet.device.base.macaddr")
        if not _mac_is_device(mac):
            continue

        mac = mac.upper()
        device_lookup[mac] = {
            "name": device.get("kismet.device.base.name"),
            "device_type": device.get("kismet.device.base.type", "Unknown"),
            "signal": _signal_for_device(device)
        }

    relevant_alerts = []

    for raw_alert in alerts:
        if not isinstance(raw_alert, dict) or not _is_relevant_alert(raw_alert):
            continue

        try:
            timestamp = float(raw_alert.get("kismet.alert.timestamp", 0))
        except (TypeError, ValueError):
            continue

        if timestamp < cutoff:
            continue

        header = str(raw_alert.get("kismet.alert.header", "Unknown"))
        alert_class = str(raw_alert.get("kismet.alert.class", "Unknown"))

        relevant_alerts.append({
            "timestamp": timestamp,
            "header": header,
            "class": alert_class,
            "severity": raw_alert.get("kismet.alert.severity", "Unknown"),
            "transmitter": str(
                raw_alert.get("kismet.alert.transmitter_mac", "")
            ).upper(),
            "source": str(
                raw_alert.get("kismet.alert.source_mac", "")
            ).upper(),
            "destination": str(
                raw_alert.get("kismet.alert.dest_mac", "")
            ).upper(),
            "other": str(
                raw_alert.get("kismet.alert.other_mac", "")
            ).upper(),
            "channel": raw_alert.get("kismet.alert.channel"),
            "frequency": raw_alert.get("kismet.alert.frequency"),
            "text": raw_alert.get("kismet.alert.text", "")
        })

    relevant_alerts.sort(
        key=lambda item: item["timestamp"],
        reverse=True
    )

    involved = {}

    def add_device(mac, event, assumed_role=None):
        if not _mac_is_device(mac):
            return

        mac = mac.upper()
        record = device_lookup.get(mac, {})
        device_type = record.get("device_type", "Unknown")

        if device_type == "Wi-Fi AP":
            role = "AP"
        elif device_type != "Unknown":
            role = "Client"
        else:
            role = assumed_role or "Device"

        if mac not in involved:
            involved[mac] = {
                "mac": mac,
                "name": record.get("name") or "Unknown",
                "device_type": device_type,
                "signal": record.get("signal"),
                "roles": set(),
                "alerts": []
            }

        involved[mac]["roles"].add(role)
        involved[mac]["alerts"].append(event)

    for event in relevant_alerts:
        header = event["header"].upper()

        if header == "NOCLIENTMFP":
            add_device(event["transmitter"], event, "AP")
            add_device(event["source"], event, "Client")
            add_device(event["destination"], event, "AP")
            add_device(event["other"], event, "Device")
        else:
            add_device(event["transmitter"], event, "AP")
            add_device(event["source"], event, "Client")
            add_device(event["destination"], event, "Client")
            add_device(event["other"], event, "Device")

    for item in involved.values():
        item["roles"] = sorted(item["roles"])
        item["alerts"].sort(
            key=lambda alert: alert["timestamp"],
            reverse=True
        )

    return {
        "alerts": relevant_alerts,
        "devices": list(involved.values()),
        "alert_count": len(relevant_alerts),
        "device_count": len(involved)
    }


def create_management_frame_radar(devices, selected_mac=None):
    fig = go.Figure()

    theta = [
        math.radians(angle)
        for angle in range(361)
    ]

    for signal in (-90, -80, -70, -60, -50, -40, -30, -20):
        radius = 0.10 + ((-20.0 - signal) / 70.0) * 0.90

        fig.add_trace(go.Scatter(
            x=[radius * math.cos(angle) for angle in theta],
            y=[radius * math.sin(angle) for angle in theta],
            mode="lines",
            line=dict(color="#CBD5E1", width=1, dash="dot"),
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
        x=[1.05 * math.cos(angle) for angle in theta],
        y=[1.05 * math.sin(angle) for angle in theta],
        mode="lines",
        line=dict(color="#94A3B8", width=1.5),
        hoverinfo="skip",
        showlegend=False
    ))

    x_values = []
    y_values = []
    colours = []
    symbols = []
    hover_text = []
    mac_values = []
    sizes = []

    for item in sorted(devices, key=lambda value: value["mac"]):
        mac = item["mac"]

        # Stable angle derived from MAC; it does not depend on list order.
        digest = hashlib.sha256(mac.encode("utf-8")).digest()
        angle = (
            int.from_bytes(digest[:4], "big") / 0xFFFFFFFF
        ) * 2.0 * math.pi

        signal = item.get("signal")

        if signal is None:
            radius = 1.05
            signal_text = "Unavailable"
        else:
            signal = max(-90.0, min(-20.0, float(signal)))
            radius = 0.10 + ((-20.0 - signal) / 70.0) * 0.90
            signal_text = f"{signal:.1f} dBm"

        x = radius * math.cos(angle)
        y = radius * math.sin(angle)

        headers = {
            alert["header"].upper()
            for alert in item["alerts"]
        }

        has_disruption = any(
            header != "NOCLIENTMFP"
            for header in headers
        )

        colour = (
            DISRUPTION_COLOUR
            if has_disruption
            else MFP_COLOUR
        )

        role = " / ".join(item["roles"]) or "Device"
        symbol = "diamond" if "AP" in item["roles"] else "circle"

        if selected_mac and mac == selected_mac.upper():
            size = 21
        else:
            size = 14

        x_values.append(x)
        y_values.append(y)
        colours.append(colour)
        symbols.append(symbol)
        mac_values.append(mac)
        sizes.append(size)

        hover_text.append(
            f"<b>{mac}</b><br>"
            f"Name: {item['name']}<br>"
            f"Role: {role}<br>"
            f"Type: {item['device_type']}<br>"
            f"Latest signal: {signal_text}<br>"
            f"Related alerts: {len(item['alerts'])}"
        )

    if devices:
        fig.add_trace(go.Scatter(
            x=x_values,
            y=y_values,
            customdata=mac_values,
            mode="markers+text",
            text=mac_values,
            textposition="top center",
            textfont=dict(size=9, color="#1E293B"),
            hovertext=hover_text,
            hovertemplate="%{hovertext}<extra></extra>",
            marker=dict(
                size=sizes,
                color=colours,
                symbol=symbols,
                line=dict(color="#FFFFFF", width=1.5),
                opacity=0.95
            ),
            showlegend=False
        ))

    # Legend: shape identifies device role; colour identifies alert category.
    legend_items = [
        ("Access Point (AP)", "diamond", "#64748B"),
        ("Client", "circle", "#64748B"),
        ("Disruption event", "circle", DISRUPTION_COLOUR),
        ("MFP protection warning", "circle", MFP_COLOUR),
    ]

    for label, symbol, colour in legend_items:
        fig.add_trace(go.Scatter(
            x=[None], y=[None],
            mode="markers",
            marker=dict(size=11, color=colour, symbol=symbol),
            name=label,
            hoverinfo="skip"
        ))

    fig.update_layout(
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
        font=dict(color="#1E293B"),
        autosize=True,
        margin=dict(l=20, r=20, t=20, b=20),
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.01,
            xanchor="left",
            x=0
        ),
        hovermode="closest",
        uirevision="management-frame-anomalies",
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


def _alert_card(alert):
    timestamp = datetime.fromtimestamp(
        alert["timestamp"]
    ).strftime("%Y-%m-%d %H:%M:%S")

    category = (
        "MFP protection warning"
        if alert["header"].upper() == "NOCLIENTMFP"
        else "Disruption event"
    )

    return html.Div([
        html.Div(
            f"{timestamp} — {alert['header']}",
            style={"fontWeight": "bold", "marginBottom": "5px"}
        ),
        html.Div(
            f"Category: {category} | "
            f"Class: {alert['class']} | "
            f"Severity: {alert['severity']}"
        ),
        html.Div(f"Transmitter: {alert['transmitter'] or 'Unknown'}"),
        html.Div(f"Source: {alert['source'] or 'Unknown'}"),
        html.Div(f"Destination: {alert['destination'] or 'Unknown'}"),
        html.Div(f"Other: {alert['other'] or '—'}"),
        html.Div(f"Channel: {alert['channel'] or '—'}"),
        html.P(
            alert["text"] or "No explanation supplied by Kismet.",
            style={"marginTop": "7px", "marginBottom": "0"}
        )
    ], style={
        "border": "1px solid #CBD5E1",
        "borderRadius": "6px",
        "padding": "10px",
        "marginBottom": "9px",
        "backgroundColor": "#FFFFFF"
    })


def create_management_frame_layout():
    return html.Div([
        dcc.Store(
            id="management_frame_selected_mac",
            data=None
        ),

        html.Div([
            # Left pane: radar
            html.Div([
                html.Div(
                    "Management-frame Anomalies",
                    className="management-frame-heading"
                ),

                html.Div(
                    "Devices involved in observed disruption events and MFP protection warnings. "
                    "Marker distance represents latest available signal strength, not event-time signal.",
                    className="management-frame-description"
                ),

                dcc.Graph(
                    id="management_frame_radar",
                    figure=create_management_frame_radar([]),
                    config={"responsive": True, "scrollZoom": True},
                    style={
                        "height": "100%",
                        "width": "100%"
                    }
                )
            ], className="management-frame-panel management-frame-radar-panel"),

            # Right pane: selected device and related alerts
            html.Div([
                html.Div(
                    "Selected device and related alerts",
                    className="management-frame-panel-heading"
                ),

                html.Div(
                    id="management_frame_status",
                    style={"padding": "8px 12px", "fontWeight": "bold"}
                ),

                html.Div(
                    id="management_frame_alert_details",
                    children="Select a device marker on the radar to view its related alerts.",
                    className="management-frame-alert-details"
                )
            ], className="management-frame-panel management-frame-details-panel")

        ], className="management-frame-grid")

    ], id="management_frame_container")


def register_management_frame_callbacks(app):

    @app.callback(
        Output("management_frame_selected_mac", "data"),
        Input("management_frame_radar", "clickData"),
        State("management_frame_selected_mac", "data")
    )
    def select_management_frame_device(click_data, current):
        if not click_data or not click_data.get("points"):
            raise dash.exceptions.PreventUpdate

        mac = click_data["points"][0].get("customdata")

        if not mac:
            raise dash.exceptions.PreventUpdate

        if current == mac:
            return None

        return mac

    @app.callback(
        [
            Output("management_frame_radar", "figure"),
            Output("management_frame_status", "children"),
            Output("management_frame_alert_details", "children")
        ],
        [
            Input("graph_type", "value"),
            Input("update_graph", "n_clicks"),
            Input("rewind_seconds", "value"),
            Input("management_frame_selected_mac", "data")
        ],
        [
            State("kismet_credentials", "value"),
            State("kismet_uri", "value")
        ]
    )
    def update_management_frame_view(
        graph_type,
        n_clicks,
        rewind_seconds,
        selected_mac,
        credentials,
        uri
    ):
        if graph_type != "scenario20_management_frame_anomalies":
            raise dash.exceptions.PreventUpdate

        try:
            data = fetch_management_frame_data(
                credentials,
                uri,
                rewind_seconds
            )

            figure = create_management_frame_radar(
                data["devices"],
                selected_mac
            )

            status = (
                f"Alerts in selected window: {data['alert_count']} | "
                f"Devices involved: {data['device_count']} | "
                "Marker position uses latest available signal."
            )

            selected = next(
                (
                    item for item in data["devices"]
                    if item["mac"] == selected_mac
                ),
                None
            )

            if selected:
                details = [
                    html.H5(
                        f"{selected['mac']} — "
                        f"{' / '.join(selected['roles'])}"
                    ),
                    html.Div(
                        f"Device name: {selected['name']} | "
                        f"Type: {selected['device_type']}"
                    ),
                    html.Hr(),
                    html.Div(
                        f"Related alerts: {len(selected['alerts'])}",
                        style={"fontWeight": "bold", "marginBottom": "8px"}
                    )
                ]

                details.extend(
                    _alert_card(alert)
                    for alert in selected["alerts"]
                )
            else:
                details = (
                    "Select a device marker to view its related alerts. "
                    f"There are {data['alert_count']} qualifying alert records "
                    "in the selected time window."
                )

            return figure, status, details

        except Exception as error:
            logging.exception(
                "Unable to update Management-frame Anomalies view"
            )

            return (
                create_management_frame_radar([]),
                f"Unable to retrieve management-frame alerts: {error}",
                "Alert details are unavailable."
            )
