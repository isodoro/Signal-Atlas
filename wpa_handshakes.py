import logging
from datetime import datetime

import dash
import requests
from dash import dcc, html
from dash.dependencies import Input, Output, State

from signal_manager import process_devices
from around_me import create_around_me_radar


def _advertised_ssid(device):
    ssid_map = (
        device.get("dot11.device", {})
        .get("dot11.device.advertised_ssid_map", {})
    )

    if isinstance(ssid_map, dict):
        for records in ssid_map.values():
            if isinstance(records, list):
                for record in records:
                    if isinstance(record, dict):
                        ssid = record.get("dot11.advertisedssid.ssid")
                        if ssid:
                            return ssid

    elif isinstance(ssid_map, list):
        for record in ssid_map:
            if isinstance(record, dict):
                ssid = record.get("dot11.advertisedssid.ssid")
                if ssid:
                    return ssid

    return None


def _extract_eapol(device):
    dot11 = device.get("dot11.device", {})
    handshake_map = dot11.get("dot11.device.wpa_handshake_list", {})

    if not isinstance(handshake_map, dict):
        return {}

    clients = {}

    for client_mac, messages in handshake_map.items():
        if not isinstance(messages, list):
            continue

        valid_messages = []

        for message in messages:
            if not isinstance(message, dict):
                continue

            if "dot11.eapol.message_num" not in message:
                continue

            valid_messages.append({
                "number": message.get("dot11.eapol.message_num"),
                "timestamp": message.get("dot11.eapol.timestamp"),
                "direction": message.get("dot11.eapol.direction"),
                "replay_counter": message.get("dot11.eapol.replay_counter"),
                "install": message.get("dot11.eapol.install"),
                "nonce": message.get("dot11.eapol.nonce"),
                "pmkid": message.get("dot11.eapol.rsn_pmkid")
            })

        if valid_messages:
            valid_messages.sort(
                key=lambda item: item.get("timestamp") or 0
            )
            clients[str(client_mac).upper()] = valid_messages

    return clients


def _message_status(messages):
    observed = sorted({
        message["number"]
        for message in messages
        if message.get("number") in (1, 2, 3, 4)
    })

    if observed == [1, 2, 3, 4]:
        return "M1–M4 observed — sequence requires validation"

    if observed:
        return "Observed: " + " + ".join(
            f"M{number}" for number in observed
        )

    return "EAPOL evidence captured; message sequence unavailable"


def _format_timestamp(value):
    if value is None:
        return "Unknown"

    try:
        return datetime.fromtimestamp(float(value)).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )
    except (TypeError, ValueError, OverflowError):
        return str(value)


def fetch_wpa_handshake_data(credentials, uri):
    if not credentials or not uri:
        raise ValueError("Kismet credentials or URI are missing")

    response = requests.get(
        f"http://{credentials}@{uri}/devices/views/all/devices.json",
        verify=False,
        timeout=15
    )
    response.raise_for_status()

    devices = response.json()

    if isinstance(devices, dict):
        devices = devices.get("devices", [])

    if not isinstance(devices, list):
        raise ValueError("Unexpected Kismet device-list response")

    signal_lookup = {
        item["mac"].upper(): item
        for item in process_devices(devices)
        if item.get("mac")
    }

    aps = []

    for device in devices:
        if device.get("kismet.device.base.type") != "Wi-Fi AP":
            continue

        clients = _extract_eapol(device)

        # An AP qualifies only when Kismet has captured EAPOL evidence.
        if not clients:
            continue

        mac = str(
            device.get("kismet.device.base.macaddr") or ""
        ).upper()

        if not mac:
            continue

        signal = signal_lookup.get(mac, {})

        aps.append({
            "mac": mac,
            "name": device.get("kismet.device.base.name") or mac,
            "ssid": _advertised_ssid(device),
            "average_signal": signal.get("average_signal"),
            "clients": clients
        })

    aps.sort(key=lambda item: item["mac"])

    return aps


def create_wpa_handshakes_layout():
    return html.Div([
        dcc.Store(
            id="wpa_handshakes_selected_ap",
            data=None
        ),

        html.Div([
            html.Div([
                html.Div(
                    "Access Points with Captured EAPOL Messages",
                    className="wpa-handshakes-heading"
                ),

                dcc.Graph(
                    id="wpa_handshakes_radar",
                    figure=create_around_me_radar(
                        [],
                        "APs with EAPOL Evidence"
                    ),
                    config={
                        "responsive": True,
                        "scrollZoom": True
                    },
                    style={
                        "height": "100%",
                        "width": "100%"
                    }
                )
            ], className="wpa-handshakes-panel wpa-handshakes-radar-panel"),

            html.Div([
                html.Div(
                    "Handshake Evidence",
                    className="wpa-handshakes-heading"
                ),

                html.Div(
                    id="wpa_handshakes_status",
                    children="Waiting for Kismet data.",
                    className="wpa-handshakes-status"
                ),

                html.Div(
                    id="wpa_handshakes_ap_details",
                    children="Select an AP marker to inspect its captured EAPOL evidence.",
                    className="wpa-handshakes-ap-details"
                ),

                html.Div(
                    id="wpa_handshakes_client_list",
                    children=[],
                    className="wpa-handshakes-client-list"
                ),

                html.Label(
                    "Client device",
                    className="wpa-handshakes-label"
                ),

                dcc.Dropdown(
                    id="wpa_handshakes_client",
                    options=[],
                    value=None,
                    placeholder="Select a client",
                    clearable=True
                ),

                html.Div(
                    id="wpa_handshakes_messages",
                    children="Select an AP and client to view captured messages.",
                    className="wpa-handshakes-messages"
                )
            ], className="wpa-handshakes-panel wpa-handshakes-details-panel")

        ], className="wpa-handshakes-grid")

    ], id="wpa_handshakes_container")


def register_wpa_handshakes_callbacks(app):

    @app.callback(
        Output("wpa_handshakes_selected_ap", "data"),
        Input("wpa_handshakes_radar", "clickData"),
        State("wpa_handshakes_selected_ap", "data")
    )
    def select_wpa_ap(click_data, current):
        if not click_data or not click_data.get("points"):
            raise dash.exceptions.PreventUpdate

        mac = click_data["points"][0].get("customdata")

        if not mac:
            raise dash.exceptions.PreventUpdate

        mac = str(mac).upper()

        return None if current == mac else mac

    @app.callback(
        Output("wpa_handshakes_client", "value"),
        Input("wpa_handshakes_selected_ap", "data")
    )
    def reset_wpa_client_selection(selected_ap):
        return None

    @app.callback(
        [
            Output("wpa_handshakes_radar", "figure"),
            Output("wpa_handshakes_status", "children"),
            Output("wpa_handshakes_ap_details", "children"),
            Output("wpa_handshakes_client_list", "children"),
            Output("wpa_handshakes_client", "options"),
            Output("wpa_handshakes_messages", "children")
        ],
        [
            Input("graph_type", "value"),
            Input("update_graph", "n_clicks"),
            Input("wpa_handshakes_selected_ap", "data"),
            Input("wpa_handshakes_client", "value")
        ],
        [
            State("kismet_credentials", "value"),
            State("kismet_uri", "value")
        ]
    )
    def update_wpa_handshakes(
        graph_type,
        n_clicks,
        selected_ap,
        selected_client,
        credentials,
        uri
    ):
        if graph_type != "scenario20_wpa_handshakes":
            raise dash.exceptions.PreventUpdate

        try:
            aps = fetch_wpa_handshake_data(credentials, uri)

            radar_selection = (
                {"type": "ap", "mac": selected_ap}
                if selected_ap else None
            )

            figure = create_around_me_radar(
                aps,
                "APs with EAPOL Evidence",
                selection=radar_selection
            )

            total_clients = sum(
                len(ap["clients"]) for ap in aps
            )

            status = (
                f"APs with EAPOL evidence: {len(aps)} | "
                f"Clients with evidence: {total_clients}"
            )

            ap = next(
                (
                    item for item in aps
                    if item["mac"] == selected_ap
                ),
                None
            )

            if not ap:
                return (
                    figure,
                    status,
                    "Select an AP marker to inspect its captured EAPOL evidence.",
                    [],
                    [],
                    "Select an AP and client to view captured messages."
                )

            clients = ap["clients"]

            client_options = [
                {
                    "label": mac,
                    "value": mac
                }
                for mac in sorted(clients)
            ]

            ap_details = html.Div([
                html.Div(
                    ap.get("ssid") or "SSID unavailable",
                    className="wpa-handshakes-ssid"
                ),
                html.Div(f"AP MAC: {ap['mac']}"),
                html.Div(f"AP name: {ap['name']}"),
                html.Div(f"Clients with captured EAPOL evidence: {len(clients)}")
            ])

            client_summary = html.Div([
                html.Div([
                    html.Div(mac, className="wpa-handshakes-client-mac"),
                    html.Div(
                        f"{len(messages)} captured message(s) — "
                        f"{_message_status(messages)}",
                        className="wpa-handshakes-client-status"
                    )
                ], className="wpa-handshakes-client-item")
                for mac, messages in sorted(clients.items())
            ])

            if not selected_client or selected_client not in clients:
                return (
                    figure,
                    status,
                    ap_details,
                    client_summary,
                    client_options,
                    "Select a client to inspect its captured EAPOL messages."
                )

            messages = clients[selected_client]

            message_cards = [
                html.Div([
                    html.Div(
                        f"M{message['number']} — "
                        f"{_format_timestamp(message['timestamp'])}",
                        className="wpa-handshakes-message-title"
                    ),
                    html.Div(
                        f"Direction: {message['direction']} | "
                        f"Replay counter: {message['replay_counter']}"
                    ),
                    html.Div(
                        f"Install flag: {message['install']}"
                    )
                ], className="wpa-handshakes-message-card")
                for message in messages
            ]

            details = html.Div([
                html.Div(
                    f"Client: {selected_client}",
                    className="wpa-handshakes-client-heading"
                ),
                html.Div(
                    _message_status(messages),
                    className="wpa-handshakes-exchange-status"
                ),
                html.Div(
                    f"Captured EAPOL messages: {len(messages)}",
                    className="wpa-handshakes-message-count"
                ),
                *message_cards
            ])

            return (
                figure,
                status,
                ap_details,
                client_summary,
                client_options,
                details
            )

        except Exception as error:
            logging.exception("Unable to update WPA Handshakes view")

            return (
                create_around_me_radar(
                    [],
                    "APs with EAPOL Evidence"
                ),
                f"Unable to retrieve WPA handshake evidence: {error}",
                "AP details are unavailable.",
                [],
                [],
                "Message details are unavailable."
            )
