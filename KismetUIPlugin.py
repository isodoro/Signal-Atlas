import dash
from dash import dcc
import dash_bootstrap_components as dbc
from dash import html
from dash.dependencies import Input, Output, State
import visdcc
import pandas as pd
import time
import math

import sys
import json
import collections
import csv
import datetime
import requests
import os
import logging

# Wi-Fi signal processing and radar visualisation.
from signal_manager import process_devices
from signal_position import process_radar
from signal_radar import create_radar_figure

from around_me import create_around_me_layout, register_around_me_callbacks
from timeline import create_timeline_layout, register_timeline_callbacks
from probed_ssids import create_probed_ssids_layout, register_probed_ssids_callbacks
from ap_identity import create_ap_identity_layout, register_ap_identity_callbacks
from management_frame_anomalies import create_management_frame_layout, register_management_frame_callbacks
from wpa_handshakes import create_wpa_handshakes_layout, register_wpa_handshakes_callbacks


logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.INFO)

app = dash.Dash(__name__)

nodes = []
edges = []

label_to_replace_in_graph = ":-:"

mac_details_cache = collections.defaultdict(dict)

tmp_csvfile = "edge_df.csv"

epoch = ""

kismet_host = os.getenv('SIGNAL_ATLAS_KISMET_HOST', '127.0.0.1')
kismet_port = os.getenv('SIGNAL_ATLAS_KISMET_PORT', '2501')
kismet_user = os.getenv('SIGNAL_ATLAS_KISMET_USER', 'kali')
kismet_password = os.getenv('SIGNAL_ATLAS_KISMET_PASSWORD', 'kali')

ui_variables = {
    'graph_type': 'db-device-and-bridge',
    'rewind_seconds': 60,
    'kismet_credentials': f'{kismet_user}:{kismet_password}',
    'kismet_uri': f'{kismet_host}:{kismet_port}',
}

def pretty_format_hex(a):
    return ':'.join([a[i:i + 2] for i in range(0, len(a), 2)])

def create_edge_df(graph_type):

    global ui_variables,mac_details_cache,epoch,devices_dict

    edge_df_handle = open(tmp_csvfile, 'w', newline='')
    edge_writer = csv.writer(edge_df_handle)
    edge_header = ['from_mac', 'to_mac', 'channel', 'total_packets', 'total_bytes']
    edge_writer.writerow(edge_header)

    kismet_api_uri = "http://" + ui_variables['kismet_credentials'] + "@" + ui_variables['kismet_uri'] + "/devices/views/all/devices.json"

    logging.info("Sending Kismet API request")

    if kismet_api_uri:
        try:
             devices_dict = requests.get(kismet_api_uri, verify=False, timeout=10).json()
        except:
            return

        for device in devices_dict:

            mac = device['kismet.device.base.macaddr']
            retval_device_type = device['kismet.device.base.type']
            manuf = device['kismet.device.base.manuf']
            if not manuf or manuf == 'Unknown':
                stripped_mac = mac.replace(":","")
                u_l_bit = (int(stripped_mac[1], 16) & 2) >> 1
                if u_l_bit:
                    manuf = "Privacy"
                else:
                    manuf = ""
            retval_node_name = manuf + label_to_replace_in_graph + mac

            first_time_text = "First seen : " + datetime.datetime.fromtimestamp(device['kismet.device.base.first_time']).strftime('%c')
            last_time_text = "Last seen : " + datetime.datetime.fromtimestamp(device['kismet.device.base.last_time']).strftime('%c')

            if retval_device_type == 'Wi-Fi AP':
                retval_node_name = device['kismet.device.base.manuf'] + "\n" + mac + "\n" + device['kismet.device.base.name']
                retval_node_details =  first_time_text + "<br/>" + last_time_text + "<br/>" + "channel <b>" +  device['kismet.device.base.channel'] + "</b><br/>"  + device['kismet.device.base.macaddr']

            else:
                retval_node_details = first_time_text + "<br/>" + last_time_text

            signal_strength = 0
            try:
                signal_strength = device['kismet.device.base.signal']['kismet.common.signal.last_signal']
            except:
                pass
            if signal_strength < 0:
                retval_node_details = retval_node_details + "<br/> Last seen signal strength: <b>" + str(signal_strength) + "</b>"

            retval_node_details = retval_node_details + "<br/>"

            mac_details_cache[mac]['node_name'] = retval_node_name
            mac_details_cache[mac]['node_details'] = retval_node_details
            mac_details_cache[mac]['device_type'] = retval_device_type
            mac_details_cache[mac]['last_time'] = device['kismet.device.base.last_time']
            mac_details_cache[mac]['channel'] = device['kismet.device.base.channel']
            mac_details_cache[mac]['packets'] = device['kismet.device.base.packets.total']
            mac_details_cache[mac]['data'] = device['kismet.device.base.datasize']
            mac_details_cache[mac]['signal'] = 0

            try:
                mac_details_cache[mac]['signal'] = device['kismet.device.base.signal']['kismet.common.signal.last_signal']
            except:
                pass

        # Change this to call a function testing all device types, then only write of device type selected by UI
        for device in devices_dict:

            channel = device['kismet.device.base.channel']

            device_mac = device['kismet.device.base.macaddr']

            try:
                client_map_dict = device['dot11.device']['dot11.device.client_map']
                for client_mac in client_map_dict:
                    valid_device = False
                    if graph_type == 'db-device':
                        if device['kismet.device.base.type'] in [
                            'Wi-Fi Device',
                            'Wi-Fi Device (Inferred)',
                            'Wi-Fi WDS Device',
                            'Wi-Fi Ad-Hoc'
                        ]:
                            valid_device = True

                    elif graph_type == 'db-device-and-bridge':
                        if device['kismet.device.base.type'] in [
                            'Wi-Fi Device',
                            'Wi-Fi Device (Inferred)',
                            'Wi-Fi WDS Device',
                            'Wi-Fi Ad-Hoc',
                            'Wi-Fi Bridged'
                        ]:
                            valid_device = True

                    if valid_device == True:
                        packets=mac_details_cache[device_mac]['packets']
                        data=mac_details_cache[device_mac]['data']

                        if (int(time.time()) - client_map_dict[client_mac]['dot11.client.last_time']) < int(ui_variables['rewind_seconds']):
                            edge_writer.writerow([device_mac,client_mac,channel,packets,data])
            except:
                pass

    edge_df_handle.flush()
    edge_df_handle.close()

    logging.info("Kismet DB processed")
    return

def update_graph_data():
    global nodes,edges,mac_details_cache,epoch

    try:
     df = pd.read_csv(tmp_csvfile)
    except:
        return

    node_list = list(set(df['from_mac'].dropna().unique().tolist() + df['to_mac'].dropna().unique().tolist()))
    node_translation_dict={
                                "Wi-Fi AP":                 ['#000000'],      #black
                                "Wi-Fi Bridged":            ['#808080'],      #grey
                                "Wi-Fi Device":             ['#008000'],      #green
                                "Wi-Fi Client":             ['#008000'],      #green
                                "Wi-Fi Device (Inferred)":  ['#808000'],      #olive
                                "Wi-Fi Ad-Hoc":             ['#800080'],      #purple
                                "Wi-Fi WDS Device":         ['#008080'],      #teal
                                "Wi-Fi WDS AP":             ['#C0C0C0'],      #silver
                                "Unknown":                  ['#800000']}      #maroon

    if len(node_list) == 0:
        nodes.clear()
        node_list = ['Nothing to display']
        edges.clear()
    else:
        nodes = []

    for node_name in node_list:

        node_label = "Nothing to display"
        node_title = "Nothing to display"
        node_color = '#FF0000' #red
        node_size = 10
        if node_name != 'Nothing to display' :
            node_label_unfiltered = mac_details_cache[node_name]['node_name']
            node_label = node_label_unfiltered.replace(label_to_replace_in_graph,"\n")
            node_title = mac_details_cache[node_name]['node_details']
            node_color = node_translation_dict[mac_details_cache[node_name]['device_type']][0];
        nodes.append({
            'id': node_name,
            'label': node_label,
            'shape': 'dot',
            'size': node_size,
            'color': node_color,
            'title': node_title,
            'font': {'size' : 10, 'color': "black"}
            }),

    for row in df.to_dict(orient='records'):
        source, target, packets, total_bytes = row['from_mac'] , row['to_mac'], row['total_packets'], row['total_bytes']
        if packets > 0:
            label = str(packets) + " packets average " + str(round(total_bytes/packets)) + " bytes  </br>since " + epoch
        else:
            label = ""
        if(total_bytes > 0):
            try:
                edges.append({
                    'id': source + "__" + target,
                    'from': source,
                    'to': target,
                    'value': math.log10(total_bytes),
                    'color': {'color' : '#CCCCCC'},
                    'width': 2,
                    'font': {'size' : 10},
                    'title': label
                })
            except:
                pass # very occasionally some rows are nan
    return True

try:
    os.remove(tmp_csvfile)
except:
    pass

graph_type_options=[]

# DEVICE DATA
graph_type_options.append({
    'label': 'DEVICE DATA',
    'value': 'device_data_header',
    'disabled': True
})
graph_type_options.append({
    'label': 'All Detected Devices - All detected APs, clients and bridged devices. Excludes probes',
    'value': 'db-device-and-bridge'
})
graph_type_options.append({
    'label': 'Wi-Fi Clients - Devices that connect to or communicate with Wi-Fi networks',
    'value': 'db-device'
})

# NETWORK OVERVIEW
graph_type_options.append({
    'label': 'NETWORK OVERVIEW',
    'value': 'network_overview_header',
    'disabled': True
})
graph_type_options.append({
    'label': 'Wi-Fi Radar - Nearby APs and devices, including currently associated clients, by signal strength',
    'value': 'around_me'
})
graph_type_options.append({
    'label': 'Device Timeline - Device activity and signal history over time',
    'value': 'timeline'
})

# WIRELESS SECURITY
graph_type_options.append({
    'label': 'WIRELESS SECURITY',
    'value': 'wireless_security_header',
    'disabled': True
})
graph_type_options.append({
    'label': 'WPA Handshakes - Captured WPA handshakes and related details',
    'value': 'scenario20_wpa_handshakes'
})
graph_type_options.append({
    'label': 'Management-Frame Security - Management-frame anomalies, disruption events and MFP warnings',
    'value': 'scenario20_management_frame_anomalies'
})

# ACCESS POINT INVESTIGATION
graph_type_options.append({
    'label': 'ACCESS POINT INVESTIGATION',
    'value': 'access_point_investigation_header',
    'disabled': True
})
graph_type_options.append({
    'label': 'Access Point Identity - Compare access points advertising the same SSID',
    'value': 'scenario20_ap_identity'
})

# DEVICE DISCOVERY
graph_type_options.append({
    'label': 'DEVICE DISCOVERY',
    'value': 'device_discovery_header',
    'disabled': True
})
graph_type_options.append({
    'label': 'SSID Probe Activity - Devices sending probe requests and the SSIDs they are searching for',
    'value': 'scenario20_probed_ssids'
})

# https://visjs.github.io/vis-network/docs/network/

controls = html.Div(
    [
        # ROW 1
        html.Div(
            [
                html.Div(
                    [
                        html.Span("Graph Type:", className="control-label"),
                        dcc.Dropdown(
                            id='graph_type',
                            options=graph_type_options,
                            value=ui_variables['graph_type'],
                            clearable=False,
                            style={'width': '280px'}
                        )
                    ],
                    className="control-group"
                ),

                html.Div(
                    [
                        html.Span("For past:", className="control-label"),
                        dcc.Dropdown(
                            id='rewind_seconds',
                            options=[
                                {'label': '1 min', 'value': 60},
                                {'label': '5 mins', 'value': 300},
                                {'label': '15 mins', 'value': 900},
                                {'label': '30 mins', 'value': 1800},
                                {'label': '45 mins', 'value': 2700},
                                {'label': '1 hr', 'value': 3600},
                                {'label': '4 hrs', 'value': 14400},
                                {'label': '8 hrs', 'value': 28800},
                                {'label': '1 day', 'value': 86400}
                            ],
                            value=ui_variables['rewind_seconds'],
                            clearable=False,
                            style={'width': '120px'}
                        )
                    ],
                    className="control-group"
                ),

                dbc.Button(
                    "Update",
                    id="update_graph",
                    n_clicks=0,
                    color="primary"
                )
            ],
            className="control-row"
        ),

        # ROW 2
        html.Div(
            [
                html.Div(
                    [
                        html.Span("Kismet Credentials: (user:pass)", className="control-label"),
                        dbc.Input(
                            id='kismet_credentials',
                            value=ui_variables['kismet_credentials'],
                            type='password',
                            style={'width': '220px'}
                        )
                    ],
                    className="control-group"
                ),

                html.Div(
                    [
                        html.Span("Kismet URI:", className="control-label"),
                        dbc.Input(
                            id='kismet_uri',
                            value=ui_variables['kismet_uri'],
                            style={'width': '240px'}
                        )
                    ],
                    className="control-group"
                )
            ],
            className="control-row"
        )
    ],
    className="dashboard-controls"
)


legend_items = [
    ("Wi-Fi AP", "#000000"),
    ("Signal Unavailable", "#F59E0B"),
    ("Wi-Fi Bridged", "#808080"),
    ("Wi-Fi Device", "#008000"),
    ("Wi-Fi Device (Inferred)", "#808000"),
    ("Wi-Fi Ad-Hoc", "#800080"),
    ("Wi-Fi WDS Device", "#008080"),
    ("Wi-Fi WDS AP", "#404040"),
    ("Unknown", "#800000")
]

legend = html.Div(
    [
        html.Div([
            html.Span(
                style={
                    "backgroundColor": colour,
                    "width": "14px",
                    "height": "14px",
                    "display": "inline-block",
                    "marginRight": "6px",
                    "border": "1px solid #999"
                }
            ),
            html.Span(label)
        ], className="legend-item")
        for label, colour in legend_items
    ],
    className="dashboard-legend"
)


network_options = {
    'height': '100%',
    'width': '100%',
    'interaction': {'hover': True},
    'edges': {
        'scaling': {
            'min': 0.5,
            'max': 5.0
        }
    },
    'physics': {
        'solver': 'forceAtlas2Based',
        'minVelocity': 0.75
    }
}


# Existing Kismet device relationship graph.
network = visdcc.Network(
    id='net',
    options=network_options,
    data={'nodes': [{}], 'edges': [{}]}
)


# Network graph container.
network_container = html.Div(
    [network],
    id='network_container',
    className="visualisation-panel",
    style={'display': 'block'}
)


# Radar visualisation container.
radar_container = html.Div([
    html.H3("Wi-Fi Signal Radar"),

    dbc.Button(
        "Refresh Radar",
        id="refresh_signal_radar",
        n_clicks=0
    ),

    html.Div(
        id="signal_radar_status",
        children="Select Radar Map to load access points.",
        className="radar-status"
    ),

    dcc.Graph(
        id="signal_radar_graph",
        figure=create_radar_figure([]),
        config={"responsive": True, "scrollZoom": True},
        style={
            "width": "100%",
            "height": "100%"
        }
    )

], id='radar_container',
   className="visualisation-panel",
   style={'display': 'none'})


# All visualisations share the same display area.
visualisation_area = html.Div([
    html.Div([
        html.Div(
            "Find a device:",
            className="control-label",
            style={"fontWeight": "bold", "marginBottom": "5px"}
        ),
        dcc.Dropdown(
            id="device_search",
            options=[],
            value=None,
            placeholder="Search MAC address, device name or SSID...",
            searchable=True,
            clearable=True,
            style={"width": "620px", "maxWidth": "100%"}
        )
    ], id="device_search_container", style={"padding": "10px 12px"}),

    dcc.Store(
        id="shared_device_selection",
        data=None
    ),

    network_container,
    radar_container,
    create_around_me_layout(),
    create_timeline_layout(),
    create_probed_ssids_layout(),
    create_ap_identity_layout(),
    create_management_frame_layout(),
    create_wpa_handshakes_layout()
], className="visualisation-area")


app.layout = html.Div([
    html.Div([
        html.Div([
            # Reserved space for the future dashboard logo.
            html.Div(
                html.Img(
                    src="/assets/SignalAtlas.webp",
                    className="dashboard-logo-image"
                ),
                className="dashboard-logo-placeholder"
            ),
            html.Div(
                controls,
                className="dashboard-header-controls"
            )
        ], className="dashboard-header"),
        legend,
        visualisation_area
    ], className="dashboard")
], style={'padding': '0', 'margin': '0'})



# Shared live Kismet device search.
def _device_search_ssids(device):
    found = set()

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if "ssid" in str(key).lower() and isinstance(item, str):
                    if item.strip():
                        found.add(item.strip())
                else:
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(device.get("dot11.device", {}))
    return sorted(found)


@app.callback(
    Output("device_search", "options"),
    Input("device_search", "search_value"),
    State("kismet_credentials", "value"),
    State("kismet_uri", "value")
)
def search_kismet_devices(search_value, credentials, uri):

    query = (search_value or "").strip().casefold()

    if not query:
        return dash.no_update

    try:
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

        options = []

        for device in devices:

            mac = device.get("kismet.device.base.macaddr", "")
            if not mac:
                continue

            device_type = device.get(
                "kismet.device.base.type", "Unknown"
            )

            name = device.get(
                "kismet.device.base.name", ""
            ) or ""

            ssids = _device_search_ssids(device)

            mac_match = query in mac.casefold()
            name_match = query in name.casefold()
            matching_ssids = [
                ssid for ssid in ssids
                if query in ssid.casefold()
            ]

            if mac_match:
                match_type = "MAC"
            elif name_match:
                match_type = "Name"
            elif matching_ssids:
                match_type = "SSID"
            else:
                continue

            selection_type = (
                "ap" if device_type == "Wi-Fi AP" else "client"
            )

            label_parts = [
                device_type,
                f"Match: {match_type}"
            ]

            if name:
                label_parts.append(name)

            display_ssids = (
                matching_ssids if match_type == "SSID" else ssids
            )

            if display_ssids:
                preview = ", ".join(display_ssids[:2])

                if len(preview) > 65:
                    preview = preview[:62] + "..."

                if len(display_ssids) > 2:
                    preview += f" (+{len(display_ssids) - 2} more)"

                label_parts.append(f"SSID: {preview}")

            label_parts.append(mac)

            options.append({
                "label": " | ".join(label_parts),
                "value": f"{selection_type}::{mac}"
            })

            if len(options) >= 100:
                break

        return options

    except Exception:
        logging.exception("Unable to search Kismet devices")
        return []


@app.callback(
    Output("shared_device_selection", "data"),
    Input("device_search", "value")
)
def update_shared_device_selection(value):

    if not value:
        return None

    selection_type, separator, mac = value.partition("::")

    if not separator or not mac:
        return None

    if selection_type not in ("ap", "client"):
        return None

    return {
        "type": selection_type,
        "mac": mac
    }



@app.callback(
    Output("device_search_container", "style"),
    Input("graph_type", "value")
)
def toggle_device_search(graph_type):
    hidden_views = (
        "db-device",
        "db-device-and-bridge",
        "scenario20_ap_identity",
        "scenario20_probed_ssids",
        "scenario20_management_frame_anomalies",
        "scenario20_wpa_handshakes"
    )

    if graph_type in hidden_views:
        return {"display": "none"}

    return {"padding": "10px 12px"}


# Display the selected visualisation.
@app.callback(
    [
        Output('network_container', 'style'),
        Output('radar_container', 'style'),
        Output('around_me_container', 'style'),
        Output('timeline_container', 'style'),
        Output('probed_ssids_container', 'style'),
        Output('ap_identity_container', 'style'),
        Output('management_frame_container', 'style'),
        Output('signal_radar_graph', 'figure'),
        Output('signal_radar_status', 'children'),
        Output('wpa_handshakes_container', 'style')
    ],
    [
        Input('graph_type', 'value'),
        Input('refresh_signal_radar', 'n_clicks')
    ],
    [
        State('kismet_credentials', 'value'),
        State('kismet_uri', 'value')
    ]
)
def refresh_signal_radar(
    graph_type,
    n_clicks,
    kismet_credentials,
    kismet_uri
):

    hidden = {'display': 'none'}
    visible = {'display': 'block'}
    empty_figure = create_radar_figure([])

    # Timeline selected.
    if graph_type == 'timeline':
        return (
            hidden, hidden, hidden, visible,
            hidden, hidden, hidden,
            empty_figure,
            "Device Timeline",
            hidden
        )

    # What is around me selected.
    if graph_type == 'around_me':
        return (
            hidden, hidden, visible, hidden,
            hidden, hidden, hidden,
            empty_figure,
            "What is around me?",
            hidden
        )

    # Probed SSIDs selected.
    if graph_type == 'scenario20_probed_ssids':
        return (
            hidden, hidden, hidden, hidden,
            visible, hidden, hidden,
            empty_figure,
            "Probed SSIDs",
            hidden
        )

    # AP Identity Comparison selected.
    if graph_type == 'scenario20_ap_identity':
        return (
            hidden, hidden, hidden, hidden,
            hidden, visible, hidden,
            empty_figure,
            "AP Identity Comparison",
            hidden
        )

    # Management-frame Anomalies selected.
    if graph_type == 'scenario20_management_frame_anomalies':
        return (
            hidden, hidden, hidden, hidden,
            hidden, hidden, visible,
            empty_figure,
            "Management-frame Anomalies",
            hidden
        )

    # WPA Handshakes selected.
    if graph_type == 'scenario20_wpa_handshakes':
        return (
            hidden, hidden, hidden, hidden,
            hidden, hidden, hidden,
            empty_figure,
            'WPA Handshakes',
            visible
        )

    # Normal network graph selected.
    if graph_type != 'signal_radar':
        return (
            visible, hidden, hidden, hidden,
            hidden, hidden, hidden,
            empty_figure,
            "Select Radar Map to load access points.",
            hidden
        )

    # Radar Map selected: retrieve live Kismet data.
    try:
        kismet_api_uri = (
            f"http://{kismet_credentials}@"
            f"{kismet_uri}/devices/views/all/devices.json"
        )

        response = requests.get(
            kismet_api_uri,
            verify=False,
            timeout=10
        )
        response.raise_for_status()

        devices = response.json()

        if isinstance(devices, dict):
            devices = devices.get('devices', [])

        aps = process_devices(devices)
        radar_data = process_radar(aps)

        figure = create_radar_figure(radar_data['aps'])

        history_count = sum(
            1 for ap in aps
            if ap.get('history_samples', 0) > 0
        )

        status = (
            "Source: Live Kismet API | "
            f"Access points displayed: {radar_data['total_aps']} | "
            f"APs with signal history: {history_count}"
        )

        logging.info(status)

        return (
            hidden, visible, hidden, hidden,
            hidden, hidden, hidden,
            figure,
            status,
            hidden
        )

    except Exception as error:
        logging.exception("Unable to refresh Wi-Fi signal radar")

        return (
            hidden, visible, hidden, hidden,
            hidden, hidden, hidden,
            empty_figure,
            f"Live Kismet connection failed: {error}",
            hidden
        )


@app.callback(
       Output('net', 'data'),
        [Input('update_graph', 'n_clicks'), Input('graph_type', 'value'), Input('kismet_credentials', 'value'), Input('kismet_uri', 'value'), Input('rewind_seconds', 'value')])
def myfun(n_clicks, graph_type, kismet_credentials, kismet_uri, rewind_seconds):

    logging.info("CALLBACK'")

    global nodes,edges,ui_variables

    ui_variables['graph_type'] = graph_type
    ui_variables['rewind_seconds'] = rewind_seconds
    ui_variables['kismet_credentials'] = kismet_credentials
    ui_variables['kismet_uri']= kismet_uri
    # Do not rebuild the network graph while Radar Map is selected.
    if graph_type in ('signal_radar', 'around_me', 'timeline', 'scenario20_probed_ssids', 'scenario20_ap_identity', 'scenario20_management_frame_anomalies', 'scenario20_wpa_handshakes'):
        return {'nodes': nodes, 'edges': edges}

    nodes.clear()
    edges.clear()
    mac_details_cache.clear()
    create_edge_df(ui_variables['graph_type'])
    update_graph_data()

    data = {'nodes':nodes, 'edges':edges}

    return data

register_around_me_callbacks(app)
register_timeline_callbacks(app)
register_probed_ssids_callbacks(app)
register_ap_identity_callbacks(app)
register_management_frame_callbacks(app)
register_wpa_handshakes_callbacks(app)

if __name__ == '__main__':

    logging.info("Starting UI:")

    kismet_login_uri =  "http://" + ui_variables['kismet_credentials'] + "@" + ui_variables['kismet_uri']

    logging.info("Checking Kismet API connection")

    try:
        response = requests.get(kismet_login_uri, verify=False, timeout=10)
    except:
        logging.warn("No response received, check Kismet server and your API URI and credentials")

    kismet_api_uri = "http://" + ui_variables['kismet_credentials'] + "@" + ui_variables['kismet_uri'] + "/system/status.json"

    logging.info("Sending Kismet API request")


    if kismet_api_uri:
        try:
            system_dict = requests.get(kismet_api_uri, verify=False, timeout=10).json()
            epoch_seconds = system_dict['kismet.system.timestamp.start_sec']
            epoch = datetime.datetime.fromtimestamp(epoch_seconds).strftime('%d-%m-%Y %H:%M:%S')
        except:
           logging.warn("No epoch received, check Kismet server and your API URI and credentials")

    app.run(port=8050,host='0.0.0.0',debug=False)
