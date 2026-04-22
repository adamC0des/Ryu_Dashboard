from flask import Flask, request, redirect, url_for, jsonify
import requests
import json
import html
import os
from datetime import datetime

app = Flask(__name__)

RYU = "http://127.0.0.1:8080"
REFRESH_SECONDS = 5

DEVICE_REGISTRY_FILE = "device_registry.json"
QUARANTINE_STATE_FILE = "quarantine_state.json"

SWITCH_LABELS = {
    "00000000bada111": "Switch_10.10.10",
    "00000000bada222": "Switch_10.10.20"
}

QUARANTINE_PORTS = {
    "00000000bada111": 2,
    "00000000bada222": 2
}

MAC_WHITELIST = {
    "00:0c:29:41:b5:e3": {"label": "RYU_10.10.0.3", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:41:b5:ed": {"label": "RYU_10.10.0.3", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:68:33:c1": {"label": "RYU_10.10.0.4", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:68:33:cb": {"label": "RYU_10.10.0.4", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:bc:8d:5d": {"label": "OFSW_Remote", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:bc:8d:67": {"label": "OFSW_Remote", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:bc:8d:71": {"label": "OFSW_Remote", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:5c:1c:37": {"label": "Virtual_Router", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:5c:1c:41": {"label": "Virtual_Router", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:5c:1c:4b": {"label": "Virtual_Router", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:92:db:a4": {"label": "Splunk_VM", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:f1:4a:c3": {"label": "Ai_IDS", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:f1:4a:cd": {"label": "Ai_IDS", "role": "Virtual Machine", "owner": "Lab"},
    "00:50:56:bc:2c:9a": {"label": "xHost_20.x1", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:7c:18:84": {"label": "xHost_20.x2", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:0c:fc:b4": {"label": "DNSCAT2_server", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:3d:74:e7": {"label": "DNSCAT2_client", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:16:37:b5": {"label": "Test_IoT_Device", "role": "Approved IoT", "owner": "Lab"},
}

BASE = f"""
<html>
<head>
<title>SDN Dashboard</title>
<meta http-equiv="refresh" content="{REFRESH_SECONDS}">
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 0;
    background: #f4f4f4;
}}
.header {{
    background: #2f6f73;
    color: white;
    padding: 18px 22px;
    font-size: 28px;
    font-weight: bold;
    display: flex;
    justify-content: space-between;
    align-items: center;
}}
.header-btn {{
    background: white;
    color: #2f6f73;
    border: none;
    padding: 10px 14px;
    border-radius: 6px;
    cursor: pointer;
    text-decoration: none;
    font-size: 14px;
    font-weight: bold;
}}
.container {{
    display: flex;
    min-height: calc(100vh - 66px);
}}
.sidebar {{
    width: 240px;
    background: #d88e85;
    padding: 15px;
}}
.sidebar a {{
    display: block;
    background: #b04733;
    color: white;
    padding: 12px;
    margin-bottom: 10px;
    text-decoration: none;
    border-radius: 6px;
    font-weight: bold;
}}
.content {{
    flex: 1;
    padding: 20px;
    background: white;
    overflow-x: auto;
}}
.switch-tab {{
    background: #d88e85;
    padding: 10px 16px;
    margin: 5px;
    display: inline-block;
    border-radius: 5px;
    text-decoration: none;
    color: #222;
    font-weight: bold;
}}
.switch-tab.active {{
    outline: 3px solid #2f6f73;
    background: #f0c3bd;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}}
th {{
    background: #8d6b1f;
    color: white;
    padding: 10px;
}}
td {{
    border: 1px solid #ccc;
    padding: 8px;
    vertical-align: top;
}}
button {{
    background: #2f6f73;
    color: white;
    border: none;
    padding: 8px 12px;
    border-radius: 4px;
    cursor: pointer;
    margin-right: 6px;
}}
button.delete-btn {{ background: #b33a3a; }}
button.quarantine-btn {{ background: #cc3300; }}
button.unquarantine-btn {{ background: #007a45; }}
button.approve-btn {{ background: #1a6fbf; }}
button.small-btn {{ padding: 6px 10px; font-size: 12px; }}
input, textarea {{
    width: 100%;
    box-sizing: border-box;
    margin-bottom: 10px;
    padding: 8px;
}}
.card {{
    background: #fafafa;
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 18px;
    margin-bottom: 20px;
}}
.msg {{
    background: #eef7f7;
    border: 1px solid #c7e0e0;
    padding: 10px;
    border-radius: 6px;
    margin-bottom: 15px;
}}
.err {{
    background: #fff0f0;
    border: 1px solid #e0b5b5;
    padding: 10px;
    border-radius: 6px;
    margin-bottom: 15px;
}}
.note {{
    background: #fff8e6;
    border: 1px solid #e6d4a8;
    padding: 10px;
    border-radius: 6px;
    margin-bottom: 15px;
}}
pre {{
    white-space: pre-wrap;
    word-break: break-word;
    margin: 0;
}}
.inline-form {{ display: inline-block; margin: 0; }}
.small {{ font-size: 12px; color: #555; }}
.badge {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: bold;
}}
.badge-trusted      {{ background: #d4f5d4; color: #1a5c1a; }}
.badge-iot          {{ background: #ffd6cc; color: #8a1f00; }}
.badge-approved-iot {{ background: #d6eaff; color: #003d80; }}
.badge-quarantined  {{ background: #ffe0b2; color: #7a3300; }}
.badge-vm           {{ background: #e0f0ff; color: #0a3060; }}
.graph-wrap {{
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}}
.graph-panel {{ flex: 2; min-width: 900px; overflow-x: auto; }}
.info-panel  {{ flex: 1; min-width: 320px; }}
svg {{
    width: 100%;
    min-width: 1200px;
    height: 900px;
    background: #f8f9fb;
    border: 1px solid #ddd;
    border-radius: 8px;
}}
.info-box {{
    background: #fafafa;
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 16px;
}}
.legend {{
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 15px;
}}
.legend-item {{
    display: flex;
    align-items: center;
    gap: 8px;
    background: #fafafa;
    border: 1px solid #ddd;
    border-radius: 6px;
    padding: 7px 12px;
    font-size: 13px;
    font-weight: bold;
}}
.legend-color {{
    width: 18px;
    height: 18px;
    border-radius: 50%;
    border: 2px solid rgba(0,0,0,0.18);
}}
</style>
</head>
<body>
<div class="header">
    <div>SDN Dashboard</div>
    <div>
        <a class="header-btn" href="javascript:window.location.reload()">&#x27F3; Refresh</a>
    </div>
</div>
<div class="container">
    <div class="sidebar">
        <a href="/">Home</a>
        <a href="/topology">Topology</a>
        <a href="/hosts">Host Discovery</a>
        <a href="/flows">Flows</a>
        <a href="/ports">Ports</a>
        <a href="/flowcontrol">Flow Control</a>
        <a href="/switches">Switches</a>
        <a href="/quarantine">Quarantine</a>
    </div>
    <div class="content">
        __CONTENT__
    </div>
</div>
</body>
</html>
"""


# -------------------------------------------------------------------
# File helpers
# -------------------------------------------------------------------
def load_json_file(path, default):
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return default

def save_json_file(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_registry():
    return load_json_file(DEVICE_REGISTRY_FILE, {})

def save_registry(registry):
    save_json_file(DEVICE_REGISTRY_FILE, registry)

def load_quarantine_state():
    return load_json_file(QUARANTINE_STATE_FILE, {})

def save_quarantine_state(state):
    save_json_file(QUARANTINE_STATE_FILE, state)


# -------------------------------------------------------------------
# Utility helpers
# -------------------------------------------------------------------
def page(html_content):
    return BASE.replace("__CONTENT__", html_content)

def normalize_mac(mac):
    return (mac or "").strip().lower()

def friendly_switch_name(dpid):
    return SWITCH_LABELS.get(str(dpid), f"SW_{str(dpid)[-3:]}")

def dpid_to_int(dpid_value):
    s = str(dpid_value).strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    if all(ch.isdigit() for ch in s):
        return int(s)
    return int(s, 16)

def get_json(path, default):
    try:
        r = requests.get(RYU + path, timeout=3)
        r.raise_for_status()
        return r.json()
    except Exception:
        return default

def post_json(path, payload):
    r = requests.post(RYU + path, json=payload, timeout=3)
    return r.text

def get_switches():
    data = get_json("/stats/switches", [])
    return data if isinstance(data, list) else []

def get_topology_switches():
    data = get_json("/v1.0/topology/switches", [])
    return data if isinstance(data, list) else []

def get_topology_links():
    data = get_json("/v1.0/topology/links", [])
    return data if isinstance(data, list) else []

def get_topology_hosts():
    data = get_json("/v1.0/topology/hosts", [])
    return data if isinstance(data, list) else []

def next_unknown_label(registry):
    count = 1
    existing = {v.get("label", "") for v in registry.values()}
    while True:
        label = f"Unregistered Device {count}"
        if label not in existing:
            return label
        count += 1

def sync_device_registry():
    registry = load_registry()
    topo_hosts = get_topology_hosts()
    seen_now = set()

    for host in topo_hosts:
        mac = normalize_mac(host.get("mac", ""))
        if not mac:
            continue

        seen_now.add(mac)
        port = host.get("port", {})
        dpid = str(port.get("dpid", "unknown"))
        port_no = str(port.get("port_no", "unknown"))
        ipv4 = host.get("ipv4", [])
        ipv6 = host.get("ipv6", [])
        now = datetime.utcnow().isoformat()

        if mac in MAC_WHITELIST:
            base = MAC_WHITELIST[mac]
            registry[mac] = {
                "label": base.get("label", "Known Device"),
                "role": base.get("role", "Virtual Machine"),
                "owner": base.get("owner", "Lab"),
                "status": "Whitelisted",
                "dpid": dpid,
                "port_no": port_no,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "last_seen": now,
                "currently_seen": True
            }
        else:
            if mac not in registry:
                registry[mac] = {
                    "label": next_unknown_label(registry),
                    "role": "IoT / Unregistered",
                    "owner": "Unregistered",
                    "status": "Not Whitelisted",
                    "dpid": dpid,
                    "port_no": port_no,
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "last_seen": now,
                    "currently_seen": True
                }
            else:
                registry[mac]["dpid"] = dpid
                registry[mac]["port_no"] = port_no
                registry[mac]["ipv4"] = ipv4
                registry[mac]["ipv6"] = ipv6
                registry[mac]["last_seen"] = now
                registry[mac]["currently_seen"] = True

    for mac in registry:
        if mac not in seen_now:
            registry[mac]["currently_seen"] = False

    save_registry(registry)
    return registry

def classify_host(mac):
    mac_norm = normalize_mac(mac)
    registry = sync_device_registry()
    quarantine_state = load_quarantine_state()
    info = registry.get(mac_norm) or {
        "label": "Unregistered Device",
        "role": "IoT / Unregistered",
        "owner": "Unregistered",
        "status": "Not Whitelisted",
        "currently_seen": False
    }

    quarantined = quarantine_state.get(mac_norm, {}).get("quarantined", False)

    if quarantined:
        return {
            "mac": mac_norm,
            "label": info.get("label", "Quarantined Device"),
            "role": "Quarantined",
            "owner": info.get("owner", "Unregistered"),
            "status": "Quarantined",
            "badge_class": "badge-quarantined",
            "trusted": False,
            "color": "#FF6600",        # bright orange — unmistakable
            "stroke": "#993300",
            "currently_seen": info.get("currently_seen", False)
        }

    role = info.get("role", "IoT / Unregistered")

    if role in ("Virtual Machine", "Approved VM"):
        return {
            "mac": mac_norm,
            "label": info.get("label", "Virtual Machine"),
            "role": "Virtual Machine",
            "owner": info.get("owner", "Lab"),
            "status": info.get("status", "Whitelisted"),
            "badge_class": "badge-vm",
            "trusted": True,
            "color": "#1565C0",
            "stroke": "#0D3A6E",
            "currently_seen": info.get("currently_seen", False)
        }
    elif role == "Approved IoT":
        return {
            "mac": mac_norm,
            "label": info.get("label", "Approved IoT"),
            "role": role,
            "owner": info.get("owner", "Lab"),
            "status": info.get("status", "Whitelisted"),
            "badge_class": "badge-approved-iot",
            "trusted": True,
            "color": "#00897B",        # teal/green
            "stroke": "#004D40",
            "currently_seen": info.get("currently_seen", False)
        }
    elif role == "Trusted / Non-IoT":
        return {
            "mac": mac_norm,
            "label": info.get("label", "Trusted Device"),
            "role": role,
            "owner": info.get("owner", "Unknown"),
            "status": info.get("status", "Whitelisted"),
            "badge_class": "badge-trusted",
            "trusted": True,
            "color": "#2E7D32",        # forest green
            "stroke": "#1B5E20",
            "currently_seen": info.get("currently_seen", False)
        }
    else:
        return {
            "mac": mac_norm,
            "label": info.get("label", "Unregistered Device"),
            "role": "IoT / Unregistered",
            "owner": info.get("owner", "Unregistered"),
            "status": info.get("status", "Not Whitelisted"),
            "badge_class": "badge-iot",
            "trusted": False,
            "color": "#C62828",        # deep crimson red
            "stroke": "#7B0000",
            "currently_seen": info.get("currently_seen", False)
        }

def render_switch_tabs(active=None, target="flows"):
    sws = get_switches()
    if not sws:
        return "<div class='card'>No switches detected.</div>"
    parts = []
    for s in sws:
        label = friendly_switch_name(str(s))
        cls = "switch-tab active" if str(s) == str(active) else "switch-tab"
        parts.append(f'<a class="{cls}" href="/{target}?dpid={s}">{label}</a>')
    return "".join(parts)


# -------------------------------------------------------------------
# APIs
# -------------------------------------------------------------------
@app.route("/api/topology")
def api_topology():
    quarantine_state = load_quarantine_state()
    stats_switches = get_switches()
    topo_switches = get_topology_switches()
    topo_links = get_topology_links()
    topo_hosts = get_topology_hosts()

    nodes = []
    edges = []

    if topo_switches:
        for sw in topo_switches:
            dpid = str(sw.get("dp", {}).get("id") or sw.get("dpid") or "unknown")
            nodes.append({"id": f"sw-{dpid}", "label": friendly_switch_name(dpid),
                          "type": "switch", "dpid": dpid, "color": "#0277BD", "stroke": "#01579B"})
    else:
        for sw in stats_switches:
            dpid = str(sw)
            nodes.append({"id": f"sw-{dpid}", "label": friendly_switch_name(dpid),
                          "type": "switch", "dpid": dpid, "color": "#0277BD", "stroke": "#01579B"})

    seen_links = set()
    for link in topo_links:
        src = link.get("src", {})
        dst = link.get("dst", {})
        src_id = str(src.get("dpid"))
        dst_id = str(dst.get("dpid"))
        if src_id and dst_id and src_id != "None" and dst_id != "None":
            key = tuple(sorted([src_id, dst_id]))
            if key not in seen_links:
                seen_links.add(key)
                edges.append({
                    "source": f"sw-{src_id}",
                    "target": f"sw-{dst_id}",
                    "label": f"{src.get('port_no','?')}↔{dst.get('port_no','?')}",
                    "type": "switch-link"
                })

    for host in topo_hosts:
        mac = normalize_mac(host.get("mac", ""))
        info = classify_host(mac)
        port = host.get("port", {})
        real_dpid = str(port.get("dpid", "unknown"))
        real_port_no = str(port.get("port_no", "unknown"))

        quarantined = quarantine_state.get(mac, {}).get("quarantined", False)
        display_dpid = real_dpid
        display_port = real_port_no

        if quarantined:
            qs = quarantine_state.get(mac, {})
            if qs.get("quarantine_switch"):
                display_dpid = str(qs["quarantine_switch"])
            if qs.get("quarantine_port"):
                display_port = str(qs["quarantine_port"])

        nodes.append({
            "id": f"host-{mac}",
            "label": info["label"],
            "type": "host",
            "mac": mac,
            "role": info["role"],
            "owner": info["owner"],
            "status": info["status"],
            "dpid": display_dpid,
            "real_dpid": real_dpid,
            "port_no": display_port,
            "real_port_no": real_port_no,
            "ipv4": host.get("ipv4", []),
            "ipv6": host.get("ipv6", []),
            "color": info["color"],
            "stroke": info.get("stroke", "#333"),
            "trusted": info["trusted"],
            "quarantined": quarantined
        })
        edges.append({
            "source": f"host-{mac}",
            "target": f"sw-{display_dpid}",
            "label": f"port {display_port}",
            "type": "host-link"
        })

    return jsonify({"nodes": nodes, "edges": edges})


# -------------------------------------------------------------------
# Pages
# -------------------------------------------------------------------
@app.route("/")
def home():
    sync_device_registry()
    switches = get_switches()
    topo_hosts = get_topology_hosts()

    trusted = iot = quarantined = vms = 0
    for h in topo_hosts:
        info = classify_host(h.get("mac", ""))
        if info["status"] == "Quarantined":
            quarantined += 1
        elif info["role"] == "Virtual Machine":
            vms += 1
        elif info["trusted"]:
            trusted += 1
        else:
            iot += 1

    html_content = f"""
    <div class='card'>
        <h2>Controller Overview</h2>
        <p><b>Detected Switches:</b> {len(switches)}</p>
        <p><b>Detected Hosts:</b> {len(topo_hosts)}</p>
        <p><b>Virtual Machines:</b> {vms}</p>
        <p><b>Whitelisted / Trusted Hosts:</b> {trusted}</p>
        <p><b>IoT / Unregistered Hosts:</b> {iot}</p>
        <p><b>Quarantined Hosts:</b> {quarantined}</p>
    </div>
    """
    html_content += render_switch_tabs()
    return page(html_content)


@app.route("/topology")
def topology():
    html_content = """
    <h2>Live Topology</h2>
    <div class="note">
        The graph polls automatically every 1.5 seconds. Click any node to inspect it and quarantine/approve from the panel.
        If a device disappears it means the VM stopped sending traffic or went offline.
    </div>

    <div class="legend">
        <div class="legend-item"><div class="legend-color" style="background:#0277BD;"></div> Switch</div>
        <div class="legend-item"><div class="legend-color" style="background:#1565C0;"></div> Virtual Machine</div>
        <div class="legend-item"><div class="legend-color" style="background:#2E7D32;"></div> Trusted / Non-IoT</div>
        <div class="legend-item"><div class="legend-color" style="background:#00897B;"></div> Approved IoT</div>
        <div class="legend-item"><div class="legend-color" style="background:#FF6600;"></div> Quarantined</div>
        <div class="legend-item"><div class="legend-color" style="background:#C62828;"></div> Unknown / Unregistered</div>
    </div>

    <div class="graph-wrap">
        <div class="graph-panel">
            <svg id="topology_svg" viewBox="0 0 2000 900" preserveAspectRatio="xMidYMid meet"></svg>
        </div>
        <div class="info-panel">
            <div class="info-box" id="node_info">
                <h3>Node Details</h3>
                <p>Click a switch or host in the topology graph.</p>
            </div>
        </div>
    </div>

    <script>
    // ── colour + shape constants ──────────────────────────────────────
    const NODE_R      = 32;   // host circle radius
    const SW_W        = 150;  // switch rect width
    const SW_H        = 56;   // switch rect height
    const TOP_Y       = 120;  // trusted/quarantined host row Y
    const SW_Y        = 450;  // switch row Y
    const BOT_Y_START = 620;  // first bottom host row Y
    const ROW_GAP     = 110;  // vertical gap between bottom rows
    const H_SPACING   = 200;  // horizontal spacing between hosts
    const COLS_PER_ROW = 7;   // max hosts per bottom row before wrapping

    async function loadTopology() {
        try {
            const res  = await fetch('/api/topology');
            const data = await res.json();
            const svg  = document.getElementById('topology_svg');
            const info = document.getElementById('node_info');
            svg.innerHTML = '';

            const nodes       = data.nodes || [];
            const edges       = data.edges || [];
            const switchNodes = nodes.filter(n => n.type === 'switch');
            const hostNodes   = nodes.filter(n => n.type === 'host');

            if (nodes.length === 0) {
                svg.innerHTML = '<text x="40" y="40" font-size="16">No topology data available.</text>';
                return;
            }

            // ── position switches evenly across canvas ────────────────
            const positions = {};
            const SW_COUNT  = Math.max(1, switchNodes.length);
            const CANVAS_W  = 2000;
            const SW_MARGIN = 200;  // padding from canvas edges
            const SW_STEP   = SW_COUNT === 1 ? 0
                                : (CANVAS_W - SW_MARGIN * 2) / (SW_COUNT - 1);
            const SW_START  = SW_COUNT === 1 ? CANVAS_W / 2 : SW_MARGIN;

            switchNodes.forEach((n, i) => {
                positions[n.id] = { x: Math.round(SW_START + i * SW_STEP), y: SW_Y };
            });

            // ── bucket hosts by parent switch + zone (top vs bottom) ──
            const topBySwitch = {};
            const botBySwitch = {};

            hostNodes.forEach(n => {
                const dpid = n.dpid || "unknown";
                const bucket = (n.trusted || n.quarantined) ? topBySwitch : botBySwitch;
                if (!bucket[dpid]) bucket[dpid] = [];
                bucket[dpid].push(n);
            });

            // ── place top hosts (trusted / quarantined) ───────────────
            Object.keys(topBySwitch).forEach(dpid => {
                const arr    = topBySwitch[dpid];
                const parent = positions['sw-' + dpid] || { x: 1000, y: SW_Y };
                const total  = arr.length;
                const startX = parent.x - ((total - 1) * H_SPACING) / 2;
                arr.forEach((node, idx) => {
                    positions[node.id] = { x: startX + idx * H_SPACING, y: TOP_Y };
                });
            });

            // ── place bottom hosts (unknown/IoT) with row-wrapping ────
            Object.keys(botBySwitch).forEach(dpid => {
                const arr    = botBySwitch[dpid];
                const parent = positions['sw-' + dpid] || { x: 1000, y: SW_Y };
                const total  = arr.length;
                const cols   = Math.min(total, COLS_PER_ROW);
                const rows   = Math.ceil(total / COLS_PER_ROW);

                arr.forEach((node, idx) => {
                    const row    = Math.floor(idx / COLS_PER_ROW);
                    const col    = idx % COLS_PER_ROW;
                    const rowLen = (row === rows - 1) ? (total - row * COLS_PER_ROW) : COLS_PER_ROW;
                    const rowStartX = parent.x - ((rowLen - 1) * H_SPACING) / 2;
                    positions[node.id] = {
                        x: rowStartX + col * H_SPACING,
                        y: BOT_Y_START + row * ROW_GAP
                    };
                });
            });

            // ── draw edges ────────────────────────────────────────────
            edges.forEach(edge => {
                const s = positions[edge.source];
                const t = positions[edge.target];
                if (!s || !t) return;

                const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('x1', s.x); line.setAttribute('y1', s.y);
                line.setAttribute('x2', t.x); line.setAttribute('y2', t.y);
                line.setAttribute('stroke', edge.type === 'switch-link' ? '#444' : '#999');
                line.setAttribute('stroke-width', edge.type === 'switch-link' ? '3' : '1.5');
                line.setAttribute('stroke-dasharray', edge.type === 'switch-link' ? 'none' : '5,3');
                svg.appendChild(line);

                // port label on edge midpoint
                const lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                lbl.setAttribute('x', (s.x + t.x) / 2 + 6);
                lbl.setAttribute('y', (s.y + t.y) / 2 - 6);
                lbl.setAttribute('text-anchor', 'middle');
                lbl.setAttribute('font-size', '10');
                lbl.setAttribute('fill', '#666');
                lbl.setAttribute('font-family', 'monospace');
                lbl.textContent = edge.label || '';
                svg.appendChild(lbl);
            });

            // ── draw nodes ────────────────────────────────────────────
            nodes.forEach(node => {
                const p = positions[node.id];
                if (!p) return;

                if (node.type === 'switch') {
                    // ── switch: rounded rectangle ─────────────────────
                    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                    rect.setAttribute('x', p.x - SW_W / 2);
                    rect.setAttribute('y', p.y - SW_H / 2);
                    rect.setAttribute('width', SW_W);
                    rect.setAttribute('height', SW_H);
                    rect.setAttribute('rx', 12);
                    rect.setAttribute('fill', node.color || '#0277BD');
                    rect.setAttribute('stroke', node.stroke || '#01579B');
                    rect.setAttribute('stroke-width', '3');
                    rect.style.cursor = 'pointer';
                    rect.style.filter = 'drop-shadow(0 3px 6px rgba(0,0,0,0.30))';
                    rect.addEventListener('click', () => showNodeInfo(node));
                    svg.appendChild(rect);

                    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    icon.setAttribute('x', p.x);
                    icon.setAttribute('y', p.y - 6);
                    icon.setAttribute('text-anchor', 'middle');
                    icon.setAttribute('font-size', '16');
                    icon.setAttribute('fill', 'white');
                    icon.textContent = '⇄';
                    svg.appendChild(icon);

                    const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    txt.setAttribute('x', p.x);
                    txt.setAttribute('y', p.y + 14);
                    txt.setAttribute('text-anchor', 'middle');
                    txt.setAttribute('font-size', '13');
                    txt.setAttribute('font-weight', 'bold');
                    txt.setAttribute('fill', 'white');
                    txt.setAttribute('font-family', 'Arial, sans-serif');
                    txt.textContent = node.label;
                    txt.style.cursor = 'pointer';
                    txt.addEventListener('click', () => showNodeInfo(node));
                    svg.appendChild(txt);

                } else {
                    // ── host: circle + label block below ─────────────
                    const isQ = node.quarantined;

                    // outer glow ring for quarantined
                    if (isQ) {
                        const glow = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                        glow.setAttribute('cx', p.x); glow.setAttribute('cy', p.y);
                        glow.setAttribute('r', NODE_R + 8);
                        glow.setAttribute('fill', 'none');
                        glow.setAttribute('stroke', '#FF6600');
                        glow.setAttribute('stroke-width', '3');
                        glow.setAttribute('stroke-dasharray', '6,3');
                        glow.setAttribute('opacity', '0.7');
                        svg.appendChild(glow);
                    }

                    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                    circle.setAttribute('cx', p.x); circle.setAttribute('cy', p.y);
                    circle.setAttribute('r', NODE_R);
                    circle.setAttribute('fill', node.color || '#C62828');
                    circle.setAttribute('stroke', node.stroke || '#333');
                    circle.setAttribute('stroke-width', '2.5');
                    circle.style.cursor = 'pointer';
                    circle.style.filter = 'drop-shadow(0 2px 5px rgba(0,0,0,0.25))';
                    circle.addEventListener('click', () => showNodeInfo(node));
                    svg.appendChild(circle);

                    // small role icon inside circle
                    const roleIcon = { 'Virtual Machine': '🖥', 'Approved IoT': '📡',
                                       'Trusted / Non-IoT': '✔', 'Quarantined': '🔒',
                                       'IoT / Unregistered': '?' }[node.role] || '?';
                    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    icon.setAttribute('x', p.x); icon.setAttribute('y', p.y + 7);
                    icon.setAttribute('text-anchor', 'middle');
                    icon.setAttribute('font-size', '18');
                    icon.setAttribute('fill', 'white');
                    icon.style.pointerEvents = 'none';
                    icon.textContent = roleIcon;
                    svg.appendChild(icon);

                    // device name label
                    const shortLabel = node.label.length > 20
                        ? node.label.substring(0, 20) + '…'
                        : node.label;
                    const nameLbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    nameLbl.setAttribute('x', p.x); nameLbl.setAttribute('y', p.y + NODE_R + 18);
                    nameLbl.setAttribute('text-anchor', 'middle');
                    nameLbl.setAttribute('font-size', '11');
                    nameLbl.setAttribute('font-weight', 'bold');
                    nameLbl.setAttribute('fill', '#111');
                    nameLbl.setAttribute('font-family', 'Arial, sans-serif');
                    nameLbl.style.pointerEvents = 'none';
                    nameLbl.textContent = shortLabel;
                    svg.appendChild(nameLbl);

                    // mac address label
                    const macLbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    macLbl.setAttribute('x', p.x); macLbl.setAttribute('y', p.y + NODE_R + 32);
                    macLbl.setAttribute('text-anchor', 'middle');
                    macLbl.setAttribute('font-size', '9');
                    macLbl.setAttribute('fill', '#555');
                    macLbl.setAttribute('font-family', 'monospace');
                    macLbl.style.pointerEvents = 'none';
                    macLbl.textContent = node.mac || '';
                    svg.appendChild(macLbl);
                }
            });

            // ── node detail panel ─────────────────────────────────────
            function showNodeInfo(node) {
                if (node.type === 'switch') {
                    info.innerHTML = `
                        <h3>Switch Details</h3>
                        <p><b>Name:</b> ${node.label}</p>
                        <p><b>DPID:</b> <code>${node.dpid}</code></p>
                        <p><a href="/flows?dpid=${node.dpid}">&#x1F4CB; View Flow Table</a></p>
                        <p><a href="/ports?dpid=${node.dpid}">&#x1F4CA; View Port Stats</a></p>
                    `;
                } else {
                    const ipv4 = (node.ipv4 && node.ipv4.length) ? node.ipv4.join(', ') : 'None';
                    const ipv6 = (node.ipv6 && node.ipv6.length) ? node.ipv6.join(', ') : 'None';

                    const statusColour = {
                        'Quarantined':     '#FF6600',
                        'Whitelisted':     '#2E7D32',
                        'Not Whitelisted': '#C62828'
                    }[node.status] || '#333';

                    let actionHtml = '';
                    if (node.quarantined) {
                        actionHtml = `
                            <form method="post" action="/unquarantineflow" style="margin-top:10px;">
                                <input type="hidden" name="dpid" value="${node.real_dpid || node.dpid}">
                                <input type="hidden" name="match" value='{"eth_src":"${node.mac}"}'>
                                <button class="unquarantine-btn" type="submit">&#x2705; Unquarantine Host</button>
                            </form>`;
                    } else {
                        actionHtml = `
                            <form method="post" action="/quarantineflow" style="margin-top:10px;">
                                <input type="hidden" name="dpid" value="${node.real_dpid || node.dpid}">
                                <input type="hidden" name="priority" value="100">
                                <input type="hidden" name="match" value='{"eth_src":"${node.mac}"}'>
                                <button class="quarantine-btn" type="submit">&#x1F512; Quarantine Host</button>
                            </form>`;
                        if (node.role === 'IoT / Unregistered') {
                            actionHtml += `
                            <form method="post" action="/approvehost" style="margin-top:8px;">
                                <input type="hidden" name="mac" value="${node.mac}">
                                <button class="approve-btn" type="submit">&#x1F4E1; Approve as IoT</button>
                            </form>
                            <form method="post" action="/approvevm" style="margin-top:8px;">
                                <input type="hidden" name="mac" value="${node.mac}">
                                <button style="background:#5b2d8e;color:white;border:none;padding:8px 12px;border-radius:4px;cursor:pointer;width:100%;" type="submit">&#x1F5A5; Approve as VM</button>
                            </form>`;
                        }
                    }

                    info.innerHTML = `
                        <h3>Host Details</h3>
                        <p><b>Name:</b> ${node.label}</p>
                        <p><b>MAC:</b> <code>${node.mac}</code></p>
                        <p><b>Role:</b> ${node.role}</p>
                        <p><b>Owner:</b> ${node.owner}</p>
                        <p><b>Status:</b> <span style="color:${statusColour};font-weight:bold;">${node.status}</span></p>
                        <p><b>IPv4:</b> ${ipv4}</p>
                        <p><b>IPv6:</b> ${ipv6}</p>
                        <p><b>Switch:</b> ${node.dpid}</p>
                        <p><b>Port:</b> ${node.port_no}</p>
                        ${actionHtml}
                    `;
                }
            }
        } catch (e) {
            document.getElementById('topology_svg').innerHTML =
                '<text x="40" y="40" font-size="16" fill="red">Topology query failed: ' + e.message + '</text>';
        }
    }

    loadTopology();
    setInterval(loadTopology, 1500);
    </script>
    """
    return page(html_content)


@app.route("/hosts")
def hosts():
    sync_device_registry()
    registry = load_registry()
    quarantine_state = load_quarantine_state()

    rows = ""
    for mac, entry in registry.items():
        info = classify_host(mac)
        dpid = entry.get("dpid", "unknown")
        port_no = entry.get("port_no", "unknown")
        currently_seen = entry.get("currently_seen", False)
        seen_text = "Online" if currently_seen else "Offline"

        badge = f"<span class='badge {info['badge_class']}'>{html.escape(info['role'])}</span>"

        if info["status"] == "Quarantined":
            control_html = f"""
            <form class="inline-form" method="post" action="/unquarantineflow">
                <input type="hidden" name="dpid" value="{dpid}">
                <input type="hidden" name="match" value='{html.escape(json.dumps({"eth_src": mac}))}'>
                <button type="submit" class="small-btn unquarantine-btn">Unquarantine</button>
            </form>"""
        elif info["role"] == "IoT / Unregistered":
            control_html = f"""
            <form class="inline-form" method="post" action="/quarantineflow">
                <input type="hidden" name="dpid" value="{dpid}">
                <input type="hidden" name="priority" value="100">
                <input type="hidden" name="match" value='{html.escape(json.dumps({"eth_src": mac}))}'>
                <button type="submit" class="small-btn quarantine-btn">Quarantine</button>
            </form>
            <form class="inline-form" method="post" action="/approvehost">
                <input type="hidden" name="mac" value="{mac}">
                <button type="submit" class="small-btn approve-btn">Approve IoT</button>
            </form>
            <form class="inline-form" method="post" action="/approvevm">
                <input type="hidden" name="mac" value="{mac}">
                <button type="submit" class="small-btn" style="background:#5b2d8e;">Approve VM</button>
            </form>"""
        else:
            control_html = f"""
            <form class="inline-form" method="post" action="/quarantineflow">
                <input type="hidden" name="dpid" value="{dpid}">
                <input type="hidden" name="priority" value="100">
                <input type="hidden" name="match" value='{html.escape(json.dumps({"eth_src": mac}))}'>
                <button type="submit" class="small-btn quarantine-btn">Quarantine</button>
            </form>"""

        rows += f"""
        <tr>
            <td>{html.escape(entry.get('label', 'Unknown'))}</td>
            <td>{html.escape(mac)}</td>
            <td>{badge}</td>
            <td>{html.escape(entry.get('owner', 'Unknown'))}</td>
            <td>{html.escape(friendly_switch_name(str(dpid)))}</td>
            <td>{html.escape(str(port_no))}</td>
            <td>{html.escape(seen_text)}</td>
            <td>{control_html}</td>
        </tr>"""

    html_content = """
    <h2>Host Discovery</h2>
    <div class='note'>
        Devices stay in the registry even after going offline.
        Unregistered devices can be approved as IoT directly from this page.
    </div>
    <table>
        <tr>
            <th>Device Name</th><th>MAC Address</th><th>Classification</th>
            <th>Owner</th><th>Switch</th><th>Port</th><th>Seen</th><th>Actions</th>
        </tr>
    """
    html_content += rows if rows else "<tr><td colspan='8'>No devices in registry.</td></tr>"
    html_content += "</table>"
    return page(html_content)


@app.route("/switches")
def switches_page():
    sws = get_switches()
    rows = "".join(
        f"<tr><td>{html.escape(friendly_switch_name(str(s)))}</td><td>{html.escape(str(s))}</td></tr>"
        for s in sws
    )
    html_content = "<h2>Switches</h2><table><tr><th>Name</th><th>DPID</th></tr>"
    html_content += rows if rows else "<tr><td colspan='2'>No switches found.</td></tr>"
    html_content += "</table>"
    return page(html_content)


@app.route("/flows")
def flows():
    sws = get_switches()
    if not sws:
        return page("<div class='card'><h2>Flow Table</h2><p>No switches detected.</p></div>")

    dpid = request.args.get("dpid", str(sws[0]))
    data = get_json(f"/stats/flow/{dpid}", {})
    flow_entries = data.get(str(dpid), []) if isinstance(data, dict) else []
    msg = request.args.get("msg", "")

    rows = ""
    for f in flow_entries:
        rows += f"""
        <tr>
            <td>{f.get('priority','')}</td>
            <td><pre>{html.escape(json.dumps(f.get('match',{}), indent=2))}</pre></td>
            <td>{f.get('packet_count','')}</td>
            <td>{f.get('byte_count','')}</td>
            <td><pre>{html.escape(json.dumps(f.get('actions',[]), indent=2))}</pre></td>
        </tr>"""

    html_content = f"<h2>Flow Table - {html.escape(friendly_switch_name(str(dpid)))}</h2>"
    if msg == "deleted":
        html_content += "<div class='msg'>Flow deleted.</div>"
    elif msg == "quarantined":
        html_content += "<div class='msg'>Quarantine rule installed.</div>"
    elif msg == "unquarantined":
        html_content += "<div class='msg'>Quarantine rule removed.</div>"

    html_content += render_switch_tabs(active=dpid, target="flows")
    html_content += """
    <table>
        <tr><th>Priority</th><th>Match</th><th>Packets</th><th>Bytes</th><th>Actions</th></tr>
    """
    html_content += rows if rows else "<tr><td colspan='5'>No flows found.</td></tr>"
    html_content += "</table>"
    return page(html_content)


@app.route("/ports")
def ports():
    sws = get_switches()
    if not sws:
        return page("<div class='card'><h2>Port Stats</h2><p>No switches detected.</p></div>")

    dpid = request.args.get("dpid", str(sws[0]))
    data = get_json(f"/stats/port/{dpid}", {})
    port_entries = data.get(str(dpid), []) if isinstance(data, dict) else []

    rows = ""
    for p in port_entries:
        rows += f"""
        <tr>
            <td>{p.get('port_no','')}</td>
            <td>{p.get('rx_packets','')}</td>
            <td>{p.get('tx_packets','')}</td>
            <td>{p.get('rx_bytes','')}</td>
            <td>{p.get('tx_bytes','')}</td>
        </tr>"""

    html_content = f"<h2>Port Stats - {html.escape(friendly_switch_name(str(dpid)))}</h2>"
    html_content += render_switch_tabs(active=dpid, target="ports")
    html_content += """
    <table>
        <tr><th>Port</th><th>RX Packets</th><th>TX Packets</th><th>RX Bytes</th><th>TX Bytes</th></tr>
    """
    html_content += rows if rows else "<tr><td colspan='5'>No port stats found.</td></tr>"
    html_content += "</table>"
    return page(html_content)


@app.route("/flowcontrol", methods=["GET", "POST"])
def flowcontrol():
    msg = err = ""
    sws = get_switches()
    dpid = sws[0] if sws else ""

    if request.method == "POST":
        try:
            payload = {
                "dpid": dpid_to_int(request.form["dpid"]),
                "priority": int(request.form["priority"]),
                "match": json.loads(request.form["match"]),
                "actions": json.loads(request.form["actions"])
            }
            msg = f"Flow add response: {post_json('/stats/flowentry/add', payload)}"
        except Exception as e:
            err = str(e)

    html_content = "<h2>Flow Control</h2>"
    if msg:
        html_content += f"<div class='msg'>{html.escape(msg)}</div>"
    if err:
        html_content += f"<div class='err'>{html.escape(err)}</div>"

    html_content += f"""
    <div class="card">
        <h3>Add Flow</h3>
        <form method="post">
            <label>DPID</label>
            <input name="dpid" value="{dpid}">
            <label>Priority</label>
            <input name="priority" value="100">
            <label>Match JSON</label>
            <textarea name="match">{{"in_port": 1}}</textarea>
            <label>Actions JSON</label>
            <textarea name="actions">[{{"type": "OUTPUT", "port": 2}}]</textarea>
            <button type="submit">Add Flow</button>
        </form>
    </div>"""
    return page(html_content)


@app.route("/quarantine")
def quarantine():
    return page("""
    <h2>Quarantine</h2>
    <div class='note'>
        Use one-click quarantine from the Topology or Host Discovery pages.
        This keeps the dashboard state consistent.
    </div>
    """)


# -------------------------------------------------------------------
# Actions
# -------------------------------------------------------------------
@app.route("/approvehost", methods=["POST"])
def approvehost():
    try:
        mac = normalize_mac(request.form["mac"])
        registry = load_registry()
        if mac in registry:
            registry[mac]["role"] = "Approved IoT"
            registry[mac]["status"] = "Whitelisted"
            save_registry(registry)
        return redirect(url_for("hosts"))
    except Exception as e:
        return page(f"<div class='err'>Approve failed: {html.escape(str(e))}</div>")


@app.route("/approvevm", methods=["POST"])
def approvevm():
    try:
        mac = normalize_mac(request.form["mac"])
        label = request.form.get("label", "").strip() or None
        registry = load_registry()
        if mac in registry:
            registry[mac]["role"] = "Virtual Machine"
            registry[mac]["status"] = "Whitelisted"
            if label:
                registry[mac]["label"] = label
            save_registry(registry)
        return redirect(url_for("hosts"))
    except Exception as e:
        return page(f"<div class='err'>Approve as VM failed: {html.escape(str(e))}</div>")


@app.route("/deleteflow", methods=["POST"])
def deleteflow():
    try:
        dpid_raw = request.form["dpid"]
        payload = {
            "dpid": dpid_to_int(dpid_raw),
            "priority": int(request.form["priority"]),
            "match": json.loads(request.form["match"])
        }
        post_json("/stats/flowentry/delete", payload)
        return redirect(url_for("flows", dpid=dpid_raw, msg="deleted"))
    except Exception as e:
        return page(f"<div class='err'>Delete failed: {html.escape(str(e))}</div>")


@app.route("/quarantineflow", methods=["GET", "POST"])
def quarantineflow():
    if request.method == "GET":
        return redirect(url_for("topology"))
    try:
        dpid_raw = str(request.form["dpid"])
        match = json.loads(request.form["match"])
        quarantine_priority = max(int(request.form.get("priority", "100")) + 100, 500)
        mac = normalize_mac(match.get("eth_src", ""))
        switch_ids = [str(s) for s in get_switches()]
        quarantine_switch = "00000000bada222" if "00000000bada222" in switch_ids else dpid_raw
        quarantine_port = QUARANTINE_PORTS.get(dpid_raw, 2)

        post_json("/stats/flowentry/add", {
            "dpid": dpid_to_int(dpid_raw),
            "priority": quarantine_priority,
            "match": match,
            "actions": [{"type": "OUTPUT", "port": quarantine_port}]
        })

        state = load_quarantine_state()
        state[mac] = {
            "quarantined": True,
            "real_switch": dpid_raw,
            "quarantine_switch": quarantine_switch,
            "quarantine_port": quarantine_port
        }
        save_quarantine_state(state)
        return redirect(url_for("topology"))
    except Exception as e:
        return page(f"<div class='err'>Quarantine failed: {html.escape(str(e))}</div>")


@app.route("/unquarantineflow", methods=["GET", "POST"])
def unquarantineflow():
    if request.method == "GET":
        return redirect(url_for("topology"))
    try:
        dpid_raw = str(request.form["dpid"])
        match = json.loads(request.form["match"])
        mac = normalize_mac(match.get("eth_src", ""))

        post_json("/stats/flowentry/delete", {
            "dpid": dpid_to_int(dpid_raw),
            "priority": 500,
            "match": match
        })

        state = load_quarantine_state()
        if mac in state:
            del state[mac]
        save_quarantine_state(state)
        return redirect(url_for("topology"))
    except Exception as e:
        return page(f"<div class='err'>Unquarantine failed: {html.escape(str(e))}</div>")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
