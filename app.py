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

# -------------------------------------------------------------------
# Friendly switch names
# -------------------------------------------------------------------
SWITCH_LABELS = {
    "00000000bada111": "Main Switch (10.10.10.x)",
    "00000000bada222": "Quarantine Switch (10.10.20.x)"
}

# -------------------------------------------------------------------
# Quarantine output port per switch
# -------------------------------------------------------------------
QUARANTINE_PORTS = {
    "00000000bada111": 2,
    "00000000bada222": 2
}

# -------------------------------------------------------------------
# Known devices
# -------------------------------------------------------------------
MAC_WHITELIST = {
    # --- Ryu Controller (RYU_10.10.0.3) ---
    "00:0c:29:41:b5:e3": {"label": "RYU_10.10.0.3", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:41:b5:ed": {"label": "RYU_10.10.0.3", "role": "Virtual Machine", "owner": "Lab"},

    # --- RYU_10.10.0.4 ---
    "00:0c:29:68:33:c1": {"label": "RYU_10.10.0.4", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:68:33:cb": {"label": "RYU_10.10.0.4", "role": "Virtual Machine", "owner": "Lab"},

    # --- OFSW_Remote ---
    "00:0c:29:bc:8d:5d": {"label": "OFSW_Remote", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:bc:8d:67": {"label": "OFSW_Remote", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:bc:8d:71": {"label": "OFSW_Remote", "role": "Virtual Machine", "owner": "Lab"},

    # --- Virtual_Router ---
    "00:0c:29:5c:1c:37": {"label": "Virtual_Router", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:5c:1c:41": {"label": "Virtual_Router", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:5c:1c:4b": {"label": "Virtual_Router", "role": "Virtual Machine", "owner": "Lab"},

    # --- Splunk_VM ---
    "00:0c:29:92:db:a4": {"label": "Splunk_VM", "role": "Virtual Machine", "owner": "Lab"},

    # --- Ai_IDS ---
    "00:0c:29:f1:4a:c3": {"label": "Ai_IDS", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:f1:4a:cd": {"label": "Ai_IDS", "role": "Virtual Machine", "owner": "Lab"},

    # --- xHosts ---
    "00:50:56:bc:2c:9a": {"label": "xHost_20.x1", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:7c:18:84": {"label": "xHost_20.x2", "role": "Virtual Machine", "owner": "Lab"},

    # --- DNSCAT2 ---
    "00:0c:29:0c:fc:b4": {"label": "DNSCAT2_server", "role": "Virtual Machine", "owner": "Lab"},
    "00:0c:29:3d:74:e7": {"label": "DNSCAT2_client", "role": "Virtual Machine", "owner": "Lab"},

    # --- Test IoT Device ---
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
button.quarantine-btn {{ background: #7a3eb1; }}
button.unquarantine-btn {{ background: #2e8b57; }}
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
.badge-trusted      {{ background: #dff3df; color: #216921; }}
.badge-iot          {{ background: #ffe2e2; color: #8a1f1f; }}
.badge-approved-iot {{ background: #efe3ff; color: #5b2a86; }}
.badge-quarantined  {{ background: #fce5ff; color: #6b1b78; }}
.badge-vm           {{ background: #ddeeff; color: #1a4a7a; }}
.graph-wrap {{
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}}
.graph-panel {{ flex: 2; min-width: 860px; }}
.info-panel  {{ flex: 1; min-width: 320px; }}
svg {{
    width: 100%;
    height: 760px;
    background: #fbfbfb;
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
    gap: 12px;
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
    padding: 8px 12px;
}}
.legend-color {{
    width: 16px;
    height: 16px;
    border-radius: 50%;
}}
</style>
</head>
<body>
<div class="header">
    <div>SDN Dashboard</div>
    <div>
        <a class="header-btn" href="javascript:window.location.reload()">⟳ Refresh</a>
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
            "color": "#7a3eb1",
            "currently_seen": info.get("currently_seen", False)
        }

    role = info.get("role", "IoT / Unregistered")

    if role == "Virtual Machine":
        return {
            "mac": mac_norm,
            "label": info.get("label", "Virtual Machine"),
            "role": role,
            "owner": info.get("owner", "Lab"),
            "status": info.get("status", "Whitelisted"),
            "badge_class": "badge-vm",
            "trusted": True,
            "color": "#2980b9",
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
            "color": "#9b59b6",
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
            "color": "#2ecc71",
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
            "color": "#e74c3c",
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
                          "type": "switch", "dpid": dpid, "color": "#3498db"})
    else:
        for sw in stats_switches:
            dpid = str(sw)
            nodes.append({"id": f"sw-{dpid}", "label": friendly_switch_name(dpid),
                          "type": "switch", "dpid": dpid, "color": "#3498db"})

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
        <div class="legend-item"><div class="legend-color" style="background:#3498db;"></div> Switch</div>
        <div class="legend-item"><div class="legend-color" style="background:#2980b9;"></div> Virtual Machine</div>
        <div class="legend-item"><div class="legend-color" style="background:#2ecc71;"></div> Trusted / Non-IoT</div>
        <div class="legend-item"><div class="legend-color" style="background:#9b59b6;"></div> Approved IoT</div>
        <div class="legend-item"><div class="legend-color" style="background:#7a3eb1;"></div> Quarantined</div>
        <div class="legend-item"><div class="legend-color" style="background:#e74c3c;"></div> Unknown / Unregistered</div>
    </div>

    <div class="graph-wrap">
        <div class="graph-panel">
            <svg id="topology_svg" viewBox="0 0 1600 760"></svg>
        </div>
        <div class="info-panel">
            <div class="info-box" id="node_info">
                <h3>Node Details</h3>
                <p>Click a switch or host in the topology graph.</p>
            </div>
        </div>
    </div>

    <script>
    async function loadTopology() {
        try {
            const res = await fetch('/api/topology');
            const data = await res.json();
            const svg = document.getElementById('topology_svg');
            const info = document.getElementById('node_info');
            svg.innerHTML = '';

            const nodes = data.nodes || [];
            const edges = data.edges || [];
            const switchNodes = nodes.filter(n => n.type === 'switch');
            const hostNodes = nodes.filter(n => n.type === 'host');

            if (nodes.length === 0) {
                svg.innerHTML = '<text x="40" y="40">No topology data available.</text>';
                return;
            }

            const positions = {};
            const centerY = 360;

            switchNodes.forEach((n, i) => {
                const total = Math.max(1, switchNodes.length);
                const spacing = total === 1 ? 0 : 700;
                const startX = total === 1 ? 800 : 450;
                positions[n.id] = { x: startX + i * spacing, y: centerY };
            });

            const topBySwitch = {};
            const bottomBySwitch = {};
            hostNodes.forEach(n => {
                const dpid = n.dpid || "unknown";
                if (n.trusted || n.quarantined) {
                    if (!topBySwitch[dpid]) topBySwitch[dpid] = [];
                    topBySwitch[dpid].push(n);
                } else {
                    if (!bottomBySwitch[dpid]) bottomBySwitch[dpid] = [];
                    bottomBySwitch[dpid].push(n);
                }
            });

            Object.keys(topBySwitch).forEach(dpid => {
                const arr = topBySwitch[dpid];
                const parent = positions['sw-' + dpid] || { x: 800, y: centerY };
                const startX = parent.x - ((arr.length - 1) * 240) / 2;
                arr.forEach((node, idx) => {
                    positions[node.id] = { x: startX + idx * 240, y: 140 };
                });
            });

            Object.keys(bottomBySwitch).forEach(dpid => {
                const arr = bottomBySwitch[dpid];
                const parent = positions['sw-' + dpid] || { x: 800, y: centerY };
                const startX = parent.x - ((arr.length - 1) * 260) / 2;
                arr.forEach((node, idx) => {
                    positions[node.id] = { x: startX + idx * 260, y: 610 };
                });
            });

            edges.forEach(edge => {
                if (!positions[edge.source] || !positions[edge.target]) return;
                const s = positions[edge.source];
                const t = positions[edge.target];
                const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('x1', s.x); line.setAttribute('y1', s.y);
                line.setAttribute('x2', t.x); line.setAttribute('y2', t.y);
                line.setAttribute('stroke', edge.type === 'switch-link' ? '#666' : '#aaa');
                line.setAttribute('stroke-width', edge.type === 'switch-link' ? '3' : '2');
                svg.appendChild(line);

                const lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                lbl.setAttribute('x', (s.x + t.x) / 2);
                lbl.setAttribute('y', (s.y + t.y) / 2 - 8);
                lbl.setAttribute('text-anchor', 'middle');
                lbl.setAttribute('font-size', '11');
                lbl.setAttribute('fill', '#555');
                lbl.textContent = edge.label || '';
                svg.appendChild(lbl);
            });

            nodes.forEach(node => {
                const p = positions[node.id];
                if (!p) return;

                if (node.type === 'switch') {
                    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                    rect.setAttribute('x', p.x - 70); rect.setAttribute('y', p.y - 34);
                    rect.setAttribute('width', 140); rect.setAttribute('height', 68);
                    rect.setAttribute('rx', 10);
                    rect.setAttribute('fill', node.color || '#3498db');
                    rect.setAttribute('stroke', '#1f4f73'); rect.setAttribute('stroke-width', '2');
                    rect.style.cursor = 'pointer';
                    rect.addEventListener('click', () => showNodeInfo(node));
                    svg.appendChild(rect);

                    const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    txt.setAttribute('x', p.x); txt.setAttribute('y', p.y + 6);
                    txt.setAttribute('text-anchor', 'middle');
                    txt.setAttribute('font-size', '12'); txt.setAttribute('font-weight', 'bold');
                    txt.setAttribute('fill', 'white');
                    txt.textContent = node.label;
                    svg.appendChild(txt);
                } else {
                    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                    circle.setAttribute('cx', p.x); circle.setAttribute('cy', p.y);
                    circle.setAttribute('r', 28);
                    circle.setAttribute('fill', node.color || '#e74c3c');
                    circle.setAttribute('stroke', '#333'); circle.setAttribute('stroke-width', '2');
                    circle.style.cursor = 'pointer';
                    circle.addEventListener('click', () => showNodeInfo(node));
                    svg.appendChild(circle);

                    const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    txt.setAttribute('x', p.x); txt.setAttribute('y', p.y + 54);
                    txt.setAttribute('text-anchor', 'middle');
                    txt.setAttribute('font-size', '11'); txt.setAttribute('font-weight', 'bold');
                    txt.setAttribute('fill', '#222');
                    txt.textContent = node.label.length > 22 ? node.label.substring(0, 22) + '...' : node.label;
                    svg.appendChild(txt);

                    const mac = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    mac.setAttribute('x', p.x); mac.setAttribute('y', p.y + 70);
                    mac.setAttribute('text-anchor', 'middle');
                    mac.setAttribute('font-size', '10'); mac.setAttribute('fill', '#555');
                    mac.textContent = node.mac || '';
                    svg.appendChild(mac);
                }
            });

            function showNodeInfo(node) {
                if (node.type === 'switch') {
                    info.innerHTML = `
                        <h3>Switch Details</h3>
                        <p><b>Name:</b> ${node.label}</p>
                        <p><b>DPID:</b> ${node.dpid}</p>
                        <p><a href="/flows?dpid=${node.dpid}">View Flow Table</a></p>
                        <p><a href="/ports?dpid=${node.dpid}">View Port Stats</a></p>
                    `;
                } else {
                    const ipv4 = (node.ipv4 && node.ipv4.length) ? node.ipv4.join(', ') : 'None';
                    const ipv6 = (node.ipv6 && node.ipv6.length) ? node.ipv6.join(', ') : 'None';

                    let actionHtml = '';
                    if (node.quarantined) {
                        actionHtml = `
                            <form method="post" action="/unquarantineflow">
                                <input type="hidden" name="dpid" value="${node.real_dpid || node.dpid}">
                                <input type="hidden" name="match" value='{"eth_src":"${node.mac}"}'>
                                <button class="unquarantine-btn" type="submit">Unquarantine Host</button>
                            </form>`;
                    } else {
                        actionHtml = `
                            <form method="post" action="/quarantineflow">
                                <input type="hidden" name="dpid" value="${node.real_dpid || node.dpid}">
                                <input type="hidden" name="priority" value="100">
                                <input type="hidden" name="match" value='{"eth_src":"${node.mac}"}'>
                                <button class="quarantine-btn" type="submit">Quarantine Host</button>
                            </form>`;
                        if (node.role === 'IoT / Unregistered') {
                            actionHtml += `
                            <form method="post" action="/approvehost" style="margin-top:8px;">
                                <input type="hidden" name="mac" value="${node.mac}">
                                <button class="approve-btn" type="submit">Approve as IoT</button>
                            </form>`;
                        }
                    }

                    info.innerHTML = `
                        <h3>Host Details</h3>
                        <p><b>Name:</b> ${node.label}</p>
                        <p><b>MAC:</b> ${node.mac}</p>
                        <p><b>Role:</b> ${node.role}</p>
                        <p><b>Owner:</b> ${node.owner}</p>
                        <p><b>Status:</b> ${node.status}</p>
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
                '<text x="40" y="40">Topology query failed.</text>';
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
                <button type="submit" class="small-btn approve-btn">Approve</button>
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
