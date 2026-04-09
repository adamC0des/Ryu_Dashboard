from flask import Flask, request, redirect, url_for, jsonify
import requests
import json
import html
import os

app = Flask(__name__)

RYU = "http://127.0.0.1:8080"
REFRESH_SECONDS = 5

DEVICE_REGISTRY_FILE = "device_registry.json"
QUARANTINE_STATE_FILE = "quarantine_state.json"

# -------------------------------------------------------------------
# Switch names
# Replace these with your exact DPIDs if needed
# -------------------------------------------------------------------
SWITCH_LABELS = {
    "0000000000000111": "Main Switch",
    "0000000000000222": "Quarantine Switch"
}

# -------------------------------------------------------------------
# Default quarantine destination port by switch DPID
# Change these to match your actual environment
# -------------------------------------------------------------------
QUARANTINE_PORTS = {
    "0000000000000111": 2,
    "0000000000000222": 2
}

# -------------------------------------------------------------------
# Optional known devices
# Any MAC not here will still get a friendly generated name
# -------------------------------------------------------------------
MAC_WHITELIST = {
    "00:00:00:00:00:01": {
        "label": "Trusted Laptop",
        "role": "Trusted / Non-IoT",
        "owner": "Admin"
    },
    "00:00:00:00:00:02": {
        "label": "Engineering Workstation",
        "role": "Trusted / Non-IoT",
        "owner": "Lab"
    },
    "00:00:00:00:00:03": {
        "label": "Approved IoT Camera",
        "role": "Approved IoT",
        "owner": "Lab"
    },
    "00:0c:29:16:37:b5": {
        "label": "IoT Test Device",
        "role": "Approved IoT",
        "owner": "Lab"
    }
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
.header-right {{
    display: flex;
    gap: 10px;
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
button.delete-btn {{
    background: #b33a3a;
}}
button.quarantine-btn {{
    background: #7a3eb1;
}}
button.unquarantine-btn {{
    background: #2e8b57;
}}
button.small-btn {{
    padding: 6px 10px;
    font-size: 12px;
}}
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
.inline-form {{
    display: inline-block;
    margin: 0;
}}
.small {{
    font-size: 12px;
    color: #555;
}}
.badge {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: bold;
}}
.badge-trusted {{
    background: #dff3df;
    color: #216921;
}}
.badge-iot {{
    background: #ffe2e2;
    color: #8a1f1f;
}}
.badge-approved-iot {{
    background: #efe3ff;
    color: #5b2a86;
}}
.badge-quarantined {{
    background: #fce5ff;
    color: #6b1b78;
}}
.graph-wrap {{
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}}
.graph-panel {{
    flex: 2;
    min-width: 860px;
}}
.info-panel {{
    flex: 1;
    min-width: 320px;
}}
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
    <div>Flow Tables</div>
    <div class="header-right">
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
# Persistence helpers
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
def page(html_content: str) -> str:
    return BASE.replace("__CONTENT__", html_content)


def safe_json_dumps(obj) -> str:
    return html.escape(json.dumps(obj))


def normalize_mac(mac: str) -> str:
    return (mac or "").strip().lower()


def friendly_switch_name(dpid: str) -> str:
    dpid = str(dpid)
    return SWITCH_LABELS.get(dpid, f"SW_{dpid[-3:]}")


def get_json(path: str, default):
    try:
        r = requests.get(RYU + path, timeout=3)
        r.raise_for_status()
        return r.json()
    except Exception:
        return default


def post_json(path: str, payload: dict):
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

    for host in topo_hosts:
        mac = normalize_mac(host.get("mac", ""))
        if not mac:
            continue

        port = host.get("port", {})
        dpid = str(port.get("dpid", "unknown"))
        port_no = str(port.get("port_no", "unknown"))
        ipv4 = host.get("ipv4", [])
        ipv6 = host.get("ipv6", [])

        if mac in MAC_WHITELIST:
            base = MAC_WHITELIST[mac]
            registry[mac] = {
                "label": base.get("label", "Known Device"),
                "role": base.get("role", "Trusted / Non-IoT"),
                "owner": base.get("owner", "Unknown"),
                "status": "Whitelisted",
                "dpid": dpid,
                "port_no": port_no,
                "ipv4": ipv4,
                "ipv6": ipv6
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
                    "ipv6": ipv6
                }
            else:
                registry[mac]["dpid"] = dpid
                registry[mac]["port_no"] = port_no
                registry[mac]["ipv4"] = ipv4
                registry[mac]["ipv6"] = ipv6

    save_registry(registry)
    return registry


def classify_host(mac: str):
    mac_norm = normalize_mac(mac)
    registry = sync_device_registry()
    quarantine_state = load_quarantine_state()

    info = registry.get(mac_norm)
    if not info:
        info = {
            "label": "Unregistered Device",
            "role": "IoT / Unregistered",
            "owner": "Unregistered",
            "status": "Not Whitelisted"
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
            "color": "#7a3eb1"
        }

    role = info.get("role", "IoT / Unregistered")
    if role == "Approved IoT":
        return {
            "mac": mac_norm,
            "label": info.get("label", "Approved IoT"),
            "role": role,
            "owner": info.get("owner", "Unknown"),
            "status": info.get("status", "Whitelisted"),
            "badge_class": "badge-approved-iot",
            "trusted": True,
            "color": "#9b59b6"
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
            "color": "#2ecc71"
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
            "color": "#e74c3c"
        }


def render_switch_tabs(active=None, target="flows"):
    sws = get_switches()
    if not sws:
        return "<div class='card'>No switches detected.</div>"

    html_parts = []
    for s in sws:
        label = friendly_switch_name(str(s))
        cls = "switch-tab active" if str(s) == str(active) else "switch-tab"
        html_parts.append(f'<a class="{cls}" href="/{target}?dpid={s}">{label}</a>')
    return "".join(html_parts)


# -------------------------------------------------------------------
# Live APIs
# -------------------------------------------------------------------
@app.route("/api/topology")
def api_topology():
    registry = sync_device_registry()
    quarantine_state = load_quarantine_state()

    stats_switches = get_switches()
    topo_switches = get_topology_switches()
    topo_links = get_topology_links()
    topo_hosts = get_topology_hosts()

    nodes = []
    edges = []

    switch_ids = set()

    if topo_switches:
        for sw in topo_switches:
            dpid = str(sw.get("dp", {}).get("id") or sw.get("dpid") or "unknown")
            switch_ids.add(dpid)
            nodes.append({
                "id": f"sw-{dpid}",
                "label": friendly_switch_name(dpid),
                "type": "switch",
                "dpid": dpid,
                "color": "#3498db"
            })
    else:
        for sw in stats_switches:
            dpid = str(sw)
            switch_ids.add(dpid)
            nodes.append({
                "id": f"sw-{dpid}",
                "label": friendly_switch_name(dpid),
                "type": "switch",
                "dpid": dpid,
                "color": "#3498db"
            })

    seen_switch_links = set()
    for link in topo_links:
        src = link.get("src", {})
        dst = link.get("dst", {})
        src_id = str(src.get("dpid"))
        dst_id = str(dst.get("dpid"))
        if src_id and dst_id and src_id != "None" and dst_id != "None":
            key = tuple(sorted([src_id, dst_id]))
            if key not in seen_switch_links:
                seen_switch_links.add(key)
                edges.append({
                    "source": f"sw-{src_id}",
                    "target": f"sw-{dst_id}",
                    "label": f"{src.get('port_no', '?')}↔{dst.get('port_no', '?')}",
                    "type": "switch-link"
                })

    for host in topo_hosts:
        mac = normalize_mac(host.get("mac", "unknown-mac"))
        info = classify_host(mac)

        port = host.get("port", {})
        real_dpid = str(port.get("dpid", "unknown"))
        real_port_no = str(port.get("port_no", "unknown"))

        quarantined = quarantine_state.get(mac, {}).get("quarantined", False)
        display_dpid = real_dpid
        display_port = real_port_no

        if quarantined:
            quarantine_switch = quarantine_state.get(mac, {}).get("quarantine_switch")
            quarantine_port = quarantine_state.get(mac, {}).get("quarantine_port")
            if quarantine_switch:
                display_dpid = str(quarantine_switch)
            if quarantine_port:
                display_port = str(quarantine_port)

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

    return jsonify({
        "nodes": nodes,
        "edges": edges,
        "switches": topo_switches,
        "links": topo_links,
        "hosts": topo_hosts
    })


@app.route("/api/summary")
def api_summary():
    registry = sync_device_registry()
    topo_hosts = get_topology_hosts()

    trusted_count = 0
    iot_count = 0
    quarantined_count = 0

    for host in topo_hosts:
        info = classify_host(host.get("mac", ""))
        if info["status"] == "Quarantined":
            quarantined_count += 1
        elif info["trusted"]:
            trusted_count += 1
        else:
            iot_count += 1

    return jsonify({
        "switch_count": len(get_switches()),
        "host_count": len(topo_hosts),
        "trusted_count": trusted_count,
        "iot_count": iot_count,
        "quarantined_count": quarantined_count
    })


# -------------------------------------------------------------------
# Pages
# -------------------------------------------------------------------
@app.route("/")
def home():
    html_content = """
    <div class='card'>
        <h2>Controller Overview</h2>
        <div id="summary_box">Loading summary...</div>
    </div>
    <div id="switch_tabs_box"></div>

    <script>
    async function loadSummary() {
        try {
            const res = await fetch('/api/summary');
            const data = await res.json();
            document.getElementById('summary_box').innerHTML = `
                <p><b>Detected Switches:</b> ${data.switch_count}</p>
                <p><b>Detected Hosts:</b> ${data.host_count}</p>
                <p><b>Whitelisted / Trusted Hosts:</b> ${data.trusted_count}</p>
                <p><b>IoT / Unregistered Hosts:</b> ${data.iot_count}</p>
                <p><b>Quarantined Hosts:</b> ${data.quarantined_count}</p>
                <p>Use the topology graph to inspect devices by MAC, see where they are attached, and quarantine unknown endpoints.</p>
            `;
        } catch (e) {
            document.getElementById('summary_box').innerHTML = 'Failed to load summary.';
        }
    }
    loadSummary();
    setInterval(loadSummary, 2000);
    </script>
    """
    html_content += render_switch_tabs()
    return page(html_content)


@app.route("/topology")
def topology():
    html_content = """
    <h2>Live Topology</h2>
    <div class="note">
        Blue = switches. Green = trusted / whitelisted devices. Purple = approved IoT or quarantined devices.
        Red = unknown / unregistered devices. Click any node to inspect it. Quarantine moves the host logically to the quarantine switch in the SDN view.
    </div>

    <div class="legend">
        <div class="legend-item"><div class="legend-color" style="background:#3498db;"></div> Switch</div>
        <div class="legend-item"><div class="legend-color" style="background:#2ecc71;"></div> Trusted / Non-IoT</div>
        <div class="legend-item"><div class="legend-color" style="background:#9b59b6;"></div> Approved IoT / Quarantined</div>
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

            if (nodes.length === 0) {
                svg.innerHTML = '<text x="40" y="40">No topology data available.</text>';
                return;
            }

            const switchNodes = nodes.filter(n => n.type === 'switch');
            const hostNodes = nodes.filter(n => n.type === 'host');

            const positions = {};
            const centerY = 360;

            // Spread switches much wider
            switchNodes.forEach((n, i) => {
                const total = Math.max(1, switchNodes.length);
                const spacing = total === 1 ? 0 : 700;
                const startX = total === 1 ? 800 : 450;
                positions[n.id] = {
                    x: startX + i * spacing,
                    y: centerY
                };
            });

            // Group hosts by switch and trust/quarantine status
            const trustedBySwitch = {};
            const iotBySwitch = {};

            hostNodes.forEach(n => {
                const dpid = n.dpid || "unknown";
                if (n.trusted || n.quarantined) {
                    if (!trustedBySwitch[dpid]) trustedBySwitch[dpid] = [];
                    trustedBySwitch[dpid].push(n);
                } else {
                    if (!iotBySwitch[dpid]) iotBySwitch[dpid] = [];
                    iotBySwitch[dpid].push(n);
                }
            });

            const trustedY = 140;
            const iotY = 610;

            Object.keys(trustedBySwitch).forEach(dpid => {
                const arr = trustedBySwitch[dpid];
                const parent = positions['sw-' + dpid] || { x: 800, y: centerY };
                const spacing = 240;
                const startX = parent.x - ((arr.length - 1) * spacing) / 2;

                arr.forEach((node, idx) => {
                    positions[node.id] = {
                        x: startX + idx * spacing,
                        y: trustedY
                    };
                });
            });

            Object.keys(iotBySwitch).forEach(dpid => {
                const arr = iotBySwitch[dpid];
                const parent = positions['sw-' + dpid] || { x: 800, y: centerY };
                const spacing = 260;
                const startX = parent.x - ((arr.length - 1) * spacing) / 2;

                arr.forEach((node, idx) => {
                    positions[node.id] = {
                        x: startX + idx * spacing,
                        y: iotY
                    };
                });
            });

            hostNodes.forEach((node, idx) => {
                if (!positions[node.id]) {
                    positions[node.id] = {
                        x: 120 + idx * 220,
                        y: node.trusted ? trustedY : iotY
                    };
                }
            });

            edges.forEach(edge => {
                if (!positions[edge.source] || !positions[edge.target]) return;

                const s = positions[edge.source];
                const t = positions[edge.target];

                const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('x1', s.x);
                line.setAttribute('y1', s.y);
                line.setAttribute('x2', t.x);
                line.setAttribute('y2', t.y);
                line.setAttribute('stroke', edge.type === 'switch-link' ? '#666' : '#aaa');
                line.setAttribute('stroke-width', edge.type === 'switch-link' ? '3' : '2');
                svg.appendChild(line);

                const tx = (s.x + t.x) / 2;
                const ty = (s.y + t.y) / 2 - 8;
                const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                label.setAttribute('x', tx);
                label.setAttribute('y', ty);
                label.setAttribute('text-anchor', 'middle');
                label.setAttribute('font-size', '11');
                label.setAttribute('fill', '#555');
                label.textContent = edge.label || '';
                svg.appendChild(label);
            });

            nodes.forEach(node => {
                const p = positions[node.id];
                if (!p) return;

                if (node.type === 'switch') {
                    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                    rect.setAttribute('x', p.x - 70);
                    rect.setAttribute('y', p.y - 34);
                    rect.setAttribute('width', 140);
                    rect.setAttribute('height', 68);
                    rect.setAttribute('rx', 10);
                    rect.setAttribute('fill', node.color || '#3498db');
                    rect.setAttribute('stroke', '#1f4f73');
                    rect.setAttribute('stroke-width', '2');
                    rect.style.cursor = 'pointer';
                    rect.addEventListener('click', () => showNodeInfo(node));
                    svg.appendChild(rect);

                    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    text.setAttribute('x', p.x);
                    text.setAttribute('y', p.y + 6);
                    text.setAttribute('text-anchor', 'middle');
                    text.setAttribute('font-size', '13');
                    text.setAttribute('font-weight', 'bold');
                    text.setAttribute('fill', 'white');
                    text.textContent = node.label;
                    svg.appendChild(text);
                } else {
                    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                    circle.setAttribute('cx', p.x);
                    circle.setAttribute('cy', p.y);
                    circle.setAttribute('r', 28);
                    circle.setAttribute('fill', node.color || '#e74c3c');
                    circle.setAttribute('stroke', '#333');
                    circle.setAttribute('stroke-width', '2');
                    circle.style.cursor = 'pointer';
                    circle.addEventListener('click', () => showNodeInfo(node));
                    svg.appendChild(circle);

                    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    text.setAttribute('x', p.x);
                    text.setAttribute('y', p.y + 54);
                    text.setAttribute('text-anchor', 'middle');
                    text.setAttribute('font-size', '12');
                    text.setAttribute('font-weight', 'bold');
                    text.setAttribute('fill', '#222');
                    text.textContent = node.label.length > 24 ? node.label.substring(0, 24) + '...' : node.label;
                    svg.appendChild(text);

                    const macText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                    macText.setAttribute('x', p.x);
                    macText.setAttribute('y', p.y + 72);
                    macText.setAttribute('text-anchor', 'middle');
                    macText.setAttribute('font-size', '10');
                    macText.setAttribute('fill', '#555');
                    macText.textContent = node.mac || '';
                    svg.appendChild(macText);
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

                    let actionButtons = `
                        <form method="post" action="/quarantineflow">
                            <input type="hidden" name="dpid" value="${node.real_dpid || node.dpid}">
                            <input type="hidden" name="priority" value="100">
                            <input type="hidden" name="match" value='{"eth_src":"${node.mac}"}'>
                            <button class="quarantine-btn" type="submit">Quarantine Host</button>
                        </form>
                    `;

                    if (node.quarantined) {
                        actionButtons = `
                            <form method="post" action="/unquarantineflow">
                                <input type="hidden" name="dpid" value="${node.real_dpid || node.dpid}">
                                <input type="hidden" name="match" value='{"eth_src":"${node.mac}"}'>
                                <button class="unquarantine-btn" type="submit">Unquarantine Host</button>
                            </form>
                        `;
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
                        <p><b>Displayed Switch:</b> ${node.dpid}</p>
                        <p><b>Displayed Port:</b> ${node.port_no}</p>
                        <p><b>Real Switch:</b> ${node.real_dpid || node.dpid}</p>
                        <p><b>Real Port:</b> ${node.real_port_no || node.port_no}</p>
                        ${actionButtons}
                        <p style="margin-top:12px;"><a href="/flows?dpid=${node.real_dpid || node.dpid}">View Flow Table</a></p>
                    `;
                }
            }

        } catch (e) {
            const svg = document.getElementById('topology_svg');
            svg.innerHTML = '<text x="40" y="40">Topology query failed.</text>';
        }
    }

    loadTopology();
    setInterval(loadTopology, 1500);
    </script>
    """
    return page(html_content)


@app.route("/hosts")
def hosts():
    registry = sync_device_registry()
    quarantine_state = load_quarantine_state()
    topo_hosts = get_topology_hosts()

    html_content = "<h2>Host Discovery</h2>"
    html_content += """
    <div class='note'>
        Devices are named automatically from the registry. Unknown devices get a stable friendly name instead of just showing 'Unregistered'.
        This page refreshes automatically.
    </div>
    """

    rows = ""
    for host in topo_hosts:
        host_mac = normalize_mac(host.get("mac", ""))
        port = host.get("port", {})
        info = classify_host(host_mac)

        dpid = str(port.get("dpid", "unknown"))
        port_no = str(port.get("port_no", "unknown"))
        quarantined = quarantine_state.get(host_mac, {}).get("quarantined", False)

        badge_class = info["badge_class"]
        badge_text = info["role"]
        if quarantined:
            badge_class = "badge-quarantined"
            badge_text = "Quarantined"

        badge = f"<span class='badge {badge_class}'>{html.escape(badge_text)}</span>"

        control_html = f"""
        <form class="inline-form" method="post" action="/quarantineflow">
            <input type="hidden" name="dpid" value="{dpid}">
            <input type="hidden" name="priority" value="100">
            <input type="hidden" name="match" value='{html.escape(json.dumps({"eth_src": host_mac}))}'>
            <button type="submit" class="small-btn quarantine-btn">Quarantine</button>
        </form>
        """

        if quarantined:
            control_html = f"""
            <form class="inline-form" method="post" action="/unquarantineflow">
                <input type="hidden" name="dpid" value="{dpid}">
                <input type="hidden" name="match" value='{html.escape(json.dumps({"eth_src": host_mac}))}'>
                <button type="submit" class="small-btn unquarantine-btn">Unquarantine</button>
            </form>
            """

        rows += f"""
        <tr>
            <td>{html.escape(info['label'])}</td>
            <td>{html.escape(host_mac)}</td>
            <td>{badge}</td>
            <td>{html.escape(info['owner'])}</td>
            <td>{html.escape(friendly_switch_name(dpid))}</td>
            <td>{html.escape(port_no)}</td>
            <td>{control_html}</td>
        </tr>
        """

    html_content += """
    <table>
        <tr>
            <th>Device Name</th>
            <th>MAC Address</th>
            <th>Classification</th>
            <th>Owner</th>
            <th>Switch</th>
            <th>Port</th>
            <th>Action</th>
        </tr>
    """
    html_content += rows if rows else "<tr><td colspan='7'>No hosts detected.</td></tr>"
    html_content += "</table>"

    return page(html_content)


@app.route("/switches")
def switches_page():
    sws = get_switches()
    rows = "".join(
        f"<tr><td>{html.escape(friendly_switch_name(str(s)))}</td><td>{html.escape(str(s))}</td></tr>"
        for s in sws
    )
    html_content = """
    <h2>Switches</h2>
    <table>
        <tr><th>Name</th><th>DPID</th></tr>
    """
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
        priority = f.get("priority", "")
        match = f.get("match", {})
        packets = f.get("packet_count", "")
        bytes_ = f.get("byte_count", "")
        actions = f.get("actions", [])

        match_json = safe_json_dumps(match)

        rows += f"""
        <tr>
            <td>{priority}</td>
            <td><pre>{html.escape(json.dumps(match, indent=2))}</pre></td>
            <td>{packets}</td>
            <td>{bytes_}</td>
            <td><pre>{html.escape(json.dumps(actions, indent=2))}</pre></td>
            <td>
                <form class="inline-form" method="post" action="/deleteflow">
                    <input type="hidden" name="dpid" value="{dpid}">
                    <input type="hidden" name="priority" value="{priority}">
                    <input type="hidden" name="match" value="{match_json}">
                    <button type="submit" class="delete-btn">Delete</button>
                </form>
            </td>
        </tr>
        """

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
        <tr>
            <th>Priority</th>
            <th>Match</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th>Actions</th>
            <th>Control</th>
        </tr>
    """
    html_content += rows if rows else "<tr><td colspan='6'>No flows found.</td></tr>"
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
            <td>{p.get('port_no', '')}</td>
            <td>{p.get('rx_packets', '')}</td>
            <td>{p.get('tx_packets', '')}</td>
            <td>{p.get('rx_bytes', '')}</td>
            <td>{p.get('tx_bytes', '')}</td>
        </tr>
        """

    html_content = f"<h2>Port Stats - {html.escape(friendly_switch_name(str(dpid)))}</h2>"
    html_content += render_switch_tabs(active=dpid, target="ports")
    html_content += """
    <table>
        <tr>
            <th>Port</th>
            <th>RX Packets</th>
            <th>TX Packets</th>
            <th>RX Bytes</th>
            <th>TX Bytes</th>
        </tr>
    """
    html_content += rows if rows else "<tr><td colspan='5'>No port stats found.</td></tr>"
    html_content += "</table>"
    return page(html_content)


@app.route("/flowcontrol", methods=["GET", "POST"])
def flowcontrol():
    msg = ""
    err = ""
    sws = get_switches()
    dpid = sws[0] if sws else ""

    if request.method == "POST":
        try:
            payload = {
                "dpid": int(request.form["dpid"]),
                "priority": int(request.form["priority"]),
                "match": json.loads(request.form["match"]),
                "actions": json.loads(request.form["actions"])
            }
            response_text = post_json("/stats/flowentry/add", payload)
            msg = f"Flow add response: {response_text}"
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
    </div>
    """
    return page(html_content)


@app.route("/quarantine", methods=["GET", "POST"])
def quarantine():
    msg = ""
    err = ""
    sws = get_switches()
    dpid = sws[0] if sws else ""

    if request.method == "POST":
        try:
            payload = {
                "dpid": int(request.form["dpid"]),
                "priority": int(request.form["priority"]),
                "match": json.loads(request.form["match"]),
                "actions": [
                    {
                        "type": "OUTPUT",
                        "port": int(request.form["quarantine_port"])
                    }
                ]
            }
            response_text = post_json("/stats/flowentry/add", payload)
            msg = f"Quarantine rule response: {response_text}"
        except Exception as e:
            err = str(e)

    html_content = "<h2>Quarantine Control</h2>"
    html_content += """
    <div class='note'>
        Normal use should be one-click quarantine from the topology or host discovery pages.
        This page is only for manual testing.
    </div>
    """
    if msg:
        html_content += f"<div class='msg'>{html.escape(msg)}</div>"
    if err:
        html_content += f"<div class='err'>{html.escape(err)}</div>"

    html_content += render_switch_tabs(active=dpid, target="quarantine")
    html_content += f"""
    <div class="card">
        <h3>Send Traffic to Quarantine Port</h3>
        <form method="post">
            <label>DPID</label>
            <input name="dpid" value="{dpid}">
            <label>Priority</label>
            <input name="priority" value="500">
            <label>Match JSON</label>
            <textarea name="match">{{"in_port": 1}}</textarea>
            <label>Quarantine Port</label>
            <input name="quarantine_port" value="2">
            <button type="submit" class="quarantine-btn">Apply Quarantine</button>
        </form>
    </div>
    """
    return page(html_content)


# -------------------------------------------------------------------
# Actions
# -------------------------------------------------------------------
@app.route("/deleteflow", methods=["POST"])
def deleteflow():
    try:
        dpid = int(request.form["dpid"])
        priority = int(request.form["priority"])
        match = json.loads(request.form["match"])

        payload = {
            "dpid": dpid,
            "priority": priority,
            "match": match
        }

        post_json("/stats/flowentry/delete", payload)
        return redirect(url_for("flows", dpid=dpid, msg="deleted"))
    except Exception as e:
        return page(f"<div class='err'>Delete failed: {html.escape(str(e))}</div>")


@app.route("/quarantineflow", methods=["POST"])
def quarantineflow():
    try:
        dpid = str(request.form["dpid"])
        match = json.loads(request.form["match"])
        original_priority = int(request.form.get("priority", "100"))
        quarantine_priority = max(original_priority + 100, 500)

        mac = normalize_mac(match.get("eth_src", ""))
        quarantine_switch = "0000000000000222" if "0000000000000222" in [str(s) for s in get_switches()] else dpid
        quarantine_port = QUARANTINE_PORTS.get(dpid, 2)

        payload = {
            "dpid": int(dpid),
            "priority": quarantine_priority,
            "match": match,
            "actions": [
                {
                    "type": "OUTPUT",
                    "port": quarantine_port
                }
            ]
        }

        post_json("/stats/flowentry/add", payload)

        state = load_quarantine_state()
        state[mac] = {
            "quarantined": True,
            "real_switch": dpid,
            "quarantine_switch": quarantine_switch,
            "quarantine_port": quarantine_port
        }
        save_quarantine_state(state)

        return redirect(url_for("topology"))
    except Exception as e:
        return page(f"<div class='err'>Quarantine failed: {html.escape(str(e))}</div>")


@app.route("/unquarantineflow", methods=["POST"])
def unquarantineflow():
    try:
        dpid = int(request.form["dpid"])
        match = json.loads(request.form["match"])
        mac = normalize_mac(match.get("eth_src", ""))

        # Best-effort delete of the quarantine flow
        payload = {
            "dpid": dpid,
            "priority": 500,
            "match": match
        }
        post_json("/stats/flowentry/delete", payload)

        state = load_quarantine_state()
        if mac in state:
            del state[mac]
            save_quarantine_state(state)

        return redirect(url_for("topology"))
    except Exception as e:
        return page(f"<div class='err'>Unquarantine failed: {html.escape(str(e))}</div>")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
