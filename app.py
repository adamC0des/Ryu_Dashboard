from flask import Flask, request, redirect, url_for, jsonify
import requests
import json
import html

app = Flask(__name__)

RYU = "http://127.0.0.1:8080"
REFRESH_SECONDS = 10

# ============================================================
# MAC WHITELIST
# Add approved devices here.
# Unknown MACs will be treated as IoT / Unregistered.
# ============================================================
MAC_WHITELIST = {
    "00:00:00:00:00:01": {
        "label": "Engineering Laptop",
        "role": "Trusted / Non-IoT",
        "owner": "Admin"
    },
    "00:00:00:00:00:02": {
        "label": "Security Workstation",
        "role": "Trusted / Non-IoT",
        "owner": "SOC"
    }
}

DEFAULT_UNKNOWN_ROLE = "IoT / Unregistered"

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
    padding: 20px;
    font-size: 30px;
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
    min-height: calc(100vh - 70px);
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
.switch {{
    background: #d88e85;
    padding: 10px 16px;
    margin: 5px;
    display: inline-block;
    border-radius: 5px;
    text-decoration: none;
    color: #222;
    font-weight: bold;
}}
.switch.active {{
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
.graph-wrap {{
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}}
.graph-panel {{
    flex: 2;
    min-width: 700px;
}}
.info-panel {{
    flex: 1;
    min-width: 280px;
}}
svg {{
    width: 100%;
    height: 620px;
    background: #fbfbfb;
    border: 1px solid #ddd;
    border-radius: 8px;
}}
.node-label {{
    font-size: 12px;
    font-weight: bold;
    pointer-events: none;
}}
.info-box {{
    background: #fafafa;
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 16px;
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

def page(html_content: str) -> str:
    return BASE.replace("__CONTENT__", html_content)

def safe_json_dumps(obj) -> str:
    return html.escape(json.dumps(obj))

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

def normalize_mac(mac: str) -> str:
    return (mac or "").strip().lower()

def classify_host(mac: str):
    mac_norm = normalize_mac(mac)
    if mac_norm in MAC_WHITELIST:
        info = MAC_WHITELIST[mac_norm]
        role = info.get("role", "Trusted / Non-IoT")
        label = info.get("label", "Whitelisted Device")
        owner = info.get("owner", "Unknown")
        if role == "Approved IoT":
            badge_class = "badge-approved-iot"
            color = "#9b59b6"
        else:
            badge_class = "badge-trusted"
            color = "#2ecc71"
        return {
            "mac": mac_norm,
            "label": label,
            "role": role,
            "owner": owner,
            "status": "Whitelisted",
            "badge_class": badge_class,
            "trusted": True,
            "color": color
        }

    return {
        "mac": mac_norm,
        "label": "Unknown Device",
        "role": DEFAULT_UNKNOWN_ROLE,
        "owner": "Unregistered",
        "status": "Not Whitelisted",
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
        label = f"SW_{str(s)[-3:]}"
        cls = "switch active" if str(s) == str(active) else "switch"
        html_parts.append(f'<a class="{cls}" href="/{target}?dpid={s}">{label}</a>')
    return "".join(html_parts)

@app.route("/api/topology")
def api_topology():
    stats_switches = get_switches()
    topo_switches = get_topology_switches()
    topo_links = get_topology_links()
    topo_hosts = get_topology_hosts()

    nodes = []
    edges = []

    switch_ids = []

    if topo_switches:
        for sw in topo_switches:
            dpid = sw.get("dp", {}).get("id") or sw.get("dpid") or "unknown"
            switch_ids.append(str(dpid))
            nodes.append({
                "id": f"sw-{dpid}",
                "label": f"SW_{str(dpid)[-3:]}",
                "type": "switch",
                "dpid": str(dpid),
                "color": "#3498db"
            })
    else:
        for sw in stats_switches:
            switch_ids.append(str(sw))
            nodes.append({
                "id": f"sw-{sw}",
                "label": f"SW_{str(sw)[-3:]}",
                "type": "switch",
                "dpid": str(sw),
                "color": "#3498db"
            })

    for link in topo_links:
        src = link.get("src", {})
        dst = link.get("dst", {})
        src_id = src.get("dpid")
        dst_id = dst.get("dpid")
        if src_id and dst_id:
            edges.append({
                "source": f"sw-{src_id}",
                "target": f"sw-{dst_id}",
                "label": f"{src.get('port_no', '?')}→{dst.get('port_no', '?')}",
                "type": "switch-link"
            })

    for host in topo_hosts:
        mac = host.get("mac", "unknown-mac")
        info = classify_host(mac)
        port = host.get("port", {})
        dpid = port.get("dpid", "unknown")
        port_no = port.get("port_no", "unknown")

        nodes.append({
            "id": f"host-{mac}",
            "label": info["label"],
            "type": "host",
            "mac": mac,
            "role": info["role"],
            "owner": info["owner"],
            "status": info["status"],
            "dpid": str(dpid),
            "port_no": str(port_no),
            "color": info["color"],
            "trusted": info["trusted"]
        })

        edges.append({
            "source": f"host-{mac}",
            "target": f"sw-{dpid}",
            "label": f"port {port_no}",
            "type": "host-link"
        })

    return jsonify({
        "nodes": nodes,
        "edges": edges,
        "switches": topo_switches,
        "links": topo_links,
        "hosts": topo_hosts
    })

@app.route("/")
def home():
    sws = get_switches()
    topo_hosts = get_topology_hosts()
    classified = [classify_host(h.get("mac", "")) for h in topo_hosts]

    trusted_count = sum(1 for h in classified if h["trusted"])
    iot_count = sum(1 for h in classified if not h["trusted"])

    html_content = "<div class='card'><h2>Controller Overview</h2>"
    html_content += f"<p><b>Detected Switches:</b> {len(sws)}</p>"
    html_content += f"<p><b>Detected Hosts:</b> {len(topo_hosts)}</p>"
    html_content += f"<p><b>Whitelisted / Trusted Hosts:</b> {trusted_count}</p>"
    html_content += f"<p><b>IoT / Unregistered Hosts:</b> {iot_count}</p>"
    html_content += "<p>Use the topology graph to inspect devices by MAC, see where they are attached, and quarantine unknown endpoints.</p></div>"
    html_content += render_switch_tabs()
    return page(html_content)

@app.route("/topology")
def topology():
    html_content = """
    <h2>Live Topology</h2>
    <div class="note">
        Blue = switches. Green = trusted / whitelisted devices. Red = IoT / unregistered devices.
        Click any node to inspect it. Unknown hosts are ideal quarantine candidates.
    </div>

    <div class="graph-wrap">
        <div class="graph-panel">
            <svg id="topology_svg" viewBox="0 0 1200 620"></svg>
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
            const centerY = 280;

            // Lay out switches across the center
            switchNodes.forEach((n, i) => {
                const x = 250 + i * (700 / Math.max(1, switchNodes.length - 1 || 1));
                positions[n.id] = { x, y: centerY };
            });

            // Hosts above/below by trust status
            let trustedIndex = 0;
            let iotIndex = 0;

            hostNodes.forEach((n) => {
                const parentX = positions['sw-' + n.dpid] ? positions['sw-' + n.dpid].x : 600;

                if (n.trusted) {
                    positions[n.id] = {
                        x: parentX - 80 + (trustedIndex % 3) * 80,
                        y: 120 + Math.floor(trustedIndex / 3) * 70
                    };
                    trustedIndex++;
                } else {
                    positions[n.id] = {
                        x: parentX - 80 + (iotIndex % 3) * 80,
                        y: 430 + Math.floor(iotIndex / 3) * 70
                    };
                    iotIndex++;
                }
            });

            // Draw edges
            edges.forEach(edge => {
                if (!positions[edge.source] || !positions[edge.target]) return;

                const s = positions[edge.source];
                const t = positions[edge.target];

                const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('x1', s.x);
                line.setAttribute('y1', s.y);
                line.setAttribute('x2', t.x);
                line.setAttribute('y2', t.y);
                line.setAttribute('stroke', edge.type === 'switch-link' ? '#777' : '#aaa');
                line.setAttribute('stroke-width', edge.type === 'switch-link' ? '3' : '2');
                svg.appendChild(line);

                const tx = (s.x + t.x) / 2;
                const ty = (s.y + t.y) / 2 - 6;
                const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                label.setAttribute('x', tx);
                label.setAttribute('y', ty);
                label.setAttribute('text-anchor', 'middle');
                label.setAttribute('font-size', '11');
                label.textContent = edge.label || '';
                svg.appendChild(label);
            });

            // Draw nodes
            nodes.forEach(node => {
                const p = positions[node.id];
                if (!p) return;

                if (node.type === 'switch') {
                    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
                    rect.setAttribute('x', p.x - 42);
                    rect.setAttribute('y', p.y - 25);
                    rect.setAttribute('width', 84);
                    rect.setAttribute('height', 50);
                    rect.setAttribute('rx', 8);
                    rect.setAttribute('fill', node.color || '#3498db');
                    rect.setAttribute('stroke', '#1f4f73');
                    rect.setAttribute('stroke-width', '2');
                    rect.style.cursor = 'pointer';
                    rect.addEventListener('click', () => showNodeInfo(node));
                    svg.appendChild(rect);
                } else {
                    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                    circle.setAttribute('cx', p.x);
                    circle.setAttribute('cy', p.y);
                    circle.setAttribute('r', 24);
                    circle.setAttribute('fill', node.color || '#e74c3c');
                    circle.setAttribute('stroke', '#333');
                    circle.setAttribute('stroke-width', '2');
                    circle.style.cursor = 'pointer';
                    circle.addEventListener('click', () => showNodeInfo(node));
                    svg.appendChild(circle);
                }

                const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                text.setAttribute('x', p.x);
                text.setAttribute('y', p.y + (node.type === 'switch' ? 5 : 40));
                text.setAttribute('text-anchor', 'middle');
                text.setAttribute('class', 'node-label');
                text.textContent = node.label;
                svg.appendChild(text);
            });

            function showNodeInfo(node) {
                if (node.type === 'switch') {
                    info.innerHTML = `
                        <h3>Switch Details</h3>
                        <p><b>Label:</b> ${node.label}</p>
                        <p><b>DPID:</b> ${node.dpid}</p>
                        <p><a href="/flows?dpid=${node.dpid}">View Flow Table</a></p>
                        <p><a href="/ports?dpid=${node.dpid}">View Port Stats</a></p>
                    `;
                } else {
                    info.innerHTML = `
                        <h3>Host Details</h3>
                        <p><b>Label:</b> ${node.label}</p>
                        <p><b>MAC:</b> ${node.mac}</p>
                        <p><b>Role:</b> ${node.role}</p>
                        <p><b>Owner:</b> ${node.owner}</p>
                        <p><b>Status:</b> ${node.status}</p>
                        <p><b>Attached Switch:</b> ${node.dpid}</p>
                        <p><b>Port:</b> ${node.port_no}</p>

                        <form method="post" action="/quarantineflow">
                            <input type="hidden" name="dpid" value="${node.dpid}">
                            <input type="hidden" name="priority" value="100">
                            <input type="hidden" name="match" value='{"eth_src":"${node.mac}"}'>
                            <button class="quarantine-btn" type="submit">Quarantine Host</button>
                        </form>

                        <p style="margin-top:12px;"><a href="/flows?dpid=${node.dpid}">View Flow Table</a></p>
                    `;
                }
            }

        } catch (e) {
            const svg = document.getElementById('topology_svg');
            svg.innerHTML = '<text x="40" y="40">Topology query failed.</text>';
        }
    }

    loadTopology();
    setInterval(loadTopology, 3000);
    </script>
    """
    return page(html_content)

@app.route("/hosts")
def hosts():
    topo_hosts = get_topology_hosts()

    html_content = "<h2>Host Discovery</h2>"
    html_content += """
    <div class='note'>
        Hosts are identified by MAC address. If a MAC appears in the whitelist, it is labeled as approved.
        If not, it is classified as IoT / Unregistered.
    </div>
    """

    rows = ""
    for host in topo_hosts:
        host_mac = host.get("mac", "")
        port = host.get("port", {})
        info = classify_host(host_mac)

        dpid = port.get("dpid", "unknown")
        port_no = port.get("port_no", "unknown")

        badge = f"<span class='badge {info['badge_class']}'>{html.escape(info['role'])}</span>"

        rows += f"""
        <tr>
            <td>{html.escape(host_mac)}</td>
            <td>{html.escape(info['label'])}</td>
            <td>{badge}</td>
            <td>{html.escape(info['status'])}</td>
            <td>{html.escape(info['owner'])}</td>
            <td>{html.escape(str(dpid))}</td>
            <td>{html.escape(str(port_no))}</td>
        </tr>
        """

    html_content += """
    <table>
        <tr>
            <th>MAC Address</th>
            <th>Label</th>
            <th>Classification</th>
            <th>Whitelist Status</th>
            <th>Owner</th>
            <th>Switch DPID</th>
            <th>Port</th>
        </tr>
    """
    html_content += rows if rows else "<tr><td colspan='7'>No hosts detected.</td></tr>"
    html_content += "</table>"

    html_content += "<div class='card'><h3>Current MAC Whitelist</h3><pre>"
    html_content += html.escape(json.dumps(MAC_WHITELIST, indent=2))
    html_content += "</pre></div>"

    return page(html_content)

@app.route("/switches")
def switches_page():
    sws = get_switches()
    rows = "".join(f"<tr><td>{s}</td></tr>" for s in sws)
    html_content = """
    <h2>Switches</h2>
    <table>
        <tr><th>DPID</th></tr>
    """
    html_content += rows if rows else "<tr><td>No switches found.</td></tr>"
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

                <form class="inline-form" method="post" action="/quarantineflow">
                    <input type="hidden" name="dpid" value="{dpid}">
                    <input type="hidden" name="priority" value="{priority}">
                    <input type="hidden" name="match" value="{match_json}">
                    <button type="submit" class="quarantine-btn">Quarantine</button>
                </form>
            </td>
        </tr>
        """

    html_content = "<h2>Flow Table</h2>"
    if msg == "deleted":
        html_content += "<div class='msg'>Flow deleted.</div>"
    elif msg == "quarantined":
        html_content += "<div class='msg'>Quarantine rule installed.</div>"

    html_content += render_switch_tabs(active=dpid, target="flows")
    html_content += """
    <table>
        <tr>
            <th>Priority</th>
            <th>Match</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th>Actions</th>
            <th>Controls</th>
        </tr>
    """
    html_content += rows if rows else "<tr><td colspan='6'>No flows found.</td></tr>"
    html_content += "</table>"
    html_content += "<p class='small'>Delete removes the selected flow. Quarantine installs a higher-priority redirect rule for the same match.</p>"
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

    html_content = "<h2>Port Stats</h2>"
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
        Quarantine installs a higher-priority rule that redirects matching traffic to the quarantine port.
        Unknown / unregistered MAC devices discovered in Host Discovery are strong quarantine candidates.
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
        dpid = int(request.form["dpid"])
        match = json.loads(request.form["match"])
        original_priority = int(request.form.get("priority", "100"))
        quarantine_priority = max(original_priority + 100, 500)

        quarantine_port = 2

        payload = {
            "dpid": dpid,
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
        return redirect(url_for("flows", dpid=dpid, msg="quarantined"))
    except Exception as e:
        return page(f"<div class='err'>Quarantine failed: {html.escape(str(e))}</div>")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
