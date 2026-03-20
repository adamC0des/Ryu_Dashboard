from flask import Flask, request, redirect, url_for, jsonify
import requests
import json
import html

app = Flask(__name__)

RYU = "http://127.0.0.1:8080"
REFRESH_SECONDS = 10

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
    width: 220px;
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
.topology-wrap {{
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}}
.topology-box {{
    min-width: 260px;
    flex: 1;
    background: #fafafa;
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 16px;
}}
.node {{
    padding: 10px 12px;
    margin: 8px 0;
    border-radius: 6px;
    font-weight: bold;
}}
.node-switch {{
    background: #d8eced;
    border: 1px solid #7eb0b4;
}}
.node-host {{
    background: #f6e4cf;
    border: 1px solid #d2a56b;
}}
.link-row {{
    padding: 8px 0;
    border-bottom: 1px solid #eee;
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

    result = {
        "stats_switches": stats_switches,
        "topology_switches": topo_switches,
        "topology_links": topo_links,
        "topology_hosts": topo_hosts
    }
    return jsonify(result)

@app.route("/")
def home():
    sws = get_switches()
    html_content = "<div class='card'><h2>Controller Overview</h2>"
    html_content += f"<p><b>Detected Switches:</b> {len(sws)}</p>"
    html_content += "<p>Use the menu to inspect topology, flow tables, port stats, add/remove rules, or quarantine traffic.</p></div>"
    html_content += render_switch_tabs()
    return page(html_content)

@app.route("/topology")
def topology():
    html_content = """
    <h2>Live Topology</h2>
    <div class="note">
        This page polls the controller for topology data in real time.
        If Ryu exposes /v1.0/topology/*, you will see switches, links, and hosts.
        Otherwise, it will fall back to live switch detection from /stats/switches.
    </div>

    <div class="topology-wrap">
        <div class="topology-box">
            <h3>Switches</h3>
            <div id="switches_box">Loading...</div>
        </div>

        <div class="topology-box">
            <h3>Links</h3>
            <div id="links_box">Loading...</div>
        </div>

        <div class="topology-box">
            <h3>Hosts</h3>
            <div id="hosts_box">Loading...</div>
        </div>
    </div>

    <script>
    async function loadTopology() {
        try {
            const res = await fetch('/api/topology');
            const data = await res.json();

            const switchesBox = document.getElementById('switches_box');
            const linksBox = document.getElementById('links_box');
            const hostsBox = document.getElementById('hosts_box');

            let switchHtml = "";
            let linkHtml = "";
            let hostHtml = "";

            if (data.topology_switches && data.topology_switches.length > 0) {
                data.topology_switches.forEach(sw => {
                    const dpid = sw.dp.id || sw.dpid || JSON.stringify(sw);
                    switchHtml += `<div class="node node-switch">${dpid}</div>`;
                });
            } else if (data.stats_switches && data.stats_switches.length > 0) {
                data.stats_switches.forEach(sw => {
                    switchHtml += `<div class="node node-switch">DPID ${sw}</div>`;
                });
                switchHtml += `<div class="small">Using switch-only fallback from /stats/switches</div>`;
            } else {
                switchHtml = "No switches detected.";
            }

            if (data.topology_links && data.topology_links.length > 0) {
                data.topology_links.forEach(link => {
                    const src = link.src ? `${link.src.dpid}:${link.src.port_no}` : "unknown";
                    const dst = link.dst ? `${link.dst.dpid}:${link.dst.port_no}` : "unknown";
                    linkHtml += `<div class="link-row">${src} → ${dst}</div>`;
                });
            } else {
                linkHtml = "No live links detected.";
            }

            if (data.topology_hosts && data.topology_hosts.length > 0) {
                data.topology_hosts.forEach(host => {
                    const mac = host.mac || "unknown-mac";
                    const attach = host.port ? `${host.port.dpid}:${host.port.port_no}` : "unknown-port";
                    hostHtml += `<div class="node node-host">${mac}<br><span class="small">${attach}</span></div>`;
                });
            } else {
                hostHtml = "No hosts detected.";
            }

            switchesBox.innerHTML = switchHtml;
            linksBox.innerHTML = linkHtml;
            hostsBox.innerHTML = hostHtml;

        } catch (e) {
            document.getElementById('switches_box').innerHTML = "Topology query failed.";
            document.getElementById('links_box').innerHTML = "Topology query failed.";
            document.getElementById('hosts_box').innerHTML = "Topology query failed.";
        }
    }

    loadTopology();
    setInterval(loadTopology, 3000);
    </script>
    """
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
        Set the port to the interface connected to your quarantine environment.
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
