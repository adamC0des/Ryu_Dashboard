from flask import Flask, request
import requests
import json

app = Flask(__name__)

RYU = "http://127.0.0.1:8080"

BASE = """
<html>
<head>
<title>SDN Dashboard</title>
<meta http-equiv="refresh" content="10">
<style>
body {
    font-family: Arial, sans-serif;
    margin: 0;
    background: #f4f4f4;
}
.header {
    background: #2f6f73;
    color: white;
    padding: 20px;
    font-size: 30px;
    font-weight: bold;
}
.container {
    display: flex;
    min-height: calc(100vh - 70px);
}
.sidebar {
    width: 220px;
    background: #d88e85;
    padding: 15px;
}
.sidebar a {
    display: block;
    background: #b04733;
    color: white;
    padding: 12px;
    margin-bottom: 10px;
    text-decoration: none;
    border-radius: 6px;
    font-weight: bold;
}
.content {
    flex: 1;
    padding: 20px;
    background: white;
}
.switch {
    background: #d88e85;
    padding: 10px 16px;
    margin: 5px;
    display: inline-block;
    border-radius: 5px;
    text-decoration: none;
    color: #222;
    font-weight: bold;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}
th {
    background: #8d6b1f;
    color: white;
    padding: 10px;
}
td {
    border: 1px solid #ccc;
    padding: 8px;
    vertical-align: top;
}
button {
    background: #2f6f73;
    color: white;
    border: none;
    padding: 8px 12px;
    border-radius: 4px;
    cursor: pointer;
}
input, textarea {
    width: 100%;
    box-sizing: border-box;
    margin-bottom: 10px;
    padding: 8px;
}
.card {
    background: #fafafa;
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 18px;
    margin-bottom: 20px;
}
.msg {
    background: #eef7f7;
    border: 1px solid #c7e0e0;
    padding: 10px;
    border-radius: 6px;
    margin-bottom: 15px;
}
.err {
    background: #fff0f0;
    border: 1px solid #e0b5b5;
    padding: 10px;
    border-radius: 6px;
    margin-bottom: 15px;
}
pre {
    white-space: pre-wrap;
    word-break: break-word;
    margin: 0;
}
</style>
</head>
<body>
<div class="header">Flow Tables</div>
<div class="container">
    <div class="sidebar">
        <a href="/">Home</a>
        <a href="/flows">Flows</a>
        <a href="/ports">Ports</a>
        <a href="/flowcontrol">Flow Control</a>
        <a href="/switches">Switches</a>
    </div>
    <div class="content">
        __CONTENT__
    </div>
</div>
</body>
</html>
"""

def page(html: str) -> str:
    return BASE.replace("__CONTENT__", html)

def get_json(path: str, default):
    try:
        r = requests.get(RYU + path, timeout=3)
        r.raise_for_status()
        return r.json()
    except Exception:
        return default

def get_switches():
    data = get_json("/stats/switches", [])
    return data if isinstance(data, list) else []

def render_switch_tabs(active=None):
    sws = get_switches()
    if not sws:
        return "<div class='card'>No switches detected.</div>"
    html = []
    for s in sws:
        label = f"SW_{str(s)[-3:]}"
        style = " style='outline:3px solid #2f6f73;'" if str(s) == str(active) else ""
        html.append(f'<a class="switch"{style} href="/flows?dpid={s}">{label}</a>')
    return "".join(html)

@app.route("/")
def home():
    sws = get_switches()
    html = "<div class='card'><h2>Controller Overview</h2>"
    html += f"<p><b>Detected Switches:</b> {len(sws)}</p>"
    html += "<p>Use the menu to inspect flow tables, port stats, or add/remove rules.</p></div>"
    html += render_switch_tabs()
    return page(html)

@app.route("/flows")
def flows():
    sws = get_switches()
    if not sws:
        return page("<div class='card'><h2>Flow Table</h2><p>No switches detected.</p></div>")

    dpid = request.args.get("dpid", str(sws[0]))
    data = get_json(f"/stats/flow/{dpid}", {})
    flows = data.get(str(dpid), []) if isinstance(data, dict) else []

    rows = ""
    for f in flows:
        priority = f.get("priority", "")
        match = f.get("match", {})
        packets = f.get("packet_count", "")
        bytes_ = f.get("byte_count", "")
        actions = f.get("actions", [])
        rows += f"""
        <tr>
            <td>{priority}</td>
            <td><pre>{json.dumps(match, indent=2)}</pre></td>
            <td>{packets}</td>
            <td>{bytes_}</td>
            <td><pre>{json.dumps(actions, indent=2)}</pre></td>
        </tr>
        """

    html = "<h2>Flow Table</h2>"
    html += render_switch_tabs(active=dpid)
    html += """
    <table>
        <tr>
            <th>Priority</th>
            <th>Match</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th>Actions</th>
        </tr>
    """
    html += rows if rows else "<tr><td colspan='5'>No flows found.</td></tr>"
    html += "</table>"
    return page(html)

@app.route("/ports")
def ports():
    sws = get_switches()
    if not sws:
        return page("<div class='card'><h2>Port Stats</h2><p>No switches detected.</p></div>")

    dpid = request.args.get("dpid", str(sws[0]))
    data = get_json(f"/stats/port/{dpid}", {})
    ports = data.get(str(dpid), []) if isinstance(data, dict) else []

    rows = ""
    for p in ports:
        rows += f"""
        <tr>
            <td>{p.get('port_no', '')}</td>
            <td>{p.get('rx_packets', '')}</td>
            <td>{p.get('tx_packets', '')}</td>
            <td>{p.get('rx_bytes', '')}</td>
            <td>{p.get('tx_bytes', '')}</td>
        </tr>
        """

    html = "<h2>Port Stats</h2>"
    html += render_switch_tabs(active=dpid)
    html += """
    <table>
        <tr>
            <th>Port</th>
            <th>RX Packets</th>
            <th>TX Packets</th>
            <th>RX Bytes</th>
            <th>TX Bytes</th>
        </tr>
    """
    html += rows if rows else "<tr><td colspan='5'>No port stats found.</td></tr>"
    html += "</table>"
    return page(html)

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
            r = requests.post(RYU + "/stats/flowentry/add", json=payload, timeout=3)
            msg = f"Flow add response: {r.text}"
        except Exception as e:
            err = str(e)

    html = "<h2>Flow Control</h2>"
    if msg:
        html += f"<div class='msg'>{msg}</div>"
    if err:
        html += f"<div class='err'>{err}</div>"

    html += f"""
    <div class="card">
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
    return page(html)

@app.route("/switches")
def switches_page():
    sws = get_switches()
    rows = "".join(f"<tr><td>{s}</td></tr>" for s in sws)
    html = """
    <h2>Switches</h2>
    <table>
        <tr><th>DPID</th></tr>
    """
    html += rows if rows else "<tr><td>No switches found.</td></tr>"
    html += "</table>"
    return page(html)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
