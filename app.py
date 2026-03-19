
import json
import os
from html import escape

import requests
from flask import Flask, redirect, render_template_string, request, url_for

app = Flask(__name__)

RYU = os.environ.get("RYU_BASE", "http://127.0.0.1:8080").rstrip("/")
REFRESH_SECONDS = int(os.environ.get("DASHBOARD_REFRESH", "10"))

BASE_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Ryu SDN Dashboard</title>
    <meta http-equiv="refresh" content="{{ refresh_seconds if auto_refresh else 999999 }}">
    <style>
        :root { --teal:#2f6f73; --teal-dark:#24595c; --rose-bg:#d88e85; --rose:#b04733; --rose-dark:#8f3525; --paper:#ffffff; --soft:#f4f4f4; --line:#d7d7d7; --text:#222; --muted:#666; --gold:#8d6b1f; --ok:#2d7d46; --warn:#946200; --bad:#9b2d2d; }
        * { box-sizing:border-box; }
        body { margin:0; font-family:Arial, Helvetica, sans-serif; background:var(--soft); color:var(--text); }
        .header { background:var(--teal); color:white; padding:18px 24px; font-size:34px; font-weight:bold; display:flex; align-items:center; justify-content:space-between; }
        .header small { font-size:14px; font-weight:normal; opacity:.9; }
        .container { display:flex; min-height:calc(100vh - 74px); }
        .sidebar { width:230px; background:#d39289; padding:18px 12px; }
        .sidebar a { display:block; background:var(--rose); color:white; text-decoration:none; margin-bottom:12px; padding:12px 14px; border-radius:6px; font-weight:bold; }
        .sidebar a.active, .sidebar a:hover { background:var(--rose-dark); }
        .content { flex:1; padding:24px; background:var(--paper); }
        .grid { display:grid; grid-template-columns:repeat(12, 1fr); gap:18px; }
        .col-12 { grid-column:span 12; } .col-8 { grid-column:span 8; } .col-6 { grid-column:span 6; } .col-4 { grid-column:span 4; }
        @media (max-width:980px) { .col-8,.col-6,.col-4 { grid-column:span 12; } .sidebar { width:185px; } }
        .card { background:#fafafa; border:1px solid var(--line); padding:18px; border-radius:10px; box-shadow:0 1px 1px rgba(0,0,0,.04); }
        .card h2, .card h3 { margin-top:0; }
        .switch-tabs { margin:8px 0 18px; display:flex; flex-wrap:wrap; gap:10px; }
        .switch-tabs a { display:inline-block; background:#d88e85; color:#222; text-decoration:none; padding:10px 18px; border-radius:6px; font-weight:bold; }
        .switch-tabs a.active { background:var(--rose-dark); color:white; }
        table { border-collapse:collapse; width:100%; margin-top:10px; }
        th, td { border:1px solid #cfcfcf; padding:10px; text-align:left; font-size:14px; vertical-align:top; }
        th { background:var(--gold); color:white; position:sticky; top:0; }
        .small { color:var(--muted); font-size:13px; }
        .mono { font-family:"Courier New", monospace; font-size:13px; word-break:break-word; }
        input, textarea, select { width:100%; padding:10px; margin-top:6px; margin-bottom:12px; box-sizing:border-box; border:1px solid #cfcfcf; border-radius:6px; background:white; }
        textarea { min-height:92px; resize:vertical; }
        button, .btn { background:var(--teal); color:white; border:none; padding:10px 16px; border-radius:6px; cursor:pointer; text-decoration:none; display:inline-block; font-weight:bold; }
        button:hover, .btn:hover { background:var(--teal-dark); }
        .btn-danger { background:var(--bad); } .btn-danger:hover { filter:brightness(.92); }
        .flash { background:#eef7ff; border:1px solid #b8d5f1; padding:12px 14px; border-radius:8px; margin-bottom:16px; }
        .pill { display:inline-block; padding:3px 8px; border-radius:999px; font-size:12px; font-weight:bold; background:#ececec; color:#333; }
        .pill.ok { background:#dff4e6; color:var(--ok); } .pill.warn { background:#fff3d1; color:var(--warn); } .pill.bad { background:#f7dfdf; color:var(--bad); }
        .topology-wrap { overflow:auto; background:white; }
        .node { fill:#f6f6f6; stroke:var(--teal); stroke-width:2; } .node-label { font-size:13px; font-weight:bold; fill:#333; } .link { stroke:#8d6b1f; stroke-width:3; } .link-label { font-size:12px; fill:#555; }
        .raw-box { background:#f0f0f0; padding:12px; overflow-x:auto; border-radius:8px; border:1px solid #ddd; }
        .section-title { margin:0 0 10px; font-size:28px; }
    </style>
</head>
<body>
    <div class="header"><div>Flow Tables</div><small>Ryu API: {{ ryu_base }}</small></div>
    <div class="container">
        <div class="sidebar">
            <a class="{{ 'active' if active_nav == 'home' else '' }}" href="{{ url_for('home') }}">Home</a>
            <a class="{{ 'active' if active_nav == 'flows' else '' }}" href="{{ url_for('flows') }}">Flows</a>
            <a class="{{ 'active' if active_nav == 'groups' else '' }}" href="{{ url_for('groups') }}">Groups</a>
            <a class="{{ 'active' if active_nav == 'meters' else '' }}" href="{{ url_for('meters') }}">Meters</a>
            <a class="{{ 'active' if active_nav == 'flow_control' else '' }}" href="{{ url_for('flow_control') }}">Flow Control</a>
            <a class="{{ 'active' if active_nav == 'quarantine' else '' }}" href="{{ url_for('quarantine') }}">Quarantine</a>
            <a class="{{ 'active' if active_nav == 'topology' else '' }}" href="{{ url_for('topology') }}">Topology</a>
            <a class="{{ 'active' if active_nav == 'ports' else '' }}" href="{{ url_for('ports') }}">Port Stats</a>
            <a class="{{ 'active' if active_nav == 'switches' else '' }}" href="{{ url_for('switches') }}">Switches</a>
            <a class="{{ 'active' if active_nav == 'messages' else '' }}" href="{{ url_for('messages') }}">Messages</a>
            <a class="{{ 'active' if active_nav == 'configuration' else '' }}" href="{{ url_for('configuration') }}">Configuration</a>
            <a class="{{ 'active' if active_nav == 'about' else '' }}" href="{{ url_for('about') }}">About</a>
        </div>
        <div class="content">
            {% if flash %}<div class="flash">{{ flash|safe }}</div>{% endif %}
            {{ content|safe }}
        </div>
    </div>
</body>
</html>
"""

def ryu_get(path):
    try:
        r = requests.get(f"{RYU}{path}", timeout=3)
        r.raise_for_status()
        if r.text:
            return r.json(), None
        return {}, None
    except Exception as e:
        return None, str(e)

def ryu_post(path, payload):
    try:
        r = requests.post(f"{RYU}{path}", json=payload, timeout=3)
        return r.text or "OK", None
    except Exception as e:
        return None, str(e)

def get_switches():
    data, _ = ryu_get("/stats/switches")
    return data or []

def safe_json(value):
    return escape(json.dumps(value, indent=2, sort_keys=True))

def pretty_switch_name(sw):
    s = str(sw)
    return f"SW_{s[-3:]}" if len(s) >= 3 else f"SW_{s}"

def switch_tabs(active=None, route_name="flows"):
    sws = get_switches()
    if not sws:
        return '<p class="small">No switches detected yet.</p>'
    html = ['<div class="switch-tabs">']
    for sw in sws:
        cls = "active" if str(sw) == str(active) else ""
        html.append(f'<a class="{cls}" href="{url_for(route_name)}?dpid={sw}">{pretty_switch_name(sw)}</a>')
    html.append("</div>")
    return "".join(html)

def layout_topology(switches, links):
    nodes = [{"id": str(sw), "label": pretty_switch_name(sw)} for sw in switches]
    count = len(nodes)
    if count == 0:
        return ""
    if count == 1:
        nodes[0].update({"x": 300, "y": 140})
    else:
        import math
        cx, cy, r = 320, 180, 110 + max(0, count - 4) * 18
        for idx, n in enumerate(nodes):
            theta = (2 * math.pi * idx / count) - math.pi / 2
            n["x"] = cx + r * math.cos(theta)
            n["y"] = cy + r * math.sin(theta)
    node_map = {n["id"]: n for n in nodes}
    svg = ['<svg width="700" height="380" viewBox="0 0 700 380">']
    for l in links:
        src = str(l.get("src", {}).get("dpid", ""))
        dst = str(l.get("dst", {}).get("dpid", ""))
        if src in node_map and dst in node_map:
            a, b = node_map[src], node_map[dst]
            svg.append(f'<line class="link" x1="{a["x"]}" y1="{a["y"]}" x2="{b["x"]}" y2="{b["y"]}"></line>')
    for n in nodes:
        x, y = n["x"], n["y"]
        svg.append(f'<rect class="node" x="{x-48}" y="{y-28}" width="96" height="56" rx="8"></rect>')
        svg.append(f'<text class="node-label" x="{x}" y="{y-2}" text-anchor="middle">{escape(n["label"])}</text>')
        svg.append(f'<text class="link-label" x="{x}" y="{y+16}" text-anchor="middle">{escape(n["id"][-6:])}</text>')
    svg.append("</svg>")
    return "".join(svg)

def render_page(content, active_nav, flash="", auto_refresh=False):
    return render_template_string(BASE_HTML, content=content, active_nav=active_nav, flash=flash, auto_refresh=auto_refresh, refresh_seconds=REFRESH_SECONDS, ryu_base=RYU)

@app.route("/")
def home():
    sws = get_switches()
    links, _ = ryu_get("/v1.0/topology/links")
    links = links or []
    content = f'''
    <div class="grid">
        <div class="card col-8">
            <h2>Controller Overview</h2>
            <p><b>Detected Switches:</b> {len(sws)}</p>
            <p><b>Detected Links:</b> {len(links)}</p>
            <p class="small">Every page pulls fresh state from the Ryu REST API, so rerunning the dashboard or changing the environment will reflect new switches and devices without hard-coded values.</p>
        </div>
        <div class="card col-4">
            <h3>Quick Actions</h3>
            <p><a class="btn" href="{url_for('flows')}">Open Flow Tables</a></p>
            <p><a class="btn" href="{url_for('flow_control')}">Add / Delete Flow</a></p>
            <p><a class="btn" href="{url_for('quarantine')}">Quarantine Device</a></p>
        </div>
        <div class="col-12">{switch_tabs(route_name='flows')}</div>
    </div>'''
    return render_page(content, "home", auto_refresh=True)

@app.route("/switches")
def switches():
    sws = get_switches()
    rows = "".join(f"<tr><td>{i+1}</td><td>{pretty_switch_name(sw)}</td><td class='mono'>{sw}</td></tr>" for i, sw in enumerate(sws))
    content = f'''<h2 class="section-title">Switches</h2>
    <table><tr><th>#</th><th>Name</th><th>DPID</th></tr>
    {rows if rows else '<tr><td colspan="3">No switches found.</td></tr>'}
    </table>'''
    return render_page(content, "switches", auto_refresh=True)

@app.route("/flows")
def flows():
    sws = get_switches()
    if not sws:
        return render_page("<h2>Flow Tables</h2><p>No switches found.</p>", "flows", auto_refresh=True)
    dpid = request.args.get("dpid") or str(sws[0])
    data, err = ryu_get(f"/stats/flow/{dpid}")
    if err:
        return render_page(f"<h2>Flow Tables</h2><p>Error: {escape(err)}</p>", "flows", auto_refresh=True)
    flows = data.get(str(dpid), [])
    rows = ""
    for flow in flows:
        priority = flow.get("priority", "")
        match = "<br>".join(f"{escape(str(k))} = {escape(str(v))}" for k, v in flow.get("match", {}).items()) or "-"
        cookie = flow.get("cookie", "")
        duration = flow.get("duration_sec", "")
        packet_count = flow.get("packet_count", "")
        byte_count = flow.get("byte_count", "")
        actions = flow.get("actions", [])
        actions_str = "<br>".join(escape(str(a)) for a in actions) if actions else "-"
        match_json = escape(json.dumps(flow.get("match", {})))
        rows += f'''<tr>
            <td>{priority}</td><td>{match}</td><td>{cookie}</td><td>{duration}</td>
            <td>{packet_count}</td><td>{byte_count}</td><td>{actions_str}</td>
            <td><form method="post" action="{url_for('delete_flow_inline')}" style="margin:0">
                <input type="hidden" name="dpid" value="{escape(str(dpid))}">
                <input type="hidden" name="priority" value="{escape(str(priority))}">
                <input type="hidden" name="match" value="{match_json}">
                <button class="btn btn-danger" type="submit">Delete</button>
            </form></td>
        </tr>'''
    content = f'''<h2 class="section-title">Flow Table</h2>
    {switch_tabs(active=dpid, route_name='flows')}
    <table>
        <tr><th>Priority</th><th>Match Fields</th><th>Cookie</th><th>Duration</th><th>Packets</th><th>Bytes</th><th>Actions</th><th>Control</th></tr>
        {rows if rows else '<tr><td colspan="8">No flows found.</td></tr>'}
    </table>'''
    return render_page(content, "flows", flash=request.args.get("flash",""), auto_refresh=True)

@app.route("/flow-control", methods=["GET", "POST"])
def flow_control():
    sws = get_switches()
    default_dpid = sws[0] if sws else ""
    flash = ""
    if request.method == "POST":
        try:
            dpid = int(request.form["dpid"])
            priority = int(request.form["priority"])
            match = json.loads(request.form["match"] or "{}")
            if request.form.get("mode") == "add":
                actions = json.loads(request.form["actions"] or "[]")
                payload = {"dpid": dpid, "priority": priority, "match": match, "actions": actions}
                resp, err = ryu_post("/stats/flowentry/add", payload)
                flash = f"<b>Add Flow Response:</b> {escape(resp) if resp else escape(err)}"
            else:
                payload = {"dpid": dpid, "priority": priority, "match": match}
                resp, err = ryu_post("/stats/flowentry/delete", payload)
                flash = f"<b>Delete Flow Response:</b> {escape(resp) if resp else escape(err)}"
        except Exception as e:
            flash = f"<b>Error:</b> {escape(str(e))}"
    content = f'''<h2 class="section-title">Flow Control</h2>
    <div class="grid">
        <div class="card col-6">
            <h3>Add Flow</h3>
            <form method="post">
                <input type="hidden" name="mode" value="add">
                <label>DPID</label><input name="dpid" value="{default_dpid}">
                <label>Priority</label><input name="priority" value="100">
                <label>Match JSON</label><textarea name="match">{{"in_port": 1}}</textarea>
                <label>Actions JSON</label><textarea name="actions">[{{"type": "OUTPUT", "port": 2}}]</textarea>
                <button type="submit">Add Flow</button>
            </form>
        </div>
        <div class="card col-6">
            <h3>Delete Flow</h3>
            <form method="post">
                <input type="hidden" name="mode" value="delete">
                <label>DPID</label><input name="dpid" value="{default_dpid}">
                <label>Priority</label><input name="priority" value="100">
                <label>Match JSON</label><textarea name="match">{{"in_port": 1}}</textarea>
                <button class="btn btn-danger" type="submit">Delete Flow</button>
            </form>
        </div>
    </div>'''
    return render_page(content, "flow_control", flash=flash)

@app.route("/flow-delete-inline", methods=["POST"])
def delete_flow_inline():
    try:
        payload = {"dpid": int(request.form["dpid"]), "priority": int(request.form["priority"]), "match": json.loads(request.form["match"] or "{}")}
        resp, err = ryu_post("/stats/flowentry/delete", payload)
        msg = f"Delete flow response: {resp if resp else err}"
    except Exception as e:
        msg = f"Delete flow error: {e}"
    return redirect(url_for("flows", dpid=request.form.get("dpid"), flash=msg))

@app.route("/ports")
def ports():
    sws = get_switches()
    if not sws:
        return render_page("<h2>Port Stats</h2><p>No switches found.</p>", "ports", auto_refresh=True)
    dpid = request.args.get("dpid") or str(sws[0])
    data, err = ryu_get(f"/stats/port/{dpid}")
    if err:
        return render_page(f"<h2>Port Stats</h2><p>Error: {escape(err)}</p>", "ports", auto_refresh=True)
    stats = data.get(str(dpid), [])
    rows = ""
    for p in stats:
        rows += f"<tr><td>{p.get('port_no','')}</td><td>{p.get('rx_packets','')}</td><td>{p.get('tx_packets','')}</td><td>{p.get('rx_bytes','')}</td><td>{p.get('tx_bytes','')}</td><td>{p.get('rx_errors','')}</td><td>{p.get('tx_errors','')}</td></tr>"
    content = f'''<h2 class="section-title">Port Statistics</h2>
    {switch_tabs(active=dpid, route_name='ports')}
    <table><tr><th>Port</th><th>RX Packets</th><th>TX Packets</th><th>RX Bytes</th><th>TX Bytes</th><th>RX Errors</th><th>TX Errors</th></tr>
    {rows if rows else '<tr><td colspan="7">No stats found.</td></tr>'}
    </table>'''
    return render_page(content, "ports", auto_refresh=True)

@app.route("/topology")
def topology():
    sws = get_switches()
    links, links_err = ryu_get("/v1.0/topology/links")
    switches_raw, sw_err = ryu_get("/v1.0/topology/switches")
    links = links or []
    topo_sws = [str(s.get("dpid", "")) for s in switches_raw] if switches_raw else [str(sw) for sw in sws]
    graph = layout_topology(topo_sws, links)
    note = ""
    if links_err or sw_err:
        note = "<p class='small'>Topology REST endpoints are not available in the current Ryu mode. The dashboard is showing switches only. To enable link discovery, you would need a Ryu topology app that exposes /v1.0/topology/*.</p>"
    content = f'''<h2 class="section-title">Topology</h2><div class="card topology-wrap">{graph if graph else '<p>No topology data available.</p>'}</div>{note}'''
    return render_page(content, "topology", auto_refresh=True)

@app.route("/groups")
def groups():
    sws = get_switches()
    if not sws:
        return render_page("<h2>Groups</h2><p>No switches found.</p>", "groups", auto_refresh=True)
    dpid = request.args.get("dpid") or str(sws[0])
    data, err = ryu_get(f"/stats/groupdesc/{dpid}")
    if err:
        content = f"<h2 class='section-title'>Groups</h2>{switch_tabs(active=dpid, route_name='groups')}<div class='card'><p>Group information is unavailable from the current switch/controller combination.</p><p class='small'>{escape(err)}</p></div>"
        return render_page(content, "groups", auto_refresh=True)
    rows = "".join(f"<tr><td>{g.get('group_id','')}</td><td class='mono'>{escape(str(g.get('type','')))}</td><td class='mono'>{escape(str(g.get('buckets','')))}</td></tr>" for g in data.get(str(dpid), []))
    content = f"<h2 class='section-title'>Groups</h2>{switch_tabs(active=dpid, route_name='groups')}<table><tr><th>Group ID</th><th>Type</th><th>Buckets</th></tr>{rows if rows else '<tr><td colspan="3">No groups found.</td></tr>'}</table>"
    return render_page(content, 'groups', auto_refresh=True)

@app.route("/meters")
def meters():
    sws = get_switches()
    if not sws:
        return render_page("<h2>Meters</h2><p>No switches found.</p>", "meters", auto_refresh=True)
    dpid = request.args.get("dpid") or str(sws[0])
    data, err = ryu_get(f"/stats/meterconfig/{dpid}")
    if err:
        content = f"<h2 class='section-title'>Meters</h2>{switch_tabs(active=dpid, route_name='meters')}<div class='card'><p>Meter information is unavailable from the current switch/controller combination.</p><p class='small'>{escape(err)}</p></div>"
        return render_page(content, "meters", auto_refresh=True)
    rows = "".join(f"<tr><td>{m.get('meter_id','')}</td><td class='mono'>{escape(str(m.get('flags','')))}</td><td class='mono'>{escape(str(m.get('bands','')))}</td></tr>" for m in data.get(str(dpid), []))
    content = f"<h2 class='section-title'>Meters</h2>{switch_tabs(active=dpid, route_name='meters')}<table><tr><th>Meter ID</th><th>Flags</th><th>Bands</th></tr>{rows if rows else '<tr><td colspan="3">No meters found.</td></tr>'}</table>"
    return render_page(content, 'meters', auto_refresh=True)

@app.route("/quarantine", methods=["GET", "POST"])
def quarantine():
    sws = get_switches()
    default_dpid = sws[0] if sws else ""
    flash = ""
    if request.method == "POST":
        try:
            payload = {"dpid": int(request.form["dpid"]), "priority": int(request.form.get("priority", 50000)), "match": json.loads(request.form["match"] or "{}"), "actions": []}
            resp, err = ryu_post("/stats/flowentry/add", payload)
            flash = f"<b>Quarantine response:</b> {escape(resp) if resp else escape(err)}"
        except Exception as e:
            flash = f"<b>Error:</b> {escape(str(e))}"
    content = f'''<h2 class="section-title">Quarantine Device</h2>
    <div class="card">
        <p class="small">This installs a high-priority drop flow. Use this to isolate a host by source MAC, destination MAC, IP fields, or port.</p>
        <form method="post">
            <label>DPID</label><input name="dpid" value="{default_dpid}">
            <label>Priority</label><input name="priority" value="50000">
            <label>Match JSON</label><textarea name="match">{{"eth_src": "00:00:00:00:00:01"}}</textarea>
            <button class="btn btn-danger" type="submit">Apply Quarantine</button>
        </form>
    </div>'''
    return render_page(content, "quarantine", flash=flash)

@app.route("/messages")
def messages():
    sws_data, sws_err = ryu_get("/stats/switches")
    content = f'''<h2 class="section-title">Messages</h2>
    <div class="grid">
        <div class="card col-6"><h3>Controller Status</h3><p><span class="pill {'ok' if sws_data is not None else 'bad'}">{'Connected' if sws_data is not None else 'Unavailable'}</span></p><p class="small">This page is useful for quick API troubleshooting while your environment changes.</p></div>
        <div class="card col-6"><h3>Raw /stats/switches</h3><div class="raw-box mono">{safe_json(sws_data) if sws_data is not None else escape(sws_err or 'Unknown error')}</div></div>
    </div>'''
    return render_page(content, "messages", auto_refresh=True)

@app.route("/configuration")
def configuration():
    content = f'''<h2 class="section-title">Configuration</h2>
    <div class="card"><table>
        <tr><th>Setting</th><th>Value</th></tr>
        <tr><td>RYU_BASE</td><td class="mono">{escape(RYU)}</td></tr>
        <tr><td>Auto Refresh</td><td>{REFRESH_SECONDS} seconds on live pages</td></tr>
        <tr><td>Dynamic Discovery</td><td>Enabled on every request</td></tr>
    </table><p class="small">If your controller IP changes, restart this dashboard with a new <span class="mono">RYU_BASE</span> environment variable.</p></div>'''
    return render_page(content, "configuration")

@app.route("/about")
def about():
    content = '''<h2 class="section-title">About</h2><div class="card"><p><b>Ryu SDN Dashboard</b> is a lightweight browser UI on top of the Ryu REST API.</p><ul><li>Flow tables and delete controls</li><li>Port statistics</li><li>Group and meter views when supported</li><li>Topology page with graceful fallback</li><li>Quarantine button for high-priority drop rules</li><li>Fresh switch discovery on every request</li></ul></div>'''
    return render_page(content, "about")

if __name__ == "__main__":
    app.run(host=os.environ.get("DASHBOARD_HOST", "0.0.0.0"), port=int(os.environ.get("DASHBOARD_PORT", "5000")), debug=True)
