from flask import Flask, request, render_template_string
import requests
import json

app = Flask(__name__)

RYU="http://127.0.0.1:8080"

BASE="""
<html>

<head>

<title>SDN Dashboard</title>

<meta http-equiv="refresh" content="10">

<style>

body{
font-family:Arial;
margin:0;
background:#f4f4f4;
}

.header{

background:#2f6f73;

color:white;

padding:20px;

font-size:30px;

}

.container{

display:flex;

}

.sidebar{

width:220px;

background:#d88e85;

padding:15px;

}

.sidebar a{

display:block;

background:#b04733;

color:white;

padding:12px;

margin-bottom:10px;

text-decoration:none;

border-radius:6px;

}

.content{

flex:1;

padding:20px;

background:white;

}

.switch{

background:#d88e85;

padding:10px;

margin:5px;

display:inline-block;

border-radius:5px;

}

table{

width:100%;

border-collapse:collapse;

}

th{

background:#8d6b1f;

color:white;

padding:10px;

}

td{

border:1px solid #ccc;

padding:8px;

}

button{

background:#2f6f73;

color:white;

border:none;

padding:8px;

border-radius:4px;

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

{content}

</div>

</div>

</body>

</html>
"""

def switches():

    r=requests.get(RYU+"/stats/switches")

    return r.json()

@app.route("/")

def home():

    sw=switches()

    html="<h2>Controller Overview</h2>"

    html+=f"Switches detected: {len(sw)}<br><br>"

    for s in sw:

        html+=f'<a class="switch" href="/flows?dpid={s}">SW_{str(s)[-3:]}</a>'

    return BASE.format(content=html)

@app.route("/flows")

def flows():

    sw=switches()

    if not sw:

        return BASE.format(content="No switches")

    dpid=request.args.get("dpid")

    if not dpid:

        dpid=sw[0]

    r=requests.get(RYU+"/stats/flow/"+str(dpid))

    data=r.json()[str(dpid)]

    rows=""

    for f in data:

        rows+=f"""

        <tr>

        <td>{f.get('priority')}</td>

        <td>{f.get('match')}</td>

        <td>{f.get('packet_count')}</td>

        <td>{f.get('byte_count')}</td>

        <td>{f.get('actions')}</td>

        </tr>

        """

    html=f"""

    <h2>Flow Table</h2>

    <table>

    <tr>

    <th>Priority</th>

    <th>Match</th>

    <th>Packets</th>

    <th>Bytes</th>

    <th>Actions</th>

    </tr>

    {rows}

    </table>

    """

    return BASE.format(content=html)

@app.route("/ports")

def ports():

    sw=switches()

    if not sw:

        return BASE.format(content="No switches")

    dpid=sw[0]

    r=requests.get(RYU+"/stats/port/"+str(dpid))

    data=r.json()[str(dpid)]

    rows=""

    for p in data:

        rows+=f"""

        <tr>

        <td>{p['port_no']}</td>

        <td>{p['rx_packets']}</td>

        <td>{p['tx_packets']}</td>

        <td>{p['rx_bytes']}</td>

        <td>{p['tx_bytes']}</td>

        </tr>

        """

    html=f"""

    <h2>Port Stats</h2>

    <table>

    <tr>

    <th>Port</th>

    <th>RX</th>

    <th>TX</th>

    <th>RX Bytes</th>

    <th>TX Bytes</th>

    </tr>

    {rows}

    </table>

    """

    return BASE.format(content=html)

@app.route("/flowcontrol",methods=["GET","POST"])

def flowcontrol():

    msg=""

    if request.method=="POST":

        payload={

        "dpid":int(request.form["dpid"]),

        "priority":int(request.form["priority"]),

        "match":json.loads(request.form["match"]),

        "actions":json.loads(request.form["actions"])

        }

        requests.post(RYU+"/stats/flowentry/add",json=payload)

        msg="Flow Added"

    sw=switches()

    dpid=sw[0] if sw else ""

    html=f"""

    <h2>Flow Control</h2>

    {msg}

    <form method="post">

    DPID:<input name="dpid" value="{dpid}">

    Priority:<input name="priority" value="100">

    Match JSON:<textarea name="match">{{"in_port":1}}</textarea>

    Actions JSON:<textarea name="actions">[{{"type":"OUTPUT","port":2}}]</textarea>

    <button>Add Flow</button>

    </form>

    """

    return BASE.format(content=html)

@app.route("/switches")

def sw():

    sws=switches()

    rows=""

    for s in sws:

        rows+=f"<tr><td>{s}</td></tr>"

    html=f"""

    <h2>Switches</h2>

    <table>

    <tr><th>DPID</th></tr>

    {rows}

    </table>

    """

    return BASE.format(content=html)

app.run(host="0.0.0.0",port=5000)
