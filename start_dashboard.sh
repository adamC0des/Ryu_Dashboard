#!/bin/bash

echo "Starting SDN Controller Environment..."

echo "Stopping old processes..."
pkill -f ryu-manager
pkill -f app.py

sleep 2

echo "Starting Ryu Controller..."

cd ~/ryu || exit

PYTHONPATH=. python3.8 ./bin/ryu-manager \
ryu/app/simple_switch_13.py \
ryu/app/ofctl_rest.py \
ryu/app/rest_topology.py \
ryu/app/ws_topology.py \
--observe-links &

sleep 5

echo "Starting Dashboard..."

cd ~/dashboard || exit

python3.8 app.py &

sleep 2

echo ""
echo "======================================"
echo "SDN Dashboard running"
echo "Dashboard:"
echo "http://127.0.0.1:5000"
echo ""
echo "Ryu REST API:"
echo "http://127.0.0.1:8080"
echo "======================================"
echo ""

echo "Environment ready."
