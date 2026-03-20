#!/bin/bash
set -e

echo "Starting SDN Controller Environment..."

pkill -f ryu-manager || true
pkill -f "python3.8 app.py" || true

sleep 2

echo "Starting Ryu Controller..."
cd ~/ryu || exit 1
PYTHONPATH=. python3.8 ./bin/ryu-manager \
ryu/app/simple_switch_13.py \
ryu/app/ofctl_rest.py \
ryu/app/rest_topology.py &
RYU_PID=$!

sleep 5

echo "Starting Dashboard..."
cd ~/Ryu_Dashboard || exit 1
python3.8 app.py &
DASH_PID=$!

echo ""
echo "Dashboard: http://127.0.0.1:5000"
echo "Ryu REST:   http://127.0.0.1:8080"
echo ""

wait $RYU_PID
