#!/bin/bash
set -e

echo "Starting SDN Controller Environment..."

echo "Stopping old processes..."
pkill -f ryu-manager || true
pkill -f "python3.8 app.py" || true

sleep 2

echo "Starting Ryu Controller..."
cd /home/ryu-controller/ryu || exit 1
PYTHONPATH=. python3.8 ./bin/ryu-manager \
ryu/app/simple_switch_13.py \
ryu/app/ofctl_rest.py &
RYU_PID=$!

sleep 5

echo "Starting Dashboard..."
cd /home/ryu-controller/Ryu_Dashboard || exit 1
python3.8 app.py &
DASH_PID=$!

sleep 2

echo ""
echo "======================================"
echo "SDN Dashboard running"
echo "Dashboard: http://127.0.0.1:5000"
echo "Ryu REST API: http://127.0.0.1:8080"
echo "======================================"
echo ""

wait $RYU_PID
