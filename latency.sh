#!/bin/bash

# activate virtual network
echo "Virtual Environment Activated"
echo
source venv/bin/activate

# Create summary of flowtable occupancy
echo "Calculating latency of packets injected & generating log using packet injection log file and log captured using WireShark during the virtual network simulation....." &
echo
python3 app/get_latency.py
echo