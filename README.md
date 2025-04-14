# DDoSFlowGuard
An SDN-based DDoS detection tool leveraging flow statistics (Packet Count, Byte Count, Src_Count_per_Dst) with Ryu and Mininet for real-time traffic analysis and attack mitigation.

## Features
- Real-time flow stats collection using Ryu SDN controller
- Simulated normal and DDoS traffic with Mininet
- Customizable attack scenarios

## Getting Started
1. Install dependencies: `sudo apt install mininet ryu hping3`
2. Run Ryu controller: `ryu-manager flow_stats_handler.py`
3. Simulate traffic: `sudo python3 ddos_traffic.py`
# sdn_module_senior_project
