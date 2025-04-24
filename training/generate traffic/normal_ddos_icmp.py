#!/usr/bin/env python

"""
Wireless mesh network simulation with ICMP traffic generation.
"""

import time
import random
import subprocess
from datetime import datetime
from mininet.log import setLogLevel, info
from mn_wifi.link import wmediumd, mesh
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference
from mininet.node import Controller, RemoteController
from containernet.node import DockerSta
from containernet.term import makeTerm

def generate_icmp(sender, receiver_ip, duration, attack_type='normal', burst_duration=10):
    """
    Generate ICMP traffic with specified criteria (normal or DDoS).
    Args:
        sender: The station sending the traffic.
        receiver_ip: IP address of the receiver.
        duration: Total duration of the attack in seconds.
        attack_type: Type of attack ('normal' or 'ddos').
        burst_duration: Duration of each burst in seconds.
    """
    # Define normal and DDoS criteria
    criteria_normal = [
        (10, (40, 800)),    # 10 pps, 40-800 bytes
        (100, (40, 500)),   # 100 pps, 40-500 bytes
        (1000, (40, 100)),  # 1000 pps, 40-100 bytes
    ]
    criteria_ddos = [
        (1000, (800, 1500)),    # 1000 pps, 800-1500 bytes
        (10000, (40, 400)),     # 10000 pps, 40-400 bytes
        (100000, (40, 100)),    # 100000 pps, 40-100 bytes
    ]
    rate_map = {10: "u100000", 100: "u10000", 1000: "u1000", 10000: "u100", 100000: "u10"}
    rate_desc = {
        10: "low (10 pps)", 
        100: "medium (100 pps)", 
        1000: "high (1000 pps)",
        10000: "very high (10000 pps)",
        100000: "extreme (100000 pps)"
    }
    
    # Select criteria based on attack type
    criteria = criteria_normal if attack_type == 'normal' else criteria_ddos
    
    start_time = time.time()
    total_end_time = start_time + duration
    info(f"*** Generating {attack_type.upper()} ICMP traffic from {sender.name} to {receiver_ip}\n")
    
    while time.time() < total_end_time:
        rate, size_range = random.choice(criteria)
        packet_size = random.randint(size_range[0], size_range[1])
        density = rate_map[rate]
        
        # Use the provided burst_duration
        packet_count = int(rate * burst_duration)
        burst_start_time = time.time()

        info(f"[{datetime.now()}] {sender.IP()} -> {receiver_ip}: Start ICMP (size={packet_size} bytes, rate={rate_desc[rate]}, count={packet_count}, duration={burst_duration:.2f}s)\n")
        
        sender.cmd(f"hping3 --icmp -d {packet_size} --interval {density} -c {packet_count} {receiver_ip} -q &")
        
        expected_duration = packet_count / rate
        time.sleep(expected_duration + 1)  # Add a small buffer to ensure hping3 finishes
        
        current_time = time.time()
        elapsed_time = current_time - start_time
        progress = (elapsed_time / duration) * 100
        info(f"[Progress: {progress:.2f}%] {sender.IP()} -> {receiver_ip}: Burst ended\n")
        
        # Set pause duration based on attack type
        pause = 29 if attack_type == 'ddos' else 29
        info(f"[{datetime.now()}] Pausing for {pause:.2f}s\n")
        time.sleep(pause)

def create_topology():
    """Create and run the network topology."""
    info("*** Cleaning up containers\n")
    subprocess.run("sudo docker rm -f $(docker ps -aq)", shell=True, check=False)

    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)

    info("*** Adding stations\n")
    attacker1 = net.addStation(
        'attacker1', cls=DockerSta, dimage="nisach/ddos_attack:v2.3", mac='00:00:00:00:00:11',
        ip='10.0.0.11/8', range=50, mem_limit='512m', cpu_shares=10, position='10,10,0')
    attacker2 = net.addStation(
        'attacker2', cls=DockerSta, dimage="nisach/ddos_attack:v2.3", mac='00:00:00:00:00:12',
        ip='10.0.0.12/8', range=50, mem_limit='512m', cpu_shares=10, position='30,10,0')
    attacker3 = net.addStation(
        'attacker3', cls=DockerSta, dimage="nisach/ddos_attack:v2.3", mac='00:00:00:00:00:16',
        ip='10.0.0.13/8', range=50, mem_limit='512m', cpu_shares=10, position='0,0,0')
    server1 = net.addStation(
        'server1', cls=DockerSta, dimage="knotnot/proxy-server", mac='00:00:00:00:00:13',
        ip='10.0.0.4/8', range=50, mem_limit='512m', cpu_shares=30, position='40,90,0')
    server2 = net.addStation(
        'server2', cls=DockerSta, dimage="knotnot/backend-1", mac='00:00:00:00:00:14',
        ip='10.0.0.5/8', range=50, mem_limit='512m', cpu_shares=20, position='25,80,0')
    server3 = net.addStation(
        'server3', cls=DockerSta, dimage="knotnot/backend-1", mac='00:00:00:00:00:15',
        ip='10.0.0.6/8', range=50, mem_limit='512m', cpu_shares=20, position='30,80,0')

    info("*** Adding Access Points\n")
    net.addAccessPoint('ap1', ssid='ssid1', mode='g', channel=1, position='20,60,0', range=50,dpid="1")
    net.addAccessPoint('ap2', ssid='ssid1', mode='g', channel=6, position='20,20,0', range=50,dpid="2")

    info("*** Adding controller\n")
    controller = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info("*** Configuring nodes\n")
    for sta in net.stations:
        sta.params['noise_threshold'] = -85
    for ap in net.aps:
        ap.params['noise_threshold'] = -85
    net.configureNodes()

    info("*** Creating AP link\n")
    net.addLink(net.get('ap1'), net.get('ap2'))

    info("*** Starting network\n")
    net.build()
    controller.start()
    for ap in net.aps:
        ap.start([controller])
    
    net.setPropagationModel(model="logDistance", exp=5)
    net.plotGraph(max_x=100, max_y=100)

    info("*** Connecting stations\n")
    for sta in [attacker1, attacker2, attacker3, server1, server2, server3]:
        makeTerm(sta, cmd="bash -c 'apt-get update && apt-get install -y iw wireless-tools net-tools hping3 && iw dev {}-wlan0 connect ssid1'".format(sta.name))

    time.sleep(60)
    info("*** Starting ICMP traffic\n")
    # Start normal attack from attacker1 to server1 and DDoS attack from attacker2 to server1
    import threading
    duration = 14400  # Total duration for both attacks
    
    start_time = time.time()
    total_end_time = start_time + duration
    
    while time.time() < total_end_time:
        # Randomize burst_duration once per loop for both attacks
        burst_duration = random.uniform(5, 30)
        
        # Start threads with the same burst_duration
        t1 = threading.Thread(target=generate_icmp, args=(attacker1, server1.IP(), duration, 'normal', burst_duration))
        t2 = threading.Thread(target=generate_icmp, args=(attacker2, server1.IP(), duration, 'ddos', burst_duration))
        
        t1.start()
        t2.start()
        
        # Wait for both threads to complete their burst
        t1.join()
        t2.join()
    
    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
