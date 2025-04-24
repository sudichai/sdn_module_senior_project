import csv
import os
from datetime import datetime
from time import time
from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import pandas as pd
import joblib
import paramiko
import mysql.connector
import logging
from ryu.lib.packet import ether_types

class FlowStatsHandler(app_manager.RyuApp):
    """Ryu application for handling flow statistics and DDoS detection."""
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    SERVER_SRC = "00:00:00:00:00:13"

    def __init__(self, *args, **kwargs):
        """Initialize the application."""
        super().__init__(*args, **kwargs)
        self._setup_logging()
        
        # File paths for CSV outputs
        self.output_file = '/home/wifi/sdn/main/flow_stats.csv'
        self.action_log_file = '/home/wifi/sdn/main/action_log.csv'
        self.port_stats_history = {}
        self.start_time = time()
        self.seconds_since_start = 0
        # Cache for SQL logging
        self.stats_cache = defaultdict(lambda: {
            'rx_bytes_per_sec': 0.0,
            'tx_bytes_per_sec': 0.0,
            'cpu_util': None,
            'logged': False
        })
        
        # Initialize datapaths, meter ID, and connections
        self.datapaths = {}
        self.meter_id = 1
        self.ssh_client = None
        self.db = None
        self._init_connections()
        
        # Cache for DDoS detection counts, separated by datapath
        self.ddos_detection_count = defaultdict(lambda: defaultdict(int))
        self.action_log = []

        # Map protocol numbers to names
        self.protocol_map = {1: 'ICMP', 6: 'TCP'}

        # Load machine learning models
        self.rf_models = {}
        for proto in self.protocol_map:
            self._load_model(proto)

        # Initialize action log CSV
        self._init_action_log_csv()

        # Start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)

    def _setup_logging(self):
        """Configure logging with a clear format."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            handlers=[logging.StreamHandler()]
        )
        self.logger = logging.getLogger(__name__)
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    def _init_connections(self):
        """Initialize SSH and MySQL connections."""
        self._init_ssh()
        try:
            self.db = mysql.connector.connect(
                host="172.20.10.3",  
                port=3306, 
                user="root",
                password="47363",
                database="sdn"
            )
            self.logger.info("MySQL connection established")
        except Exception as e:
            self.logger.error(f"MySQL connection failed: {e}")
            self.db = None

        if not os.path.exists(self.output_file):
            self._create_csv_headers()

    def _init_ssh(self):
        """Initialize SSH connection with password authentication."""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                hostname="172.20.10.5",
                #hostname="127.0.0.1",
                port=22,
                username="wifi",
                password="wifi",
                allow_agent=False,
                look_for_keys=False
            )
            self.logger.info("SSH connection established")
        except Exception as e:
            self.logger.error(f"SSH connection failed: {e}")
            self.ssh_client = None

    def _load_model(self, protocol):
        """Load Random Forest model for a specific protocol."""
        model_path = f'/home/wifi/sdn/training/model/rf_model_{protocol}.joblib'
        try:
            self.rf_models[protocol] = joblib.load(model_path)
            self.logger.info(f"Loaded model for {self.protocol_map[protocol]}")
        except Exception as e:
            self.logger.error(f"Failed to load model for {self.protocol_map[protocol]}: {e}")
            self.rf_models[protocol] = None

    def _create_csv_headers(self):
        """Create headers for flow stats CSV file."""
        headers = [
            'Seconds Since Start', 'Real Timestamp', 'Ethernet Src', 'Ethernet Dst', 'Protocol',
            'Packet Count', 'Byte Count', 'Packet Rate', 'Byte Rate', 'CPU utilization',
            'Duration (sec)', 'Duration (nsec)', 'Prediction', 'Priority', 'Idle Timeout',
            'Hard Timeout', 'Datapath', 'Match Fields', 'Instructions'
        ]
        with open(self.output_file, 'w', newline='') as f:
            csv.writer(f).writerow(headers)

    def _init_action_log_csv(self):
        """Initialize action log CSV file."""
        if not os.path.exists(self.action_log_file):
            headers = ['Seconds Since Start', 'Datapath', 'Eth Src', 'Eth Dst', 'Count', 'Action']
            with open(self.action_log_file, 'w', newline='') as f:
                csv.writer(f).writerow(headers)

    def _monitor(self):
        """Periodically request flow statistics from datapaths."""
        while True:
            self.seconds_since_start = int(time() - self.start_time)
            for dp in self.datapaths.values():
                self._request_flow_stats(dp)
                self._request_port_stats(dp)
            hub.sleep(5)

    def _request_flow_stats(self, datapath):
        """Send flow stats request to the specified datapath."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, match=parser.OFPMatch())
        datapath.send_msg(req)
        self.logger.info(f"Requesting flow stats from switch: {datapath.id}")

    def _request_port_stats(self, datapath):
        """Send port stats request to the specified datapath."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
        self.logger.info(f"Requesting port stats from switch: {datapath.id}")

    def _get_cpu_utilization(self):
        """Retrieve CPU utilization via SSH."""
        try:
            if self.ssh_client is None or not self.ssh_client.get_transport().is_active():
                self._init_ssh()

            if self.ssh_client:
                cmd = f"echo 'wifi' | sudo -S docker exec mn.server1 top -bn1 | grep 'Cpu(s)' | awk '{{split($0, a, /[ ,]+/); for(i in a) if(a[i]==\"id\") print a[i-1]}}'"
                stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()

                if error and "incorrect password" in error.lower():
                    self.logger.error("SSH command failed: Incorrect sudo password")
                    return 0.0
                elif "No such container" in error or "not found" in error:
                    self.logger.error("SSH command failed: Container mn.server1 not running")
                    return 0.0
                elif not output:
                    self.logger.error(f"SSH command failed: No output received: {error}")
                    return 0.0

                cpu_idle_value = float(output)
                if 0 <= cpu_idle_value <= 100:
                    cpu_utilization = round(100 - cpu_idle_value, 2)
                    return cpu_utilization
                else:
                    self.logger.error(f"SSH command error: CPU idle value out of range: {output}")
                    return 0.0
            else:
                self.logger.error("SSH client not available")
                return 0.0
        except ValueError as e:
            self.logger.error(f"Error converting to float: {e}, Output received: '{output}'")
            return 0.0
        except Exception as e:
            self.logger.error(f"Error retrieving CPU utilization from server1 via SSH: {e}")
            return 0.0

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply from datapath."""
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        stats = ev.msg.body

        if not hasattr(self, 'meter_created'):
            self._create_meter(datapath)
            self.meter_created = True

        cpu_util = self._get_cpu_utilization()
        seconds_since_start = self.seconds_since_start
        real_timestamp = datetime.fromtimestamp(self.start_time + seconds_since_start).strftime('%Y-%m-%d %H:%M:%S')
        total_bytes, total_packets = 0, 0
        prediction = "NoFlowData"

        # Store CPU utilization in cache
        cache_key = (seconds_since_start, datapath.id)
        self.stats_cache[cache_key]['cpu_util'] = cpu_util

        with open(self.output_file, 'a', newline='') as f:
            writer = csv.writer(f)
            for stat in stats:
                if not self._is_valid_flow(stat):
                    continue

                match = stat.match
                eth_src, eth_dst = match.get('eth_src', "N/A"), match.get('eth_dst', "N/A")
                protocol = match.get('ip_proto', 0)
                if protocol not in self.protocol_map:
                    continue

                proto_name = self.protocol_map[protocol]
                duration = stat.duration_sec + (stat.duration_nsec / 1e9)
                pkt_rate = stat.packet_count / (duration + 1e-6)
                byte_rate = stat.byte_count / (duration + 1e-6)

                total_bytes += stat.byte_count
                total_packets += stat.packet_count

                features = pd.DataFrame([{
                    'Packet Count': stat.packet_count,
                    'Byte Count': stat.byte_count,
                    'Packet Rate': pkt_rate,
                    'Byte Rate': byte_rate,
                    'CPU utilization': cpu_util
                }])
                if self._extract_instructions(stat) != []:
                    prediction = self._detect_ddos(datapath, parser, features, eth_src, eth_dst, protocol, duration)

                writer.writerow([
                    seconds_since_start, real_timestamp, eth_src, eth_dst, proto_name,
                    stat.packet_count, stat.byte_count, f"{pkt_rate:.2f}", f"{byte_rate:.2f}",
                    cpu_util, stat.duration_sec, stat.duration_nsec, prediction,
                    stat.priority, stat.idle_timeout, stat.hard_timeout, datapath.id,
                    str(match), str(self._extract_instructions(stat))
                ])

        # Attempt to log to DB if all data is available
        self._log_to_db(seconds_since_start, real_timestamp, datapath.id)

    def _is_valid_flow(self, stat):
        """Check if a flow is valid for processing."""
        match = stat.match
        return (
            match.get('eth_src', "N/A") != "N/A" and
            match.get('eth_dst', "N/A") != "N/A" and
            stat.packet_count > 0 and stat.byte_count > 0
        )

    def _detect_ddos(self, datapath, parser, features, eth_src, eth_dst, protocol, duration):
        """Detect DDoS attacks and apply mitigation based on detection count."""
        proto_name = self.protocol_map.get(protocol, "Unknown")
        model = self.rf_models.get(protocol)
        if not model:
            self.logger.error(f"No model for {proto_name}")
            return "Unknown"

        try:
            features_subset = features[['Packet Count', 'Byte Count', 'Packet Rate', 'Byte Rate', 'CPU utilization']]
            prediction = model.predict(features_subset)[0]
            probs = model.predict_proba(features_subset)[0]
            prob_dict = dict(zip(model.classes_, probs))
            if duration == 0 or eth_src == self.SERVER_SRC:
                return prediction

            self.logger.info(f"\nTraffic Analysis from ap{datapath.id}:")
            self.logger.info(f"  Source: {eth_src} -> Destination: {eth_dst}")
            self.logger.info(f"  Protocol: {proto_name}")
            self.logger.info(f"  Prediction: {prediction}")
            self.logger.info(f"  CPU Usage: {features['CPU utilization'].iloc[0]:.2f}%")
            self.logger.info(f"  Probabilities:")
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_dst=eth_dst, eth_src=eth_src, ip_proto=protocol)
            for cls, prob in prob_dict.items():
                self.logger.info(f"    {cls}: {prob:.2f}")

            max_prob = max(probs)
            dpid = datapath.id
            if prediction in ["DDoS_ICMP", "DDoS_TCP"] and max_prob >= 0.9:
                self.ddos_detection_count[dpid][eth_src] += 1
                count = self.ddos_detection_count[dpid][eth_src]
                self.logger.info(f"  Detection count for dp:{dpid}, src:{eth_src} = {count}")

                if count > 4:
                    self.logger.info(f"\033[31m*** Permanent block triggered for {eth_src} ***\033[0m")
                    self._remove_prior_flows(datapath, parser, eth_src, eth_dst, protocol)
                    self.add_flow(datapath, 20, match, [], 600, 600)
                    self._log_action(dpid, eth_src, eth_dst, count, "perm_block")
                elif count > 2:
                    self.logger.info(f"\033[31mTemporary block triggered for {eth_src}\033[0m")
                    self._remove_prior_flows(datapath, parser, eth_src, eth_dst, protocol)
                    self.add_flow(datapath, 10, match, [], 30, 20)
                    self._log_action(dpid, eth_src, eth_dst, count, "temp_block")
            elif prediction in ["DDoS_ICMP", "DDoS_TCP"] and max_prob >= 0.5:
                self.logger.info(f"  Rate Limiting triggered for {eth_src}")
                self._apply_rate_limit(datapath, parser, eth_src, eth_dst, prediction, 100)
            return prediction
        except Exception as e:
            self.logger.error(f"Classification error for {proto_name}: {e}")
            return "Unknown"

    def _remove_prior_flows(self, datapath, parser, eth_src, eth_dst, protocol):
        """Remove existing flow rules that allow traffic from eth_src to eth_dst for the given protocol."""
        ofproto = datapath.ofproto
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            eth_src=eth_src,
            eth_dst=eth_dst,
            ip_proto=protocol
        )
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(flow_mod)
        self.logger.info(f"Removed prior flow rules for src:{eth_src}, dst:{eth_dst}, proto:{self.protocol_map.get(protocol, 'Unknown')}")

    def _apply_rate_limit(self, datapath, parser, eth_src, eth_dst, prediction, rate):
        """Apply a rate limit rule for a source."""
        self._add_rate_limit_rule(datapath, parser, eth_src, eth_dst, rate)
        action = f"Rate Limit at {rate} kBps"
        self._log_action(datapath.id, eth_src, eth_dst, 0, action)
        self.logger.info(f"\033[33m  Action: {action}\033[0m")

    def _log_action(self, datapath_id, eth_src, eth_dst, count, action):
        """Log mitigation action to CSV file."""
        seconds_since_start = self.seconds_since_start
        self.action_log.append((seconds_since_start, datapath_id, eth_src, eth_dst, count, action))
        with open(self.action_log_file, 'a', newline='') as f:
            csv.writer(f).writerow([seconds_since_start, datapath_id, eth_src, eth_dst, count, action])

    def _add_rate_limit_rule(self, datapath, parser, eth_src, eth_dst, rate):
        """Add an OpenFlow rule to limit packet rate from a source."""
        ofproto = datapath.ofproto
        meter_id = self.meter_id
        bands = [parser.OFPMeterBandDrop(rate=rate, burst_size=10)]
        datapath.send_msg(parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands
        ))
        match = parser.OFPMatch(eth_src=eth_src, eth_dst=eth_dst)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [
            parser.OFPInstructionMeter(meter_id=meter_id, type_=ofproto.OFPIT_METER),
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            priority=5,
            match=match,
            instructions=inst,
            idle_timeout=10,
            hard_timeout=15
        ))
        self.meter_id += 1
        self.logger.info(f"Added rate limit for {eth_src} at {rate}kbps")

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """Handle port statistics reply from datapath."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        seconds_since_start = self.seconds_since_start

        # Aggregate RX/TX bytes per second across all ports
        total_rx_bytes_per_sec = 0.0
        total_tx_bytes_per_sec = 0.0
        for stat in body:
            port_no = stat.port_no
            tx_bytes = stat.tx_bytes
            rx_bytes = stat.rx_bytes
            key = (dpid, port_no)
            if key in self.port_stats_history:
                prev_tx_bytes, prev_rx_bytes, prev_seconds = self.port_stats_history[key]
                duration = seconds_since_start - prev_seconds
                if duration > 0:
                    tx_bytes_per_sec = (tx_bytes - prev_tx_bytes) / duration
                    rx_bytes_per_sec = (rx_bytes - prev_rx_bytes) / duration
                else:
                    tx_bytes_per_sec = 0.0
                    rx_bytes_per_sec = 0.0
            else:
                tx_bytes_per_sec = 0.0
                rx_bytes_per_sec = 0.0
            self.port_stats_history[key] = (tx_bytes, rx_bytes, seconds_since_start)
            total_rx_bytes_per_sec += rx_bytes_per_sec
            total_tx_bytes_per_sec += tx_bytes_per_sec
            self.logger.info(
                f"[ap{dpid}] Port {port_no}: TX {tx_bytes_per_sec:.2f} Bps | RX {rx_bytes_per_sec:.2f} Bps"
            )

        # Store aggregated RX/TX bytes per second in cache
        cache_key = (seconds_since_start, dpid)
        self.stats_cache[cache_key]['rx_bytes_per_sec'] = total_rx_bytes_per_sec
        self.stats_cache[cache_key]['tx_bytes_per_sec'] = total_tx_bytes_per_sec

        # Attempt to log to DB if all data is available
        real_timestamp = datetime.fromtimestamp(self.start_time + seconds_since_start).strftime('%Y-%m-%d %H:%M:%S')
        self._log_to_db(seconds_since_start, real_timestamp, dpid)

    def _log_to_db(self, seconds_since_start, real_timestamp, datapath_id):
        """Log flow statistics to MySQL database."""
        if not self.db:
            return

        cache_key = (seconds_since_start, datapath_id)
        cache = self.stats_cache[cache_key]

        # Check if all required data is available and not yet logged
        if (
            cache['rx_bytes_per_sec'] > 0.0 and
            cache['tx_bytes_per_sec'] > 0.0 and
            cache['cpu_util'] is not None and
            not cache['logged']
        ):
            try:
                cursor = self.db.cursor()
                sql = """
                    INSERT INTO experimentgunnot (seconds_since_start, real_timestamp, datapath_id,
                    rx_bytes_per_sec, tx_bytes_per_sec, cpu_utilization)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (
                    seconds_since_start,
                    real_timestamp,
                    datapath_id,
                    cache['rx_bytes_per_sec'],
                    cache['tx_bytes_per_sec'],
                    cache['cpu_util']
                ))
                self.db.commit()
                self.logger.debug(f"Logged to DB: {cursor.rowcount} row(s)")
                cursor.close()
                # Mark as logged to prevent duplicate entries
                cache['logged'] = True
            except Exception as e:
                self.logger.error(f"DB insert failed: {e}")

    def _extract_instructions(self, stat):
        """Extract instructions from a flow stat."""
        return [inst.to_jsondict() for inst in stat.instructions]

    def _create_meter(self, datapath):
        """Create a default meter for rate limiting."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        bands = [parser.OFPMeterBandDrop(rate=100, burst_size=10)]
        datapath.send_msg(parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=self.meter_id,
            bands=bands
        ))

        self.logger.debug(f"Created meter {self.meter_id} for datapath {datapath.id}")

    def add_flow(self, datapath, priority, match, actions, hard_timeout, idle_timeout):
        """Add a flow entry to the datapath."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Handle datapath state changes (connect/disconnect)."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info(f"Datapath {datapath.id} connected")
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self.logger.info(f"Datapath {datapath.id} disconnected")

