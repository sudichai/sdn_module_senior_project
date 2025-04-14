#flow_stats_handler.py

import csv
import os
from datetime import datetime
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
    PROTECTED_SRC = "00:00:00:00:00:13"  # Protected source MAC address

    def __init__(self, *args, **kwargs):
        """Initialize the application."""
        super().__init__(*args, **kwargs)
        self._setup_logging()
        
        # File paths for CSV outputs
        self.output_file = '/home/wifi/sdn/main/flow_stats.csv'
        self.action_log_file = '/home/wifi/sdn/main/action_log.csv'
        
        # Initialize datapaths, meter ID, and connections
        self.datapaths = {}
        self.meter_id = 1
        self.ssh_client = None
        self.db = None
        self._init_connections()
        
        # Cache for DDoS detection counts
        self.ddos_detection_count = defaultdict(int)
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
        # Suppress Paramiko's debug logs
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    def _init_connections(self):
        """Initialize SSH and MySQL connections."""
        self._init_ssh()
        try:
            self.db = mysql.connector.connect(
                host="`host",  
                port=47000, 
                user="root",
                password="47363",
                database="sdn"
            )
            self.logger.info("MySQL connection established")
        except Exception as e:
            self.logger.error(f"MySQL connection failed: {e}")
            self.db = None

        # Create CSV file if it doesn't exist
        if not os.path.exists(self.output_file):
            self._create_csv_headers()

    def _init_ssh(self):
        """Initialize SSH connection with password authentication."""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                hostname="127.0.0.1",
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
            'Timestamp', 'Eth Src', 'Eth Dst', 'Protocol', 'Packets',
            'Bytes', 'Packet Rate', 'Byte Rate', 'CPU Util (%)',
            'Duration (s)', 'Duration (ns)', 'Datapath', 'Match',
            'Priority', 'Idle Timeout', 'Hard Timeout', 'In Port',
            'Instructions', 'Prediction'
        ]
        with open(self.output_file, 'w', newline='') as f:
            csv.writer(f).writerow(headers)

    def _init_action_log_csv(self):
        """Initialize action log CSV file."""
        if not os.path.exists(self.action_log_file):
            headers = ['Timestamp', 'Eth Src', 'Action']
            with open(self.action_log_file, 'w', newline='') as f:
                csv.writer(f).writerow(headers)

    def _monitor(self):
        """Periodically request flow statistics from datapaths."""
        while True:
            for dp in self.datapaths.values():
                self._request_flow_stats(dp)
            hub.sleep(5)

    def _request_flow_stats(self, datapath):
        """Send flow stats request to a datapath."""
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowStatsRequest(datapath, match=parser.OFPMatch()))
        self.logger.debug(f"Requested flow stats from datapath {datapath.id}")

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

        # Create meter if not already created
        if not hasattr(self, 'meter_created'):
            self._create_meter(datapath)
            self.meter_created = True

        cpu_util = self._get_cpu_utilization()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        total_bytes, total_packets = 0, 0
        prediction = "NoFlowData"

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

                prediction = self._detect_ddos(datapath, parser, features, eth_src, eth_dst, protocol)

                writer.writerow([
                    timestamp, eth_src, eth_dst, proto_name, stat.packet_count,
                    stat.byte_count, f"{pkt_rate:.2f}", f"{byte_rate:.2f}", cpu_util,
                    stat.duration_sec, stat.duration_nsec, datapath.id, str(match),
                    stat.priority, stat.idle_timeout, stat.hard_timeout, match.get('in_port', "N/A"),
                    str(self._extract_instructions(stat)), prediction
                ])

        self._log_to_db(timestamp, datapath.id, total_bytes, total_packets, cpu_util, prediction)

    def _is_valid_flow(self, stat):
        """Check if a flow is valid for processing."""
        match = stat.match
        return (
            match.get('eth_src', "N/A") != "N/A" and
            match.get('eth_dst', "N/A") != "N/A" and
            stat.packet_count > 0 and stat.byte_count > 0
        )

    def _detect_ddos(self, datapath, parser, features, eth_src, eth_dst, protocol):
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

            # Log traffic analysis details
            self.logger.info(f"\nTraffic Analysis:")
            self.logger.info(f"  Source: {eth_src} -> Destination: {eth_dst}")
            self.logger.info(f"  Protocol: {proto_name}")
            self.logger.info(f"  Prediction: {prediction}")
            self.logger.info(f"  CPU Usage: {features['CPU utilization'].iloc[0]:.2f}%")
            self.logger.info(f"  Probabilities:")
            for cls, prob in prob_dict.items():
                self.logger.info(f"    {cls}: {prob:.2f}")

            max_prob = max(probs)
            cache_key = f"{eth_src}_{prediction}"
            if prediction in ["DDoS_ICMP", "DDoS_TCP"] and max_prob >= 0.9:  # Fixed: Use max_prob instead of prediction
                if eth_src == self.PROTECTED_SRC:
                    self.logger.info(f"  Skipping mitigation for protected source {eth_src}")
                    return prediction

                self.ddos_detection_count[cache_key] += 1
                self.logger.info(f"  Detection count: {self.ddos_detection_count[cache_key]}")

                # Apply mitigation based on detection count
                if self.ddos_detection_count[cache_key] > 4:
                    self.logger.info(f"  Permanent block triggered for {eth_src}")
                    self._apply_permanent_block(datapath, parser, eth_src, prediction)
                elif self.ddos_detection_count[cache_key] > 2:
                    self.logger.info(f"  Temporary block triggered for {eth_src}")
                    self._apply_temp_block(datapath, parser, eth_src, prediction)
            elif max_prob >= 0.5:
                self._apply_rate_limit(datapath, parser, eth_src, prediction, 500)  # Fixed: Removed erroneous self parameter
                self.logger.info(f"  Rate Limiting triggered for {eth_src}")
            return prediction
        except Exception as e:
            self.logger.error(f"Classification error for {proto_name}: {e}")
            return "Unknown"

    def _apply_temp_block(self, datapath, parser, eth_src, prediction):
        """Apply a temporary block rule for a source."""
        self._add_drop_rule(datapath, parser, eth_src, idle_timeout=10, hard_timeout=15)
        action = f"Temporary Block (Prediction: {prediction}, Detection Count: {self.ddos_detection_count[f'{eth_src}_{prediction}']})"
        self._log_action(eth_src, action)
        self.logger.info(f"\033[31m  Action: {action}\033[0m")

    def _apply_permanent_block(self, datapath, parser, eth_src, prediction):
        """Apply a permanent block rule for a source, removing previous temporary rules."""
        ofproto = datapath.ofproto
        # Remove existing temporary rules to avoid conflicts
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=eth_src)
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        ))
        # Add permanent block rule
        self._add_drop_rule(datapath, parser, eth_src, idle_timeout=0, hard_timeout=0)
        action = f"Permanent Block (Prediction: {prediction}, Detection Count: {self.ddos_detection_count[f'{eth_src}_{prediction}']})"
        self._log_action(eth_src, action)
        self.logger.info(f"\033[31m  Action: {action}\033[0m")

    def _apply_rate_limit(self, datapath, parser, eth_src, prediction, rate):
        """Apply a rate limit rule for a source."""
        self._add_rate_limit_rule(datapath, parser, eth_src, rate)
        action = f"Rate Limit at {rate}kbps (Prediction: {prediction})"
        self._log_action(eth_src, action)
        self.logger.info(f"\033[33m  Action: {action}\033[0m")

    def _log_action(self, eth_src, action):
        """Log mitigation action to CSV file."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.action_log.append((timestamp, eth_src, action))
        with open(self.action_log_file, 'a', newline='') as f:
            csv.writer(f).writerow([timestamp, eth_src, action])

    def _add_drop_rule(self, datapath, parser, eth_src, idle_timeout, hard_timeout):
        """Add an OpenFlow rule to drop packets from a source."""
        ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=eth_src)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=10,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)
        self.logger.info(f"Added drop rule for {eth_src} (Idle: {idle_timeout}s, Hard: {hard_timeout}s)")

    def _add_rate_limit_rule(self, datapath, parser, eth_src, rate):
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
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=eth_src)
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

    def _log_to_db(self, timestamp, datapath_id, total_bytes, total_packets, cpu_util, prediction):
        """Log flow statistics to MySQL database."""
        if not self.db:
            return
        try:
            cursor = self.db.cursor()
            sql = """
                INSERT INTO flow_stats (timestamp, datapath_id, total_byte_count,
                total_packet_count, cpu_utilization, prediction)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (timestamp, datapath_id, total_bytes, total_packets, cpu_util, prediction))
            self.db.commit()
            self.logger.debug(f"Logged to DB: {cursor.rowcount} row(s)")
            cursor.close()
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

    def __del__(self):
        """Clean up SSH and database connections."""
        if self.ssh_client:
            self.ssh_client.close()
            self.logger.info("SSH connection closed")
        if self.db:
            self.db.close()
            self.logger.info("DB connection closed")
