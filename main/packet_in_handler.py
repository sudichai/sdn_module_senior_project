#packet_in_handler.py

from datetime import datetime
from ryu.lib.packet import packet, ethernet, ipv4, icmp, tcp, udp
from ryu.lib.packet import ether_types, arp
from ryu.ofproto import ofproto_v1_3

class PacketInHandler:
    def __init__(self, logger, mac_to_port):
        self.logger = logger
        self.mac_to_port = mac_to_port

    def handle_packet_in(self, ev):
        msg = ev
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst
        
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src_mac] = in_port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
            #print(out_port)
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
        
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                src_ipv4 = ip.src
                dst_ipv4 = ip.dst
                protocol = ip.proto

                match = None
                if protocol == 1:  # ICMP
                    icmp_pkt = pkt.get_protocol(icmp.icmp)
                    if icmp_pkt:
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,eth_dst=dst_mac, eth_src=src_mac,
                                                ip_proto=protocol)#,in_port=in_port) #icmpv4_type=icmp_pkt.type )
                elif protocol == 6:  # TCP
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    if tcp_pkt:
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,eth_dst=dst_mac, eth_src=src_mac,
                                                ip_proto=protocol)#,in_port=in_port)
                                                #tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port, 
                elif protocol == 17:  # UDP
                    udp_pkt = pkt.get_protocol(udp.udp)
                    if udp_pkt:
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,eth_dst=dst_mac, eth_src=src_mac,
                                                ip_proto=protocol)#,in_port=in_port)
                                                #udp_src=udp_pkt.src_port, udp_dst=udp_pkt.dst_port, 
                else:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port)
                    
                if match:           
                    self.add_flow(datapath, 1, match, actions, hard_timeout=30, idle_timeout=20)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        

    def add_flow(self, datapath, priority, match, actions, hard_timeout, idle_timeout):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                hard_timeout=hard_timeout, idle_timeout=idle_timeout)
        datapath.send_msg(mod)
