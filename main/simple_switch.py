from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from packet_in_handler import PacketInHandler
from switch_features_handler import SwitchFeaturesHandler
from flow_stats_handler import FlowStatsHandler 

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.switch_features_handler = SwitchFeaturesHandler(self.logger)
        self.packet_in_handler = PacketInHandler(self.logger, self.mac_to_port)
        self.flow_stats_handler = FlowStatsHandler(self.logger)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler_wrapper(self, ev):
        """Handle switch features event."""
        self.switch_features_handler.handle_switch_features(ev.msg.datapath)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        """Track datapath connections."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.flow_stats_handler.datapaths[datapath.id] = datapath  
        elif ev.state == CONFIG_DISPATCHER:
            self.flow_stats_handler.datapaths.pop(datapath.id, None) 

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler_wrapper(self, ev):
        """Handle packet-in events."""
        self.packet_in_handler.handle_packet_in(ev.msg)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow stats reply events."""
        self.flow_stats_handler.flow_stats_reply_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Handle port stats reply events."""
        self.flow_stats_handler._port_stats_reply_handler(ev)
