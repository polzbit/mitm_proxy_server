from scapy.all import sniff
from threading import Thread, Event

class Sniffer(Thread):
    ''' Thread for incommig dns requests '''
    def  __init__(self, interface, sniff_filter, packet_handler, fin_action):
        super().__init__()
        self.interface = interface
        self.SNIFF_FILTER = sniff_filter
        self.packet_handler = packet_handler
        self.stop_sniffer = Event()
        self.fin_action = fin_action

    def run(self):
        ''' Run Thread '''
        sniff(prn=self.packet_handler, filter=self.SNIFF_FILTER, store=False, stop_filter=self.is_stopped, iface=self.interface)

    def stop(self, timeout=None):
        ''' Stop Thread '''
        self.stop_sniffer.set()
        self.fin_action()
        super().join(timeout)

    def is_stopped(self, packet):
        return self.stop_sniffer.isSet()

