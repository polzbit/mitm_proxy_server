
from twisted.internet import protocol
from proxy.proxy_protocols import TCPProxyProtocol

class TCPFactory(protocol.ServerFactory):
    ''' Factory for tcp communication '''
    protocol = TCPProxyProtocol
    def __init__(self, dst_ip, dst_port, ssl=True):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.ssl = ssl