
from twisted.internet import protocol, reactor
from twisted.internet import ssl as twisted_ssl
from dns.resolver import Resolver

class TCPProxyProtocol(protocol.Protocol):
    """
        Listens for TCP connection from client device and forward it to specified destination (service API server) 
        over a second TCP connection, using a ProxyToServerProtocol.
        If ssl False it assumes that data is not encrypted.
        else it assumes that both ends are encrypted using TLS.
    """
    def __init__(self):
        self.buffer = None
        self.proxy_to_server_protocol = None
 
    def connectionMade(self):
        """
            Called when a client connects to proxy. 
            Makes connection from proxy to server.
        """
        print("[*] Connection made from CLIENT -> PROXY")
        proxy_to_server_factory = protocol.ClientFactory()
        proxy_to_server_factory.protocol = ProxyToServerProtocol
        proxy_to_server_factory.server = self

        if self.factory.ssl:
            reactor.connectSSL(self.factory.dst_ip, self.factory.dst_port, proxy_to_server_factory, twisted_ssl.CertificateOptions())
        else:
            reactor.connectTCP(self.factory.dst_ip, self.factory.dst_port, proxy_to_server_factory)
 
    def dataReceived(self, data):
        """
            Called when proxy receives data from client. 
            Sends data to  server.
            CLIENT -> PROXY -> SERVER
        """
        print("[*] CLIENT -> SERVER")
        print(data)
        if self.proxy_to_server_protocol:
            self.proxy_to_server_protocol.write(data)
        else:
            self.buffer = data
 
    def write(self, data):
        self.transport.write(data)
 
class ProxyToServerProtocol(protocol.Protocol):
    """
        Connects to server over TCP connection.
        It sends data to server from TLSTCPProxyProtocol, 
        and use TLSTCPProxyProtocol to send response from server to client.
    """
    def connectionMade(self):
        """
            Called when proxy connects to server.  
            flush proxy buffer to the server.
        """
        print("[*] Connection made from PROXY -> SERVER")
        self.factory.server.proxy_to_server_protocol = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''
 
    def dataReceived(self, data):
        """
            Called when proxy receives data from server. 
            Sends data to client.
            SERVER -> PROXY -> CLIENT
        """
        print("[*] SERVER -> CLIENT")
        print(data)
        self.factory.server.write(data)
 
    def write(self, data):
        if data:
            self.transport.write(data)



