
from threading import Thread
from twisted.internet import reactor, error

class TCPListener(Thread):
    ''' Thread for incommig tcp communication '''
    def  __init__(self, factory, ssl_factory, port, ssl_port, iface_addr, cert):
        super().__init__()
        self.factory = factory
        self.ssl_factory = ssl_factory
        self.LISTEN_PORT = port
        self.SSL_PORT = ssl_port
        self.cert = cert
        self.SERVER_IP = iface_addr
        self.running = False

    def run(self):
        ''' Run Thread '''
        try:
            self.running = True
            reactor.listenTCP(self.LISTEN_PORT, self.factory, interface=self.SERVER_IP)
            reactor.listenSSL(self.SSL_PORT, self.ssl_factory, self.cert.options(), interface=self.SERVER_IP)
            reactor.run(installSignalHandlers=False)    # installSignalHandlers=False, disable signl library error when runnng in thread
        except error.CannotListenError:
            self.running = False
            print(f'[!] Interface {self.SERVER_IP} not set correctly.')

    def stop(self, timeout=None):
        ''' Stop Thread '''
        if self.running:
            reactor.stop()
            try:
                super().join(timeout)
            except KeyboardInterrupt:
                pass

