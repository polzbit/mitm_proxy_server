
from twisted.internet import ssl as twisted_ssl
from dns.resolver import Resolver
from threads.tcp_listener_thread import TCPListener
from ca.cert_auth import CertificateAuthority
from proxy.proxy_factories import TCPFactory

class ProxyServer:
    ''' Proxy communication manager to handle tcp ssl or normal traffic '''
    def __init__(self, server_ip, target_host, ca_name="Certificates and Sons Corp", cert_path="./cert.pem"):
        self.SERVER_IP = server_ip
        self.target_host = target_host
        self.CA_NAME = ca_name
        self.CA_CERT_PATH = cert_path
        self.TLS_LISTEN_PORT = 4434
        self.TLS_DST_PORT = 443
        self.LISTEN_PORT = 80
        self.ssl_factory = TCPFactory(self.SERVER_IP, self.TLS_DST_PORT, ssl=True)
        self.tcp_factory = TCPFactory(self.SERVER_IP, self.LISTEN_PORT, ssl=False)
        self.resolver = Resolver()
        self.cert = None
        self.listener = None 

    def print_host_records(self):
        ''' Show target host records '''
        print(f"[*] DNS records for {self.target_host}...")
        a_records = self.resolver.query(self.target_host, 'A')
        print(f"[*] Found {len(a_records)} A records:")
        for r in a_records:
            print(f"[-] {r.address}")

    def sign_cert(self):
        ''' Sign host reacord '''
        # sign certificate
        ca = CertificateAuthority(self.CA_CERT_PATH)
        certfile = ca.sign_certificate(self.target_host)
        # read certificate
        with open(certfile) as f:
            cert = twisted_ssl.PrivateCertificate.loadPEM(f.read())
            return cert
    
    def _run(self):
        ''' Start listener thread '''
        if self.listener == None:
            # generate ca cert if not exists
            CertificateAuthority.generate_certificate(self.CA_CERT_PATH, self.CA_NAME)
            # sign cert host
            self.cert = self.sign_cert()
            # start listener thread
            print(f"[*] Starting Proxy Server...\n[*] Interface: {self.SERVER_IP}\n[*] TLS Port: {self.TLS_LISTEN_PORT}\n[*] TCP Port: {self.LISTEN_PORT}")
            self.listener = TCPListener(self.tcp_factory, self.ssl_factory, self.LISTEN_PORT, self.TLS_LISTEN_PORT, self.SERVER_IP, self.cert)
            self.listener.start()
    
    def _stop(self):
        ''' Stop listener thread '''
        if self.listener != None:
            self.listener.stop()
            print("[*] Proxy Server stopped.")
            self.listener = None