'''
MITM Proxy server - a cli tool to catch tcp traffic between target device and a remote server. 
'''
from argparse import ArgumentParser, RawTextHelpFormatter
from scapy.all import IFACES
from time import sleep
from dns_spoofer.dns_spoofer import DNS_Spoofer
from ca.cert_auth import CertificateAuthority
from proxy.proxy_server import ProxyServer

def getParse():
    ''' CLI Parsing Function '''
    # setup argument parser
    parser = ArgumentParser(
        description='MITM tool to setup proxy server with fake dns authenticator to middle between target device and running service.', 
        formatter_class=RawTextHelpFormatter
    )
    subs = parser.add_subparsers(dest='mode')
    # parser nic scan setup
    scan_parser = subs.add_parser('nic-scan', help='Show network interface cards (NICs).\n\n')

    # parser ca setup
    ca_parser = subs.add_parser('ca', help='Generate certificate files:\n - [-p] Path for new certificate.\n - [-n] Certificate authority name.\n\n')
    ca_parser.add_argument('-p', '--path', dest='path', help='Enter path for certificate file (ext .pem).', default="./cert.pem")
    ca_parser.add_argument('-n', '--name', dest='name', help='Enter authority name.', default="Certificates and Sons Corp")

    # parser observe setup
    obs_parser = subs.add_parser('observe', help='Observe network and targets:\n - [-i] Enter network interface index.\n - [-a] Arp scan network for targets.\n - [-t] Enter selected target.\n\n')
    obs_parser.add_argument('-i', '--interface', dest='interface', help='Enter NIC interface index.', type=int, default=16, required=True)
    obs_parser.add_argument('-t', '--target', dest='target', help='Enter target device ip address.')
    obs_parser.add_argument('-a', '--arp', dest='arp', help='Find target using arp scan.', action='store_true')

    # parser proxy setup
    proxy_parser = subs.add_parser('proxy', help='Proxy server setup:\n - [-i] Enter network interface index.\n - [-t] Enter selected target.\n - [-d] Enter target service domain.\n - [-s] Enter target service subdomains (optoinal).\n\n')
    proxy_parser.add_argument('-i', '--interface', dest='interface', help='Enter NIC interface index.', type=int, default=16, required=True)
    proxy_parser.add_argument('-t', '--target', dest='target', help='Enter target device ip address.', required=True)
    proxy_parser.add_argument('-d', '--domain', dest='domain', help='Enter target domain hostname.', required=True)
    proxy_parser.add_argument('-s', '--subdomains', dest='subdomains', nargs='*', help='Enter target subdomains.', type=list, default=[])

    # check arguments
    args = parser.parse_args()
    
    if args.mode == 'ca':
        # Generate cetifcate file
        CertificateAuthority.generate_certificate(args.path, args.name)
    elif args.mode == 'nic-scan':
        # Print nics info
       IFACES.show()
    elif args.mode == 'observe' and args.arp:
        # Print arp scan results
        target = args.target
        target_nic_index = args.interface
        dns_server = DNS_Spoofer(target, target_domain='',iface_index=target_nic_index)
        clients = dns_server.arp_scan()
        print(clients)
    elif args.mode == 'observe' and validateIp(args.target):
        # Start target services analysis
        try:
            target = args.target
            target_nic_index = args.interface
            dns_server = DNS_Spoofer(target, target_domain='',iface_index=target_nic_index)
            dns_server._run_observer()
            while True:
                sleep(100)
        except KeyboardInterrupt:
            dns_server._stop()
    elif args.mode == 'observe' and not validateIp(args.target):
        # Print error
        parser.error('[!] Specify target device IP address --help for more information')
    elif args.mode == 'proxy' and validateIp(args.target) and validateHost(args.domain):
        # Start target service tls analysis
        try:
            target = args.target
            host = args.domain
            host_subdomains = args.subdomains
            target_nic_index = args.interface
            dns_server = DNS_Spoofer(target, target_domain=host, subdomains=host_subdomains ,iface_index=target_nic_index)
            proxy_server = ProxyServer(dns_server.SERVER_IP, host)
            dns_server._run_handler()
            proxy_server._run()
            while True:
                sleep(100)
        except KeyboardInterrupt:
            dns_server._stop()
            proxy_server._stop()
    else:
        parser.error('[!] Specify target device IP address and target hostname --help for more information')
    
    
def validateIp(ip):
    ''' IP Validator '''
    return ip != '' and ip != None

def validateHost(host):
    ''' Host Validator '''
    return host != '' and host != None

def main():
    getParse()
    import sys
    sys.exit(0)
    
if __name__ == "__main__":
    main()