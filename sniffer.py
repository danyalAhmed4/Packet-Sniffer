#!/usr/bin/env python3
"""
Network Sniffer - A Python tool for capturing and analyzing network traffic.
Uses Scapy library - works with Npcap/WinPcap on Windows.

Usage:
    python sniffer.py [options]

Note: Install Npcap (https://npcap.com) on Windows for best results.
      Install with "Install Npcap in WinPcap API-compatible Mode" option.

Author: Network Security Tool
"""

try:
    from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, conf
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import argparse
import datetime
import json
from collections import defaultdict
import time


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class PacketAnalyzer:
    """Analyzes captured network packets."""
    
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.bandwidth = defaultdict(int)
        self.start_time = time.time()
    
    def update_stats(self, protocol, src_ip, dst_ip, src_port=None, dst_port=None, size=0):
        """Update packet statistics."""
        self.packet_count += 1
        self.protocol_stats[protocol] += 1
        self.ip_stats[src_ip] += 1
        self.ip_stats[dst_ip] += 1
        self.bandwidth[protocol] += size
        
        if src_port:
            self.port_stats[src_port] += 1
        if dst_port:
            self.port_stats[dst_port] += 1
    
    def get_summary(self):
        """Get a summary of captured traffic."""
        elapsed = time.time() - self.start_time
        return {
            "total_packets": self.packet_count,
            "elapsed_time": f"{elapsed:.2f}s",
            "packets_per_second": f"{self.packet_count / max(elapsed, 1):.2f}",
            "protocols": dict(self.protocol_stats),
            "top_ips": dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_ports": dict(sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
            "bandwidth_by_protocol": {k: f"{v} bytes" for k, v in self.bandwidth.items()}
        }


class NetworkSniffer:
    """Main network sniffer class."""
    
    PROTOCOLS = {
        1: 'ICMP',
        2: 'IGMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        43: 'IPv6-Route',
        44: 'IPv6-Frag',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6',
        59: 'IPv6-NoNxt',
        60: 'IPv6-Opts',
        88: 'EIGRP',
        89: 'OSPF',
        103: 'PIM',
        112: 'VRRP',
        132: 'SCTP',
        136: 'UDPLite'
    }
    
    ETHER_TYPES = {
        0x0800: 'IPv4',
        0x0806: 'ARP',
        0x8035: 'RARP',
        0x809B: 'AppleTalk',
        0x80F3: 'AARP',
        0x8100: 'VLAN',
        0x86DD: 'IPv6',
        0x8847: 'MPLS',
        0x8848: 'MPLS',
        0x8863: 'PPPoE Discovery',
        0x8864: 'PPPoE Session',
        0x88CC: 'LLDP',
        0x88E5: 'MACsec',
        0x88F7: 'PTP',
    }
    
    PORT_NAMES = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP-S', 68: 'DHCP-C',
        69: 'TFTP', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3',
        111: 'RPC', 119: 'NNTP', 123: 'NTP', 135: 'MS-RPC',
        137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
        143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap', 179: 'BGP',
        194: 'IRC', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
        465: 'SMTPS', 500: 'IKE', 514: 'Syslog', 520: 'RIP',
        587: 'SMTP-Sub', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
        1080: 'SOCKS', 1194: 'OpenVPN', 1433: 'MSSQL', 1434: 'MSSQL-UDP',
        1521: 'Oracle', 1701: 'L2TP', 1723: 'PPTP', 1883: 'MQTT',
        2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel-SSL',
        3306: 'MySQL', 3389: 'RDP', 3478: 'STUN', 4443: 'Pharos',
        5060: 'SIP', 5061: 'SIPS', 5222: 'XMPP', 5432: 'PostgreSQL',
        5900: 'VNC', 5938: 'TeamViewer', 6379: 'Redis', 6443: 'K8s-API',
        6667: 'IRC', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
        8883: 'MQTT-SSL', 8888: 'HTTP-Alt', 9000: 'SonarQube',
        9092: 'Kafka', 9200: 'Elasticsearch', 9300: 'ES-Transport',
        11211: 'Memcached', 27017: 'MongoDB', 27018: 'MongoDB',
        50000: 'SAP', 51820: 'WireGuard'
    }
    
    DNS_TYPES = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
        15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR',
        43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 257: 'CAA'
    }
    
    HTTP_METHODS = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', 
                    b'OPTIONS', b'PATCH', b'CONNECT', b'TRACE']
    
    def __init__(self, interface=None, filter_protocol=None, filter_port=None, 
                 verbose=False, output_file=None, packet_limit=None):
        self.interface = interface
        self.filter_protocol = filter_protocol.upper() if filter_protocol else None
        self.filter_port = filter_port
        self.verbose = verbose
        self.output_file = output_file
        self.packet_limit = packet_limit
        self.analyzer = PacketAnalyzer()
        self.running = False
        self.captured_packets = []
        
    def get_port_name(self, port):
        """Get the service name for a port number."""
        return self.PORT_NAMES.get(port, str(port))
    
    def parse_http_data(self, data):
        """Parse HTTP request/response."""
        try:
            if not data:
                return None
            
            for method in self.HTTP_METHODS:
                if data.startswith(method):
                    lines = data.split(b'\r\n')
                    if lines:
                        request_line = lines[0].decode('utf-8', errors='ignore')
                        parts = request_line.split(' ')
                        if len(parts) >= 2:
                            return {
                                'type': 'Request',
                                'method': parts[0],
                                'uri': parts[1][:100], 
                                'version': parts[2] if len(parts) > 2 else 'HTTP/1.0'
                            }
            
            if data.startswith(b'HTTP/'):
                lines = data.split(b'\r\n')
                if lines:
                    status_line = lines[0].decode('utf-8', errors='ignore')
                    parts = status_line.split(' ', 2)
                    if len(parts) >= 2:
                        return {
                            'type': 'Response',
                            'version': parts[0],
                            'status_code': parts[1],
                            'reason': parts[2] if len(parts) > 2 else ''
                        }
            
            return None
        except:
            return None
    
    def should_capture(self, protocol, src_port=None, dst_port=None):
        """Check if packet matches filter criteria."""
        if self.filter_protocol and protocol != self.filter_protocol:
            return False
        if self.filter_port:
            if src_port != self.filter_port and dst_port != self.filter_port:
                return False
        return True
    
    def print_packet_info(self, packet_info):
        """Print formatted packet information."""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        protocol = packet_info.get('protocol', 'UNKNOWN')
        src_ip = packet_info.get('src_ip', 'N/A')
        dst_ip = packet_info.get('dst_ip', 'N/A')
        src_port = packet_info.get('src_port', '')
        dst_port = packet_info.get('dst_port', '')
        
        if protocol == 'TCP':
            color = Colors.GREEN
        elif protocol == 'UDP':
            color = Colors.BLUE
        elif protocol == 'ICMP':
            color = Colors.YELLOW
        elif protocol == 'ARP':
            color = Colors.RED
        elif 'IPv6' in protocol:
            color = Colors.HEADER
        else:
            color = Colors.CYAN
        
        src = f"{src_ip}:{src_port}" if src_port else src_ip
        dst = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
        
        src_service = f" ({self.get_port_name(src_port)})" if src_port and src_port in self.PORT_NAMES else ""
        dst_service = f" ({self.get_port_name(dst_port)})" if dst_port and dst_port in self.PORT_NAMES else ""
        
        extra_info = ""
        if 'arp_opcode' in packet_info:
            extra_info = f" [{packet_info['arp_opcode']}]"
        elif 'dns' in packet_info:
            dns = packet_info['dns']
            extra_info = f" [{dns['type']}: {dns['query_name']} ({dns['query_type']})]"
        elif 'http' in packet_info:
            http = packet_info['http']
            if http['type'] == 'Request':
                extra_info = f" [{http['method']} {http['uri'][:50]}]"
            else:
                extra_info = f" [HTTP {http['status_code']}]"
        
        print(f"{Colors.BOLD}[{timestamp}]{Colors.ENDC} {color}{protocol:8}{Colors.ENDC} "
              f"{src}{src_service} → {dst}{dst_service}{extra_info}")
        
        if self.verbose:
            if 'flags' in packet_info:
                print(f"    Flags: {', '.join(packet_info['flags'])}")
            if 'ttl' in packet_info:
                print(f"    TTL: {packet_info['ttl']}")
            if 'sequence' in packet_info:
                print(f"    Seq: {packet_info['sequence']}, Ack: {packet_info['acknowledgment']}")
            if 'data' in packet_info and packet_info['data']:
                data_preview = packet_info['data'][:100]
                try:
                    decoded = data_preview.decode('utf-8', errors='ignore')
                    if decoded.strip():
                        print(f"    Data: {decoded[:100]}")
                except:
                    pass
            print()
    
    def save_packet(self, packet_info):
        """Save packet to output file."""
        if self.output_file:
            self.captured_packets.append(packet_info)
    
    def print_banner(self):
        """Print startup banner."""
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    NETWORK PACKET SNIFFER                     ║
║                                                               ║
╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}
        """
        print(banner)
        print(f"{Colors.YELLOW}[*] Starting packet capture...{Colors.ENDC}")
        print(f"{Colors.YELLOW}[*] *Note: Requires Npcap installed on Windows{Colors.ENDC}")
        if self.filter_protocol:
            print(f"{Colors.YELLOW}[*] Filtering by protocol: {self.filter_protocol}{Colors.ENDC}")
        if self.filter_port:
            print(f"{Colors.YELLOW}[*] Filtering by port: {self.filter_port}{Colors.ENDC}")
        if self.packet_limit:
            print(f"{Colors.YELLOW}[*] Packet limit: {self.packet_limit}{Colors.ENDC}")
        print(f"{Colors.YELLOW}[*] Press Ctrl+C to stop capturing{Colors.ENDC}")
    
    def print_summary(self):
        """Print capture summary."""
        summary = self.analyzer.get_summary()
        print("\n" + "=" * 70)
        print(f"{Colors.CYAN}{Colors.BOLD}CAPTURE SUMMARY{Colors.ENDC}")
        print("=" * 70)
        print(f"Total Packets Captured: {summary['total_packets']}")
        print(f"Elapsed Time: {summary['elapsed_time']}")
        print(f"Packets/Second: {summary['packets_per_second']}")
        
        print(f"\n{Colors.GREEN}Protocol Distribution:{Colors.ENDC}")
        for proto, count in summary['protocols'].items():
            print(f"  {proto}: {count}")
        
        print(f"\n{Colors.BLUE}Top 10 IP Addresses:{Colors.ENDC}")
        for ip, count in list(summary['top_ips'].items())[:10]:
            print(f"  {ip}: {count} packets")
        
        print(f"\n{Colors.YELLOW}Top 10 Ports:{Colors.ENDC}")
        for port, count in list(summary['top_ports'].items())[:10]:
            service = self.get_port_name(port)
            print(f"  {port} ({service}): {count}")
        
        print(f"\n{Colors.CYAN}Bandwidth by Protocol:{Colors.ENDC}")
        for proto, size in summary['bandwidth_by_protocol'].items():
            print(f"  {proto}: {size}")
        
        if self.output_file and self.captured_packets:
            for pkt in self.captured_packets:
                if 'data' in pkt and isinstance(pkt['data'], bytes):
                    pkt['data'] = pkt['data'].hex()
            
            with open(self.output_file, 'w') as f:
                json.dump({
                    'summary': summary,
                    'packets': self.captured_packets
                }, f, indent=2, default=str)
            print(f"\n{Colors.GREEN}[+] Results saved to {self.output_file}{Colors.ENDC}")
    
    def start_capture(self):
        """Start capturing packets using Scapy."""
        if not SCAPY_AVAILABLE:
            print(f"{Colors.RED}[!] Error: Scapy library is not installed!{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] Install it with: pip install scapy{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] On Windows, also install Npcap from https://npcap.com{Colors.ENDC}")
            return
        
        self.print_banner()
        self.running = True
        
        try:
            # Suppress Scapy warnings
            conf.verb = 0
            
            # Build filter string for Scapy
            bpf_filter = None
            if self.filter_protocol:
                proto_lower = self.filter_protocol.lower()
                if proto_lower in ['tcp', 'udp', 'icmp', 'arp']:
                    bpf_filter = proto_lower
                    if self.filter_port:
                        bpf_filter = f"{proto_lower} port {self.filter_port}"
            elif self.filter_port:
                bpf_filter = f"port {self.filter_port}"
            
            print(f"{Colors.GREEN}[+] Capture started successfully!{Colors.ENDC}")
            if bpf_filter:
                print(f"{Colors.YELLOW}[*] BPF Filter: {bpf_filter}{Colors.ENDC}")
            print("-" * 70)
            
            # Start sniffing with Scapy
            sniff(
                iface=self.interface,
                prn=self.process_scapy_packet,
                filter=bpf_filter,
                count=self.packet_limit if self.packet_limit else 0,
                store=False,
                stop_filter=lambda x: not self.running
            )
                    
        except PermissionError:
            print(f"{Colors.RED}[!] Error: Permission denied!{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] On Windows: Install Npcap from https://npcap.com{Colors.ENDC}")
            print(f"{Colors.YELLOW}[*] Make sure to check 'Install Npcap in WinPcap API-compatible Mode'{Colors.ENDC}")
            return
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Stopping capture...{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.ENDC}")
            if "Npcap" in str(e) or "winpcap" in str(e).lower() or "pcap" in str(e).lower():
                print(f"{Colors.YELLOW}[*] Install Npcap from https://npcap.com{Colors.ENDC}")
        finally:
            self.running = False
            self.print_summary()
    
    def process_scapy_packet(self, packet):
        """Process a packet captured by Scapy."""
        try:
            timestamp = datetime.datetime.now().isoformat()
            packet_info = {
                'timestamp': timestamp,
                'size': len(packet)
            }
            
            # Get MAC addresses if Ethernet layer exists
            if Ether in packet:
                packet_info['src_mac'] = packet[Ether].src.upper()
                packet_info['dst_mac'] = packet[Ether].dst.upper()
            
            # Handle ARP packets
            if ARP in packet:
                arp = packet[ARP]
                arp_opcodes = {1: 'ARP Request', 2: 'ARP Reply'}
                packet_info.update({
                    'protocol': 'ARP',
                    'src_ip': arp.psrc,
                    'dst_ip': arp.pdst,
                    'arp_opcode': arp_opcodes.get(arp.op, f'Unknown({arp.op})')
                })
                
                if self.should_capture('ARP'):
                    self.analyzer.update_stats('ARP', arp.psrc, arp.pdst, size=len(packet))
                    self.print_packet_info(packet_info)
                    self.save_packet(packet_info)
                return
            
            # Handle IPv6 packets
            if IPv6 in packet:
                ipv6 = packet[IPv6]
                packet_info.update({
                    'src_ip': ipv6.src,
                    'dst_ip': ipv6.dst,
                    'protocol': 'IPv6',
                    'hop_limit': ipv6.hlim
                })
                
                if TCP in packet:
                    tcp = packet[TCP]
                    packet_info['protocol'] = 'IPv6/TCP'
                    packet_info['src_port'] = tcp.sport
                    packet_info['dst_port'] = tcp.dport
                    packet_info['flags'] = self._get_tcp_flags(tcp)
                elif UDP in packet:
                    udp = packet[UDP]
                    packet_info['protocol'] = 'IPv6/UDP'
                    packet_info['src_port'] = udp.sport
                    packet_info['dst_port'] = udp.dport
                
                if self.should_capture('IPv6'):
                    self.analyzer.update_stats('IPv6', ipv6.src, ipv6.dst, size=len(packet))
                    self.print_packet_info(packet_info)
                    self.save_packet(packet_info)
                return
            
            # Handle IPv4 packets
            if IP in packet:
                ip = packet[IP]
                proto_name = self.PROTOCOLS.get(ip.proto, f'OTHER({ip.proto})')
                
                packet_info.update({
                    'src_ip': ip.src,
                    'dst_ip': ip.dst,
                    'protocol': proto_name,
                    'ttl': ip.ttl
                })
                
                # Handle TCP
                if TCP in packet:
                    tcp = packet[TCP]
                    packet_info.update({
                        'protocol': 'TCP',
                        'src_port': tcp.sport,
                        'dst_port': tcp.dport,
                        'sequence': tcp.seq,
                        'acknowledgment': tcp.ack,
                        'flags': self._get_tcp_flags(tcp)
                    })
                    
                    # Check for HTTP
                    if Raw in packet and (tcp.sport in [80, 8080, 8000] or tcp.dport in [80, 8080, 8000]):
                        http_info = self.parse_http_data(bytes(packet[Raw].load))
                        if http_info:
                            packet_info['http'] = http_info
                    
                    if self.should_capture('TCP', tcp.sport, tcp.dport):
                        self.analyzer.update_stats('TCP', ip.src, ip.dst, tcp.sport, tcp.dport, len(packet))
                        self.print_packet_info(packet_info)
                        self.save_packet(packet_info)
                
                # Handle UDP
                elif UDP in packet:
                    udp = packet[UDP]
                    packet_info.update({
                        'protocol': 'UDP',
                        'src_port': udp.sport,
                        'dst_port': udp.dport,
                        'udp_size': udp.len
                    })
                    
                    # Check for DNS
                    if DNS in packet and (udp.sport == 53 or udp.dport == 53):
                        dns = packet[DNS]
                        dns_info = {
                            'type': 'Response' if dns.qr else 'Query',
                            'query_name': dns.qd.qname.decode() if dns.qd else 'Unknown',
                            'query_type': self.DNS_TYPES.get(dns.qd.qtype, f'Type{dns.qd.qtype}') if dns.qd else 'Unknown',
                            'questions': dns.qdcount,
                            'answers': dns.ancount
                        }
                        packet_info['dns'] = dns_info
                    
                    if self.should_capture('UDP', udp.sport, udp.dport):
                        self.analyzer.update_stats('UDP', ip.src, ip.dst, udp.sport, udp.dport, len(packet))
                        self.print_packet_info(packet_info)
                        self.save_packet(packet_info)
                
                # Handle ICMP
                elif ICMP in packet:
                    icmp = packet[ICMP]
                    icmp_types = {
                        0: 'Echo Reply', 3: 'Destination Unreachable',
                        4: 'Source Quench', 5: 'Redirect',
                        8: 'Echo Request', 11: 'Time Exceeded'
                    }
                    packet_info.update({
                        'protocol': 'ICMP',
                        'icmp_type': icmp.type,
                        'icmp_type_name': icmp_types.get(icmp.type, 'Unknown'),
                        'code': icmp.code
                    })
                    
                    if self.should_capture('ICMP'):
                        self.analyzer.update_stats('ICMP', ip.src, ip.dst, size=len(packet))
                        self.print_packet_info(packet_info)
                        self.save_packet(packet_info)
                
                # Handle other protocols
                else:
                    if self.should_capture(proto_name):
                        self.analyzer.update_stats(proto_name, ip.src, ip.dst, size=len(packet))
                        self.print_packet_info(packet_info)
                        self.save_packet(packet_info)
                        
        except Exception as e:
            if self.verbose:
                print(f"{Colors.RED}Error processing packet: {e}{Colors.ENDC}")
    
    def _get_tcp_flags(self, tcp):
        """Extract TCP flags from a Scapy TCP packet."""
        flags = []
        if tcp.flags.S: flags.append('SYN')
        if tcp.flags.A: flags.append('ACK')
        if tcp.flags.P: flags.append('PSH')
        if tcp.flags.R: flags.append('RST')
        if tcp.flags.F: flags.append('FIN')
        if tcp.flags.U: flags.append('URG')
        return flags


def main():
    parser = argparse.ArgumentParser(
        description='Network Packet Sniffer - Capture and analyze network traffic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python sniffer.py                          # Capture all traffic
  python sniffer.py -p TCP                   # Capture only TCP traffic
  python sniffer.py -p UDP --port 53         # Capture DNS traffic
  python sniffer.py -v -o capture.json       # Verbose output, save to file
  python sniffer.py -n 100                   # Capture only 100 packets
        '''
    )
    
    parser.add_argument('-i', '--interface', 
                        help='Network interface to capture on (auto-detect if not specified)')
    parser.add_argument('-p', '--protocol', 
                        choices=['TCP', 'UDP', 'ICMP', 'ARP', 'IPv6', 'ALL',
                                 'tcp', 'udp', 'icmp', 'arp', 'ipv6', 'all'],
                        help='Filter by protocol (TCP, UDP, ICMP, ARP, IPv6, or ALL)')
    parser.add_argument('--port', type=int, 
                        help='Filter by port number')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('-o', '--output', 
                        help='Save captured packets to JSON file')
    parser.add_argument('-n', '--count', type=int,
                        help='Number of packets to capture (unlimited if not specified)')
    
    args = parser.parse_args()
    
    sniffer = NetworkSniffer(
        interface=args.interface,
        filter_protocol=args.protocol,
        filter_port=args.port,
        verbose=args.verbose,
        output_file=args.output,
        packet_limit=args.count
    )
    
    sniffer.start_capture()


if __name__ == '__main__':
    main()
