from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
import threading
import datetime

IP_MAC_PAIRS = {}
ARP_REQ_TABLE = {}

stop_sniffing = False

output_function = print 

def sniff_requests():
    def stop_filter(pkt):
        return stop_sniffing
    sniff(filter='arp', lfilter=outgoing_req, prn=add_req, iface='docker0', stop_filter=stop_filter)

def sniff_replays():
    def stop_filter(pkt):
        return stop_sniffing
    sniff(filter='arp', lfilter=incoming_reply, prn=check_arp_header, iface='docker0', stop_filter=stop_filter)

def incoming_reply(pkt):
    return pkt[ARP].psrc != str(get_if_addr('docker0')) and pkt[ARP].op == 2

def outgoing_req(pkt):
    return pkt[ARP].psrc == str(get_if_addr('docker0')) and pkt[ARP].op == 1

def add_req(pkt):
    ARP_REQ_TABLE[pkt[ARP].pdst] = datetime.datetime.now()

def check_arp_header(pkt):
    if not pkt[Ether].src == pkt[ARP].hwsrc or not pkt[Ether].dst == pkt[ARP].hwdst:
        return alarm('Inconsistent ARP message', pkt[ARP].psrc, pkt[ARP].hwsrc)
    return known_traffic(pkt)

def known_traffic(pkt):
    if pkt[ARP].psrc not in IP_MAC_PAIRS.keys():
        return spoof_detection(pkt)
    elif IP_MAC_PAIRS[pkt[ARP].psrc] == pkt[ARP].hwsrc:
        return
    return alarm('IP-MAC pair change detected', pkt[ARP].psrc, pkt[ARP].hwsrc)

def spoof_detection(pkt):
    ip_ = pkt[ARP].psrc
    t = datetime.datetime.now()
    mac = pkt[0][ARP].hwsrc
    if ip_ in ARP_REQ_TABLE.keys() and (t - ARP_REQ_TABLE[ip_]).total_seconds() <= 5:
        ip = IP(dst=ip_)
        SYN = TCP(sport=40508, dport=40508, flags="S", seq=12345)
        E = Ether(dst=mac)
        if not srp1(E / ip / SYN, verbose=False, timeout=2):
            alarm('Fake IP-MAC pair', ip_, mac)
        else:
            IP_MAC_PAIRS[ip_] = mac
    else:
        send(ARP(op=1, pdst=ip_), verbose=False)

def alarm(alarm_type, ip=None, mac=None):
    message = f'Under Attack - {alarm_type}'
    if ip and mac:
        message += f'. IP: {ip}, MAC: {mac}'
    output_function(message)
    
if __name__ == "__main__":
    req_ = threading.Thread(target=sniff_requests, args=())
    req_.start()
    rep_ = threading.Thread(target=sniff_replays, args=())
    rep_.start()
