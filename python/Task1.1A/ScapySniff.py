from scapy.all import *


def print_pkt(pkt):
    pkt.show()
print("~~~Sniffing...~~~")
pkt = sniff(iface='enp0s3', filter='icmp', prn=print_pkt)
