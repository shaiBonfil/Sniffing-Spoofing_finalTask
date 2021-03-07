from scapy.all import *

def print_pkt(pkt):
	pkt.show()

print("~~~ Sniffing... ICMP only ~~~)

ls = ['enp0s3']
pkt = sniff(iface=ls,filter='icmp',prn=print_pkt)


