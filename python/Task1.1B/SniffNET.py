from scapy.all import *

def print_pkt(pkt):
	pkt.show()

print("~~~ Sniffing... 128.230.0.0/16" ~~~")

ls = ['enp0s3']
f = 'net 128.230.0.0/16'
pkt = sniff(iface=ls,filter=f,prn=print_pkt)
