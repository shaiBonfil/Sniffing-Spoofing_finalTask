from scapy.all import *

def print_pkt(pkt):
	pkt.show()

print("~~~ Sniffing... TCP with condition only ~~~")

ls = ['enp0s3']
f = 'tcp and src host 10.0.2.6 and dst port 23'
pkt = sniff(iface=ls,filter=f,prn=print_pkt)
