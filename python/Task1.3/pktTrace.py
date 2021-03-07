from scapy.all import *
a = IP()
a.dst = '213.8.143.143' #www.one.co.il
a.ttl = 1
for i in range (9):
    b = ICMP()
    send(a/b)
    a.ttl +=1
