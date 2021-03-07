from scapy.all import *

def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("Original:")
        print("Source=", pkt[IP].src)
        print("Destination=", pkt[IP].dst)
        a = IP()
        a.src = pkt[IP].dst
        a.dst = pkt[IP].src
        a.ihl = pkt[IP].ihl
        a.ttl = 15

        b = ICMP(type=0,id=pkt[ICMP].id,seq =pkt[ICMP].seq)

        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            spoof = a/b/data
        else:
            spoof = a/b
        print(" Spoofing.. :) ")
        print("NewSrc=" ,a.src)
        print("NewDst=",a.dst)
        send(spoof,verbose=0)

print("~~ Sniffing.. ~~ ")
f = 'icmp and src host 10.0.2.15'
sniff(filter= f,prn=spoof_pkt)

