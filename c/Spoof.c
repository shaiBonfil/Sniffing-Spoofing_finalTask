#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

#include <stdlib.h>    // for exit failure
#include <linux/tcp.h> // For Sniffing password

#include <ctype.h> // for isprint() check if the character is printable or not

#include <string.h> 

#define ETHER_ADDR_LEN 6
#define EXIT_FAILURE 1
#define MTU 1500

enum {FALSE , TRUE};

/* Ethernet header */

struct ethheader
{
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

/* IP header */

struct ipheader
{

    unsigned char iph_ihl : 4, iph_ver : 4; // IP header length , IP version

    unsigned char iph_tos;      // Type of service
    unsigned short int iph_len; // IP Packet length (data + header)

    unsigned short int iph_ident;                     // Identification
    unsigned short int iph_flag : 3, iph_offset : 13; // Fragmentation flags , Flags offset

    unsigned char iph_ttl;         // Time to Live
    unsigned char iph_protocol;    // Protocol type
    unsigned short int iph_chksum; // IP datagram checksum

    struct in_addr iph_sourceip; // Source IP address
    struct in_addr iph_destip;   // Destination IP address
};

/* ICMP header */

struct icmpheader
{
    unsigned char icmp_type; // ICMP type
    unsigned char icmp_code; // Code for ERROR

    unsigned short int icmp_chksum; // checksum for ICMP header and DATA
    unsigned short int icmp_id; // used for identification the request
    unsigned short int icmp_seq; // swquence number
};

void spoof_RawSocket(struct ipheader* ip)
{
    struct sockaddr_in dest_addr;
    int enable = 1;

    // Creating the Raw Socket.
    int sock = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    if(sock == -1){
        printf("Fail to Create");
        exit(EXIT_FAILURE);
    }
    // Set socket to enable IP_HDRINCL on the socket.
    int set = setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&enable,sizeof(enable));
        if(set == -1){
        printf("Fail to Set Socket");
        exit(EXIT_FAILURE);
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = ip->iph_destip;

    sendto(sock,ip,ntohs(ip->iph_len),0,(struct sockaddr*)&dest_addr,sizeof(dest_addr));

    close(sock);
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

// spoof ICMP, src IP set to 1.2.3.4
int main()
{
    char buffer[MTU];

    memset(buffer, 0, MTU);

    //fill ICMP header
    struct icmpheader *icmp = (struct icmpheader*)(buffer + sizeof(struct ipheader));

    icmp->icmp_type = 8; // ICMP request - type 8
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = calculate_checksum((unsigned short*)icmp, sizeof(struct icmpheader));

    //fill IP header
    struct ipheader *ip = (struct ipheader*)buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 99;
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
    ip->iph_destip.s_addr = inet_addr("10.0.2.4");
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

    //sedn spoofed packet
    spoof_RawSocket(ip);

    return 0;

}