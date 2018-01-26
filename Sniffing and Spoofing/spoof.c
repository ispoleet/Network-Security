// ------------------------------------------------------------------------------------------------ 
/*  Purdue CS528 - Network Security - Spring 2016
**  Lab 1: Packet Sniffing and Spoofing
**  Kyriakos Ispoglou (ispo)
**
**  Task 2: Packet Spoofing
**
**  This program can send spoofed ICMP echo (ping) packets along with spoofed Ethernet frames. 
**  Source and destination IP and MAC addresses are specified from command line along with packet
**  payload.
**
**  Program can send 3 types of spoofed packets:
**      [1]. ICMP echo packet
**      [2]. Ethernet frames
**      [3]. [1] within [2]
**
**  The way that this program is implemented demonstrates the beauty of encapsulation. Packets,
**  generated independently starting from upper layers and are encapsulated as payload while 
**  we're moving deeper in the stack. With this design, this program can be easily extended to
**  support more types of spoofed packets.
**
**
**   * * * ---===== Command Line Arguments =====--- * * *
**
**      --type      Spoofed packet type (ethernet, ping, all)
**      --payload   Packet payload
**      --src-ip    Source IP address
**      --dst-ip    Destination IP address
**      --src-mac   Source MAC address
**      --dst-mac   Destination MAC address
**      --help      Display this message and exit
**  
**
**   * * * ---===== Examples =====--- * * *
**  
**  * Send a PING packet to 128.10.130.191 coming from 128.10.130.190:
**      ./spoof --payload='This is a bogus payload' --type=ping \
**              --src-ip=128.10.130.190 --dst-ip=128.10.130.191 
**
**  * Send an Ethernet frame to 99:99:99:99:99:99 coming from 01:02:03:04:05:06
**      ./spoof --payload='This is a bogus payload' --type=ethernet \
**              --src-mac=01:02:03:04:05:06 --dst-mac=99:99:99:99:99:99
**
**  * Send an Ethernet frame to 99:99:99:99:99:99 coming from 01:02:03:04:05:06 which
**    encapsulates a ping packet to 128.10.130.191 and comes from 128.10.130.190:
**      ./spoof --payload='This is a bogus payload' --type=all --src-mac=01:02:03:04:05:06 \
**              --dst-mac=99:99:99:99:99:99 --src-ip=128.10.130.190 --dst-ip=128.10.130.191
*/
// ------------------------------------------------------------------------------------------------ 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

/* MACRO declarations */
#define IF  "eth14"                                     // interface to send frames
// convert MAC address from string to bytes
#define mac_addr(a, mac)                \
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &a[0],&a[1],&a[2],&a[3],&a[4],&a[5])

// print usage message
#define PRNT_HELP                                                                   \
    printf( "Usage: %s <attributes> \n"                                             \
                        "\t--type\t\tSpoofed packet type (ethernet, ping, all)\n"   \
                        "\t--payload\tPacket payload\n"                             \
                        "\t--src-ip\tSource IP address\n"                           \
                        "\t--dst-ip\tDestination IP address\n"                      \
                        "\t--src-mac\tSource MAC address\n"                         \
                        "\t--dst-mac\tDestination MAC address\n"                    \
                        "\t--help\t\tDisplay this message and exit\n\n", argv[0] )

/* type/enum definitions */
typedef unsigned char      byte;
typedef unsigned short int word;
typedef struct { byte *d; size_t l; } arr_t;                // buffer + size
enum TYPE {TYPE_ETHERNET, TYPE_ICMPECHO, TYPE_ALL, TYPE_UNDEFINED};
// ------------------------------------------------------------------------------------------------
/*
**  chksum(): Calculate checksum of a specific buffer.
**
**  Arguments: buf (byte*)     : buffer to calculate its checksum
**             buflen (size_t) : buffer's size inb bytes
**
**  Return Value: The buffer's checksum in BIG endian.
*/
uint16_t chksum( byte buf[], size_t buflen )
{
    uint32_t sum = 0, i;                                // checksum, iterator

    if( buflen < 1 ) return 0;                          // if buffer is empty, exit

    for( i=0; i<buflen-1; i+=2 ) sum += *(word*)&buf[i];// add all half-words together  

    if( buflen & 1 ) sum += buf[buflen - 1];            // if you missed last byte, add it

    return ~((sum >> 16) + (sum & 0xffff));             // fold high to low order word
                                                        // return 1's complement
}
// ------------------------------------------------------------------------------------------------
/*
**  mk_ping_pkt(): Generate a ping packet, with a given payload.
**
**  Arguments: payload (arr_t) : Packet payload
**
**  Return Value: An arr_t pointer containing the complete ping packet
*/
arr_t mk_ping_pkt( arr_t payload )
{
    arr_t pkt = { 
        .d = malloc(sizeof(struct icmphdr) + payload.l),
        .l = sizeof(struct icmphdr) + payload.l 
    };
    struct icmphdr *icmph = (struct icmphdr*) pkt.d;


    /* fill ICMP header and calculate checksum on the whole packet */
    icmph->type     = ICMP_ECHO;                        // ICMP echo
    icmph->code     = 0;
    icmph->checksum = 0;                                // set to 0 for now
    
    /* copy packet payload */
    memcpy(&pkt.d[sizeof(struct icmphdr)], payload.d, payload.l);

    icmph->checksum = chksum(pkt.d, pkt.l);             // calc checksum now

    return pkt;                                         // return packet
}
// ------------------------------------------------------------------------------------------------
/*
**  mk_ip_pkt(): Generate an IP packet, with a given payload.
**
**  Arguments: src (char*)     : source IP address
**             dst (char*)     : destination IP address
**             proto (byte)    : upper layer protocol
**             payload (arr_t) : Packet payload
**
**  Return Value: An arr_t pointer containing the complete IP packet
*/
arr_t mk_ip_pkt( char *src, char *dst, byte proto, arr_t payload )
{
    arr_t pkt = { 
        .d = malloc(sizeof(struct iphdr) + payload.l),
        .l = sizeof(struct iphdr) + payload.l
    };
    struct iphdr *iph = (struct iphdr*) pkt.d;

    /* fill IP header */
    iph->version  = 4;
    iph->ihl      = 5;  
    iph->tos      = 0;
    iph->tot_len  = htons(pkt.l);                       // set packet's total length
    iph->id       = htons(9999);                        // set some ID
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = proto;                              // set upper layer protocol
    iph->check    = 0;                                  // set to 0 for now
    iph->saddr    = inet_addr(src);                     // spoofed source IP
    iph->daddr    = inet_addr(dst);                     // target's IP
    iph->check    = chksum(pkt.d, 20);                  // calculate checksum of the header

    /* copy packet payload */
    memcpy(&pkt.d[sizeof(struct iphdr)], payload.d, payload.l);

    return pkt;                                         // return packet
}
// ------------------------------------------------------------------------------------------------
/*
**  mk_eth_frm(): Generate an Ethernet frame, with a given payload.
**
**  Arguments: src (char*)     : source MAC address
**             dst (char*)     : destination MAC address
**             payload (arr_t) : Packet payload
**
**  Return Value: An arr_t pointer containing the complete Ethernet packet
*/
arr_t mk_eth_frm( char *src, char *dst, arr_t payload )
{
    arr_t frm = { 
        .d = malloc(sizeof(struct ether_header) + payload.l),
        .l = sizeof(struct ether_header) + payload.l
    };
    struct ether_header *eh  = (struct ether_header*) frm.d;


    /* fill ethernet header */
    eh->ether_type = htons(ETH_P_IP);                   // ethernet type
    mac_addr(eh->ether_shost, src);                     // spoofed MAC address
    mac_addr(eh->ether_dhost, dst);                     // target  MAC address
    
    /* copy frame payload */
    memcpy(&frm.d[sizeof(struct ether_header)], payload.d, payload.l);

    return frm;                                         // return frame
}
// ------------------------------------------------------------------------------------------------
/*
**  snd_pkt(): Send a (spoofed) IP packet.
**
**  Arguments: dst (char*)     : destination IP address
**             payload (arr_t) : Packet payload
**
**  Return Value: 0 on success, -1 on failure.
*/
int snd_pkt(char *dst, arr_t pkt)
{
    int    sd, on = 1;                                  // raw socket descriptor / flag
    struct sockaddr_in trg_addr = {                     // target's address information
            .sin_zero        = { 0,0,0,0,0,0,0,0 },     // zero this out
            .sin_family      = AF_INET,                 // IPv4
            .sin_port        = 0,                       // ignore this      
            .sin_addr.s_addr = inet_addr(dst)           // set destination address
        };


    /* make a raw socket */
    if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("[-] Error! Cannot create raw socket");
        return -1;
    }

    /* inform kernel that we have added packet headers */
    if( setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0 ) {
        perror("[-] Error! Cannot set IP_HDRINCL");
        return -1;
    }

    /* send spoofed packet (set routing flags to 0) */
    if(sendto(sd, pkt.d, pkt.l, 0, (struct sockaddr*)&trg_addr, sizeof(trg_addr)) < 0){
        perror("[-] Error! Cannot send spoofed packet");
        return -1;
    }
    else 
        printf( "[+] Spoofed IP packet sent successfully!\n");

    return 0;                                           // success!
}
// ------------------------------------------------------------------------------------------------
/*
**  snd_frm(): Send a (spoofed) Ethernet frame.
**
**  Arguments: iface (char*)   : Interface to send frame on
**             dst (char*)     : destination MAC address
**             payload (arr_t) : Packet payload
**
**  Return Value: 0 on success, -1 on failure.
*/
int snd_frm(char *iface, char *dst, arr_t frm)
{
    struct ifreq       ifidx = { 0 };                   // interface index
    struct sockaddr_ll trg_addr;                        // target address
    int    sd;                                          // raw socket descriptor

        
    /* make a raw socket */
    if((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {   
        perror("[-] Error! Cannot create raw socket");
        return -1;
    }

    /* Get the index of the interface to send on */
    strncpy(ifidx.ifr_name, iface, strlen(iface));      // set interface name
    if( ioctl(sd, SIOCGIFINDEX, &ifidx) < 0 ) {         // get interface index
        perror("[-] Error! Cannot get interface index");
        return -1;
    }

    trg_addr.sll_ifindex = ifidx.ifr_ifindex;           // interface index
    trg_addr.sll_halen   = ETH_ALEN;                    // address length
    mac_addr(trg_addr.sll_addr, dst);                   // set target MAC address
    
    
    /* send spoofed packet (set routing flags to 0) */
    if(sendto(sd, frm.d, frm.l, 0, (struct sockaddr*)&trg_addr, sizeof(struct sockaddr_ll)) < 0) {
        perror("[-] Error! Cannot send spoofed frame");
        return -1;
    }
    else
        printf( "[+] Spoofed Ethernet frame sent successfully!\n");

    return 0;                                           // success!
}
// ------------------------------------------------------------------------------------------------
/*
**  main(): Our main function.
**
**  Return Value: 0 on success, -1 on failure.
*/
int main( int argc, char *argv[] )
{
    struct option longopt[] = {
        /* short options are dummy. Hide them from user and use only the long ones. */
        {"type",    required_argument, 0, 'a'},
        {"src-ip",  required_argument, 0, 'b'},
        {"dst-ip",  required_argument, 0, 'c'},
        {"src-mac", required_argument, 0, 'd'},
        {"dst-mac", required_argument, 0, 'e'},
        {"payload", required_argument, 0, 'p'},
        {"help",    no_argument,       0, 'h'},
        {0,         0,                 0,  0 }
    };

    char  *srcip=NULL, *dstip=NULL, *srcmac=NULL, *dstmac=NULL, *payload=NULL;
    int   type, opt, longidx = 0;
    arr_t pkt = { .d = NULL, .l = 0 };


    /* ------------------------------------------------------------------------
     * Parse arguments
     * ------------------------------------------------------------------------ */      
    printf( "+--------------------------------------------------+\n"
            "|      PURDUE Univ. CS528 - Network Security       |\n"
            "|       Lab 1: Packet Sniffing and Spoofing        |\n"
            "|  Task 2: Spoof Ping packets and Ethernet frames  |\n"             
            "+--------------------------------------------------+\n\n" );

    /* parse options: for each option... */
    /* payload is not important for this program. We assume it's NULL terminating */
    while( (opt = getopt_long(argc, argv, "a:b:c:d:e:h", longopt, &longidx)) != -1) 
        switch(opt) 
        {           
            case 'a':
                     if( !strcmp(optarg, "ethernet")) type = TYPE_ETHERNET;
                else if( !strcmp(optarg, "ping")    ) type = TYPE_ICMPECHO;
                else if( !strcmp(optarg, "all")     ) type = TYPE_ALL;
                else                                  type = TYPE_UNDEFINED;
                break;      

            case 'b': srcip  = optarg; break;
            case 'c': dstip  = optarg; break;
            case 'd': srcmac = optarg; break;
            case 'e': dstmac = optarg; break;
            case 'p': pkt.d  = optarg; pkt.l = strlen(optarg); break;
            default : PRNT_HELP; return -1;             // failure
        }

    if( !pkt.d ) { PRNT_HELP; return -1; }
    
    /* ------------------------------------------------------------------------
     * Create and send packet
     * ------------------------------------------------------------------------ */
    switch( type )                                      // what packet to spoof?
    {
        // --------------------------------------------------------------------
        case TYPE_ALL:                                  // send Ethernet + ping
            if( !srcmac || !dstmac || !srcmac|| !dstmac ) { PRNT_HELP; return -1; }

            /* Create and send an Ethernet frame with an ICMP ECHO packet as a payload. */
            /* Note the beauty of encapulation */
            return snd_frm(IF, 
                        dstmac, 
                        mk_eth_frm(srcmac, dstmac, 
                            mk_ip_pkt(srcip, dstip, IPPROTO_ICMP, mk_ping_pkt(pkt)))
                    );
        // -------------------------------------------------------------------- 
        case TYPE_ICMPECHO:                             // send ICMP echo
            if( !srcip || !dstip ) { PRNT_HELP; return -1; }

            /* Create and send ICMP ECHO packet */
            return snd_pkt(dstip, mk_ip_pkt(srcip, dstip, IPPROTO_ICMP, mk_ping_pkt(pkt)));
        // --------------------------------------------------------------------
        case TYPE_ETHERNET:                             // send Ethernet
            if( !srcmac || !dstmac ) { PRNT_HELP; return -1; }

            return snd_frm(IF, dstmac, mk_eth_frm(srcmac, dstmac, pkt) );
        // --------------------------------------------------------------------
        case TYPE_UNDEFINED:
        default:
            PRNT_HELP;
        // --------------------------------------------------------------------
    }

    /// TODO: Release allocated memory

    return 0;                                           // success!
}
// ------------------------------------------------------------------------------------------------
