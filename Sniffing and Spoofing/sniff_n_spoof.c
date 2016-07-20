// ------------------------------------------------------------------------------------------------ 
/*  Purdue CS528 - Network Security - Spring 2016
**  Lab 1: Packet Sniffing and Spoofing
**  Kyriakos Ispoglou (ispo)
**
**  Task 3: Packet Sniffing & Spoofing
**
**  This program sniffs for ping requests that are destined for a specific host X. Once it finds
**  such a packet, it crafts a fake ping reply, with source address of X and sends back that
**  packet. Thus even if X is down, the end user will receive valid ping replies.
*/
// ------------------------------------------------------------------------------------------------ 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>


/* MACRO declarations */
#define MAX_ETHER       1518                            // max sniffing frame size
#define MAX_FRAMES      64                              // number of frames to sniff
#define SIZE_ETHERNET   14                              // ethernet header is always 14 bytes
#define IF              "eth14"                         // interface to sniff frames
#define PRNT_HELP       printf( "Usage: %s --dst-ip=<Destination IP address>\n\n", argv[0] )

/* type/enum definitions */
typedef unsigned char      byte;
typedef unsigned short int word;
typedef struct { byte *d; size_t l; } arr_t;            // buffer + size

char  *dst_ip = NULL;                                   // spoofed IP address for fake replies
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
**  snd_frm_raw(): Send a (spoofed) Ethernet frame. It's like snd_frm() from spoof.c but destina-
**      tion MAC address is passed as raw bytes and not as a string like  "13:37:be:ef:99:99".
**
**  Arguments: iface (char*)   : Interface to send frame on
**             dst (byte*)     : destination MAC address in RAW format
**             payload (arr_t) : Packet payload
**
**  Return Value: 0 on success, -1 on failure.
*/
int snd_frm_raw(char *iface, byte dst[], arr_t frm)
{
    struct ifreq       ifidx = { 0 };                   // interface index
    struct sockaddr_ll trg_addr;                        // target address
    int    sd, i;                                       // raw socket descriptor

        
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
    
    for( i=0; i<6; ++i ) trg_addr.sll_addr[i] = dst[i]; // set target MAC address
    
    
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
**  sniff_frame(): Pcap callback functions. This function gets called when we sniff a packet that
**      matches with our filter.
**
**  Arguments: args (u_char*)       : User supplied additional arguments
**             header (pcap_pkthdr) : Packet's metadata
**             packet (u_char*)     : Actual packet
**
**  Return Value: None.
*/
void sniff_frame(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int pktcnt = 1;                              // packet counter   
    struct sockaddr_in  ipaddr = {0};
    struct ether_header *eh    = (struct ether_header*) packet;
    struct iphdr        *iph   = (struct iphdr*)   (packet + ETH_HLEN);
    struct icmphdr      *icmph = (struct icmphdr*) (packet + ETH_HLEN + (iph->ihl << 2));
    arr_t  frm;
    

    /* ------------------------------------------------------------------------
     * Print packet information
     * ------------------------------------------------------------------------ */      
    ipaddr.sin_addr.s_addr = iph->saddr;
    printf("[%d] %s -> ", pktcnt, inet_ntoa(ipaddr.sin_addr));

    ipaddr.sin_addr.s_addr = iph->daddr;
    printf("%s. Len %d. ICMP: type %d, code %d\n", 
        inet_ntoa(ipaddr.sin_addr), header->len, icmph->type, icmph->code);


    /* ------------------------------------------------------------------------
     * Check if packet is echo type and its destination is "dst_ip"
     * ------------------------------------------------------------------------ */      
     if( icmph->type == 8 && icmph->code == 0 && iph->daddr == inet_addr(dst_ip) )
     {
        int i, bkp;                                     // some locals

        /* we got a packet for destination X. Send a fake ping reply */
        printf( "[+] Ping request to %s found! Sending a fake response...\n", dst_ip);

        for( i=0; i<6; ++i ) {                          // swap source and destination MACs
            bkp = eh->ether_shost[i];
            eh->ether_shost[i] = eh->ether_dhost[i];
            eh->ether_dhost[i] = bkp;
        }
        
        /*
         * Sending an IP packet doesn't work, because MAC addresses won't be consistent.
         * We have to send an Ethernet frame.
         */

        frm.d = (byte*) eh;                             // get the whole IP packet
        frm.l = ntohs(iph->tot_len) + ETH_HLEN;         // and its length (or header->len)
        
        iph->daddr    = iph->saddr;                     // swap source and destination addresses
        iph->saddr    = inet_addr(dst_ip);
        iph->check    = 0;
        iph->check    = chksum(&frm.d[ETH_HLEN], 20);   // calculate checksum of the header

        icmph->type     = 0;                            // change type to echo reply
        icmph->checksum = 0;                            // set to 0 for now     
        icmph->checksum = chksum((byte*)icmph, (header->len-(iph->ihl << 2)-ETH_HLEN) );

        snd_frm_raw(IF, eh->ether_dhost, frm);          // send fake reply
     }
    
    ++pktcnt;                                           // increment packet counter
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
        {"dst-ip",  required_argument, 0, 's'}, 
        {"help",    no_argument,       0, 'h'},
        {0,         0,                 0,  0 }
    };

    int    type, opt, longidx = 0;                      // auxiliary vars
    char   errbuf[PCAP_ERRBUF_SIZE];                    // error buffer
    struct bpf_program fp;                              // filter program   
    pcap_t *hndl;                                       // sniffing handle
    
    /* ------------------------------------------------------------------------
     * Parse arguments
     * ------------------------------------------------------------------------ */      
    printf( "+--------------------------------------------------+\n"
            "|      PURDUE Univ. CS528 - Network Security       |\n"
            "|       Lab 1: Packet Sniffing and Spoofing        |\n"
            "|        Task 3: Sniff & Spoof Ping packets        |\n"             
            "+--------------------------------------------------+\n\n" );

    /* parse options: for each option... */ 
    while( (opt = getopt_long(argc, argv, "s:h", longopt, &longidx)) != -1) 
        switch(opt) {           
            case 's': dst_ip  = optarg; break;
            default : PRNT_HELP; return -1;             // failure
        }

    if( dst_ip == NULL ) { PRNT_HELP; return -1; }      // IP address not set. Abort


    /* ------------------------------------------------------------------------
     * Insert sniffing filters
     * ------------------------------------------------------------------------ */
    /* open devive for sniffing (promiscuous mode is required!) */
    if( (hndl = pcap_open_live(IF, MAX_ETHER, 1, 100, errbuf)) == NULL ) {  
        fprintf(stderr, "[-] Error! Cannot open device: %s\n", errbuf);
        return -1;
    } 

    /* compile our ICMP filter expression */
    if( pcap_compile(hndl, &fp, "icmp", 0, 0) == -1 )   {
        fprintf(stderr, "[-] Error! Cannot process filter: %s\n", pcap_geterr(hndl));
        return -1;
    }

    /* apply filter */
    if( pcap_setfilter(hndl, &fp) == -1 ) {
        fprintf(stderr, "[-] Error! Cannot install filter: %s\n", pcap_geterr(hndl));
        return -1;
    }

    printf("[+] Sniffing on device %s\n", IF);
    
    pcap_loop(hndl, MAX_FRAMES, sniff_frame, NULL);     // set callback function 
                                                        //   and start sniffing 
    /* ------------------------------------------------------------------------
     * Clean up
     * ------------------------------------------------------------------------ */
    pcap_freecode(&fp);                                 // free BPF program
    pcap_close(hndl);                                   // close handle
    
    printf("[+] Sniffing complete\n" );

    return 0;                                           // success!
}
// ------------------------------------------------------------------------------------------------
