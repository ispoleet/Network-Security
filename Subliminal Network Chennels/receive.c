// ------------------------------------------------------------------------------------------------ 
/*  Purdue CS528 - Network Security - Spring 2016
**  Final Project: Subliminal Network Channels
**  Kyriakos Ispoglou (ispo)
**              _                          _______ 
**             | |                  _     (_______)
**    ___ _   _| |__  ____  _____ _| |_    _       
**   /___) | | |  _ \|  _ \| ___ (_   _)  | |      
**  |___ | |_| | |_) ) | | | ____| | |_   | |_____ 
**  (___/|____/|____/|_| |_|_____)  \__)   \______)
**
**  subnet C - Version 1.0  
**
**
**  receive.c
**
**  This file is the complement of transmit.c. It receives packets from a specific host and 
**  extract the information from the covert channel. Obviously functions here, need to know which
**  covert channel was used in order to extract the correct data.
**
**  Sending these packets might cause the server to reply with bogus requests. In order to fix
**  that we should add some iptables rules to drop responses. We should drop the response (in
**  OUTPUT chain) and not the request (in INPUT chain) because we have to process the packet.
**  We can do this using libiptc, but not on this version. So we manually set the following rules
**  on the server's side (we can apply them on client side too):
**  
**  [1]. Drop PING responses:
**      iptables -A OUTPUT -p icmp --icmp-type echo-reply -d 192.168.1.100 -j REJECT
**
**  [2]. Drop DNS responses (no matter if DNS server is listening or not):
**      iptables -A OUTPUT -p icmp --icmp-type port-unreachable -d 192.168.1.100 -j REJECT
**      iptables -A OUTPUT -p udp --sport 53 -d 192.168.1.100 -j REJECT
**
**  [3]. Drop TCP responses (ACK/RST on bogus SYN)
**      iptables -A OUTPUT -p tcp --tcp-flags ALL ACK,RST -d 192.168.1.100 -j REJECT
**
**
**   * * * ---===== TODO list =====--- * * *
**
**      [1]. Verify the checksums of received packets and make further checks to ensure that
**           packets really contain covert channels (reduce false positives).
**
**      [2]. Use libiptc to set iptables rules automatically
*/
// ------------------------------------------------------------------------------------------------ 
#include "subnetc.h"
#include "transmit.h"                                   // globals for transmission

#define MAX_ETHER           1518                        // max sniffing frame size
#define MAX_FILTER_SZ       64                          // max filter expression size
#define N_FRAMES            16384                       // how many frames to sniff
#define SIZE_ETHERNET       14                          // ethernet header is always 14 bytes
#define MAX_COVERT_CHAN_LEN 128                         // max size of covert channel per packet

pcap_t  *hndl;                                          // sniffing handle

// ------------------------------------------------------------------------------------------------
/*
**  print_ip(): A wrapper of inet_ntoa(). Convert an uint32_t ip to a string. 
**
**  Arguments: ip (uint32_t) : ip address (BIG endian)
**
**  Return Value: A string containing the ip address.
*/
char *print_ip( uint32_t ip )
{ 
    struct in_addr addr = { .s_addr = ip };
    return inet_ntoa(addr);                             // return IP
}

// ------------------------------------------------------------------------------------------------
/*
**  sniff_frame(): Pcap callback functions. This function gets called when we sniff a packet that
**      matches with our filter. Our filter here is a specific destination IP. When a packet 
**      arrives the bits from the covert channels extracted and another callback is called to
**      accumulate them.
**
**  Arguments: args (u_char*)       : User supplied additional arguments (covert channel method)
**             header (pcap_pkthdr) : Packet's metadata
**             packet (u_char*)     : Actual packet
**
**  Return Value: None.
*/
void sniff_frame( u_char *args, const struct pcap_pkthdr *header, const u_char *packet )
{
    static int pktcnt = 1;                              // packet counter   
    
    struct ether_header *eh     = (struct ether_header*) packet;
    struct iphdr        *iph    = (struct iphdr*) (packet + ETH_HLEN);
    
    int     method  = *(uint*)args;                     // get covert channel method        
    byte    buf[ MAX_COVERT_CHAN_LEN ] = { 0 };         // store extarcted bits here
    int     buflen = 16;                                // at least 16 bits from IP ID
    int     k;                                          // iterator
        

    if( iph->ihl != 5 ) {                               // discard IP packets with options
        printf( "[-] Error! IP packet with options found.\n" );
        return;
    }


    /* print packet information */
    //prnt_dbg( DBG_LVL_2, "[+] #%d Got packet from %s.\n", pktcnt, print_ip(iph->saddr) );
    prnt_dbg( DBG_LVL_3, "[+] Packet: " );
    for( k=ETH_HLEN; k<header->len; k++ ) 
        prnt_dbg( DBG_LVL_3, "%02x ", packet[k] & 255 );
    prnt_dbg( DBG_LVL_3, "\n");


    // ------------------------------------------------------------------------
    if( iph->protocol == IPPROTO_ICMP &&                // ICMP packet found
        (method & COVERT_MASK_LOW) == COVERT_ICMP )     //   and method matches?
    {
        struct icmphdr *icmph = (struct icmphdr*) (iph + 1);
        
        
        /* check if packet is valid */
        if( !icmph->code &&
            (
                icmph->type == ICMP_ECHO      && (method & COVERT_MASK_HIGH) == COVERT_REQ ||
                icmph->type == ICMP_ECHOREPLY && (method & COVERT_MASK_HIGH) == COVERT_RESP
            )
        ) ;
        else {
            printf( "[-] Error! Invalid ICMP packet.\n" );
            return;
        }

        /* no covert channel in ICMP. Do nothing */
    }
    // ------------------------------------------------------------------------
    else if( iph->protocol == IPPROTO_TCP &&            // TCP packet found?
             (method & COVERT_MASK_LOW) == COVERT_TCP ) //   and method matches?
    {
        struct tcphdr *tcph = (struct tcphdr*) (iph + 1);


        /* check if packet is valid */
        if( tcph->syn && (method & COVERT_MASK_HIGH & ~COVERT_NAT) == COVERT_REQ ||
            tcph->ack && tcph->rst && (method & COVERT_MASK_HIGH & ~COVERT_NAT) == COVERT_RESP ) ;
        else {          
            printf( "[-] Error! Invalid TCP packet.\n" );
            
            return;
        }
                
        unpack(ntohl(tcph->seq),    32, &buf[16]);      //   and 32 bits from sequence number
        buflen += 32;                                   // set buffer length

        if( !(method & COVERT_NAT) ) {
            unpack(ntohs(tcph->source), 14, &buf[48]);  // extract 14 bits from source port
            buflen += 14;
        }       
    }
    // ------------------------------------------------------------------------
    else if( iph->protocol == IPPROTO_UDP &&            // UDP packet found?
             (method & COVERT_MASK_LOW) == COVERT_DNS ) //   and method matches?
    {
        struct udphdr *udph = (struct udphdr*) (iph + 1);
        struct dnshdr *dnsh = (struct dnshdr*) (udph + 1);


        dnsh->ques_cnt = ntohs(dnsh->ques_cnt);         // change endianess
        dnsh->ansr_cnt = ntohs(dnsh->ansr_cnt);
        dnsh->ns_cnt   = ntohs(dnsh->ns_cnt);


        if( ntohs(udph->dest) == DNS_DPORT &&           // DNS packet?
            dnsh->ques_cnt == 1 &&                      // 1 question
            (
                !dnsh->ansr_cnt && !dnsh->ns_cnt &&
                    (method & COVERT_MASK_HIGH & ~COVERT_NAT) == COVERT_REQ 
                ||
                dnsh->ansr_cnt == 1 && dnsh->ns_cnt == 1 && 
                    (method & COVERT_MASK_HIGH & ~COVERT_NAT) == COVERT_RESP
            ) 
        ) ;
        else {
            printf( "[-] Error! Invalid UDP/DNS packet.\n" );
            return;
        }

    
        unpack(ntohs(dnsh->id), 16, &buf[16]);          //   and 16 bits from sequence number
        buflen += 16;                                   // set buffer length

        if( !(method & COVERT_NAT) ) {
            unpack(ntohs(udph->source), 14, &buf[32]);  // extract 14 bits from source port
            buflen += 14;
        }

    }
    // ------------------------------------------------------------------------
    else {                                              // unknown protocol
        printf( "[-] Error! Unknown protocol (%d) | Covert method mismatch (0x%x).\n", 
                iph->protocol, method );
        return;
    }
    // ------------------------------------------------------------------------


    /* assume that received packet is valid. Extract data from covert channel */
    unpack(ntohs(iph->id), 16, buf);                    // extract IP ID too
    accumulate( buf, buflen );                          // accumulate buffer

    ++pktcnt;                                           // increment packet counter
}

// ------------------------------------------------------------------------------------------------
/*
**  alarm_handler(): Handler for SIGALRM.
**
**  Arguments: sig (int) : signal number
**
**  Return Value: None.
*/
void alarm_handler( int sig )
{
    pcap_breakloop( hndl );                             // stop sniffing

    prnt_dbg( DBG_LVL_1, "[+] Stop sniffing...\n" );
}

// ------------------------------------------------------------------------------------------------
/*
**  receive(): This functions waits for packets that have a covert channel from a remote host.
**      Because pcap_loop() is called, this function works with callbacks. 
**
**  Arguments: iface (char*) : interface to start sniffing
**             dstip (char*) : destination IP address
**             nbrk (int)    : for how many seconds to sniff
**             method (int)  : covert channel method that used for transmission
**
**  Return Value: 0 on success, -1 on failure.
*/
int receive( char *iface, char *dstip, int nbrk, int method )
{
    struct  bpf_program fp;                             // filter program   
    char    errbuf[PCAP_ERRBUF_SIZE],                   // error buffer
            filter[MAX_FILTER_SZ] = { 0 };              // filter expression


    if( !iface || !dstip ) return -1;                   // check arguments
        

    /* set filter expression: accept traffic only from a specific host */
    snprintf(filter, MAX_FILTER_SZ, "src host %s", dstip);


    /* open device for sniffing (promiscuous mode is required!) */
    if( (hndl = pcap_open_live(iface, MAX_ETHER, 1, 100, errbuf)) == NULL ) {   
        fprintf(stderr, "[-] Error! Cannot open device: %s\n", errbuf);
        return -1;
    } 

    /* compile our ICMP filter expression */
    if( pcap_compile(hndl, &fp, filter, 0, 0) == -1 )   {
        fprintf(stderr, "[-] Error! Cannot process filter: %s\n", pcap_geterr(hndl));
        return -1;
    }

    /* apply filter */
    if( pcap_setfilter(hndl, &fp) == -1 ) {
        fprintf(stderr, "[-] Error! Cannot install filter: %s\n", pcap_geterr(hndl));
        return -1;
    }

    prnt_dbg( DBG_LVL_1, "[+] Sniffing on device %s\n", iface );
    prnt_dbg( DBG_LVL_0, "[+] At any time press Ctrl+C to stop sniffing and continue processing.\n" );

    alarm( nbrk );                                      // set an alarm
    signal( SIGALRM, alarm_handler );                   //   and its handler
    signal( SIGINT,  alarm_handler );                   // ^C should also stop

    /* set callback function and start sniffing */
    pcap_loop(hndl, N_FRAMES, sniff_frame, (void*)&method); 


    /* Clean up */
    pcap_freecode(&fp);                                 // free BPF program
    pcap_close(hndl);                                   // close handle
    
    prnt_dbg( DBG_LVL_1, "[+] Sniffing complete\n" );

    return 0;                                           // success!
}
// ------------------------------------------------------------------------------------------------
