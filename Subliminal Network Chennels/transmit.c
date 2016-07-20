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
**  transmit.c
**
**  This file sends some data to a remote destination using covert channels. Three types of 
**  covert channels are available with 2 options in each channel:
**      [1] ICMP covert channel: Use 16 bits from IP ID
**
**      [2] TCP covert channel: Use 16 bits from IP ID + 32 bits from TCP sequence number
**                               + 14 bits from TCP source port
**
**      [3] DNS covert channel: Use 16 bits from IP ID + 16 bits from DNS ID + 14 bits from
**                              UDP source port
**
**  Each method can send packets that are exactly like normal packets, except that the values
**  in these fields contain information. Each method can send packets that are 'requests' or
**  'responses'. For instance:
**      [1]. ICMP ping echo and reply
**
**      [2]. TCP SYN and [ACK, RST]
**
**      [3]. DNS query and response (with some dummy addresses)
**
**
**  Note the way that the packets get constructed and how the concept of encapsulation applies 
**  here: Each function implements a protocol and gets as payload the output of a function that
**  implements a higher level protocol.
**
**  Usually the source port should be an ephemeral random port (2 MSBits are set). That's why 
**  we use only 14 out of 16 bits for source port. In the case that at least 1 device is behind 
**  NAT, then source ports will be change by NAT, so can't use these 14 bits (--nat option)
**  Some NATs may also change TCP sequence numbers to make them more secure. In that case the
**  TCP covert channel doesn't work.
**
**  In the best case we can have 62 bits per packet, so the bandwidth is very small.
**
**  In [1], authors suggest to use 24LBits of TCP sequence number and not 32 to make it more
**  stealthy, but here we use the whole 32 bits.
**
**  NOTE: If you do any changes here, don't forget to keep receive.c consistent
**
**  References:
**      [1]. Embedding Covert Channels into TCP/IP:
**           http://sec.cs.ucl.ac.uk/users/smurdoch/papers/ih05coverttcp.pdf
**
**
**   * * * ---===== TODO list =====--- * * *
**
**      [1]. Add more types of packets
**
**      [2]. Check alignment issues in mk_dns_pkt()
**
**      [3]. Fix destination ports in repsponses. TCP response is not exactly the 'answer' to 
**           TCP request: in TCP reply, sequence number should be 0 (when RST is set), and 
**           destination port should be equal with source port on request. The same with DNS.
*/
// ------------------------------------------------------------------------------------------------ 
#include "subnetc.h"
#include "transmit.h"                                   // globals for transmission


#define IPHDR_LEN           sizeof(struct iphdr)        // IP   header length
#define UDPHDR_LEN          sizeof(struct udphdr)       // UDP  header length
#define TCPHDR_LEN          sizeof(struct tcphdr)       // TCP  header length
#define ICMPHDR_LEN         sizeof(struct icmphdr)      // ICMP header length
#define DNSHDR_LEN          sizeof(struct dnshdr)       // DNS  header length

#define PING_PAYLOAD        "\x00\x00\x00\x00\x00\x00\x00\x00"                                 \
                            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" \
                            "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f" \
                            "\x30\x31\x32\x33\x34\x35\x36\x37"
#define PING_PAYLOAD_LEN    0x30                        // don't use sizeof (NULL byte is included)

#define DNS_FLAG_RESP       0x8400                      // flags for DNS response packet
#define DNS_FLAG_QUES       0x0100                      // flags for DNS question packet
#define DUMMY_DOMAIN        "\03foo\05risvc\03net\00"   // a dummy domain 
#define DUMMY_DOMAIN_LEN    15                          //   its length
#define DUMMY_DOMAIN_IP     "99.99.99.99"               //  and it's dummy IP address
#define NS_DOMAIN           "\04myns\05risvc\03net\00"  // a dummy nameserver
#define NS_DOMAIN_LEN       16                          //   and its length

#define DNS_REQUEST         0x10                        // DNS request method (value doesn't matter)
#define DNS_RESPONSE        0x20                        // DNS response method
#define TTL                 86400                       // Time-To-Live (1D)

#define BIG_BUF_LEN         1024                        // a big buffer for temporary storage

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

    for(i=0; i<buflen-1; i+=2) sum += *(word*)&buf[i];  // add all half-words together  

    if( buflen & 1 ) sum += buf[buflen - 1];            // if you missed last byte, add it

    return ~((sum >> 16) + (sum & 0xffff));             // fold high to low order word
                                                        // return 1's complement
}

// ------------------------------------------------------------------------------------------------
/*
**  mk_ip_pkt(): Generate an IP packet, with a given payload. If the upper layer protocol is
**      TCP or UDP, then we also have to caclulate the checksum of the pseudo header, which is
**      part of the upper layer protocol. The pseudo header contains the header and the payload
**      of TCP/UDP plus the following fields from IP: source and destination IP, protocol a 
**      reserved byte (which is 0) and packet's total length.
**
**  Arguments: id (uint16_t*)  : IP ID
**             proto (byte)    : upper layer protocol
**             src (char*)     : source IP address
**             dst (char*)     : destination IP address
**             payload (byte*) : packet payload
**             len (int*)      : payload length (IN/OUT)
**
**  Return Value: A pointer to payload augmented with IP header. len will contain the updated
**      length. If an error occurs, function returns NULL.
*/
byte *mk_ip_pkt( uint16_t id, byte proto, char *src, char *dst, byte *payload, int *len )
{
    struct iphdr *iph;                                  // IP header
    byte *pkt;                                          // packet buffer
    

    if( !(pkt = realloc(payload, IPHDR_LEN + *len)) ) { // extend payload to include IP header
        *len = -1; 
        return NULL; 
    }
    
    memmove(&pkt[IPHDR_LEN], pkt, *len);                // shift payload
    
    *len += IPHDR_LEN;                                  // adjust length
    iph   = (struct iphdr*) pkt;                        // process IP header

    /* ------------------------------------------------------------------------
     * The problem: TCP/UDP checksum is the checksum of the entire TCP/UDP 
     * packet plus a special pseudo-header which contains: src ip, dst ip, a 
     * reserved byte, protocol number and length from TCP/UDP header. Caclulating 
     * checksum of this pseudo-header can end up in really ugly code. A nice 
     * trick is to fill the fields of the pseudo-header in the IP/UDP headers, 
     * leaving all other fields 0 (which is not affect the checksum calculation). 
     *
     * The only problem here is the alignment. However it happens that the fields 
     * in the pseudo-header have the same alignment with the IP/UDP headers, so 
     * we're fine here :)
     * ------------------------------------------------------------------------ 
     */
    bzero(pkt, IPHDR_LEN);                              // zero out header first

    /* fill pseudo-header fields in IP header */
    iph->saddr    = inet_addr(src);                     // source IP (may be spoofed)
    iph->daddr    = inet_addr(dst);                     // destination IP
    iph->protocol = proto;                              // upper layer protocol
    iph->tot_len  = htons(*len - IPHDR_LEN);            // packet's total length
    

    /* time for our trick. pseudo-header is ready. calculate checksum, if needed  */
    if( proto == IPPROTO_UDP ) 
    {
        struct udphdr *udph = (struct udphdr*) (iph + 1);
        
        udph->check = 0;                                // set to 0 for now
        udph->check = chksum(pkt, *len);                // checksum of pseudo-header + payload
    }
    else if( proto == IPPROTO_TCP ) 
    {
        struct tcphdr *tcph = (struct tcphdr*) (iph + 1);

        tcph->check = 0;                                // set to 0 for now
        tcph->check = chksum(pkt, *len);                // checksum of pseudo-header + payload
    }

    
    /* fill the rest of IP header */
    iph->version  = 4;                                  // IPv4
    iph->ihl      = 5;                                  // no options
    iph->tos      = 0;                                  // no QoS
    iph->tot_len  = htons( *len );                      // packet's total length
    iph->id       = htons( id );                        // hide information here
    iph->frag_off = 0;                                  // no fragments
    iph->ttl      = 64;                                 // TTL
    iph->check    = 0;                                  // set to 0 for now
    iph->check    = chksum( pkt, 20 );                  // checksum of the header


    return pkt;                                         // return packet
}

// ------------------------------------------------------------------------------------------------
/*
**  mk_ping_pkt(): Generate a ping packet. To make this packet indistinguishable from normal
**      pings, a fixed payload is given. Note that there's no information leak here. The actual
**      leak is on IP ID. However we should set a payload for that IP packet and an ICMP payload
**      seems pretty good.
**
**  Arguments: type (uint16_t) : ping type (request/response)
**             len (int*)      : packet length (OUT)
**
**  Return Value: A pointer containing the ping packet. len will contain the updated length.
**      NULL on failure.
*/
byte *mk_ping_pkt( uint16_t type, int *len )
{
    byte            *pkt   = calloc( ICMPHDR_LEN + PING_PAYLOAD_LEN, 1 );
    struct icmphdr  *icmph = (struct icmphdr*) pkt;


    if( !pkt ) { *len = -1; return NULL; }              // abort on failure

    /* fill ICMP header and calculate checksum on the whole packet */
    icmph->type     = type;                             // ICMP echo request/reply
    icmph->code     = 0;                                // code is 0 for pings
    icmph->checksum = 0;                                // set to 0 for now


    /* copy packet payload */
    memcpy( &pkt[ICMPHDR_LEN], PING_PAYLOAD, PING_PAYLOAD_LEN );

    *len = ICMPHDR_LEN + PING_PAYLOAD_LEN;              // adjustlength
    icmph->checksum = chksum(pkt, *len);                // calc checksum now

    return pkt;                                         // return packet
}

// ------------------------------------------------------------------------------------------------
/*
**  mk_tcp_pkt(): Generate a TCP control packet (with no payload). This packet will be the payload
**      of an IP packet, so the checksum is not calculated here, but on mk_ip_pkt().
**
**  Arguments: sport (uint16_t) : source port 
**             dport (uint16_t) : destination port
**             seq (uint32_t)   : sequence number
**             ack (uint32_t)   : acknownledgement number
**             len (int*)       : packet length (OUT)
**
**  Return Value: A pointer containing the TCP packet. len will contain the updated length. NULL
**      on failure.
*/
byte *mk_tcp_pkt( uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, byte flags, int *len )
{
    byte            *pkt  = calloc( TCPHDR_LEN, 1 );
    struct tcphdr   *tcph = (struct tcphdr*) pkt;


    if( !pkt ) { *len = -1; return NULL; }              // abort on failure

    *len = TCPHDR_LEN;                                  // set packet length

    tcph->source  = htons( sport );                     // source port
    tcph->dest    = htons( dport );                     // destination port
    tcph->seq     = htonl( seq );                       // sequence number
    tcph->ack_seq = htonl( ack );                       // acknownledgement number
    tcph->doff    = 5;                                  // header size (no options)
    tcph->fin     = (flags & FIN) != 0;                 // flags
    tcph->syn     = (flags & SYN) != 0;                 //
    tcph->rst     = (flags & RST) != 0;                 //
    tcph->psh     = (flags & PSH) != 0;                 //
    tcph->ack     = (flags & ACK) != 0;                 //
    tcph->urg     = (flags & URG) != 0;                 //
    // tcph->ecn     = flags & ECN != 0;
    // tcph->cwr     = flags & ECN != 0;
    tcph->window  = htons( 5840 );                      // max allowed window size
    tcph->check   = 0;                                  // set to 0 for now
    tcph->urg_ptr = 0;                                  // no urgent data
    
    return pkt;                                         // return TCP packet
}

// ------------------------------------------------------------------------------------------------
/*
**  mk_udp_pkt(): Generate a UDP packet with a given payload. As in mk_tcp_pkt(), checksum is not
**      calculated here.
**
**  Arguments: sport (uint16_t) : source port
**             dport (uint16_t) : destination port
**             payload (byte*)  : packet payload
**             len (int*)       : payload length (IN/OUT)
**
**  Return Value: A pointer to payload augmented with UDP header. len will contain the updated 
**      length. NULL on failure.
*/
byte *mk_udp_pkt( uint16_t sport, uint16_t dport, byte *payload, int *len )
{   
    struct udphdr *udph;                                // UDP header
    byte *pkt;                                          // packet buffer
    

    if( !(pkt = realloc(payload, UDPHDR_LEN + *len)) ){ // extend payload to include IP header
        *len = -1; 
        return NULL; 
    }
    
    memmove(&pkt[UDPHDR_LEN], pkt, *len);               // shift down payload to insert headers
    *len += UDPHDR_LEN;                                 // adjust length
    udph  = (struct udphdr*) pkt;                       // UDP header within packet


    /* fill pseudo-header fields in UDP header */
    udph->source = htons(sport);                        // source port
    udph->dest   = htons(dport);                        // destination port
    udph->len    = htons(*len);                         // packet length    
    udph->check  = 0;                                   // 0

    return pkt;                                         // return packet
}

// ------------------------------------------------------------------------------------------------
/*
**  mk_dns_pkt(): Generate A DNS packet. As mk_ping_pkt() the goal here is to create a DNS packet
**      which is indistinguishable from normal DNS requests/responses and hide information in ID
**      field. This function supports only 2 types of DNS messages:
**          1. A DNS request for a dummy domain
**          2. A DNS response for that domain with an A record in it and an dummy authoritative 
**              nameserver RR for that domain.
**
**  Note that the goal is to leak information not to make normal DNS queries.
**
**
**  Arguments: type (byte)   : type of packet (request/response)
**             id (uint16_t) : DNS ID
**             len (int*)    : packet length (OUT)
**
**  Return Value: A pointer containing the DNS packet. len will contain the updated length. NULL
**      on failure.
*/
byte *mk_dns_pkt( uint16_t id, byte type, int *len )
{
    byte            *pkt  = calloc( BIG_BUF_LEN, 1 );   // allocate somethig very big for now
    struct dnshdr   *dnsh = (struct dnshdr*) pkt;       // DNS header


    if( !pkt ) { *len = -1; return NULL; }              // abort on failure

    /* DNS request : 1 question                         */
    /* DNS response: 1 question, 1 answer, 1 nameserver */
    dnsh->id       = htons( id );
    dnsh->flags    = htons( type == DNS_REQUEST ? DNS_FLAG_QUES : DNS_FLAG_RESP );
    dnsh->ques_cnt = htons( 1 );
    dnsh->ansr_cnt = htons( type == DNS_REQUEST ? 0 : 1 );
    dnsh->ns_cnt   = htons( type == DNS_REQUEST ? 0 : 1 );
    dnsh->add_cnt  = htons( 0 );
    *len = DNSHDR_LEN;                                  // set size


    /* set the query first */
    memcpy(&pkt[*len], DUMMY_DOMAIN, DUMMY_DOMAIN_LEN); // copy the domain
    *len += DUMMY_DOMAIN_LEN;

    //  
    // TODO: Check if we have issues with alignment!
    //  
    *(uint16_t*)&pkt[*len]     = htons(A);              // set type
    *(uint16_t*)&pkt[*len + 2] = htons(IN);             //  and class
    *len += 4;                                          // adjust packet's length


    /* set the DNS response (is needed) */
    if( type == DNS_RESPONSE )
    {       
        /* set the answer RR first */
        
        /* 0xc0 -> pointer to a name string
         * 0x0c -> query string is at offset 12 (after DNS header)
         */     
        *(uint16_t*)&pkt[*len]     = htons( 0xc000 | DNSHDR_LEN );
        *(uint16_t*)&pkt[*len + 2] = htons( A   );      // address type
        *(uint16_t*)&pkt[*len + 4] = htons( IN  );      // internet class
        *(uint32_t*)&pkt[*len + 6] = htonl( TTL );      // time to live
        *len += 10;                                     // adjust size


        /* An A RR. rdata is the resolved IP address */
        *(uint16_t*)&pkt[*len + 0] = htons(4);      
        *(uint32_t*)&pkt[*len + 2] = inet_addr(DUMMY_DOMAIN_IP);    
        *len += 6;                                      // adjust size
        

        /* then, set the nameserver RR */
        *(uint16_t*)&pkt[*len]     = htons( 0xc000 | DNSHDR_LEN );
        *(uint16_t*)&pkt[*len + 2] = htons( NS  );      // nameserver type
        *(uint16_t*)&pkt[*len + 4] = htons( IN  );      // internet class
        *(uint32_t*)&pkt[*len + 6] = htonl( TTL );      // time to live
        *len += 10;                                     // adjust size


        /* An NS RR. rdata is the nameserver's domain */
        *(uint16_t*)&pkt[*len] = htons(NS_DOMAIN_LEN+2);// +1 for 1st prepebded byte +1 for NULL
        *len += 2;                                      // adjust size

        memcpy(&pkt[*len], NS_DOMAIN, NS_DOMAIN_LEN);   // copy nameserver domain
        *len += NS_DOMAIN_LEN;                          // adjust length
    }


    /* buffer was too big. Truncate it */
    if( !(pkt = realloc(pkt, *len)) ){ *len = -1; return NULL; }

    return pkt;                                         // return packet
}

// ------------------------------------------------------------------------------------------------
/*
**  snd_pkt(): Send an (possibly spoofed) IP packet.
**
**  Arguments: dst (char*) : destination IP address
**             pkt (byte*) : packet to send
**             len (int)   : packet length
**
**  Return Value: 0 on success, -1 on failure.
*/
int snd_pkt( char *dst, byte *pkt, int len )
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
        close( sd );                                    // close socket
        return -1;
    }

    /* send spoofed packet (set routing flags to 0) */
    if( sendto(sd, pkt, len, 0, (struct sockaddr*)&trg_addr, sizeof(trg_addr)) < 0 ) {
        perror("[-] Error! Cannot send spoofed packet");
        close( sd );                                    // close socket
        return -1;
    }
    else 
    ;// prnt_dbg(DBG_LVL_2, "[+] Raw IP packet sent successfully to %s.\n", dst);

    close( sd );                                        // close socket

    return 0;                                           // success!
}

// ------------------------------------------------------------------------------------------------ 
/*
**  transmit(): Send a small secret through a covert channel. The covert channel here contains
**      some fields in the packet headers which supposed to be random. Packets send through this 
**      function are the same with normal packets, except that the values in the "random" fields 
**      contain the secret bits.
**
**      This function supports 3 types of covert channels:
**          [1]. ICMP packets: 16b in IP ID
**          [2]. TCP packets : 16b in IP ID + 14b in source port + 32b in sequence number = 62b
**          [3]. DNS packets : 16 bits in IP ID + 16 bits in DNS ID = 32 bits
**
**      Each of the above types can either be a "request" packet or a "reply" packet. In case 
**      that we want a bidirectional communication, we the one side sends something (a request)
**      the other side should reply with a response of this request. This way detection is even
**      harder as we mimic the normal traffic.
**
**      Please refer to the beginning of the file for a discussion on why we're using these
**      fields as covert channels
**
**
**  Arguments: secret (byte*) : a binary array containing the secret to send
**             len (int)      : length of that array
**             dstip (char*)  : destination IP address
**             method (int)   : method to use for transmission
**             ack (uint32_t) : TCP ACK number (set to 0). Used only with TCP response method
**
**  Return Value: 0 on success, -1 on failure.
*/
int transmit( byte *secret, int len, char *dstip, int method, uint32_t ack )
{
    static int pktcnt = 1;                              // packet counter   
    byte    *pkt;                                       // generated packet
    byte    proto;                                      // packet protocol
      

    switch( method & COVERT_MASK_HIGH & ~COVERT_NAT ) { // check if exactly 1 upper method is set
        case COVERT_REQ :
        case COVERT_RESP: break;                        // we're ok here            
        default:                                        // 0 or 2 methods set
            printf("[-] Error! transmit(): Invalid method.\n");
            return -1;                                  // failure
    }

        
    /* Note how beautifully we can apply encapsulation :) */
    switch( method & COVERT_MASK_LOW )                  // check lower method
    {
        // --------------------------------------------------------------------
        case COVERT_ICMP:                               // send ICMP packet?            
            proto = IPPROTO_ICMP;                       // set protocol
            pkt   = mk_ping_pkt(method & COVERT_REQ ? ICMP_ECHO : ICMP_ECHOREPLY, &len);            
            break;
        // --------------------------------------------------------------------
        case COVERT_TCP:                                // send TCP packet? (mimic HTTP traffic)
            if( len < 48 + (method & COVERT_NAT ? 0 : 14) ) 
                return -1;                              // check length first 

            proto = IPPROTO_TCP;                        // set protocol
            pkt   = mk_tcp_pkt(                         // make a TCP control packet
                        (method & COVERT_NAT) ?         // leak secret in 14 LSBits of source port
                            TCP_SPORT :                 // if NAT is disabled
                            0xc000 | pack(&secret[48], 14), 
                        TCP_DPORT,                      // destination port is fixed (80)
                        pack(&secret[16], 32),          // the next 32 bits to 
                        ack,                            // acknownledgement number
                        method & COVERT_REQ ? SYN : RST | ACK,
                        &len                            // packet length (fixed)
                    );
            break;
        // --------------------------------------------------------------------
        case COVERT_DNS:                                // send DNS packet?
            if( len < 32 + (method & COVERT_NAT ? 0 : 14) ) 
                return -1;                              // check length first 

            proto = IPPROTO_UDP;                        // set protocol
            pkt   = mk_udp_pkt(                         // make a UDP packet
                        (method & COVERT_NAT) ?         // leak secret in 14 LSBits of source port
                            TCP_SPORT :                 // if NAT is disabled
                            0xc000 | pack(&secret[32], 14), 
                        UDP_DPORT,                      // destination port is fixed (53)
                        mk_dns_pkt(                     // make a DNS packet
                            pack(&secret[16], 16),      // set ID
                            method & COVERT_REQ ? DNS_REQUEST : DNS_RESPONSE, 
                            &len                        // packet length
                        ), 
                        &len                            // packet length
                    );
            break;
        // --------------------------------------------------------------------
        default: printf("[-] Error! transmit(): Invalid method.\n"); return -1;
        // --------------------------------------------------------------------
    }

    /* encapsulate the selection from above in an IP packet */
    pkt = mk_ip_pkt( pack(secret, 16),                  // secret also goes here 
                     proto,                             // set protocol
                     SOURCE_IP,                         // address can be spoofed
                     dstip,                             // destination IP
                     pkt,                               // encapsulate payload from above
                     &len                               // payload length
            );

    //prnt_dbg(DBG_LVL_2, "[+] #%d: Raw packet: ", pktcnt++ );  
    //prnt_buf(DBG_LVL_2, "", pkt, len,0);              // print packet before you send it
    prnt_buf(DBG_LVL_2, "", secret, 62, 1);


    return snd_pkt(dstip, pkt, len);                    // send that packet


    // TODO Free pkt buffer
}
// ------------------------------------------------------------------------------------------------ 
