// ------------------------------------------------------------------------------------------------
// CS536 - Data Communication and Computer Networks
// Fall 2015
// Lab 6: Overlay Network Routing and Turbo Charged Data Transport
//
// Kyriakos Ispoglou (ispo)
//
//
// overlayrouter.c
//
// Please refer to problem description for more details. Here routing table is assumbed to be 
// small, so linear searches are acceptable. Also we assume no security model (as it's not 
// required by the problem). So, a malicious router can screw up everything.
// 
// Note: All transmitted numbers are in little endian
//
// (for a better view set tab size to 4)
// ------------------------------------------------------------------------------------------------
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ifaddrs.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>


// #define __DEBUG__                            // uncomment me for verbose output
#define MAXROUTELEN     128                     // maximum number of overlay routers
#define PKTSZ           65507                   // max packet size for UDP
#define TTL             30                      // ttl of unconfirmed entries
#define NRTTBLROWS      64                      // rows of routing table
#define START_PORT      30000                   // port number assignment starts from here
#define NDATASOCK       128                     // max number of overlay sockets/ports

#ifdef __DEBUG__
    /* MACRO for printing incoming packets */
    #define __PRINT_PACKET__(p, l) {                        \
                char *pp = (char*)&p;                       \
                int   ii;                                   \
                                                            \
                printf("[+] Raw packet: ");                 \
                                                            \
                for( ii=0; ii<l; ++ii )                     \
                    if( pp[ii] == '$' ) printf("$ ");       \
                    else printf("%02x ", pp[ii] & 0xff );   \
                                                            \
                printf("\n");                               \
            }
#else
    #define __PRINT_PACKET__(p, l) ;            // declare an empty MACRO
#endif


/* An incoming packet at control port can be either be a route request or a route
 * confirmation. So, we pack both in a union and after we receive/infer the actual 
 * type, we can process packet accordingly.
 */
union {
    /* a compact and convenient way to represent route request */
    struct __attribute__((__packed__)) route_t {
        char     delimiter1;                // must be '$'
        uint32_t daddr;                     // dst-IP
        char     delimiter2;                // must be '$'
        uint16_t dport;                     // dst-port
        char     delimiter3;                // must be '$'

        struct __attribute__((__packed__)) router_t {
            uint32_t ip;                    // routerk-IP
            char     delimiter;             // must be '$'
        } router[ MAXROUTELEN ];
    } route;

    /* this is for route confirmation: $$routerk-IP$data-port-k$ */
    struct __attribute__((__packed__)) confirm_t {
        char     delimiter1;                // must be '$'
        char     delimiter2;                // must be '$'
        uint32_t addr;                      // router(i)-IP
        char     delimiter3;                // must be '$'
        uint16_t port;                      // data-port-(i)
        char     delimiter4;                // must be '$'
    } cnfm;
} p;

/* a received packet in a data port can either be a port ACK or a normal packet */
union {
    /* a compact and convenient way to represent port acknowledgement */
    struct __attribute__((__packed__)) ack_t {
        char     delimiter1;                // must be '$'
        uint16_t dport;                     // dst-port
        char     delimiter2;                // must be '$'
    } ack;

    char pkt[PKTSZ];                        // buffer for packet forwarding
} q;

/* routing table entry */
struct route_entry_t {
    int      state;                         // entry state
    uint16_t data_port;                     // data port which packets pass through 
    time_t   ts;                            // timestamp since creation

    struct node_t {
        uint32_t ip;                        // node IP
        uint16_t port;                      // node port
    } src, dst;                             // we have 2 nodes: source and destination

} rttbl[ NRTTBLROWS ];

/* potential states of routing table entries */
enum rttbl_state {
    UNUSED    = 0,                          // empty slot
    COMPLETE  = 1,                          // entry has been filled
    CONFIRMED = 2                           // entry has been confirmed
};

/* inflate socket with additional information (socket++) */
struct socketpp_t {
    int sd;                                 // socket descriptor
    uint32_t ip;                            // IP of sender
    uint16_t pt;                            // port of sender
} ds[ NDATASOCK ];

int ns,                                     // # of data sockets                
    sockd;                                  // socket descriptor


/** -----------------------------------------------------------------------------------------------
 * handler(): Signal handler
 *
 *  @signum: signal number
 */
void handler( int signum )
{
    int k;

    /* remove expired entries from routing table */
    if( signum == SIGALRM )
    {
        time_t now = time(NULL);
        int    cnt = 0, i;

        /* look for complete entries that are not verified and have expired */
        for( i=0; i<NRTTBLROWS; ++i )
            if( rttbl[i].state == COMPLETE && now - rttbl[i].ts > TTL )
            {
                rttbl[i].state = UNUSED;
                ++cnt;
            }
    
        if( cnt > 0 ) printf("[+] Removing %d expired entries...\n", cnt);
    }
}

/** -----------------------------------------------------------------------------------------------
 * fatal(): Print an error message, close sockets and terminate program.
 *
 *  @err: error message to display
 */
void fatal( const char *err )
{
    char exterr[128];
    int i;


    snprintf( exterr, 128, "[-] Error! %s", err );
    perror( exterr );                       // print error

    close( sockd );                         // close all sockets
    for( i=0; i<ns; ++i ) close( ds[i].sd );

    exit( EXIT_FAILURE );                   // abort
}

/** -----------------------------------------------------------------------------------------------
 * ip2s(): Convert an 4-byte IP to a string.
 *
 *  @ip: IP address to convert (little endian)
 *
 *  return: A newly allocated string (in heap) containing the IP address. 
 */
char *ip2s( uint32_t ip )
{ 
    struct in_addr ia = { .s_addr = htonl(ip) };
    
    /*
     * It seems that inet_ntoa() uses a unique internal buffer to hold ip; if we say: 
     * printf( "%s %s", inet_ntoa(ip1), inet_ntoa(ip2)) the output will be "ip2 ip2". 
     * Thus we have to allocate a new buffer wefor our string.
     *
     * Also we have to invoke free() later on.
     */
    return strdup( inet_ntoa(ia) );
}

/** -----------------------------------------------------------------------------------------------
 * is_local_ip(): Check if an IP is owned by current overlay router.
 *
 *  @ip: IPv4 address to check
 *
 *  return: 1 if IP is local. 0 otherwise.
 */
int is_local_ip( uint32_t ip )
{
    struct ifaddrs *addrs, *p;
    int found = 0;

    /* get addresses from all interfaces */
    getifaddrs( &addrs );   

    /* iterate over interfaces and stop when you reach list tail/find a match */
    for( p=addrs; p && !found; p=p->ifa_next )      
        if( p->ifa_addr->sa_family == AF_INET &&
            ((struct sockaddr_in*) p->ifa_addr)->sin_addr.s_addr == htonl(ip) )
                found = 1; 
        
    /* release objects */
    freeifaddrs( addrs );

    return found;
}

/** -----------------------------------------------------------------------------------------------
 * bind_port(): Create a socket and bind it to a local port.
 *
 *  @port: port number to bind socket
 *
 *  return: A socket binded to that port; upon failure fatal() will terminate program.
 */
int bind_port( uint16_t port )
{
    int sockd;
    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
        .sin_zero        = { 0,0,0,0,0,0,0,0 }
    };

    /* create socket */
    if( (sockd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 )
        fatal("Cannot create socket");

    /* enable address reuse for that port */
    if( setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0 )
        fatal("Cannot reuse address");

    /* bind socket to local address:port */
    if( bind(sockd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) < 0 )
        fatal("Cannot bind UDP socket");

    /* all set. Return socket */
    return sockd;
}

/** -----------------------------------------------------------------------------------------------
 * addroute(): Add a new entry in routing table. 
 *
 *  @sip: source IP
 *  @sport: source port
 *  @dip: destination IP
 *  @dport: destination port
 *  @dataport: data port that traffic pass through
 *  @state: initial state
 *
 *  return: 0 on success. -1 on failure (table is full).
 */
int addroute( uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport, 
              uint16_t dataport, int state )
{
    int i;

    /* look for the 1st empty slot in routing table and add an entry*/
    for( i=0; i<NRTTBLROWS; ++i )
        if( rttbl[i].state == UNUSED ) 
        {
            rttbl[i].state     = state;
            rttbl[i].ts        = time(0);
            rttbl[i].data_port = dataport;
            rttbl[i].src.ip    = sip;
            rttbl[i].src.port  = sport;
            rttbl[i].dst.ip    = dip;
            rttbl[i].dst.port  = dport;

            // TODO: free strings returned by ip2s 
            printf( "[*] (%s, %d) => (%s, %d)\n", ip2s(sip), sport, ip2s(dip), dport);
        
            return 0;
        }

    return -1;                              // failure; table is full
}

/** -----------------------------------------------------------------------------------------------
 * confirmroute(): Confirm an entry in routing table. 
 *
 *  @ip: source IP
 *  @port: source port
 */
void confirmroute(uint32_t ip, uint16_t port)
{
    int i;

    /* search and confirm the requested entries (usually 2) */
    for( i=0; i<NRTTBLROWS; ++i )
        if( rttbl[i].state == COMPLETE && 
            (rttbl[i].src.ip == ip && rttbl[i].src.port == port ||
             rttbl[i].dst.ip == ip && rttbl[i].dst.port == port) 
        ) {
            rttbl[i].state = CONFIRMED;

            // TODO: free strings returned by ip2s 
            printf( "[*] Confirmed: (%s, %d) => (%s, %d)\n", 
                    ip2s(rttbl[i].src.ip), rttbl[i].src.port, 
                    ip2s(rttbl[i].dst.ip), rttbl[i].dst.port );

        }
}

/** -----------------------------------------------------------------------------------------------
 * forward(): Given (srcip, srcport) perform a lookup in routing table to find (dstip, dstport).
 *
 *  @sip: source IP 
 *  @sport: source port
 *  @dip: destination IP (OUT)
 *  @dport: destination port (OUT)
 *
 *  return: If lookup was successful, function returns the intermediate data port. Otherwise -1 
 *      is returned.
 */
int forward(uint32_t sip, uint16_t sport, uint32_t *dip, uint16_t *dport)
{
    int i;

    /* search for source and copy destination pair */
    for( i=0; i<NRTTBLROWS; ++i )
        if( rttbl[i].state    == CONFIRMED && 
            rttbl[i].src.ip   == sip    && 
            rttbl[i].src.port == sport )
        {   
            *dip   = rttbl[i].dst.ip;
            *dport = rttbl[i].dst.port;

            return rttbl[i].data_port;      // success; return data port
        }

    return -1;                              // failure; source doesn't exist
}

/** -----------------------------------------------------------------------------------------------
 * main(): Send command to server and print out the response
 */
int main(int argc, char *argv[])
{
    fd_set dset;                        // descriptor sets
    int i, len;                         // auxiliary
    static int data_port = START_PORT;
    uint32_t myip = 0;
    int ctrl_port = atoi(argv[1]);



    /* check the number of arguments */
    if( argc != 2 ) {
        printf( "Usage: %s server-port\n\n", argv[0] );
        return -1;
    }

    printf("[+] Overlay router started.\n");

    /* bind control port (upon error bind_port() will terminate) */
    sockd = bind_port(ctrl_port);

    /* clear routing table */
    for( i=0; i<NRTTBLROWS; ++i ) rttbl[i].state = UNUSED;

    /* set alarm for collecting stale entries in routing table */
    signal(SIGALRM, handler);
    ualarm(500000, 500000);

    /* server's main loop */
    for( ;; )  
    {
        struct sockaddr_in addr;
        socklen_t          addrlen = sizeof(addr);
        uint32_t           newip;
        uint16_t           newpt;
        int                l, k;
        

        /* prepare descriptor set for select() */
        FD_ZERO(&dset);
        FD_SET(sockd, &dset);

        for( i=0; i<ns; ++i ) 
            if( ds[i].sd > 0 ) FD_SET(ds[i].sd, &dset);

        /* poll sockets to check which are "ready" */
        if(select(FD_SETSIZE, &dset, NULL,NULL,NULL) < 0) 
        {
            /* poll them again */
            if( errno == EINTR ) continue;
            
            /* failure :( */
            fatal("Cannot poll socket descriptors");
        }


        /** Our design is "loose"; When we receive a packet, we ignore the destination port. 
         *  It's very easy to add more restrictions as the routing table contains data_port,
         *  but we don't do it as it's not part of problem description.
         * 
         *  Although this implementaation is simpler, it's possible for a client to send 
         *  traffic in a data port that is reserver for another path.
         *
         *  WARNING: We must check data ports first and then control port. If we have a
         *      port ACK and a route confirmation waiting, we must process port ACK first.
         */
        for( i=0; i<ns; ++i )
        if( ds[i].sd > 0 && FD_ISSET(ds[i].sd, &dset) )
        {
            bzero(&q, sizeof(q));

            /* receive packet from data port */
            if((l=recvfrom(ds[i].sd, &q, sizeof(q), 0, (struct sockaddr*)&addr, &addrlen)) < 0)
                /* Errors during send/receive on UDP are rare, and the source of the error is 
                 * usually the current program, so it's a good idea to halt it.
                 */
                fatal("Cannot read UDP packet from data port");
        
            __PRINT_PACKET__(q, l);


            /* if source port is ctrl_port we have an port ACK packet */
            if( htons(addr.sin_port) == ctrl_port && l == sizeof(struct ack_t) )
            {
                // TODO: extra check
                // if(ack->delimiter1 == '$' && ack->delimiter2 == '$')

                if( addroute(ds[i].ip, ds[i].pt, htonl(addr.sin_addr.s_addr), q.ack.dport, 
                                data_port, COMPLETE) < 0 ||

                    addroute(htonl(addr.sin_addr.s_addr), q.ack.dport, ds[i].ip, ds[i].pt, 
                                data_port, COMPLETE) < 0 )
                {
                    printf("[-] Error! Routing table is full. Cannot add route.\n");
                    continue;                   // do not abort
                }
            }

            /* otherwise we have a regular packet for forwarding */
            else {

                /* lookup table to find next hop */
                if(forward(htonl(addr.sin_addr.s_addr), htons(addr.sin_port), &newip, &newpt) < 0)
                {
                    printf("[-] Error! Cannot find a match for (%s,%d) in routing table\n",
                            ip2s(htonl(addr.sin_addr.s_addr)), htons(addr.sin_port));

                    continue;                   // do not abort 
                }

                /* forward packet to the next hop */                
                addr.sin_addr.s_addr = htonl(newip);
                addr.sin_port        = htons(newpt);

                if( sendto(ds[i].sd, q.pkt, l, 0, (struct sockaddr*)&addr, addrlen) < 0 )
                    fatal("Cannot forward packet");
            }
        }

        /* Now, we check if we have a packet at control packet */
        if( FD_ISSET( sockd, &dset ) )
        {
            bzero(&p, sizeof(p));

            /* receive route path or route confirmation */
            if((l = recvfrom(sockd, &p, sizeof(p), 0, (struct sockaddr*)&addr, &addrlen)) < 0) 
                fatal("Cannot receive packet from control port");
                
            __PRINT_PACKET__(p, l);


            /* check if packet is a route confirmation: $$routerk-IP$data-port-k$ => 10B */
            if( l == 10 )
            {
                /* confirm route */
                confirmroute(p.cnfm.addr, p.cnfm.port);
                uint16_t a;

                /* lookup routing table to find previous hop (last arg is ignored) */
                if( forward(p.cnfm.addr, p.cnfm.port, &newip, &newpt) < 0 )
                {
                    printf("[-] Error! Cannot find a FEEDBACK match for (%s, %d) in routing "
                           "table\n", ip2s(p.cnfm.addr), p.cnfm.port);
                    continue;                   // do not abort 
                }
                
                /* send route confirmation to previous hop */
                bzero(&p, sizeof(p));
                p.cnfm.delimiter1 = '$';
                p.cnfm.delimiter2 = '$';
                p.cnfm.addr       = myip;
                p.cnfm.delimiter3 = '$';
                p.cnfm.port       = newpt;              
                p.cnfm.delimiter4 = '$';
                
                /** WARNING: One problem that we have here, is that we don't know when to stop;
                 *  Although it's easy for a router to check if it's the last router, it has no
                 *  way to check if it's the 1st router and thus to stop. The 1st router, we try
                 *  to send a route confirmation to overlaybuild at (src-ip, src-port) and thus
                 *  an ICMP port unreachable packet will be generated. Although this won't cause
                 *  any issues it's not very good :\
                 */
                addr.sin_port        = htons(ctrl_port);
                addr.sin_addr.s_addr = htonl(newip);

                if(sendto(sockd, &p.cnfm, sizeof(p.cnfm), 0, (struct sockaddr*)&addr, addrlen) < 0)
                    fatal("Cannot send route confirmation packet");

                continue;
            }

            /* otherwise, packet is a route path */

            /* calculate the number of routers in the path (-1 as we start from 0)*/            
            k = (l - 9) / 5 - 1;
            
            /* if last IP is not for this router, silently discard packet */
            if( !is_local_ip(p.route.router[k].ip) )
                continue;

            myip = p.route.router[k].ip;


            /* create a new socket++ */
            ds[ns].sd = bind_port(data_port);
            ds[ns].ip = htonl(addr.sin_addr.s_addr);
            ds[ns].pt = htons(addr.sin_port);

            /* return an ACK packet to (prev_router, prev_data_port) with the new data_port */
            q.ack.delimiter1 = '$';
            q.ack.dport      = data_port;
            q.ack.delimiter2 = '$';

            if( sendto(sockd, &q.ack, sizeof(q.ack), 0, (struct sockaddr*)&addr, addrlen) < 0 ) 
                fatal("Cannot send port ACK packet");


            /* strip last IP address (so easy :P) */
            l -= 5;

            /* is this the end of the path? */
            if( l > 9 )
            {
                /* No. Forward path to control port of next router */
                addr.sin_addr.s_addr = htonl( p.route.router[k-1].ip );
                addr.sin_port        = htons( ctrl_port );

                if(sendto(ds[ns].sd, &p.route, l, 0, (struct sockaddr*)&addr, addrlen) < 0)
                    fatal("Cannot send packet to extend path");
            }

            else { 
                printf("[+] I'm the last node of the path!\n");

                /* add entry to routing table (it's already confirmed) */
                if( addroute(p.route.daddr, p.route.dport, htonl(addr.sin_addr.s_addr), 
                                htons(addr.sin_port), data_port, CONFIRMED) < 0 ||

                    addroute(htonl(addr.sin_addr.s_addr), htons(addr.sin_port), p.route.daddr, 
                                p.route.dport, data_port, CONFIRMED) < 0 )
                {
                    printf("[-] Error! Routing table is full.\n");
                    continue;                   // do not abort         
                }

                /* next hop is final destination; start sending backwards */
                bzero(&p, sizeof(p));

                p.cnfm.delimiter1 = '$';
                p.cnfm.delimiter2 = '$';
                p.cnfm.addr       = myip;
                p.cnfm.delimiter3 = '$';
                p.cnfm.port       = data_port;
                p.cnfm.delimiter4 = '$';
                

                /** WARNING: Here we have the same problem as before. What if there's only 1 
                 *  overlay router? In this case, previous hop is source, so packet will lost.
                 */
                addr.sin_port        = htons(ctrl_port);
                addr.sin_addr.s_addr = htonl(ds[ns].ip);

                if(sendto(sockd, &p.cnfm, sizeof(p.cnfm), 0, (struct sockaddr*)&addr, addrlen) < 0)
                    fatal("Cannot send route confirmation packet");
            }
        
            /* update port and socket counters */
            ++data_port;
            ++ns;
        }
    }

    return 0;
}
// ------------------------------------------------------------------------------------------------
