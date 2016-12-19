// ------------------------------------------------------------------------------------------------
// CS536 - Data Communication and Computer Networks
// Fall 2015
// Lab 6: Overlay Network Routing and Turbo Charged Data Transport
//
// Kyriakos Ispoglou (ispo)
//
//
// overlaybuild.c
//
//
// * * * Example * * *
//   ./overlaybuild `dig +short borg13.cs.purdue.edu` 7777 
//          `dig +short sslab09.cs.purdue.edu` 
//          `dig +short borg09.cs.purdue.edu` 
//          `dig +short sslab00.cs.purdue.edu` 
//          `dig +short borg00.cs.purdue.edu` 9999 31337
//
//
// (for a better view set tab size to 4)
// ------------------------------------------------------------------------------------------------
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define __DEBUG__                           // uncomment me for verbose output
#define MAXROUTELEN     128                 // maximum number of overlay routers

/* a compact and convenient way to represent route request */
struct __attribute__((__packed__)) route_t {
    char     delimiter1;                    // must be '$'
    uint32_t daddr;                         // dst-IP
    char     delimiter2;                    // must be '$'
    uint16_t dport;                         // dst-port
    char     delimiter3;                    // must be '$'

    struct __attribute__((__packed__)) router_t {
        uint32_t addr;                      // routerk-IP
        char     delimiter;                 // must be '$'
    } router[ MAXROUTELEN ];
} route;

/* a compact and convenient way to represent port ACKnowledgement */
struct __attribute__((__packed__)) ack_t {
    char     delimiter1;                    // must be '$'
    uint16_t dport;                         // dst-port
    char     delimiter2;                    // must be '$'
} ack;


/** -----------------------------------------------------------------------------------------------
 * s2ip(): Convert a string containing an IP address to integer.
 *
 *  @ip_s: string containing IP address
 *
 *  return: An integer of that IP in little endian
 */
uint32_t s2ip( char *ip_s )
{
    struct in_addr ia;
    inet_pton(AF_INET, ip_s, &ia);          // ignore errors
    return htonl(ia.s_addr);
}

/** -----------------------------------------------------------------------------------------------
 * assoc(): Associate a UDP socket with a remote peer.
 *
 *  @ip: IP address of remote peer (char*)
 *  @port: Port of remote peer
 *  @build_port: Source port
 *
 *  return: An associated socket ready for read()/write(); -1 on failure.
 */
int assoc( char *ip, uint16_t port, uint16_t build_port )
{
    int sockd;
    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = htonl(s2ip(ip)),
        .sin_zero        = { 0,0,0,0,0,0,0,0 }
    }, locaddr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(build_port),
        .sin_addr.s_addr = INADDR_ANY,
        .sin_zero        = { 0,0,0,0,0,0,0,0 }
    };

    /* create socket */
    if( (sockd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror( "[-] Error. Cannot create socket" );        
        return -1;
    }

    /* bind server to local address:build_port */
    if( bind(sockd, (struct sockaddr*)&locaddr, sizeof(struct sockaddr_in)) < 0 ) {
        perror("[-] Error! Cannot bind socket");
        return -1;
    }

    /* connect the UDP socket. This is an old-school trick to avoid cumbersome and 
     * unreliable code with UDP sockets. If a UDP socket calls sendto() to send a
     * packet to an unreachable port, then recvfrom() will wait for ever. To solve 
     * this issue, we inform kernel to record the IP:port of the server so that any 
     * ICMP errors arrive, they will be forwarder to the app. Also, connect() takes 
     * the server's address as an argument, so the kernel forwards to the application, 
     * only the UDP packets that are originated from that specific host, and discarding 
     * packets from every other host.
     *
     * Another advantage is that we don't have to call the cumbersome sendto() function 
     * each time we want to send something. We simply call write().
     *
     * With this trick, when port is unreachable, we can grab errors like this:
     *      [-] Error! Cannot send UDP packet: Connection refused
     */
    if( connect(sockd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ) {
        perror( "[-] Error. Cannot connect on UDP socket" );
        close( sockd );
        return -1;
    }

    return sockd;
}

/** -----------------------------------------------------------------------------------------------
 * main(): Send command to server and print out the response
 */
int main(int argc, char *argv[])
{
    int sockd,                              // socket descriptor
        a;                                  // iterator

 
    /* check arguments first */
    if( argc < 6 ) {
        printf( "Usage: %s dst-IP dst-port routerk-IP ... router2-IP router1-IP "
                "overlay-port build-port\n\n", argv[0] );

        return -1;
    }

    /* prepare route request packet */
    route.delimiter1 = '$';
    route.daddr      = s2ip(argv[1]);
    route.delimiter2 = '$';
    route.dport      = atoi(argv[2]);
    route.delimiter3 = '$';

    for( a=3; a<argc-2; ++a ) {
        route.router[a-3].addr      = s2ip(argv[a]);
        route.router[a-3].delimiter = '$';
    }

    /* associate socket with the last router (1) */
    sockd = assoc(argv[argc - 3], atoi(argv[argc - 2]), atoi(argv[argc - 1]));

    /* send route request */
    if( write(sockd, &route, 9+(argc-5)*5) < 0 )
    {
        perror("[-] Error. Cannot send setup packet");
        close( sockd );
        return -1;
    }

    /* wait for the ACK packet */
    if( read(sockd, &ack, sizeof(struct ack_t)) < 0 ) 
    {
        perror("[-] Error. Cannot receive setup packet");
        close( sockd );
        return -1;
    }

#ifdef __DEBUG__
    {
        char *p = (char*)&ack;
        int i;

        printf("[+] Raw packet: ");

        /* print raw response */
        for( i=0; i<sizeof(ack); ++i ) 
            if( p[i] == '$' ) printf( "$ " );
            else printf("%02x ", p[i] & 0xff );
    
        printf("\n");
    }
#endif

    /* display the returned port */
    printf( "[+] Router path established!\n" );
    printf( "[+] You can now connect at %s:%d\n", argv[argc - 3], ack.dport );
    printf( "[+] Don't forget to set source port to %s\n", argv[argc - 1] );
    printf( "[+] Bye bye :)\n" );

    close(sockd);

    return 0;
}
// ------------------------------------------------------------------------------------------------
