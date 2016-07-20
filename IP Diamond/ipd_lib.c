// ------------------------------------------------------------------------------------------------
/*  Purdue CS536 - Computer Networks - Fall 2015
**  Final Project: IP Diamond
**  Kyriakos Ispoglou (ispo)
**
**   ___________  ______ _                                 _ 
**  |_   _| ___ \ |  _  (_)                               | |
**    | | | |_/ / | | | |_  __ _ _ __ ___   ___  _ __   __| |
**    | | |  __/  | | | | |/ _` | '_ ` _ \ / _ \| '_ \ / _` |
**   _| |_| |     | |/ /| | (_| | | | | | | (_) | | | | (_| |
**   \___/\_|     |___/ |_|\__,_|_| |_| |_|\___/|_| |_|\__,_|
**                                                           
**  * * * ---===== IP Diamond v1.1 =====--- * * *
**
**
**  ipd_lib.c
**
**  This file contains some common functions that used by multiple files.
*/
// ------------------------------------------------------------------------------------------------
#include "ipd_lib.h"


// ------------------------------------------------------------------------------------------------
//  myassert(): Abort the program if assertion is false.
//
//  Retunrn Value: 0 on success, -1 on failure.
//
void myassert( int cond, char *err )
{
    if( !cond ) {
        printf( "[ERROR] %s. Abort\n", err );           // condition error
        exit( EXIT_FAILURE );                           // abort execution
    }
}

// ------------------------------------------------------------------------------------------------
//  get_ifaddr(): Get IP address of a given interface.
//
//  Return Value: The IP address of that interface. If IP address not found, function returns -1.
//
uint32_t get_ifaddr( char *ifname )
{
    struct ifaddrs  *ifaddr, *ii;                       // interface list & iterator
    uint32_t        addr = 0xffffffff;                  // return value


    getifaddrs( &ifaddr );                              // get interfaces addresses

    for( ii=ifaddr; ii; ii=ii->ifa_next )               // iterate through interfaces
    {
        if( ii->ifa_addr->sa_family == AF_INET &&       // IPv4?
            !strcmp(ii->ifa_name, ifname) )             // interface name matches?
        {
            struct sockaddr_in *sa = (struct sockaddr_in*) ii->ifa_addr;            
            addr = htonl(sa->sin_addr.s_addr);      // get source IP

            printf("[INFO] IP address of %s is %s\n", ii->ifa_name, inet_ntoa(sa->sin_addr) );

            break;                                      // stop searching
        }
    }

    freeifaddrs( ifaddr );                              // free struct

    return addr;                                        // return ip
}

// ------------------------------------------------------------------------------------------------
//  bind_serv(): Create a socket and bind a server locally on a specific port.
//
//  Return Value: If function is successful, server's socket descriptor is returned. Upon error,
//      function returns -1.
//
int bind_serv( uint16_t port )
{
    int lstn_sd = -1;                                   // server's socket descriptor
    struct sockaddr_in
        serv_addr = {                                   // server's information
            .sin_family      = AF_INET,                 // IPv4
            .sin_port        = htons(port),             // at this port
            .sin_addr.s_addr = INADDR_ANY,              // bind locally,
            .sin_zero        = { 0,0,0,0,0,0,0,0 }      // zero this out
        };
    
    /* create TCP socket */
    if( (lstn_sd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        perror( "[ERROR] Cannot create socket");
        return -1;
    }

    /* bind to address */
    if( bind(lstn_sd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0 ) {
        perror( "[ERROR] Cannot bind");
        close( lstn_sd );
        return -1;
    }

    /* set listening queue */
    if( listen(lstn_sd, MAXLV1RLYS) < 0 ) {             // handle up to MAXLV1RLYS level 1 relays
        perror( "[ERROR] Cannot listen");
        close( lstn_sd );
        return -1;        
    }

    return lstn_sd;                                     // return server's socket
}

// ------------------------------------------------------------------------------------------------
//  prnt_pkt_nfo(): Print source and destination addresses, size and up to 8 bytes of the payload.
//
//  Return Value: None.
//
void prnt_pkt_nfo( uchr_t *pkt, int pktlen )
{
    struct iphdr    *ip = (struct iphdr*) pkt;          // pointer to packet's header
    struct in_addr  src, dst;                           // source and destination addresses
    int             i;                                  // iterator

    
    src.s_addr = ip->saddr;                             // get source and dest addresses
    dst.s_addr = ip->daddr;

    /* split calls to inet_ntoa(). Otherwise you'll overwrite the addresses */
    printf( "Got IP packet! [%s", inet_ntoa(src) ); 
    printf( " -> %s] (%d) Bytes. Data: " , inet_ntoa(dst), pktlen );
        

    for(i=0; i<MIN(pktlen-(ip->ihl << 2), 8); ++i)      // print up 8 bytes of payload
        printf( "%02x ", pkt[(ip->ihl << 2) + i] & 0xff );
    
    printf( "\n" );                                     // close with a newline

}
// ------------------------------------------------------------------------------------------------
