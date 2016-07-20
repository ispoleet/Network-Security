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
**  ipd_lib.h
**
**  This is the common library of all source files. It contains all declarations. 
*/
// ------------------------------------------------------------------------------------------------
#ifndef IPD_SHR_LIB                                     /* include only once */
#define IPD_SHR_LIB

// ------------------------------------------------------------------------------------------------
// Include headers
// ------------------------------------------------------------------------------------------------
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h> 
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h> 
#include <pthread.h>
#include <argp.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>


// ------------------------------------------------------------------------------------------------
// MACRO declarations
// ------------------------------------------------------------------------------------------------
#define BUFFER_GRANULARITY  4                           // bit for buffer indexing
#define MAX_NBUFFERS        (1<<BUFFER_GRANULARITY)     // must be power of 2
#define BUFMASK             0x000f                      // must match with granularity
#define MAXLV1RLYS          32                          // maximum number of level 1 relays
#define NRELAYS             3                           // default number of level 1 relays
#define MAXIPLEN            65536                       // max IP packet size
#define MAXPKTLEN           MAXIPLEN                    // an alias
#define DEFAULT_IF          "eth0"                      // set default interface
#define ATTACKER_MODE       0x1337                      // attacker mode
#define L2_RELAY_MODE       0xcafe                      // level 2 relay mode
#define ERROR_KRNL_SEM      0x700001                    // semaphore error code
#define ERROR_KRNL_COPY     0x700002                    // cannot copy to userspace
#define TARGET__ADDR        0x3b030a80                  // 128.10.3.59 (xinu09.cs.purdue.edu)
// #define TARGET__ADDR         0xc0a80166              // 192.168.1.102 (within LAN)

#define MIN(a, b) ((a) < (b) ? (a) : (b))               // minimum of 2 numbers
#define CHKPORT(p)  ((p) > 0 && (p) <= 65536)           // check if port is valid


// ------------------------------------------------------------------------------------------------
// Typedef declarations
// ------------------------------------------------------------------------------------------------
typedef unsigned char       uchr_t;                     // typedefs
typedef unsigned int        uint_t;     
typedef unsigned short int  ushort_t;
typedef short int           short_t;


// ------------------------------------------------------------------------------------------------
// Structure declarations
// ------------------------------------------------------------------------------------------------
typedef struct {                                        // ipd packet header
    uchr_t      signature[4];                           // 4 byte tag (must be "ipd\0")
    ushort_t    seqnum;                                 // sequence number
    uchr_t      nfrgms,                                 // total number of fragments
                frgmid;                                 // fragment id
    ushort_t    frgmoff,                                // fragment's offset withing IP packet
                frgmlen;                                // fragment's length
} __attribute__((__packed__)) ipd_header_t;

typedef struct {                                        // a buffer to hold incoming fragments
    uchr_t          data[MAXIPLEN];                     // reconstructed IP packet
    
    /* buffer's metadata */ 
    uchr_t          nfrgms;                             // fragments collected so fat
    ushort_t        seq;                                // packet's sequence number    
    int             tot_len,                            // total length of the packet
                    state;                              // unused in this version
    struct timeval  tv;                                 // unused too
} reasm_buf_t;


// ------------------------------------------------------------------------------------------------
// Function declarations
// ------------------------------------------------------------------------------------------------

/*
 *  Abort the program if assertion is false.
 */
void myassert( int cond, char *err );

/*
 * Get IP address of a given interface.
 */
uint32_t get_ifaddr( char *ifname );

/*
 *  Create socket and make server listen locally on a specific port.
 */
int bind_serv( uint16_t port );

/*
 *  Print some basic fields/data of an IP packet.
 */
void prnt_pkt_nfo( uchr_t *pkt, int pktlen );

/*
 *  Wait for packets from netfilter module and send them to level 1 relays.
 */
void *usr_main( void* thread_data );

/*
 *  Reassemble a packet from its fragments and route it.
 */
void *reassemble( void *n_ptr );


// ------------------------------------------------------------------------------------------------
#endif
// ------------------------------------------------------------------------------------------------
