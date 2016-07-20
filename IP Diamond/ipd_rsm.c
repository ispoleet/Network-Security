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
**  ipd_rsm.c
** 
**  This file implements the "backward" direction of the packets (from level 2 relay to attacker).
**  It's the most sensitive part of the project. Most bugs found here, so we must be very careful.
**  Functions here, are responsible for receiving individual fragmentsfrom relays, merging them, 
**  reconstructing the original IP packet and forwarding it to its desired destination.
**
**
**  * * * ---===== TODO list =====--- * * *
**
**  [1]. Implement garbage collection on buffers.
**  [2]. Handle IP packets with options.
*/
// ------------------------------------------------------------------------------------------------
#include "ipd_lib.h"                                    // all headers are here


extern int bsock[MAXLV1RLYS+1];                         // level 1 relay backward sockets
extern int nrlys;                                       // number of level 1 relays
extern int srcaddr;                                     // source IP address

reasm_buf_t buf[MAX_NBUFFERS];                          // our circular buffer

// ------------------------------------------------------------------------------------------------
//  chksum(): Calculate checksum of a specific buffer.
//
//  Return Value: The buffer's checksum in BIG endian.
//
ushort_t chksum( uchr_t *buf, int buflen )
{
    uint32_t    sum = 0, i;                             // checksum, iterator


    if( buflen < 1 ) return 0;                          // if buffer is empty, exit

    for( i=0; i<buflen-1; i+=2 )                        // add all half-words together
        sum += *(uint16_t*)&buf[i];

    if( buflen & 1 ) sum += buf[buflen - 1];            // if you missed last byte, add it

    sum = (sum >> 16) + (sum & 0xffff);                 // fold high order word to low order word

    return ~sum;                                        // return 1's complement
}

// ------------------------------------------------------------------------------------------------
//  push_pkt(): Push a reassembled packet to TCP/IP for routing.
//
//  Retunrn Value: 0 on success, -1 on failure.
//
int push_pkt( uchr_t *pkt, int pktlen )
{
    struct iphdr        *iph = (struct iphdr*) pkt;     // ip header    
    int                 raw_sd, one = 1;                // socket and set flag  
    
    struct sockaddr_in  trg_addr = {                    // target's address information
        .sin_zero        = { 0,0,0,0,0,0,0,0 },         // zero this out
        .sin_family      = AF_INET,                     // IPv4
        .sin_port        = htons(0),                    // ignore port
        .sin_addr.s_addr = htonl(iph->daddr == TARGET__ADDR ? TARGET__ADDR : srcaddr)
    };


    /* ------------------------------------------------------------------------
     * "fix" packet addresses
     * ------------------------------------------------------------------------ */
    if( iph->daddr == TARGET__ADDR )                    // forward direction 
        iph->saddr = htonl(srcaddr);

    else if( iph->saddr == TARGET__ADDR )               // backward direction 
        iph->daddr = htonl(srcaddr);
    
    else {
        printf("[ERROR] Invalid source/destination address!\n");
        return -1;
    }

    iph->check = 0;                                     // update checksum too
    iph->check = chksum((uchr_t*)iph, iph->ihl << 2);

    if( iph->ihl != 5 ) {                               // are there IP options?
        printf( "[ERROR] IP options are not handled yet!");
        return -1;
    }


    /* ------------------------------------------------------------------------
     * When we transmit TCP/UDP packets we have a problem: The checksum of these
     * protocols is the checksum of their header plus the pseudoheader, a subset 
     * of IP header with the following fields:
     *      Source Address
     *      Destination Address
     *      Reserved
     *      Protocol
     *      TCP (or UDP) Length (header + data)
     *
     * This means that we have to update the TCP/UDP checksum too. The method we
     * follow, is to take a backup of IP header, zero out all fields execpt the
     * important ones, calculate the checksum of the whole packet (zeros do not
     * affect the checksum) and then restore IP header.
     * This method is possible because the 1-byte protocol field is 16bit 
     * aligned.
     * ------------------------------------------------------------------------ */
    if( iph->protocol == IPPROTO_TCP ||                 // TCP protocol?
        iph->protocol == IPPROTO_UDP )                  // UDP protocol?
    {
        struct tcphdr   *tcph = (struct tcphdr*) (iph + 1);
        struct udphdr   *udph = (struct udphdr*) (iph + 1);
        struct iphdr    bkp;
        uint16_t        *check;
        

        /* backup and zero original IP header */
        memcpy((uint8_t*)&bkp, (uint8_t*)iph, sizeof(struct iphdr));
        bzero( (uint8_t*)iph, sizeof(struct iphdr));

        /* re-fill pseudo-header fields in IP header */
        iph->saddr    = bkp.saddr;                      // source IP (may be spoofed)
        iph->daddr    = bkp.daddr;                      // destination IP
        iph->protocol = bkp.protocol;                   // upper layer protocol
        iph->tot_len  = ntohs(htons(bkp.tot_len) - sizeof(struct iphdr));

        
        if( iph->protocol == IPPROTO_TCP ) check = &tcph->check;
        else check = &udph->check;

        *check = 0;                                     // checksum of pseudo-header + payload  
        *check = chksum((uchr_t*)iph, htons(bkp.tot_len));


        /* restore original IP header */
        memcpy((uint8_t*)iph, (uint8_t*)&bkp, sizeof(struct iphdr));
    }


    /* ------------------------------------------------------------------------
     * Forward packet for routing
     * ------------------------------------------------------------------------ */
    if( (raw_sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 ) {
        perror( "Cannot create raw socket" );
        return -1;
    }
    
    /* inform kernel that IP header is included in the packet */
    if( setsockopt(raw_sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0 ) {
        perror( "Cannot set IP_HDRINCL" );
        close( raw_sd );
        return -1;
    }

    /* send packet */
    if( sendto(raw_sd, pkt, pktlen, 0, (struct sockaddr*) &trg_addr, sizeof(trg_addr)) < 0) {
        perror( "Cannot send raw packet" );
        close( raw_sd );
        return -1;
    }

    close(raw_sd);                                      // close socket (ignore failures)

    return 0;                                           // success!
}

// ------------------------------------------------------------------------------------------------
//  reassemble(): Per-thread function. Each thread waits for a unique relay to send a fragment. 
//      Once it receives it, it adds it in the right buffer, in the right slot. If a buffer 
//      becomes full (all fragments received => packet is complete), it calls push_pkt.
//
//  Return Value: Function always returns NULL.
//
void *reassemble( void *n_ptr )
{
    uchr_t       *frgm = malloc(MAXPKTLEN);             // store received fragment
    uint_t       n     = *((uint_t*) n_ptr);            // get thread id
    ipd_header_t ipd_hdr;                               // ipd_header       
    int          r1, r2, idx;                           // auxiliary variables
        

    for( ;; )                                           // forever...
    {
        /* read an ipd header and it's payload. MSG_WAITALL is crucial */
        r1 = recv(bsock[n], &ipd_hdr, sizeof(ipd_hdr), MSG_WAITALL);
        r2 = recv(bsock[n], frgm, ipd_hdr.frgmlen, MSG_WAITALL);

        if( r1 != sizeof(ipd_hdr) ||                    // read less
            r2 != ipd_hdr.frgmlen ||
            strcmp(ipd_hdr.signature, "ipd\0") )        // or signature mismatch
        {
            printf( "[ERROR] Thread #%d. Can't read packet. (%d,%d) bytes read\n'", n, r1, r2);
            break;
        }


        /* packet read ok */        
        idx = ipd_hdr.seqnum & BUFMASK;                 // find buffer for that packet


        printf( "[INFO] Thread #%d. Packet %d, Fragment %d, Total fragments:%d\n", 
            n, ipd_hdr.seqnum, ipd_hdr.frgmid, ipd_hdr.nfrgms);
        
        /* if buffer contains fragments from another packet, discard fragment */
        if( buf[ idx ].seq && buf[ idx ].seq != ipd_hdr.seqnum ) {
            printf( "[ERROR] Thread #%d. Dropping fragment :(\n", n );
            continue;
        }
        

        /* buffer ok. add piece to buffer. Assume no overlaps */
        memcpy(&buf[idx].data[ipd_hdr.frgmoff], frgm, ipd_hdr.frgmlen);

        buf[idx].tot_len += ipd_hdr.frgmlen;            // update total length

        if( ++buf[idx].nfrgms >= ipd_hdr.nfrgms )       // assume no overlaps
        {
            /* packet completed. Route it (push it to TCP/IP stack) */
            prnt_pkt_nfo(buf[idx].data, buf[idx].tot_len);
            push_pkt    (buf[idx].data, buf[idx].tot_len);  

            /// TODO: check return value

            buf[idx].seq     = 0;                       // make buffer reusable
            buf[idx].tot_len = 0;
            buf[idx].nfrgms  = 0;
        }
        

        /// TODO: garbage collection (use "gettimeofday(&buf[idx].tv, NULL)")       

    }

    free( frgm );                                       // eventually free fragment...

    return NULL;
}
// ------------------------------------------------------------------------------------------------
