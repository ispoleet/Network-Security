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
**  ipd_usr.c
** 
**  This file implements the "forward" direction of the packets (from attacker to level 2 relay).
*/
// ------------------------------------------------------------------------------------------------
#include "ipd_lib.h"                                    // all headers are here


extern int fsock[MAXLV1RLYS+1];                         // level 1 relay forward sockets
extern int nrlys;                                       // number of level 1 relays

static int seq = 0;                                     // global packet sequence number

// ------------------------------------------------------------------------------------------------
//  split_n_snd(): Get a packet, split it in some fragments and send each fragment to a different
//      level 1 relay.
//
//  Retunrn Value: 0 on success, -1 on failure.
//
int split_n_snd(uchr_t *pkt, int pktlen)
{
    const int   gran = (pktlen + (nrlys-1)) / nrlys;    // size of each fragment (rounded up)
    int         n;                                      // iterator


    /* increment global sequence number                             */
    /* We need it to distinguish fragments from different packets   */
    /* Don't confuse it with sequence numbers in IP header!         */
    ++seq;
                                                        
    for( n=0; n<nrlys; ++n )                            // for each relay
    {
        ipd_header_t    ipd_hdr = {                     // make ipd packet header
            .signature = { 'i','p','d','\0'},           // tag header
            
            .seqnum    = seq,                           // set packet's sequence number
            .nfrgms    = nrlys,                         // and total number of fragments

            .frgmid    = n,                             // fragment id
            .frgmoff   = n*gran,                        // offset within original packet
            .frgmlen   = n == nrlys-1 ? pktlen-n*gran : gran    // last packet may be smaller
        };

        /* send header and then send fragment */
        if( send(fsock[n+1], &ipd_hdr,              sizeof(ipd_hdr), 0) != sizeof(ipd_hdr) ||
            send(fsock[n+1], &pkt[ipd_hdr.frgmoff], ipd_hdr.frgmlen, 0) != ipd_hdr.frgmlen )
                return -1;                              // failure
        

        /* in redundancy mode you have to send it to >1 relays */
    }


    return 0;                                           // success
}

// ------------------------------------------------------------------------------------------------
//  usr_main(): Wait for packets from netfilter module and send them to level 1 relays.
//
//  Retunrn Value: 0 on success, -1 on failure.
//
void *usr_main( void *thread_data )
{   
    uchr_t  pkt[MAXPKTLEN];                             // store incoming packet from kernel
    int     n, devmode;                                 // iterator & device mode (flags)   
    int     fd = 0;                                     // file and socket decstiptors
    
    
    devmode = *((uint32_t*) thread_data) == ATTACKER_MODE ? O_RDONLY : O_RDWR;

    /* ------------------------------------------------------------------------
     * Connect to ipd_krnl and enable packet stealing
     * ------------------------------------------------------------------------ */
    if((fd = open("/dev/ip_diamond", devmode)) < 0) {  // connect to ipd_krnl 
        perror( "[ERROR] Cannot connect to ipd_krnl");

        return NULL;
    }

    for( ;; ) {                                         // do it for ever       
        int pktlen;                                     // packet length


        /* read a packet from kernel. Blcok if no packet is available */
        if( (pktlen = read(fd, pkt, MAXPKTLEN)) < 0 ) {

            switch( pktlen ) {                          // verbose error
                // ----------------------------------------------------------------
                case -ERROR_KRNL_SEM: 
                    printf("[ERROR] Cannot lock semaphore.\n"); 
                    break;
                // ----------------------------------------------------------------
                case -ERROR_KRNL_COPY: 
                    printf("[ERROR] Cannot copy to userspace.\n");
                // ----------------------------------------------------------------
            }

            break;                                      // failure (jump to clean up)
        }

        if( !pktlen ) continue;                         // ignore empty packets


        /* at this point pkt buffer contains our packet */

        prnt_pkt_nfo(pkt, pktlen);                      // print packet's info

        /* ------------------------------------------------------------------------
         * ---===== * * * WARNING * * * =====---
         * If we don't spoof source IP address and send the packet to level 2 relay
         * we can expose attacker's real IP address, which is very bad. Because it can
         * cause problems in functionality we leave it for now. But you can do it 
         * this way:
         *
         *  struct iphdr *ip = (struct iphdr*) pkt;
         *  ip->saddr  = 0x1337beef;
         * ------------------------------------------------------------------------ */
        if( split_n_snd(pkt, pktlen) < 0 ) {            // split and send packet to level 1 relays
            printf( "[ERROR] Cannot send to level 1 relays.\n" 
                    "[INFO] Current version cannot recover from these errors.\n" );
            break;                                      // failure (jump to clean up)
        }
    }


    /* ------------------------------------------------------------------------
     *  phase 4: Clean up (both on success and error)
     * ------------------------------------------------------------------------ */
    close(fd);                                          // close connection with kernel

    return NULL;                                            // not always success
}
// ------------------------------------------------------------------------------------------------
