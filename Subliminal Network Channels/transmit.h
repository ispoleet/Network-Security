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
**  transmit.h
**
**  This header includes some shared globals that are used by both transmit.c and receive.c.
*/
// ------------------------------------------------------------------------------------------------ 
#ifndef TRANSMIT_H_DEFINED
#define TRANSMIT_H_DEFINED                              // include only once
// ------------------------------------------------------------------------------------------------ 
#define SOURCE_IP       "192.168.1.100"                 // source IP address (can be spoofed)

#define DNS_DPORT       53                              // default DNS port (53)
#define TCP_SPORT       31337                           // default TCP source and destination ports
#define TCP_DPORT       80                              //
#define UDP_SPORT       31337                           // default UDP source and destination ports
#define UDP_DPORT       DNS_DPORT                       // (assume UDP is only used to carry DNS)

// ------------------------------------------------------------------------------------------------
/* DNS packet header */
struct dnshdr {                                         
        uint16_t id;                                    // identifier
        uint16_t flags;                                 // flags and codes
        uint16_t ques_cnt, ansr_cnt, ns_cnt, add_cnt;   // record counters
} __attribute__ ((packed));


/* DNS class and type enums */
enum RR_TYPE   { A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, TXT=16 };
enum DNS_CLASS { IN=1, CH=3, HS=4 };

/* TCP packet flags */
enum TCP_FLAGS { FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECN=0x40, CWR=0x80 };

// ------------------------------------------------------------------------------------------------ 
#endif
// ------------------------------------------------------------------------------------------------ 
