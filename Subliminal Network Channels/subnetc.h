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
**  subnetc.h
**
**  Exported API: This header contains the shared stuff between all files.
*/
// ------------------------------------------------------------------------------------------------ 
#ifndef SUBNETC_H_DEFINED
#define SUBNETC_H_DEFINED                               // include only once
// ------------------------------------------------------------------------------------------------ 
#include <stdio.h>                                      // includes from all files
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <argp.h>
#include <pcap.h>
#include <math.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// ------------------------------------------------------------------------------------------------ 
/* debug levels: How much information to display */
#define DBG_LVL_0           0                           // Do not display anything
#define DBG_LVL_1           1                           // Display only important things
#define DBG_LVL_2           2                           // Display packet flows
#define DBG_LVL_3           3                           // Display everything

#define OP_SERVER           0x10                        // operate as a server (receiver)
#define OP_CLIENT           0x20                        // operate as a client (sender)

#define COVERT_ICMP         0x0001                      // Use ICMP covert channel
#define COVERT_TCP          0x0002                      // Use TCP  covert channel
#define COVERT_DNS          0x0004                      // Use DNS  covert channel

#define COVERT_REQ          0x0100                      // Use request  packets
#define COVERT_RESP         0x0200                      // Use response packets

#define COVERT_NAT          0x0400                      // NAT is used

#define COVERT_MASK_LOW     0x00ff                      // mask to extract channel type
#define COVERT_MASK_HIGH    0xff00                      // mask to extract packet type

#define MAX_COVERT_CHAN_BW  (((16+14+32) >> 3) + 1)     // max possible bandwidth


#define DSA_SIGN_PARAM_SZ   20                          // signature parameter size
#define DSA_SIGN_SZ         DSA_SIGN_PARAM_SZ * 2       // signature size (depends on subldsa.c)


#define RECV_BUF_SZ         1048576
#define HEAP_PADD           65536                       // extra space in heap to allocate to avoid
                                                        // overflows

// ------------------------------------------------------------------------------------------------ 
/* type/enum definitions */
typedef unsigned char       byte;
typedef unsigned short int  word;
typedef unsigned int        uint;


extern int dbg_level;
// ------------------------------------------------------------------------------------------------ 
/* function declarations */

/*
**  primegen(): Generate secret primes for subliminal channels. 
**
**  Arguments: nprimes (int) : number of primes to generate
**
**  Return Value: 0 on success, -1 on failure.
*/
int primegen( int nprimes );


/*
**  dsagen(): Generate DSA parameters: p, q, g, x, y = g^x.
**
**  Arguments: None.
**
**  Return Value: A DSA struct on success, NULL on failure.
*/
DSA *dsagen( void );


/*
**  dsasubl_ins(): Generate a signature with a subliminal message in it.
**
**  Arguments: secret (byte*) : a binary array with the subliminal bits to insert
**             len (int)      : length of that array
**             r_only (byte)  : if set, do not return s
**
**  Return Value: 0 on success, -1 on failure.
*/
byte *dsasubl_ins( byte *secret, int len, byte r_only );


/*
**  dsasubl_ext(): Extract a subliminal message from a signature.
**
**  Arguments: sign (byte*)    : the DSA signature (r,s) only
**             len (int)       : length of the expected subliminal message
**             not_vrfy (byte) : if set, verify signature (s may be missing)
**
**  Return Value: A binary array with the subliminal bits in it. NULL on failure.
*/
byte *dsasubl_ext( byte *sign, int len, byte not_vrfy );


/*
**  rsagen(): Generate RSA parameters: n, e, p, q, d. 
**
**  Arguments: None.
**
**  Return Value: A RSA struct on success, NULL on failure.
*/
RSA *rsagen( void );


/*
**  rsaencr(): Encrypt a message using RSA. Message can't be greater than public modulus. To make
**      sure that decryption will be correct, add a tag before main message and encrypt it all
**      together.
**
**  Arguments: msg (byte*) : message to encrypt
**             mlen (int)  : message length
**             clen (int*) : ciphertext length (OUT)
**
**  Return Value: A pointer to the ciphertext. NULL on failure.
*/
byte *rsaencr( byte *msg, int mlen, int *clen );


/*
**  rsadecr(): Decrypt a ciphertext using RSA. Verify the decryption by chacking the tag at the
**      beginning of the plaintext.
**
**  Arguments: cipher (byte*) : ciphertext to decrypt
**             clen (int)     : ciphertext length
**             plen (int*)    : plaintext length (OUT)
**
**  Return Value: A pointer to the plaintext. NULL on failure. clen is updated properly to 
**      contain the length of the plaintext
*/
byte *rsadecr( byte *cipher, int clen, int *plen );


/*
**  transmit(): Send a small secret through a covert channel. 
**
**  Arguments: secret (byte*) : a binary array containing the secret to send
**             len (int)      : length of that array
**             dstip (char*)  : destination IP address
**             method (int)   : method to use for transmission
**             ack (int32_t)  : TCP ACK number (set to 0). Used only with TCP response method
**
**  Return Value: 0 on success, -1 on failure.
*/
int transmit( byte *secret, int len, char *dstip, int method, uint32_t ack );


/*
**  receive(): Wait for packets that have a covert channel from a remote host.
**
**  Arguments: iface (char*) : interface to start sniffing
**             dstip (char*) : destination IP address
**             nfrm (int)    : how many frames to sniff
**             method (int)  : covert channel method that used for transmission
**
**  Return Value: 0 on success, -1 on failure.
*/
int receive( char *iface, char *dstip, int nfrm, int method );


/*
**  prnt_dbg(): A printf equivalent. 
**
**  Arguments: printf-like variable arguments
**
**  Return Value: None.
*/
void prnt_dbg( int level, char *msg, ... );


/*
**  prnt_buf(): Print a buffer in hex notation.
**
**  Arguments: level (int) : debug level
**             msg (char*) : message before buffer
**             buf (byte*) : buffer to print
**             len (int)   : buffer length
**             bits (byte) : print buffer as bits
**
**  Return Value: None.
*/
void prnt_buf( int level, char *msg, byte *buf, int len, byte bits );


/*
**  load_secret(): Load a secret from a file.
**
**  Arguments: filename (char*) : filename to read secret from
**             buflen (int*)    : length of the buffer (OUT)
**
**  Return Value: A pointer to the buffer that holds the secret. NULL on failure.
*/
byte *load_secret( char *filename, int *buflen );


/*
**  store_secret(): Store a secret into a file.
**
**  Arguments: filename (char*) : filename to read secret from
**             buf (byte*)      : buffer to store
**             buflen (int)     : length of the buffer
**
**  Return Value: 0 on success, -1 on failure.
*/
int store_secret( char *filename, byte *buf, int buflen );


/*
**  expand(): Expand a buffer to its binary format. 
**
**  Arguments: buf (char*)   : buffer to expand
**             buflen (int*) : length of the buffer (IN/OUT)
**
**  Return Value: A pointer to the expanded buffer. buflen is updated to show the new buffer 
**      length. NULL on failure.
*/
byte *expand( byte *buf, int *buflen );


/*
**  shrink(): Opposite of expand(). 
**
**  Arguments: buf (char*)   : expanded buffer
**             buflen (int*) : length of the buffer (IN/OUT)
**
**  Return Value: A pointer to the shrinked buffer. buflen is updated to show the new buffer 
**      length. NULL on failure.
*/
byte *shrink( byte *buf, int *buflen );


/*
**  pack(): Convert a sequence of bits in a big-endian number.
**
**  Arguments: buf (byte*) : buffer to read bits from
**             bits (uint) : how many bits to read
**  
**  Return Value: This number on success, -1 on failure.
*/
inline uint32_t pack( byte* buf, uint bits );


/*
**  unpack(): Inverse of pack(). Convert a big-endian number to sequence of bits
**
**  Arguments: num (uint32_t) : number to covert to bit stream
**             bits (uint)    : how many bits to extract
**             buf (byte*)    : buffer to store bits
**  
**  Return Value: A pointer to the beginning of bit stream, NULL on failure.
*/
inline byte *unpack( uint32_t num, uint bits, byte *buf );


/*
**  accumulate(): Callback function of receive(). Accumulate some bits to the existing ones.
**
**  Arguments: buf (byte*) : buffer with the new bits
**             len (int)   : buffer length
**
**  Return Value: None.
*/
void accumulate( byte *buf, int len );

// ------------------------------------------------------------------------------------------------ 
#endif
// ------------------------------------------------------------------------------------------------ 
