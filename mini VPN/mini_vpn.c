// ------------------------------------------------------------------------------------------------ 
/*  Purdue CS528 - Network Security - Spring 2016
**  Lab 3: Virtual Private Network
**  Kyriakos Ispoglou (ispo)
**
**            _       ___     ______  _   _ 
**  _ __ ___ (_)_ __ (_) \   / /  _ \| \ | |
** | '_ ` _ \| | '_ \| |\ \ / /| |_) |  \| |
** | | | | | | | | | | | \ V / |  __/| |\  |
** |_| |_| |_|_|_| |_|_|  \_/  |_|   |_| \_|
**
**  miniVPN v1.0
**
**  miniVPN is a simple VPN server-client program. It provides an encrypted tunnel of IP packets
**  over UDP. It works as follows: First a tunnel interface is created at both ends and the routing
**  tables are configured properly. Then an SSL connection is established between server and 
**  client. Using this encrypted connection session keys and IVs are negotiated. Once the crypto
**  parameters configured, we we start forwarding packets between tunnel interfaces in both ends.
**  each packet is encrypted using AES128 CTR and encapsulated in a UDP payload. Thus we can ensure
**  confidentiality of the packet. Integrity is also provided by using HMAC of the encrypted 
**  packet (SHA 256 is used); Encrypt then MAC mode.
**
**  When connection established, both sides exchange an 48byte random nonce, and the session key
**  is calculated as follows: sess_key = md5(client_nonce || server_nonce). The goal of the 
**  session key is to be unpredictable, so the randomness of the nonces can ensure this property.
**  Using the counter mode, we exchange IVs through the SSL channel, and thus we don't have to 
**  send them within each packet.
**  
**  Note that it's possible for some reason IVs to stop being synchronized, if for example packets
**  arrive out of order. In that keys we have inform other peer and reset a new IV. We can easily 
**  detect unsynced IVs by placing a signature at the beginning of each packet. If decryption fails 
**  we can infer that IVs are not sync. This is because HMAC can provide ciphertext integrity, so 
**  the only reason that decryption will fail is due to the bad IVs. Note that with this design we
**  can detect replay attacks. Packets with invalid MAC are dropped.
**
**  Client can negotiate a new session key or set a new IV at any time and inform server about
**  this change.
**
**  Client is authenticated using public keys. If public keys are not available on the client 
**  side, we fall-back in username/password authentication. Server request and authentication
**  and client responds with a username and a password. Server verifies them by looking up
**  its shadow file and either allows clients to connect or terminates connection.
**
**
**   * * * ---===== Protocol Details =====--- * * *
**
**  Protocol runs over SSL channel. The UDP channel is used only for exchanging encrypted data.
**
**  Client starts with a HELO message, and server responds with a HELO ACK. If client hasn't 
**  public keys, server sends an AUTH REQ message and server responds with a USR AUTH message
**  which contains username and password. Server verifies the credentials and sends back either
**  an AUTH SUCC or an AUTH FAIL message.
**  
**  Once client gets authenticated, both sides send a NONCE and an IV message, and negotiate
**  a session key. During runtime, client can send a NONCE or an IV message and set a new IV
**  or a session key.
**
**  When client wants to terminate connection, a TUN FIN message is send, so the server can
**  release allocated resources.
**  
**
**   * * * ---===== Command Line Arguments =====--- * * *
**
**      -S              operate as a VPN server
**      -C <server_ip>  operate as a VPN client
**      -p <port>       port to connect or listen (depends on -S|-C)
**      -a <*.crt>      CA certificate file name
**      -c <*.crt>      host's certificate file name
**      -k <key>        host's private key file name
**      -U              use Username/Password authentication
**      -i <dev>        TUN interface device name
**      -l <iface_ip>   IP address of TUN interface
**      -m <iface_mask> subnet mask of TUN interface
**      -r <net_ip>     remote virtual network address
**      -n <net_mask>   remote virtual network subnet mask
**      -x              do not use tunnel encryption
**      -d              enable debug mode - display verbose information
**      -h              print help message and exit
**
**
**   * * * ---===== Runtime Commands =====--- * * *
**
**      SETKEY      Set a new nonce and update the session key
**      SETIV       Set a new IV and inform the other side
**      CLOSE       Close this command window
**      KILL        Kill current process (SERVER only) - Do not inform other side
**      EXIT        Terminate VPN peer (CLIENT only)
**      HELP        Print help message
**  
**
**   * * * ---===== Examples =====--- * * *
**
**  * Setup a VPN server at port 9999, using CA certificate 'ca.crt', server certificate 
**    'server.crt' and private key 'server.key'. Tunnel interface is 'tun0' with IP 10.0.1.1/24.
**    Remote network is 10.0.2.0/24. Enable debug mode.
**
**  sudo ./minivpn -S -p9999 -a ca.crt -c server.crt -k server.key 
**                 -i tun0 -l 10.0.1.1 -m 255.255.255.0 -r 10.0.2.0 -n 255.255.255.0 -d
**
**
**  * Connect to VPN server 192.168.1.100:9999 using public key authentication. Tunnel interface
**  is 'tun0' with IP 10.0.2.1/24. Remote network is 10.0.1.0/24. Enable debug mode too.
**
**  sudo ./minivpn -C 192.168.1.100 -p9999 -a ca.crt -c client.crt -k client.key 
**                 -i tun0 -l 10.0.2.1 -m 255.255.255.0 -r 10.0.1.0 -n 255.255.255.0 -d
**
**
**  * Connect to VPN server 192.168.1.100:9999 using username/password authentication. Tunnel 
**  interface is 'tun0' with IP 10.0.2.1/24. Remote network is 10.0.1.0/24. Enable debug mode too.
**
**  sudo ./minivpn -C 192.168.1.100 -p9999 -a ca.crt -U
**                 -i tun0 -l 10.0.2.1 -m 255.255.255.0 -r 10.0.1.0 -n 255.255.255.0 -d
**
**
**   * * * ---===== TODO list =====--- * * *
**
**  [1]. Do a better cleanup on main()
**  [2]. Check if IP addresses are valid on parse_args()
**  [3]. Check if server works against malicious clients (clients can send arbitrary data)
**  [4]. Huge IP packets cannot be encapsulated. In this cases we have to split them into fragments 
**          and send each fragment.
*/
// ------------------------------------------------------------------------------------------------ 
#include <stdio.h>                                      // a lot of required headers
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <getopt.h>
#include <crypt.h>
#include <shadow.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/route.h>
#include <arpa/inet.h> 
#include <openssl/rsa.h>                                // openssl stuff
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
// ------------------------------------------------------------------------------------------------ 
// #define UDP_TIMEOUT      10                          // max timeout in UDP response (disabled)
#define BACKLOG             32                          // max size of listen queue
#define OP_SERVER           1                           // operate as a server
#define OP_CLIENT           2                           // operate as a client 
#define OP_CLIENT_NOKEY     3                           // operate as a client with no pub key
#define MAX_PKT_SZ          16384                       // max encapsulated packet size
#define MAX_CTRL_PKT_SZ     128                         // max control packet size
#define PROTO_TCP           1                           // TCP protocol
#define PROTO_UDP           2                           // UDP protocol
#define TUN_PKT_SIG         "miniVPN\0"                 // Tunnel packet signature
#define TUN_PKT_SIG_SZ      8                           // Tunnel packet signature size
#define HMAC_DIGEST_LENGTH  SHA256_DIGEST_LENGTH        // HMAC is as long as SHA256
#define TEXT_CMD_MASK       0x0f                        // text command mask
#define DATA_CMD_MASK       0xf0                        // data command mask
#define MSG_SZ              16                          // control message size
#define NONCE_SZ            48                          // nonce size
#define IV_SZ               8                           // IV size
#define AUTH_SZ             80                          // user/pass combination size
#define KEY_SZ              16                          // key size
#define KEY_SZ_BITS         (KEY_SZ << 3)               // key size in bits
#define USR_PW_DELIMITER_S  "\x90"                      // delimiter between usr and pw (string version)
#define USR_PW_DELIMITER_C  '\x90'                      // and character version
#define MAX2(a,b)   (a) > (b) ? (a) : (b)               // maximum of 2 values
#define MAX3(a,b,c) MAX2(a,b) > (c) ? MAX2(a,b) : (c)   // maximum of 3 values


/* do some MACRO checks */
#if IV_SZ << 1 != AES_BLOCK_SIZE                        // IV size mismatch?
    #error "IV size does not match with AES block size!"
#endif 

#if MAX_PKT_SZ > 32768                                  // packet is going to be encapsulated
                                                        // it can't be very big
    #error "Maximum packet size is too big"             
#endif
// ------------------------------------------------------------------------------------------------ 
enum ctrl_cmd {                                         // commands over control channel
    UNDEF       = 0xff,         /* invalid command            */
    HELO        = 0x01,         /* hello message              */
    HELO_ACK    = 0x02,         /* acknowledge hello          */
    TUN_FIN     = 0x13,         /* finalize tunnel connection */
    AUTH_REQ    = 0x14,         /* authentication request     */
    USR_AUTH    = 0x15,         /* authenticate client        */
    AUTH_SUCC   = 0x16,         /* successful authentication  */
    AUTH_FAIL   = 0x17,         /* failed authentication      */
    IV          = 0x41,         /* set IV                     */
    NONCE       = 0x42          /* set nonce                  */
};

enum sighdlr_cmd {                                          // commands over signal handler
    NONE        = 0x00,         /* no action                  */
    EXIT        = 0x01,         /* terminate client           */
    SET_KEY     = 0x02,         /* change session key         */
    SET_IV      = 0x03          /* change IV                  */
};
// ------------------------------------------------------------------------------------------------ 
typedef unsigned char uchar;                            // unsigned char shortcut

typedef struct {                                        // buffer information
    uint8_t d[MAX_PKT_SZ];                              // data
    size_t  l;                                          // and length
} buf_t;

typedef struct {                                        // control data information
    size_t len;                                         // length 
    struct {
        uint8_t cmd;                                    // command type
        union {
            char    msg[MSG_SZ];                        // text message
            uint8_t iv[IV_SZ];                          // IV
            uint8_t nonce[NONCE_SZ];                    // nonce
            char    auth[AUTH_SZ];                      // user/pass separated by '\x90'
            uint8_t raw[MAX_CTRL_PKT_SZ - 1];           // raw interpretation of all the above
        } pl;                                           // payload 
    } buf;                                              // packet buffer (what to send)
} ctrl_t;

typedef struct {                                        // vpn session information
    struct peer_info {                                  // information about peer
        uint8_t  nonce[NONCE_SZ];                       // nonce
        uint8_t  iv[IV_SZ];                             // IV
        uchar    ivctr[AES_BLOCK_SIZE];                 // these 3 are needed for 
        uint32_t ctr;                                   //   AES_ctr128_encrypt
        uchar    ecount[AES_BLOCK_SIZE]; 
    } me, oth;                                          // keep info for you and for the other
    
    uint8_t key[KEY_SZ];                                // session key
    AES_KEY aeskey;                                     // session key as it used by AES*()
} vpnsess_t;

// ------------------------------------------------------------------------------------------------
/* global variables */  
vpnsess_t sess;                                         // session information
uint8_t   debug;                                        // debug mode (0/1)
uint8_t   hdlr_act;                                     // action requested from handler
uint8_t   op;                                           // operation    
uint8_t   dis_enc = 0;                                  // disable encryption?
// ------------------------------------------------------------------------------------------------




///////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                               //
//                                      AUXILIARY FUNCTIONS                                      //
//                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////

// ------------------------------------------------------------------------------------------------
/*
**  set_iv(): Set IV related variables that are needed by AES_ctr128_encrypt().
**
**  Arguments: p (peer_info*) : Which "side" to set (yours or others) 
*/
#define set_iv(p)                                       \
    (p)->ctr = 0;                                       \
    bzero ((p)->ecount, IV_SZ << 1);                    \
    bzero ((p)->ivctr,  IV_SZ << 1);                    \
    memcpy((p)->ivctr,  (p)->iv, IV_SZ);                \
                                                        \
    printf( "[+] Setting IV parameters: ");             \
    print_data((p)->ivctr, AES_BLOCK_SIZE)

// ------------------------------------------------------------------------------------------------
/*
**  set_ip(): Auxiliary function. ifreq and rtentry structs accept IP addresses through sockaddr_in
**      structures. However our IPs are in uint32_t format. The conversion is tricky, so we made a 
**      function.
**
**  Arguments: addr (sockaddr*) : struct to store ip address 
**             ip (uint32_t)    : ip address (BIG endian)
**
**  Return Value: None.
*/
void set_ip( struct sockaddr *addr, uint32_t ip )
{
    struct in_addr      ia = { .s_addr = ip };              // set in_addr struct first
    struct sockaddr_in *sa = (struct sockaddr_in*)addr;     // cast pointer

    sa->sin_family = AF_INET;                               // IPv4
    sa->sin_addr   = ia;                                    // set ip address
}

// ------------------------------------------------------------------------------------------------
/*
**  print_ip(): A wrapper of inet_ntoa(). Convert an uint32_t ip to a string. 
**
**  Arguments: ip (uint32_t) : ip address (BIG endian)
**
**  Return Value: A string containing the ip address.
*/
char *print_ip( uint32_t ip )
{ 
    struct in_addr addr = {.s_addr = ip };
    char*          str  = malloc(32);                   // aaa.bbb.ccc.ddd\0 = 16 bytes


    /*
     * It seems that inet_ntoa() uses a unique internal buffer to hold ip; if we say: 
     * printf( "%s %s", inet_ntoa(ip1), inet_ntoa(ip2)) the output will be "ip2 ip2". 
     * Thus we have to allocate a new space for out string, in order to be able to call
     * print_ip() many times within printf().
     *
     * NOTE: we have some leftovers on the heap.
     */
    strncpy(str, inet_ntoa(addr), 32);                  // convert and copy to a new string

    return str;                                         // return string
}

// ------------------------------------------------------------------------------------------------
/*
**  print_data(): Print binary data as hex.
**
**  Arguments: buf (uint8_t*) : our buffer
**             len (size_t)   : size of buffer
**
**  Return Value: None.
*/
void print_data( uint8_t *buf, size_t len )
{ 
    int i;                                              // iterator

    for( i=0; i<len; ++i )
        printf( "%02X", buf[i] & 0xff );                // print each byte

    printf( "\n" );
}

// ------------------------------------------------------------------------------------------------
/*
**  prnt_dbg(): A printf equivalent. We use prnt_dbg() to print debug information. If debug flag
**      is not set, nothing is printed.
**
**  Arguments: printf-like variable arguments
**
**  Return Value: None.
*/
void prnt_dbg( char *msg, ... )
{
    va_list args;                                       // argument list

    if( debug ) {                                       // debug is enabled?
        va_start(args, msg);
        vfprintf(stdout, msg, args);                    // print debug information
        va_end(args);
    }
}
// ------------------------------------------------------------------------------------------------




///////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                               //
//                                       TUNNEL FUNCTIONS                                        //
//                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////

// ------------------------------------------------------------------------------------------------
/*
**  tun_init(): Initialize tunnel. This process has several steps. First we create the tunnel
**      interface using TUN/TAP kernel module. Then we run the tun interface. Finally we add
**      an entry in the routing table for the remote network.
**
**  Arguments: dev (char*)       : interface name
**             ifip (uint32_t)   : interface ip address (BIG endian)
**             ifmask (uint32_t) : interface subnet mask (BIG endian)
**             rip (uint32_t)    : network ip of the other side of the tunnel (BIG endian)
**             rmask (uint32_t)  : network subnet mask of the other side of the tunnel (BIG endian)
**
**  Return Value: On success, function returns the tunnel descriptor. If an error occuers, 
**      function returns -1.
*/
int tun_init( char *dev, uint32_t ifip, uint32_t ifmask, uint32_t rip, uint32_t rmask )
{
// use this macro to avoid ugly repetition in the code
#define myassert(exp, msg)                                         \
    if( (exp) < 0 ) {                /* evaluate expression */     \
        perror( "[-] Error! " msg ); /* verbose error */           \
        close( sd );                 /* close socket descriptor */ \
        close( td );                 /* close tunnel descriptor */ \
        return -1;                   /* return (failure0 */        \
    }

    struct ifreq    ifr = { 0 };                        // interface request
    struct rtentry  route;                              // routing table entry
    int             sd, td;                             // socket & tunnel descriptor
    

    /* ------------------------------------------------------------------------
     * create tunnel interface
     * ------------------------------------------------------------------------ */
     printf( "[+] Creating tunnel interface %s...\n", dev );

    if( (td = open("/dev/net/tun", O_RDWR)) < 0 ) {     // open tun device for R+W
        perror("[-] Error! Cannot open TUN/TAP device");
        return -1;                                      // failure :(
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;                // TUN device | no packet information
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);               // set device name

    if( ioctl(td, TUNSETIFF, (void *)&ifr) < 0 ) {      // create interface
        perror("[-] Error! Cannot create TUN interface");
        close( td ); return -1;                         // close tunnel descriptor and exit
    }


    /* ------------------------------------------------------------------------
     * configure tunner interface
     * ------------------------------------------------------------------------ */
    printf( "[+] Configuring %s: inet addr:%s Mask:%s\n", dev, print_ip(ifip), print_ip(ifmask) );

    ifr.ifr_addr.sa_family = AF_INET;                   // IPv4

    sd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);      // create a socket first

    set_ip(&ifr.ifr_addr, ifip);                        // set interface ip address
    myassert(ioctl(sd, SIOCSIFADDR,    &ifr), "Cannot set interface address");

    set_ip(&ifr.ifr_addr, ifmask);                      // set interface network mask
    myassert(ioctl(sd, SIOCSIFNETMASK, &ifr), "Cannot set interface mask");

    ifr.ifr_flags = IFF_UP | IFF_RUNNING;               // run interface
    myassert(ioctl(sd, SIOCSIFFLAGS,   &ifr), "Cannot run interface");


    /* ------------------------------------------------------------------------
     * configure routing table
     * ------------------------------------------------------------------------ */
    printf( "[+] Configuring routing table: Destination:%s Gateway:0.0.0.0 Genmask:%s\n", 
            print_ip(rip), print_ip(rmask) );

    memset( &route, 0, sizeof(route) );                 // clear routing table entry
 
    set_ip(&route.rt_gateway, 0x00000000);              // set the gateway to 0,
    set_ip(&route.rt_dst,     rip);                     //   destination network and
    set_ip(&route.rt_genmask, rmask);                   //   subnet mask
 
    route.rt_dev    = dev;                              // set interface
    route.rt_flags  = RTF_UP;                           // route is usable
    route.rt_metric = 0;                                // clear metric
    
    myassert(ioctl(sd, SIOCADDRT, &route), "Cannot add routing entry");


    /* ------------------------------------------------------------------------
     * cleanup
     * ------------------------------------------------------------------------ */
    printf( "[+] Tunnel successfully configured.\n") ;

    close( sd );                                        // close temporary socket
    return td;                                          // return tunnel descriptor
#undef myassert                                         // we don't need this anymore
}

// ------------------------------------------------------------------------------------------------
/*
**  tun_send(): Send data over the tunnel.
**
**  Arguments: td (int)     : the tunnel descriptor
**             buf (buf_t*) : packet to send
**
**  Return Value: 0 on success, -1 on failure.
*/
int tun_send( int td, buf_t *buf )
{
    prnt_dbg("[+] Sending %d bytes to the tunnel.\n", buf->l);

    return write(td, buf->d, buf->l) < 0 ? -1 : 0;      // write data to tunnel descriptor
}

// ------------------------------------------------------------------------------------------------
/*
**  tun_recv(): Receive data from the tunnel.
**
**  Arguments: td (int)     : the tunnel descriptor
**             buf (buf_t*) : where to store packet
**
**  Return Value: -1 on failure. The number of bytes received on success.
*/
int tun_recv( int td, buf_t *buf )
{
    buf->l = read(td, buf->d, MAX_PKT_SZ);              // read packet

    prnt_dbg("[+] %d bytes received from tunnel.\n", buf->l);

    return buf->l;
}
// ------------------------------------------------------------------------------------------------




///////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                               //
//                                    DATA TRANSFER FUNCTIONS                                    //
//                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////

// ------------------------------------------------------------------------------------------------
/*
**  serv_init(): Initialize a server. Server will bind to a local address.
**
**  Arguments: port (uint16_t) : port to listen
**             proto (uint8_t) : socket protocol (TCP/UDP)
**
**  Return Value: server socket on success, -1 on failure.
*/
int serv_init( uint16_t port, uint8_t proto )
{
// If you want to set receive timeout on UDP sockets:
//      struct timeval tv = { .tv_sec = UDP_TIMEOUT, .tv_usec = 0 };
    struct sockaddr_in serv_addr = {                    // server's address information
            .sin_zero        = { 0,0,0,0,0,0,0,0 },     // zero this out
            .sin_family      = AF_INET,                 // IPv4
            .sin_port        = htons(port),             // listening port
            .sin_addr.s_addr = INADDR_ANY               // bind locally
        };
    int sd, opt = 1, retn = 0;                          // other vars

    
    /* make socket */
    if((sd = socket(AF_INET, proto == PROTO_TCP ? SOCK_STREAM : SOCK_DGRAM, 0)) < 0) {  
        perror("[-] Error! Cannot create socket");
        retn = -1;                                      // failure :(
    }

    /* avoid EADDRINUSE error on bind() */
    else if( setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0 ) {
        perror("[-] Error! Cannot reuse address");
        retn = -1;
    }

    else if( bind(sd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0 ) {
        perror("[-] Error! Cannot bind address");
        retn = -1;
    }

    /* listen() called only on TCP sockets */
    else if( proto == PROTO_TCP && listen(sd, BACKLOG) < 0 ) {
        perror("[-] Error! Cannot listen for connections");
        retn = -1;
    }

//  else if( proto == PROTO_UDP && 
//           setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 )  
//  {
//      perror("[-] Error! Cannot set timeout for UDP socket");
//      return -1;
//  }

    /* if socket() failed, we'll close an invalid socket. No problem. */
    if( retn < 0 ) { close(sd); return -1; }            // something went wrong

    return sd;                                          // return server's socket
}

// ------------------------------------------------------------------------------------------------
/*
**  serv_accp(): Accept a connection from a client
**
**  Arguments: serv_sd (int) : server's socket
**
**  Return Value: client socket on success, -1 on failure.
*/
int serv_accp( int serv_sd )
{   
    struct sockaddr_in  clnt_addr;                      // get client's info
    uint32_t            len = sizeof(clnt_addr);        //
    int                 sd;                             // socket descriptor


    /* wait for a client to connect to you */
    if( (sd = accept(serv_sd, (struct sockaddr*) &clnt_addr, &len)) < 0 ) {
        perror("[-] Error! Cannot accept connection");
        return -1;                                      // failure
    }
    
    printf("[+] Client %s:%d connected.\n", inet_ntoa(clnt_addr.sin_addr), clnt_addr.sin_port);

    return sd;                                          // return client's socket
}

// ------------------------------------------------------------------------------------------------
/*
**  clnt_init(): Initialize a connection with a remote server.
**
**  Arguments: ip (uint32_t)   : ip address of the server (ignored if proto is UDP)
**             port (uint16_t) : port of the server (ignored if proto is UDP)
**             proto (uint8_t) : server protocol (TCP/UDP)
**
**  Return Value: server socket on success, -1 on failure.
*/
int clnt_init( uint32_t ip, uint16_t port, uint8_t proto )
{
    int sd;                                             // socket descriptor
    struct sockaddr_in serv_addr = {                    // server's address information
            .sin_zero        = { 0,0,0,0,0,0,0,0 },     // zero this out
            .sin_family      = AF_INET,                 // IPv4
            .sin_port        = htons(port),             // listening port
            .sin_addr.s_addr = ip                       // bind locally
        };

    
    /* make socket */
    if((sd = socket(AF_INET, proto == PROTO_TCP ? SOCK_STREAM : SOCK_DGRAM, 0)) < 0) {
        perror("[-] Error! Cannot create socket");
        return -1;                                      // failure :(
    }

    /* connect to server */
    if(proto == PROTO_TCP && connect(sd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("[-] Error! Cannot connect to server");
        return -1;                                      // failure :(
    }

    return sd;                                          // return server socket
}

// ------------------------------------------------------------------------------------------------
/*
**  udp_send(): Send a UDP packet.
**
**  Arguments: sd (int)        : open socket to send data
**             ip (uint32_t)   : ip address of the remote host
**             port (uint16_t) : port of the remote host
**             pkt (buf_t*)    : packet to send
**
**  Return Value: 0 on success, -1 on failure.
*/
int udp_send( int sd, uint32_t ip, uint16_t port, buf_t *pkt )
{
    struct sockaddr_in addr = {                         // address information
            .sin_zero        = { 0,0,0,0,0,0,0,0 },     // zero this out
            .sin_family      = AF_INET,                 // IPv4
            .sin_port        = htons(port),             // listening port
            .sin_addr.s_addr = ip                       // bind locally
        };

    
    if( sendto(sd, pkt->d, pkt->l, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0 ) {        
        perror("[-] Error! Cannot send UDP packet");
        return -1;                                      // failure :(   
    }

    prnt_dbg( "[+] %d bytes sent to %s:%d\n", pkt->l, print_ip(ip), port );

    return 0;                                           // success!
}

// ------------------------------------------------------------------------------------------------
/*
**  udp_recv(): Receive data from an UDP packet. IP address and port of the remote host are
**      returned. We need this information in order to be able to send a response back.
**
**  Arguments: sd (int)         : open socket to send data
**             ip (uint32_t*)   : ip address of the remote host (OUT)
**             port (uint16_t*) : port of the remote host (OUT)
**             pkt (buf_t*)     : buffer to store packet (OUT)
**
**  Return Value: On success function returns 0 and len contains the number of bytes received. If
**      an error occurs, functions returns -1 and ip and port parameters don't change.
*/
// ------------------------------------------------------------------------------------------------
int udp_recv( int sd, uint32_t *ip, uint16_t *port, buf_t *pkt )
{
    struct sockaddr_in addr;                            // remote host address information
    socklen_t addrlen = sizeof(addr);                   //   and its size

    
    if( (pkt->l = recvfrom(sd, pkt->d, MAX_PKT_SZ, 0, (struct sockaddr*) &addr, &addrlen)) < 0 ) {
        perror("[-] Error! Cannot receive UDP packet");
        return -1;                                      // failure :(   
    }

    *ip   = addr.sin_addr.s_addr;                       // set ip address
    *port = htons(addr.sin_port);                       // set port

    prnt_dbg( "[+] %d bytes received from %s:%d\n", pkt->l, print_ip(*ip), *port );

    return 0;                                           // success!
}
// ------------------------------------------------------------------------------------------------




///////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                               //
//                             SSL CODE - CONTROL CHANNEL FUNCTIONS                              //
//                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////

// ------------------------------------------------------------------------------------------------
/*
**  ssl_init(): SSL preliminaries. Setup parameters and verify certificate.
**
**  Arguments: ca_crt (char*) : file path of the CA certificate
**             crt (char*)    : file path of the host certificate
**             key (char*)    : file path of the private key
**             op (uint8_t)   : operation (server/client)
**
**  Return Value: An SSL_CTX object on success. NULL on failure.
*/
SSL_CTX *ssl_init( char *ca_crt, char *crt, char *key, uint8_t op )
{
    SSL_CTX *ctx;                                       // SSL_CTX object to return


    SSL_load_error_strings();                           // register error strings
    SSLeay_add_ssl_algorithms();                        // register available ciphers/digests

    /* create the SSL_CTX object */
    if(!(ctx = SSL_CTX_new(op == OP_SERVER ? SSLv23_server_method() : SSLv23_client_method()))) {
        ERR_print_errors_fp( stderr );                  // print error 
        return NULL;                                    //   and return
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);     // set the verification flags
    SSL_CTX_load_verify_locations(ctx, ca_crt, NULL);   // verify CA certificate

    /* load certificate and private key */
    if( op != OP_CLIENT_NOKEY && (                      // if key has specified
        SSL_CTX_use_certificate_file(ctx, crt, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file (ctx, key, SSL_FILETYPE_PEM) != 1 )) 
    {
        SSL_CTX_free( ctx );                            // release object
        ERR_print_errors_fp( stderr );                  // print error 
        return NULL;                                    //   and return
    }

    /* verify that certificate corresponds to this private key */
    if( op != OP_CLIENT_NOKEY && SSL_CTX_check_private_key(ctx) != 1 ) {            
        printf( "[-] Error! Private not match with certificate's pub key!\n");
        SSL_CTX_free( ctx );                            // release object
        return NULL;                                    //   and return
    }

    return ctx;                                         // return SSL context
}

// ------------------------------------------------------------------------------------------------
/*
**  ssl_start(): Start SSL connection. Convert an open socket to an SSL connection.
**
**  Arguments: ctx (SSL_CTX*) : SSL context object
**             sd (int)       : open socket to convert it to SSL
**             op (uint8_t)   : operation (server/client)
**
**  Return Value: An SSL object on success. NULL on failure.
*/
SSL* ssl_start( SSL_CTX *ctx, int sd, uint8_t op )
{
    SSL *ssl;                                           // SSL object to return


    if( !(ssl = SSL_new(ctx)) ) {                       // create a new SSL objet 
        perror( "[-] Error! Cannot create SSL structure");
        return NULL;                                    // failure
    }
    SSL_set_fd(ssl, sd);                                // connect SSL object with socket

    switch( op )                                        // operation ?
    {
        case OP_SERVER:
            if( SSL_accept( ssl ) < 0 )                 // wait ab SSL connection
            {
                ERR_print_errors_fp(stderr);
                SSL_free( ssl );                        // release SSL object
                return NULL;                            //   and return
            }           
            break;

        case OP_CLIENT:
        case OP_CLIENT_NOKEY:
            if( SSL_connect( ssl ) < 0 )                // connect using SSL
            {
                ERR_print_errors_fp(stderr);
                SSL_free( ssl );                        // release SSL object
                return NULL;                            //   and return
            }
    }

    /* optional: print cipher suite */
    printf("[+] SSL connection using %s\n", SSL_get_cipher(ssl) );

    return ssl;                                         // return SSL object
}

// ------------------------------------------------------------------------------------------------
/*
**  ssl_cleanup(): Release allocated object.
**
**  Arguments: ctx (SSL_CTX*) : SSL context object
**             ssl (SSL*)     : SSL object
**
**  Return Value: None.
*/
SSL* ssl_cleanup( SSL_CTX *ctx, SSL *ssl )
{
    SSL_CTX_free( ctx );                                // release context
    SSL_free( ssl );                                    //   and SSL objects
}

// ------------------------------------------------------------------------------------------------
/*
**  ssl_prnt_cert(): Print other's side certificate.
**
**  Arguments: ssl (SSL*) : a valid SSL object
**
**  Return Value: If peer has a certificate function returns 1. Otherwise it returns 0.
*/
int ssl_prnt_cert( SSL *ssl )
{
    X509 *cert;                                         // X509 certificate


    if( cert = SSL_get_peer_certificate(ssl) )          // get X509 cert of other side
    {
        printf("[+] Peer certificate:\n");
        printf("[*] Subject: %s\n", X509_NAME_oneline(X509_get_subject_name(cert), 0, 0));
        printf("[*] Issuer:  %s\n", X509_NAME_oneline(X509_get_issuer_name (cert), 0, 0));
        
        X509_free( cert );                              // free certificate

        return 1;                                       // certificate found
    } 
    else printf("[+] Peer does not have a certificate.\n");

    return 0;                                           // certificate not found
}

// ------------------------------------------------------------------------------------------------
/*
**  ssl_send(): Send data over SSL socket. This function doesn't get called directly from main.
**
**  Arguments: ssl (SSL*)     : an SSL object
**             pkt (ctrl_t*)  : control packet to send
**
**  Return Value: 0 on success, -1 on failure.
*/
int ssl_send( SSL *ssl, ctrl_t *pkt )
{
    int rd;                                             // size of data to read


    /* send data over SSL */
    if( (rd = SSL_write(ssl, (uint8_t*)&pkt->buf, pkt->len)) <= 0 ) {   
        ERR_print_errors_fp( stderr );                  // print error
        return -1;                                      //   and return failure
    }

    prnt_dbg( "[+] %d Bytes sent to SSL channel\n", pkt->len ); 

    return 0;                                           // success
}

// ------------------------------------------------------------------------------------------------
/*
**  ssl_send(): Send data over SSL socket. This function doesn't get called directly from main.
**
**  Arguments: ssl (SSL*)     : an SSL object
**             pkt (ctrl_t*)  : control packet to store data (OUT)
**
**  Return Value: -1 on failure. If no errors occurred, len will contain the size of the received 
**      data and function returns 0.
*/
int ssl_recv( SSL *ssl, ctrl_t *pkt )
{   
    /* receive data from SSL */
    if( (pkt->len = SSL_read(ssl, (uint8_t*)&pkt->buf, MAX_CTRL_PKT_SZ)) <= 0 ) {       
        ERR_print_errors_fp( stderr );                  // print error
        return -1;                                      //   and return failure
    }

    prnt_dbg( "[+] %d Bytes received from SSL channel (Command: %d)\n", pkt->len, pkt->buf.cmd );

    if( debug && pkt->len > 1 && pkt->buf.cmd != USR_AUTH )
    {
        if( pkt->buf.cmd & DATA_CMD_MASK ) {            // we got data. print them as hex
            printf( "[+] Command Data: " );
            print_data(pkt->buf.pl.raw, pkt->len - 1);
        }   

        else
            printf( "[+] Command Text: %s\n", pkt->buf.pl.msg );
    }

    return 0;                                           // success
}

// ------------------------------------------------------------------------------------------------
/*
**  snd_cmd(): Send a command over our SSL control channel.
**
**  Arguments: cmd (uint8_t)  : command to send
**             pl  (uint8_t*) : command's payload (command type specifies payload length)
**             ssl (SSL*)     : active ssl object
**
**  Return Value: 0 on success, -1 on failure.
*/
int snd_cmd( uint8_t cmd, uint8_t *pl, SSL *ssl )
{   
    ctrl_t pkt;                                         // control packe to send


    bzero(pkt.buf.pl.raw, MAX_CTRL_PKT_SZ-1);           // remove dead data first (no memory leaks)

    switch( cmd )                                       // set payload first
    {
        // --------------------------------------------------------------------
        case HELO:
        case HELO_ACK:          
            pkt.len = MSG_SZ + 1;                       // set hello size           
            if( !pl ) return -1;                        // catch NULL pointers
            strncpy(pkt.buf.pl.msg, pl, MSG_SZ);        // copy hello message
            break;
        // --------------------------------------------------------------------
        case TUN_FIN:                                   // all these have no payload
        case AUTH_REQ:
        case AUTH_SUCC:
        case AUTH_FAIL:     
            pkt.len = 1;                                // 1 byte is enough
            break;
        // --------------------------------------------------------------------
        case USR_AUTH:
            pkt.len = AUTH_SZ + 1;                      // set credentials size
            if( !pl ) return -1;                        // catch NULL pointers
            strncpy(pkt.buf.pl.auth, pl, AUTH_SZ);      // copy credentials
            break;
        // --------------------------------------------------------------------
        case IV:
            pkt.len = IV_SZ + 1;                        // set iv size
            if( !pl ) return -1;                        // catch NULL pointers
            memcpy(pkt.buf.pl.iv, pl, IV_SZ);           // copy iv
            break;
        // --------------------------------------------------------------------
        case NONCE:
            pkt.len = NONCE_SZ + 1;                     // set nonce size
            if( !pl ) return -1;                        // catch NULL pointers
            memcpy(pkt.buf.pl.nonce, pl, NONCE_SZ);     // copy nonce
    }
    
    pkt.buf.cmd = cmd;                                  // set command

    return ssl_send( ssl, &pkt );                       // send packet and return
}

// ------------------------------------------------------------------------------------------------
/*
**  rcv_n_proc_cmd(): Receive and process a command. Wait for a command from control channel and
**      process it. Sometimes we send a command and we expect a response. If the response is not
**      the expecting one, we return an error.
**
**  Arguments: cmd (uint8_t) : expected command
**             ssl (SSL*)    : active ssl object
**
**  Return Value: >0 on success, -1 on failure. If FIN command received, function returns 1.
**      Otherwise a value of 0 is returned.
*/
int rcv_n_proc_cmd( uint8_t expcmd, SSL *ssl )
{
    ctrl_t pkt;                                         // control packe to send
    int    i;                                           // iterator


    if( ssl_recv( ssl, &pkt ) < 0 )                     // wait for a packet
        return -1;

    if( expcmd != UNDEF && pkt.buf.cmd != expcmd ) {    // expect a specific command?
        printf( "[-] Error! Unexpected command.\n" );
        return -1;                                      // failure
    }


    /* ------------------------------------------------------------------------
     * process command
     * ------------------------------------------------------------------------ */
    switch( pkt.buf.cmd )
    {
        // --------------------------------------------------------------------
        case HELO:     return strcmp(pkt.buf.pl.msg, "HELO") ? -1 : 0;
        // --------------------------------------------------------------------
        case HELO_ACK: return strcmp(pkt.buf.pl.msg, "HELO OK") ? -1 : 0;
        // --------------------------------------------------------------------
        case TUN_FIN:  return 1;                        // start teardown
        // --------------------------------------------------------------------
        case AUTH_REQ: return send_auth(ssl);           // send usr/pw
        // --------------------------------------------------------------------
        case USR_AUTH:
            /* extract username and password from payload */
            for( i=0; pkt.buf.pl.auth[i]; ++i )
                if( pkt.buf.pl.auth[i] == USR_PW_DELIMITER_C ) 
                {
                    pkt.buf.pl.auth[i] = '\0';
                    break;
                }

            if( i >= pkt.len -1 ||
                auth_usr(pkt.buf.pl.auth, &pkt.buf.pl.auth[i+1]) < 0 )
            {
                snd_cmd( AUTH_FAIL, NULL, ssl );        // send error message
                return 1;                               // terminate server instance
            }
            
            for( i=0; pkt.buf.pl.auth[i]; pkt.buf.pl.auth[i++]='\0');

            snd_cmd( AUTH_SUCC, NULL, ssl );            // client authenticated.
            
            break;
        // --------------------------------------------------------------------
        case AUTH_SUCC:
            printf( "[+] User authenticated successfully.\n" );
            break;
        // --------------------------------------------------------------------
        case AUTH_FAIL:
            printf( "[+] User authentication failed.\n" );
            return 1;                                   // terminate client
        // --------------------------------------------------------------------
        case IV:
            memcpy(sess.oth.iv, pkt.buf.pl.iv, IV_SZ);  // get new IV from peer
            set_iv(&sess.oth);                          // update AES parameters

            printf( "[+] IV updated: ");
            print_data(sess.oth.iv, IV_SZ);

            break;
        // --------------------------------------------------------------------
        case NONCE: 
            memcpy(sess.oth.nonce, pkt.buf.pl.nonce, NONCE_SZ);
        
            /* generate session key from nonces */
            if( gen_sesskey(op == OP_SERVER ? sess.oth.nonce : sess.me.nonce, 
                            op != OP_SERVER ? sess.oth.nonce : sess.me.nonce) < 0 )
                return -1;

            break;
        // --------------------------------------------------------------------
        default: printf( "[-] Error! Unknown command!\n" ); return -1;
    }
    
    return 0;                                           // success
}
// ------------------------------------------------------------------------------------------------




///////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                               //
//                            CRYPTO FUNCTIONS - SECURING THE TUNNEL                             //
//                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////

// ------------------------------------------------------------------------------------------------
/*
**  gen_sesskey(): Generate session key. Our session key is generated as follows:
**      sess_key = md5(client_nonce || server_nonce).
**      Nonces are sent over encrypted channel so, we don't have to implement more complex key
**      exchange schemes. Our key must be unique per session and unpredictable, and our scheme
**      satisfies both properties.
**
**  Arguments: client_nonce (uint8_t*) : client's nonce
**             server_nonce (uint8_t*) : server's nonce
**
**  Return Value: 0 on success, -1 on failure.
*/
int gen_sesskey( uint8_t *client_nonce, uint8_t *server_nonce )
{
#if KEY_SZ != MD5_DIGEST_LENGTH                         // session key fits in key buffer? 
    #error "Session key doesn't have the same size with key buffer"
 #endif

    MD5_CTX ctx;                                        // hash related data  


    MD5_Init( &ctx );                                   // set context
    MD5_Update( &ctx, client_nonce, NONCE_SZ );         // client nonce
    MD5_Update( &ctx, server_nonce, NONCE_SZ );         // concatenate server nonce
    MD5_Final( sess.key, &ctx );                        // get session key

    printf( "[+] Shared key negotiated: ");
    print_data(sess.key, KEY_SZ);                       // print session key

    if( AES_set_encrypt_key(sess.key, KEY_SZ_BITS, &sess.aeskey) < 0 ) {
        printf("[-] Error! Cannot set AES key!\n");
        return -1;                                      // failure x(
    }

    return 0;                                           // success!
}
    
// ------------------------------------------------------------------------------------------------
/*
**  hmac(): Calculate the HMAC of an (encrypted) packet. HMAC uses SHA256 hash.
**
**  Arguments: pkt (buf_t*)    : buffer that contains (encrypted packet)
**             hash (uint8_t*) : where to store HMAC (OUT)
**
**  Return Value: None.
*/
void hmac( buf_t *pkt, uint8_t *hash )
{
    uint32_t len = SHA256_DIGEST_LENGTH;                // hash size
    HMAC_CTX ctx;                                       // HMAC context

    HMAC_CTX_init(&ctx);                                // initialize context 
    HMAC_Init_ex(&ctx, sess.key, KEY_SZ, EVP_sha256(), NULL);
    HMAC_Update(&ctx, pkt->d, pkt->l);
    HMAC_Final(&ctx, hash, &len);
    HMAC_CTX_cleanup(&ctx);                             // we don't need context anymore
}

// ------------------------------------------------------------------------------------------------
/*
**  encr_pkt(): Encrypt a packet using AES 128 counter mode (CTR). The encrypted packet has the
**      following format:
**          +----------------------------------------+   |
**          |         miniVPN\0 (signature)          |   |
**          +----------------------------------------+    > AES-128-CTR 
**          |            original packet             |   |
**          +----------------------------------------+ __|
**          | HMAC(E(signature + packet)) (SHA-256)  |
**          +----------------------------------------+
**
**  HMAC can ensure cipher integrity. However it's possible that IV on the other side to not be
**  consistent with this IV (unsynchronized). In that cases decryption will fail. We can detect
**  such cases by looking whether the signature is valid upon decryption.
**
**  Arguments: pkt (buf_t*)    : input (unencrypted) packet
**             encpkt (buf_t*) : output (encrypted) packet (OUT)
**
**  Return Value: 0 on success, -1 on failure.
*/
int encr_pkt( buf_t *pkt, buf_t *encpkt )
{
    if( dis_enc )                                       // no encryption?
    {
        encpkt->l = pkt->l;                             // simply copy packet
        memcpy( encpkt->d, pkt->d, pkt->l );
        return 0;
    }

    memcpy(encpkt->d, TUN_PKT_SIG, TUN_PKT_SIG_SZ);     // copy signature first
    memcpy(&encpkt->d[TUN_PKT_SIG_SZ], pkt->d, pkt->l); // append original packet
        
    if( (encpkt->l = pkt->l + TUN_PKT_SIG_SZ) > MAX_PKT_SZ ) {
        printf("[-] Error! Packet overflow detected.\n");
        return -1;
    }

    encpkt->l = pkt->l + TUN_PKT_SIG_SZ;                // ignore overflows for now

    /* encrypt packet */
    AES_ctr128_encrypt( encpkt->d, encpkt->d, encpkt->l, &sess.aeskey, 
                        sess.oth.ivctr, sess.oth.ecount, &sess.oth.ctr );

    hmac( encpkt, &encpkt->d[encpkt->l] );              // append HMAC(ciphertext)  
    encpkt->l += HMAC_DIGEST_LENGTH;

    if( encpkt->l > MAX_PKT_SZ ) {
        printf("[-] Error! Packet overflow detected.\n");
        return -1;
    }

    return 0;                                           // success
}

// ------------------------------------------------------------------------------------------------
/*
**  decr_pkt(): Reverse function of encr_pkt(). Decrypt a packet. Before decryption verify its
**      HMAC and after decryption check if IVs are still synchronized.
**
**  Arguments: encpkt (buf_t*) : input (encrypted) packet
**             pkt (buf_t*)    : output (plain) packet (OUT)
**
**  Return Value: 0 -> success, -1 -> packet corrupted, -2 -> IV unsync.
*/
int decr_pkt( buf_t *encpkt, buf_t *pkt )
{   
    uint8_t hash[HMAC_DIGEST_LENGTH];                   // store HMAC here


    if( dis_enc )                                       // no encryption?
    {
        pkt->l = encpkt->l;                             // simply copy packet
        memcpy( pkt->d, encpkt->d, encpkt->l );
        return 0;
    }

    encpkt->l -= HMAC_DIGEST_LENGTH;                    // remove HMAC from packet
    hmac( encpkt, hash );                               // calculate HMAC

    /* verify HMAC */
    if( memcmp(&encpkt->d[encpkt->l], hash, HMAC_DIGEST_LENGTH) ) {
        printf( "[-] Error! Cannot verify packet HMAC. Ignoring packet...\n");
        return -1;                                      // ignore packet
    }

    /* decrypt packet (int CTR we actually encrypt twice) */
    AES_ctr128_encrypt( encpkt->d, encpkt->d, encpkt->l, &sess.aeskey, 
                        sess.me.ivctr, sess.me.ecount, &sess.me.ctr );
    
    /* verify signature */
    if( memcmp(encpkt->d, TUN_PKT_SIG, TUN_PKT_SIG_SZ) ) {

        // fatal error: IVs must resync
        printf( "[-] Error! Cannot verify packet's signature. Resync IVs...\n");
        print_data(encpkt->d, 32);
        return -2;                                      // failure
    }

    pkt->l = encpkt->l - TUN_PKT_SIG_SZ;
    memcpy(pkt->d, &encpkt->d[TUN_PKT_SIG_SZ], pkt->l); // extract plain packet

    return 0;                                           // success
}
// ------------------------------------------------------------------------------------------------




///////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                               //
//                                    MISCELLANEOUS FUNCTIONS                                    //
//                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////

// ------------------------------------------------------------------------------------------------
/*
**  send_auth(): Send an authentication request to the server
**
**  Arguments: ssl (SSL*) : an active SSL object
**
**  Return Value: 0 on success, -1 on failure.
*/
int send_auth( SSL *ssl ) //
{
    char auth[AUTH_SZ], *pw;                            // store credentials here
    int  i, retn = 0;                                   // assume success


    printf( "Username: "); 
    fgets(auth, AUTH_SZ, stdin);                        // read username
    pw = getpass("Password: ");                         //  and password

    auth[strlen(auth)-1] = '\0';                        // remove newline


    /* ...and pack them:  [username][DELIMITER][password] */    
    strncat(auth, USR_PW_DELIMITER_S, AUTH_SZ-strlen(auth));
    strncat(auth, pw, AUTH_SZ-strlen(auth) - 1);        // strlen(USR_PW_DELIMITER_S) = 1


    if( snd_cmd(USR_AUTH, auth, ssl) < 0 )              // authenticate client
        retn = -1;                                      // adjust return value
    
    for( i=0; pw[i];   pw[i++]='\0' );                  // don't leave passwords in memory
    for( i=0; auth[i]; auth[i++]='\0' );

    return retn;                                        // return
}

// ------------------------------------------------------------------------------------------------
/*
**  auth_usr(): Authenticate a client in case that public keys are missing.
**
**  Arguments: user (char*) : Username
**             pass (char*) : Password
**
**  Return Value: 0 on success, -1 on authentication failure or error.
*/
int auth_usr( char *user, char *pass )
{
    struct spwd *spwd;                                  // shadow password
    char        *pwhash;                                // password hash


    printf( "[+] Authenticating user \"%s\"...\n", user );

    /* get shadow password */
    if( (spwd = getspnam(user)) == NULL )
        ;

    /* hash input password */
    else if( (pwhash = crypt(pass, spwd->sp_pwdp)) == NULL )
        ;

    /* compare hashes */
    else if( strcmp(pwhash, spwd->sp_pwdp) == 0 ) {
        printf( "[+] Authentication succeeded.\n" );
        return 0;                                       // success!
    }

    printf( "[+] Authentication failed.\n" );

    return -1;                                          // failure
}

// ------------------------------------------------------------------------------------------------
/*
**  parse_args(): Parse command line arguments. Perform all required checks to ensure that all
**      arguments are correct.
**
**  Arguments: argc (int)          : main()'s argc
**             argv (char**)       : main()'s argv
**             op (uint8_t*)       : operation (serve/client) (OUT)
**             ip (uint32_t*)      : ip address of the server (OUT)
**             port (uint16_t*)    : port of the other size (OUT)
**             ca_cert (char**)    : CA certificate file (OUT)
**             cert (char**)       : host certificate (OUT)
**             priv_key (char**)   : host private key (OUT)
**             if_ip (uint32_t*)   : interface ip address (OUT)
**             if_mask (uint32_t*) : interface subnet mask (OUT)
**             r_net (uint32_t*)   : remote virtual network address (OUT)
**             r_mask (uint32_t*)  : remote virtual network subnet mask (OUT)
**             iface (char**)      : TUN interface name (OUT)
**
**  Return Value: 0 on success, -1 on failure.
*/
int parse_args( int argc, char *argv[], uint8_t *op, uint32_t *ip, uint16_t *port,
                char **ca_cert, char **cert, char **priv_key, char **iface, uint32_t *if_ip, 
                uint32_t *if_mask, uint32_t *r_net, uint32_t *r_mask )
{
    const char *help =  {                               // help text
        "Options Summary:\n"
        "\t-S\t\tOperate as a VPN server\n"
        "\t-C <server_ip>\tOperate as a VPN client\n"
        "\t-p <port>\tport to connect or listen (depends on -S|-C)\n"
        "\n"
        "\t-a <*.crt>\tCA certificate file name\n"
        "\t-c <*.crt>\tHost's certificate file name\n"
        "\t-k <key>\tHost's private key file name\n"
        "\t-U\t\tUse username/Password authentication\n"
        "\n"
        "\t-i <dev>\tTUN interface device name\n"
        "\t-l <iface_ip>\tIP address of TUN interface\n"
        "\t-m <iface_mask>\tSubnet mask of TUN interface\n"
        "\t-r <net_ip>\tRemote virtual network address\n"
        "\t-n <net_mask>\tRemote virtual network subnet mask\n"
        "\n"
        "\t-x\t\tDo not use tunnel encryption\n"
        "\t-d\t\tEnable debug mode - display verbose information\n"
        "\t-h\t\tPrint this message and exit\n"
        "\n"
    };

    int opt, longidx = 0;                               // getopt stuff
    struct option longopt[] = {                         // command line arguments
        {"client",      required_argument, 0, 'C'},
        {"server",      no_argument,       0, 'S'},
        {"port",        required_argument, 0, 'p'},
        {"ca-cert",     required_argument, 0, 'a'},
        {"certificate", required_argument, 0, 'c'},
        {"private-key", required_argument, 0, 'k'},
        {"userauth",    no_argument,       0, 'U'},
        {"interface",   required_argument, 0, 'i'},
        {"loc-net",     required_argument, 0, 'l'},
        {"loc-mask",    required_argument, 0, 'm'},
        {"rem-net",     required_argument, 0, 'r'},
        {"rem-mask",    required_argument, 0, 'n'},
        {"no-encr",     no_argument,       0, 'x'},
        {"debug",       no_argument,       0, 'd'},
        {"help",        no_argument,       0, 'h'},
        {0,             0,                 0,  0 }
    };


    /* ------------------------------------------------------------------------
     * parse options: for each option...
     * ------------------------------------------------------------------------ */
    while( (opt = getopt_long(argc, argv, "C:Sp:a:c:k:Ui:l:m:r:n:xdh", longopt, &longidx)) != -1 )
        switch(opt) 
        {                   
            case 'S': *op = OP_SERVER; *ip = 0xffffffff;        break;
            case 'C': *op = OP_CLIENT; *ip = inet_addr(optarg); break;
            case 'p': *port     = atoi(optarg); break;
            case 'a': *ca_cert  = optarg; break;
            case 'c': *cert     = optarg; break;
            case 'k': *priv_key = optarg; break;
            case 'U': *op = OP_CLIENT_NOKEY; break;
            case 'i': *iface    = optarg; break;
            case 'l': *if_ip    = inet_addr(optarg); break;
            case 'm': *if_mask  = inet_addr(optarg); break;
            case 'r': *r_net    = inet_addr(optarg); break;
            case 'n': *r_mask   = inet_addr(optarg); break;
            case 'x': dis_enc   = 1; break;
            case 'd': debug     = 1; break;
            default : printf( "\nUsage: %s [options]\n%s", argv[0], help );
                      return -1;
        }


    /* ------------------------------------------------------------------------
     * verify that the arguments are correct
     * ------------------------------------------------------------------------ */
#define cerr(s) printf( "[-] Error! " s ". Abort.\n\n" )

    if( *op != OP_SERVER && *op != OP_CLIENT && *op != OP_CLIENT_NOKEY ) 
        cerr( "Operation not set" );
    else if( !*ca_cert  && *op != OP_CLIENT_NOKEY ) cerr( "CA certificate is missing" );
    else if( !*cert     && *op != OP_CLIENT_NOKEY ) cerr( "Host certificate is missing" );
    else if( !*priv_key && *op != OP_CLIENT_NOKEY ) cerr( "Private key  is missing" );
    else if( !*iface )    cerr( "Interface name is missing" );
    else if( !*if_ip )    cerr( "Local network address is missing" );
    else if( !*if_mask )  cerr( "Local network mask is missing" );
    else if( !*r_net )    cerr( "Remote network address is missing" );
    else if( !*r_mask )   cerr( "Remote network mask is missing" );
    //
    // TODO: Check if network masks are valid
    //
    else 
        return 0;                                       // success!

#undef cerr


    /* ------------------------------------------------------------------------
     * error sink
     * ------------------------------------------------------------------------ */  
    printf( "\nUsage: %s [options]\n%s", argv[0], help );
    return -1;
}

// ------------------------------------------------------------------------------------------------
/*
**  sig_handler(): Handler to catch SIGINT signals. A small menu during runtime is provided.
**      User can set change session key, IV or close the tunnel.
**
**  Arguments: signum (int) : signal number
**
**  Return Value: None.
*/
void sig_handler( int signum )
{
    char cmd[16] = { 0 };                               // user command
    const char *help =  {                               // help message
        "Available Commands:\n"
        "* SETKEY : Set a new nonce and update the session key\n"
        "* SETIV  : Set a new IV and inform the other side\n"
        "* CLOSE  : Close this command window\n"
        "* KILL   : Kill current process (SERVER only) - Do not inform other side\n"
        "* EXIT   : Terminate VPN peer\n"
        "* HELP   : Print this message\n"
    };

    
    /* ------------------------------------------------------------------------
     * Ctrl+C pressed?
     * ------------------------------------------------------------------------ */
    if( signum == SIGINT )
    {
        printf( "\n================================================================\n");    
        
        for( ;; )                                       // forever...
        {
            printf( "Command?: ");
            fgets( cmd, 16, stdin );                    // read command
            cmd[strlen(cmd)-1] = '\0';                  // remove trailing newline

            /* process command */
                 if( !strcmp(cmd, "HELP")   ) printf("%s\n", help);
            else if( !strcmp(cmd, "KILL")   ) exit(0);
            else if( !strcmp(cmd, "CLOSE")  ) { hdlr_act = NONE;    return; }
            else if( !strcmp(cmd, "EXIT")   ) { hdlr_act = EXIT;    return; }           
            else if( !strcmp(cmd, "SETKEY") ) { hdlr_act = SET_KEY; return; }
            else if( !strcmp(cmd, "SETIV")  ) { hdlr_act = SET_IV;  return; }
            else printf("Unknown command! Type \"HELP\" for more information.\n");
        }
    }
}
// -----------------------------------------------------------------------------------------------




///////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                               //
//                                           MAIN CODE                                           //
//                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////

// -----------------------------------------------------------------------------------------------
/*
**  proc_fd(): Process file/socket descriptors. The problem here is that we have to wait for
**      3 descriptors at the same time: the tunnel descriptor for packets arriving to the 
**      tunnel interface, the ssl socket descriptor for control packets and the udp socket
**      descriptor for encrypted packets. Thus we have to use non-blocking calls and poll them.
**      When a descriptor gets ready, we read the data from it. A pthread approach won't work so 
**      well as it may be slower and much more complicated than select().
**
**  Arugments: tund (int)       : The tunnel descriptor
**              usockd (int)    : UDP socket descriptor
**              csockd (int)    : TCP socket descriptor (control channel)
**              ssl (SSL*)      : an active SSL object
**              ip (uint32_t)   : IP of the remote peer (for UDP)
**              port (uint16_t) : port of the remote peer (for UDP)
**
**  Return Value: If an error occurs, functions returns -1. Otherwise it loops for ever...
*/
int proc_fd( int tund, int usockd, int csockd, SSL *ssl, uint32_t ip, uint16_t port )
{
    const int   maxd = MAX3(tund, usockd, csockd);      // maximum descritptor
    fd_set      dset;                                   // descriptor set
    buf_t       pktin, pktout;                          // input and output packets
    
    
    for( ;; )                                           // forever...
    {
        /* ------------------------------------------------------------------------
         * this is our main loop. It's possible to have a signal hadler action 
         * request too
         * ------------------------------------------------------------------------ */
         switch( hdlr_act )
         {
            // ----------------------------------------------------------------
            case EXIT: 
                printf( "[+] Terminating client...\n" );
                                
                snd_cmd( TUN_FIN, NULL, ssl );          // send FIN request
                hdlr_act = NONE;                        // reset action
                return 1;                               //  finalize connection
            // ----------------------------------------------------------------
            case SET_KEY:
                printf( "[+] Negotiating a new session key...\n" );
                
                RAND_bytes(sess.me.nonce, NONCE_SZ);    
                printf("[+] Nonce updated: ");
                print_data( sess.me.nonce, NONCE_SZ);

                if( snd_cmd( NONCE, sess.me.nonce, ssl ) < 0 ||
                    gen_sesskey( sess.me.nonce, sess.oth.nonce ) < 0 )
                        return -1;          

                hdlr_act = NONE;                        // reset action             
                break;
            // ----------------------------------------------------------------
            case SET_IV:
                printf( "[+] Setting a new IV...\n" );
                                
                RAND_bytes( sess.me.iv, IV_SZ );        // generate a new IV    
                set_iv(&sess.me);                       // set AES parameters

                if( snd_cmd(IV, sess.me.iv, ssl) < 0 )  // send new IV to the other side
                    return -1;

                hdlr_act = NONE;                        // reset action
         }

         
        /* ------------------------------------------------------------------------
         * then poll socket descriptors
         * ------------------------------------------------------------------------ */
        FD_ZERO(&dset);                                 // clear set
        FD_SET(tund,   &dset);                          // add descriptors to the set
        FD_SET(usockd, &dset);
        FD_SET(csockd, &dset);

        if(select(maxd+1, &dset, NULL,NULL,NULL) < 0) { // check which desciptors are "ready"
            if( errno == EINTR ) continue;              // poll them again
            
            perror( "[-] Error! Cannot poll socket descriptors" );
            return -1;                                  // failure :(
        }

        bzero(pktin.d,  MAX_PKT_SZ);                    // clear packets (optional)
        bzero(pktout.d, MAX_PKT_SZ);


        /* ------------------------------------------------------------------------
         * check which descriptor(s) are ready
         * ------------------------------------------------------------------------ */
        if( FD_ISSET( tund, &dset ) )                   // data arrived from tunnel
        {
            if( tun_recv(tund, &pktin) < 0 ||           // read data from tunnel, 
                encr_pkt(&pktin, &pktout) < 0 ||        // encrypt them and 
                udp_send(usockd, ip, port, &pktout)<0 ) // send them to the other side
            {
                printf( "[-] Error! Cannot read from tunnel and send to peer.\n" );
                return -1;                              // failure
            }
        }

        if( FD_ISSET( usockd, &dset ) )                 // data arrived from the other side
        {
            if( udp_recv(usockd, &ip, &port, &pktin) < 0 )              
                return -1;
            
            switch( decr_pkt(&pktin, &pktout) )         // decrypt packet
            {
                case 0:                                 // success
                    if( tun_send(tund, &pktout) < 0 )   // forward packet to the tunnel                     
                        return -1;                      // potential error will be printed in tun_send
                    break;

                case -2:                                // IV is not sync                                   
                    RAND_bytes(sess.me.iv, IV_SZ);      // generate a new IV    
                    set_iv(&sess.me);                   // set AES parameters

                    if(snd_cmd(IV, sess.me.iv, ssl)<0)  // send new IV to the other side
                        return -1;

                /* in -1 case, packet is corrupted (non fatal), so we do nothing */
            }
        }

        if( FD_ISSET( csockd, &dset ) )                 // data arrived to the SSL channel
        {
            switch( rcv_n_proc_cmd(UNDEF, ssl) )        // process control command
            {
                case -1: printf( "[-] Error! Cannot read from control channel.\n" );
                         return -1;

                case 1:  return 0;                      // FIN received. Break loop.
            }
        }
    }

    return 0;                                           // exit with no errors?
}

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
    char        *ca_cert, *cert, *priv_key, *iface;     // string names
    uint32_t    ip, if_ip, if_mask, r_net, r_mask;      // ip addresses
    int         td, tsock, usock, csock;                // descriptors
    uint16_t    port;                                   // port 
    SSL_CTX     *ctx;                                   // context object
    SSL         *ssl;                                   // ssl object
    pid_t       pid;                                    // process id


    /* ------------------------------------------------------------------------
     * Parse command line arguments
     * ------------------------------------------------------------------------ */
    printf( "+--------------------------------------------------+\n"
            "|      PURDUE Univ. CS528 - Network Security       |\n"
            "|          Lab 3: Virtual Private Network          |\n"
            "|                                            -ispo |\n"
            "+--------------------------------------------------+\n\n" );
    printf( "[+] miniVPN v1.0 - (ispo@purdue.edu)\n");

    if( parse_args( argc, argv, &op, &ip, &port, &ca_cert, &cert, &priv_key, 
                    &iface, &if_ip, &if_mask, &r_net, &r_mask ) < 0 )
    {
        return -1;                                      // argument error. Abort
    }
    
    /* * * all IP addresses are in BIG endian * * */
    
    signal( SIGCHLD, SIG_IGN );                         // rip all defunct children
    signal( SIGINT, sig_handler );                      // catch ctrl+C


    /* ------------------------------------------------------------------------
     * configure tunnel and ssl connection
     * ------------------------------------------------------------------------ */
    if( (td = tun_init( iface, if_ip, if_mask, r_net, r_mask )) < 0 )
        return -1;

    printf( "[+] Initializing SSL. Verifying certificates...\n" );
    
    if( !(ctx = ssl_init(ca_cert,cert, priv_key, op)) ) // init SSL and verify certs
        return -1;

    switch( op )
    {
        // --------------------------------------------------------------------
        case OP_SERVER:         
            printf( "[+] Server started. Listening on port %d (TCP/UDP)...\n", port );

            usock = serv_init( port, PROTO_UDP );       // listen on TCP port
            tsock = serv_init( port, PROTO_TCP );       // listen on UDP port

            if( usock < 0 || tsock < 0 ) return -1;     // check sockets

            for( ;; )                                   // server multiple clients
            {
                if( (csock = serv_accp( tsock )) < 0 )  // wait for a TCP client
                    return -1;
                
                if( (pid = fork()) == 0 ) break;        // child process serves client
                if( pid < 0 ) {
                    printf( "[-] Error! Cannot fork server process!\n" );
                    return -1;                          // abort
                }

                /* parent process waits for the next client */
            }


            printf( "[+] Client connected. Starting SSL connection...\n" );

            if( !(ssl = ssl_start(ctx, csock, op)) )    // convert tcp connection to ssl
                return -1;

            /* SSL connection established. Wait for a hello message. */
            if( rcv_n_proc_cmd( HELO, ssl ) < 0 ||      // wait for hello message and acknowledge
                snd_cmd( HELO_ACK, "HELO OK", ssl ) < 0 ) 
                    return -1;                          /// TODO: do a cleanup


            if( !ssl_prnt_cert( ssl ) )                 // print other's side certificate
            {
                /* certificate doesn't exists. Ask for authentication */
                printf( "[+] Requesting Client authentication...\n");   

                if( snd_cmd( AUTH_REQ, NULL, ssl ) < 0 ||
                    rcv_n_proc_cmd( USR_AUTH, ssl ) )   // wait for creds
                {
                    printf( "[-] Exiting.\n" );
                    return -1;                      /// TODO: do a cleanup
                }
            }

            break;
        // --------------------------------------------------------------------     
        case OP_CLIENT:
        case OP_CLIENT_NOKEY:
            printf( "[+] Client started. Connecting to %s:%d\n", print_ip(ip), port );

            csock = clnt_init(ip, port, PROTO_TCP);     // connect to the server
            usock = clnt_init(0, 0, PROTO_UDP);         // create a UDP socket

            if( usock < 0 || csock < 0 ) return -1;     // check sockets


            printf( "[+] Starting SSL connection...\n" );
        
            if( !(ssl = ssl_start(ctx, csock, op)) )    // convert tcp connection to ssl
                return -1;                              /// TODO: do a cleanup

            if( !ssl_prnt_cert( ssl ) ) {               // print other's side certificate
                printf( "[-] Error! Server does not have a certificate.\n");
                return -1;                              /// TODO: do a cleanup
            }

            if( snd_cmd( HELO, "HELO", ssl ) < 0 ||         // start by sending a HELLO
                rcv_n_proc_cmd( HELO_ACK, ssl ) < 0 )       // wait for a HELLO ACK
                    return -1;                              /// TODO: do a cleanup

            if( op == OP_CLIENT_NOKEY )                 // key not provided?
            {
                printf( "[+] Public key not found. Authentication Required:\n");    
                
                if( rcv_n_proc_cmd( AUTH_REQ, ssl ) < 0 ||  // wait for authentication request
                    rcv_n_proc_cmd( UNDEF, ssl ) )          // AUTH_REQ will send a USR_AUTH
                                                            // so expect a SUCC/FAIL command
                        return -1;                          /// TODO: do a cleanup
            }

            break;
        // --------------------------------------------------------------------
    }


    /* ------------------------------------------------------------------------
     *  negotiate session key and exchange IVs
     * ------------------------------------------------------------------------ */  
    printf( "[+] SSL (control) channel established.\n" );
    printf( "[+] Negotiating session key and synchronizing IVs...\n" );

    RAND_bytes(sess.me.nonce, NONCE_SZ);                // generate a nonce
    if( snd_cmd(NONCE, sess.me.nonce, ssl) < 0 ||       //   and send it
        rcv_n_proc_cmd(NONCE, ssl) < 0 )                // wait for nonce from other side
            return -1;                                  /// TODO: do a cleanup
    
    /* generate session key from nonces */
    if( gen_sesskey(op == OP_SERVER ? sess.oth.nonce : sess.me.nonce, 
                    op != OP_SERVER ? sess.oth.nonce : sess.me.nonce) < 0 )
            return -1;                                  /// TODO: do a cleanup


    RAND_bytes(sess.me.iv, IV_SZ);                      // generate IV
    set_iv(&sess.me);                                   // set AES parameters

    printf( "[+] Generating IV: ");
    print_data(sess.me.iv, IV_SZ);                      // print you IV

    if( snd_cmd(IV, sess.me.iv, ssl) < 0 )              // send IV to the other side
        return -1;                                      /// TODO: do a cleanup
    
    /* IV from the other side will be received during proc_fd() */


    /* ------------------------------------------------------------------------
     *  start polling tunnel and socket descriptors and move data around them
     * ------------------------------------------------------------------------ */  
    printf( "[+] Waiting for packets...\n" );

    proc_fd(td, usock, csock, ssl, ip, port);           // enter main loop


    /* ------------------------------------------------------------------------
     *  cleanup code
     * ------------------------------------------------------------------------ */  
    printf( "[+] Finalizing Connection...\n" );

    ssl_cleanup(ctx, ssl);                              // release ssl objects

    close( csock );                                     // close descriptors
    close( tsock );
    close( usock );

    printf( "[+] Connection Closed.\nBye bye :)\n" );   

    return 0;                                           // success!
}
// ------------------------------------------------------------------------------------------------
