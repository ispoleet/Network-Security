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
**  ipd_relay.c
**
**  The simplest part of the project. Each relay is connected (back) to both backbones that run 
**  in attacker's and level 2 relay machines. Level 1 relays are usually home computers behind 
**  NAT, it's better not to bind, but to use reverse connections instead. Once connections are 
**  established, ipd_relay it simply forwards data from one socket to another.
**
**  Note that we open 2 connections to each side: One for forward traffic and one for backward
**  (reverse) traffic. We could use select() and non-blocking sockets, to use 1 socket for both
**  directions, but this approach is simpler.
**
**
**   * * * ---===== Command Line Arguments =====--- * * *
**
**      -1 IPADDR       IP address of the first backbone
**      -2 IPADDR       IP address of the second backbone
**      -b PORT         Port for backward traffic in backbone #1
**      -B PORT         Port for backward traffic in backbone #2
**      -f PORT         Port for forward  traffic in backbone #1
**      -F PORT         Port for forward  traffic in backbone #2
**
**
**   * * * ---===== Examples =====--- * * *
**
**  * Connect to 192.168.1.100 at ports 9000 and 8000 and  to 192.168.1.101 at ports 9000 and
**      8000.
**
**  ./ipd_relay -1 192.168.1.100 -f 9000 -b 8000 -2 192.168.1.101 -F 9000 -B 8000
*/
// ------------------------------------------------------------------------------------------------
#include <unistd.h>                                     
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <argp.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

// ------------------------------------------------------------------------------------------------
#define MAXIPLEN            65536                       // max IP packet size
#define CHKPORT(p)          ((p) > 0 && (p) <= 65536)   // check if port is valid
#define SET_SOCKADDR(s, ip, port)       \
    s.sin_family = AF_INET;             \
    s.sin_port        = htons(port);    \
    s.sin_addr.s_addr = inet_addr(ip);  \
    bzero(s.sin_zero, 8)


struct sockdir_t {                                      // used to make easy bidirectional traffic
    int from_sd, to_sd;                                 // source and destination sockets
};

// ------------------------------------------------------------------------------------------------ 
const  char *argp_program_version     = "IP Diamond v1.1";
const  char *argp_program_bug_address = "ispo@purdue.edu";
static char doc[]                     = "IP Diamond - Parallelizing bot relays: Relay";
static char args_doc[]                = "";
static struct argp_option options[]   = 
{ 
    { NULL,  '1', "IP_ADDR",   0, "Backbone #1 IP address" },
    { NULL,  '2', "IP_ADDR",   0, "Backbone #2 IP address" },
    { 0,0,0,0, "" },
    { NULL,  'f', "PORT",   0, "Port for forward  traffic in backbone #1" },
    { NULL,  'b', "PORT",   0, "Port for backward traffic in backbone #1" },
    { NULL,  'F', "PORT",   0, "Port for forward  traffic in backbone #2" },
    { NULL,  'B', "PORT",   0, "Port for backward traffic in backbone #2" },
    { 0 } 
};

struct arguments {
    char        *b1_ip, *b2_ip;                         // Backbone's IP addresses
    uint32_t    f_port, b_port, F_port, B_port;         // and ports
};


// ------------------------------------------------------------------------------------------------
//  myassert(): Evaluate a condition and abort on failure, by printing the appropriate message.
//
//  Retunrn Value: None.
//
void myassert( int cond, char *err )
{
    if( !cond ) {                                       // false condition?
        printf( "[ERROR] %s. Abort\n", err );

        exit( EXIT_FAILURE );                           // abort
    }
}

// ------------------------------------------------------------------------------------------------
//  parse_opt(): Callback function of argp_parse().
//
//  Arguments: key (int)          : short option set
//             arg (char*)        : argument value
//             state (argp_state) : internal state of argp
//
//  Return Value: 0 on success, an error code on failure.
//
static error_t parse_opt( int key, char *arg, struct argp_state *state ) 
{
    struct arguments *arguments = state->input;

    switch( key )                                       // parse argument
    {
        case '1': arguments->b1_ip  = arg;       break;
        case '2': arguments->b2_ip  = arg;       break;
        case 'f': arguments->f_port = atoi(arg); break;
        case 'b': arguments->b_port = atoi(arg); break;
        case 'F': arguments->F_port = atoi(arg); break;
        case 'B': arguments->B_port = atoi(arg); break;
        
        case ARGP_KEY_ARG: return 0;
        default          : return ARGP_ERR_UNKNOWN;
    }   

    return 0;
}

// ------------------------------------------------------------------------------------------------
//  relay_func(): Read data from one socket and send them to another.
//
//  Return Value: Function always returns NULL.
//
void *relay_func( void *thread_data )
{
    struct sockdir_t *sd = (struct sockdir_t*) thread_data; // get socket directions
    char             buf[MAXIPLEN];                         // packet buffer
    int              nrd;                                   // number of bytes read


    printf("[INFO] Relay Function started...\n");

    while((nrd = recv(sd->from_sd,buf,MAXIPLEN-1,0))>0) // read packet from one side
    {
        printf ("[INFO] Relaying fragment (%d -> %d)!\n", sd->from_sd, sd->to_sd);

        if( send(sd->to_sd, buf, nrd, 0) != nrd ) {     // forward packet to the other side
            perror( "[ERROR] Cannot forward data" );
            return NULL;
        }
    } 

    printf("[INFO] Relay Function stoped.\n");

    if( nrd < 0 ) {                                     // error on read?
        perror( "[ERROR] Cannot receive data" );
        return NULL;
    }
    
    return NULL;                                        // we don't care about this
}

// ------------------------------------------------------------------------------------------------
//  main(): Establish connections with attacker and level 2 relay and spawn 2 threads to relay
//      data back and forth.
//
//  Return Value: 0 on success. -1 on failure. We can't detect errors on relay_func().
//
int main(int argc, char *argv[])
{
    static struct argp argp    = { options, parse_opt, args_doc, doc, 0 };
    struct arguments arguments = { 0 };

    struct sockdir_t    fwd, rvs;                       // socket directions
    struct sockaddr_in  f, b, F, B;                     // socket information
    pthread_t           thd_back, thd_forth;            // thread and 
    int                 f_sock, b_sock, F_sock, B_sock; //   socket descriptors
        

    /* ------------------------------------------------------------------------
     * Parse command line arguments
     * ------------------------------------------------------------------------ */  
    printf( "---===== ------------------------------------------ =====---\n"
            "---=====   PURDUE Univ. CS536 - Computer Networks   =====---\n"
            "---=====          Final Project: IP Diamond         =====---\n"
            "---=====                                            =====---\n"
            "---=====                                     -ispo  =====---\n"
            "---===== ------------------------------------------ =====---\n"
            "[INFO] ipd_relay started...\n"
            "[INFO] Parsing arguments...\n" );

    if( argp_parse( &argp, argc, argv, 0, 0, &arguments ) < 0 )
        return -1;

    myassert( arguments.b1_ip && arguments.b2_ip, "IP address is missing" );

    myassert( CHKPORT(arguments.f_port) &&
              CHKPORT(arguments.b_port) &&
              CHKPORT(arguments.F_port) && 
              CHKPORT(arguments.B_port), "Port is missing" );

    printf( "[INFO] Backbone #1 (%s) at ports: %d -> %d\n"
            "[INFO] Backbone #2 (%s) at ports: %d -> %d\n",
            arguments.b1_ip, arguments.f_port, arguments.b_port,
            arguments.b2_ip, arguments.F_port, arguments.B_port
        );

    SET_SOCKADDR(f, arguments.b1_ip, arguments.f_port);
    SET_SOCKADDR(b, arguments.b1_ip, arguments.b_port);
    SET_SOCKADDR(F, arguments.b2_ip, arguments.F_port);
    SET_SOCKADDR(B, arguments.b2_ip, arguments.B_port);


    /* ------------------------------------------------------------------------
     * Connect (back) to backbones #1 and #2
     * ------------------------------------------------------------------------ */
    if( (f_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ||
        (b_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ||
        (F_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ||
        (B_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
            perror( "[ERROR] Cannot create socket(s)" );
            return -1;
    }

    if( connect(f_sock, (struct sockaddr*)&f, sizeof(struct sockaddr_in)) < 0 ||
        connect(b_sock, (struct sockaddr*)&b, sizeof(struct sockaddr_in)) < 0 ||
        connect(F_sock, (struct sockaddr*)&F, sizeof(struct sockaddr_in)) < 0 ||
        connect(B_sock, (struct sockaddr*)&B, sizeof(struct sockaddr_in)) < 0 ) {
            perror( "[ERROR] Cannot connect to relay (and/or) attacker" );

            return -1;
    }

    // set sockets for directions (forward and reverse) 
    // with this trick, we can use the same code for both directions
    fwd.from_sd = f_sock; fwd.to_sd = B_sock;
    rvs.from_sd = F_sock; rvs.to_sd = b_sock;

    printf( "[INFO] ipd_relay connected to both sides...\n" );


    /* ------------------------------------------------------------------------
     * Spawn 2 threads: one for each direction of traffic
     * ------------------------------------------------------------------------ */
    if( pthread_create(&thd_back,  NULL, relay_func, (void*) &fwd) || 
        pthread_create(&thd_forth, NULL, relay_func, (void*) &rvs) ) {
            perror( "[ERROR] Cannot create thread" );
            return -1;
    }
 
    pthread_join(thd_back,  NULL);                      // wait for threads to finish
    pthread_join(thd_forth, NULL);   

    return 0;
}
// ------------------------------------------------------------------------------------------------
