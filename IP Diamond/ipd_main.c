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
**  ipd_main.c
**
**  The main file of backbone. During startup, this backbone waits for a given number of relays 
**  to connect to it. Once all connections are established, backbone waits for a packet from 
**  kernel module (ipd_krnl). This would be easier if we used TUN/TAP interfaces. Then packet is
**  splited into (almost) equal fragments and each fragment is sent to a different relay (basic 
**  mode), or each fragment is sent to >1 different relays to achieve a fault tolerance
**  (redundancy mode). 
**
**  We need redundancy mode because:
**      [1] Relays are unreliable. It's possible for a relay to sunddenly go down. In this case 
**          we need to find the missing fragment and retransmit it, which takes some time.
**
**      [2] If a relay has very low bandwidth or high latency, it will the bottleneck.
**
**  By sending each fragment through >1 different relays, we are (almost) sure that at least 1 
**  fragment will arrive successfully. Also, among all copies of the same fragment, we only care 
**  about the "fastest" one. Note that it's better not to send >1 fragments to the same relay. 
**  For instance, if we need 3 relays for basic mode, we need 9 relays for redundancy mode with
**  redundancy factor 3.
**
**
**   * * * ---===== Command Line Arguments =====--- * * *
**
**      --attacker      Backbone runs on attacker's machine
**      --l2-relay      Backbone runs on level 2 relay machine
**      -b PORT         Port for backward traffic
**      -f PORT         Port for forward  traffic
**      -i IFNAME       Interface name to use its IP address (Default: eth0)
**      -n NRELAYS      Number of intermediate relays
**
**
**   * * * ---===== Examples =====--- * * *
**
**  * Run on attacker's machine. Use ports 9000 and 8000 and 3 level 1 relays.
**
**  sudo ./ipd_backbone -f 9000 -b 8000 -n 3 --attacker
**
**  * Run on level 2 relay. Use ports 9000 and 8000 and 3 level 1 relays.
**
**  sudo ./ipd_backbone -f 9000 -b 8000 -n 1 --l2-relay
**
**
**  * * * ---===== TODO list =====--- * * *
**
**  [1]. Implement redundancy mode.
*/
// ------------------------------------------------------------------------------------------------
#include "ipd_lib.h"                                    // all headers are here


// ------------------------------------------------------------------------------------------------ 
int         fsock[MAXLV1RLYS+1], bsock[MAXLV1RLYS+1];   // forward and backward sockets
int         nrlys = NRELAYS;                            // number of level 1 relays to wait for 
uint32_t    srcaddr;                                    // source IP address

// ------------------------------------------------------------------------------------------------ 
const  char *argp_program_version     = "IP Diamond v1.1";
const  char *argp_program_bug_address = "ispo@purdue.edu";
static char doc[]                     = "IP Diamond - Parallelizing bot relays: Backbone";
static char args_doc[]                = "";
static struct argp_option options[]   = 
{ 
    { NULL,  'f', "PORT",    0, "Port for forward  traffic" },
    { NULL,  'b', "PORT",    0, "Port for backward traffic" },
    { NULL,  'n', "NRELAYS", 0, "Number of intermediate relays" },
    { NULL,  'i', "IFNAME",  0, "Interface name to use its IP address (Default: eth0)" },

    { 0,0,0,0, "" },
    { "attacker",  '\x90', NULL, 0, "Backbone runs on attacker's machine" },    
    { "l2-relay",  '\x91', NULL, 0, "Backbone runs on level 2 relay machine" }, 
    { 0 } 
};

struct arguments {
    uint32_t    fport, bport;                           // forward and backward ports
    uint32_t    nrlys;                                  // number of intermediate relays
    uint32_t    mode;                                   // backbone mode
    char        *ifname;                                // interface name
};

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
        case 'f': arguments->fport  = atoi(arg);  break;
        case 'b': arguments->bport  = atoi(arg);  break;
        case 'n': arguments->nrlys  = atoi(arg);  break;
        case 'i': arguments->ifname = arg;        break;
        
        case '\x90': arguments->mode = ATTACKER_MODE; break;
        case '\x91': arguments->mode = L2_RELAY_MODE; break;
        
        case ARGP_KEY_ARG: return 0;
        default          : return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

// ------------------------------------------------------------------------------------------------
//  main(): 
//
//  main(): Wait some relays, to connect to you. Then start collecting fragments from relays and
//      try to reassemble packets. Once you reassemble a packet, route it.
//
//  Retunrn Value: 0 on success, -1 on failure.
//
//  Retunrn Value: 0 on success, -1 on failure.
//
int main( int argc, char *argv[] )
{   
    static struct argp  argp = { options, parse_opt, args_doc, doc, 0 };
    struct arguments    arguments = { 0 };
    pthread_t           thd_id[MAXLV1RLYS+1];           // thread handles
    int                 id[MAXLV1RLYS+1];               // thread IDs
    uint_t              n;                              // iterator
    
    
    /* Thread argument must be constant. If we pass an iterator as an  argument, */
    /* when thread reads the argument, iterator will be different                */
    for( n=0; n<=MAXLV1RLYS; ++n ) id[n] = n;           // set thread IDs

    arguments.ifname = DEFAULT_IF;                      // default interface


    /* ------------------------------------------------------------------------
     * Parse command line arguments
     * ------------------------------------------------------------------------ */  
    printf( "---===== ------------------------------------------ =====---\n"
            "---=====   PURDUE Univ. CS536 - Computer Networks   =====---\n"
            "---=====          Final Project: IP Diamond         =====---\n"
            "---=====                                            =====---\n"
            "---=====                                     -ispo  =====---\n"
            "---===== ------------------------------------------ =====---\n"
            "[INFO] ipd_backbone started...\n"
            "[INFO] Parsing arguments...\n" );


    /* parse arguments */
    if( argp_parse( &argp, argc, argv, 0, 0, &arguments ) < 0 )
        return -1;

    /* check arguments */
    myassert( CHKPORT(arguments.fport) && CHKPORT(arguments.bport), 
              "Invalid port number"
    );

    myassert( arguments.nrlys > 0 && arguments.nrlys <= MAXLV1RLYS,
              "Invalid number of relays"
    );

    myassert( arguments.mode == ATTACKER_MODE || arguments.mode == L2_RELAY_MODE,  
              "Invalid backbone mode"
    );

    myassert( (srcaddr = get_ifaddr(arguments.ifname)) != -1,
              "Invalid interface name"
    );


    printf( "[INFO] Forward port: %d. Backward port %d.\n"
            "[INFO] Waiting %d relays to connect...\n",
                arguments.fport, arguments.bport, arguments.nrlys
    );


    /* ------------------------------------------------------------------------
     *  Wait N intermediate (level 1) relays to connect to you
     * ------------------------------------------------------------------------ */
    nrlys = arguments.nrlys;                                // get #relays

    if( (fsock[0] = bind_serv(arguments.fport)) < 0 ||      // bind forward 
        (bsock[0] = bind_serv(arguments.bport)) < 0 )       //  and backward ports
            return -1;

    for( n=1; n<=arguments.nrlys; ++n ) {
        fsock[n] = accept(fsock[0], NULL, NULL);            // wait N level 1 relays
        bsock[n] = accept(bsock[0], NULL, NULL);

        /* we don't care if we store the 2 sockets of a relay in different slots */
    }

    printf( "[INFO] Waiting for packets...\n" );


    /* ------------------------------------------------------------------------
     *  Create nrlys+1 threads
     * ------------------------------------------------------------------------ */
    myassert( !pthread_create(&thd_id[0], NULL, usr_main, (void*)&arguments.mode), 
                "Cannot create thread" );

    for( n=1; n<=nrlys; ++n )
        myassert( !pthread_create(&thd_id[n], NULL, reassemble, (void*)&id[n]),
                    "Cannot create thread" )
        ;
        

    /* ------------------------------------------------------------------------
     *  Wait for threads to finish (if they)
     * ------------------------------------------------------------------------ */   
    for( n=0; n<=nrlys; ++n )
        pthread_join(thd_id[n], NULL);                  // wait for threads to terminate
    

    for( n=0; n<=nrlys; ++n ) {
        close(fsock[n]);            // close relays
        close(bsock[n]);            // close relays
    }
    
    printf("[INFO] Program stoped.\n");

    return 0;                                           // not always successful
}
// ------------------------------------------------------------------------------------------------
