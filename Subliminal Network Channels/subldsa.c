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
**  subldsa.c
**
**  This file implements a subliminal channel using DSA. There are 2 ways for implementing a
**  subliminal channel using DSA. The first way is to hide information in k parameter. If the
**  verifier knows the secret key x, he can trivially extract k and read the message. This
**  can gives us good bandwidth, but we have to be careful because if we send the same secret
**  twice, an adversary can decrypt our secret x and break the channel.
**
**  The 2nd method is more stealthy and based on quadratic residues. Verifier does not need
**  to know the secret key. Both sides agree on a number of large secret primes (~10-16). For
**  simplicity, assume that these primes are already shared. Now the we sign a message and we
**  the signature (r,s). If the 1st bit of the secret is 1 then we want r to be quadratic 
**  residue modulo the 1st prime. If the 1st bit is 0, then we want r to be quadratic non
**  residue modulo the 1st prime. If the 2nd bit of the secret is 1, then we want r to be 
**  quadratic residue modulo the 2nd prime, and so on. No one can read this information.
**  Even if someone knows what happens he can't prove anything unless he knows the secret
**  primes. So the security here is based on our secret primes. We can exchange them using DH
**  and update them periodically to ensure forward secrecy but I leave it for future versions.
**  
**  So we start signing the message until we get a 'good' r. Because the number of quadratic
**  residues and quadratic non-reisudes in a prime modulo are about equal the chances to get
**  a 'good' r are 2^-N, where N is the number of subliminal bits we want to leak. The more
**  data we leak the harder is to find a suitable r.
**
**  As you can see, in case that we don't verify the signature s parameter is useless. For
**  this reason signature verification is optional and we omit s from transmission. Each
**  of r,s is 160 bits long, and we can leak around 12 bits per signature in a reasonable 
**  time. You can see that bandwidth is very low (160 bits to leak 12), but we have ultimate 
**  stealthiness.
**  
**
**   * * * ---===== TODO list =====--- * * *
**
**      [1]. Current version signs a constant message that is known to both sides. It would be
**           better if we sign the actual packets that get transmitted so ensure packet integrity.
**
**      [2]. Functions do not keep any state about the keys. Every time we want to send a packet
**           we load and we unload the DSA parameters. It may sounds inefficient, but we only
**           set and unset BIGNUMs from constant arrays and we don't have to pass an extra argument
**           at each function. Keep state of DSA parameters could be an option here.
*/
// ------------------------------------------------------------------------------------------------ 
#include "subnetc.h"                                    // all includes are here

#define SEED_SIZE           32                          // random seed for number generation
#define DSA_SIGN_MSG        "ispoooooooooooo\0"         // message to sign
#define DSA_SIGN_MSG_LEN    16                          // 
#define PRIME_SIZE          128                         // prime number size in bits
#define PRIME_SIZE_BYTES    (PRIME_SIZE >> 3)           //   and bytes
#define DSA_PARAM_LEN       160                         // DSA_generate_parameters has 1st argument
#define DSA_PARAM_LEN_BYTES (DSA_PARAM_LEN >> 3)        //   <2048 this is 160. Otherwise it's 256
#define N_SECRET_PRIMES     16                          // max number of primes
#define SUBL_CHANNEL_BW     N_SECRET_PRIMES             // max bandwidth for subliminal channel (bits)

/* How many times to search for a 'good' signature. With 2^N_SECRET_PRIMES tries
 * we expect to find a number with very good probability. To be totally safe we
 * multiply it with 64, so the chances to not find anything are very small
 */
#define SUBL_MSG_MAXTRIES   (1 << N_SECRET_PRIMES) << 5


/* our sercet primes for subliminal channel (we may not use all of them) */
const byte secret_prime[16][16] = {
    "\xe6\xda\xb5\xfd\xd3\xe6\x5f\xad\x69\x2d\x0a\x6b\x33\x1e\x7b\x91",
    "\xfa\x6a\x9e\x14\xa0\x26\xe9\xc0\x89\xda\xb8\x6b\xbf\xa5\xe9\x9d",
    "\xf4\x92\x36\xd9\xc5\x29\x47\x72\x83\x5d\x56\x4c\xb4\x7d\xed\xc9",
    "\xf4\x46\x3b\xf4\xc9\xe8\x10\x9e\xe6\x77\x01\xea\x73\xd8\x33\xe9",
    "\xc0\x8e\xf0\x07\xeb\x0d\xda\x16\x20\xe7\xff\x8c\x20\xde\xcc\x85",
    "\xd0\x41\x3c\xad\x5e\x4a\x4a\xda\xc7\x2c\x14\x03\xe9\xc0\x12\xbb",
    "\xe3\x7c\xc0\x68\xaa\xd3\x34\x79\xa5\x67\x75\xaf\x7b\x5a\x87\x9b",
    "\xee\xae\x25\xd7\x84\x98\x40\x4d\x61\x55\x6b\xd5\xba\x9c\x98\xef",
    "\xd2\xf6\xdf\x15\x2f\x10\x39\x65\xcd\x52\x1e\x1c\x27\xfa\x8b\x63",
    "\xec\x9c\x80\x38\x52\x55\xc7\x45\x46\x70\xac\x88\x3d\xfe\x35\x5f",
    "\xc2\x68\x0b\x61\x4a\x1b\xa4\xa2\xd9\x17\x46\x92\x7e\x1d\xd4\x53",
    "\xdd\xbf\x9f\x6d\x72\x8b\x1a\xc9\xa8\x86\xdd\xa8\xc8\x66\xe8\xcb",
    "\xd2\x95\xd2\x31\xbc\x5d\x46\x5e\x38\xfc\x24\xc1\x8a\x20\xb3\x81",
    "\xf0\x2f\x8a\x87\x36\x7d\xae\x04\xc1\x10\x37\xb2\xc5\x1f\x75\x71",
    "\xcf\x0c\xe9\x70\x97\x0b\x82\x47\x38\x4f\xf5\x93\xa6\xe3\x99\x99",
    "\xe5\xf9\xde\xd0\x71\xfe\xb8\xbc\x3c\xc1\x0c\xf7\x22\xa3\xe4\xc7",
};

/* DSA public parameters */
const byte *_p   = "\xec\x91\x71\xa1\xe4\x83\xfd\xa3\x66\x47\x0f\x3a\x3a\x37\x5f\x3f\x13\xaa\xef\x2f"
                   "\x19\x24\x3b\x6d\xa0\xb6\xa9\x4b\xf9\x06\xd8\x83\xeb\x0c\x4f\x43\xee\x5a\x10\x34"
                   "\x79\xd1\x6a\x2c\xad\x01\x86\x50\x6a\xfd\x4b\xb6\x44\x02\x84\x43\x9c\xb9\x1b\xc9"
                   "\xf2\x7b\x55\x6a\xba\x00\x52\xa0\x30\x66\x8e\xfe\x14\x7e\xdd\x70\x87\xf3\xe5\x7f"
                   "\x5f\xf0\xac\x84\x06\x05\xab\xe7\xf8\xf8\x64\xed\x2a\xa6\xa2\x09\xe5\xc6\xca\x06"
                   "\x54\xf1\x39\x30\x4a\xcf\x62\x60\x8b\xf5\x44\xaa\xd9\x62\xb7\xf4\xc1\x6a\xaf\x2a"
                   "\x42\x86\x0c\x6a\x82\xd3\x92\x89";

const byte *_q   = "\xc7\x47\x9f\xb3\xf4\xdd\xcb\xda\x1a\x3a\xaf\xba\xfd\x25\x6f\x8b\xa7\x85\x89\x55";

const byte *_g   = "\x99\x8c\x79\xb9\xf9\x61\x67\x5c\xb8\x97\xb3\x50\x3d\x70\x2e\xd5\x09\x0f\x96\x36"
                   "\xe2\x07\xd6\xe5\x2e\x82\xae\xe3\x19\xe0\x2c\x65\x40\xbc\x32\x51\x0a\xaa\x42\x9b"
                   "\x4a\x29\xe6\xa5\xe7\x40\x8d\x4d\x1f\x2e\x2b\x2d\x51\x8d\xe1\x29\xdf\x72\x4f\xcf"
                   "\x6b\x1d\x79\xc1\x3e\x7c\x2c\x45\xa2\x15\x2c\x90\x86\x2d\xe8\x4c\xe3\xff\x3c\x48"
                   "\x69\xfe\xac\x3f\xae\xcc\x51\x5b\xae\x30\x37\x53\xc1\x24\xdd\x5d\x2d\x03\xb7\xd3"
                   "\xec\xd4\xc1\xe0\xb7\x6d\xa7\xd1\x7e\x6b\xa8\xa1\x67\x35\xaa\xaf\xb2\x62\x92\x57"
                   "\xd5\xa8\xb9\x7e\x87\xdb\x3d\xcb";

const byte *_pub = "\x1d\xad\x35\xae\xcb\x85\x0a\xc1\xf4\x67\x7d\x50\x57\xda\x5f\x1f\x41\xdf\x88\x3f"
                   "\x9c\xbf\x80\xb5\x22\x69\xc8\xcc\xd0\x5e\x9d\x1e\x6a\x05\x6e\xf0\x88\xe6\x3a\x94"
                   "\xdc\xc8\x19\xf3\xa9\x96\x54\x32\x97\xd1\x8e\xcc\x3f\x28\x03\xb9\xad\x0d\x5b\xb3"
                   "\x70\xdc\x7d\x36\x73\x78\x4b\xa6\x0e\xc5\x90\x7d\x00\x02\x54\xa9\x03\xc0\xdc\x49"
                   "\x8e\x5d\x0e\xe5\x78\xf7\xa4\x06\xae\x48\xb5\xab\xab\x03\x0c\x84\x4d\x0d\x87\x38"
                   "\x2f\x5c\xc1\xc9\x4e\x67\xcc\x2f\x68\xaa\xa3\xfa\xf4\x98\x80\xca\x84\x0d\x32\x7b"
                   "\xaf\xe7\xf6\xac\xb5\xa9\x11\x71";

/* DSA private key 'x' */
byte *_prv = "\xb3\x03\x2d\x29\x2d\x29\x8d\x3c\x0d\xf1\x2a\x7e\xdc\x71\x78\xe8\x03\x0c\x36\xd0";

const int _p_l   = 128;
const int _q_l   = 20;
const int _g_l   = 128;
const int _prv_l = 20;
const int _pub_l = 128;

// ------------------------------------------------------------------------------------------------ 
/*
**  printbn(): Print a BIGNUM as C-style hex (\xNN). You can also prepend and append a constant
**      string.
**
**  Arguments: before (char*) : string to prepend
**             bn (BIGNUM*)   : BIGNUM to print
**             after (char*)  : string to append
**
**  Return Value: 0 on success, -1 on failure.
*/
int printbn( const char *before, BIGNUM *bn, const char *after )
{
    byte *buf = malloc( BN_num_bytes(bn) );             // bignum buffer
    int     j;                                          // iterator
    

    if( !buf ) return -1;                               // malloc failed?

#ifdef _PRINT_DECIMAL_                                  // print it as decimal
    prnt_dbg( DBG_LVL_3, "%s%s%s\n", before, BN_bn2dec(bn), after );
#else
    if( !BN_bn2bin(bn, buf) ) {
        free( buf );                                    // release bignum
        return -1;                                      // convert to binary
    }

    if( before ) prnt_dbg( DBG_LVL_0, "%s\"", before ); // print header if exists
    
    for( j=0; j<BN_num_bytes(bn); ++j )
        prnt_dbg( DBG_LVL_0, "\\x%02x", buf[j] );       // print number in \xNN format

    if( after ) prnt_dbg( DBG_LVL_0, "\"%s", after );   // print trailer if exists
#endif

    free( buf );                                        // release bignum

    return 0;                                           // success!
}

// ------------------------------------------------------------------------------------------------ 
/*
**  primegen(): Generate secret primes for subliminal channels. This function it's not part of the
**      actual program. It just called one time to generate the primes. primegen() prints in
**      stdout the primes in a C-style array, so you can copy-paste it to the source code.
**
**  Arguments: nprimes (int) : number of primes to generate
**
**  Return Value: 0 on success, -1 on failure.
*/
int primegen( int nprimes )
{
    BIGNUM  *p = BN_new();                              // prime number
    int     i;                                          // iterator


    prnt_dbg( DBG_LVL_1, "[+] Generating %d primes...\n"
            "\tconst byte secret_prime[%d][%d] = {\n", nprimes, nprimes, PRIME_SIZE_BYTES );

    for( i=1; i<=nprimes; ++i )                 
        /* generate an (unsafe) prime and print it (do not add ',' at last prime) */
        if( !BN_generate_prime_ex(p, PRIME_SIZE, 0, NULL, NULL, NULL) ||
            printbn("\t\t", p, i == nprimes ? "\n" : ",\n") < 0 )
        {
            printf( "[-] Error! Cannot generate prime numbers (%lu).\n", ERR_get_error() );
            BN_free( p );                               // free prime
            return -1;                                  // failure
        }
    
    prnt_dbg( DBG_LVL_1, "\t};\n[+] Ok.\n");
    
    BN_free( p );                                       // free prime
    return 0;                                           // success.
}

// ------------------------------------------------------------------------------------------------ 
/*
**  dsagen(): Generate DSA parameters: p, q, g, x, y = g^x. This function (like primegen()) is 
**      also called once to generate the parameters, and it's not part of the actual program.
**
**  Arguments: None.
**
**  Return Value: A DSA struct on success, NULL on failure.
*/
DSA *dsagen( void )
{
    byte    seed[ SEED_SIZE ];                          // random seed
    DSA     *dsa;                                       // dsa struct to hold parameters
    

    prnt_dbg( DBG_LVL_1, "[+] Generating DSA parameters...\n" );

    RAND_bytes(seed, SEED_SIZE);                        // geberate a strong seed
    
    if( !(dsa = DSA_generate_parameters(2048, seed, SEED_SIZE<<3, NULL, NULL, NULL, NULL)) ) {
        printf( "[-] Error! Cannot generate DSA parameters (%lu).\n", ERR_get_error() );
        return NULL;                                    // failure
    }

    if( !DSA_generate_key( dsa ) ) {
        printf( "[-] Error! Cannot generate DSA key pair (%lu).\n", ERR_get_error() );
        DSA_free( dsa );                                // free struct
        return NULL;
    }

    /* A DSA struct has (among the others) these numbers:
     *      BIGNUM *p;              // prime number (public)
     *      BIGNUM *q;              // 160-bit subprime, q | p-1 (public)
     *      BIGNUM *g;              // generator of subgroup (public)
     *      BIGNUM *priv_key;       // private key x
     *      BIGNUM *pub_key;        // public key y = g^x
     */

    /* print DSA parameters/key in C-style format */
    printbn( "const byte *_p   = ", dsa->p, ";\n" );
    printbn( "const byte *_q   = ", dsa->q, ";\n" );
    printbn( "const byte *_g   = ", dsa->g, ";\n" );
    printbn( "      byte *_prv = ", dsa->priv_key, ";\n" );
    printbn( "const byte *_pub = ", dsa->pub_key,  ";\n" );

    prnt_dbg( DBG_LVL_0, "\n" );
    prnt_dbg( DBG_LVL_0, "const int _p_l   = %d;\n", BN_num_bytes(dsa->p) );
    prnt_dbg( DBG_LVL_0, "const int _q_l   = %d;\n", BN_num_bytes(dsa->q) );
    prnt_dbg( DBG_LVL_0, "const int _g_l   = %d;\n", BN_num_bytes(dsa->g) );
    prnt_dbg( DBG_LVL_0, "const int _prv_l = %d;\n", BN_num_bytes(dsa->priv_key) );
    prnt_dbg( DBG_LVL_0, "const int _pub_l = %d;\n", BN_num_bytes(dsa->pub_key)  );

    printf( "[+] ok.\n" );

    return dsa;                                         // return dsa struct
}

// ------------------------------------------------------------------------------------------------ 
/*
**  dsaset(): Set DSA parameters. Create a DSA struct and copy the (constant) parameters in it.
**      Parameters are defined as global variables.
**
**  Arguments: set_prv (byte) : if true, set private key.
**
**  Return Value: A DSA struct on success, NULL on failure.
*/
DSA *dsaset( byte set_prv )
{
    DSA     *dsa = DSA_new();                           // dsa struct to hold parameters
    

    prnt_dbg( DBG_LVL_3, "[+] Setting DSA parameters...\n" );

    dsa->p        = BN_new();                           // allocate bignums
    dsa->q        = BN_new();
    dsa->g        = BN_new();
    dsa->priv_key = BN_new();
    dsa->pub_key  = BN_new();

    /* and copy the parameters to them */
    if( !BN_bin2bn(_p,   _p_l,   dsa->p) ||
        !BN_bin2bn(_q,   _q_l,   dsa->q) ||
        !BN_bin2bn(_g,   _g_l,   dsa->g) ||
        !BN_bin2bn(_prv, _prv_l, dsa->priv_key) ||
        !BN_bin2bn(_pub, _pub_l, dsa->pub_key) )
    {
        BN_free( dsa->p );                              // free BNs
        BN_free( dsa->q );
        BN_free( dsa->g );
        BN_free( dsa->priv_key );
        BN_free( dsa->pub_key  );
        DSA_free( dsa );                                // free DSA

        return NULL;                                    // failure
    }

    if( !set_prv ) dsa->priv_key = NULL;                // one side has private key

    return dsa;                                         // return dsa struct
}

// ------------------------------------------------------------------------------------------------ 
/*
**  dsasign(): Sign a message using DSA. The important thing here is the signature and not the
**      actual message. For now, we can assume that the message is constant.
**
**  Arguments: dsa (DSA*)  : DSA struct with our parameters
**             slen (int*) : signature length (OUT)
**
**  Return Value: On success, function returns the signature (r,s) in ASN.1 DER format. Upon 
**      failure, function returns NULL.
*/
byte *dsasign( DSA *dsa, int *slen )
{
    byte    *sign;                                      // our signature
    

    if( !dsa || !(sign = malloc(DSA_size(dsa))) )       // return if NULL pointers
        return NULL;

    if( !DSA_sign(0, DSA_SIGN_MSG, DSA_SIGN_MSG_LEN, sign, slen, dsa)) {        
        printf( "[-] Error! Cannot sign message (%lu).\n", ERR_get_error() );

        free( sign );                                   // free signature buffer
        return NULL;                                    // failure
    }
    
    return sign;                                        // return signature
}

// ------------------------------------------------------------------------------------------------ 
/*
**  dsaverf(): Verify a DSA signature. Before we extract the subliminal message we have to verify
**      first that the signature is correct.
**
**  Arguments: dsa (DSA*)   : DSA struct with our parameters
**             sign (byte*) : DSA signature
**             slen (int)   : DSA signature length
**
**  Return Value: If signature is correct, function returns 0. If signature is wrong, or if an 
**      error occurs, function returns -1.
*/
int dsaverf( DSA *dsa, byte *sign, int slen )
{
    int r = DSA_verify(0, DSA_SIGN_MSG, DSA_SIGN_MSG_LEN, sign, slen, dsa);


    if( r > 0 ) return 0;                               // success!
    else if( !r ) printf( "[-] Error! Signature is wrong.\n" );
    else          printf( "[-] Error! Signature verification failed (%lu).\n", ERR_get_error() );

    return -1;                                          // failure x(
}

// ------------------------------------------------------------------------------------------------ 
/*
**  dsasubl_ins(): Generate a signature with a subliminal message in it.
**
**  Arguments: secret (byte*) : a binary array with the subliminal bits to insert
**             len (int)      : length of that array
**             r_only (byte)  : if set, do not return s
**
**  Return Value: 0 on success, -1 on failure.
*/
byte *dsasubl_ins( byte *secret, int len, byte r_only )
{
/* these macros will help me release allocated memory correctly */
#define CLEANUP_BN  BN_free(a); BN_free(b);   BN_free(c);   BN_free(p); BN_free(r);\
                    BN_free(s); BN_free(one); BN_free(two); BN_CTX_free(ctx)
#define CLEANUP_DSA DSA_free(dsa); CLEANUP_BN
#define CLEANUP_BUF free( buf );   CLEANUP_DSA

    BIGNUM  *a, *b, *c, *p, *r, *s, *one, *two;         // our BIGNUMs
    BN_CTX  *ctx;                                       // internal context for BIGNUM library
    DSA     *dsa;                                       // DSA parameters
    byte    *sign, *buf;                                // signature buffers
    int     slen;                                       // signature length
    int     i, j, k;                                    // iterators


    if( len > N_SECRET_PRIMES ) {                       // we need one secret prime per bit
         printf( "[-] Error! Subliminal message is too long.\n" );
         return NULL;
    }

    ctx = BN_CTX_new();                                 // allocate context
    a   = BN_new();                                     // allocate these BIGNUMs
    b   = BN_new();                                     // assume no errors
    c   = BN_new(); 
    p   = BN_new();
    r   = BN_new(); 
    s   = BN_new();
    one = BN_new();
    two = BN_new();

    if( !BN_one(one) || !BN_set_word(two, 2) ||         // initialize the 1 and 2 first
        !(dsa = dsaset(1)) )                            //   and set dsa key (+private key)
    {
        CLEANUP_BN;
        return NULL;                                    // failure
    }

    /* In DSA k must be unique and random. Thus if we sign the same message multiple times,
     * the signatures will be different every time. The goal here is to find such a signature
     * (r,s) such that:
     *  If the 1st bit of subliminal message is 1 then r, will be quadratic residue modulo the
     *  first prime. If the 1st bit of subliminal message is 0 then r will be quadratic non 
     *  residue modulo the first prime.
     *  If the 2nd bit of subliminal message is 1 then r, will be quadratic residue modulo the
     *  second prime, and so on... 
     *  
     * Note the number of quadratic residues and non-residues modulo a prime are about equal,
     * so the chances to find a 'good' r are 2^-N, where N is the length of subliminal message. 
     * This means that the more information we leak, the hardest is to find a 'good' r.
     */ 
    for( i=0; i<SUBL_MSG_MAXTRIES; i++ )                // try to find a 'good' signature
    {
        if( !(sign = dsasign(dsa, &slen)) ) {           // sign message
            CLEANUP_DSA;
            return NULL;                                // failure
        }

        /* Signature is in ASN.1 DER format. This is a pretty complex format, but we can focus 
         * on the encodings that we're interested in. Let's see a signature example:
         *  302d                        (30 = type is SEQUENCE, 2c = len in octets)
         *  0215                        (02 = type is INTEGER,  15 = len in octets)
         *    00be68af7012597f5b7498... (r parameter)
         *  0214                        (02 = type is INTEGER,  14 = len in octets)
         *    0d1efa2ecab312ac119a66... (s parameter)
         *  
         *
         * Bit string might be padded with 0~7 bits to be multiple of 8. Padding can be ignored.
         * Thus, rhe encoded signature is usually 46~48 bytes. However the actual r and s 
         * parameters are 160 bits (20 bytes) each. Because bandwidth is very limited, we can 
         * only send r and s (40 bytes) and not the encoded signature.
         *
         * NOTE: If the MSBit is set then we have to prepend a NULL byte, otherwise number will
         * be treated as negative. If MSByte is 0 we can omit it so the length will be 0x13.
         */

        prnt_dbg( DBG_LVL_3, "[+] %4d: ", i );          // print signature
        for( k=0; k<slen; k++ ) prnt_dbg( DBG_LVL_3, "%02x", sign[k] & 255 );
        prnt_dbg( DBG_LVL_3, "\n");


        /* Now, decode signature and extract r and s.
         * signature has always the same format, so we can easily find r and s.
         */
        int st_r = 4,          len_r = sign[3],         // find offsets and lengths of
            st_s = 6 + len_r, len_s = sign[st_s-1];     //   r,s within signature


        /* In order to simplify things we do not accept signature which are less than
         * DSA_PARAM_LEN_BYTES bytes or they have an MSByte of 0.
         * We also do an overflow check, so lenghts can be up to DSA_PARAM_LEN_BYTES+1
         * (if MSBit is set we add one extra byte)
         */
        if( len_r < DSA_PARAM_LEN_BYTES || len_r > DSA_PARAM_LEN_BYTES + 1 ||
            len_s < DSA_PARAM_LEN_BYTES || len_s > DSA_PARAM_LEN_BYTES + 1 ||
            (len_r == DSA_PARAM_LEN_BYTES && !sign[st_r]) || 
            (len_s == DSA_PARAM_LEN_BYTES && !sign[st_s]) )
        {
            continue;
        }
        
        BN_bin2bn(&sign[st_r], len_r, r);               // r to BIGNUM

        for( j=0; j<len; ++j )                          // check if r is 'good'
        {
            BN_bin2bn(secret_prime[j], PRIME_SIZE_BYTES, p);    

            BN_gcd(a, r, p, ctx);
            if( !BN_is_one(a) )                         // r not coprime with p ?
                break;                                  // try a new signature

            BN_sub(a, p, one);                          // a = p - 1
            BN_div(b, c, a, two, ctx);                  // b = (p - 1) / 2
            BN_mod_exp(c, r, b, p, ctx);                // c = r^((p-1)/2) % p

            if( BN_is_one(c) )                          // c == 1 ?
            {                                           //   c is quadratic residue
                if( secret[j] == 0 ) break;             // if bit is wrong, try a new signature
            }
            else if( !BN_cmp(c, a) )                    // c == p - 1 mod p? (-1) 
            {                                           //   c is quadratic non-residue
                if( secret[j] == 1 ) break;             // if bit is wrong, try a new signature
            }
            else {
                printf( "[-] Error! Unexpected value for 'c'.\n" );
                CLEANUP_DSA;
                return NULL;                            // failure
            }
        }

        if( j == len )                                  // all primes matched?
        {               
            prnt_dbg( DBG_LVL_2, "[+] Good signature found after %d tries.\n", i );         
            prnt_buf( DBG_LVL_2, "[+] ", sign, slen, 0 );
    
            /* there may be NULL bytes prepended to r,s, so do it the safe way */
            BN_bin2bn(&sign[st_s], len_s, s);           // s to BIGNUM
                    
            if( !(buf = malloc(BN_num_bytes(r) + BN_num_bytes(s))) ) {
                CLEANUP_DSA;
                return NULL;                            // malloc failed.
            }

            if( BN_bn2bin(r, buf) &&                    // pack r (and s maybe)
                (r_only || BN_bn2bin(s, &buf[BN_num_bytes(r)]))  )
                    ;
            else {
                CLEANUP_BUF;
                return NULL;                            // malloc failed.
            }

            prnt_buf( DBG_LVL_2, "[+] Returning: ",buf, // print signature
                        DSA_PARAM_LEN_BYTES + (r_only ? 0 : DSA_PARAM_LEN_BYTES), 0 );

            CLEANUP_DSA;                                // release memory (except buffer)
            return buf;                                 // return that buffer
        }
    }

    printf( "[-] Error! Cannot find a 'good' signature.\n" );
    CLEANUP_DSA;
    return NULL;                                        // nothing found after SUBL_MSG_MAXTRIES 

#undef CLEANUP_BUF                                      // undef these to avoid conflicts
#undef CLEANUP_DSA
#undef CLEANUP_BN
}

// ------------------------------------------------------------------------------------------------ 
/*
**  dsasubl_ext(): Extract a subliminal message from a signature.
**
**  Arguments: sign (byte*)    : the DSA signature (r,s) only
**             len (int)       : length of the expected subliminal message
**             not_vrfy (byte) : if set, verify signature (s may be missing)
**
**  Return Value: A binary array with the subliminal bits in it. NULL on failure.
*/
byte *dsasubl_ext( byte *sign, int len, byte not_vrfy )
{
/* these macros will help me release allocated memory correctly (different from dsasubl_ins) ones */
#define CLEANUP_BN  BN_free(a); BN_free(b);   BN_free(c);   BN_free(p); \
                    BN_free(r); BN_free(one); BN_free(two); BN_CTX_free(ctx)
#define CLEANUP_DSA DSA_free(dsa); CLEANUP_BN
#define CLEANUP_BUF free( secret ); free( buf ); CLEANUP_DSA

/* these macros will "push" stuff on a buffer */
#define PUSH_CH( sign, idx, ch) sign[(*idx)++] = ch
#define PUSH_BUF(sign, idx, buf, len)   \
    for( k=0; k<len; ++k )              \
        sign[(*idx)++] = *(byte*)((long long int)buf + (long long int)k) & 0xff


    BIGNUM  *a, *b, *c, *p, *r, *one, *two;             // our BIGNUMs
    BN_CTX  *ctx;                                       // internal context for BIGNUM library
    DSA     *dsa;                                       // DSA parameters
    int     j, k, sz = 0;                               // iterators
    byte    *buf = NULL, *secret = NULL;                // signature buffers


    if( len > N_SECRET_PRIMES ) {
         printf( "[-] Error! Cannot extract such a large subliminal message.\n" );
         return NULL;
    }

    ctx = BN_CTX_new();                                 // allocate context
    a   = BN_new();                                     // allocate these BIGNUMs
    b   = BN_new();                                     // assume no errors
    c   = BN_new(); 
    p   = BN_new();
    r   = BN_new(); 
    one = BN_new();
    two = BN_new();

    if( !BN_one(one) || !BN_set_word(two, 2) ||         // initialize the 1 and 2 first
        !(dsa = dsaset(0)) )                            //   and set dsa key (priv key not needed)
    {
        CLEANUP_BN;
        return NULL;                                    // failure
    }

    if( !not_vrfy )                                     // verify signature?
    {
        /* First we check that signature is valid. Thus we have to ASN.1 encode r and s.
         * Because we did some assumptions in dsasubl_ins() we know that r,s are exactly
         * DSA_PARAM_LEN_BYTES bytes. The only check we do is to see if MSBit is set, and 
         * if so, to append a NULL byte.
         */
        int len_r = DSA_PARAM_LEN_BYTES + ((sign[0]                   & 0x80) >> 7),
            len_s = DSA_PARAM_LEN_BYTES + ((sign[DSA_PARAM_LEN_BYTES] & 0x80) >> 7);
        
        if( !(buf = malloc(2+ 2+ len_r +2 +len_s)) ||   // include "headers" of numbers
            !(secret = malloc(len)) )
        {
            CLEANUP_DSA;
            return NULL;                                // failure
        }

        /* copy r first */
        PUSH_CH(buf, &sz, 0x30);                        // SEQUENCE
        PUSH_CH(buf, &sz, 2 + len_r + 2 + len_s);       //
        PUSH_CH(buf, &sz, 0x02);                        // INTEGER
        PUSH_CH(buf, &sz, len_r);                       //

        if( len_r == 0x15 ) PUSH_CH(buf, &sz, 0x00);    // append a NULL
        
        PUSH_BUF(buf, &sz, sign, DSA_PARAM_LEN_BYTES);  // copy r

        /* then copy s first */
        PUSH_CH(buf, &sz, 0x02);                        // INTEGER
        PUSH_CH(buf, &sz, len_s);                       // 
        
        if( len_s == 0x15 ) PUSH_CH(buf, &sz, 0x00);    // append a NULLL
        PUSH_BUF(buf, &sz, &sign[DSA_PARAM_LEN_BYTES], DSA_PARAM_LEN_BYTES);


        /*
         * verify signature 
         */
        if( dsaverf( dsa, buf, 6 + len_r + len_s) < 0 ) {
            CLEANUP_BUF;                                // dsaverf will print the error message
            return NULL;
        }
    } 
    else if ( !(secret = malloc(len)) ) {
        CLEANUP_DSA;
        return NULL;                                    // failure
    }
    else prnt_dbg( DBG_LVL_2, "[+] Signature not verified.\n" );

    /*
     * signature verified. Extract secret 
     */
    BN_bin2bn(sign, DSA_PARAM_LEN_BYTES, r);            // r to BIGNUM

    for( j=0; j<len; ++j )                              // check if r is 'good'
    {
        BN_bin2bn(secret_prime[j], PRIME_SIZE_BYTES, p);    

        BN_gcd(a, r, p, ctx);
        if( !BN_is_one(a) ) {                           // r not coprime with p ?
            CLEANUP_BUF;
            return NULL;                                // failure
        }

        BN_sub(a, p, one);                              // a = p - 1
        BN_div(b, c, a, two, ctx);                      // b = (p - 1) / 2
        BN_mod_exp(c, r, b, p, ctx);                    // c = r^((p-1)/2) % p

        if( BN_is_one(c) ) secret[j] = 1;               // c is quadratic residue c == 1 ?
        else if( !BN_cmp(c, a) ) secret[j] = 0;         // c == p - 1 mod p? (-1) 
        else {
            printf( "[-] Error! Unexpected value for 'c'.\n" );
            CLEANUP_BUF;
            return NULL;
        }
    }

    CLEANUP_DSA;
    return secret;                                      // return that secret

#undef PUSH_CH
#undef PUSH_BUF 
#undef CLEANUP_BUF                                      // undef these to avoid conflicts
#undef CLEANUP_DSA
#undef CLEANUP_BN
}

// ------------------------------------------------------------------------------------------------ 
