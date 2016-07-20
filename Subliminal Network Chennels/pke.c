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
**  pke.c
**
**  This file implements a public key encryption scheme, using RSA. It's used to add one 
**  layer of protection in the leaked data. Data are encrypted using receiver's public
**  key and then ciphertext is send through our subliminal channel. Even in the worst case 
**  scenario that someone knows the secret primes he can recover the ciphertext, but not
**  the plaintext because the decryption key is kept safe on the receiver.
**
**
**   * * * ---===== TODO list =====--- * * *
**
**      [1]. encryption is done in ECB mode. Change it to CBC.
**
**      [2]. As in subldsa.c it could another option to keep the state of RSA parameters.
*/
// ------------------------------------------------------------------------------------------------ 
#include "subnetc.h"

#define RSA_KEY_LEN         1024                        // RSA key length
#define RSA_PUB_EXP         17                          // typical values for e: 3, 17, 65537
#define PLAINTEXT_TAG       "\xde\xad\xbe\xef"          // tag at the beginning of plaintext
#define PLAINTEXT_TAG_LEN   4                           // and its length
#define PLAINTEXT_SZ        ((RSA_KEY_LEN >> 3) >> 1)   // message is half of the ciphertext


/* public key */
const byte *_rsa_n = "\xbe\x6b\xc0\xc2\x83\xda\xa8\x8a\xf9\xfc\x4d\xf7\xd1\x5e\xbc\xed\x9e\x8a\x6a"
                     "\x9a\x44\xaf\x05\x5e\x61\x60\xe1\x14\x1f\x8a\x1f\x12\x64\x25\x73\x70\xe6\x6c"
                     "\xa6\xf8\xa5\x8c\x1c\x08\x62\x54\x74\x54\x64\xdb\xba\xf2\xf6\x9b\xcd\x34\x14"
                     "\xdf\xd1\xd6\x4c\x8a\xce\xb8\x55\x1a\x64\xb0\x76\x3b\xb7\x2c\xc3\x16\x08\xca"
                     "\x3c\xaa\xa9\x34\x91\x54\xff\x9e\xf3\x7a\xfb\xc2\x74\xfd\xe5\x0f\xe3\x7c\x89"
                     "\xb4\xac\xc4\x82\xc4\x21\x83\x38\xb0\xb0\xd9\x5b\x20\x9d\xe8\xa2\x73\xe9\x86"
                     "\x1d\xf6\x15\xdf\xa1\x80\xf2\x34\xee\xe9\x71\x48\xbb\xfb";
const byte *_rsa_e = "\x03";


/* private key */
const byte *_rsa_p = "\xfb\x97\x2b\x97\xfe\x3d\x70\xd7\x84\x78\x98\x1a\x72\x79\x0d\xa3\x1e\xb9\x1b"
                     "\xc5\xd5\x14\x68\x02\x48\x7d\xf8\x43\x9d\xcf\x75\x6a\x06\xea\xe1\xe0\xb6\xb0"
                     "\x64\x3c\xb5\xab\x77\x4d\x3d\x79\x1b\x24\xdb\xe7\xb1\xdf\x1a\x76\x8b\xcf\xb7"
                     "\x9b\x02\xf4\xe7\x14\x91\xb7";

const byte *_rsa_q = "\xc1\xc2\x20\xe6\xf9\x05\x90\xb6\x4d\x92\x84\xa7\xbf\x81\x96\x79\x0d\x14\x71"
                     "\xb9\x24\xb1\xb5\xf9\xa0\x7b\xd3\xcf\x42\xf0\xc8\xbc\x17\x3f\x46\x6c\x02\x77"
                     "\x2c\xb5\x0b\x52\x7d\xbc\xbc\x53\x22\x04\x76\x4f\xbf\x3e\x3d\x02\xa8\x0d\x5f"
                     "\xc2\x01\x5d\xf2\x0c\x97\xdd";

const byte *_rsa_d = "\x7e\xf2\x80\x81\xad\x3c\x70\x5c\xa6\xa8\x33\xfa\x8b\x94\x7d\xf3\xbf\x06\xf1"
                     "\xbc\x2d\xca\x03\x94\x40\xeb\x40\xb8\x15\x06\xbf\x61\x98\x18\xf7\xa0\x99\x9d"
                     "\xc4\xa5\xc3\xb2\xbd\x5a\xec\x38\x4d\x8d\x98\x92\x7c\xa1\xf9\xbd\x33\x78\x0d"
                     "\xea\x8b\xe4\x33\x07\x34\x79\xba\x80\xba\xcb\xa9\xfb\x23\xbf\x4b\x5c\x9d\x5a"
                     "\xb1\xca\xae\x10\x43\xaf\xa1\x6a\xa6\x78\x93\xd9\xb2\xad\x65\xfe\x01\xd2\xdd"
                     "\x09\xb4\x66\xe6\xfa\x45\x92\x6f\xd4\x9f\xe7\x99\x64\x6d\x68\x43\x87\x0f\x89"
                     "\xc8\x90\x7e\xee\xf3\xc2\x91\xe5\x47\x0f\x10\x1a\x61\x9b";

const int _rsa_n_l = 128;
const int _rsa_e_l = 1;
const int _rsa_p_l = 64;
const int _rsa_q_l = 64;
const int _rsa_d_l = 128;

// ------------------------------------------------------------------------------------------------ 
/*
**  rsagen(): Generate RSA parameters: n, e, p, q, d. This function is called only once to 
**      generate the parameters; it's not part of the actual program.
**
**  Arguments: None.
**
**  Return Value: A RSA struct on success, NULL on failure.
*/
RSA *rsagen( void )
{
    RSA *rsa;                                           // rsa struct to hold parameters
    

    prnt_dbg( DBG_LVL_1, "[+] Generating RSA key pair of %d bits...\n", RSA_KEY_LEN );
     
    /* generate and RSA key pair */
    if( !(rsa = RSA_generate_key(RSA_KEY_LEN, RSA_PUB_EXP, NULL, NULL)) ) {
        printf( "[-] Error! Cannot generate RSA key pair (%lu).\n", ERR_get_error() );
        return NULL;                                    // failure
    }

    /* A RSA struct has the following BIGNUM  numbers:
     *      n, e                => public key
     *      d, p, q             => private key
     *      dmp1, dmq1, iqmp    => auxiliary numbers to speed up calculations
     */

    /* print DSA parameters/key in C-style format */
    printbn( "const byte *_rsa_n = ", rsa->n, ";\n" );
    printbn( "const byte *_rsa_e = ", rsa->e, ";\n" );
    printbn( "const byte *_rsa_p = ", rsa->p, ";\n" );
    printbn( "const byte *_rsa_q = ", rsa->q, ";\n" );
    printbn( "const byte *_rsa_d = ", rsa->d, ";\n" );

    prnt_dbg( DBG_LVL_0, "\n" );
    prnt_dbg( DBG_LVL_0, "const int _rsa_n_l = %d;\n", BN_num_bytes(rsa->n) );
    prnt_dbg( DBG_LVL_0, "const int _rsa_e_l = %d;\n", BN_num_bytes(rsa->e) );
    prnt_dbg( DBG_LVL_0, "const int _rsa_p_l = %d;\n", BN_num_bytes(rsa->p) );
    prnt_dbg( DBG_LVL_0, "const int _rsa_q_l = %d;\n", BN_num_bytes(rsa->q) );
    prnt_dbg( DBG_LVL_0, "const int _rsa_d_l = %d;\n", BN_num_bytes(rsa->d) );

    printf( "[+] ok.\n" );

    return rsa;                                         // return rsa struct
}

// ------------------------------------------------------------------------------------------------ 
/*
**  rsaset(): Set RSA parameters. Create an RSA struct and copy the (constant) parameters in it.
**      Parameters are defined as global variables.
**
**  Arguments: set_prv (byte) : if true, set private key.
**
**  Return Value: A RSA struct on success, NULL on failure.
*/
RSA *rsaset( byte set_prv )
{
    RSA *rsa = RSA_new();                               // dsa struct to hold parameters
    

    prnt_dbg( DBG_LVL_3, "[+] Setting DSA parameters...\n" );

    rsa->n = BN_new();                                  // allocate bignums
    rsa->e = BN_new();
    rsa->p = BN_new();
    rsa->q = BN_new();
    rsa->d = BN_new();
    
    /* and copy the parameters to them */
    if( !BN_bin2bn(_rsa_n, _rsa_n_l,   rsa->n) ||
        !BN_bin2bn(_rsa_e, _rsa_e_l,   rsa->e) ||
        !BN_bin2bn(_rsa_p, _rsa_p_l,   rsa->p) ||
        !BN_bin2bn(_rsa_q, _rsa_q_l,   rsa->q) ||
        !BN_bin2bn(_rsa_d, _rsa_d_l,   rsa->d) )
    {
        BN_free( rsa->n );                              // free BNs
        BN_free( rsa->e );
        BN_free( rsa->p );
        BN_free( rsa->q );
        BN_free( rsa->d  );
        RSA_free( rsa );                                // free RSA

        return NULL;                                    // failure
    }

    if( !set_prv ) {                                    // one side has private key
         rsa->p = NULL;
         rsa->q = NULL;
         rsa->d = NULL;
    }

    return rsa;                                         // return rsa struct
}

// ------------------------------------------------------------------------------------------------ 
/*
**  rsaencr_blk(): Encrypt a block using RSA. Block can't be greater than public modulus. To make
**      sure that decryption will be correct, add a tag before main block and encrypt it all
**      together.
**
**  Arguments: blk (byte*) : block to encrypt
**             mlen (int)  : block length
**             clen (int*) : ciphertext length (OUT)
**
**  Return Value: A pointer to the ciphertext. NULL on failure.
*/
byte *rsaencr_blk( byte *blk, int blen, int *clen )
{
    RSA     *rsa = rsaset(0);                           // get public key only
    byte    *plain, *cipher;                            // ciphertext
    

    *clen = 0;                                          // clear it first

    if( blen+PLAINTEXT_TAG_LEN >= (RSA_KEY_LEN >> 3) || // block too big?
        !rsa ||                                         // NULL struct?
        !(cipher = malloc( RSA_size(rsa) )) ||          // allocation failure?
        !(plain  = malloc(blen + PLAINTEXT_TAG_LEN)) )
            return NULL;                                // return on error

    memcpy(plain, PLAINTEXT_TAG, PLAINTEXT_TAG_LEN);    // prepend signature 
    memcpy(&plain[PLAINTEXT_TAG_LEN], blk, blen);
    
    /* encrpyt message (the safe way) */
    if( (*clen = RSA_public_encrypt(blen + PLAINTEXT_TAG_LEN, plain, cipher, 
                                    rsa, RSA_PKCS1_PADDING)) < 0 ) 
    {
        printf("[-] Error! Cannot encrypt message (%lu).\n", ERR_get_error());  

        RSA_free( rsa );                                // release memory
        free( cipher );
        free( plain );

        return NULL;
    }

    RSA_free( rsa );
    free( plain );

    return cipher;                                      // return ciphertext
}

// ------------------------------------------------------------------------------------------------
/*
**  rsadecr_blk(): Decrypt a ciphertext (block) using RSA. Verify the decryption by chacking the 
**      tag at the beginning of the plaintext.
**
**  Arguments: cipher (byte*) : ciphertext to decrypt
**             clen (int)     : ciphertext length
**             plen (int*)    : plaintext length (OUT)
**
**  Return Value: A pointer to the plaintext. NULL on failure. 
*/
byte *rsadecr_blk( byte *cipher, int clen, int *plen )
{
    RSA     *rsa = rsaset(1);                           // get public and private key
    byte    *plain, *blk;                               // plaintext and message


    if( !rsa || !(plain = malloc( clen )) ||
                !(blk   = malloc( clen )) )
    {
        *plen = -1;
        return NULL;                                    // return on error
    }
            

    if( (*plen = RSA_private_decrypt(clen, cipher, plain, rsa, RSA_PKCS1_PADDING)) < 0 ) {  
        printf("[-] Error! Cannot decrypt message (%lu).\n", ERR_get_error());  

        RSA_free( rsa );                                // release memory
        free( plain );
        free( blk );

        *plen = -1;
        return NULL;
    }

    /* verify tag and remove it if it's correct */
    if( memcmp(plain, PLAINTEXT_TAG, PLAINTEXT_TAG_LEN) ) {
        printf("[-] Error! Plaintext tag mismatch.\n" );    

        RSA_free( rsa );                                // release memory
        free( plain );

        *plen = -1;
        return NULL;
    }
    else 
        memcpy( blk, &plain[PLAINTEXT_TAG_LEN], *plen-PLAINTEXT_TAG_LEN );
    

    *plen -= PLAINTEXT_TAG_LEN;                         // adjust length

    free( plain );
    RSA_free( rsa );

    return blk;                                         // return plaintext
}

// ------------------------------------------------------------------------------------------------ 
/*
**  rsaencr(): Encrypt a (large) message using RSA. Message is splitted into blocks and each
**      block is encrypted using RSA. ECB mode is used. It's insecure and in future versions it
**      will be replaced by CBC mode.
**
**  Arguments: msg (byte*) : message to encrypt
**             mlen (int)  : message length
**             clen (int*) : ciphertext length (OUT)
**
**  Return Value: A pointer to the ciphertext. NULL on failure.
*/
byte *rsaencr( byte *msg, int mlen, int *clen )
{
    byte    *cipher;                                    // buffer to hold ciphertext
    int     len, j;


    if( !(cipher = calloc((int)ceil((float)mlen/PLAINTEXT_SZ) * (RSA_KEY_LEN >> 3), 1)) ) {
        printf("[-] Error! Cannot allocate ciphertext buffer.\n" ); 
        
        *clen = -1;                                     // failure
        return NULL;
    }
        

    /* message must be padded up to PLAINTEXT_SZ */
    msg = realloc(msg, mlen+PLAINTEXT_SZ);              // extend message buffer
    bzero(&msg[mlen], PLAINTEXT_SZ);                    // zero padding


    /* for each block - ECB mode: Insecure! */
    for( j=0, *clen=0; j<mlen; j+=PLAINTEXT_SZ, *clen+=RSA_KEY_LEN >> 3 )
    {
        byte *blk = rsaencr_blk(&msg[j], PLAINTEXT_SZ, &len);
        
        if( !blk ) { *clen = -1; return NULL; }         // error will be printed in rsadecr_blk()

        memcpy(&cipher[*clen], blk, len);

        free( blk );
    }

    return cipher;
}

// ------------------------------------------------------------------------------------------------ 
/*
**  rsadecr(): Decrypt a (large) ciphertext using RSA. Ciphertext is decrypted block by block. 
**
**  Arguments: cipher (byte*) : ciphertext to decrypt
**             clen (int)     : ciphertext length
**             plen (int*)    : plaintext length (OUT)
**
**  Return Value: A pointer to the plaintext. NULL on failure.
*/
byte *rsadecr( byte *cipher, int clen, int *plen )
{
    byte    *plain;                                     // buffer to hold plaintext
    int     len = 0, j;


    if( !(plain = calloc((int)ceil((float)clen/(RSA_KEY_LEN >> 3)) * PLAINTEXT_SZ, 1)) ) {
        printf("[-] Error! Cannot allocate plaintext buffer.\n" );  
        
        *plen = -1;                                     // failure
        return NULL;
    }

    /* for each block - ECB mode: Insecure! */
    for( j=0, *plen=0; j<clen; j+=RSA_KEY_LEN >> 3, *plen+=len )
    {
        byte *blk = rsadecr_blk(&cipher[j], RSA_KEY_LEN >> 3, &len);
        
        if( !blk ) { *plen = -1; return NULL; }         // error will be printed in rsadecr_blk()

        memcpy( &plain[*plen], blk, len );

        free( blk );
    }

    return plain;                                       // return decrypted text
}
// ------------------------------------------------------------------------------------------------ 
