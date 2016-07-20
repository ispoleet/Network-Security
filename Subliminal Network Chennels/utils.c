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
**  utils.c
**
**  This file contains some useful functions that deal with intermediate buffers.
*/
// ------------------------------------------------------------------------------------------------ 
#include "subnetc.h"                                    // all includes are here


// ------------------------------------------------------------------------------------------------
/*
**  prnt_dbg(): A printf equivalent. We use prnt_dbg() to print debug information. If debug flag
**      is not set, nothing is printed.
**
**  Arguments: printf-like variable arguments
**
**  Return Value: None.
*/
void prnt_dbg( int level, char *msg, ... )
{
    va_list args;                                       // argument list

    if( level <= dbg_level ) {                          // debug level is appropriate?
        va_start( args, msg );
        vfprintf( stdout, msg, args );                  // print debug information
        va_end( args );
    }
}

// ------------------------------------------------------------------------------------------------
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
void prnt_buf( int level, char *msg, byte *buf, int len, byte bits )
{
    int k;                                              // iterator

    prnt_dbg( level, "%s", msg );                       // print message

    if( bits )                                          // print as bitstream?
        for( k=0; k<len; k++ )
            prnt_dbg( level, "%01x", buf[k] & 255 );

    else for( k=0; k<len; k++ )                         // print as hex
            prnt_dbg( level, "%02x ", buf[k] & 255 );



    prnt_dbg( level, "\n");                             // finish with a newline
}

// ------------------------------------------------------------------------------------------------
/*
**  load_secret(): Load a secret from a file.
**
**  Arguments: filename (char*) : filename to read secret from
**             buflen (int*)    : length of the buffer (OUT)
**
**  Return Value: A pointer to the buffer that holds the secret. NULL on failure.
*/
byte *load_secret( char *filename, int *buflen )
{
    FILE    *fp;                                        // file pointer
    byte    *buf;                                       // buffer
    

    if( !(fp = fopen( filename, "rb" )) ) {             // try to open file
        printf( "[-] Error! Invalid file name '%s'.\n", filename );
        return NULL;                                    // failure
    }

    fseek( fp, 0, SEEK_END );                           // move file position indicator to the end
    *buflen = ftell( fp );                              // obtain its value    
    fseek( fp, 0, SEEK_SET );                           // move it back to the beginning

    if( !(buf = calloc(*buflen, 1)) ) {                 // allocate space for file
        printf( "[-] Error! Cannot allocate memory for file data.\n" );
        *buflen = -1;
        return NULL;
    }

    if( fread(buf, 1, *buflen, fp) != *buflen ) {       // read file
        printf( "[-] Error! Cannot read from file '%s'.\n", filename );
        *buflen = -1;
        return NULL;
    }

    fclose( fp );                                       // no error checks here

    prnt_buf( DBG_LVL_2, "[+] Secret read: ", buf, *buflen, 0 );

    return buf;                                         // return buffer
}

// ------------------------------------------------------------------------------------------------
/*
**  store_secret(): Store a secret into a file.
**
**  Arguments: filename (char*) : filename to read secret from
**             buf (byte*)      : buffer to store
**             buflen (int)     : length of the buffer
**
**  Return Value: 0 on success, -1 on failure.
*/
int store_secret( char *filename, byte *buf, int buflen )
{
    FILE *fp;                                           // file pointer

    if( !(fp = fopen( filename, "wb" )) ) {             // try to open file
        printf( "[-] Error! Invalid file name '%s'.\n", filename );
        return -1;                                      // failure
    }

    if( fwrite(buf, 1, buflen, fp) != buflen ) {        // write file
        printf( "[-] Error! Cannot write to file '%s'.\n", filename );
        return -1;
    }

    fclose( fp );                                       // no error checks here

    prnt_dbg( DBG_LVL_2, "[+] Secret stored successfully to '%s'.\n", filename );

    return 0;                                           // success!
}

// ------------------------------------------------------------------------------------------------
/*
**  expand(): Expand a buffer to its binary format. Instead of storing 8 bits per byte, we store
**      1 bit per byte. Because we can leak few bits of the secret in each packet, it's easier to
**      work with bits instead of bytes.
**
**  Arguments: buf (char*)   : buffer to expand
**             buflen (int*) : length of the buffer (IN/OUT)
**
**  Return Value: A pointer to the expanded buffer. buflen is updated to show the new buffer 
**      length. NULL on failure.
*/
byte *expand( byte *buf, int *buflen )
{
    byte    *buf_e;                                     // expanded buffer
    int     k, j;                                   // iterators


    /* allocate space for expanded buffer */
    if( !(buf_e = calloc((*buflen << 3) + MAX_COVERT_CHAN_BW, 1)) ) {
        printf( "[-] Error! Cannot allocate memory for expanded buffer.\n" );
        *buflen = -1;       
        return NULL;
    }

    /* expand buffer */
    for( k=0; k<*buflen; ++k )                          // for each byte
        for( j=7; j>=0; --j )                           // for each bit
            buf_e[(k<<3) + (7-j)] = (buf[k] & (1 << j)) >> j;

    *buflen <<= 3;                                      // update length

    prnt_buf( DBG_LVL_3, "[+] Buffer expanded: ", buf_e, *buflen, 1 );
    
    return buf_e;                                       // return expanded buffer
}

// ------------------------------------------------------------------------------------------------
/*
**  shrink(): Opposite of expand(). This functions takes an expanded bit arrau and shrinks it back
**      to a normal byte array. If buflen is not a multiple of 8 no worries :)
**
**  Arguments: buf (char*)   : expanded buffer
**             buflen (int*) : length of the buffer (IN/OUT)
**
**  Return Value: A pointer to the shrinked buffer. buflen is updated to show the new buffer 
**      length. NULL on failure.
*/
byte *shrink( byte *buf, int *buflen )
{
    byte    *buf_s;                                     // expanded buffer
    int     k, j;                                       // iterators


    if( !(buf_s = calloc((*buflen >> 3) + 256, 1)) ) {  // allocate space for normal buffer
        printf( "[-] Error! Cannot allocate memory for shrinked buffer.\n" );
        *buflen = -1;       
        return NULL;
    }

    /* shrink buffer */
    for( k=0; k<*buflen; ++k )                          // for each bit
        buf_s[k >> 3] |= buf[ k ] << (7 - k % 8);       // shrink 8 bits to a byte

    *buflen >>= 3;                                      // update length
    if( (*buflen << 3) != k ) ++(*buflen);              // in case that buflen % 8 != 0

    prnt_buf( DBG_LVL_3, "[+] Buffer shrinked: ", buf_s, *buflen, 0 );

    return buf_s;                                       // return expanded buffer
}


// ------------------------------------------------------------------------------------------------
/*
**  pack(): Convert a sequence of bits in a big-endian number.
**
**  Arguments: buf (byte*) : buffer to read bits from
**             bits (uint) : how many bits to read
**  
**  Return Value: This number on success, -1 on failure.
*/
inline uint32_t pack( byte* buf, uint bits )
{
    uint32_t num = 0;                                   // result
    uint     k;                                         // iterator

    if( bits > 32 ) return -1;                          // error

    for( k=0; k<bits; ++k ) num = (num << 1) | buf[k];  // convert

    return num;                                         // return number
}

// ------------------------------------------------------------------------------------------------
/*
**  unpack(): Inverse of pack(). Convert a big-endian number to sequence of bits
**
**  Arguments: num (uint32_t) : number to covert to bit stream
**             bits (uint)    : how many bits to extract
**             buf (byte*)    : buffer to store bits
**  
**  Return Value: A pointer to the beginning of bit stream, NULL on failure.
*/
inline byte *unpack( uint32_t num, uint bits, byte *buf )
{   
    int k;                                              // iterator

    if( bits > 32 ) return NULL;                        // error

    for( k=bits-1; k>=0; --k )                          // convert
        buf[bits-1 - k] = num & (1 << k) ? 1 : 0;
    
    return buf;                                         // return bit stream
}


// ------------------------------------------------------------------------------------------------ 
