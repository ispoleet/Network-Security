// ------------------------------------------------------------------------------------------------
// CS 536 - Data Communication and Computer Networks
// Fall 2015
// Lab 4: Symmetric Client/Servers - Problem 2 (wetalk)
//
// Kyriakos Ispoglou
//
//                _        _ _    
//               | |      | | |   
//  __      _____| |_ __ _| | | __
//  \ \ /\ / / _ \ __/ _` | | |/ /
//   \ V  V /  __/ || (_| | |   < 
//    \_/\_/ \___|\__\__,_|_|_|\_\
//
// asyncomm.h - API for asynchronous commnucation over UDP
//
// ------------------------------------------------------------------------------------------------
#ifndef __ASYNCOMM_H__
#define __ASYNCOMM_H__

/* we need this header to display error */
#include <ncurses.h>

#include <stdio.h>
#include <unistd.h> 
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


/* maximum error length */
#define ERRMSGLEN			128

/* in case that is not defined */
#ifndef CMDBUFLEN
	#define CMDBUFLEN		256
#endif

/* map numbers with exception types */
#define EXCEPTION_SOCKET 	1
#define EXCEPTION_SOCKOPT 	2
#define EXCEPTION_BIND		3
#define EXCEPTION_SIGSET	4

/** -----------------------------------------------------------------------------------------------
 * asynctalk: Class for asynchronous UDP communication between 2 peers.
 */   
class asyncomm {
	private:
		/* socket descriptors */
		int sockd;

		/* other peer's address information */
		struct sockaddr_in addr;

		/* when a peer is connected this is true */
		bool ishere;

	public:
		/* in case of an error, err buffer is get the error description we use this indirecct 
		 * way to handle errors, as we cannot print them directly if ncurses is used
		 */
		char err[ERRMSGLEN];
		bool iserror;
		
		/* class constructor and destructor */
		asyncomm( uint16_t port, void (*handler)(int)  );
		~asyncomm();

		/* associate a peer for communication */
		int assoc(const char *domain, const char *port);

		/* check if a peer is already associated */
		bool is_assoc();

		/* send data to the other peer */
		int send(const char *buf, const size_t buflen);

		/* receive data from the other peer */
		int recv(char *buf, size_t &buflen);

		/* get ip address and port of the connected peer */
		void getaddr( char *ip, char *port );
};

// ------------------------------------------------------------------------------------------------
#endif
// ------------------------------------------------------------------------------------------------
