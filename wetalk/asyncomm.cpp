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
// asyncomm.cpp - API for asynchronous commnucation over UDP
//
// ------------------------------------------------------------------------------------------------
#include "asyncomm.h"


/** -----------------------------------------------------------------------------------------------
 * asyncomm::asyncomm(): Class constructor.
 *
 *	@port: Port number to bind
 *	@handler: Signal handler to register SIGPOLL signal
 */
asyncomm::asyncomm( uint16_t port, void (*handler)(int) )
{
	struct sockaddr_in addr;
	struct sigaction hdl;
	socklen_t addrlen;
	int one = 1;


	/* prepare address information */
	bzero(&addr, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;			


	try {
		/* create socket */
		if( (sockd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 )
			throw EXCEPTION_SOCKET;	

		/* enable address reuse for that port */
		if( setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)) < 0 )
			throw EXCEPTION_SOCKOPT;

		/* bind server to local address:port */
		if( bind(sockd, (struct sockaddr*)&addr, sizeof(addr)) < 0 )
			throw EXCEPTION_BIND;

		/* set signal hadler for SIGPOLL signal */	  
	  	hdl.sa_handler = handler;
	  	hdl.sa_flags   = 0;
	 
  		if( sigfillset(&hdl.sa_mask)    < 0 ||
			sigaction(SIGPOLL, &hdl, 0) < 0 ||
			fcntl(sockd, F_SETOWN, getpid()) < 0 ||
			fcntl(sockd, F_SETFL,  O_NONBLOCK | FASYNC) < 0 )
  				throw 
  			;
	}
	catch( int exc_id )	{
		
		/* in case that we're using ncurses, we should stop them first, to make perror() visible */
		endwin();

		/* verbose error */
		switch( exc_id )
		{
			case 1: perror("[-] Error! Cannot create socket");      break;
			case 2: perror("[-] Error! Cannot set socket option");  break;
			case 3: perror("[-] Error! Cannot bind UDP socket");    break;
			case 4: perror("[-] Error! Cannot set signal handler"); break;
		}

		/* close socket and terminate */
		close( sockd );

		exit( EXIT_FAILURE );
	}

	/* no peer and no error */
	ishere  = false;
	iserror = false;
}


/** -----------------------------------------------------------------------------------------------
 * asyncomm::asyncomm(): Class destructor.
 */
asyncomm::~asyncomm() 
{
	/* close socket and you're done! */
	close(sockd); 
}


/** -----------------------------------------------------------------------------------------------
 * asyncomm::assoc(): Assosiate a peer for communication (active mode). Association is done using
 *	connect(). This has the advantage that once 2 peers are associated, a 3rd peer cannot 
 *	connect with them.
 *
 *	@domain: peer name
 *	@port: port to connect to
 *	
 *	return: 0 on success, -1 on failure. Upon error, err buffer is set accordingly.
 */
int asyncomm::assoc( const char *domain, const char *port )
{
	struct addrinfo hints, *res, *it;
	int ret;


	/* if any of these is NULL, abort */
	if( !domain || !port ) {
		strncpy(err, "[Error] hostname/port is missing", ERRMSGLEN);
		iserror = true;

		return -1;
	}

	/* set up the parameters for returned addrinfo */
	bzero( &hints, sizeof(hints) );

	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	hints.ai_flags    = AI_ADDRCONFIG;


	/* resolve hostname to IP address(es); gethostbyname() is deprecated */
	if( getaddrinfo(domain, port, &hints, &res) ) {		
		strncpy(err, "[Error] Cannot resolve hostname", ERRMSGLEN);
		iserror = true;

		return -1;
	}

	/* a domain might have multiple IPs. Connect to the first address */

	/* take a local copy of sockaddr_in  (ignore overflows :P) */	
	memcpy(&addr, res->ai_addr, res->ai_addrlen);

	/* free allocated stuff */
	freeaddrinfo( res );

	/* connect to UDP socket (active mode) 
	 *
	 * This is an old-school trick to avoid cumbersome calls to recvfrom()/sendto().
	 * Also, if a UDP socket calls sendto() to send a UDP packet to an unreachable port, 
	 * any ICMP port unreachable errors that will be returned will be ignored. connect() 
	 * takes the server's address as an argument, so the kernel forwards to the application, 
	 * only the UDP packets that are originated from that specific host, and discarding packets 
	 * from every other host.
	 */
	if( connect(sockd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ) {
		strncpy(err, "[Error] Cannot connect to server", ERRMSGLEN);
		iserror = true;

		return -1;
	}

	/* a peer is associated */
	ishere = true;

	/* success! */
	return 0;
} 


/** -----------------------------------------------------------------------------------------------
 * asyncomm::is_assoc(): Check if a peer is associated. 
 *
 * 	return: True if a peer is connected, false otherwise.
 */
bool asyncomm::is_assoc() 
{
	return ishere;
}


/** -----------------------------------------------------------------------------------------------
 * asyncomm::send(): Send data to the other peer.
 *
 *	@buf: data to send
 *	@buflen: size of data
 *
 * 	return: The number of bytes successfully sent. -1 On failure. 
 */
int asyncomm::send( const char *buf, const size_t buflen )
{
	/* send only if peer exists */
	if( !ishere ) return -1;

	/* send data and return whatever write() returns */
	return write(sockd, buf, buflen);
}


/** -----------------------------------------------------------------------------------------------
 * asyncomm::recv(): Receive data from the other peer.
 *
 *	@buf: buffer to store data
 *	@buflen: buffer size
 *
 *	return: 0 on success, -1 on failure.
 */
int asyncomm::recv( char *buf, size_t &buflen )
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	int rv;


	bzero(buf, buflen);

	/* if a peer is already associated, simply read from the socket */
	if( ishere ) return (buflen = read(sockd, buf, buflen));
	else 
	{
		/* wait for a packet from an unassociated peer (passive mode) */
		if( (int)(buflen = 
				recvfrom(sockd, buf, buflen, 0, (struct sockaddr*)&addr, &addrlen)) < 0)
		{
			return -1;
		}
	
		/* copy the sockaddr_in of the peer */
		memcpy(&this->addr, &addr, addrlen);

		
		/* associate the connection with that peer */
		if( connect(sockd, (struct sockaddr*)&addr, addrlen) < 0 ) 
			return -1;

		/* we now have a peer */
		ishere = true; 	
	}

	return buflen;
}


/** -----------------------------------------------------------------------------------------------
 * asyncomm::getaddr(): Return IP address and port of remote peer.
 *
 *	@ip: array to store ip address
 *	@port: array to store port
 */
void asyncomm::getaddr( char *ip, char *port)
{
	if( !ishere ) return;

	/* extract ip string from sockaddr_in */		
	inet_ntop(AF_INET, &(addr.sin_addr), ip, INET_ADDRSTRLEN);

	/* cast port number to string (overflow it, I don't care!) */
	sprintf( port, "%d", htons(addr.sin_port) );
}

// ------------------------------------------------------------------------------------------------
