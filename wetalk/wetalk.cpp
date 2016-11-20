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
// wetalk.cpp - Main file
//
//
// TODO: wetalk can be connected to itself. Fix it.
//
//
// In order to simplify our event-driven design, we abstracting the wetalk app in states.
// The state diagram is shown below. The tuples in transitions denote
// (user_input, received_message). Not all states are really need to be implemented here.
//
//
//                                                 ("q",-)
// +-------+         +------------------------------------------------------------------+
// | START |-----+   |                                                                  |
// +-------+     |   |                  timeout/(-,"KO")                                |
//               |   |   +------------------------------------------------+             |
//               |   |   |                                                |             |
//               v   |   v                                                |             |
//          +----+---+---+----+      ("hostname port", +)        +--------+--------+    |
// +------->|      IDLE       |--------------------------------->|      WAIT       |    |
// |        +--------+--------+                                  +--------+--------+    |
// |                 |                                                    |             |
// |                 |(-,"wannatalk")                                     |(-,"OK")     |
// |                 |                                                    |             |
// |("n",-)          |                                                    |    (*,*)    |
// |                 |                                                    |  +--------+ |
// |                 v                                                    v  v        | |
// |        +--------+--------+             ("c",-)              +--------+--+-----+  | |
// |        |     REQUEST     |--------------------------------->|      ASSOC      |  | |
// |        +--------+--------+                                  +--------+--+-----+  | |
// |                 |                                                    |  |        | |
// |                 |                                      ("q",-)(-,"E")|  +--------+ |
// +-----------------+                                                    |             |
//                                                                        v             |
//                                                                    +---+---+         |
//                                                                    | CLOSE |<--------+
//                                                                    +-------+
//
// ------------------------------------------------------------------------------------------------
#include <unistd.h> 
#include <stdlib.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <string.h>


/* according to problem description, messages >50 bytes muste be truncated */
#define CMDBUFLEN			50
#define CONNECTION_TIMEOUT 	7
#define CTRLBUFLEN			256


#include "usriface.h"
#include "asyncomm.h"


//#define __DEBUG__

/* our global objects */
usriface *ui;
asyncomm *peer;


/* program states */
enum _state_ {START, IDLE, WAIT, REQUEST, ASSOC, CLOSE};
int state;

/* flag to enable/disable user input */
bool disable_input;


/** -----------------------------------------------------------------------------------------------
 * chst(): Change the program's state based on the input. Because our code is event-driven, we 
 * 	need code to process different part of the input at different places. This can end up in a
 *  awkward design, and we might miss many corner cases. With this trick all input processing is
 *  done here.
 *
 *	@currst: current state
 *	@inp: user's input
 *	@pkt: received packet
 *	@len: length of inp, or pkt (only one is non-NULL)
 *
 *	return: The new state after processing
 */
int chst( int currst, char *inp, char *pkt, size_t len )
{

	/* if debug is enabled print state in each step */
#ifdef __DEBUG__	
	char msg[256];

	sprintf(msg, "st:%d | inp:%s | pkt:%s | len:%ld", currst, inp, pkt, len);
	ui->write(INTR, msg);
#endif


	/* if a packet was received */
 	if( pkt )
	{
		if( currst == START || currst == IDLE )
		{
			/* if you got "wannatalk" message, move on REQUEST state */
			if( !strcmp(pkt, "wannatalk") ) 
			{
				char msg[64], ip[32], port[8];


				/* display peer's IP and port */
				peer->getaddr(ip, port);
				
				snprintf(msg, CMDBUFLEN, "Chat request from %s:%s", ip, port);

				ui->write(CTRL, msg);
				ui->write(CTRL, "Press 'c' to accept request, or 'n' to discard it");

				return REQUEST;
			}

			/* if you receive anything else, stay on IDLE state */		
			return IDLE;
		}
		
		else if( currst == WAIT )
		{
			/* enable input again */
			disable_input = false;

			/* if OK was received, associate peer */
			if( !strcmp(pkt, "OK") ) {
				ui->write(CTRL, "Connection accepted!");
				return ASSOC;
			}
		
			/* in case of connection refuse, explicitly inform user */
			else if( !strcmp(pkt, "KO") ) {
				ui->write(CTRL, "Connection refused by other peer");
				return IDLE;
			}

			/* if timeout expired, go back to IDLE (this "if" is redundant) */
			else if( !strcmp(inp, "timeout") && !strcmp(pkt, "timeout") )
				return IDLE;
	
			/* if KO, or something else received, go back to IDLE state */
			return IDLE;
		}
		
		else if( currst == ASSOC )
		{
			/* if 'E' was received, teardown connection */
			if( !strcmp(pkt, "E") ) {

				ui->write(CTRL, "Connection closed by other peer");
				ui->write(INTR, "To connect to a new peer, type: hostname port");

				return IDLE;
			}

			/* display whatever was received  (drop 1st character) 
			 * if packet doesn't start with 'D' silently discard it
			 */
			if( pkt[0] == 'D') ui->write(RECV, &pkt[1]);
	 	}
	}


	/* if we have user input */
	else if( inp )
	{
		if( currst == START || currst == IDLE )
		{
			char msg[CTRLBUFLEN];
			char *p;

			/* if 'q' was pressed, teardown connection */
			if( !strcmp(inp, "q") ) {

				/* move on CLOSE state */
				ui->write(CTRL, "Exiting. Bye Bye :)");
				sleep(1);

				delete peer;
				delete ui;

				exit( EXIT_SUCCESS );
			}


			/* treat input as "hostname port" */
			if( !(p = strchr(inp, ' ')) ) {
				ui->write(CTRL, "[Error] Not connected");
				return IDLE;
			}

			/* replace space with NULL */
			*p = '\0';

			/* hostname is at inp[0], while port number is right after space */
			if( peer->assoc(inp, p+1) < 0 ) {
				ui->write(CTRL, peer->err);
				
				return IDLE;
			}
			
			/* association was successfull. Display peer's information */
			snprintf(msg, CTRLBUFLEN, "Connecting to %s:%s (timeout: %dsec)", 
					inp, p+1, CONNECTION_TIMEOUT);

			ui->write(CTRL, msg);
			
			/* send SYN message */
			if(	peer->send("wannatalk\0", 11) < 0 ) {
				ui->write(CTRL, "[Error] Cannot send packet");

				/* upon failure, go back to idle state */
				return IDLE;
			}

			/* set SYN timeout */
			alarm( CONNECTION_TIMEOUT );
			disable_input = true;

			/* move on WAIT state */
			return WAIT;
		}
		
		else if( currst == REQUEST )
		{
			/* if 'c' was pressed, accept connection */
			if( !strcmp(inp, "c") ) {
				
				if(	peer->send("OK\0", 3) < 0 ) 
					ui->write(CTRL, "[Error] Cannot send packet");

				return ASSOC;
			}

			/* if 'n' was pressed, reject connection */
			else if( !strcmp(inp, "n") )
				if(	peer->send("KO\0", 3) < 0 ) 
					ui->write(CTRL, "[Error] Cannot send packet");

		
			/* otherwise go back to IDLE state */
			return IDLE;
		}

		else if( currst == ASSOC )
		{
			/* if 'q' was pressed, teardown connection */
			if( !strcmp(inp, "q") ) {
				if(	peer->send("E\0", 2) < 0 ) 
					ui->write(CTRL, "[Error] Cannot send packet");
				
				/* move on CLOSE state */
				ui->write(CTRL, "Exiting. Bye Bye :)");
				sleep(1);

				delete peer;
				delete ui;

				exit( EXIT_SUCCESS );
			}

			/* otherwise, send whatever user typed */

			/* prepend 'D' in the message */
			memmove(&inp[1], inp, len);
			inp[0] = 'D';

			/* send message */
			if( peer->send(inp, len) < 0 )
				ui->write(CTRL, "[Error] Cannot send message");
	 	}
	}


	/* keep the same state */
	return currst;
}


/** -----------------------------------------------------------------------------------------------
 * sighdlr(): Signal Handler (it's used for many events).
 *
 *	@signum: signal number
 */
void sighdlr( int signum )
{
	/* window size changed? */
	if( signum == SIGWINCH ) 
	{
		/* forgot about previous window (using endwin) and re-initialize to the new window */
		endwin();
		refresh();
		ui->render();
	}

	/* timeout expired */
	else if( signum == SIGALRM ) 
	{
		char timeout[] = { "timeout" };


		/* accept timeout only in WAIT state */
		if( state != WAIT ) return;

		disable_input = false;

		ui->write(CTRL, "Connection timeout. Please try another host");
		
		/* update state */
		state = chst(state, timeout, timeout, -1);
	}

	/* socket descriptor is ready (something has arrived) */
	else if( signum == SIGPOLL )
	{
		char buf[ CMDBUFLEN + 1 ];
		size_t len = CMDBUFLEN;

		/* when buffer is full make it NULL terminating */
		bzero(buf, CMDBUFLEN+1);

		/* receive packet */
		if( peer->recv(buf, len) < 0 ) {
			ui->write(CTRL, "[Error] Cannot receive messsage");
			disable_input = false;

			return;
		}

		/* process packet and update state */
		state = chst(state, NULL, buf, len);
	}
}


/** -----------------------------------------------------------------------------------------------
 * procinp(): This function is called when user completes a command.
 *
 *	@inp: user input
 *	@len: length of user input
 */
void procinp( char *inp, size_t len) 
{
	/* simply update state based on input */
	state = chst(state, inp, NULL, len);
}


/** -----------------------------------------------------------------------------------------------
 * main(): Program's entry point.
 */
int main(int argc, char *argv[]) 
{ 
	/* check arguments */
	if( argc != 2 ) {
		printf( "Usage: %s my-port-number\n\n", argv[0] );
		return -1;
	}

	/* catch signals from alarm() */
	signal(SIGALRM, sighdlr);

	/* create peer and user interface objects */
	peer = new asyncomm(atoi(argv[1]), sighdlr);
	ui   = new usriface(sighdlr);
	

	/* print intro messages */
	ui->write(INTR, "Welcome to wetalk v1.0 - ispo@purdue.edu");
	ui->write(INTR, "Window resizing is supported");
	ui->write(INTR, "To connect to a peer, type: hostname port");
	ui->write(INTR, "To quit application, type 'q'");
	
	
	/* start from IDLE state */
	state = IDLE;
	disable_input = false;

	/* our program is event-driven, so main body is minimal */
	for( ;; )
	{
		/* read a character and display it */
		if( !disable_input ) ui->wrtch( getchar(), procinp );

		/* when input is disabled, prevent 100% cpu usage */
		else usleep(1000);
	}

	/* dead code */
	return 0;
}

// ------------------------------------------------------------------------------------------------
