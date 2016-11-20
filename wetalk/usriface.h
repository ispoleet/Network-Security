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
// usriface.h - API for user interface management
//
// ------------------------------------------------------------------------------------------------
#ifndef __USRIFACE_H__
#define __USRIFACE_H__


#include <ncurses.h> 
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <queue>


/* application banner */
#define BANNER 			"wetalk v1.0 - Simple UDP Chat Application"

/* dimension limits */
#define MAXCHATSCR_X 	384
#define MAXCHATSCR_Y 	128
#define MAXCMDSCR_X 	384
#define MAXCMDSCR_Y 	3
#define DEFCMDSCR_Y 	3
#define SCRMIN_X		50
#define SCRMIN_Y		16

/* upper bounds in buffers */
#define MAXMSGLEN		384
#define MSGHISTORYSZ	64

/* input buffer is configured by user; if not set the default */
#ifndef CMDBUFLEN
	#define CMDBUFLEN	MAXMSGLEN
#endif

/* watch out this case! */
#if CMDBUFLEN > MAXMSGLEN
	#error CMDBUFLEN must be smaller than MAXMSGLEN to avoid overflow!
#endif

/* color macros */
#define SND_COLOR 		1
#define RCV_COLOR 		2
#define CMD_COLOR 		3
#define INT_COLOR 		4
#define COLOR(type) 	COLOR_PAIR(type##_COLOR)

/* virtual key codes */
#define VK_RETURN 		13
#define VK_BACKSPACE 	127


using namespace std;


/* fat pointers: pointer + upper bound */
struct fatptr { int i, j; };

/* message types */
enum msg_type {UNDEF='\0', INTR='!', RECV='>', SEND='<', CTRL='*'};

/** -----------------------------------------------------------------------------------------------
 * usriface: Class for User Interface. This class provides actually a very strict API for reading
 *	to and writing from the console. When window is resized, the text and the windows properly
 *	updated.
 */
class usriface {
	private:
		/* our ncurses-types windows */
		WINDOW *cnvwin, *cmdwin;

		/* the window dimensions */
		struct wnd { int x, y; } scr, cnv, cmd;

		/* Conversation array contains the chat history to be displayed. Usually the terminal 
		 * size is much smaller than available history, so only the most recent parts are 
		 * displayed.
		 *
		 * Input array contains what the user types. It's only one line long. If input is too
		 * long only the last part is displayed.
		 *
 		 * Terminal size adds a limitation by itself, so we can use a sufficiently large static
 		 * array.
		 */
		struct msg {
			char 	data[MAXMSGLEN+1];	// +1 for extra NULL byte
			size_t 	len;		
			int 	type;

		} conv[MSGHISTORYSZ], input;

		/* current index and size of conv. Resets to 0 when reaches MSGHISTORYSZ */
		int cidx, csz;

	public:
		/* class constructor and destructor */
		usriface( void (*)(int) );
		~usriface();

		/* render (or "refresh") console */
		void render();

		/* write a message to the terminal */
		void write(const char mtype, const char *msg);

		/* write a character to the command window */
		void wrtch(char ch, void (*)( char *inp, size_t len) );
};

// ------------------------------------------------------------------------------------------------
#endif
// ------------------------------------------------------------------------------------------------
