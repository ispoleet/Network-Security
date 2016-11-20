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
// usriface.cpp - API for user interface management
//
// ------------------------------------------------------------------------------------------------
#include "usriface.h"


/** -----------------------------------------------------------------------------------------------
 * usriface::usriface(): Class constructor.
 */
usriface::usriface( void (*sighdlr)(int) )
{
	/* zero out buffers */
	bzero(&input, sizeof(struct msg));

	for( int i=0; i<MSGHISTORYSZ; ++i )
		bzero(&conv[i], sizeof(struct msg));

	cidx = 0; csz = 0;


	/* initialize ncurses */
	initscr();			
	cbreak();						// disanle line buffering
	noecho();						// don't echo characters   
   	keypad(cmdwin, TRUE);			// enable keypad in command window      
   	idcok(cmdwin, 1); 
   	idlok(cmdwin, 1);   
   	refresh();
	start_color();					// start colors
	use_default_colors();
	curs_set( TRUE ); 				// show cursor


	/* set signal hander to catch window resizing */
	signal(SIGWINCH, sighdlr);

	/* create windows */
	cnvwin = newwin(0, 0, 0, 0);
	cmdwin = newwin(0, 0, 0, 0);

	/* set colors and attributes */
	wattrset(stdscr, A_BOLD);
	wattrset(cnvwin, A_BOLD);
	wattrset(cmdwin, A_BOLD);

	init_pair(RCV_COLOR, COLOR_GREEN,  COLOR_BLACK);
	init_pair(SND_COLOR, COLOR_BLUE,   COLOR_BLACK);
	init_pair(CMD_COLOR, COLOR_RED,    COLOR_BLACK);
	init_pair(INT_COLOR, COLOR_YELLOW, COLOR_BLACK);
		
	wbkgd(cnvwin, COLOR(RCV));
	wbkgd(cmdwin, COLOR(SND));

	wattron(cnvwin, A_BOLD);
	wattron(cmdwin, A_BOLD);

	/* render terminal */
	this->render();
}


/** -----------------------------------------------------------------------------------------------
 * usriface::~usriface(): Class destructor.
 */
usriface::~usriface( void )
{
	/* make borders invisible */
	wborder(cnvwin, ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ');
	wborder(cmdwin, ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ');

	/* update changes */
	wrefresh(cnvwin);
	wrefresh(cmdwin);

	/* delete windows */
	delwin(cnvwin);
	delwin(cmdwin);

	/* teardown ncurses mode */
	endwin();
}


/** -----------------------------------------------------------------------------------------------
 * usriface::render(): Render screen. The tricky part of render() is to adjust chat history in
 * 	window dimensions. So, when we resize the window, render only displays the lastest history 
 *	that can fit in window.
 */
void usriface::render()
{
	/* get terminal coordinates (height/width) */
	getmaxyx(stdscr, scr.y, scr.x); 

	/* if terminal is too small, abort */
	if( scr.x < SCRMIN_X || scr.y < SCRMIN_Y )
	{
		wclear(stdscr); 
		mvwprintw(stdscr, 1, 1, "Screen is too small!");
		
		return;
	}

	/* calc coordinaates of command and conversation windows */
	cmd.x = scr.x;	cmd.y = DEFCMDSCR_Y;	
	cnv.x = scr.x;	cnv.y = scr.y - cmd.y - 1;

	/* adjust windows in the terminal */
	wresize(cnvwin, cnv.y, cnv.x); 
	wresize(cmdwin, cmd.y, cmd.x); 	
	mvwin(cnvwin, 1, 0); 
	mvwin(cmdwin, cnv.y+1, 0); 
	
	/* clear windows, to write the new data */
	wclear(stdscr); 
	wclear(cnvwin); 
	wclear(cmdwin); 

	/* print banner */
	mvwprintw(stdscr, 0, scr.x/2 - strlen(BANNER)/2, BANNER);
	wrefresh(stdscr);	
		
	/* draw window outlines */    
	box(cnvwin, 0, 0); wrefresh(cnvwin);
	box(cmdwin, 0, 0); wrefresh(cmdwin);


	/**
	 * The conv buffer, is usually much larger than cnvwin, so we need to display only the
	 * most recent part of conv. Simply printing the last cnv.y lines doesn't work as a 
	 * message can span multiple lines.
	 *
	 * A quick and dirty trick here is to use a queue, to "stretch" the conv buffer into a
	 * a buffer with width equal with cnvwin, and arbitrary large height. Then we discard
	 * the oldest entries from it (if they are), that do not fit in the window. The pros 
	 * of the queue, is that if we have very few entries, we can display them on top of the
	 * window, but if we have many we only display the most recent ones.
	 */
	queue <struct fatptr> Q;
	int i, j, sz;
	

	/** 
	 * Instead of copying strings from conv to the queue, we simply push pointers to them.
	 * We use "fat" pointers as we also need to know the upper bound of the buffer, to avoid
	 * avoid overflows.
	 *
	 * The for loop below it's tricky: We want to start from pushing the oldest entry first.
	 * This way when we start poping, the oldest entry will poped first. When conv is not
	 * full, the oldest entry is at conv[0]. But when is full, oldest entry is at conv[cidx].
	 * So we use csz as invariant and we properly update index, in such a way to handle both
	 * cases.
	 */
	for( sz=0, i=csz<MSGHISTORYSZ ? 0 : cidx; sz<csz; ++sz, i=++i % MSGHISTORYSZ )	
#if __cplusplus >= 201103L
		/* in C++ >= 11 we can have extended initializers */
		for( j=0; j<conv[i].len; Q.push({i,j}), j+=cnv.x-2 )
			;
#else
		/* otherwise use the traditional initializer */
		for( j=0; j<conv[i].len; j+=cnv.x-2 )
		{
			struct fatptr ptr = {.i = i, .j = j};
			Q.push(ptr);
		}	
#endif	

	/* pop oldest elements of the queue, until the remaining can fit in the screen */
	/* don't write to borders, so stop at cnv.y - 2 */
	while( Q.size() > cnv.y - 2 ) Q.pop();

	/* display the remaining things to cnvwin */
	for( i=0; !Q.empty(); ++i ) 
	{
		struct fatptr ptr = Q.front(); Q.pop();

		/* based on type use the right color */
		switch( conv[ptr.i].type )
		{
			case SEND: wattron(cnvwin, COLOR(SND)); break;
			case RECV: wattron(cnvwin, COLOR(RCV)); break;
			case CTRL: wattron(cnvwin, COLOR(CMD)); break;
			case INTR: wattron(cnvwin, COLOR(INT));
		}

		/* again stop at cnv.x-2 and start from (1,1), to avoid writing to borders */
		for( j=0; j<cnv.x-2 && ptr.j+j < conv[ptr.i].len; ++j )
			mvwprintw(cnvwin, i+1, j+1, "%c", conv[ptr.i].data[ptr.j + j]); 
	}

	/* remove colors */
	wattroff(cnvwin, COLOR(SND) | COLOR(RCV) | COLOR(CMD) );


	/* display contents of command window */
	mvwprintw(cmdwin, 1, 1, "? "); 
	
	/*cmd.x - 5 =  2 for border + 2 for "$ "  + 1 to not having cursor in border */
	for( i=0, j=input.len < (cmd.x-5) ? 0 : input.len - (cmd.x-5); j<input.len; ++j, ++i )
		mvwprintw(cmdwin, 1, i+3, "%c", input.data[j]); 


	/* refresh again windows to reflect our changes */
	wrefresh(cnvwin); 
	wrefresh(cmdwin); 
}


/** -----------------------------------------------------------------------------------------------
 * usriface::write(): Write a message to chat screen.
 *
 * 	@mtype: Type of message (the character that prepends the message)
 *	@msg: Message to display
 */
void usriface::write( const char mtype, const char *msg )
{
	/* safe-copy to history buffer */
	conv[cidx].len = snprintf(conv[cidx].data, MAXMSGLEN, "%c %s%c", mtype, msg, 0);
	conv[cidx].type = mtype;

	/* in case that len(msg) > MAXMSGLEN, adjust length */
	if( conv[cidx].len > MAXMSGLEN ) conv[cidx].len = MAXMSGLEN;

	/* circularly update index and size */
	cidx = ++cidx % MSGHISTORYSZ;
	if( csz < MSGHISTORYSZ ) ++csz;

	/* render terminal to display the newly added message */
	this->render();
}


/** -----------------------------------------------------------------------------------------------
 * usriface::wrtch(): Write a character to the command buffer and display it.
 *
 * 	@ch: Character to write
 *	@callback: Callback function that processes input buffer before it gets flushed
 */
void usriface::wrtch( char ch, void (*callback)( char*,  size_t) )
{
	/* discard invalid characters */
	if( ch == -1 ) return;

	/* if enter was pressed, send it to conv window, and clear buffer */
	if( ch == VK_RETURN )
	{
		/* if no input, ignore */
		if( !input.len ) return;

		/* append a NULL */
		input.data[ input.len++ ] = '\0';

		/* write data to conv window and clear buffer */
		this->write(SEND, input.data);		

		/* call callback function to processs input first */
		callback(input.data, input.len);

		bzero(&input, sizeof(struct msg) );
	}

	/* if backspace was pressed, remove last character (if exists) */
	else if( ch == VK_BACKSPACE )
	{
		/* if no input, ignore */
		if( !input.len ) return;

		input.data[ --input.len ] = '\0';
	}
		
	/* a regular key was pressed; append it to buffer (w/o overflows)  */
	else if( input.len < CMDBUFLEN )

		/* TODO: Ignore special chars, like arrow keys, scrolls, etc. */
		input.data[ input.len++ ] = ch;


	/* make changes visible */
	this->render();
}

// ------------------------------------------------------------------------------------------------
