/*
 * $Id: ward.c,v 1.8 2005/01/22 11:13:05 raptor Exp $
 *
 * ward.c v2.3 - Fast wardialer for UNIX systems (PSTN/ISDN/GSM)
 * Copyright (c) 2001-2005 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * This is a classic wardialer tool: ward.c scans a list of phone numbers,
 * hunting for modems answering on the other end, and providing a nicely
 * formatted output of the scan results. It can generate a list of phone
 * numbers from a user-supplied mask, in both incremental or random order.
 * It's one of the fastest PBX scanners around, maybe the best for UNIX.
 *
 * Tested on Linux, OpenBSD, FreeBSD, NetBSD, Mac OS X and Windows/Cygwin. 
 * Do the tuning for your system and compile with: gcc ward.c -o ward -lm.
 *
 * CHANGES:
 * v2.3 -	other minor fixes for newer compilers
 * v2.2 -	some minor fixes and clean-up of the code
 * v2.1 -	fixed a weird strncpy() bug on Linux
 * v2.0 -	major rewrite of the whole source code
 *
 * TODO:
 * - detect and report on fax lines [already working on it]
 * - some more details in the log (simple things like no answer etc.)
 * - two timeouts: one for ring attempts and another for after call pickup
 * - new source code distribution scheme + getopt_long
 * - new logging module (separate phonelist and log?)
 * - config file where to put normal settings with the cli overriding it
 * - (n)curses interface? GTK GUI?
 * - distributed scanning architecture (agents, central db, etc.)?
 */

#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/time.h>

/* general information */
#define	NAME		"ward.c"
#define VERSION		"v2.3"
#define DESCRIPTION	"Fast wardialer for UNIX systems (PSTN/ISDN/GSM)"
#define	COPYRIGHT	"Copyright (c) 2001-2005"
#define AUTHOR		"Marco Ivaldi <raptor@0xdeadbeef.info>"

/* getopt() bit masks */
#define OPT_NMASK 	0x01
#define OPT_RAND	0x02
#define OPT_GENERATE	0x04
#define OPT_SCAN	0x08
#define OPT_TIMEOUT	0x10
#define OPT_DEVICE	0x20

/* color definitions */
#define GREEN 		"\E[32m\E[1m"
#define YELLOW		"\E[33m\E[1m"
#define RED		"\E[31m\E[1m"
#define BLUE		"\E[34m\E[1m"
#define BRIGHT		"\E[m\E[1m"
#define NORMAL		"\E[m"

/* local setup, change if needed */
#define MODEM_DEV 	"/dev/modem"	// default modem device
//#define MODEM_DEV	"/dev/ttyS0"	// Linux-style modem device
//#define MODEM_DEV	"/dev/cua00"	// BSD-style modem device
//#define MODEM_DEV	"/dev/cu.modem"	// Mac-style modem device
#define MODEM_SPEED 	B9600		// default modem speed (in baud)
#define MODEM_TIMEOUT 	60		// default modem timeout
#define MAX_RETRIES 	2		// max number of dial retries
#define MAX_LEN 	16		// max length of number, status, out
#define MAX_FILE_LEN	256		// max length of file, dev, strbuf

/* local functions declaration */
void 	scan(char *file);
int 	dial(char *number, int retry);
void 	writefile(int last, int inc, char *file);
void 	listgen(char *mask, int inc, char *file);
int 	initmodem(char *dev);
void 	closemodem(int fd);
int 	hupmodem(int fd);
void 	sendcmd(int fd, int timewait, char *fmt, ...);
void 	cleanup(int ignored);
void 	fatalerr(char *error, ...);
void 	usage(char *name);

/* global variables */
int 	fd, timeout = MODEM_TIMEOUT;
struct 	termios newtio, oldtio;
char 	dev[MAX_FILE_LEN] = MODEM_DEV;
char 	**numbers;

/*
 * main().
 */
int
main(int argc, char **argv) 
{
	int 	inc = 1, opt_line = 0;
	char 	mask[MAX_LEN];
	char 	file[MAX_FILE_LEN];

	/* disable buffering for stdout */
	setvbuf(stdout, NULL, _IONBF, 0);

        fprintf(stderr, "%s\n%s %s - %s\n%s %s\n\n%s", BLUE, NAME, VERSION, 
	    DESCRIPTION, COPYRIGHT, AUTHOR, NORMAL);

	/* parse command line */
	if (argc < 2) 
		usage(argv[0]);

	{
	int c = 0;

	while ((c = getopt(argc, argv, "d:g:hn:rs:t:")) != -1)
		switch (c) {
		case 'g': 	/* activate generation mode */
			opt_line |= OPT_GENERATE;
			strncpy(file, optarg, MAX_FILE_LEN - 1);
			break;				
 		case 's':	/* activate scanning mode */
			opt_line |= OPT_SCAN;
 	               	strncpy(file, optarg, MAX_FILE_LEN - 1);
 	               	break;
              	case 'n':	/* set the number mask */
			opt_line |= OPT_NMASK;
              		strncpy(mask, optarg, MAX_LEN - 1);
			break;
		case 'r':	/* use random mode */
			opt_line |= OPT_RAND;
			inc = 0;
			break;
		case 't':	/* set modem timeout */
			opt_line |= OPT_TIMEOUT;
			timeout = atoi(optarg);
			break;
		case 'd':	/* set modem device */
			opt_line |= OPT_DEVICE;
			strncpy(dev, optarg, MAX_FILE_LEN - 1);
			break;
		case 'h':
		case '?':
		default:	/* print usage */
			usage(argv[0]);
		}			
	}		

	if (!(opt_line & OPT_GENERATE) && !(opt_line & OPT_SCAN))
		fatalerr("err: please select an action [generate or scan]");
	
	if ((opt_line & OPT_GENERATE) && (opt_line & OPT_SCAN))
		fatalerr("err: select only one action [generate or scan]");

	/* signals handling */
        signal(SIGINT, cleanup);

	/* enter generation mode */
	if (opt_line & OPT_GENERATE) {

		if (!(opt_line & OPT_NMASK))
			fatalerr("err: -n <arg> is required with -g");

		listgen(mask, inc, file);

	/* enter scanning mode */
     	} else 

		scan(file);

	exit(0);
}	 

/*
 * scan(): scanner engine.
 *
 * Warning, the parser is really minimal!
 */
void
scan(char *file)
{
	FILE 	*f;
	int 	size = 1;
	char 	number[MAX_LEN], status[MAX_LEN], c[2];

	/* open numbers file */
	if ((f = fopen(file, "r+")) == NULL)
		fatalerr("err: unable to open file %s", file);

	/* open and init modem device */
	if ((fd = initmodem(dev)) < 0)
		fatalerr("err: unable to open %s", dev);

	fprintf(stdout, "Using modem device\t: %s\n", dev);
	fprintf(stdout, "Using modem timeout\t: %dsecs\n\n", timeout);
	fprintf(stdout, "Starting scan.\n");

	/* reset modem */
	sendcmd(fd, 2, "ATZ\r");

	/* parse the numbers file (FIXME) */
	while (size) { 

		bzero(number, MAX_LEN);
		bzero(status, MAX_LEN);
		bzero(c, 2);

		/* read phone number */
		for (;;) {
			size = fread(c, 1, 1, f);  

			if (c[0] == '\t' || !size)
				break;

			strncat(number, c, 1);
		}					

		/* read phone number status */
		for (;;) {
			size = fread(c, 1, 1, f);

			if (c[0] == '\n' || !size)
				break;

			strncat(status, c, 1);
		}

		/* dial the number, if not already scanned */
		if (!strcmp(status, "UNSCANNED")) {

                	switch (dial(number, MAX_RETRIES)) {
			case 1:		/* CONNECT */
				fseek(f, -10, SEEK_CUR);
				fwrite("CONNECT  \n", 10, 1, f);
				break;
			case 2:		/* BUSY */
				fseek(f, -10, SEEK_CUR);
                        	fwrite("BUSY     \n", 10, 1, f);
				break;
			case 3:		/* NO ANSWER */
				fseek(f, -10, SEEK_CUR);
                        	fwrite("-        \n", 10, 1, f);
				break;
			}			
		}
	}

	fprintf(stdout, "Scan finished.\n\n");

	/* close modem and return */
	closemodem(fd);
	return;
}

/* 
 * dial(): actually dial a phone number and get modem response.
 *
 * 1: CONNECT
 * 2: BUSY
 * 3: NO ANSWER
 * 4: EOF
 */
int
dial(char *number, int retry)
{
	int 	i;
	char 	out[MAX_LEN];

        bzero(out, sizeof(out));

	if (!strlen(number)) 
		return(4);

	/* modem hangup */
	fprintf(stdout, "Hanging up...                                     \r");

	if (!hupmodem(fd)) { /* ugly hack for a better error handling (FIXME) */
		if (!hupmodem(fd))	
			fatalerr("err: %s not responding", dev);
	}

        fprintf(stdout, "Dialing: %s (%i)                 \r", number, timeout);
	
	/* send the dial command string */
	sendcmd(fd, 2, "ATM0DT%s\r", number); /* modem volume set to 0 */
	//sendcmd(fd, 2, "ATDT%s\r", number); /* don't mess with modem volume */

	for (i = timeout; i > 0; i--) {

		fprintf(stdout, "Dialing: %s (%i)               \r", number, i);

		/* read modem output */
		if (read(fd, out, MAX_LEN - 1)) {

			/* CONNECT */
			if (strstr(out, "CONNECT") != NULL) {

				fprintf(stdout, "%sCONNECT: %s\n%s", GREEN, 
				    number, NORMAL);

				sleep(3); /* some modems need a delay */
				sendcmd(fd, 2, "+++");

				return(1);
			}

			/* BUSY */
			if (strstr(out, "BUSY") != NULL) {

				fprintf(stdout, "%sBUSY:    %s\n%s", YELLOW, 
				    number, NORMAL);

				return(2);
			}

			/* ERROR */
			if (strstr(out, "ERROR") != NULL) {

				fatalerr("err: ERROR. SIM problem?");
			}

			/* NO ANSWER (speed hacks) */
			if (strstr(out, "NO") != NULL) {

				if (timeout - i < 3) { /* line problem? */

					/* catch the error */
					if (!retry)
						fatalerr("err: NO CARRIER."
						    " Line problem?");

					/* retry recursively */
					fprintf(stdout, "RETRY:   %s\n", 
					    number);
					return(dial(number, retry - 1));

				} else 

					return(3);
			}

			/* NO ANSWER */
			if (strstr(out, "OK") != NULL)

				return(3);
		}

		sleep(1);
	}											
	return(3);
}	

/*
 * writefile(): write numbers to file.
 *
 * Weird strncpy() bug on Linux reported by Circuit <circuit@hackthisbox.org> 
 * is now fixed.
 */
void
writefile(int last, int inc, char *file)
{
	FILE 	*f;
	int 	i;

	if ((f = fopen(file, "a")) == NULL)
		fatalerr("err: unable to open file %s", file);
	
	fprintf(stdout, "Writing numbers to file...\n");

	/* use incremental mode */
	if (inc)
		for (i = 0; i < last; i++) {

			if (!fwrite(numbers[i], 1, strlen(numbers[i]), f))
				fatalerr("err: unable to write to file %s", 
				    file);

			fwrite("\tUNSCANNED\n", 1, 11, f); /* mark as new */

                        fprintf(stdout, "%d numbers left         \r", last - i);
		}

	/* use random mode */
	else {
		int j;
		struct timeval rnd;

		while (last) {

			gettimeofday(&rnd, NULL);
			srand(rnd.tv_usec);

			/* some deep voodoo magic */
	                j = 0 + (int)((last + 0.0) * rand()/(RAND_MAX + 1.0));
			
                        if(!fwrite(numbers[j], 1, strlen(numbers[j]), f))
				fatalerr("err: unable to write to file %s", 
				    file);

			fwrite("\tUNSCANNED\n", 1, 11, f); /* mark as new */

			strncpy(numbers[j], numbers[last - 1], 
			    strlen(numbers[j]));
			last--;
			
                        fprintf(stdout, "%d numbers left             \r", last);
		}		  
	}				

	/* close file */
	fclose(f);

	fprintf(stdout, "Done.                                           \n\n");
	return;
}		

/*
 * listgen(): list generator engine.
 */
void
listgen(char *mask, int inc, char *file)
{
	int 	i, j, tot_numbers;
	int	nextx = 0, nextn = 0, xpos[MAX_LEN];
	char 	n[MAX_LEN]; 
		
	/* parse the number mask */
	for (i = 0; i < strlen(mask); i++) {

		if (mask[i] == 'x') {
			xpos[nextx] = i;
			mask[i] = '0';
			nextx++;
		}
	}
	
	if ((!nextx) || (nextx > 4))
		fatalerr("err: please specify 1 to 4 x's");

	/* allocate the needed amount of memory */
	tot_numbers = pow(10, nextx);
	numbers = (char **)malloc(tot_numbers * sizeof(char *));

	/* fill the numbers array with all possibilities */
	fprintf(stdout, "Generating numbers list...\n");

	for (i = 0; i < tot_numbers; i++) {

		snprintf(n, MAX_LEN - 1, "%d", i);

	 	if (strlen(n) == nextx) {
	
	 		for (j = 0; j < nextx; j++) 
				mask[xpos[j]] = n[j];
        
			numbers[nextn] = strdup((const char *)mask);
                        nextn++;

		} else {

			for (j = 0 ; j < nextx - strlen(n); j++) 
				mask[xpos[j]] = '0';

			for (j = nextx - strlen(n); j < nextx; j++)
				mask[xpos[j]] = n[j + strlen(n) - nextx];

			numbers[nextn] = strdup((const char *)mask);
                        nextn++;
		}

	}						
		
	/* write to file and free() the memory */
	writefile(nextn, inc, file);		

	for (i = 0; i < nextn; i++)
       		free(numbers[i]);
	free(numbers);

	return;
}	

/*
 * initmodem(): open modem device and initialize serial port.
 *
 * This function returns the file descriptor associated with the modem device.
 */
int
initmodem(char *dev)
{
	int 	flags;

        if ((fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK)) == -1)
                return(fd);

	/* save old terminal settings */	
        tcgetattr(fd, &oldtio);

	/* set up the new struct and init serial port */
        tcgetattr(fd, &newtio);

        newtio.c_cflag |= 	MODEM_SPEED | CS8 | CLOCAL | CREAD;
        newtio.c_iflag |= 	IGNPAR;
        newtio.c_oflag = 	0;
        newtio.c_lflag = 	0;
        newtio.c_cc[VTIME] = 	0;
        newtio.c_cc[VMIN] = 	0;

        tcflush(fd, TCIFLUSH);
        tcsetattr(fd, TCSANOW, &newtio);

	/* we no longer want to have the serial port non-blocking */
        flags = fcntl(fd, F_GETFL);
        if (flags == -1)
                 fatalerr("err: failed to get serial tty flags"); 

        flags &= ~O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) == -1)
                 fatalerr("err: failed to set serial port ~O_NONBLOCK");

        return(fd);
}

/*
 * closemodem(): reset serial port and close modem device.
 */
void
closemodem(int fd)
{
	/* hangup and reset modem */
	sendcmd(fd, 1, "+++ATH0\r");
	sendcmd(fd, 1, "ATZ\r");

	/* set old attributes for the serial port */
        tcsetattr(fd, TCSANOW, &oldtio);
        close(fd);

	/* re-enable line buffering for stdout */
	setvbuf(stdout, NULL, _IOLBF, 0);
}

/*
 * hupmodem(): hangup line and get modem response.
 *
 * 0: ERROR, modem not responding
 * 1: OK, modem connected
 */
int
hupmodem(int fd)
{
	char 	out[MAX_LEN];

	bzero(out, sizeof(out));

	sendcmd(fd, 2, "ATH0\r");
	read(fd, out, MAX_LEN - 1);

	/* modem is not responding */
	if (strstr(out, "OK") == NULL)
		return(0);

	/* modem connected */
	return(1);
}

/*
 * sendcmd(): send a command to modem.
 */
void
sendcmd(int fd, int timewait, char *fmt, ...)
{
	char 	strbuf[MAX_FILE_LEN];
        va_list	ap;

        bzero(strbuf, sizeof(strbuf));

        /* flush i/o */
        tcflush(fd, TCIOFLUSH);

        /* send the command */
        va_start(ap, fmt);
        vsnprintf(strbuf, sizeof(strbuf) - 1, fmt, ap);
        write(fd, strbuf, strlen(strbuf));
        va_end(ap);

        /* wait for whatever char has been transmitted */
        tcdrain(fd);
        sleep(timewait);

        return;
}

/*
 * cleanup(): SIGINT handler.
 */
void
cleanup(int ignored)
{
	if (fd)
		closemodem(fd);

	fprintf(stderr, "\n");
	fatalerr("err: program interrupted... cleanup done");	
}

/*
 * fatalerr(): error handling routine.
 */
void
fatalerr(char *error, ...)
{
        va_list ap;
        va_start(ap, error);

        fprintf(stderr, "%sward-", RED);
        vfprintf(stderr, error, ap);
        fprintf(stderr, " (exit forced).\n\n%s", NORMAL);

        va_end(ap);

        exit(1);
}

/*
 * usage(): print usage.
 */
void
usage(char *name)
{
        fprintf (stderr, 
	    "%susage%s:\n"
	    "\t%s [ [-g file] [-n nummask] ] [-r]   (generation mode)\n"
            "\t%s [-s file] [-t timeout] [-d dev]   (scanning mode)\n\n", 
	    BRIGHT, NORMAL, name, name);

        fprintf (stderr,
	    "%sgeneration mode%s:\n"
	    "\t-g  generate numbers list and save it to file\n"
	    "\t-n  number mask to be used in generation mode\n"
	    "\t-r  toggle random mode ON\n\n"
	    "%sscanning mode%s:\n"
	    "\t-s  scan a list of phone numbers from file\n"
	    "\t-t  set the modem timeout (default=%dsecs)\n"
	    "\t-d  use this device (default=%s)\n\n"
	    "%shelp%s:\n"
	    "\t-h  print this help\n\n", BRIGHT, NORMAL, BRIGHT, NORMAL, 
	    timeout, dev, BRIGHT, NORMAL);

        exit (0);
}
