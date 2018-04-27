/*
 * $Id: bounce.c,v 1.2 2004/06/02 15:36:48 raptor Exp $
 *
 * bounce v1.0 - simple TCP bouncer
 * Copyright (c) 2001 Raptor <raptor@antifork.org>
 *
 * Simple program to bounce through TCP ports.
 * Use it just as a telnet-like client and send a SIGINT (pressing ^C is
 * fine) to make it sit on the background and open the specified port on 
 * localhost. Then you can connect on this local port and resume the 
 * interrupted session, data-piped.
 * Resume the data-piped sessions that are still active sending a SIGINT
 * to the background process.
 *
 * Based on an idea of ``asynchro'' (tool found in the wild). 
 * !Not RFC854 compliant, so it can't handle scripting of telnet sessions!
 * Tested on Linux/x86 and OpenBSD/x86.
 *
 * FOR EDUCATIONAL PURPOSES ONLY (tm).
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>

#define VERSION 	"1.0"
#define AUTHOR 		"Raptor"
#define MAIL_SUPPORT 	"<raptor@antifork.org>"

#define OPT_TARGET 	0x01
#define OPT_LOCAL 	0x02
#define OPT_REMOTE 	0x04

#define MAXBUFF 	255
#define MAXADDR 	64


/* Function prototypes */
void fatalerr(char * pattern,...);
void usage(char * name);
void split(int ignored);
int readline(int fdsock, char * line, int maxlen);
void writeline(int fdsock, char * line, int maxlen);
int server(void);
/* Prototypes end */


extern int errno;
int lport, bytes, pid = 0;


int main(int argc, char *argv[])
{
	char target[MAXADDR];
	int opt_line, rport;
	struct sockaddr_in addr;
     	struct hostent *hostp;

     	char buffer[MAXBUFF];
	int s;
     	fd_set p;


/* Parse command line */
        if (argc < 3) usage(argv[0]);

        {
        int c = 0;

        while ((c = getopt(argc, argv, "t:l:r:h")) != EOF)

	    	switch (c) {
		case 'h':
			usage(argv[0]);
			break;
	      	case 't':
			opt_line |= OPT_TARGET;
		   	strncpy(target, optarg, MAXADDR - 1);
		   	break;
	      	case 'l':
			opt_line |= OPT_LOCAL;
		   	lport = atoi(optarg);
		   	break;
	      	case 'r':
			opt_line |= OPT_REMOTE;
		   	rport = atoi(optarg);
		   	break;
	      	}
	}


/* Input control */
        if (!(opt_line & OPT_TARGET) || !*target)
        	fatalerr ("err: -t/--target <arg> required");

	if (!(opt_line & OPT_LOCAL))
		fatalerr ("err: -l/--local <arg> required");

	if (!(opt_line & OPT_REMOTE))
		fatalerr ("err: -r/--remote <arg> required");
				

/* Get the IP address */
     	if ((addr.sin_addr.s_addr = inet_addr(target)) == -1) {

	    	if (!(hostp = gethostbyname(target)))
		   	fatalerr("err: %s", strerror(errno));

	      	memcpy(&addr.sin_addr.s_addr, hostp->h_addr, hostp->h_length);
       	}


/* Signals handling */
	signal(SIGINT, split);


/* Go on and connect() to the remote port */
     	addr.sin_family = AF_INET;
     	addr.sin_port = htons(rport);

     	if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		fatalerr("err: %s", strerror(errno));

     	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		fatalerr("err: %s", strerror(errno));


/* Telnet-like client */
     	while (1) {

	    	bzero(buffer, MAXBUFF);

	    	FD_ZERO(&p);
	    	FD_SET(s, &p);
	    	FD_SET(0, &p);
	    	select(FD_SETSIZE, &p, NULL, NULL, NULL);

	    	if (FD_ISSET(0, &p)) {
		   	read(0, buffer, MAXBUFF - 1);
		   	write(s, buffer, strlen(buffer));
	      	}

	    	if (FD_ISSET(s, &p)) {
		   	if (!(bytes = (read(s, buffer, MAXBUFF - 1)))) {
				kill(pid, SIGTERM); /* End child process */
				exit(0);            /* when father dies  */
			}
		        write(1, buffer, bytes);
	      	}

       	}
}



void split(int ignored) /* SIGINT handler, forks and starts server */
{
     	int fd[2];

     	socketpair(AF_UNIX, SOCK_STREAM, 0, fd);

     	if ((pid = fork ()) <  0)
		fatalerr("err: %s", strerror(errno));

     	if (!pid) { /* Child process */

	    	dup2(fd[1], 0);
	    	dup2(fd[1], 1);

	    	server(); /* actually run the server */

	    	exit(0); /* the server is dead, exit() */
       	}

	/* Father process */

	if (daemon(0, 1) < 0) /* go to the background */
		fatalerr("err: %s", strerror(errno));

     	dup2(fd[0], 0);
     	dup2(fd[0], 1);

	return;
}



int server() /* Local data-pipe server */
{
     	int input, len, s;
     	struct sockaddr_in local, addr;
     	char buffer[MAXBUFF];
     	char prova[MAXBUFF];
     	fd_set p;

	if ((input = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
   		fatalerr("err: %s", strerror(errno));

     	if (setsockopt(input, SOL_SOCKET, SO_REUSEADDR, &len, sizeof (len)) < 0)
   		fatalerr("err: %s", strerror(errno));

     	local.sin_family = AF_INET;
     	local.sin_port = htons(lport);
     	local.sin_addr.s_addr = htonl(INADDR_ANY);

     	if (bind(input, (struct sockaddr *)&local, sizeof(local)) < 0)
   		fatalerr("err: %s", strerror(errno));

     	listen(input, 1); /* Listen with a backlog of 1 incoming connection */


     	len = sizeof(addr);

	if ((s = accept(input, (struct sockaddr *)&addr, &len)) < 0)
		fatalerr("err: %s", strerror(errno));


	while (1) { /* the main loop */

		bzero(buffer, MAXBUFF);

		FD_ZERO(&p);
		FD_SET(s, &p);
		FD_SET(0, &p);
		select(FD_SETSIZE, &p, NULL, NULL, NULL);

		if (FD_ISSET(0, &p)) {
			read(0, buffer, MAXBUFF - 1);
		 	write(s, buffer, strlen(buffer));
		 }

		if (FD_ISSET(s, &p)) {
			if (!(bytes = (read(s, buffer, MAXBUFF -1)))) return;
			write(1, buffer, bytes);
		 }

	}

}



void fatalerr(char * pattern,...) /* Error handling routine */
{
        va_list ap;
        va_start(ap, pattern);

        fprintf(stderr,"bounce-");
        vfprintf(stderr,pattern,ap);
        fprintf(stderr," (exit forced).\n");

        va_end(ap);

        exit(-1);
}



void usage(char * name) /* Print usage */
{
	fprintf(stderr,"BOUNCE %s: tcp bouncer\nCopyright (c) 2001 %s %s\n\n",VERSION,AUTHOR,MAIL_SUPPORT);
        fprintf (stderr, "usage: %s [option]\n", name);

        fprintf (stderr,
                "     -t  target hostname or IP address\n"
                "     -l  local TCP port to bind\n"
                "     -r  remote TCP port to connect to\n"
                "     -h  print this help\n");

        exit (0);
}
