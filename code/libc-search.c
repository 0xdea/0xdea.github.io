/*
 * $Id: libc-search.c,v 1.5 2003/08/28 17:31:26 raptor Exp $
 *
 * libc-search.c - quick libc symbol/pattern search helper
 * Copyright (c) 2003 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * This quick and easily-adaptable program loads its dynamic libraries and 
 * tries to find the address of the symbol/pattern specified as command 
 * line argument. It can be somewhat useful when writing exploits with the 
 * return-into-libc technique.
 *
 * Compile with the same shared libs of the program you want to exploit, 
 * plus of course -ldl.
 *
 * $ gcc libc-search.c -o libc-search -lc -ldl
 * $ ./libc-search -s system               
 * The system address is: 0x4005f590
 * $ ./libc-search -s _exit 
 * The _exit address is: 0x400bae90
 * $ ./libc-search -p /bin/sh
 * The /bin/sh address is: 0x4012276d
 * $ ./libc-search -p /bin/sh -b 0x4012276e
 * The /bin/sh address is: 0x401254e3
 *
 * NOTE. Don't use it to find functions used in the local program itself
 * (e.g. exit, fprintf, etc.) or you'll end up finding the ones in .plt.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <signal.h>

#define	LIBBASE		0x4001a000	// change if needed
#define OPT_SYMBOL	0x01
#define	OPT_PATTERN	0x02
#define	OPT_LIBBASE	0x04

void fault() /* SIGSEGV handler */
{
	fprintf(stderr, "ERROR: sorry, pattern not found\n");
	exit(-1);
}

void check_zero(int addr) /* check an address for the presence of a 0x00 */
{
	if ( !(addr & 0xff) || !(addr & 0xff00) || !(addr & 0xff0000) ||
		!(addr & 0xff000000) )
		fprintf(stderr, "WARNING: the address contains a 0x00!\n");
}

int search_str(char *pattern, int addr) /* search for a string in libc */
{
	/* install SIGSEGV handler and begin search */
	signal(SIGSEGV, fault);

	while ( memcmp((void *)addr, pattern, strlen(pattern) + 1) )
		addr++;

	/* uninstall SIGSEGV handler and end search */
	signal(SIGSEGV, SIG_DFL);

	check_zero(addr);
	return(addr);
}

int search(char *pattern)
{
	void *p;
	int addr;

	/* dlopen() the main program */
	if ( !(p = dlopen(NULL, RTLD_LAZY)) ) {
		fprintf(stderr, "%s\n", dlerror());
		exit(-1);
	}

	/* search for the pattern */
	if ( !(addr = (int)dlsym(p, pattern)) ) {
		fprintf(stderr, "%s\n", dlerror());
		exit(-1);
	}

	dlclose(p);

	check_zero(addr);
	return(addr);
}

void usage(char *name)
{
	fprintf(stderr, "usage: %s [ -s <symbol> | " 
			"-p <pattern> [-b <libbase>] ]\n", name);
	exit(-1);
}

int main(int argc, char **argv)
{
	int address, libbase = LIBBASE, opt_line = 0;
	char arg[256], *foo;

	if (argc < 2)
		usage(argv[0]);

	/* parse command line */
	{
		int c = 0;
		while ( (c = getopt(argc, argv, "s:p:b:h")) != EOF )

			switch (c) {
				case 'h':
					usage(argv[0]);
					break;
				case 's':
					opt_line |= OPT_SYMBOL;
					strncpy(arg, optarg, 255);
					break;
				case 'p':
					opt_line |= OPT_PATTERN;
					strncpy(arg, optarg, 255);
					break;
				case 'b':
					opt_line |= OPT_LIBBASE;
					libbase = strtoul(optarg, &foo, 16);
					break;
			}
	}

	/* check command line options */
	if ( !(opt_line & OPT_SYMBOL) && !(opt_line & OPT_PATTERN) )
		usage(argv[0]);
	if ( (opt_line & OPT_SYMBOL) && (opt_line & OPT_PATTERN) )
		usage(argv[0]);
	if ( (opt_line & OPT_SYMBOL) && (opt_line & OPT_LIBBASE) )
		usage(argv[0]);

	if (opt_line & OPT_SYMBOL)
		/* find symbol */
		address = search(arg);
	else
		/* find pattern */
		address = search_str(arg, libbase);

	fprintf(stderr, "The %s address is: %p\n", arg, address);

	exit(0);
}
