#!/usr/bin/perl

#
# $Id: autoscan.pl,v 1.1.1.1 2001/11/17 14:04:49 raptor Exp $
#
# autoscan.pl v0.4 - Autonet NUA scanner
# Copyright (c) 2001 Raptor <raptor@antifork.org>
#
# This program scans for valid NUAs using the autonet x25pad gateway,
# logging valid NUAs that refuse connection (requiring a valid NUI to
# connect), freely available NUAs (accepting reverse charging) and
# Calls Cleared 0-67 (DTE, subaddress specification needed). ADP 
# Network Services are not logged (who cares about that stuff?).
# Automatic subaddress scan when a DTE is received is not implemented.
#
# Now a bit of theory:
# Autonet NUA syntax: AAAhhhhhSS (AAA=area, hhhhh=host, SS=subaddress)
# NUAs on Autonet are most likely something like AAAhhh00[SS], so i
# strongly suggest to scan using only 3 digits for the host part of the NUA.
# Scan subaddresses using 7 digits (see examples in usage message).
#
# Based on brutus.pl, also by Raptor <raptor@antifork.org>
#
# FOR EDUCATIONAL PURPOSES ONLY (tm).
#


# Modules
use Net::Telnet;
use Getopt::Std;


# Default vars
$author = "Raptor <raptor\@antifork.org>";
$version = "v0.4";
$usage = "\nautoscan.pl $version by $author\n\nUsage:\nautoscan.pl -h host <-l nualist | -a area -s start -e end> [-t timeout] [-L log]\n\nhost\t: specifies target autonet gateway\nnualist\t: NUAs to be tried by autoscan\narea\t: generate all NUAs with this area code\nstart\t: begin the scan with this NUA\nend\t: end the scan with this NUA\ntimeout\t: specifies connection timeout, default 10 secs\nlog\t: specifies the optional log file\n\nExamples:\nautoscan -h gateway.autonet.net -l nua.txt\nautoscan -h gateway.autonet.net -a 313 -s 000 -e 999\nautoscan -h gateway.autonet.net -a 313 -s 1234500 -e 1234599\n\n";
$timeout = 10;

$n = 0; # NUAs counter
$v = 0; # valid counter

$LOG_WRONG = 0; # don't log wrong NUAs by default
$WAIT_TIME = 2; # time to wait before sending a command

chomp($date = `date "+%m/%d, %H:%M:%S"`);



# Command line
getopt("h:l:t:L:a:s:e:"); # whoa!

die $usage if (!($opt_h) || !(($opt_l) xor ($opt_a))); # mandatory options
die $usage if ((($opt_s) || ($opt_e)) && !($opt_a)); # dependency
die $usage if (!(($opt_s) && ($opt_e)) && ($opt_a)); # dependency

$target = $opt_h;
$logfile = $opt_L if $opt_L;
$timeout = $opt_t if $opt_t;


# Do you want NUA generation?
if ($opt_a) {
	die "err: area code must be 3 digits long\n" if length($opt_a) != 3;
	$area = $opt_a;

	die "err: start address and end address must have the same number of digits\n" if length($opt_s) != length($opt_e);
	die "err: host part of the nua must be <= 7 digits long\n" if length($opt_s) > 7;
	die "err: -e value must be greater than -s value\n" if $opt_s >= $opt_e;
	$from = $opt_s;
	$to = $opt_e;
}

# Do you want to get NUAs (and/or mnemonic codes) from file?
if ($opt_l) {
	$nuafile = $opt_l;
	die "err: $nuafile: no such file\n" if !(open NUA, "<$nuafile"); 
}



# Print start info to stdout/logfile
if ($nuafile) {
	$start = "\n\n---Breaking from file $nuafile started at $date---\n";
} else {
	$first = $area.$from;
	$last = $area.$to;
	$start = "\n\n---Breaking from $first to $last started at $date---\n";
}
print $start;

if ($logfile) {
	die "err: $logfile: error writing to file\n" 
		if !(open LOG, ">>$logfile");
	print LOG $start;
	select(LOG); # flush log output
	$| = 1;
	select(STDOUT);
}



# Start scanning from nuafile
if ($nuafile) {
	while (<NUA>) {
		next if $_ eq "\n"; # skip empty lines
		chomp($nua = $_);
		$n++;
		&scan("23");
	}

	close NUA;

# Start scanning generating a list of NUAs
} else {
	for ($nua=$first; $nua<=$last; $nua++) {
		$n++;
		&scan("23");
	}
}



# Print end info to stdout/logfile
chomp($date = `date "+%m/%d, %H:%M:%S"`);
$total = "\n[T]  $n NUA(s) totally tested, $v valid addresses found\n";
$end = "--- Breaking on $target ended at $date ---\n";
print $total;
print $end;

if ($logfile) {
	print LOG $total;
	print LOG $end;
	close LOG;
}

exit(0);



#################### Local Functions #######################



# Logging routine
sub log {
	# Valid address with reverse charging enabled found!
	if ($gotcha == 1) {
		$v++;
		$log = "[x]  $nua (REV)\n";
	
	# Valid address found (requires a valid autonet NUI)
	} elsif ($gotcha == 2) {
		$v++;
		$log = "[x]  $nua\n";

	# DTE (subaddress needed)
	} elsif ($gotcha == 3) {
		$log = "[ ]  $nua (dte)\n";
	
	# Address is not good
	} elsif ($LOG_WRONG) {
		$log = "[ ]  $nua is not good...\n";
	} else {
		$log = "";
	}

	print $log;
	print LOG $log if $logfile;

	return;
}



# Bruteforcer routine
sub scan {

	# Connect to gateway
	$t = new Net::Telnet (	
		Port => $_[0],
		Host => $target,
		Timeout => $timeout,
		Errmode => "return");
	die "err: can't connect\n" if !$t;

	# We don't care about Command: prompt, we simply send data
        $t->print("\n");
	sleep $WAIT_TIME; # wait some seconds before sending command
        $t->print("c $nua");
        $gotcha = 0;

        # Determine wether the NUA is valid or not
        (undef, $match) = $t->waitfor(-match => '/\?\*\*User/',
		-match => '/Code: 0-67/', -match => '/\?\*\*/', 
		-match => '/ADP/', -match => '/CALL CONNECTED/');
	
	if ($match =~ /Code: 0-67/) {
		$gotcha = 3; # Call cleared (DTE)
	} elsif ($match =~ /\?\*\*User/) {
		$gotcha = 2; # no reverse
	} elsif ($match =~ /CALL CONNECTED/) {
		$gotcha = 1; # reverse enabled
	}

	# Log results	
	&log;

	$t->close;
	return;
}
