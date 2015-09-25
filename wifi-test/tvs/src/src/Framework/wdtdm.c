/* Copyright (c) <2002>, Intel Corporation
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or 
 * without modification, are permitted provided that the following 
 * conditions are met:
 * 
 * Redistributions of source code must retain the above copyright 
 * notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of Intel Corporation, nor the names 
 * of its contributors may be used to endorse or promote products 
 * derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/***************************************************************************
$Id: wdtdm.c,v 1.3 2004/07/21 16:43:31 xling Exp $
                          wdtdm.c  -  description
                             -------------------
    begin                : Tue Mar 12 2002
    copyright            : (C) 2002 by LingXiaoFeng
    email                : LingXiaoFeng
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#define MAXFD 64

void daemon_init(const char *pname, int facility);
void (*oldtimefunc)(), (*oldhupfunc)(), time_catch(), hup_catch();

int fd;
int reflash_time = 4, margin_time;
void print_info(char* strInfo, ... )
{
	va_list parameters;
	vprintf( strInfo, parameters );

}


main(char argc, char *argv[])
{
	int err;

	int bytes;
	char command_buf[200];

	openlog("test", LOG_PID, 0);
	syslog(LOG_WARNING|LOG_USER, "testdaemon, begin");
	if(argc < 2)
		exit(1);
	if(!strcmp(argv[1], "i"))
	{
		err = system("lsmod | grep ipmi_comb");
        	margin_time = argc >= 3 ?atoi(argv[2]):600;
		margin_time = margin_time < 2 ? 60:margin_time;
		if(err == 0)
		{
			err = system("rmmod ipmi_comb");
			if( err != 0)
			{
				print_info("ipmi_comb driver already been used by other process\n");
				exit(2);
			}
		}
	        sprintf(command_buf, "insmod ipmi_comb action=1 pre_action=2 margin=%d pre_margin=5", margin_time);
        	printf(command_buf);
		err = system(command_buf);
		if(err != 0)
		{
			print_info("insmod ipmi_comb failure!\n");
			exit(3);
		}
	}else if(argv[1][0] == 'u')
	{
		system("killall -HUP wdtdm");
        exit(0);
 	}
	daemon_init("wdtd", 0);	
	fd = open("/dev/watchdog", O_WRONLY);
	if(fd == -1)
	{
		print_info("open watchdog device error!\n");
		exit(4);
	}
//    oldtimefunc = signal(SIGALRM, time_catch);
	oldhupfunc = signal(SIGHUP, hup_catch);
//   	alarm(reflash_time);
	if( write(fd,"\0",1) ==	-1) /*	refreshes (or resets) the timer	*/
	{
		print_info("write device error!\n");
		exit(5);
	}

	print_info("watchdog timer work now!\n");
	fsync(fd); /* make sure	it's written out to the	device */
	for(;;)
	{
		sleep(30);
/*
        if( write(fd,"\0",1) ==	-1)
        {
		print_info("write device error!\n");
        	exit(5);
        }
*/
	}
}
void hup_catch()
{
	close(fd);
  	signal(SIGHUP,oldhupfunc);
	exit(0);
}
void time_catch()
{
	if( write(fd,"\0",1) ==	-1) /*	refreshes (or resets) the timer	*/
	{
		print_info("write watchdog device error!\n");
		exit(5);
	}
	alarm(reflash_time);
}

void daemon_init(const char *pname, int facility)
{
	int i;
	pid_t pid;
	int daemon_proc;
	if(pid = fork())
		exit(0);
	setsid();
//	signal(SIGHUP,SIG_IGN);
	if(pid = fork())
		exit(0);
	daemon_proc = 1;
	chdir("/");
	umask(0);
	for(i = 0; i < MAXFD; i++)
	{
        if(i != fd)
            close(i);
	}

}
