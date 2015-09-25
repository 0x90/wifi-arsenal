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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#define MAXFD 64


main(char argc, char *argv[])
{
	int err, kfd;
        char buf;
        fd_set readfds;
        struct timeval tv;
        if(argc != 2)
        {
                printf("Usage:%s <seconds>", argv[0]);
                exit(0);
        }

        FD_ZERO(&readfds);
	kfd = open("/dev/console", O_RDONLY);
	tv.tv_sec = atoi(argv[1]);
        tv.tv_usec = 0;
	system("stty cbreak");
	for(;;)
	{
                FD_SET(kfd, &readfds);
                err = select( kfd + 1, &readfds, NULL, NULL, &tv);
                if(err != 0)
                {
                     if(FD_ISSET(kfd, &readfds))
                     {
                         read(kfd, &buf, 1);
                         if(buf == 'Y' || buf == 'y')
			 {
			     system("stty -cbreak");
                             exit(1);
			 }
                         else if(buf == 'N' || buf == 'n')
                             break;
                         else
                             continue;
                     }
                }/*end if*/
                if(tv.tv_sec == 0)
                    break;
	}
        close(kfd);
	system("stty -cbreak");
        exit(0);
}



