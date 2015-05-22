/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2001-2004  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id: atshell.c,v 1.1.1.1 2005/12/27 14:31:21 bytebeater Exp $
 */

/*
 * Just a little quick hack to get a shell from attest
 * Updated by Bastian Ballmann
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>

static int at_command(int fd, char *cmd, int to)
{
	fd_set rfds;
	struct timeval timeout;
	unsigned char buf[1024];
	int sel, len, i, n;

	write(fd, cmd, strlen(cmd));

	for (i = 0; i < 100; i++) {

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		timeout.tv_sec = 0;
		timeout.tv_usec = to;

		if ((sel = select(fd + 1, &rfds, NULL, NULL, &timeout)) > 0) {

			if (FD_ISSET(fd, &rfds)) {
				memset(buf, 0, sizeof(buf));
				len = read(fd, buf, sizeof(buf));
				for (n = 0; n < len; n++)
					printf("%c", buf[n]);
				if (strstr(buf, "\r\nOK") != NULL)
					break;
				if (strstr(buf, "\r\nERROR") != NULL)
					break;
				if (strstr(buf, "\r\nCONNECT") != NULL)
					break;
			}

		}

	}

	return 0;
}

static int open_device(char *device)
{
	int fd;
	struct termios ti;

	if ((fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK)) < 0) {
		printf("Can't open serial port. %s (%d)\n", strerror(errno), errno);
		return -1;
	}

	tcflush(fd, TCIOFLUSH);

	/* Switch tty to RAW mode */
	cfmakeraw(&ti);
	tcsetattr(fd, TCSANOW, &ti);

	return fd;
}

static int open_socket(bdaddr_t *bdaddr, uint8_t channel, int dev_id)
{
	struct sockaddr_rc remote_addr, local_addr;
        struct hci_dev_info di;
	int s;

	if ((s = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)) < 0) {
		printf("Can't create socket. %s (%d)\n", strerror(errno), errno);
		return -1;
	}

	memset(&local_addr, 0, sizeof(local_addr));

        // Get the bluetooth address of the first local 
        // bluetooth device
        if(hci_devinfo(0, &di) < 0) 
        {
           perror("HCI device info failed");
           exit(1);
        }

	local_addr.rc_family = AF_BLUETOOTH;
        local_addr.rc_bdaddr = di.bdaddr;

	bacpy(&local_addr.rc_bdaddr, BDADDR_ANY);
	if (bind(s, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
		printf("Can't bind socket. %s (%d)\n", strerror(errno), errno);
		close(s);
		return -1;
	}

	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.rc_family = AF_BLUETOOTH;
	bacpy(&remote_addr.rc_bdaddr, bdaddr);
	remote_addr.rc_channel = channel;
	if (connect(s, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0) {
		printf("Can't connect. %s (%d)\n", strerror(errno), errno);
		close(s);
		return -1;
	}

	return s;
}

static void usage(void)
{
	printf("Usage:\n\tattest <device> | <bdaddr> [channel] [hci_dev_nr]\n");
}

int main(int argc, char *argv[])
{
	int fd;
        
	bdaddr_t bdaddr;
	uint8_t channel;

	char *atcmd;
	char prompt[]="at> ";
        int hci_nr = 0;

	switch (argc) {
	case 2:
	  str2ba(argv[1], &bdaddr);
	  channel = 1;
	  break;
	case 3:
	  str2ba(argv[1], &bdaddr);
	  channel = atoi(argv[2]);
	  break;
	case 4:
	  hci_nr = atoi(argv[3]);
	  break;
	default:
	  usage();
	  exit(-1);
	}

	if (bacmp(BDADDR_ANY, &bdaddr)) {
		printf("Connecting to %s on channel %d\n", argv[1], channel);
		fd = open_socket(&bdaddr, channel, hci_nr);
	} else {
		printf("Opening device %s\n", argv[1]);
		fd = open_device(argv[1]);
	}

	if (fd < 0)
		exit(-2);

	at_command(fd, "ATZ\r\n", 10000);

	while(1)
	  {
	    atcmd = readline(prompt);

	    if((!strcmp(atcmd,"exit")) || (!strcmp(atcmd,"quit")))
	      {
		close(fd);
		exit(0);
	      }
	    else
	      {
		strcat(atcmd,"\r\n");
		at_command(fd, atcmd, 100000);
	      }
	  }

	close(fd);
	return 0;
}
