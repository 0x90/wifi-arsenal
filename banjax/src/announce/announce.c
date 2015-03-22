#include <arpa/inet.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BEGIN	0x1
#define END		0x2
#define CHANGE	0x3

struct pkt {
	uint8_t type;
	uint8_t val;
};

int
main(int ac, char **av)
{
	static struct option opts[] = {
		{"begin",	no_argument,			0, 'b' },
		{"end",		no_argument,			0, 'e' },
		{"change",	required_argument,	0, 'c' },
		{"port",	   required_argument,	0, 'p' },
		{0,			0,							0, 0 }
	};

	uint8_t val;
	uint16_t port = 5959;
	int c, opt_index, enable = 1;
	struct __attribute__((__packed__)) pkt p;
	bzero(&p, sizeof(p));
	const size_t P_SZ = sizeof(p);
	while((c = getopt_long(ac, av, "bc:ep:", opts, &opt_index)) != -1) {
		switch(c) {
		case 'b':
			p.type = BEGIN;
			p.val = 0;
			break;
		case 'c':
			p.type = CHANGE;
			p.val = strtoul(optarg, NULL, 10);
			break;
		case 'e':
			p.type = END;
			p.val = 0;
			break;
		case 'p':
			port = strtoul(optarg, NULL, 10);
			break;
		}
	}
	if(optind != ac - 1) {
		fprintf(stderr, "usage: announce [opts] <dev>\n");
		exit(EXIT_FAILURE);
	}

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if(-1 == s) {
		perror("socket(AFD_INET, SOCK_DGRAM, 0)");
		exit(EXIT_FAILURE);
	}

	if(-1 == setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, av[optind], strlen(av[optind]) + 1)) {
		perror("setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, av[optind], strlen(optind) + 1)");
		exit(EXIT_FAILURE);
	}

	if(-1 == setsockopt(s, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable))) {
		perror("setsockopt(s, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable))");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_BROADCAST;
	ssize_t sent = sendto(s, &p, sizeof(p), 0, (struct sockaddr*) &addr, sizeof(addr));
	if(-1 == sent) {
		perror("sendto(s, &p, sizeof(p), 0, (struct sockaddr*) &addr, sizeof(addr))");
		exit(EXIT_FAILURE);
	}
	close(s);

	exit(EXIT_SUCCESS);
}
