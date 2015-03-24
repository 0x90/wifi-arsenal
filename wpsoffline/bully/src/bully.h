/*
    bully - retrieve WPA/WPA2 passphrase from a WPS-enabled AP

    Copyright (C) 2012  Brian Purcell <purcell.briand@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef _BULLY_H
#define _BULLY_H

#define	EXE_NAME "bully"

typedef struct pcap_pkthdr	phdr_t;
typedef struct wps_config	wpsc_t;
typedef struct wps_data		wpsd_t;  
typedef struct wps_registrar_config wpsr_t;
typedef struct wps_context	wctx_t;
typedef struct wpabuf		wpab_t;

char	*__vp;
#define	__vs 1024
int	__vb = 3;
FILE*	__vf;
#define	vprint(...) { snprintf(__vp,__vs,__VA_ARGS__); if ((__vp[1]=='+'?3:__vp[1]=='!'?2:1)<=__vb) fputs(__vp,__vf); }

char hx[16] = "0123456789abcdef";
#define HEXSZ 2049
char _xbuf[HEXSZ];
char *hex(void *p, int len);

#define MAX_FCS_FAIL	3
#define MAX_RETRIES	2
#define LOCK_WAIT_SECS	43

#define	ACKTIME		25
#define STDTIME		200
#define M13TIME		2000

#define SUCCESS		0
#define FCSFAIL		1
#define INJFAIL		1
#define TIMEOUT		2
#define ACKFAIL		2
#define DEORDIS		3
#define EAPFAIL		4
#define WPSFAIL		5
#define KEY1NAK		6
#define KEY2NAK		7

char *names[] = { "Success",
		"Failure",
		"Timeout",
		"NoAssoc",
		"EAPFail",
		"WPSFail",
		"Pin1Bad",
		"Pin2Bad" };

char *state[] = { "Last State",
		"Rx(Beacon)",
		"Tx(DeAuth)",
		"Tx( Auth )",
		"Rx( Auth )",
		"Tx( Assn )",
		"Rx( Assn )",
		"Tx( Strt )",
		"Rx(  ID  )",
		"Tx(  ID  )",
		"Rx(  M1  )",
		"Tx(  M2  )",
		"Rx(M2D/M3)",
		"Tx(  M4  )",
		"Rx(  M5  )",
		"Tx(  M6  )",
		"Rx(  M7  )" };
#define	START_ASSOC	1
#define	START_EAPOL	7
#define	RECV_M2D_M3	12

int map[17] = {0,0,0,0,0,0,0,0,0,0,4,5,7,8,9,10,11};

#define	PKT_ACK	0
#define	PKT_PR	1
#define	PKT_BEA	2
#define	PKT_AUT	3
#define	PKT_ASN	4
#define	PKT_EID	5
#define	PKT_M1	6
#define	PKT_M3	7
#define	PKT_M5	8
#define	PKT_M7	9
#define	PKT_EAP	10
#define	PKT_NOP	11

struct {
	int	user;
	int	def;
	int	count;
	int	avg;
	int	max;
} times[] = {
	{0,  100,  1,  100,  100},       /* ACK */
	{0,  660,  1, 2650, 2650},       /* PR */
	{0,  660,  1, 2650, 2650},       /* BEA */
	{0,  100,  1,  200,  200},       /* AUT */
	{0,  100,  1,  200,  200},       /* ASN */
	{0,  712,  1, 2850, 2850},       /* EID */
	{0, 8962,  1,35850,35850},       /* M1 */
	{0, 4585,  1,18350,18350},       /* M3 */
	{0,  860,  1, 3450, 3450},       /* M5 */
	{0, 2685,  1,10750,10750},       /* M7 */
	{0,  100,  1,  100,  100},       /* EAP */
	{0,    0,  1,    0,    0},       /* NOP */
};

struct global {
	uint8	*ifname;
	char	*essid;
	char	*ssids;
	uint8	bssid[6];
	char	*smacs;
	uint8	hwmac[6];
	char	*hop;
	char	*warpath;
	char	*runf;
	char	*pinf;
	char	schan[8];
	int8	*index;
	int	*chans;
	int	*freqs;
	int	chanx;
	int	start;
	int	test;
	int	probe;
	int	win7;
	int	eapfail;
	int	eapmode;
	int	eapflag;
	int	restart;
	int	fixed;
	int	force;
	int	random;
	int	suppress;
	int	ignore;
	int	verbose;
	int	has_rth;
	int	has_fcs;
	int	nocheck;
	int	broken;
	int	use_ack;
	int	m57nack;
	int	retries;
	int	acktime;
	int	stdtime;
	int	m13time;
	int	dlt;
	int	sequence;
	int	delay;
	int	k1delay, k1step, k1count;
	int	k2delay, k2step, k2count;
	int	lwait;
	int	detect;
	int	dcount;
	int	state;
	int	pinstart;
	int	pindex;
	int	d1xlnx;
	int	eapidx;
	int	eaplnx;
	int	wfaopx;
	char	*error;
	char	*perr;
	pcap_t	*pfd;
	phdr_t	*phdr;
	frame_t	*inp;
	uint8	*asshat;
	int	assl;
	uint8	*dprobe;
	int	reql;
	wpsd_t	*wdata;
	int16	*pin1;
	int16	*pin2;
};


#define W7_DEVICE_NAME	"Glau"
#define W7_MANUFACTURER	"Microsoft"
#define W7_MODEL_NAME	"Windows"
#define W7_MODEL_NUMBER	"6.1.7601"
#define W7_DEVICE_TYPE	"\x00\x01\x00\x50\xF2\x04\x00\x01"
#define W7_OS_VERSION	"\x01\x00\x06\x00"
#define W7_RF_BANDS	0x01


char usage[] =
"\n"
"  usage: %s <options> interface\n"
"\n"
"  Required arguments:\n"
"\n"
"      interface      : Wireless interface in monitor mode (root required)\n"
"\n"
"      -b, --bssid macaddr    : MAC address of the target access point\n"
"   Or\n"
"      -e, --essid string     : Extended SSID for the access point\n"
"\n"
"  Optional arguments:\n"
"\n"
"      -c, --channel N[,N...] : Channel number of AP, or list to hop [b/g]\n"
"      -i, --index N          : Starting pin index (7 or 8 digits)  [Auto]\n"
"      -l, --lockwait N       : Seconds to wait if the AP locks WPS   [43]\n"
"      -o, --outfile file     : Output file for messages          [stdout]\n"
"      -p, --pin N            : Starting pin number (7 or 8 digits) [Auto]\n"
"      -s, --source macaddr   : Source (hardware) MAC address      [Probe]\n"
"      -v, --verbosity N      : Verbosity level 1-3, 1 is quietest     [3]\n"
"      -w, --workdir path     : Location of pin/session files  [~/.bully/]\n"
"      -5, --5ghz             : Hop on 5GHz a/n default channel list  [No]\n"
"      -B, --bruteforce       : Bruteforce the WPS pin checksum digit [No]\n"
"      -F, --force            : Force continue in spite of warnings   [No]\n"
"      -S, --sequential       : Sequential pins (do not randomize)    [No]\n"
"      -T, --test             : Test mode (do not inject any packets) [No]\n"
"\n"
"  Advanced arguments:\n"
"\n"
"      -a, --acktime N        : Deprecated/ignored                  [Auto]\n"
"      -r, --retries N        : Resend packets N times when not acked  [2]\n"
"      -m, --m13time N        : Deprecated/ignored                  [Auto]\n"
"      -t, --timeout N        : Deprecated/ignored                  [Auto]\n"
"      -1, --pin1delay M,N    : Delay M seconds every Nth nack at M5 [0,1]\n"
"      -2, --pin2delay M,N    : Delay M seconds every Nth nack at M7 [5,1]\n"
"      -A, --noacks           : Disable ACK check for sent packets    [No]\n"
"      -C, --nocheck          : Skip CRC/FCS validation (performance) [No]\n"
"      -D, --detectlock       : Detect WPS lockouts unreported by AP  [No]\n"
"      -E, --eapfail          : EAP Failure terminate every exchange  [No]\n"
"      -L, --lockignore       : Ignore WPS locks reported by the AP   [No]\n"
"      -M, --m57nack          : M5/M7 timeouts treated as WSC_NACK's  [No]\n"
"      -N, --nofcs            : Packets don't contain the FCS field [Auto]\n"
"      -P, --probe            : Use probe request for nonbeaconing AP [No]\n"
"      -R, --radiotap         : Assume radiotap headers are present [Auto]\n"
"      -W, --windows7         : Masquerade as a Windows 7 registrar   [No]\n"
"      -Z, --suppress         : Suppress packet throttling algorithm  [No]\n"
"      -V, --version          : Print version info and exit\n"
"      -h, --help             : Display this help information\n\n%s";


#endif /* _BULLY_H */
