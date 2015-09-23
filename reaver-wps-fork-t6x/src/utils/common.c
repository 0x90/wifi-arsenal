/*
 * wpa_supplicant/hostapd / common helper functions, etc.
 * Copyright (c) 2002-2007, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"

#include "common.h"


static int hex2num(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}


static int hex2byte(const char *hex)
{
    int a, b;
    a = hex2num(*hex++);
    if (a < 0)
        return -1;
    b = hex2num(*hex++);
    if (b < 0)
        return -1;
    return (a << 4) | b;
}


/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, u8 *addr)
{
    int i;

    for (i = 0; i < 6; i++) {
        int a, b;

        a = hex2num(*txt++);
        if (a < 0)
            return -1;
        b = hex2num(*txt++);
        if (b < 0)
            return -1;
        *addr++ = (a << 4) | b;
        if (i < 5 && *txt++ != ':')
            return -1;
    }

    return 0;
}


/**
 * hwaddr_aton2 - Convert ASCII string to MAC address (in any known format)
 * @txt: MAC address as a string (e.g., 00:11:22:33:44:55 or 0011.2233.4455)
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: Characters used (> 0) on success, -1 on failure
 */
int hwaddr_aton2(const char *txt, u8 *addr)
{
    int i;
    const char *pos = txt;

    for (i = 0; i < 6; i++) {
        int a, b;

        while (*pos == ':' || *pos == '.' || *pos == '-')
            pos++;

        a = hex2num(*pos++);
        if (a < 0)
            return -1;
        b = hex2num(*pos++);
        if (b < 0)
            return -1;
        *addr++ = (a << 4) | b;
    }

    return pos - txt;
}


/**
 * hexstr2bin - Convert ASCII hex string into binary data
 * @hex: ASCII hex string (e.g., "01ab")
 * @buf: Buffer for the binary data
 * @len: Length of the text to convert in bytes (of buf); hex will be double
 * this size
 * Returns: 0 on success, -1 on failure (invalid hex string)
 */
int hexstr2bin(const char *hex, u8 *buf, size_t len)
{
    size_t i;
    int a;
    const char *ipos = hex;
    u8 *opos = buf;

    for (i = 0; i < len; i++) {
        a = hex2byte(ipos);
        if (a < 0)
            return -1;
        *opos++ = a;
        ipos += 2;
    }
    return 0;
}


/**
 * inc_byte_array - Increment arbitrary length byte array by one
 * @counter: Pointer to byte array
 * @len: Length of the counter in bytes
 *
 * This function increments the last byte of the counter by one and continues
 * rolling over to more significant bytes if the byte was incremented from
 * 0xff to 0x00.
 */
void inc_byte_array(u8 *counter, size_t len)
{
    int pos = len - 1;
    while (pos >= 0) {
        counter[pos]++;
        if (counter[pos] != 0)
            break;
        pos--;
    }
}


void wpa_get_ntp_timestamp(u8 *buf)
{
    struct os_time now;
    u32 sec, usec;
    be32 tmp;

    /* 64-bit NTP timestamp (time from 1900-01-01 00:00:00) */
    os_get_time(&now);
    sec = now.sec + 2208988800U; /* Epoch to 1900 */
    /* Estimate 2^32/10^6 = 4295 - 1/32 - 1/512 */
    usec = now.usec;
    usec = 4295 * usec - (usec >> 5) - (usec >> 9);
    tmp = host_to_be32(sec);
    os_memcpy(buf, (u8 *) &tmp, 4);
    tmp = host_to_be32(usec);
    os_memcpy(buf + 4, (u8 *) &tmp, 4);
}


static inline int _wpa_snprintf_hex(char *buf, size_t buf_size, const u8 *data,
        size_t len, int uppercase)
{
    size_t i;
    char *pos = buf, *end = buf + buf_size;
    int ret;
    if (buf_size == 0)
        return 0;
    for (i = 0; i < len; i++) {
        ret = os_snprintf(pos, end - pos, uppercase ? "%02X" : "%02x",
                data[i]);
        if (ret < 0 || ret >= end - pos) {
            end[-1] = '\0';
            return pos - buf;
        }
        pos += ret;
    }
    end[-1] = '\0';
    return pos - buf;
}

/**
 * wpa_snprintf_hex - Print data as a hex string into a buffer
 * @buf: Memory area to use as the output buffer
 * @buf_size: Maximum buffer size in bytes (should be at least 2 * len + 1)
 * @data: Data to be printed
 * @len: Length of data in bytes
 * Returns: Number of bytes written
 */
int wpa_snprintf_hex(char *buf, size_t buf_size, const u8 *data, size_t len)
{
    return _wpa_snprintf_hex(buf, buf_size, data, len, 0);
}


/**
 * wpa_snprintf_hex_uppercase - Print data as a upper case hex string into buf
 * @buf: Memory area to use as the output buffer
 * @buf_size: Maximum buffer size in bytes (should be at least 2 * len + 1)
 * @data: Data to be printed
 * @len: Length of data in bytes
 * Returns: Number of bytes written
 */
int wpa_snprintf_hex_uppercase(char *buf, size_t buf_size, const u8 *data,
        size_t len)
{
    return _wpa_snprintf_hex(buf, buf_size, data, len, 1);
}


#ifdef CONFIG_ANSI_C_EXTRA

#ifdef _WIN32_WCE
void perror(const char *s)
{
    wpa_printf(MSG_ERROR, "%s: GetLastError: %d",
            s, (int) GetLastError());
}
#endif /* _WIN32_WCE */


int optind = 1;
int optopt;
char *optarg;

int getopt(int argc, char *const argv[], const char *optstring)
{
    static int optchr = 1;
    char *cp;

    if (optchr == 1) {
        if (optind >= argc) {
            /* all arguments processed */
            return EOF;
        }

        if (argv[optind][0] != '-' || argv[optind][1] == '\0') {
            /* no option characters */
            return EOF;
        }
    }

    if (os_strcmp(argv[optind], "--") == 0) {
        /* no more options */
        optind++;
        return EOF;
    }

    optopt = argv[optind][optchr];
    cp = os_strchr(optstring, optopt);
    if (cp == NULL || optopt == ':') {
        if (argv[optind][++optchr] == '\0') {
            optchr = 1;
            optind++;
        }
        return '?';
    }

    if (cp[1] == ':') {
        /* Argument required */
        optchr = 1;
        if (argv[optind][optchr + 1]) {
            /* No space between option and argument */
            optarg = &argv[optind++][optchr + 1];
        } else if (++optind >= argc) {
            /* option requires an argument */
            return '?';
        } else {
            /* Argument in the next argv */
            optarg = argv[optind++];
        }
    } else {
        /* No argument */
        if (argv[optind][++optchr] == '\0') {
            optchr = 1;
            optind++;
        }
        optarg = NULL;
    }
    return *cp;
}
#endif /* CONFIG_ANSI_C_EXTRA */


#ifdef CONFIG_NATIVE_WINDOWS
/**
 * wpa_unicode2ascii_inplace - Convert unicode string into ASCII
 * @str: Pointer to string to convert
 *
 * This function converts a unicode string to ASCII using the same
 * buffer for output. If UNICODE is not set, the buffer is not
 * modified.
 */
void wpa_unicode2ascii_inplace(TCHAR *str)
{
#ifdef UNICODE
    char *dst = (char *) str;
    while (*str)
        *dst++ = (char) *str++;
    *dst = '\0';
#endif /* UNICODE */
}


TCHAR * wpa_strdup_tchar(const char *str)
{
#ifdef UNICODE
    TCHAR *buf;
    buf = os_malloc((strlen(str) + 1) * sizeof(TCHAR));
    if (buf == NULL)
        return NULL;
    wsprintf(buf, L"%S", str);
    return buf;
#else /* UNICODE */
    return os_strdup(str);
#endif /* UNICODE */
}
#endif /* CONFIG_NATIVE_WINDOWS */


/**
 * wpa_ssid_txt - Convert SSID to a printable string
 * @ssid: SSID (32-octet string)
 * @ssid_len: Length of ssid in octets
 * Returns: Pointer to a printable string
 *
 * This function can be used to convert SSIDs into printable form. In most
 * cases, SSIDs do not use unprintable characters, but IEEE 802.11 standard
 * does not limit the used character set, so anything could be used in an SSID.
 *
 * This function uses a static buffer, so only one call can be used at the
 * time, i.e., this is not re-entrant and the returned buffer must be used
 * before calling this again.
 */
const char * wpa_ssid_txt(const u8 *ssid, size_t ssid_len)
{
    static char ssid_txt[33];
    char *pos;

    if (ssid_len > 32)
        ssid_len = 32;
    os_memcpy(ssid_txt, ssid, ssid_len);
    ssid_txt[ssid_len] = '\0';
    for (pos = ssid_txt; *pos != '\0'; pos++) {
        if ((u8) *pos < 32 || (u8) *pos >= 127)
            *pos = '_';
    }
    return ssid_txt;
}


void * __hide_aliasing_typecast(void *foo)
{
    return foo;
}


/*
 * WPS pin generator for some Belkin routers. Default pin is generated from the
 * BSSID and serial number. BSSIDs are not encrypted and the serial number is
 * included in the WPS information element contained in 802.11 probe response
 * packets.
 *
 * Known to work against:
 *
 *  o F9K1001v4         [Broadcom, Arcadyan, SuperTask!]
 *  o F9K1001v5         [Broadcom, Arcadyan, SuperTask!]
 *  o F9K1002v1         [Realtek, SerComm]
 *  o F9K1002v2         [Ralink, Arcadyan]
 *  o F9K1002v5         [Broadcom, Arcadyan]
 *  o F9K1103v1         [Ralink, Arcadyan, Linux]
 *  o F9K1112v1         [Broadcom, Arcadyan, Linux]
 *  o F9K1113v1         [Broadcom, Arcadyan, Linux]
 *  o F9K1105v1         [Broadcom, Arcadyan, Linux]
 *  o F6D4230-4v2       [Ralink, Arcadyan, Unknown RTOS]
 *  o F6D4230-4v3       [Broadcom, Arcadyan, SuperTask!]
 *  o F7D2301v1         [Ralink, Arcadyan, SuperTask!]
 *  o F7D1301v1         [Broadcom, Arcadyan, Unknown RTOS]
 *  o F5D7234-4v3       [Atheros, Arcadyan, Unknown RTOS]
 *  o F5D7234-4v4       [Atheros, Arcadyan, Unknown RTOS]
 *  o F5D7234-4v5       [Broadcom, Arcadyan, SuperTask!]
 *  o F5D8233-4v1       [Infineon, Arcadyan, SuperTask!]
 *  o F5D8233-4v3       [Ralink, Arcadyan, Unknown RTOS]
 *  o F5D9231-4v1       [Ralink, Arcadyan, SuperTask!]
 *
 * Known to NOT work against:
 *
 *  o F9K1001v1         [Realtek, SerComm, Unknown RTOS]
 *  o F9K1105v2         [Realtek, SerComm, Linux]
 *  o F6D4230-4v1       [Ralink, SerComm, Unknown RTOS]
 *  o F5D9231-4v2       [Ralink, SerComm, Unknown RTOS]
 *  o F5D8233-4v4       [Ralink, SerComm, Unknown RTOS]
 *
 */
/* http://www.devttys0.com/2015/04/reversing-belkins-wps-pin-algorithm/ */


int char2int(char c)
{
    char buf[2] = { 0 };

    buf[0] = c;
    return strtol(buf, NULL, 16);
}
 

/* http://www.devttys0.com/2015/04/reversing-belkins-wps-pin-algorithm/ */
/* Generates a standard WPS checksum from a 7 digit pin */
int wps_checksum(int pin)
{
    int div = 0;

    while(pin)
    {
        div += 3 * (pin % 10);
        pin /= 10;
        div += pin % 10;
        pin /= 10;
    }

    return ((10 - div % 10) % 10);
}

unsigned int hexToInt(const char *hex)
{
	unsigned int result = 0;

	while (*hex)
	{
	if (*hex > 47 && *hex < 58)
	  result += (*hex - 48);
	else if (*hex > 64 && *hex < 71)
	  result += (*hex - 55);
	else if (*hex > 96 && *hex < 103)
	  result += (*hex - 87);

	if (*++hex)
	  result <<= 4;
	}

return result;
}


/* Belkin Default Pin generator created by devttys0 team */
/* http://www.devttys0.com/2015/04/reversing-belkins-wps-pin-algorithm/ */ 
/* Munges the MAC and serial numbers to create a WPS pin */
int pingen_belkin(char *mac, char *serial, int len_serial, int add)
{
    #define NIC_NIBBLE_0    0
    #define NIC_NIBBLE_1    1
    #define NIC_NIBBLE_2    2
    #define NIC_NIBBLE_3    3

    #define SN_DIGIT_0      0
    #define SN_DIGIT_1      1
    #define SN_DIGIT_2      2
    #define SN_DIGIT_3      3

    int sn[4], nic[4];
    int mac_len, serial_len;
    int k1, k2, pin;
    int p1, p2, p3;
    int t1, t2;
    char buff_mac[24];
    int buff_mac_i;

    mac_len = strlen(mac);
    serial_len = len_serial;
	
	//serial[len_serial] = '\0';

    buff_mac_i = hexToInt(mac);
    buff_mac_i = buff_mac_i + add;
    sprintf(buff_mac,"%X",buff_mac_i);

	mac_len = strlen(buff_mac);


    /* Get the four least significant digits of the serial number */
    sn[SN_DIGIT_0] = char2int(serial[serial_len-1]);
    sn[SN_DIGIT_1] = char2int(serial[serial_len-2]);
    sn[SN_DIGIT_2] = char2int(serial[serial_len-3]);
    sn[SN_DIGIT_3] = char2int(serial[serial_len-4]);

    /* Get the four least significant nibbles of the MAC address */
    nic[NIC_NIBBLE_0] = char2int(buff_mac[mac_len-1]);
    nic[NIC_NIBBLE_1] = char2int(buff_mac[mac_len-2]);
    nic[NIC_NIBBLE_2] = char2int(buff_mac[mac_len-3]);
    nic[NIC_NIBBLE_3] = char2int(buff_mac[mac_len-4]);

    k1 = (sn[SN_DIGIT_2] + 
          sn[SN_DIGIT_3] +
          nic[NIC_NIBBLE_0] + 
          nic[NIC_NIBBLE_1]) % 16;

    k2 = (sn[SN_DIGIT_0] +
          sn[SN_DIGIT_1] +
          nic[NIC_NIBBLE_3] +
          nic[NIC_NIBBLE_2]) % 16;

    pin = k1 ^ sn[SN_DIGIT_1];
    
    t1 = k1 ^ sn[SN_DIGIT_0];
    t2 = k2 ^ nic[NIC_NIBBLE_1];
    
    p1 = nic[NIC_NIBBLE_0] ^ sn[SN_DIGIT_1] ^ t1;
    p2 = k2 ^ nic[NIC_NIBBLE_0] ^ t2;
    p3 = k1 ^ sn[SN_DIGIT_2] ^ k2 ^ nic[NIC_NIBBLE_2];
    
    k1 = k1 ^ k2;

    pin = (pin ^ k1) * 16;
    pin = (pin + t1) * 16;
    pin = (pin + p1) * 16;
    pin = (pin + t2) * 16;
    pin = (pin + p2) * 16;
    pin = (pin + k1) * 16;
    pin += p3;
    pin = (pin % 10000000) - (((pin % 10000000) / 10000000) * k1);
	
	//pingen mac init c83a35
	//printf("WPS PIN is: %07d%d\n",4402328%10000000,wps_checksum(4402328%10000000));
    
    return (pin * 10) + wps_checksum(pin);
}


/* 
Calculates the default WPS pin from the BSSID/MAC of many D-Link routers/APs.
Craig Heffner
Tactical Network Solutions 


http://www.devttys0.com/2014/10/reversing-d-links-wps-pin-algorithm/
*/

int pingen_dlink(char *mac, int add)
{
    int nic=0, pin=0;
    char buff[10];

    nic = hexToInt(strncpy(buff, mac+6, sizeof(buff)));
    nic = nic + add;

    pin = nic ^ 0x55AA55;
    pin = pin ^ (((pin & 0x0F) << 4) +
		 ((pin & 0x0F) << 8) +
		 ((pin & 0x0F) << 12) +
		 ((pin & 0x0F) << 16) +
				 ((pin & 0x0F) << 20));
    pin = pin % (int) 10e6;
	
    if (pin < (int) 10e5)
    {
    	pin += ((pin % 9) * (int)10e5) + (int)10e5;
		
    }

    return (pin * 10) + wps_checksum(pin);
}

//Zhaochunsheng algorithm/
int pingen_zhaochunsheng(char *mac, int add)
{
    int default_pin=0, pin=0, i=0, pin_len = 9;
    //char *bssid = mac2str(get_bssid(), ':');
    char *bssid_copy = (char *)malloc(strlen(mac) + 1);
    char *bssid_parts, temp[7] = { 0 };

    strcpy(bssid_copy, mac);
    bssid_parts = strtok(bssid_copy, ":");

    while(bssid_parts)
    {
        if(i > 2)
        {
            strcat(temp, bssid_parts);
        }

        bssid_parts = strtok(NULL, ":");
        ++i;
    }

    temp[6] = '\0';
    sscanf(temp, "%x", &default_pin);
    default_pin = default_pin % 10000000;

    snprintf(pin, pin_len, "%08d", (default_pin * 10) + wps_checksum(default_pin));

    return pin;
}

//mac to decimal by kib0rg
int pingen_zyxel(char *mac, int add)
{
    //pingen make by kib0rg, a little change by t6x
    int pin;

    char mac_address[7] = {0};
 
    sprintf(mac_address, "%c%c%c%c%c%c", mac[6], mac[7], mac[8], mac[9], mac[10], mac[11]);

    pin = (hexToInt(mac_address) + add) % 10000000;

    return (pin * 10) + wps_pin_checksum(pin);
}
