/*
 * AirTap - Wireless Frame Capture
 */

#ifndef _AIRTAP_H_
#define _AIRTAP_H_

#define AT_TYPE_MGMT 0x00
#define AT_TYPE_CNTL 0x04
#define AT_TYPE_DATA 0x08
#define AT_TYPE_ALL  0x0C

#define AT_SUBTYPE_ALL 0xF0

#define AT_MGMT_SUBTYPE_ASSOC_REQ   0x00
#define AT_MGMT_SUBTYPE_ASSOC_RSP   0x10
#define AT_MGMT_SUBTYPE_REASSOC_REQ 0x20
#define AT_MGMT_SUBTYPE_REASSOC_RSP 0x30
#define AT_MGMT_SUBTYPE_PROBE_REQ   0x40
#define AT_MGMT_SUBTYPE_PROBE_RSP   0x50
#define AT_MGMT_SUBTYPE_BEACON      0x80
#define AT_MGMT_SUBTYPE_ATIM        0x90
#define AT_MGMT_SUBTYPE_DISASSOC    0xa0
#define AT_MGMT_SUBTYPE_AUTH        0xb0
#define AT_MGMT_SUBTYPE_DEAUTH      0xc0
#define AT_MGMT_SUBTYPE_ALL         0xF0

/* XXX: CNTL subtypes */
#define AT_CNTL_SUBTYPE_ALL         0xF0

/* XXX: DATA subtypes */
#define AT_DATA_SUBTYPE_DATA        0x00
#define AT_DATA_SUBTYPE_ALL         0xF0

#define AT_DIR_NODS   0x00    /* STA -> STA */
#define AT_DIR_TODS   0x01    /* STA -> AP  */
#define AT_DIR_FROMDS 0x02    /* AP  -> STA */
#define AT_DIR_DSTODS 0x03    /* AP  -> AP  */
#define AT_DIR_ALL    0x03

/*
 * Make our own headers because it's easier than using system
 * dependent ones.
 */

typedef struct p80211item_uint32
{
	u_int32_t		did		__attribute__ ((packed));
	u_int16_t		status	__attribute__ ((packed));
	u_int16_t		len		__attribute__ ((packed));
	u_int32_t		data	__attribute__ ((packed));
} __attribute__ ((packed)) p80211item_uint32_t;

struct at_prism_header {
    u_int32_t              msgcode;
    u_int32_t              msglen;
    u_int8_t               interface[16];
    p80211item_uint32_t    hosttime;
    p80211item_uint32_t    mactime;
    p80211item_uint32_t    channel;
    p80211item_uint32_t    rssi;
    p80211item_uint32_t    sq;
    p80211item_uint32_t    signal;
    p80211item_uint32_t    noise;
    p80211item_uint32_t    rate;
    p80211item_uint32_t    istx;
    p80211item_uint32_t    frmlen;
} __attribute__ ((packed));

struct at_hermes_header {
    u_int16_t    status;
    u_int16_t    reserved[2];
    u_int8_t     silence;
    u_int8_t     signal;
    u_int8_t     rate;
    u_int8_t     reserved2;
    u_int8_t     retry_count;    /* Transmit only */
    u_int8_t     tx_rate;
    u_int16_t    tx_control;     /* Transmit only */
} __attribute__ ((packed));

struct at_wifi_frame {
    u_int16_t    frame_control;
    u_int16_t    duration_id;
    u_int8_t     address1[6];
    u_int8_t     address2[6];
    u_int8_t     address3[6];
    u_int16_t    sequence_control;
} __attribute__ ((packed));

typedef struct at_frame_info {
    u_int32_t    channel;
    u_int32_t    signal;
    u_int32_t    noise;
} at_frame_info_t;

typedef void (*at_hook_t)(const unsigned char* frame,
                          const at_frame_info_t* frame_info);

extern int airtap_open(char* interface_or_file);
extern int airtap_loop(void);

extern void airtap_add_hook(unsigned int type,
                            unsigned int subtype,
                            unsigned int dir,
                            at_hook_t hook);

#endif /* _AIRTAP_H_ */
