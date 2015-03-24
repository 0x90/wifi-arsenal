#ifndef _JIGDUMP_H_
#define _JIGDUMP_H_

#define JIGDUMP_HDR_VERSION 0xae
#define JIGDUMP_HDR_SNAPLEN 132 // 802.11 (32) + LLC (8) + IP(88) + FCS (4)
#define JIGDUMP_HDR_SNAPLEN_DHCP 400
#define JIGDUMP_HDR_SNAPLEN_MAX 400
#define JIGDUMP_HDR_F_RX    0x0
#define JIGDUMP_HDR_F_TX    0x1
#define JIGDUMP_HDR_F_MAC_TIME 0x2
#define JIGDUMP_HDR_F_FCS   0x4
#define JIGDUMP_HDR_F_TSF_SLAVE   0x8
#define JIGDUMP_HDR_F_TSF_CARRY 0x10
#define JIGDUMP_HDR_F_PREV_ERRS_OVERFLOW 0x20
#define JIGDUMP_HDR_F_TSF_LEAP   0x40
#define JIGDUMP_HDR_F_MAC_TSC   0x80

struct jigdump_hdr
{
	u_int8_t version_;
	u_int8_t hdrlen_;

	u_int32_t phyerr_;

	int8_t rssi_;
	int flags_;
	u_int8_t channel_;
	int freq_ ;
	u_int16_t rate_;
	u_int32_t rate_idx_;

	u_int16_t caplen_;
	u_int16_t snaplen_;

	u_int8_t antenna_;
} __attribute__ ((packed));


#define JIGBLOCK_MAX_SIZE (16000)

#endif
