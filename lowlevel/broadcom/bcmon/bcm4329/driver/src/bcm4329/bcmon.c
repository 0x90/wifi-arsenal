#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/module.h>	/* Specifically, a module */
#include <linux/fs.h>
#include <asm/uaccess.h>	/* for get_user and put_user */
#include <osl.h>

#include "bcmon.h"

struct sk_buff* bcmon_decode_skb(struct sk_buff* skb)
{
	char radio_tap_header[15];
	char* data;
	unsigned int data_offset;
	unsigned int pkt_len;
	int rssi;
	char my_byte;

	data = skb->data;
	pkt_len = *(unsigned short*)data;
	skb_trim(skb, pkt_len);
	data_offset = 12+ 0x1e + 6;
	if(pkt_len<24)
		return 0;
	my_byte = data[12+12];
	if ((my_byte==5) || (my_byte==1))
		return 0;
	if (my_byte & 4)
		data_offset += 2;
	rssi = data[0x12];

	((unsigned int*)radio_tap_header)[0] = 0x000f0000; // it_version, it_pad, it_len
	((unsigned int*)radio_tap_header)[1] = 0x2a;
	radio_tap_header[8] = 0x10; // flags: FRAME_INC_FCS
	// TODO: extract frequency from packet
	((unsigned short*)(radio_tap_header+10))[0] = 2437; // frequency
	((unsigned short*)(radio_tap_header+10))[1] = 0x0080; // G2_SPEC
	radio_tap_header[14] = rssi;

	skb_pull(skb,data_offset);
	skb_push(skb,sizeof(radio_tap_header));
	memcpy(skb->data,radio_tap_header,sizeof(radio_tap_header));

	return skb;
}
void bcmon_loaded(void) {
	return;

}
EXPORT_SYMBOL(bcmon_loaded);

