#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

#include <fcntl.h>
#include "bcm43xxinject.h"
#include "wtinject.h"

int tx80211_bcm43xx_init(struct tx80211 *in_tx)
{

	in_tx->capabilities = tx80211_bcm43xx_capabilities();
	in_tx->open_callthrough = &bcm43xx_open;
	in_tx->close_callthrough = &bcm43xx_close;
	in_tx->setmode_callthrough = &wtinj_setmode;
	in_tx->getmode_callthrough = &wtinj_getmode;
	in_tx->getchan_callthrough = &wtinj_getchannel;
	in_tx->setchan_callthrough = &wtinj_setchannel;
	in_tx->txpacket_callthrough = &wtinj_send;
	in_tx->setfuncmode_callthrough = &wtinj_setfuncmode;

	return 0;
}

int tx80211_bcm43xx_capabilities()
{
	 return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | 
		 TX80211_CAP_SEQ | TX80211_CAP_BSSTIME |
		 TX80211_CAP_CTRL |
		 TX80211_CAP_DURID | TX80211_CAP_SNIFFACK |
		 TX80211_CAP_DSSSTX | TX80211_CAP_OFDMTX);
}

int bcm43xx_open(struct tx80211 *in_tx)
{
	const char inject_nofcs_pname[] = "/sys/class/net/%s/device/inject_nofcs";
	char *inject_nofcs_location = NULL;
	int nofcs;

	nofcs=-1;

	if (strlen(in_tx->ifname) == 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				 "No interface name\n");
		return -1;
	}

	inject_nofcs_location = (char*) malloc(strlen(in_tx->ifname) +
										   strlen(inject_nofcs_pname) +
										   5); 
	if (inject_nofcs_location==NULL) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				 "Can't allocate memory for inject_nofcs path\n");
		return -1;
	} 

	snprintf(inject_nofcs_location, 
			 strlen(in_tx->ifname) + strlen(inject_nofcs_pname) + 5, 
			 inject_nofcs_pname, in_tx->ifname);

	nofcs = open(inject_nofcs_location, O_WRONLY);
	if (nofcs < 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				 "Error opening file: %s. Is your bcm43xx driver patched?\n",
				 inject_nofcs_location);
	}

	free(inject_nofcs_location);

	if (nofcs<0) return -1;
	else {
		in_tx->raw_fd=nofcs;
		return 0;
	}
}

int bcm43xx_close(struct tx80211 *in_tx)
{
	if (!(in_tx->raw_fd<0)) { int i=close(in_tx->raw_fd); in_tx->raw_fd=-1; return i; }
	return 0;
}

#endif /* linux */

