#include <typedefs.h>
#include <linuxver.h>
#include <osl.h>

#include <proto/ethernet.h>
#include <dngl_stats.h>
#include <bcmutils.h>
#include <dhd.h>
#include <dhd_dbg.h>

#include <linux/fcntl.h>
#include <linux/fs.h>

struct dhd_info;
extern int _dhd_set_mac_address(struct dhd_info *dhd,
					int ifidx, struct ether_addr *addr);

#ifdef SLP_PATH
#define CIDINFO "/opt/etc/.cid.info"
#define PSMINFO "/opt/etc/.psm.info"
#define MACINFO "/opt/etc/.mac.info"
#define	REVINFO "/data/.rev"
#else
#define	REVINFO "/data/.rev"
#define CIDINFO "/data/.cid.info"
#define PSMINFO "/data/.psm.info"
#endif /*SLP_PATH*/

#ifdef READ_MACADDR
int dhd_read_macaddr(struct dhd_info *dhd, struct ether_addr *mac)
{
	struct file *fp      = NULL;
	char macbuffer[18]   = {0};
	mm_segment_t oldfs   = {0};
	char randommac[3]    = {0};
	char buf[18]         = {0};
	char *filepath       = "/efs/wifi/.mac.info";
#ifdef CONFIG_TARGET_LOCALE_VZW
	char *nvfilepath       = "/data/misc/wifi/.nvmac.info";
#else
	char *nvfilepath       = "/data/.nvmac.info";
#endif
	int ret = 0;

		fp = filp_open(filepath, O_RDONLY, 0);
		if (IS_ERR(fp)) {
start_readmac:
			/* File Doesn't Exist. Create and write mac addr.*/
			fp = filp_open(filepath, O_RDWR | O_CREAT, 0666);
			if (IS_ERR(fp)) {
			DHD_ERROR(("[WIFI] %s: File open error\n", filepath));
				return -1;
			}
			oldfs = get_fs();
			set_fs(get_ds());

		/* Generating the Random Bytes for 3 last octects of the MAC address */
			get_random_bytes(randommac, 3);

			sprintf(macbuffer, "%02X:%02X:%02X:%02X:%02X:%02X\n",
					0x00, 0x12, 0x34, randommac[0], randommac[1], randommac[2]);
		DHD_ERROR(("[WIFI]The Random Generated MAC ID: %s\n", macbuffer));

			if (fp->f_mode & FMODE_WRITE) {
			ret = fp->f_op->write(fp, (const char *)macbuffer, sizeof(macbuffer), &fp->f_pos);
				if (ret < 0)
				DHD_ERROR(("[WIFI]MAC address [%s] Failed to write into File: %s\n", macbuffer, filepath));
				else
				DHD_ERROR(("[WIFI]MAC address [%s] written into File: %s\n", macbuffer, filepath));
			}
			set_fs(oldfs);
		/* Reading the MAC Address from .mac.info file( the existed file or just created file)*/
		ret = kernel_read(fp, 0, buf, 18);
	} else {
		/* Reading the MAC Address from .mac.info file( the existed file or just created file)*/
		ret = kernel_read(fp, 0, buf, 18);
/* to prevent abnormal string display when mac address is displayed on the screen. */
		buf[17] = '\0';
		DHD_ERROR(("Read MAC : [%s] [%d] \r\n" , buf, strncmp(buf , "00:00:00:00:00:00" , 17)));
		if (strncmp(buf , "00:00:00:00:00:00" , 17) < 1) {
			DHD_ERROR(("goto start_readmac \r\n"));
			filp_close(fp, NULL);
			goto start_readmac;
		}
	}

	if (ret)
		sscanf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
			   (unsigned int *)&(mac->octet[0]), (unsigned int *)&(mac->octet[1]),
			   (unsigned int *)&(mac->octet[2]), (unsigned int *)&(mac->octet[3]),
			   (unsigned int *)&(mac->octet[4]), (unsigned int *)&(mac->octet[5]));
	else
		DHD_ERROR(("dhd_bus_start: Reading from the '%s' returns 0 bytes\n", filepath));

	if (fp)
		filp_close(fp, NULL);

	/* Writing Newly generated MAC ID to the Dongle */
	if (0 == _dhd_set_mac_address(dhd, 0, mac))
		DHD_INFO(("dhd_bus_start: MACID is overwritten\n"));
	else
		DHD_ERROR(("dhd_bus_start: _dhd_set_mac_address() failed\n"));

	return 0;
}
#endif /* READ_MACADDR */

#ifdef RDWR_MACADDR
static int g_imac_flag;

enum {
	MACADDR_NONE = 0 ,
	MACADDR_MOD,
	MACADDR_MOD_RANDOM,
	MACADDR_MOD_NONE,
	MACADDR_COB,
	MACADDR_COB_RANDOM
};

int dhd_write_rdwr_macaddr(struct ether_addr *mac)
{
	char *filepath_old = "/data/.mac.info";
	char *filepath = "/efs/wifi/.mac.info";
	struct file *fp_mac = NULL;
	char buf[18]      = {0};
	mm_segment_t oldfs    = {0};
	int ret = -1;

	if ((g_imac_flag != MACADDR_COB) && (g_imac_flag != MACADDR_MOD))
		return 0;

	sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X\n",
			mac->octet[0], mac->octet[1], mac->octet[2],
			mac->octet[3], mac->octet[4], mac->octet[5]);

	/* /data/.mac.info will be created */
	fp_mac = filp_open(filepath_old, O_RDWR | O_CREAT, 0666);
	if (IS_ERR(fp_mac)) {
		DHD_ERROR(("[WIFI] %s: File open error\n", filepath_old));
		return -1;
	}	else {
		oldfs = get_fs();
		set_fs(get_ds());

		if (fp_mac->f_mode & FMODE_WRITE) {
			ret = fp_mac->f_op->write(fp_mac, (const char *)buf,
				sizeof(buf), &fp_mac->f_pos);
			if (ret < 0)
				DHD_ERROR(("[WIFI] Mac address [%s] Failed"
				" to write into File: %s\n", buf, filepath_old));
			else
				DHD_INFO(("[WIFI] Mac address [%s] written"
				" into File: %s\n", buf, filepath_old));
		}
		set_fs(oldfs);
		filp_close(fp_mac, NULL);
	}
	/* /efs/wifi/.mac.info will be created */
	fp_mac = filp_open(filepath, O_RDWR | O_CREAT, 0666);
	if (IS_ERR(fp_mac)) {
		DHD_ERROR(("[WIFI] %s: File open error\n", filepath));
		return -1;
	}	else {
		oldfs = get_fs();
		set_fs(get_ds());

		if (fp_mac->f_mode & FMODE_WRITE) {
			ret = fp_mac->f_op->write(fp_mac, (const char *)buf,
				sizeof(buf), &fp_mac->f_pos);
			if (ret < 0)
				DHD_ERROR(("[WIFI] Mac address [%s] Failed"
				" to write into File: %s\n", buf, filepath));
			else
				DHD_INFO(("[WIFI] Mac address [%s] written"
				" into File: %s\n", buf, filepath));
		}
		set_fs(oldfs);
		filp_close(fp_mac, NULL);
	}

	return 0;

}

int dhd_check_rdwr_macaddr(struct dhd_info *dhd, dhd_pub_t *dhdp,
		struct ether_addr *mac)
{
	struct file *fp_mac = NULL;
	struct file *fp_nvm = NULL;
	char macbuffer[18]    = {0};
	char randommac[3]   = {0};
	char buf[18]      = {0};
	char *filepath_old      = "/data/.mac.info";
	char *filepath      = "/efs/wifi/.mac.info";
#ifdef CONFIG_TARGET_LOCALE_NA
	char *nvfilepath       = "/data/misc/wifi/.nvmac.info";
#else
	char *nvfilepath = "/data/.nvmac.info";
#endif
	char cur_mac[128]   = {0};
	char dummy_mac[ETHER_ADDR_LEN] = {0x00, 0x90, 0x4C, 0xC5, 0x12, 0x38};
	char cur_macbuffer[18]  = {0};
	int ret = -1;

	g_imac_flag = MACADDR_NONE;

	fp_nvm = filp_open(nvfilepath, O_RDONLY, 0);
	if (IS_ERR(fp_nvm)) { /* file does not exist */

		/* Create the .nvmac.info */
		fp_nvm = filp_open(nvfilepath, O_RDWR | O_CREAT, 0666);
		if (!IS_ERR(fp_nvm))
			filp_close(fp_nvm, NULL);

		/* read MAC Address */
		strcpy(cur_mac, "cur_etheraddr");
		ret = dhd_wl_ioctl_cmd(dhdp, WLC_GET_VAR, cur_mac,
				sizeof(cur_mac), 0, 0);
		if (ret < 0) {
			DHD_ERROR(("Current READ MAC error \r\n"));
			memset(cur_mac , 0 , ETHER_ADDR_LEN);
			return -1;
		} else {
			DHD_ERROR(("MAC (OTP) : "
			"[%02X:%02X:%02X:%02X:%02X:%02X] \r\n",
			cur_mac[0], cur_mac[1], cur_mac[2], cur_mac[3],
			cur_mac[4], cur_mac[5]));
		}

		sprintf(cur_macbuffer, "%02X:%02X:%02X:%02X:%02X:%02X\n",
			cur_mac[0], cur_mac[1], cur_mac[2],
			cur_mac[3], cur_mac[4], cur_mac[5]);

		fp_mac = filp_open(filepath_old, O_RDONLY, 0);
		if (IS_ERR(fp_mac)) { /* file does not exist */
			/* read mac is the dummy mac (00:90:4C:C5:12:38) */
			if (memcmp(cur_mac, dummy_mac, ETHER_ADDR_LEN) == 0)
				g_imac_flag = MACADDR_MOD_RANDOM;
			else if (strncmp(buf, "00:00:00:00:00:00", 17) == 0)
				g_imac_flag = MACADDR_MOD_RANDOM;
			else
				g_imac_flag = MACADDR_MOD;
		} else {
			int is_zeromac;

			ret = kernel_read(fp_mac, 0, buf, 18);
			filp_close(fp_mac, NULL);
			buf[17] = '\0';

			is_zeromac = strncmp(buf, "00:00:00:00:00:00", 17);
			DHD_ERROR(("MAC (FILE): [%s] [%d] \r\n",
				buf, is_zeromac));

			if (is_zeromac == 0) {
				DHD_ERROR(("Zero MAC detected."
					" Trying Random MAC.\n"));
				g_imac_flag = MACADDR_MOD_RANDOM;
			} else {
				sscanf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
					(unsigned int *)&(mac->octet[0]),
					(unsigned int *)&(mac->octet[1]),
					(unsigned int *)&(mac->octet[2]),
					(unsigned int *)&(mac->octet[3]),
					(unsigned int *)&(mac->octet[4]),
					(unsigned int *)&(mac->octet[5]));
			/* current MAC address is same as previous one */
				if(memcmp(cur_mac,mac->octet,ETHER_ADDR_LEN) == 0) {
					g_imac_flag = MACADDR_NONE;
				} else { /* change MAC address */
					if (0 == _dhd_set_mac_address(dhd, 0, mac)) {
						DHD_INFO(("%s: MACID is"
						" overwritten\n", __FUNCTION__));
						g_imac_flag = MACADDR_MOD;
					} else {
						DHD_ERROR(("%s: "
						"_dhd_set_mac_address()"
						" failed\n", __FUNCTION__));
						g_imac_flag = MACADDR_NONE;
					}
				}
			}
		}
		fp_mac = filp_open(filepath, O_RDONLY, 0);
		if (IS_ERR(fp_mac)) { /* file does not exist */
			/* read mac is the dummy mac (00:90:4C:C5:12:38) */
			if (memcmp(cur_mac, dummy_mac, ETHER_ADDR_LEN) == 0)
				g_imac_flag = MACADDR_MOD_RANDOM;
			else if (strncmp(buf, "00:00:00:00:00:00", 17) == 0)
				g_imac_flag = MACADDR_MOD_RANDOM;
			else
				g_imac_flag = MACADDR_MOD;
		} else {
			int is_zeromac;

			ret = kernel_read(fp_mac, 0, buf, 18);
			filp_close(fp_mac, NULL);
			buf[17] = '\0';

			is_zeromac = strncmp(buf, "00:00:00:00:00:00", 17);
			DHD_ERROR(("MAC (FILE): [%s] [%d] \r\n",
				buf, is_zeromac));

			if (is_zeromac == 0) {
				DHD_ERROR(("Zero MAC detected."
					" Trying Random MAC.\n"));
				g_imac_flag = MACADDR_MOD_RANDOM;
			} else {
				sscanf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
					(unsigned int *)&(mac->octet[0]),
					(unsigned int *)&(mac->octet[1]),
					(unsigned int *)&(mac->octet[2]),
					(unsigned int *)&(mac->octet[3]),
					(unsigned int *)&(mac->octet[4]),
					(unsigned int *)&(mac->octet[5]));
			/* current MAC address is same as previous one */
				if(memcmp(cur_mac,mac->octet,ETHER_ADDR_LEN) == 0) {
					g_imac_flag = MACADDR_NONE;
				} else { /* change MAC address */
					if (0 == _dhd_set_mac_address(dhd, 0, mac)) {
						DHD_INFO(("%s: MACID is"
						" overwritten\n", __FUNCTION__));
						g_imac_flag = MACADDR_MOD;
					} else {
						DHD_ERROR(("%s: "
						"_dhd_set_mac_address()"
						" failed\n", __FUNCTION__));
						g_imac_flag = MACADDR_NONE;
					}
				}
			}
		}
	} else {
		/* COB type. only COB. */
		/* Reading the MAC Address from .nvmac.info file
		 * (the existed file or just created file)
		 */
		ret = kernel_read(fp_nvm, 0, buf, 18);

		/* to prevent abnormal string display when mac address
		 * is displayed on the screen.
		 */
		buf[17] = '\0';
		DHD_ERROR(("Read MAC : [%s] [%d] \r\n", buf,
			strncmp(buf, "00:00:00:00:00:00", 17)));
		if ((buf[0] == '\0') ||
			(strncmp(buf, "00:00:00:00:00:00", 17) == 0)) {
			g_imac_flag = MACADDR_COB_RANDOM;
		} else {
			sscanf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
				(unsigned int *)&(mac->octet[0]),
				(unsigned int *)&(mac->octet[1]),
				(unsigned int *)&(mac->octet[2]),
				(unsigned int *)&(mac->octet[3]),
				(unsigned int *)&(mac->octet[4]),
				(unsigned int *)&(mac->octet[5]));
			/* Writing Newly generated MAC ID to the Dongle */
			if (0 == _dhd_set_mac_address(dhd, 0, mac)) {
				DHD_INFO(("%s: MACID is overwritten\n",
					__FUNCTION__));
				g_imac_flag = MACADDR_COB;
			} else {
				DHD_ERROR(("%s: _dhd_set_mac_address()"
					" failed\n", __FUNCTION__));
			}
		}
		filp_close(fp_nvm, NULL);
	}

	if ((g_imac_flag == MACADDR_COB_RANDOM) ||
	    (g_imac_flag == MACADDR_MOD_RANDOM)) {
		get_random_bytes(randommac, 3);
		sprintf(macbuffer, "%02X:%02X:%02X:%02X:%02X:%02X\n",
			0x60, 0xd0, 0xa9, randommac[0], randommac[1],
			randommac[2]);
		DHD_ERROR(("[WIFI] The Random Generated MAC ID : %s\n",
			macbuffer));
		sscanf(macbuffer, "%02X:%02X:%02X:%02X:%02X:%02X",
			(unsigned int *)&(mac->octet[0]),
			(unsigned int *)&(mac->octet[1]),
			(unsigned int *)&(mac->octet[2]),
			(unsigned int *)&(mac->octet[3]),
			(unsigned int *)&(mac->octet[4]),
			(unsigned int *)&(mac->octet[5]));
		if (0 == _dhd_set_mac_address(dhd, 0, mac)) {
			DHD_INFO(("%s: MACID is overwritten\n", __FUNCTION__));
			g_imac_flag = MACADDR_COB;
		} else {
			DHD_ERROR(("%s: _dhd_set_mac_address() failed\n",
				__FUNCTION__));
		}
	}

	return 0;
}
#endif /* RDWR_MACADDR */

#ifdef RDWR_KORICS_MACADDR
int dhd_write_rdwr_korics_macaddr(struct dhd_info *dhd, struct ether_addr *mac)
{
	struct file *fp      = NULL;
	char macbuffer[18]   = {0};
	mm_segment_t oldfs   = {0};
	char randommac[3]    = {0};
	char buf[18]         = {0};
	char *filepath       = "/efs/wifi/.mac.info";
	int is_zeromac       = 0;
	int ret = 0;
	/* MAC address copied from efs/wifi.mac.info */
	fp = filp_open(filepath, O_RDONLY, 0);

	if (IS_ERR(fp)) {
		/* File Doesn't Exist. Create and write mac addr.*/
		fp = filp_open(filepath, O_RDWR | O_CREAT, 0666);
		if (IS_ERR(fp)) {
			DHD_ERROR(("[WIFI] %s: File open error\n",
				filepath));
			return -1;
		}

		oldfs = get_fs();
		set_fs(get_ds());

		/* Generating the Random Bytes for
		 * 3 last octects of the MAC address
		 */
		get_random_bytes(randommac, 3);

		sprintf(macbuffer, "%02X:%02X:%02X:%02X:%02X:%02X\n",
				0x60, 0xd0, 0xa9, randommac[0],
				randommac[1], randommac[2]);
		DHD_ERROR(("[WIFI] The Random Generated MAC ID : %s\n",
				macbuffer));

		if (fp->f_mode & FMODE_WRITE) {
			ret = fp->f_op->write(fp,
				(const char *)macbuffer,
					sizeof(macbuffer), &fp->f_pos);
			if (ret < 0)
				DHD_ERROR(("[WIFI] Mac address [%s]"
					" Failed to write into File:"
					" %s\n", macbuffer, filepath));
			else
				DHD_ERROR(("[WIFI] Mac address [%s]"
					" written into File: %s\n",
					macbuffer, filepath));
		}
		set_fs(oldfs);
	} else {
	/* Reading the MAC Address from .mac.info file
	 * (the existed file or just created file)
	 */
	    ret = kernel_read(fp, 0, buf, 18);
		/* to prevent abnormal string display when mac address
		 * is displayed on the screen.
		 */
		buf[17] = '\0';
		/* Remove security log */
		/*DHD_ERROR(("Read MAC : [%s] [%d] \r\n", buf,
			strncmp(buf, "00:00:00:00:00:00", 17)));*/
		if ((buf[0] == '\0') ||
			(strncmp(buf, "00:00:00:00:00:00", 17) == 0)) {
			is_zeromac = 1;
		}
	}

	if (ret)
		sscanf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
			(unsigned int *)&(mac->octet[0]),
			(unsigned int *)&(mac->octet[1]),
			(unsigned int *)&(mac->octet[2]),
			(unsigned int *)&(mac->octet[3]),
			(unsigned int *)&(mac->octet[4]),
			(unsigned int *)&(mac->octet[5]));
	else
		DHD_INFO(("dhd_bus_start: Reading from the"
			" '%s' returns 0 bytes\n", filepath));

	if (fp)
		filp_close(fp, NULL);

	if (!is_zeromac) {
		/* Writing Newly generated MAC ID to the Dongle */
		if (0 == _dhd_set_mac_address(dhd, 0, mac))
			DHD_INFO(("dhd_bus_start: MACID is overwritten\n"));
		else
			DHD_ERROR(("dhd_bus_start: _dhd_set_mac_address() "
				"failed\n"));
	} else {
		DHD_ERROR(("dhd_bus_start:Is ZeroMAC BypassWrite.mac.info!\n"));
	}

	return 0;
}
#endif /* RDWR_KORICS_MACADDR */

#ifdef USE_CID_CHECK
static int dhd_write_cid_file(const char *filepath, const char *buf, int buf_len)
{
	struct file *fp = NULL;
	mm_segment_t oldfs = {0};
	int ret = 0;

	/* File is always created.*/
	fp = filp_open(filepath, O_RDWR | O_CREAT, 0666);
	if (IS_ERR(fp)) {
		DHD_ERROR(("[WIFI] %s: File open error\n", filepath));
		return -1;
	} else {
		oldfs = get_fs();
		set_fs(get_ds());

		if (fp->f_mode & FMODE_WRITE) {
			ret = fp->f_op->write(fp, buf, buf_len, &fp->f_pos);
			if (ret < 0)
				DHD_ERROR(("[WIFI] Failed to write CIS[%s]"
					" into '%s'\n", buf, filepath));
			else
				DHD_ERROR(("[WIFI] CID [%s] written into"
					" '%s'\n", buf, filepath));
		}
		set_fs(oldfs);
	}
	filp_close(fp, NULL);

	return 0;
}

#ifdef DUMP_CIS
static void dhd_dump_cis(const unsigned char *buf, int size)
{
	int i;
	for (i = 0; i < size; i++) {
		DHD_ERROR(("%02X ", buf[i]));
		if ((i % 15) == 15) DHD_ERROR(("\n"));
	}
	DHD_ERROR(("\n"));
}
#endif /* DUMP_CIS */

#ifdef BCM4334_CHIP
#define CIS_CID_OFFSET 43
#else
#define CIS_CID_OFFSET 31
#endif /* BCM4334_CHIP */

int dhd_check_module_cid(dhd_pub_t *dhd)
{
	int ret = -1;
#ifdef BCM4334_CHIP
	unsigned char cis_buf[250] = {0};
	const char *revfilepath = REVINFO;
	int flag_b3 = 0;
#else
	unsigned char cis_buf[128] = {0};
#endif
	const char *cidfilepath = CIDINFO;

	/* Try reading out from CIS */
	cis_rw_t *cish = (cis_rw_t *)&cis_buf[8];

	cish->source = 0;
	cish->byteoff = 0;
	cish->nbytes = sizeof(cis_buf);

	strcpy(cis_buf, "cisdump");
	ret = dhd_wl_ioctl_cmd(dhd, WLC_GET_VAR, cis_buf,
				sizeof(cis_buf), 0, 0);
	if (ret < 0) {
		DHD_ERROR(("%s: CIS reading failed, err=%d\n",
			__FUNCTION__, ret));
		return ret;
	} else {
#ifdef BCM4334_CHIP
		unsigned char semco_id[4] = {0x00, 0x00, 0x33, 0x33};
		unsigned char semco_id_sh[4] = {0x00, 0x00, 0xFB, 0x50};	//for SHARP FEM(new)
		DHD_ERROR(("%s: CIS reading success, err=%d\n",
			__FUNCTION__, ret));
#ifdef DUMP_CIS
		dump_cis(cis_buf, 48);
#endif
		if (memcmp(&cis_buf[CIS_CID_OFFSET], semco_id, 4) == 0) {
			DHD_ERROR(("CID MATCH FOUND : Semco, 0x%02X 0x%02X \
			0x%02X 0x%02X\n", cis_buf[CIS_CID_OFFSET],
			cis_buf[CIS_CID_OFFSET+1], cis_buf[CIS_CID_OFFSET+2],
			cis_buf[CIS_CID_OFFSET+3]));
			dhd_write_cid_file(cidfilepath, "semco", 5);
		} else if (memcmp(&cis_buf[CIS_CID_OFFSET], semco_id_sh, 4) == 0) {
			DHD_ERROR(("CIS MATCH FOUND : Semco_sh, 0x%02X 0x%02X \
			0x%02X 0x%02X\n", cis_buf[CIS_CID_OFFSET],
			cis_buf[CIS_CID_OFFSET+1], cis_buf[CIS_CID_OFFSET+2],
			cis_buf[CIS_CID_OFFSET+3]));
			dhd_write_cid_file(cidfilepath, "semcosh", 7);
		} else {
			DHD_ERROR(("CID MATCH FOUND : Murata, 0x%02X 0x%02X \
			0x%02X 0x%02X\n", cis_buf[CIS_CID_OFFSET],
			cis_buf[CIS_CID_OFFSET+1], cis_buf[CIS_CID_OFFSET+2],
			cis_buf[CIS_CID_OFFSET+3]));
			dhd_write_cid_file(cidfilepath, "murata", 6);
		}

		/* Try reading out from OTP to distinguish B2 or B3 */
		memset(cis_buf, 0, sizeof(cis_buf));
		cish = (cis_rw_t *)&cis_buf[8];

		cish->source = 0;
		cish->byteoff = 0;
		cish->nbytes = sizeof(cis_buf);

		strcpy(cis_buf, "otpdump");
		ret = dhd_wl_ioctl_cmd(dhd, WLC_GET_VAR, cis_buf,
					sizeof(cis_buf), 0, 0);
		if (ret < 0) {
			DHD_ERROR(("%s: OTP reading failed, err=%d\n",
				__FUNCTION__, ret));
			return ret;
		}

		/* otp 33th character is identifier for 4334B3 */
		cis_buf[34] = '\0';
		flag_b3 = bcm_atoi(&cis_buf[33]);
		if(flag_b3 & 0x1){
			DHD_ERROR(("REV MATCH FOUND : 4334B3, %c\n", cis_buf[33]));
			dhd_write_cid_file(revfilepath, "4334B3", 6);
		}

#else /* BCM4330_CHIP */
		unsigned char murata_id[4] = {0x80, 0x06, 0x81, 0x00};
		unsigned char semco_ve[4] = {0x80, 0x02, 0x81, 0x99};
#ifdef DUMP_CIS
		dhd_dump_cis(cis_buf, 48);
#endif
		if (memcmp(&cis_buf[CIS_CID_OFFSET], murata_id, 4) == 0) {
			DHD_ERROR(("CID MATCH FOUND : Murata\n"));
			dhd_write_cid_file(cidfilepath, "murata", 6);
		} else if (memcmp(&cis_buf[CIS_CID_OFFSET], semco_ve, 4)
			== 0) {
			DHD_ERROR(("CID MATCH FOUND : Semco VE\n"));
			dhd_write_cid_file(cidfilepath, "semcove", 7);
		} else {
			DHD_ERROR(("CID MISMATCH"
				" 0x%02X 0x%02X 0x%02X 0x%02X\n",
				cis_buf[CIS_CID_OFFSET],
				cis_buf[CIS_CID_OFFSET + 1],
				cis_buf[CIS_CID_OFFSET + 2],
				cis_buf[CIS_CID_OFFSET + 3]));
			dhd_write_cid_file(cidfilepath, "samsung", 7);
		}
#endif /* BCM4334_CHIP */
		DHD_ERROR(("%s: CIS write success, err=%d\n",
			__FUNCTION__, ret));
	}

	return ret;
}
#endif /* USE_CID_CHECK */

#ifdef GET_MAC_FROM_OTP
static int dhd_write_mac_file(const char *filepath, const char *buf, int buf_len)
{
	struct file *fp = NULL;
	mm_segment_t oldfs = {0};
	int ret = 0;

	fp = filp_open(filepath, O_RDWR | O_CREAT, 0666);
	/*File is always created.*/
	if (IS_ERR(fp)) {
		DHD_ERROR(("[WIFI] %s: File open error\n", filepath));
		return -1;
	} else {
		oldfs = get_fs();
		set_fs(get_ds());

		if (fp->f_mode & FMODE_WRITE) {
			ret = fp->f_op->write(fp, buf, buf_len, &fp->f_pos);
			if (ret < 0)
				DHD_ERROR(("[WIFI] Failed to write CIS[%s]\
into '%s'\n", buf, filepath));
			else
				DHD_ERROR(("[WIFI] MAC [%s] written\
into '%s'\n", buf, filepath));
		}
		set_fs(oldfs);
	}
	filp_close(fp, NULL);

	return 0;
}

#define CIS_MAC_OFFSET 33

int dhd_check_module_mac(dhd_pub_t *dhd)
{
	int ret = -1;
	unsigned char cis_buf[250] = {0};
	unsigned char mac_buf[20] = {0};
	const char *macfilepath = "/efs/wifi/.mac.info";

	/* Try reading out from CIS */
	cis_rw_t *cish = (cis_rw_t *)&cis_buf[8];
	struct file *fp_mac = NULL;

	fp_mac = filp_open(macfilepath, O_RDONLY, 0);
	if (!IS_ERR(fp_mac)) {
		kernel_read(fp_mac, fp_mac->f_pos, mac_buf, sizeof(mac_buf));
		DHD_ERROR(("[WIFI].mac.info file already exist : [%s]\n",
			mac_buf));
		return 0;
	}
	cish->source = 0;
	cish->byteoff = 0;
	cish->nbytes = sizeof(cis_buf);

	strcpy(cis_buf, "cisdump");
	ret = dhd_wl_ioctl_cmd(dhd, WLC_GET_VAR, cis_buf,
		sizeof(cis_buf), 0, 0);
	if (ret < 0) {
		DHD_ERROR(("%s: CIS reading failed, err=%d\n", __func__,
			ret));
	} else {
		unsigned char mac_id[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#ifdef DUMP_CIS
		dump_cis(cis_buf, 48);
#endif
		mac_id[0] = cis_buf[CIS_MAC_OFFSET];
		mac_id[1] = cis_buf[CIS_MAC_OFFSET + 1];
		mac_id[2] = cis_buf[CIS_MAC_OFFSET + 2];
		mac_id[3] = cis_buf[CIS_MAC_OFFSET + 3];
		mac_id[4] = cis_buf[CIS_MAC_OFFSET + 4];
		mac_id[5] = cis_buf[CIS_MAC_OFFSET + 5];

		sprintf(mac_buf, "%02X:%02X:%02X:%02X:%02X:%02X\n",
			mac_id[0], mac_id[1], mac_id[2], mac_id[3], mac_id[4],
			mac_id[5]);
		DHD_ERROR(("[WIFI]mac_id is setted from OTP: [%s]\n", mac_buf));
		dhd_write_mac_file(macfilepath, mac_buf, sizeof(mac_buf));
	}

	return ret;
}
#endif /* GET_MAC_FROM_OTP */

#ifdef WRITE_MACADDR
int dhd_write_macaddr(struct ether_addr *mac)
{
    char *filepath_old      = "/data/.mac.info";
    char *filepath      = "/efs/wifi/.mac.info";

	struct file *fp_mac = NULL;
	char buf[18]      = {0};
	mm_segment_t oldfs    = {0};
	int ret = -1;
	int retry_count = 0;

startwrite:

	sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X\n",
			mac->octet[0], mac->octet[1], mac->octet[2],
			mac->octet[3], mac->octet[4], mac->octet[5]);

	/* File will be created /data/.mac.info. */
	fp_mac = filp_open(filepath_old, O_RDWR | O_CREAT, 0666);

	if (IS_ERR(fp_mac)) {
		DHD_ERROR(("[WIFI] %s: File open error\n", filepath_old));
		return -1;
	} else {
		oldfs = get_fs();
		set_fs(get_ds());

		if (fp_mac->f_mode & FMODE_WRITE) {
			ret = fp_mac->f_op->write(fp_mac, (const char *)buf,
				sizeof(buf), &fp_mac->f_pos);
			if (ret < 0)
				DHD_ERROR(("[WIFI] Mac address [%s] Failed to"
				" write into File: %s\n", buf, filepath_old));
			else
				DHD_INFO(("[WIFI] Mac address [%s] written"
				" into File: %s\n", buf, filepath_old));
		}
		set_fs(oldfs);
		filp_close(fp_mac, NULL);
	}
	/* check .mac.info file is 0 byte */
	fp_mac = filp_open(filepath_old, O_RDONLY, 0);
	ret = kernel_read(fp_mac, 0, buf, 18);

	if ((ret == 0) && (retry_count++ < 3)) {
		filp_close(fp_mac, NULL);
		goto startwrite;
	}

	filp_close(fp_mac, NULL);
	/* end of /data/.mac.info */

	/* File will be created /efs/wifi/.mac.info. */
	fp_mac = filp_open(filepath, O_RDWR | O_CREAT, 0666);

	if (IS_ERR(fp_mac)) {
		DHD_ERROR(("[WIFI] %s: File open error\n", filepath));
		return -1;
	} else {
		oldfs = get_fs();
		set_fs(get_ds());

		if (fp_mac->f_mode & FMODE_WRITE) {
			ret = fp_mac->f_op->write(fp_mac, (const char *)buf,
				sizeof(buf), &fp_mac->f_pos);
			if (ret < 0)
				DHD_ERROR(("[WIFI] Mac address [%s] Failed to"
				" write into File: %s\n", buf, filepath));
			else
				DHD_INFO(("[WIFI] Mac address [%s] written"
				" into File: %s\n", buf, filepath));
		}
		set_fs(oldfs);
		filp_close(fp_mac, NULL);
	}

	/* check .mac.info file is 0 byte */
	fp_mac = filp_open(filepath, O_RDONLY, 0);
	ret = kernel_read(fp_mac, 0, buf, 18);

	if ((ret == 0) && (retry_count++ < 3)) {
		filp_close(fp_mac, NULL);
		goto startwrite;
	}

	filp_close(fp_mac, NULL);

	return 0;
}
#endif /* WRITE_MACADDR */

#ifdef CONFIG_CONTROL_PM
extern bool g_pm_control;
void sec_control_pm(dhd_pub_t *dhd, uint *power_mode)
{
	struct file *fp = NULL;
	char *filepath = PSMINFO;
	mm_segment_t oldfs = {0};
	char power_val = 0;
	char iovbuf[WL_EVENTING_MASK_LEN + 12];

	g_pm_control = FALSE;

	fp = filp_open(filepath, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		/* Enable PowerSave Mode */
		dhd_wl_ioctl_cmd(dhd, WLC_SET_PM, (char *)power_mode,
			sizeof(uint), TRUE, 0);

		fp = filp_open(filepath, O_RDWR | O_CREAT, 0666);
		if (IS_ERR(fp) || (fp == NULL)) {
			DHD_ERROR(("[%s, %d] /data/.psm.info open failed\n",
				__FUNCTION__, __LINE__));
			return;
		} else {
			oldfs = get_fs();
			set_fs(get_ds());

			if (fp->f_mode & FMODE_WRITE) {
				power_val = '1';
				fp->f_op->write(fp, (const char *)&power_val,
					sizeof(char), &fp->f_pos);
			}
			set_fs(oldfs);
		}
	} else {
		kernel_read(fp, fp->f_pos, &power_val, 1);
		DHD_ERROR(("POWER_VAL = %c \r\n" , power_val));

		if (power_val == '0') {
#ifdef ROAM_ENABLE
			uint roamvar = 1;
#endif
			*power_mode = PM_OFF;
			/* Disable PowerSave Mode */
			dhd_wl_ioctl_cmd(dhd, WLC_SET_PM, (char *)power_mode,
				sizeof(uint), TRUE, 0);
			/* Turn off MPC in AP mode */
			bcm_mkiovar("mpc", (char *)power_mode, 4,
					iovbuf, sizeof(iovbuf));
			dhd_wl_ioctl_cmd(dhd, WLC_SET_VAR, iovbuf,
				sizeof(iovbuf), TRUE, 0);
			g_pm_control = TRUE;
#ifdef ROAM_ENABLE
			/* Roaming off of dongle */
			bcm_mkiovar("roam_off", (char *)&roamvar, 4,
					iovbuf, sizeof(iovbuf));
			dhd_wl_ioctl_cmd(dhd, WLC_SET_VAR, iovbuf,
				sizeof(iovbuf), TRUE, 0);
#endif
		} else {
			dhd_wl_ioctl_cmd(dhd, WLC_SET_PM, (char *)power_mode,
				sizeof(uint), TRUE, 0);
		}
	}

	if (fp)
		filp_close(fp, NULL);
}
#endif
#ifdef GLOBALCONFIG_WLAN_COUNTRY_CODE
int dhd_customer_set_country(dhd_pub_t *dhd)
{
	struct file *fp = NULL;
	char *filepath = "/data/.ccode.info";
	char iovbuf[WL_EVENTING_MASK_LEN + 12] = {0};
	char buffer[10] = {0};
	int ret = 0;
	wl_country_t cspec;
	int buf_len = 0;
	char country_code[WLC_CNTRY_BUF_SZ];
	int country_rev;
	int country_offset;
	int country_code_size;
	char country_rev_buf[WLC_CNTRY_BUF_SZ];
	fp = filp_open(filepath, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		DHD_ERROR(("%s: %s open failed\n", __FUNCTION__, filepath));
		return -1;
	} else {
		if (kernel_read(fp, 0, buffer, sizeof(buffer))) {
			memset(&cspec, 0, sizeof(cspec));
			memset(country_code, 0, sizeof(country_code));
			memset(country_rev_buf, 0, sizeof(country_rev_buf));
			country_offset = strcspn(buffer, " ");
			country_code_size = country_offset;
			if (country_offset != 0) {
				strncpy(country_code, buffer, country_offset);
				strncpy(country_rev_buf, buffer+country_offset+1, strlen(buffer) - country_code_size + 1);
				country_rev = bcm_atoi(country_rev_buf);
				buf_len = bcm_mkiovar("country", (char *)&cspec, sizeof(cspec), iovbuf, sizeof(iovbuf));
				ret = dhd_wl_ioctl_cmd(dhd, WLC_GET_VAR, iovbuf, buf_len, FALSE, 0);
				memcpy((void *)&cspec, iovbuf, sizeof(cspec));
				if (!ret) {
					DHD_ERROR(("%s: get country ccode:%s country_abrev:%s rev:%d  \n", __FUNCTION__, cspec.ccode, cspec.country_abbrev, cspec.rev));
					if ((strncmp(country_code, cspec.ccode, WLC_CNTRY_BUF_SZ) != 0) || (cspec.rev != country_rev)) {
						strncpy(cspec.country_abbrev, country_code, country_code_size);
						strncpy(cspec.ccode, country_code, country_code_size);
						cspec.rev = country_rev;
						DHD_ERROR(("%s: set country ccode:%s country_abrev:%s rev:%d  \n", __FUNCTION__, cspec.ccode, cspec.country_abbrev, cspec.rev));
						buf_len = bcm_mkiovar("country", (char *)&cspec, sizeof(cspec), iovbuf, sizeof(iovbuf));
						ret = dhd_wl_ioctl_cmd(dhd, WLC_SET_VAR, iovbuf, buf_len, TRUE, 0);
					}
				}
			} else {
				DHD_ERROR(("%s: set country %s failed code \n", __FUNCTION__, country_code));
				ret = -1;
			}
		} else {
			DHD_ERROR(("%s: Reading from the '%s' returns 0 bytes \n", __FUNCTION__, filepath));
			ret = -1;
		}
	}
	if (fp)
		filp_close(fp, NULL);

	return ret;
}
#endif
