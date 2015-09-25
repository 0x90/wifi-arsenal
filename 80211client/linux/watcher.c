#include <stdio.h>
#include<stdint.h>
#include <stdlib.h>
#include<sys/socket.h>

#include<pcap.h>

#include<memory.h>

#include <sys/types.h>
#include "data.h"
#include<time.h>
#include<assert.h>
#include<stdbool.h>
#include<unistd.h>
#include<sys/wait.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<net/if.h>
#include<arpa/inet.h>

//#include "debug.h"

uint8_t BroadcastAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; // 广播MAC地址,Broadcast

const uint8_t MultcastAddr[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }; // 多播MAC地址,neareast
typedef enum { REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4, H3CDATA = 10 } EAP_Code;
typedef enum { IDENTITY = 1, NOTIFICATION = 2, MD5 = 4, AVAILABLE = 20 } EAP_Type;
static int times = 20;//重复请求的次数

void SendStartPkt(pcap_t *handle, uint8_t localmac[6]);
void GetMacFromDevice(uint8_t mac[6], const char *devicename);
void SendResponseIdentity(pcap_t *adhandle, const  u_char *pkt_data, uint8_t localmac[6]);
void SendResponseMD5(pcap_t *adhandle, const  u_char *pkt_data);

/*不涉及ether设备未运行处理,比如休眠后唤醒,网卡重置处理*/
int auth802x(char *DeviceName)
{

	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	//时间相关
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	//抓去相关
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_short len;

	//过滤相关
	uint8_t	MAC[6];
	struct bpf_program fcode;
	char	FilterStr[100];
	bool serverIsFound = false;
	//-----------------------------------------------------------------------------------------------
		

	/* 打开设备 */
	if ((adhandle = pcap_open_live(DeviceName,          // 设备名
		65536,            // 要捕捉的数据包的部分 
		// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		1,    // 混杂模式
		1000,             // 读取超时时间
		errbuf            // 错误缓冲池
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", DeviceName);
		/* 释放设列表 */
		return -1;
	}

	//----------------------------------------------------------------------------
	
	/* 查询本机MAC地址 */
	GetMacFromDevice(MAC, DeviceName);

	//捕获发往本机的eap数据包
	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
		MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);
	/* 主动发起认证会话 */
	SendStartPkt(adhandle, MAC);
	printf("client: Start.\n");
	//------------------------------------------------------------------
	while (!serverIsFound )
	{
		res = pcap_next_ex(adhandle, &header, &pkt_data);
		// NOTE: 这里没有检查网线是否接触不良或已被拔下,已处理
		if (res == -1)
		  return -1;

		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		//dprintf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

		//printf("\n----%d-----\n", res);
		if (res==1 && pkt_data[18] == 1)
		{
			serverIsFound = true;
			len = *(u_short *)(pkt_data + 20);
			len = htons(len);
			//dprintf("\nServer( %02x:%02x:%02x:%02x:%02x:%02x )-->(%02x:%02x:%02x:%02x:%02x:%02x)\neap_id=%d,len=%d\n", 
			//	pkt_data[6], pkt_data[7], pkt_data[8], pkt_data[9], pkt_data[10], pkt_data[11], 
			//	pkt_data[0], pkt_data[1], pkt_data[2], pkt_data[3], pkt_data[4], pkt_data[5], pkt_data[19], len);
		}
		else
		{	// 延时后重试
			if (1 == times)
			{
				printf("Reconnection is failed.---from Forward @SCUT\n");
				return -1;
			}
			printf(",");
			sleep(1);
			SendStartPkt(adhandle, MAC);
			times--;
			// NOTE: 这里没有检查网线是否接触不良或已被拔下
		}
		
	}
	//-----------------------------------------------------------------------
	// 分情况应答下一个包
	if (pkt_data[22] == 1)
	{	// 通常情况会收到包Request Identity，应回答Response Identity
		printf("\n[%d] Server: Request Identity!\n", pkt_data[19]);//打印ID
		SendResponseIdentity(adhandle, pkt_data,MAC);
		printf("[%d] client: Response Identity.\n", pkt_data[19]);
	}

	// 重设过滤器，只捕获华为802.1X认证设备发来的包（包括多播Request Identity / Request AVAILABLE）
	sprintf(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
		pkt_data[6], pkt_data[7], pkt_data[8], pkt_data[9], pkt_data[10], pkt_data[11]);
	//printf("%s", FilterStr);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);

	//------------------------------------------------------------------------
	times = 30;//重置最大请求数
	// 进入循环体,不断处理认证请求
	for (;;)
	{
		// 调用pcap_next_ex()函数捕获数据包
		//-------------------------------------------进入等代阶段----------
		while ((res = pcap_next_ex(adhandle, &header, &pkt_data) )!= 1)
		{
			printf("."); // 若捕获失败或无数据，则等1秒后重试
			sleep(1);     // 直到成功捕获到一个数据包后再跳出
			// NOTE: 这里没有检查网线是否已被拔下或插口接触不良,已处理
			if (res == -1){
				printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
				return -1;
			}
		}
		//-------------------------------------------------------------------

		// 根据收到的Request，回复相应的Response包
		if (pkt_data[18] == REQUEST)
		{
			switch ((EAP_Type)pkt_data[22])
			{
			case IDENTITY:
				printf("\n[%d] Server: Request Identity!\n", pkt_data[19]);
				SendResponseIdentity(adhandle, pkt_data,MAC);
				printf("\n[%d] client: Response Identity.\n", pkt_data[19]);
				break;
			case MD5:
				//dprintf("\n[%d] Server: Request MD5-Challenge!\n", pkt_data[19]);
				SendResponseMD5(adhandle, pkt_data);
				//dprintf("\n[%d] client: Response MD5-Challenge.\n", pkt_data[19]);
				break;
			default:
				printf("\n[%d] Server: Request (type:%d)!\n", pkt_data[19], (EAP_Type)pkt_data[22]);
				printf("Error! Unexpected request type\n");
				exit(-1);
				break;
			}
			//break;//退出for循环
		}
		else if ((EAP_Code)pkt_data[18] == FAILURE)
		{	// 处理认证失败信息
			printf("\n[%d] Server: Failure.\n", pkt_data[19]);
			if (1 == times)
			{
				printf("Reconnection is failed.---from Forward @SCUT\n");
				return -1;
			}
			//重新认证开始
			sleep(1);
			SendStartPkt(adhandle, MAC);
			times--;
			//break;
		}
		else if ((EAP_Code)pkt_data[18] == SUCCESS)
		{
			printf("\n[%d] Server: Success.\n", pkt_data[19]);
			// 刷新IP地址
			times = 20;
			//break;
		}
		else
		{
			printf("\n[%d] Server: (H3C data)\n", pkt_data[19]);
			// TODO: 这里没有处理华为自定义数据包
			break;
		}
	}

	return 0;
}
void SendStartPkt(pcap_t *handle, uint8_t localmac[6])
{
	uint8_t packet[19] = {0};//注意初始化为0
	//填充ether数据头
	ether_header *eh = (ether_header *)packet;
	x802_header *uh = (x802_header *)(packet + sizeof(ether_header));
	uint8_t *sp = (uint8_t *)(packet + sizeof(ether_header)+sizeof(x802_header));

	int i = 0;
	for (i = 0; i < 6; i++)
	{
		eh->eh_src[i] = localmac[i];
		eh->eh_dst[i] = MultcastAddr[i];
	}
	eh->eh_type = htons(0x888e);
	
	uh->version = 0x01;
	uh->type = 0x01;
	uh->len = 0x0;
	*sp = 0x0;

	if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0){
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(handle));
		return;
	}
}
//收到server 发送的request时调用
void SendResponseIdentity(pcap_t *adhandle, const u_char *pkt_data, uint8_t localmac[6])
{
	//printf("eap struct len:%d\n",sizeof(eap_header));
	u_char packet[100] = { 0 };
	ether_header *eth = (ether_header *)packet;
	x802_header *uh = (x802_header *)(packet+14);//14=sizeof(eher_header)
	eap_header *eh = (eap_header *)(packet+sizeof(ether_header)+sizeof(x802_header));

	const char *IDENTITY = "host/billgates-PC";//your choice
	u_short lens;
	//printf("ether:%d,x802:%d,eap:%d数据位置:%d", sizeof(ether_header),sizeof(x802_header),sizeof(eap_header)
	//	,sizeof(ether_header)+sizeof(x802_header)+sizeof(eap_header)-1);
	//u_short datapos = sizeof(ether_header)+sizeof(x802_header)+sizeof(eap_header)-1;
	u_char *identity = (u_char *)(packet + sizeof(ether_header)+sizeof(x802_header)+sizeof(eap_header)-1);//从eap最后系统补0开始
	//初始化etherheader
	int i = 0;
	/*sucess之后,scutclient维持连接的回复是固定的,目的地是广播地址,源地址本机Mac.
	这里简单交换数据包以太网地址进行回复,错误的回复也可以通过,但效率更低
	*/
	for (i = 0; i < 6; i++){
		//eth->eh_src[i] = pkt_data[i];//dst
		//eth->eh_dst[i] = pkt_data[i + 6];//src
		eth->eh_src[i] = localmac[i];//dst
		eth->eh_dst[i] = MultcastAddr[i];//src
	}
	eth->eh_type = htons(0x888e);

	//初始化x802_header
	uh->version = 0x01;
	uh->type = 0x0;
	uh->len = 0x0;
	
	//初始化eap_header
	eh->code = 0x02;//respond
	eh->id = pkt_data[19];
	eh->len = 0x0;
	eh->type = 0x01;//identity

	//初始identity信息
	//*identity = "aaa";
	//printf("\nLen('%s')=%d\n",IDENTITY, strlen(IDENTITY));
	memcpy(identity, IDENTITY, strlen(IDENTITY));

	//lens为eap包头+其后数据大小
	lens = sizeof(eap_header)-1+strlen(IDENTITY)+1;//add 0x00
	//printf("\neap+数据总长度:%d\n",lens);
	uh->len = htons(lens);
	eh->len = uh->len;
	//printf("\n总大小:%d\n,待发送:%d\n", sizeof(packet), sizeof(ether_header)+sizeof(x802_header)+lens);
	//只发送packet构造出来的那部分,多余部分不能发送
	if (pcap_sendpacket(adhandle, packet, sizeof(ether_header)+sizeof(x802_header)+lens) != 0){//不加上-1
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
		return;
	}
}
void SendResponseMD5(pcap_t *adhandle, const  u_char *pkt_data){
	u_char packet[100] = { 0 };
	ether_header *eth = (ether_header *)packet;
	x802_header *uh = (x802_header *)(packet + 14);//14=sizeof(eher_header)
	eap_header *eh = (eap_header *)(packet + sizeof(ether_header)+sizeof(x802_header));

	u_short lens;
	u_short datapos = sizeof(ether_header)+sizeof(x802_header)+sizeof(eap_header);

	//eap-md5 value
	packet[datapos - 1] = 0x10;
	char *value = (char *)(packet + datapos);
	char *extra_data = (char *)(packet + datapos + 16);
	//value field
	u_char VALUE[16] = {0};
	const char *user = "";//up to you
	memcpy(VALUE,user,strlen(user));
	memcpy(value,VALUE,16);
	//extra-data field
	const char *EXTRA_DATA = "";//up to you
	memcpy(extra_data,EXTRA_DATA,strlen(EXTRA_DATA));
	

	//初始化etherheader
	int i = 0;
	for (i = 0; i < 6; i++){
		eth->eh_src[i] = pkt_data[i];//dst
		eth->eh_dst[i] = pkt_data[i + 6];//src
	}
	eth->eh_type = htons(0x888e);

	//初始化x802_header
	uh->version = 0x01;
	uh->type = 0x0;
	uh->len = 0x0;

	//初始化eap_header
	eh->code = 0x02;//respond
	eh->id = pkt_data[19];
	eh->len = 0x0;
	eh->type = 0x04;//Legacy Nak



	//lens为eap包头+其后数据大小
	lens = sizeof(eap_header)-1 + 1 + 16 + strlen(EXTRA_DATA)+1;//add 0x00
	//printf("\neap+数据总长度:%d\n", lens);
	uh->len = htons(lens);
	eh->len = uh->len;
	//printf("\n总大小:%d\n,待发送:%d\n", sizeof(packet), sizeof(ether_header)+sizeof(x802_header)+lens);
	//只发送packet构造出来的那部分,多余部分不能发送
	if (pcap_sendpacket(adhandle, packet, sizeof(ether_header)+sizeof(x802_header)+lens) != 0){//不加上-1
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
		return;
	}
}
void GetMacFromDevice(uint8_t mac[6], const char *devicename)
{

	int	fd;
	int	err;
	struct ifreq	ifr;

	fd = socket(PF_PACKET, SOCK_RAW, htons(0x0806));
	assert(fd != -1);

	assert(strlen(devicename) < IFNAMSIZ);
	strncpy(ifr.ifr_name, devicename, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	err = ioctl(fd, SIOCGIFHWADDR, &ifr);
	assert(err != -1);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	err = close(fd);
	assert(err != -1);
	return;
}
