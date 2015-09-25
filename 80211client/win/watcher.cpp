#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include<stdint.h>
#include <Winsock2.h>
// need link with Ws2_32.lib
#pragma comment(lib,"ws2_32.lib")

#include<pcap.h>
#pragma comment(lib,"wpcap.lib")

#include<memory.h>
#include <stdlib.h>
#include <sys/types.h>
#include "data.h"
#include <windows.h> 

#include<atlbase.h>
#include<atlconv.h>
#include"iphlpapi.h"
#pragma comment(lib, "Iphlpapi.lib")


uint8_t BroadcastAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; // 广播MAC地址,Broadcast

const uint8_t MultcastAddr[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }; // 多播MAC地址,neareast
typedef enum { REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4, H3CDATA = 10 } EAP_Code;
typedef enum { IDENTITY = 1, NOTIFICATION = 2, MD5 = 4, AVAILABLE = 20 } EAP_Type;
static int times = 20;//重复请求的次数

typedef struct setting
{
	char device[100];
	uint8_t	mac[6];
}Setting;

void SendStartPkt(pcap_t *handle, uint8_t localmac[6]);
void GetMacFromDevice(uint8_t mac[6], const char *devicename);
int GetNameMacfromDevice(uint8_t mac[6], char devicename[100]);
void SendResponseIdentity(pcap_t *adhandle, const  u_char *pkt_data, uint8_t localmac[6]);
void SendResponseMD5(pcap_t *adhandle, const  u_char *pkt_data);
long file_size(char *filename);
/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void packet_handler1(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ether_header *eh;
	x802_header *uh;
	eap_header *eaph;
	time_t local_tv_sec;

	//eap数据
	u_char version;//802.1x版本号
	u_char type;//eap的类型0--eap,1--eapol
	u_short len;//eap数据包长度,包括首部
	int i = 0;

	u_char code;//request--1,respond--2
	u_char id;//数据id
	u_char eap_type;//1--identity,--md5-challenge,3--legacy_Nak

	//将地址转化为可视结构
	unsigned char   eh_dst[6] = {0}; //目的地址
	unsigned char   eh_src[6] = {0}; //源地址

	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* 打印数据包的时间戳和长度 */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* 获得ehernet数据包头部的位置 */
	eh = (ether_header *)(pkt_data); //以太网头部长度

	/* 获得802.1x首部的位置 */
	uh = (x802_header *)(pkt_data + 14);

	//ethernet头部信息
	for (i = 0; i < 6; i++)
	{
		eh_dst[i] = eh->eh_dst[i];
		eh_src[i] = eh->eh_src[i];
	}
	
	//802.1x头部信息
	version = uh->version;
	type = uh->type;
	len = htons(uh->len);//需要进行大段小段转换

	if (type == 0)
	{
		/* 获取eap首部位置 */
		eaph = (eap_header *)((u_char *)uh + 4);
		code = eaph->code;
		id = eaph->id;
		eap_type = eaph->type;
	}
	
	/* 打印Mac地址和eap信息 */
	for (i = 0; i < 6; i++)
	{
		if (i==5)
			printf("%x", eh_src[i]);
		else
			printf("%x:", eh_src[i]);
	}
	printf("-->");
	for (i = 0; i < 6; i++)
	{
		if (i == 5)
			printf("%x", eh_dst[i]);
		else
			printf("%x:", eh_dst[i]);
	}
	
	printf("\n802.1x:version=%d,type=%d,length=%d\n", version, type, len);
	if (type==0)
		printf("EAP:code=%d,ID=%d,Type=%d\n", code, id, eap_type);
}

int receive802package(){

	pcap_if_t *alldevs;
	pcap_if_t *d;

	int inum;
	int i = 0;

	pcap_t *adhandle;

	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;

	char packet_filter[] = "ether proto 0x888e";
	struct bpf_program fcode;

	/* 获得设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到已选设备 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* 打开适配器 */
	if ((adhandle = pcap_open(d->name,  // 设备名
		65536,     // 要捕捉的数据包的部分
		// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
		1000,      // 读取超时时间
		NULL,      // 远程机器验证
		errbuf     // 错误缓冲池
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 检查数据链路层，为了简单，我们只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;


	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 开始捕捉 */
	pcap_loop(adhandle, 0, packet_handler1, NULL);

	return 0;
}
/*不涉及ether设备未运行处理,比如休眠后唤醒,网卡重置处理*/
int auth802x()
{

	//pcap_if_t *alldevs;
	//pcap_if_t *d;
	//int inum;
	int i = 0;
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
	//uint8_t	MAC[6];
	//char devicename[100];
	//uint8_t	MAC[6];
	Setting setting;
	
	struct bpf_program fcode;
	char	FilterStr[100];
	bool serverIsFound = false;

	FILE *fp;
	


	long filesize = file_size("setting.ini");
	if (filesize>0)
	{
		fp = fopen("setting.ini", "rb");
		//-------------------OK-----------------------
		//fscanf(fp, "%s\n", dev1.devicename1);
		//fscanf(fp, "%x\t%x\t%x\t%x\t%x\t%x", dev1.MAC1, dev1.MAC1 + 1, dev1.MAC1 + 2, dev1.MAC1 + 3, 
		//	dev1.MAC1 + 4, dev1.MAC1 + 5);
		//------------------OK------------------------
		fscanf(fp, "%s\n%x\t%x\t%x\t%x\t%x\t%x", setting.device, setting.mac, setting.mac + 1, setting.mac + 2, setting.mac + 3,
			setting.mac + 4, setting.mac + 5);
		//------------------BAD--------------------
		//scanf("%x\t%x\t%x\t%x\t%x\t%x", &devicename, &MAC[0], &MAC[1], &MAC[2], &MAC[3], &MAC[4], &MAC[5]);
		//fscanf(fp, "%s\n", &dev1.devicename1);
		//fscanf(stdin, "%s\n%x\t%x\t%x\t%x\t%x\t%x", dev1.devicename1, &dev1.MAC1[0], &dev1.MAC1[1], &dev1.MAC1[2], &dev1.MAC1[3], dev1.MAC1[4], &dev1.MAC1[5]);
		//------------------BAD-------------------
		//fscanf(fp,"%s\n%x\t%x\t%x\t%x\t%x\t%x", &devicename, &MAC[0], &MAC[1], &MAC[2], &MAC[3], &MAC[4], &MAC[5]);
		//fscanf(fp, "%s%x%x%x%x%x%x", devicename, &MAC[0], &MAC[1], &MAC[2], &MAC[3], &MAC[4], &MAC[5]);
		//-----------------BAD----------------
		//fscanf(fp, "%s\n%x\t%x\t%x\t%x\t%x\t%x", devicename, MAC, MAC+1, MAC+2, MAC+3, MAC+4, MAC+5);
		//----------------BAD-------------
		//fscanf(fp, "%s\n%x\t%x\t%x\t%x\t%x\t%x", &devicename, MAC, MAC + 1, MAC + 2, MAC + 3, MAC + 4, MAC + 5);
		//------------------BAD---------------
		//fscanf(fp, "%s\n%x\t%x\t%x\t%x\t%x\t%x", &devicename, &MAC, MAC + 1, MAC + 2, MAC + 3, MAC + 4, MAC + 5);


		printf("\n");
		
		printf("AdapterName:\t%s\n", setting.device);
		printf("AdapterAddr:\t");
		for (i = 0; i < 6; i++){
			printf("%02X%c", setting.mac[i], i == 6 - 1 ? '\n' : '-');
		}
		
		/*
		printf("AdapterName:\t%s\n", devicename);
		printf("AdapterAddr:\t");
		for (i = 0; i < 6; i++){
			printf("%02X%c", MAC[i], i == 6 - 1 ? '\n' : '-');
		}
		*/
	}
	else
	{
		//-----------------------------------------------------------------------------------------------
		fp = fopen("setting.ini", "wb");
		/* 查询本机MAC地址 */
		if (GetNameMacfromDevice(setting.mac, setting.device) == -1)
			exit(-1);

		printf("AdapterName:\t%s\n", setting.device);

		printf("AdapterAddr:\t");
		for (i = 0; i < 6; i++){
			printf("%02X%c", setting.mac[i], i == 6 - 1 ? '\n' : '-');
		}

		fprintf(fp, "%s\n%2x\t%2x\t%2x\t%2x\t%2x\t%2x", setting.device, setting.mac[0], setting.mac[1], 
			setting.mac[2], setting.mac[3], setting.mac[4], setting.mac[5]);
	}
	fclose(fp);
	printf("debug:%d\n", file_size("setting.ini"));
	//------------------------------------------------------------------------------
	/* 打开设备 */
	if ((adhandle = pcap_open(setting.device,          // 设备名
		65536,            // 要捕捉的数据包的部分 
		// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", setting.device);
		/* 释放设列表 */
		//pcap_freealldevs(alldevs);
		return -1;
	}

	//printf("\nlistening on %s...\n", d->description);

	//----------------------------------------------------------------------------
	
	

	//捕获发往本机的eap数据包
	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
		setting.mac[0], setting.mac[1], setting.mac[2], setting.mac[3], setting.mac[4], setting.mac[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);
	/* 主动发起认证会话 */
	SendStartPkt(adhandle, setting.mac);
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
				printf("\nReconnection is failed.\n");
				return -1;
			}
			printf(",");
			Sleep(1000);
			SendStartPkt(adhandle, setting.mac);
			times--;
			// NOTE: 这里没有检查网线是否接触不良或已被拔下
		}
		
	}
	//-----------------------------------------------------------------------
	// 分情况应答下一个包

	res = pcap_next_ex(adhandle, &header, &pkt_data);
	// NOTE: 这里没有检查网线是否接触不良或已被拔下,已处理
	if (res == -1)
		return -1;
	if (pkt_data[22] == 1)
	{	// 通常情况会收到包Request Identity，应回答Response Identity
		printf("\n[%d] Server: Request Identity!\n", pkt_data[19]);//打印ID
		SendResponseIdentity(adhandle, pkt_data, setting.mac);
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
			Sleep(1000);     // 直到成功捕获到一个数据包后再跳出
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
				SendResponseIdentity(adhandle, pkt_data, setting.mac);
				printf("\n[%d] client: Response Identity.\n", pkt_data[19]);
				break;
			case MD5:
				printf("\n[%d] Server: Request MD5-Challenge!\n", pkt_data[19]);
				SendResponseMD5(adhandle, pkt_data);
				printf("\n[%d] client: Response MD5-Challenge.\n", pkt_data[19]);
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
			Sleep(1000);
			SendStartPkt(adhandle, setting.mac);
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

	const char *IDENTITY = "";//up to you
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
	lens = sizeof(eap_header)-1+strlen(IDENTITY)+1;
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
	u_char VALUE[16] = { 0 };
	const char *user = "";//up to you
	memcpy(VALUE, user, strlen(user));
	memcpy(value, VALUE, 16);
	//extra-data field
	const char *EXTRA_DATA = "";//up to you
	memcpy(extra_data, EXTRA_DATA, strlen(EXTRA_DATA));


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
	lens = sizeof(eap_header)-1 + 1 + 16 + strlen(EXTRA_DATA) + 1;//add 0x00
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
/*linux 下函数,请看linux下程序*/
void GetMacFromDevice(uint8_t mac[6], const char *devicename)
{
	//要使用本机的mac
	mac[0] = 0x7c;
	mac[1] = 0x05;
	mac[2] = 0x07;
	mac[3] = 0x40;
	mac[4] = 0x82;
	mac[5] = 0xe6;
}
/*windows 下函数*/
int GetNameMacfromDevice(uint8_t mac[6], char devicename[100])
{
	u_int inum;
	u_int i = 0, j = 0;
	char *name;
	//char tmp[100];

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);


	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS)
	{
		GlobalFree(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			//if (strstr(pAdapter->Description, "PCI") > 0 || pAdapter->Type == 71)
			//pAdapter->Description中包含"PCI"为：物理网卡,pAdapter->Type是71为：无线网卡
			//{
			printf("---------------------------%d---------------------------------\n", j + 1);
			printf("AdapterName:\t%s\n", pAdapter->AdapterName);
			printf("AdapterDesc:\t%s\n", pAdapter->Description);

			printf("AdapterAddr:\t");
			for (i = 0; i < pAdapter->AddressLength; i++)
			{
				printf("%02X%c", pAdapter->Address[i],
					i == pAdapter->AddressLength - 1 ? '\n' : '-');
			}
			printf("AdapterType:\t%d\n", pAdapter->Type);
			printf("IPAddress:\t%s\n", pAdapter->IpAddressList.IpAddress.String);
			printf("IPMask:\t%s\n", pAdapter->IpAddressList.IpMask.String);
			//}
			pAdapter = pAdapter->Next;
			j++;
		}

		printf("Enter the interface number (1-%d):", j);
		scanf("%d", &inum);

		if (inum < 1 || inum > j)
		{
			printf("\nInterface number out of range.\n");
			return -1;
		}
		/* 跳转到已选中的适配器 */
		for (pAdapter = pAdapterInfo, i = 0; i < inum - 1; pAdapter = pAdapter->Next, i++);

		name = pAdapter->AdapterName;
		/*转换为winpcap的设备名*/
		strcpy(devicename, "rpcap://\\Device\\NPF_");
		strcpy(devicename + strlen("rpcap://\\Device\\NPF_"), name);

		//printf("内部:%s\n", devicename);

		for (i = 0; i < pAdapter->AddressLength; i++)
		{
			mac[i] = pAdapter->Address[i];
		}
		return 0;
	}
	else
	{
		printf("Call to GetAdaptersInfo failed.\n");
		return -1;
	}
	return 0;
}
/*适合小文件判断大小*/
long file_size(char *filename)
{
	long filesize = -1;
	FILE *fp;
	fp = fopen(filename, "rb");
	if (fp == NULL)
		return filesize;
	
	fseek(fp,0,SEEK_END);
	filesize = ftell(fp);
	fclose(fp);
	return filesize;
}
