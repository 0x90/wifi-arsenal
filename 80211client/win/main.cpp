#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include<stdint.h>
#include <Winsock2.h>
// need link with Ws2_32.lib
#pragma comment(lib,"ws2_32.lib")

#include<pcap.h>
#pragma comment(lib,"wpcap.lib")
//#include "remote-ext.h"

/*放置一个库搜索记录到对象文件中，这个类型应该是和commentstring
（指定你要Linker搜索的lib的名称和路径）这个库的名字放在Object文件的
默认库搜索记录的后面，linker搜索这个库就像你在命令行输入这个命令一样。
你可以在一个源文件中设置多个库记录，它们在object文件中的顺序和在源文
件中的顺序一样。如果默认库和附加库的次序是需要区别的，使用Z编译开关是防止默认库放到object模块。

*/
#include<memory.h>

#include <stdlib.h>
#include <sys/types.h>
#include "data.h"



unsigned short checksum(unsigned short *addr, int len);
int sendpackage(); //发送TCP数据包
int receivepackage();
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int receive802package();
void SendStartPkt(pcap_t *handle, uint8_t localmac[]);
int auth802x();

int main(int argc, char *argv[])
{
	//sendpackage();
	
	//receivepackage();
	//receive802package();
	
	
	int res;
	res = auth802x();

	system("pause");
	if (res < 0)
		return res;
	return 0;
}


int receivepackage(){

	pcap_if_t *alldevs;
	pcap_if_t *d;

	int inum;
	int i = 0;

	pcap_t *adhandle;

	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;

	char packet_filter[] = "ip and udp";
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
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

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
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
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
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)
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
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	struct sockaddr_in antelope;
	char *udpsrc;

	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* 打印数据包的时间戳和长度 */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* 获得IP数据包头部的位置 */
	ih = (ip_header *)(pkt_data +
		14); //以太网头部长度

	/* 获得UDP首部的位置 */
	ip_len = (ih->h_verlen & 0xf) * 4;//ipÍ·³¤¶È
	uh = (udp_header *)((u_char *)ih + ip_len);

	/* 将网络字节序列转换成主机字节序列 */
	sport = ntohs(uh->source);
	dport = ntohs(uh->dest);

	antelope.sin_addr.s_addr = ih->sourceIP; // store IP in antelope
	udpsrc = inet_ntoa(antelope.sin_addr);

	antelope.sin_addr.s_addr = ih->destIP; // store IP in antelope
	//some_addr = inet_ntoa(ih->sourceIP); // return the IP
	/* 打印IP地址和UDP端口 */
	printf("%s:%d -> %s:%d\n",
		udpsrc,
		sport,
		inet_ntoa(antelope.sin_addr),
		dport);
}

/*
*构建数据包
*/
int sendpackage()
{
	/***********设备*****************/
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	int inum;//选择网络设备
	char errbuf[PCAP_ERRBUF_SIZE];

	//输出设备句柄
//	pcap_t *fp;
	//
	pcap_t *adhandle;
	/****************************/
	
	/************数据包构造***********************/
	//待发送数据
	unsigned char buffer[IPTCPSIZE] = { 0 };

	//以太网首部指针
	ether_header *pether_header = (ether_header *)buffer;
	//IP数据头指针
	ip_header *pip_herder = (ip_header *)(buffer + sizeof(ether_header));
	//UDP数据头指针
	//udp_header *pudp_herder = (udp_header *)(buffer + sizeof(ether_header)+sizeof(ip_header));
	tcp_header *ptcp_header = (tcp_header *)(buffer + sizeof(ether_header)+sizeof(ip_header));
	//伪首部头指针
	char buffer2[sizeof(buffer)-sizeof(ether_header)-sizeof(ip_header)+sizeof(psd_header)] = { 0 };
	psd_header *psd = (psd_header *)buffer2;
	/****************************/

	//针对以太网头部源地址进行赋值
	pether_header->eh_dst[0] = 0x00;		//0x0 * 16 + 0x0;;		百度00:1a:a9:15:46:57
	pether_header->eh_dst[1] = 0x1a;		//0x2 * 16 + 0x1;		
	pether_header->eh_dst[2] = 0xa9;		//0x2 * 16 + 0x7;
	pether_header->eh_dst[3] = 0x15;		//0x2 * 16 + 0x3;
	pether_header->eh_dst[4] = 0x46;		//0x7 * 16 + 0x2;
	pether_header->eh_dst[5] = 0x57;		//0xf * 16 + 0xe;
	//针对以太网头部目的地址进行赋值
	pether_header->eh_src[0] = 0x78;		//0x0 * 16 + 0x0;;		±¾»ú78:84:3c:d0:34:6a
	pether_header->eh_src[1] = 0x84;		//0x1 * 16 + 0xF;
	pether_header->eh_src[2] = 0x3c;		//0xD * 16 + 0x0;
	pether_header->eh_src[3] = 0xd0;		//0x1 * 16 + 0x6;
	pether_header->eh_src[4] = 0x34;		//0x6 * 16 + 0x3;
	pether_header->eh_src[5] = 0x6a;		//0x7 * 16 + 0x1;
	//针对以太网协议进行赋值
	pether_header->eh_type = htons(0x0800);;//ETHERTYPE_IP

	//构建IP数据头
	pip_herder->h_verlen = (4 << 4 | (sizeof(ip_header) / sizeof(ULONG))); //version+ip头部长度（按4字节对齐）
 //  pip_herder->version = 4; //设定版本号,一般IP类型为IPv4
	pip_herder->tos = 0; //设定类型,服务类型
	//设定长度,总长度（包含IP数据头，TCP数据头以及数据）
	pip_herder->total_len = htons(sizeof(buffer)-sizeof(ether_header));

	pip_herder->ident = htons(0x1000);//设定识别码

	pip_herder->frag_and_flags = htons(0);//设定偏移量,标志位偏移量
	pip_herder->ttl = 0x80;//设定生存时间
	pip_herder->protocol = IPPROTO_TCP; //设定协议类型,(6,tcp),协议类型
	pip_herder->checksum = 0; //设定检验和
	pip_herder->sourceIP = inet_addr("211.66.26.220"); //设定源地址，本机
	pip_herder->destIP = inet_addr("119.75.217.56");//设定目的地址，百度
	pip_herder->checksum = checksum((uint16_t*)pip_herder, sizeof(ip_header)); //重新设定检验和
	/*
	//构建UDP数据头
	pudp_herder->dest = htons(7865); //目的端口号
	pudp_herder->source = htons(2834);//源端口号
	pudp_herder->len = htons(sizeof(buffer)-sizeof(ether_header)-sizeof(ip_header));//设定长度
	pudp_herder->checkl = 0;//设定检验和
	*/
	//构建TCP数据头
	ptcp_header->th_sport = htons(1234);
	ptcp_header->th_dport = htons(80);
	ptcp_header->th_seq = htonl(0x7d2cb526);
	ptcp_header->th_ack = htonl(0);
	//0000,0000 00,000010
	ptcp_header->th_lenres = ((sizeof(tcp_header) / sizeof(u_long)) << 4 | 0);
	printf("%x\n", ptcp_header->th_lenres);
	ptcp_header->th_flag = 2;
	ptcp_header->th_win = htons(2048);
	ptcp_header->th_sum = 0;
	ptcp_header->th_urp = 0;

	//构造伪首部
	psd->saddr = inet_addr("211.66.26.220");//本机
	psd->daddr = inet_addr("119.75.217.56");//百度
	psd->ptcl = IPPROTO_TCP;
	psd->tcpl = htons(sizeof(buffer)-sizeof(ether_header)-sizeof(ip_header));
	psd->mbz = 0;

	memcpy(buffer2 + sizeof(psd_header), (void *)ptcp_header, sizeof(buffer)-sizeof(ether_header)-sizeof(ip_header));
	//0x31c7
	ptcp_header->th_sum = checksum((USHORT *)buffer2, sizeof(buffer)-sizeof(ether_header)-sizeof(ip_header)+sizeof(psd_header));
	/************构造数据包结束**********************/
	/*获取本地机器设备列表*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/*打印列表*/
	for (d = alldevs; d; d = d->next){
		printf("%d,%s",++i,d->name);
		if (d->description)
			printf("(%s)\n", d->description);
		else
			printf("(No description available)\n");
	}
	if (i == 0){
		printf("\nNo interfaces found! Make sure WinPcap is installde.\n");
		return -1;
	}

	printf("Enter the interface number(1-%d:)", i);
	scanf("%d",&inum);

	if (inum < 1 || inum > i){
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	/*跳转到已选设备*/
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
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 发送数据包 */
	if (pcap_sendpacket(adhandle, buffer, sizeof(buffer) /* size */) != 0)
	{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(adhandle));
		return -1;
	}
	else
		printf("package send\n");

	return 0;
}

//ip.dst==119.75.217.56 || ip.src==119.75.217.56
//计算校验和
USHORT checksum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;
	while (size>1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR *)buffer;
	}
	//将32位数转换成16  while (cksum>>16) 
	while (cksum >> 16)
		cksum = (cksum >> 16) + (cksum & 0xffff);
	return (USHORT)(~cksum);
}

unsigned short checksum1(unsigned short *addr, int len)
{
	register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}


	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}


	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}


