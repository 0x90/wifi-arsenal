typedef struct ether_header
{
	unsigned char   eh_dst[6]; //目的地址
	unsigned char   eh_src[6]; //源地址
	unsigned short  eh_type; //eh_type的值需要考察上一层的协议，如果为ip则为0x0800
}ether_header;

typedef struct ip_hdr
{
	unsigned char       h_verlen; //IP类型为IPv4+ip头部长度（按4字节对齐)
//	unsigned char       version:4; //一般IP类型为IPv4,4表示4位
	unsigned char       tos; //服务类型
	unsigned short      total_len; //总长度（包含IP数据头，TCP数据头以及数据）
	unsigned short      ident; //识别码,ID定义单独IP,
	unsigned short      frag_and_flags;//标志位偏移量
	unsigned char       ttl; //生存时间
	unsigned char       protocol; //协议类型
	unsigned short      checksum; //检查和
	unsigned long        sourceIP; //源IP地址
	unsigned long        destIP; //目的IP地址
}ip_header;


typedef struct tcp_header
{
	unsigned short    th_sport;  //源端口
	unsigned short    th_dport; //目的端口
	unsigned int     th_seq; //序列号
	unsigned int     th_ack; //确认号
	//0000,0000 00,000010
	unsigned char    th_lenres; //4 位TCP首部+6位保留的前 4 位
	unsigned char    th_flag; //6位保留的前后2 位+标志位
	unsigned short    th_win; //窗口大小
	unsigned short    th_sum; //检验和
	unsigned short    th_urp; //紧急指针
}tcp_header;

typedef struct udp_header
{
	uint16_t source;			 /* source port,等价于unsigned short */
	uint16_t dest;				 /* destination port */
	uint16_t len;					 /* udp length */
	uint16_t checkl;			 /* udp checksum */
}udp_header;

typedef struct psd_header
{
	unsigned long    saddr;  //源地址
	unsigned long    daddr; //目的地址
	char            mbz; //置空
	char            ptcl; //协议类型
	unsigned short    tcpl; //数据包长度
}psd_header;

#define IPTCPSIZE 58

typedef struct x802_header
{
	u_char version;//802.1x版本号
	u_char type;//eap的类型0--eap,1--eapol
	u_short len;//eap数据包长度,包括首部
}x802_header;

typedef struct eap_header
{
	u_char code;//request--1,respond--2
	u_char id;//数据id
	u_short len;//eap数据包长度,包括首部
	u_char type;//1--identity,--md5-challenge,3--legacy_Nak
}eap_header;//大小为6
