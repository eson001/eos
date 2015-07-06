/*
 * Types.h
 *
 *  Created on: Jul 6, 2014
 *      Author: Clark Dong
 */

#ifndef TYPE_H_
#define TYPE_H_

#define __DEBUG__

#define __CONTAINER_KEY__
#define __TCP_REORDER_CHECK__

#define __EXPORT_REPORT
#define __EXPORT_STATISTICS__
#define __SKIP_DETECT
#define __SKIP_REPORT
#define __SKIP_WRITE
#define __SKIP_DETAIL

///////////////////////////////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)

#define ALIGN_SIZE(x, size) (((x) + (size - 1)) & ~(size - 1))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define min(a, b) (a < b ? a : b)
#define max(a, b) (a > b ? a : b)

#ifndef nullptr
#define nullptr NULL
#endif

#ifndef NUL
#define NUL 0
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#define CACHE_LINE 64
#define CACHE_MASK (!CACHE_REMAINDER)
#define CACHE_REMAINDER (CACHE_LINE-1)
#define CACHE_ALIGN(v) ((v + CACHE_REMAINDER) & ~CACHE_REMAINDER)

#define step_plus(i, size) \
	((i + 1) < (size) ? (i + 1) : 0)

#define step_nega(i, size) \
	(i > 0 ? (i - 1) : ((size) - 1))

#define loop_plus(i, b, e, size) \
	for (int i = (b); i != (e); i = step_plus(i, size))

#define TAB        0x09
#define LF         0x0A
#define CR         0x0D
#define SPACE      0x20
//	!
#define EXCLAIM    0x21
//	"
#define QUOTE      0x22
//	%
#define PERCENT    0x25
//	&
#define AMPERSAND  0x26
//	'
#define APOSTROPHE 0x27
//	(
#define LBRACKET   0x28
//	)
#define RBRACKET   0x29
//	*
#define MULTIPLE   0x2A
//	+
#define PLUS       0x2B
//	,
#define COMMA      0x2C
//	-
#define MINUS      0x2D
//	.
#define PERIOD     0x2E
//	/	SLASH
#define DIVISOR    0x2F
#define ZERO       0x30
#define NINE       0x39
//	:
#define COLON      0x3A
//	;
#define SEMICOLON  0x3B
//	<
#define LT         0x3C
//	=
#define EQUAL      0x3D
//	>
#define GT         0X3E
//	?
#define QUESTION   0x3F
//	@
#define AT         0x40
#define LETTER_A   0x41
#define LETTER_E   0x45
#define LETTER_F   0x46
//
#define BACKSLASH  0x5C
//	^
#define CIRCUMFLEX 0x5E

#define LETTER_a   0x61
#define LETTER_e   0x65
#define LETTER_f   0x66

#define DECMASK    0x0F

#define CRLF     0x0A0D

#define Ki 1024ULL
#define Mi (Ki * Ki)
#define Gi (Ki * Mi)
#define Ti (Ki * Gi);
#define Pi (Ki * Ti);
#define Ei (Ki * Pi);

#define _K 1000ULL
#define _M (_K * _K)
#define _G (_K * _M)
#define _T (_K * _G)
#define _P (_K * _T)
#define _E (_K * _P)

#define WORD_LENGTH(H, L)   (H * 0x0100 + L)

#define MAX_PACKET_SIZE               0x1000

#define PORT_DNS                       53

#define DIR_NONE      0
#define DIR_INCOMING -1		//	Recv
#define DIR_OUTGOING +1		//	Send

#define DIR_SERVER   -1
#define DIR_CLIENT   +1

#define DIR_REQUEST  -1
#define DIR_RESPONSE +1

//重组完毕以后的包最大长度
#define IP_PACKET_MIN_SIZE			0x0040
#define IP_PACKET_MAX_SIZE			0xFFFF

#define IP_PACKET_SIZE_LEVEL        24

#define ETHER_MIN_SIZE             60
//	60 - 14(ETHER HEAD SIZE) - 20 (IP HEAD SIZE)
#define IP_MIN_OVERLOAD            26

#define ETHER_HEAD_SIZE(x)          0x0E
#define ETHER_OVERLOAD_DATA(x)      ((void*)(ETHER_HEAD_SIZE(x) + (long) x))
#define ETHER_OVERLOAD_SIZE(x)      (x -     ETHER_HEAD_SIZE(x))

#define VLAN_HEAD_SIZE(x)           0x04
#define VLAN_OVERLOAD_DATA(x)       ((void*)(VLAN_HEAD_SIZE(x) + (long) x))
#define VLAN_OVERLOAD_SIZE(x)       (x -     VLAN_HEAD_SIZE(x))

#define IPV4_HEAD_SIZE(x)           (0x04 * (0x0F & *(unsigned char*)x))
#define IPV4_OVERLOAD_DATA(x, s)     ((void*)(s + (long) x))
#define IPV4_OVERLOAD_SIZE(x, s)     (x -     s)

#define ICMP_HEAD_SIZE(x)            0x08
#define ICMP_OVERLOAD_DATA(x)        ((void*)(ICMP_HEAD_SIZE(x) + (long) x))
#define ICMP_OVERLOAD_SIZE(x)        (x -     ICMP_HEAD_SIZE(x))

#define TCP_OVERLOAD_DATA(x, s)     ((void*)(s + (long) x))
#define TCP_OVERLOAD_SIZE(x, s)     (x -     s)

#define UDP_HEAD_SIZE(x)            0x08
#define UDP_OVERLOAD_DATA(x)        ((void*)(UDP_HEAD_SIZE(x) + (long) x))
#define UDP_OVERLOAD_SIZE(x)        (x -     UDP_HEAD_SIZE(x))

#define ETHER_TYPE_OTHER            0xFFFF
#define ETHER_TYPE_ARP              0x0608
#define ETHER_TYPE_IPv4             0x0008
#define ETHER_TYPE_VLAN             0x0081
#define ETHER_TYPE_IPv6             0xDD86

#define ETHER_TYPE_LACP             0x0988
#define ETHER_TYPE_MPLS             0x4788
#define ETHER_TYPE_MPLS_M           0x4888
#define ETHER_TYPE_RDMA             0x1589
#define ETHER_TYPE_FCoE             0x1489

#define ETHER_LINK_RSPT             0x03
#define ETHER_TYPE_RSPT             0x0000

#define ARP_HW_TYPE_ETHER           0x0100
#define ARP_HW_SIZE_ETHER           0x06
#define ARP_PROTOCOL_TYPE_IP        0x0008
#define ARP_PROTOCOL_SIZE_IP        0x04

#define ICMP_TYPE_RESPONSE          0x00
#define ICMP_TYPE_UNREACHABLE       0x03
#define ICMP_TYPE_REQUEST           0x08

#define VLAN_ID(x)                  (x & 0xFF0F)
#define MPLS_ID(x)                  (x & 0xFF0F)

#define IPv4_HEAD_SIZE(x)           0x14
#define IPv4_FRAGMENT(x)     (x & 0xFF0F)

#define IPv4_TYPE_ICMP              IPPROTO_ICMP
#define IPv4_TYPE_IGMP              IPPROTO_IGMP
#define IPv4_TYPE_TCP               IPPROTO_TCP
#define IPv4_TYPE_UDP               IPPROTO_UDP
#define IPv4_TYPE_SCTP              IPPROTO_SCTP

#define IP_VERSION_4                0x4
#define IP_VERSION_6                0x6

#define DNS_PORT                 0x3500
#define HTTP_PORT                0x5000

#define DNS_O_STANDARD 0
#define DNS_O_REVERSAL 1
#define DNS_O_STATUS   2

#define DNS_R_OKAY        0
#define DNS_R_BAD_FORMAT  1
#define DNS_R_BAD_SERVER  2
#define DNS_R_BAD_REFERE  3
#define DNS_R_BAD_SUPPORT 4
#define DNS_R_FORBID      5


#define DETECT_CONFIRM  +1
#define DETECT_PENDING   0
#define DETECT_NEGATIVE -1

#define PARSE_SUCCESS +1
#define PARSE_PENDING  0
#define PARSE_ERROR   -1

typedef struct TIME_STAMP {
	unsigned int seconds;
	union {
		unsigned int usecond;
		unsigned int nsecond;
	};
} TTimeStamp, * PTimeStamp;

typedef struct PCAP_FILE_HEADER {
	unsigned int   magic  ;
	unsigned short major  ;
	unsigned short minor  ;
	unsigned int   gmt    ;
	unsigned int   sigfigs;		// accuracy of timestamps
	unsigned int   length ;		// max length saved portion of each pkt
	unsigned int   link   ;       // data link type (LINKTYPE_*)
} TPCAPFileHeader, *PPCAPFileHeader;

typedef struct PCAP_PACKET_HEADER {
	TTimeStamp   time  ;        // time stamp
	unsigned int size  ;  	// length of portion present
	unsigned int length;    // length this packet (off wire)
} TPCAPPacketHeader, *PPCAPPacketHeader;

typedef union {
	unsigned char bytes[6];
	struct {
		unsigned short b2;
		unsigned int   b4;
	};
} TMAC, *PMAC;

typedef union {
	struct {
		TMAC mac;
		unsigned short vlan;
	};
	unsigned long long value;
} TMACVlan, *PMACVlan;

typedef unsigned short TVLANID;
typedef unsigned short TMPLSID;

#define MAC_OF_LONG(mac) (mac & 0x0000FFFFFFFFFFLL)
#define VALUE_OF_MAC(mac) MAC_OF_LONG(*(long*)mac)
#define VALUE_OF_VLAN(id) VLAN_ID((int)id)
#define VALUE_OF_MPLS(id) MPLS_ID((int)id)

typedef union IPV4 {
	unsigned int ip;
	unsigned char s[4];
	struct {
		unsigned short l, h;
	};
} TIPv4, *PIPv4;

typedef union IPV6 {
	unsigned int a, b, c, d;
	unsigned int s[4];
} TIPv6, *PIPv6;

typedef union IP {
	TIPv4 l;
	TIPv6 v;
	unsigned char bytes[16];
} TIP, *PIP;

typedef union VERSION {
	unsigned int value;
	unsigned char s[4];
} TVersion, *PVersion;

typedef union PORT_PAIR {
	struct {
		unsigned short sour;
		unsigned short dest;
	};
	unsigned int value;
	unsigned char bytes[4];
} TPortPair, *PPortPair;

typedef union IP_PAIR {
	struct {
		unsigned int sour;
		unsigned int dest;
	};
	struct {
		unsigned char s[4];
		unsigned char d[4];
	};
	struct {
		TIPv4 sourIP;
		TIPv4 destIP;
	};
	unsigned long long value;
	unsigned char bytes[8];
} TIPPair, *PIPPair;

typedef union {
	struct {
		TMAC dest;
		TMAC sour;
	};
	unsigned int values[3];
	struct {
		unsigned long long a;
		unsigned int       b;
	};
} TMACPair, * PMACPair;

typedef union ETHER_HEADER {
	struct {
		TMACPair pair;
		unsigned short vlan;
	};
	struct {
		unsigned char s[6];
		unsigned char d[6];
		unsigned short type;
	};
	struct {
		TMAC dest;
		TMAC sour;
		unsigned short id;
	};
	unsigned char bytes[14];
} TEtherHeader, *PEtherHeader;

typedef union ETHER_DATA {
	struct {
		unsigned long long l;
		unsigned long long h;
	};
	struct {
		unsigned char s[6];
		unsigned char d[6];
		unsigned short type;
		unsigned short data;
	};
	struct {
		TMAC dest;
		TMAC sour;
		unsigned short vlan;
	};
	unsigned char bytes[16];
	TEtherHeader ether;
} TEtherData, * PEtherData;

typedef union VLAN_HEADER {
	struct {
		unsigned char tag;
		unsigned char cfi :1, priority :3, tag_top :4;
		unsigned short type;
	};
	unsigned int value;
	unsigned char bytes[4];
} TVLANHeader, *PVLANHeader;

typedef union MPLS_HEADER {
	struct {
		unsigned short label;
		unsigned bottom:1, experimental: 3, label_top: 4;
		unsigned char ttl;
	};
	unsigned int value;
	unsigned char bytes[4];
} TMPLSHeader, * PMPLSHeader;

typedef union LACP_HEADER {
	unsigned short label;
	struct {
		unsigned char type;
		unsigned char version;
	};
} TLACPHeader, * PLACPHeader;

typedef struct LINK_CONTROL {
	unsigned char dsap;	//	Spanning Tree BPDU 0x42
	unsigned char ssap;	//	Spanning Tree BPDU 0x42
	unsigned char type;	//	Spanning Tree      0x03
} TLinkControl, * PLinkControl;

typedef struct RSTP_HEADER {
	unsigned short protocol;	//	Spanning Tree 0x0000
	unsigned char  version ;	//	Spanning Tree 0x00	Rapid/Multiple Spanning Tree 0x02
} TRSTPHeader, *PRSTPHeader;

typedef union LINK_RSTP_HEADER {
	struct {
		TLinkControl control;
		TRSTPHeader   stp;
	};
	struct {
		unsigned int   b4;	//	0x00034242
		unsigned short b2;	//	0x0000 | 0x0200
	};
	unsigned char bytes[6];
} TLinkRSTPHeader, * PLinkRSTPHeader;

typedef union PORT_HEADER {
	struct {
		union {
			struct {
				unsigned int sourIP;
				unsigned int destIP;
			};
			struct {
				unsigned char s[4];
				unsigned char d[4];
			};
			unsigned long long ip;
		};
		union {
			struct {
				unsigned short sourPort;
				unsigned short destPort;
			};
			unsigned int port;
			unsigned char p[4];
		};
	};
	struct {
		unsigned long long ipPair;	//	地址对
		unsigned int portPair;	//	端口对
	};
	unsigned char bytes[12];
} TPortHeader, *PPortHeader;

typedef struct ARP_HEADER {
	unsigned short hwType;
	unsigned short  pType;
	unsigned char  hwSize;
	unsigned char   pSize;
	unsigned short opcode;
} TARPHeader, * PARPHeader;

typedef union PORT_KEY {
	struct {
		union {
			unsigned long long l;
			struct {
				unsigned int sourIP;
				unsigned int destIP;
			};
			struct {
				unsigned char s[4];
				unsigned char d[4];
			};
			struct {
				TIPv4 sIP;
				TIPv4 dIP;
			};
			unsigned long long ip;
			TIPPair ipPair;
		};
		union {
			unsigned long long h;
			struct {
				union {
					struct {
						unsigned short sourPort;
						unsigned short destPort;
					};
					unsigned int port;
					unsigned char p[4];
				};
				union {
					struct {
						union {
							struct {
								unsigned char proto;
								         char dir  ;
							};
							unsigned short value;
						};
						unsigned short sequence;
					};
					unsigned int data;
				};
			};
			TPortPair portPair;
		};
	};
	TPortHeader head;
	unsigned char bytes[16];
} TPortKey, *PPortKey;

typedef union IP_HEADER {
	struct {
		union {
			struct {
				unsigned char head :4, version :4;
			};
			unsigned char first;
		};
		union {
			struct {
				unsigned char priority :3, cost :1, reliability :1, traffic :1,
						delay :1;
			};
			unsigned char service;
		};
		union {
			unsigned short size;
			struct {
				unsigned char H;
				unsigned char L;
			};
		};
		unsigned short identify;
		union {
			struct {
				unsigned char flag :5, MF :1, NF :1;
				unsigned char offset;
			};
			unsigned short fragment;
		};
		unsigned char ttl;
		unsigned char protocol;
		unsigned short int check;
		union {
			unsigned long long value;
			struct {
				TIPv4 sIP;
				TIPv4 dIP;
			};
			struct {
				unsigned int sour;
				unsigned int dest;
			};
			struct {
				unsigned char s[4];
				unsigned char d[4];
			};
			TPortHeader key[0];
			TIPPair ip;
		};
	};
	unsigned char bytes[20];
} TIPHeader, *PIPHeader;

typedef struct ICMP_HEADER {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	union {
		unsigned int value;
		struct {
			unsigned short id;
			unsigned short sequence;
		} echo;                     // echo datagram
		unsigned int gateway;
		struct {
			unsigned short unused;
			unsigned short mtu;
		} frag;                     // path mtu discovery
	};
} TICMPHeader, *PICMPHeader;

typedef union UDP_HEADER {
	struct {
		unsigned short int sour;
		unsigned short int dest;
		unsigned short int size;
		unsigned short int check;
	};
	unsigned int port;
	unsigned char bytes[8];
} TUDPHeader, *PUDPHeader;

typedef union TCP_HEADER {
	struct {
		union {
			unsigned int port;
			struct {
				unsigned short int sour;
				unsigned short int dest;
			};
		};
		unsigned int sequence;
		unsigned int ackSequence;
		union {
			unsigned short flag;
			struct {
				unsigned char nonce :1;
				unsigned char resv :3;
				unsigned char size :4;

				unsigned char fin :1;
				unsigned char syn :1;
				unsigned char rst :1;
				unsigned char psh :1;
				unsigned char ack :1;
				unsigned char urg :1;
				unsigned char ecn :1;
				unsigned char cwr :1;
			};
		};
		unsigned short window;
		unsigned short check;
		unsigned short surgen;
		unsigned int options[0];
	};
	unsigned char bytes[20];
} TTCPHeader, *PTCPHeader;

typedef union SCTP_HEADER {
	struct {
		unsigned short int sour;
		unsigned short int dest;
		unsigned int tag;
		unsigned int check;
	};
	unsigned char bytes[12];
} TSCTPHeader, *PSCTPHeader;

typedef union SCTP_CHUNK {
	struct {
		unsigned char type;
		unsigned char flag;
		unsigned short size;
	};
	unsigned int value;
	unsigned char bytes[4];
} TSCTPChunk, *PSCTPChunk;

typedef union CHUNK_HEADER {
	struct {
		union {
			struct {
				unsigned int sourIP;
				unsigned int destIP;
			};
			unsigned long long ip;
		};
		union {
			struct {
				unsigned short sourPort;
				unsigned short destPort;
			};
			unsigned long long port;
		};
	};
	struct {
		unsigned long long ipPair;	//	地址对
		unsigned int     portPair;	//	端口对
	};
	unsigned char bytes[24];
} TChunkHeader, *PChunkHeader;

typedef union SCTP_CHUNK_DATA {
	struct {
		unsigned char type;
		unsigned char flag;
		unsigned short size;
		unsigned int tsn;
		unsigned short identifier;
		unsigned short sequence;
		unsigned protocol;
	};
	unsigned char bytes[16];
} TSCTPChunkData, *PSCTPChunkData;

typedef union DNS_HEADER {
	struct {
		unsigned short sequence;
		union {
			struct {	//	response field
				//	qr:	1	Response
				//	op:	4	Opcode
				//	a :	1	Authoritative
				//	tc:	1	Truncated
				//	rd:	1	Recursion desired
				unsigned char rd :1, tc :1, a :1, op :4, qr :1;
				//	ra:	1	Recursion available
				//	z :	1
				//	aa:	1	Answer authenticated
				//	nd:	1	Non-authenticated data
				//	r : 1	Replay code
				unsigned char r :4, nd :1, aa :1, z :1, ra :1;
			};
			unsigned short flag;
		};
		unsigned short questions;
		unsigned short answers;
		unsigned short authoritis;
		unsigned short additions;
	};
	unsigned char bytes[12];
} TDNSHeader, *PDNSHeader;

typedef struct DNS_PACKET {
	union {
		TDNSHeader head;
		unsigned char bytes[0];
	};
	unsigned char body[0];
} TDNSPacket, *PDNSPacket;

typedef struct UDP_PACKET {
	union {
		TUDPHeader head;
		unsigned char bytes[0];
	};
	unsigned char body[0];
} TUDPPacket, *PUDPPacket;

typedef struct TCP_PACKET {
	union {
		TTCPHeader head;
		unsigned char bytes[0];
	};
	unsigned char body[0];
} TTCPPacket, *PTCPPacket;

typedef struct SCTP_PACKET {
	union {
		TUDPHeader head;
		unsigned char bytes[0];
	};
	unsigned char body[0];
} TSCTPPacket, *PSCTPPacket;

typedef struct IP_PORT_PACKET {
	union {
		TIPHeader head;
		unsigned char bytes[0];
	};
	union {
		unsigned char body[0];
		union {
			unsigned int value;
			struct {
				unsigned short sour;
				unsigned short dest;
			};
		} port;
		union {
			TTCPPacket tcp;
			TUDPPacket udp;
			TSCTPPacket sctp;
		};
	};
} TIPPortPacket, *PIPPortPacket;

typedef struct ICMP_PACKET {
	TICMPHeader head;
	unsigned char bytes[0];
} TICMPPacket, *PICMPPacket;

typedef struct IP_PACKET {
	union {
		TIPHeader head;
		unsigned char bytes[0];
	};
	union {
		unsigned char body[0];
		TICMPPacket icmp;
		TTCPPacket tcp;
		TUDPPacket udp;
		TSCTPPacket sctp;
		union {
			struct {
				unsigned short int sour;
				unsigned short int dest;
			};
			unsigned int value;
		} port;
	};
} TIPPacket, *PIPPacket;

typedef struct ARP_PACKET {
	TARPHeader head;
	TMAC senderMAC;
	TIPv4 senderIP;
	TMAC targetMAC;
	TIPv4 targetIP;
} TARPPacket, * PARPPacket;

typedef struct VLAN_PACKET {
	TVLANHeader vlan;
	union {
		unsigned char body[0];
		TIPPacket ip;
	};
} TVLANPacket, *PVLANPacket;

typedef struct MPLS_PACKET {
	TMPLSHeader mlps;
	unsigned char body[0];
} TMPLSPacket, * PMPLSPacket;

typedef struct LACP_PACKET {
	TLACPHeader lacp;
	unsigned char body[0];
} TLACPPacket, * PLACPPacket;

typedef struct RSTP_PACKET {
	TRSTPHeader lacp;
	unsigned char body[0];
} TRSTPPacket, * PRSTPPacket;

typedef struct ETHER_PACKET {
	union {
		TEtherHeader head;
		unsigned char bytes[0];
	};
	union {
		unsigned char body[0];
		TVLANHeader vlan;
		TMPLSHeader mpls;
		TLACPHeader lacp;
		TIPPacket ip;
	};
} TEtherPacket, *PEtherPacket;

#pragma pack(pop)

#define XDR_BUFFER_SIZE (32 * Ki)

#endif /* TYPE_H_ */
