/*
 * DNS.h
 *
 *  Created on: Sep 14, 2014
 *      Author: Clark Dong
 */

#ifndef DNS_H_
#define DNS_H_

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "UDP.h"

#define __DNS_VERBOSE

//	TYPE values
#define DNS_TYPE_NONE             0x00
//	a host address
#define DNS_TYPE_A                0x01
//	an authoritative name server
#define DNS_TYPE_NS               0x02
//	a mail destination (Obsolete - use MX)
#define DNS_TYPE_MD               0x03
//	a mail destination (Obsolete - use MX)
#define DNS_TYPE_MF               0x04
//	the canonical name for an alias
#define DNS_TYPE_CNAME            0x05
//	marks the start of a zone of authority
#define DNS_TYPE_SOA              0x06
//	a mailbox domain name (EXPERIMENTAL)
#define DNS_TYPE_MB               0x07
//	a mail group member (EXPERIMENTAL)
#define DNS_TYPE_MG               0x08
//	a mail rename domain name (EXPERIMENTAL)
#define DNS_TYPE_MR               0x09
//	a null RR (EXPERIMENTAL)
#define DNS_TYPE_NULL             0x0A
//	a well known service description
#define DNS_TYPE_WKS              0x0B
//	a domain name pointer
#define DNS_TYPE_PTR              0x0C
//	host information
#define DNS_TYPE_HINFO            0x0D
//	mailbox or mail list information
#define DNS_TYPE_MINFO            0x0E
//	mail exchange
#define DNS_TYPE_MX               0x0F
//	text strings
#define DNS_TYPE_TXT              0x10

//	IPv6 Address
#define DNS_TYPE_AAAA             0x28

//	A request for a transfer of an entire zone
#define DNS_QTYPE_AXFR            0xFC
//	A request for mailbox-related records (MB, MG or MR)
#define DNS_QTYPE_MAILB           0xFD
//	A request for mail agent RRs (Obsolete - see MX)
#define DNS_QTYPE_MAILA           0xFE
//	A request for all records
#define DNS_QTYPE_ANY             0xFF


//	类(CLASS values)
//	the Internet
#define DNS_CLASS_IN              0x01
//	the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
#define DNS_CLASS_CS              0x02
//	the CHAOS class
#define DNS_CLASS_CH              0x03
//	Hesiod [Dyer 87]
#define DNS_CLASS_HS              0x04


#define DNS_OP_QUERY              0x00
#define DNS_OP_IQUERY             0x01
#define DNS_OP_STATUS             0x02

#define DNS_RC_OKAY               0x00
#define DNS_RC_FORMAT             0x01
#define DNS_RC_SERVER             0x02
#define DNS_RC_NAME               0x03
#define DNS_RC_IMPLEMENTED        0x04
#define DNS_RC_REFURED            0x05

//	 any class
#define DNS_QTYPE_ANY             0xFF


///////////////////////////////////////////////////////////////////////////////////////////////////


#pragma pack(push, 1)


typedef struct SODERO_DNS_CODES {
	union {
		unsigned int codes[3];
		struct {
			unsigned int standard;
			unsigned int reversal;
			unsigned int status  ;
		};
	} o;
	union {
		unsigned int codes[6];
		struct {
			unsigned int okay;
			unsigned int badFormat;
			unsigned int badServer;
			unsigned int badRefere;
			unsigned int badSupport;
			unsigned int forbid;
		};
	} r;
} TSoderoDNSCodes, * PSoderoDNSCodes;


typedef struct SODERO_DNS_DATUM {
	TSoderoFlowDatum value;
	TSoderoDNSCodes codes;
} TSoderoDNSDatum, * PSoderoDNSDatum;



typedef struct SODERO_DNS_VALUE {
	TSoderoDNSDatum request, response;
	TSoderoUnitDatum duration;
	unsigned long long timeout;
} TSoderoDNSValue, * PSoderoDNSValue;


struct SODERO_APPLICATION_DNS;
typedef struct SODERO_APPLICATION_DNS TSoderoApplicationDNS, * PSoderoApplicationDNS;


typedef struct SODERO_DNS_ANSWER_ENTRY {
	unsigned short type;
	unsigned short claz;
	unsigned int   time;
	unsigned short name;
	unsigned short data;
} TSoderoDNSAnswerEntry, * PSoderoDNSAnswerEntry;

struct SODERO_APPLICATION_DNS {
	char * data;
	PSoderoUDPSession    owner;
	PSoderoApplicationDNS link;
	unsigned long long id;		//	session id
//	unsigned char      flag;
	unsigned long long serial;

	TSoderoDoubleValue l2;
	TSoderoDoubleDatum traffic;	//	connection's traffic
	unsigned long long b;		//	Time of First Packet
	unsigned long long e;		//	Time of Last Packet

	unsigned int sequence;

	unsigned short type;
	unsigned char ocode;
	unsigned char rcode;

	unsigned char authoritative;
	unsigned char truncated;

	char query[68];	//	For compatibility with certain special circumstances, adds extra 4 bytes
	unsigned short answer;
};


#pragma pack(pop)


extern const char * dns_t_name(int type);
extern const char * dns_q_name(int type);
extern const char * dns_c_name(int type);
extern const char * dns_o_name(int code);
extern const char * dns_r_name(int code);

extern int isDNSPacket(PUDPHeader packet);

extern int processDNSPacket(PSoderoUDPSession session, const void * data, int size, int length, PUDPHeader udp, PIPHeader ip, PEtherHeader ether);

#endif /* DNS_H_ */
