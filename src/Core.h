/*
 * Core.h
 *
 *  Created on: Sep 7, 2014
 *      Author: Clark Dong
 */

#ifndef CORE_H_
#define CORE_H_

#include "Type.h"
#include "IP.h"
#include "Stream.h"
#include "ICMP.h"
#include "TCP.h"
#include "UDP.h"
#include "DNS.h"
#include "HTTP.h"
#include "Core.h"
#include "MySQL.h"
#include "Tns.h"

#define SODERO_RESULT_COUNT 2

#define DEFAULT_NODE_LENGTH	(4 * Ki)
#define DEFAULT_NODE_DELTA	(4 * Ki)
#define DEFAULT_NODE_SIZE	sizeof(TNodeIndex)

#define DEFAULT_SERVICE_LENGTH	(4 * Ki)
#define DEFAULT_SERVICE_DELTA	(4 * Ki)
#define DEFAULT_SERVICE_SIZE	sizeof(TServiceIndex)


///////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct SODERO_PERIOD_SINGLE_COUNTER {
	TSoderoIPv4Counter ipv4;
	TSoderoTCPCounter  tcp;
} TSoderoPeriodSingleCounter, * PSoderoPeriodSingleCounter;

typedef struct SODERO_PERIOD_DOUBLE_COUNTER {
	struct {
		TSoderoIPv4Counter outgoing;
		TSoderoIPv4Counter incoming;
	} ipv4;
	struct {
		TSoderoTCPCounter outgoing;
		TSoderoTCPCounter incoming;
	} tcp;
} TSoderoPeriodDoubleCounter, * PSoderoPeriodDoubleCounter;


///////////////////////////////////////////////////////////////////////////////////////////////////


typedef union NODE_INDEX {
	unsigned long long value[3];
	struct {
		TMAC           mac ;
		unsigned short vlan;
		TIP            ip  ;
	};
	TMACVlan layer2;
} TNodeIndex, * PNodeIndex;

typedef struct SERVICE_INDEX {
	TNodeIndex         node;
	unsigned long long port;
} TServiceIndex, * PServiceIndex;

typedef struct NODE_VALUE {
	//	Dimensions l2_type
	struct {
		TSoderoDoubleDetail total;	//	Ethernet
		TSoderoDoubleDatum bcast;
		TSoderoDoubleDatum mcast;
		TSoderoDoubleDatum ucast;
		TSoderoDoubleDatum arp;
		TSoderoDoubleDatum vlan;
		TSoderoDoubleDatum ipv4;	//	NEW
		TSoderoDoubleDatum ipv6;
		TSoderoDoubleDatum mpls;
		TSoderoDoubleDatum rstp;
		TSoderoDoubleDatum lacp;
		TSoderoDoubleDatum other;
	} l2;

	//	Dimensions: l3_type
	struct {
		TSoderoDoubleDatum total;
		TSoderoDoubleDatum tcp;
		TSoderoDoubleDatum udp;
//		TSoderoDoubleDatum sctp;
		TSoderoDoubleDatum icmp;
//		TSoderoDoubleDatum igmp;
		TSoderoDoubleDatum other;
	} l3;

	TSoderoPeriodDoubleCounter counter;

	//	//	Dimensions: l4_group/server port
	struct {
		union {
			struct {
				TSoderoDNSValue incoming, outgoing;
			};
			TSoderoDNSValue value[2];
		} dns;
		union {
			struct {
				TSoderoHTTPValue incoming, outgoing;
			};
			TSoderoHTTPValue value[2];
		} http;
		union {
			struct {
				TSoderoMySQLValue incoming, outgoing;
			};
			TSoderoMySQLValue value[2];
		} mysql;
		union {
			struct {
				TSoderoTNSValue incoming, outgoing;
			};
			TSoderoTNSValue value[2];
		} tns;

//		TSoderoDoubleDatum smtp;
//		TSoderoDoubleDatum pop3;
//		TSoderoDoubleDatum ftp;
//		TSoderoDoubleDatum ssh;
	} l4;
//	PSoderoMap ports;
//
//	//	Dimensions: http_url
//	PSoderoMap urls;
//	//	Dimensions: http_url
//	PSoderoMap codes;
} TNodeValue, * PNodeValue;

//	Periodic statistics report

typedef struct SODERO_NODE {
	TNodeIndex index;
	TNodeValue value;
} TSoderoNode, * PSoderoNode;


typedef struct SODERO_PERIOD_NODE_RESULT {
//	TSoderoFlowDatum total;
	PSoderoMap       items;	//	MAC - IPv4 Nodes
	PSoderoMap       ports;	//	L4_GROUP:	MAC - IP - Port
} TSoderoPeriodNodeResult, * PSoderoPeriodNodeResult;

typedef struct SODERO_PERIOD_ITEM_RESULT {
//	TSoderoFlowDatum total;
//	PSoderoMap       ether;	//	Ethernet Protocols
	PSoderoMap       vlan;	//	VLAN IDs
	PSoderoMap       mpls;	//	MIPS IDs
} TSoderoPeriodItemResult, * PSoderoPeriodItemResult;


///////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct SODERO_SESSIONS {
	PSoderoContainer icmp;
	PSoderoContainer udp;
	PSoderoContainer tcp;
} TSoderoSessions, * PSoderoSessions;

typedef struct SODERO_PERIOD_RESULT {
	long index;
	unsigned long long time;

	TSoderoPeriodNodeResult  nodes;
	TSoderoPeriodItemResult  items;

	struct {
		struct {
			TSoderoEtherPeriodResult ether;
			TSoderoARPPeriodResult   arp  ;
			TSoderoVLANPeriodResult  vlan ;
			TSoderoMPLSPeriodResult  mpls ;
			TSoderoLACPPeriodResult  lacp ;
			TSoderoRSTPPeriodResult  rstp ;
		} l2;

		struct {
			TSoderoIPv4PeriodResult  ipv4 ;
		} l3;

		struct {
			TSoderoICMPPeriodResult  icmp ;
			TSoderoTCPPeriodResult   tcp  ;
			TSoderoUDPeriodResult    udp  ;
		} l4;
	} protocol;

} TSoderoPeriodResult, * PSoderoPeriodResult;


///////////////////////////////////////////////////////////////////////////////////////////////////


extern TNodeIndex gNode;
extern unsigned int gIndex;
extern unsigned int gSeconds;
extern unsigned long long gTime;	//	Current time
extern unsigned long long gTick;	//	Event report time
extern unsigned long long gBase;

extern PSoderoPeriodResult getPeriodResult(void);
extern PSoderoSessionManager getSessionManager(void);
extern PSoderoPointerPool getFreshStreams(void);
extern PSoderoPointerPool getFreshApplications(void);
extern PSoderoPointerPool getClosedApplications(void);
extern PSoderoPointerPool getEvents(void);
extern PSoderoTable getSessions(void);

extern void cleanTimeout(PSoderoSession session);
extern void cleanAll(void);

extern void reset_period_result(PSoderoPeriodResult result);

extern void initial_core(void);
extern void release_core(void);

extern int packetHandler(const PEtherPacket packet, int size, int length);
extern int pcapHandler(const PEtherPacket packet, const PPCAPPacketHeader header);

#endif /* CORE_H_ */
