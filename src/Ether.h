/*
 * Ether.h
 *
 *  Created on: Sep 28, 2014
 *      Author: Clark Dong
 */

#ifndef ETHER_H_
#define ETHER_H_

#include "Type.h"
#include "Common.h"
#include "Session.h"

#define DEFAULT_MAC_LENGTH	(4 * Ki)
#define DEFAULT_MAC_DELTA	(4 * Ki)
#define DEFAULT_MAC_SIZE	sizeof(TMAC)

#define DEFAULT_VLAN_LENGTH	32
#define DEFAULT_VLAN_DELTA	Ki
#define DEFAULT_VLAN_SIZE	sizeof(TVLANID)

#define DEFAULT_MPLS_LENGTH	32
#define DEFAULT_MPLS_DELTA	Ki
#define DEFAULT_MPLS_SIZE	sizeof(TMPLSID)


#pragma pack(push, 1)

typedef struct SODERO_ARP_EVENT {
	unsigned short opcode;
	TMAC senderMAC;
	TIPv4 senderIP;
	TMAC targetMAC;
	TIPv4 targetIP;
} TSoderoARPEvent, * PSoderoARPEvent;

typedef struct SODERO_ETHER_COUNTER {

} TSoderoEtherCounter, * PSoderoEtherCounter;


typedef struct SODERO_ETHER_PERIOD_RESULT {
	TSoderoFlowDatum total;

	//	Include Ether Head
	union {
		struct {
			TSoderoFlowDatum other;
			TSoderoFlowDatum ipv4 ;
			TSoderoFlowDatum ipv6 ;
			TSoderoFlowDatum vlan ;
			TSoderoFlowDatum mpls ;
			TSoderoFlowDatum rstp ;
			TSoderoFlowDatum lacp ;
			TSoderoFlowDatum arp  ;
		};
		TSoderoFlowDatum values[7];
	};

	TSoderoEtherCounter counter;
} TSoderoEtherPeriodResult, * PSoderoEtherPeriodResult;


//	Without Ether Head
typedef struct SODERO_ETHER_UNIQUE_PERIOD_RESULT {
	TSoderoFlowDatum total;
} TSoderoEtherUniquePeriodResult, * PSoderoEtherUniquePeriodResult;


typedef struct SODERO_ETHER_MULTI_PERIOD_RESULT {
	TSoderoFlowDatum total;
	PSoderoMap       items;
} TSoderoEtherMultiPeriodResult, * PSoderoEtherMultiPeriodResult;


typedef TSoderoEtherUniquePeriodResult TSoderoARPPeriodResult;
typedef PSoderoEtherUniquePeriodResult PSoderoARPPeriodResult;


typedef TSoderoEtherUniquePeriodResult TSoderoVLANPeriodResult;
typedef PSoderoEtherUniquePeriodResult PSoderoVLANPeriodResult;


typedef TSoderoEtherUniquePeriodResult TSoderoMPLSPeriodResult;
typedef PSoderoEtherUniquePeriodResult PSoderoMPLSPeriodResult;


typedef TSoderoEtherUniquePeriodResult TSoderoLACPPeriodResult;
typedef PSoderoEtherUniquePeriodResult PSoderoLACPPeriodResult;


typedef TSoderoEtherUniquePeriodResult TSoderoRSTPPeriodResult;
typedef PSoderoEtherUniquePeriodResult PSoderoRSTPPeriodResult;


#pragma pack(pop)


extern PSoderoMap createVLANPeriodResult(void);
extern PSoderoMap createMPLSPeriodResult(void);

extern int processEtherPacket(const void * data, int size, int length);

#endif /* ETHER_H_ */
