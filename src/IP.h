/*
 * IP.h
 *
 *  Created on: Sep 28, 2014
 *      Author: Clark Dong
 */

#ifndef IP_H_
#define IP_H_

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"


#define DEFAULT_IPV4_LENGTH	Ki
#define DEFAULT_IPV4_DELTA	Ki
#define DEFAULT_IPV4_SIZE	sizeof(TIPv4)


#pragma pack(push, 1)


typedef struct SODERO_IPV4_COUNTER {
	unsigned int fragmentCount;
} TSoderoIPv4Counter, * PSoderoIPv4Counter;


typedef struct SODERO_IPv4_PERIOD_RESULT {
	TSoderoFlowDatum total;

	union {
		struct {
			TSoderoFlowDatum icmp;
			TSoderoFlowDatum tcp ;
			TSoderoFlowDatum udp ;
//			TSoderoFlowDatum sctp;
			TSoderoFlowDatum other;
		};
		TSoderoFlowDatum values[4];
	};

	TSoderoIPv4Counter counter;
} TSoderoIPv4PeriodResult, * PSoderoIPv4PeriodResult;


#pragma pack(pop)


extern long sodero_ippair_hasher(PIPPair key);
extern long sodero_ippair_equaler(PIPPair a, PIPPair b);
extern void sodero_ippair_duplicator(PIPPair a, PIPPair b);

extern int processIPv4Packet(const void * data, int size, int length, PEtherHeader ether, unsigned short vlan);

#endif /* IP_H_ */
