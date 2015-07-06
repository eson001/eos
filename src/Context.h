/*
 * Context.h
 *
 *  Created on: Jul 6, 2014
 *      Author: Clark Dong
 */

#ifndef CONTEXT_H_
#define CONTEXT_H_

#include <sys/types.h>

#include <pcap.h>

#include "Type.h"

typedef struct PACKET_RESULT {
	unsigned int       count;
	unsigned long long bytes;
} TPacketResult, * PPacketResult;

typedef struct INDEX_RESULT {
	unsigned int index;
	union {
		TPacketResult value;
		struct {
			unsigned int       count;
			unsigned long long bytes;
		};
	};
} TIndexResult, * PIndexResult;

typedef struct ETHER_RESULT {
#ifdef __COMPRESS_RESULT__
//	TPacketResult ether;
//	TPacketResult vlan;
//	TPacketResult arp;
	hashmap       result;
#else
	TPacketResult result[65536];
#endif
} TEtherResult, * PEtherResult;

typedef struct VLAN_RESULT {
#ifdef __COMPRESS_RESULT__
	hashmap       result;
#else
	TPacketResult result[4096];
#endif
} TVLANResult, PVLANResult;

typedef struct IPv4_RESULT {
#ifdef __COMPRESS_RESULT__
	hashmap       result;
#else
	TPacketResult result[256];
#endif
} TIPv4Result, * PIPv4Result;

typedef struct PORT_RESULT {
	//
} TPortResult, * PPortResult;

typedef struct SODERO_SUMMARY_CONTEXT {
	unsigned long long count;
} TSummaryContext, * PSummaryContext;

typedef struct SODERO_CAPTURE_CONTEXT {
#ifdef __USE_USER_LOOP__
	int running;
#endif
	pcap_t * pcap;
	PSummaryContext data;
} TCaptureContext, * PCaptureContext;

typedef struct pcap_pkthdr TCaptureHeader, * PCaptureHeader;
typedef void (*TSoderoCaptureHandler)(void * data, const PEtherPacket packet, const PPCAPPacketHeader pkthdr);

extern pcap_t * createDevice(const char * device);
extern PCaptureContext createContext(pcap_t * pcap, void * data);

extern int destroyContext(PCaptureContext context);
extern PEtherPacket takePacket(PCaptureContext context, PCaptureHeader header);
extern int loopDevice(PCaptureContext capture, TSoderoCaptureHandler handler);
extern void stopDevice(PCaptureContext capture);

#endif /* CONTEXT_H_ */
