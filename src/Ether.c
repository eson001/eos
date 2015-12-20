/*
 * Ether.c
 *
 *  Created on: Sep 28, 2014
 *      Author: root
 */

#include <stdlib.h>
#include <string.h>

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "Core.h"
#include "Logic.h"

///////////////////////////////////////////////////////////////////////////////////////////////////


long sodero_vlan_hasher(unsigned short * key) {
	return *key;
}

long sodero_vlan_equaler(unsigned short * a, unsigned short * b) {
	return VALUE_OF_VLAN(*a) - VALUE_OF_VLAN(*b);
}

void sodero_vlan_duplicator(unsigned short * a, unsigned short * b) {
	*a = *b;
}

void sodero_vlan_cleaner(TContainerKey k, TContainerValue item) {
	if (item)
		bzero(item, sizeof(TSoderoSingleDatum));
}

TObject sodero_vlan_creater(PSoderoMap map, TContainerKey k) {
	TObject result = takeMemory(sizeof(TSoderoSingleDatum));
	sodero_vlan_cleaner(k, result);
	return result;
}

void sodero_vlan_releaser(PSoderoMap map, TContainerKey k, TObject item) {
	freeMemory(item);
}

long sodero_vlan_session_handlor(int index, PSoderoSingleDatum result, void * data) {
	return 0;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


long sodero_mpls_hasher(unsigned short * key) {
	return *key;
}

long sodero_mpls_equaler(unsigned short * a, unsigned short * b) {
	return VALUE_OF_MPLS(*a) - VALUE_OF_MPLS(*b);
}

void sodero_mpls_duplicator(unsigned short * a, unsigned short * b) {
	*a = *b;
}

void sodero_mpls_cleaner(TContainerKey k, TContainerValue item) {
	if (item)
		bzero(item, sizeof(TSoderoSingleDatum));
}

TObject sodero_mpls_creater(PSoderoMap map, TContainerKey k) {
	TObject result = takeMemory(sizeof(TSoderoSingleDatum));
	sodero_mpls_cleaner(k, result);
	return result;
}

void sodero_mpls_releaser(PSoderoMap map, TContainerKey k, TObject item) {
	freeMemory(item);
}

long sodero_mpls_session_handlor(int index, PSoderoSingleDatum result, void * data) {
	return 0;
}


PSoderoMap createVLANPeriodResult(void) {
	return sodero_map_create(DEFAULT_VLAN_LENGTH, DEFAULT_VLAN_DELTA, DEFAULT_VLAN_SIZE, SODERO_MAP_MODE_HOLD, nullptr,	//	DEFAULT_PARAMETER
			(THashHandlor  )sodero_vlan_hasher , (TEqualHandlor ) sodero_vlan_equaler , (TKeyDuplicator)sodero_vlan_duplicator,
			(TCreateHandlor)sodero_vlan_creater, (TReleaseHandlor)sodero_vlan_releaser, (TCleanHandlor )sodero_vlan_cleaner   );
}

PSoderoMap createMPLSPeriodResult(void) {
	return sodero_map_create(DEFAULT_MPLS_LENGTH, DEFAULT_MPLS_DELTA, DEFAULT_MPLS_SIZE, SODERO_MAP_MODE_HOLD, nullptr,	//	DEFAULT_PARAMETER
			(THashHandlor  )sodero_mpls_hasher , (TEqualHandlor ) sodero_mpls_equaler , (TKeyDuplicator)sodero_mpls_duplicator,
			(TCreateHandlor)sodero_mpls_creater, (TReleaseHandlor)sodero_mpls_releaser, (TCleanHandlor )sodero_mpls_cleaner   );
}


///////////////////////////////////////////////////////////////////////////////////////////////////


int processIPv6Packet(const void * data, int size, int length, PEtherHeader ether, unsigned short vlan) {
	processA(&gIPv6, length);
	return 0;
}

int processARPPacket(const void * data, int size, int length, PEtherHeader ether) {
	PSoderoPeriodResult result = getPeriodResult();
	const PARPPacket packet = (PARPPacket) data;
//	void * payload_data = VLAN_OVERLOAD_DATA(data);
//	int    payload_size = VLAN_OVERLOAD_SIZE(size);

	processA(&gARP, length);

	if (isIPv4ARP(&packet->head)) {
		PSoderoEvent event = takeEvent(sizeof(TSoderoEvent));
		event->time = gTime;
		event->type = SODERO_EVENT_REPORT;
		event->report.kind = SODERO_REPORT_ARP;
		event->report.arp.opcode = packet->head.opcode;
		event->report.arp.senderMAC = packet->senderMAC;
		event->report.arp.senderIP = packet->senderIP;
		event->report.arp.targetMAC = packet->targetMAC;
		event->report.arp.targetIP = packet->targetIP;
		sodero_pointer_add(getEvents(), event);
	}

	processA(&result->protocol.l2.arp.total, size);
	return 0;
}

int processMPLSPacket(const void * data, int size, int length, PEtherHeader ether, unsigned short vlan) {
	PSoderoPeriodResult result = getPeriodResult();
	const PMPLSPacket packet = (PMPLSPacket) data;
	void * payload_data = VLAN_OVERLOAD_DATA(data);
	int    payload_size = VLAN_OVERLOAD_SIZE(size);

	processA(&gMPLS, length);

	processA(&result->protocol.l2.mpls.total, size);

	long id = MPLS_ID(packet->mlps.value);
	PSoderoSingleDatum datum = (PSoderoSingleDatum) sodero_map_ensure(getPeriodResult()->items.mpls, &id);
	processSD(datum, size);

	processA(&result->protocol.l2.ether.ipv4, payload_size);
	payload_size = processIPv4Packet(payload_data, payload_size, length, ether, vlan);
	return payload_size;
}

int processVLANPacket(const void * data, int size, int length, PEtherHeader ether) {
	PSoderoPeriodResult result = getPeriodResult();
	const PVLANPacket packet = (PVLANPacket) data;
	void * payload_data = VLAN_OVERLOAD_DATA(data);
	int    payload_size = VLAN_OVERLOAD_SIZE(size);

	processA(&gVLAN, length);

	processA(&result->protocol.l2.vlan.total, size);

	long id = VLAN_ID(packet->vlan.value) >> 8;
	PSoderoSingleDatum datum = (PSoderoSingleDatum) sodero_map_ensure(getPeriodResult()->items.vlan, &id);
	processSD(datum, size);

	switch(packet->vlan.type) {
	case ETHER_TYPE_IPv4:
		processA(&result->protocol.l2.ether.ipv4, payload_size);
		payload_size = processIPv4Packet(payload_data, payload_size, length, ether, id);
		return payload_size;
	case ETHER_TYPE_MPLS:
		processA(&result->protocol.l2.ether.mpls, size);
		payload_size = processMPLSPacket(payload_data, payload_size, length, ether, id);
		return payload_size;
	}
	return 0;
}

int processLACPPacket(const void * data, int size, int length, PEtherHeader ether) {
	PSoderoPeriodResult result = getPeriodResult();
//	const PLACPPacket packet = (PLACPPacket) data;
//	void * payload_data = VLAN_OVERLOAD_DATA(data);
//	int    payload_size = VLAN_OVERLOAD_SIZE(size);

	processA(&gLACP, length);

	processA(&result->protocol.l2.lacp.total, size);
	return 0;
}

int processRSTPPacket(const void * data, int size, int length, PEtherHeader ether) {
	PSoderoPeriodResult result = getPeriodResult();
//	const PRSTPPacket packet = (PRSTPPacket) data;
//	void * payload_data = VLAN_OVERLOAD_DATA(data);
//	int    payload_size = VLAN_OVERLOAD_SIZE(size);

	processA(&gRSTP, length);

	processA(&gVLAN, length);

	processA(&result->protocol.l2.rstp.total, size);
	return 0;
}

static inline
int processOtherPacket(const void * data, int size, int length, PEtherHeader ether) {

	processA(&gOtherEther, length);

	return 0;
}

int processEtherSTP(PEtherPacket packet, int length, void * data, int size) {
	do {
		if (isSTPMAC(&packet->head.dest)) {
			if (isLinkSTP((PLinkRSTPHeader) packet)) {
				PSoderoPeriodResult result = getPeriodResult();
				processA(&result->protocol.l2.ether.rstp, length);
				PNodeValue node = takeMACNode(&packet->head.sour);
				processA(&node->l2.rstp.outgoing, length);
				processRSTPPacket (data, size, length, &packet->head);
				return true;
			}
		}
		if (isSTPMAC(&packet->head.sour)) {
			if (isLinkSTP((PLinkRSTPHeader) packet)) {
				PSoderoPeriodResult result = getPeriodResult();
				processA(&result->protocol.l2.ether.rstp, length);
				PNodeValue node = takeMACNode(&packet->head.dest);
				processA(&node->l2.rstp.incoming, length);
				processRSTPPacket (data, size, length, &packet->head);
				return true;
			}
		}
	} while (false);
	return false;
}

int processEtherBCAST(PEtherPacket packet, int length, void * data, int size) {
	do {
		if (isBMAC(&packet->head.dest)) {
//			PSoderoPeriodResult result = getPeriodResult();
//			processA(&result->protocol.l2.ether.bcast, length);
			PNodeValue node = takeMACNode(&packet->head.sour);
			processA(&node->l2.bcast.outgoing, length);
//			processBCASTPacket (data, size, length, &packet->head);
			return true;
		}
		if (isBMAC(&packet->head.sour)) {
//			PSoderoPeriodResult result = getPeriodResult();
//			processA(&result->protocol.l2.ether.bcast, length);
			PNodeValue node = takeMACNode(&packet->head.dest);
			processA(&node->l2.bcast.incoming, length);
//			processBCASTPacket (data, size, length, &packet->head);
			return true;
		}
	} while(false);
	return false;
}

int processEtherMCAST(PEtherPacket packet, int length, void * data, int size) {
	do {
		if (isMMAC(&packet->head.dest)) {
//			PSoderoPeriodResult result = getPeriodResult();
//			processA(&result->protocol.l2.ether.mcast, length);
			PNodeValue node = takeMACNode(&packet->head.sour);
			processA(&node->l2.mcast.outgoing, length);
//			processMCASTPacket (data, size, length, &packet->head);
			return true;
		}
		if (isMMAC(&packet->head.sour)) {
//			PSoderoPeriodResult result = getPeriodResult();
//			processA(&result->protocol.l2.ether.mcast, length);
			PNodeValue node = takeMACNode(&packet->head.dest);
			processA(&node->l2.mcast.incoming, length);
//			processMCASTPacket (data, size, length, &packet->head);
			return true;
		}
	} while(false);
	return false;
}

int processEtherUCAST(PEtherPacket packet, int length, void * data, int size) {
	if (isSMAC(&packet->head.sour)) {
//		PSoderoPeriodResult result = getPeriodResult();
//		processA(&result->protocol.l2.ether.ucast, length);
		PNodeValue node = takeMACNode(&packet->head.sour);
		processA(&node->l2.ucast.outgoing, length);
//		processMCASTPacket (data, size, length, &packet->head);
	}
	if (isSMAC(&packet->head.dest)) {
//		PSoderoPeriodResult result = getPeriodResult();
//		processA(&result->protocol.l2.ether.ucast, length);
		PNodeValue node = takeMACNode(&packet->head.dest);
		processA(&node->l2.ucast.incoming, length);
//		processMCASTPacket (data, size, length, &packet->head);
	}
	return true;
}

void processEtherCast(PEtherPacket packet, int length, void * data, int size) {
	if (processEtherUCAST(packet, length, data, size)) return;
	if (processEtherSTP  (packet, length, data, size)) return;
	if (processEtherBCAST(packet, length, data, size)) return;
	if (processEtherMCAST(packet, length, data, size)) return;
}

int processEtherPacket(const void * data, int size, int length) {
	const PEtherPacket packet = (PEtherPacket) data;
	void * payload_data = ETHER_OVERLOAD_DATA(data);
	int    payload_size = ETHER_OVERLOAD_SIZE(size);

	processA(&gTotal, length);
	processA(&gCurrent, length);

	PSoderoPeriodResult result = getPeriodResult();
	processA(&result->protocol.l2.ether.total, size);

	processEtherCast(packet, size, payload_data, payload_size);

	PNodeValue sour = takeMACNode(&packet->head.sour);
	PNodeValue dest = takeMACNode(&packet->head.dest);

	if (sour)
		processP(&sour->l2.total.outgoing, size);
	if (dest)
		processP(&dest->l2.total.incoming, size);
	switch (packet->head.type) {
		case ETHER_TYPE_IPv4:
			processA(&result->protocol.l2.ether.ipv4, size);
			if (sour)
				processA(&sour->l2.ipv4.outgoing, size);
			if (dest)
				processA(&dest->l2.ipv4.incoming, size);
			payload_size = processIPv4Packet (payload_data, payload_size, size, &packet->head, 0);
			break;
		case ETHER_TYPE_ARP :
			processA(&result->protocol.l2.ether.arp, size);
			if (sour)
				processA(&sour->l2.arp.outgoing, size);
			if (dest)
				processA(&dest->l2.arp.incoming, size);
			payload_size = processARPPacket  (payload_data, payload_size, size, &packet->head);
			break;
		case ETHER_TYPE_VLAN:
			processA(&result->protocol.l2.ether.vlan, size);
			if (sour)
				processA(&sour->l2.vlan.outgoing, size);
			if (dest)
				processA(&dest->l2.vlan.incoming, size);
			payload_size = processVLANPacket (payload_data, payload_size, size, &packet->head);
			break;
		case ETHER_TYPE_MPLS:
			processA(&result->protocol.l2.ether.mpls, size);
			if (sour)
				processA(&sour->l2.mpls.outgoing, size);
			if (dest)
				processA(&dest->l2.mpls.incoming, size);
			payload_size = processMPLSPacket (payload_data, payload_size, size, &packet->head, 0);
			break;
		case ETHER_TYPE_LACP:
			processA(&result->protocol.l2.ether.lacp, size);
			if (sour)
				processA(&sour->l2.lacp.outgoing, size);
			if (dest)
				processA(&dest->l2.lacp.incoming, size);
			payload_size = processLACPPacket (payload_data, payload_size, size, &packet->head);
			break;
		case ETHER_TYPE_IPv6:
			processA(&result->protocol.l2.ether.ipv6, size);
			if (sour)
				processA(&sour->l2.ipv6.outgoing, size);
			if (dest)
				processA(&dest->l2.ipv6.incoming, size);
			payload_size = processIPv6Packet (payload_data, payload_size, size, &packet->head, 0);
			break;
		default:
			processA(&result->protocol.l2.ether.other, size);
			if (sour)
				processA(&sour->l2.other.outgoing, size);
			if (dest)
				processA(&dest->l2.other.incoming, size);
			payload_size = processOtherPacket(payload_data, payload_size, size, &packet->head);
			break;
	}
//	PSoderoFlowDatum datum = (PSoderoFlowDatum) sodero_map_ensure(gPeriodResult->items.ether, packet->head.type);
//	processA(datum, size);

	return payload_size;
}


