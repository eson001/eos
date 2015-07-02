/*
 * IPort.c
 *
 *  Created on: Sep 28, 2014
 *      Author: Clark Dong
 */

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "ICMP.h"
#include "TCP.h"
#include "UDP.h"
#include "Core.h"
#include "Logic.h"

///////////////////////////////////////////////////////////////////////////////////////////////////


long sodero_ippair_hasher(PIPPair key) {
	return key->dest + key->sour;
}

long sodero_ippair_equaler(PIPPair a, PIPPair b) {
	return ((a->dest == b->dest) && (a->sour == b->sour))
		|| ((a->dest == b->sour) && (a->sour == b->dest));
}

void sodero_ippair_duplicator(PIPPair a, PIPPair b) {
	a->value = b->value;
}


int processIPv4OtherPacket(const void * data, int size, int length, PIPHeader ip, PEtherHeader ether) {
	processA(&gOtherIPv4, length);
	return 0;
}

int processIPv4Packet(const void * data, int size, int length, PEtherHeader ether, unsigned short vlan) {
	PIPPacket packet = (PIPPacket) data;
	PSoderoIPv4PeriodResult result = &getPeriodResult()->protocol.l3.ipv4;

	processA(&gIPv4, length);

	processA(&result->total, size);

	if (IPv4_FRAGMENT(packet->head.fragment)) {
		//	ToDo: Add Defragment
		result->counter.fragmentCount++;
		return 0;
	}

	unsigned int bytes = ntohs(packet->head.size);
	if (size > bytes)
		size = bytes;

	bytes = packet->head.head * 4;
	void * payload_data = IPV4_OVERLOAD_DATA(data, bytes);
	int    payload_size = IPV4_OVERLOAD_SIZE(size, bytes);


	TEtherHeader header = {{ether->pair, vlan}};

	PNodeValue sour = takeIPv4Node((TMACVlan){{ether->sour, vlan}}, packet->head.sIP);
	PNodeValue dest = takeIPv4Node((TMACVlan){{ether->dest, vlan}}, packet->head.dIP);
	if (sour) processP(&sour->l2.total.outgoing, length);
	if (dest) processP(&dest->l2.total.incoming, length);

	if (sour) processA(&sour->l3.total.outgoing, size);
	if (dest) processA(&dest->l3.total.incoming, size);

	switch(packet->head.protocol) {
	case IPv4_TYPE_ICMP:
		processA(&result->icmp, size);
		if (sour) processA(&sour->l3.icmp.outgoing, payload_size);
		if (dest) processA(&dest->l3.icmp.incoming, payload_size);
		return processICMPPacket(payload_data, payload_size, length, &packet->head, &header);
	case IPv4_TYPE_TCP:
		processA(&result->tcp , size);
		if (sour) processA(&sour->l3.tcp.outgoing, payload_size);
		if (dest) processA(&dest->l3.tcp.incoming, payload_size);
		counterTCPFlag(&sour->counter.tcp.outgoing, (PTCPHeader) payload_data);
		counterTCPFlag(&sour->counter.tcp.incoming, (PTCPHeader) payload_data);
		return processTCPPacket (payload_data, payload_size, length, &packet->head, &header);
	case IPv4_TYPE_UDP:
		processA(&result->udp , size);
		if (sour) processA(&sour->l3.udp.outgoing, payload_size);
		if (dest) processA(&dest->l3.udp.incoming, payload_size);
		return processUDPPacket (payload_data, payload_size, length, &packet->head, &header);
//	case IPv4_TYPE_SCTP:
//		return processSCTPPacket(payload_data, payload_size);
	default:
		processA(&result->other, size);
		if (sour) processA(&sour->l3.other.outgoing, payload_size);
		if (dest) processA(&dest->l3.other.incoming, payload_size);
		return processIPv4OtherPacket (payload_data, payload_size, length, &packet->head, &header);
	}
//	PSoderoFlowDatum datum = (PSoderoFlowDatum) sodero_map_ensure(&result->items.ipv4, packet->head.protocol);
//	processA(datum, size);

	return 0;
}

