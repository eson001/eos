/*
 * Dump.c
 *
 *  Created on: Aug 10, 2014
 *      Author: Clark Dong
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "Type.h"
#include "Parameter.h"
#include "Common.h"
#include "HTTP.h"
#include "Session.h"
#include "Context.h"
#include "Dump.h"

#ifdef __EXPORT_REPORT__

void verboseMACNode(PMAC key, PSoderoDoubleDatum datum) {
	if (isExportVerbose())
		printf("Process MAC-Node %.2x:%.2x:%.2x:%.2x:%.2x:%.2x @ %p\n",
				key->bytes[0], key->bytes[1], key->bytes[2], key->bytes[3], key->bytes[4], key->bytes[5], datum);
}

void verboseIPv4Node(PIPv4 key, PSoderoDoubleDatum datum) {
	if (isExportVerbose())
		printf("Process IP4-Node %u.%u.%u.%u @ %p\n",
				key->s[0], key->s[1], key->s[2], key->s[3], datum);
}

void dumpNode(int index, PNodeIndex k, PNodeValue v) {
	if (isExportDetail())
		printf("Report Node %d - %.2x:%.2x:%.2x:%.2x:%.2x:%.2x[%u.%u.%u.%u] @ %p incoming %llu bytes in %u packets & outgoing %llu bytes in %u packets\n",
				index, k->mac.bytes[0], k->mac.bytes[1], k->mac.bytes[2], k->mac.bytes[3], k->mac.bytes[4], k->mac.bytes[5],
				k->ip.l.s[0], k->ip.l.s[1], k->ip.l.s[2], k->ip.l.s[3],
				v, v->l2.total.incoming.total.bytes, v->l2.total.incoming.total.count, v->l2.total.outgoing.total.bytes, v->l2.total.outgoing.total.count);
}

unsigned int countTCPFlag(PSoderoTCPCounter counter) {
	unsigned int result = 0;
	if (counter->synCount) result++;
	if (counter->ackCount) result++;
	if (counter->finCount) result++;
	if (counter->rstCount) result++;
	if (counter->urgCount) result++;
	if (counter->ecnCount) result++;
	if (counter->cwrCount) result++;
	return result;
}

unsigned int countTCPSession(PSoderoTCPCounter counter) {
	unsigned int result = 0;
	if (counter->activeCount) result++;
	if (counter->establishedCount) result++;
	if (counter->connectedCount) result++;
	if (counter->disconectedCount) result++;
	if (counter->halfOpenCount) result++;
	if (counter->halfCloseCount) result++;
	return result;
}

void dumpCounter(PSoderoPeriodSingleCounter counter) {
	PSoderoIPv4Counter ipv4 = &counter->ipv4;
	if (ipv4->fragmentCount) {
		printf("IPv4: fragment %u\n", ipv4->fragmentCount);
	}

	PSoderoTCPCounter tcp = &counter->tcp;

	if (countTCPFlag(tcp)) {
		printf("TCP: syn %u ack %u fin %u rst %u urg %u ecn %u cwr %u\n",
				tcp->synCount, tcp->ackCount, tcp->finCount, tcp->rstCount, tcp->urgCount, tcp->ecnCount, tcp->cwrCount);
	}
	if (countTCPSession(tcp)) {
		printf("TCP: active %u established %u connected %u disconnected %u half open %u half close %u\n",
				tcp->activeCount, tcp->establishedCount, tcp->connectedCount, tcp->disconectedCount, tcp->halfOpenCount, tcp->halfCloseCount);
	}
}

void dump_ipport_event(int proto, int event, void * key, void * value, int cause) {
	if (isExportDetail()) {
		switch (proto) {
			case IPv4_TYPE_TCP:
			case IPv4_TYPE_UDP: {
				PPortHeader header = key;
				switch (event) {
					case SODERO_LOG_PACKET_ERROR:
						printf("Event: %s error %s - %p\n",
								ipv4_proto_name(proto), error_cause_name(cause), value);
						break;
					case SODERO_LOG_SESSION_CREAT:
						printf("Event: %s create %s - %p %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
								ipv4_proto_name(proto), creat_cause_name(cause), value,
								header->s[0], header->s[1], header->s[2], header->s[3], ntohs(header->sourPort),
								header->d[0], header->d[1], header->d[2], header->d[3], ntohs(header->destPort));
						break;
					case SODERO_LOG_SESSION_CLOSE:
						printf("Event: %s closed %s - %p\n",
								ipv4_proto_name(proto), close_cause_name(cause), value);
						break;
				}
				break;
			}
		}
	}
}

#endif

#ifdef __EXPORT_STATISTICS__
void dumpStatistics(void) {
	printf("================================================================\n");
	printf("Packet ether %llu/%u", gTotal.bytes, gTotal.count);
	if (gARP.count)
		printf(" ARP %llu/%u", gARP.bytes, gARP.count);
	if (gVLAN.count)
		printf(" VLAN %llu/%u", gVLAN.bytes, gVLAN.count);
	if (gMPLS.count)
		printf(" MPLS %llu/%u", gMPLS.bytes, gMPLS.count);
	if (gLACP.count)
		printf(" LACP %llu/%u", gLACP.bytes, gLACP.count);
	if (gRSTP.count)
		printf(" RSTP %llu/%u", gRSTP.bytes, gRSTP.count);
	if (gOtherEther.count)
		printf(" Other %llu/%u", gOtherEther.bytes, gOtherEther.count);
	printf("\n");

	printf("Packet IPv4 %llu/%u", gIPv4.bytes, gIPv4.count);
	if (gIPv6.count)
		printf(" IPv6 %llu/%u", gIPv6.bytes, gIPv6.count);
	if (gICMP.count)
		printf(" ICMP %llu/%u", gICMP.bytes, gICMP.count);
	if (gTCP.count)
		printf(" TCP %llu/%u", gTCP.bytes, gTCP.count);
	if (gUDP.count)
		printf(" UDP %llu/%u", gUDP.bytes, gUDP.count);
	if (gOtherIPv4.count)
		printf(" Other %llu/%u", gOtherIPv4.bytes, gOtherIPv4.count);
	printf("\n");


	if (gICMPRequest | gICMPResponse)
		printf("ICMP request %llu response %llu unrechabled %llu\n", gICMPRequest, gICMPResponse, gICMPUnrechabled);
	if (gDNSRequest | gDNSResponse)
		printf("DNS request %llu response %llu\n", gDNSRequest, gDNSResponse);

	if (gHTTPRequest | gHTTPResponse) {
		printf("HTTP request %llu response %llu\n", gHTTPRequest, gHTTPResponse);
		for (int i = 0; i < 8; i++)
			if (gHTTPMethod[i])
				printf("%s: %llu\n", nameOfHTTPMethod (i), gHTTPMethod[i]);
		for (int i = 0; i < 8; i++)
			if (gHTTPCode[i])
				printf("%dxx: %llu\n", i, gHTTPCode[i]);
		printf("Skiped %llu\n", gHTTPSkiped);
	}

	printf("----------------------------------------------------------------\n");

	if (tempFreed)
		printf("Temp        take %llu free %llu %.0f%% leak %lld empty %llu\n", tempTaken     , tempFreed     ,
			1e2 * tempFreed        / tempTaken       , tempTaken        - tempFreed       , tempEmpty       );
	if (memoryFreed)
		printf("Memory      take %llu free %llu %.0f%% leak %lld empty %llu\n", memoryTaken     , memoryFreed     ,
			1e2 * memoryFreed      / memoryTaken     , memoryTaken      - memoryFreed     , memoryEmpty     );
	if (blockFreed)
		printf("Block       take %llu free %llu %.0f%% leak %lld empty %llu\n", blockTaken     , blockFreed     ,
			1e2 * blockFreed       / blockTaken      , blockTaken       - blockFreed      , blockEmpty      );
	if (bufferFreed)
		printf("Buffer      take %llu free %llu %.0f%% leak %lld empty %llu\n", bufferTaken     , bufferFreed     ,
			1e2 * bufferFreed      / bufferTaken     , bufferTaken      - bufferFreed     , eventEmpty      );
	if (eventFreed)
		printf("Event       take %llu free %llu %.0f%% leak %lld empty %llu\n", eventTaken      , eventFreed      ,
			1e2 * eventFreed       / eventTaken      , eventTaken       - eventFreed      , eventEmpty      );
	if (applicationFreed)
		printf("Application take %llu free %llu %.0f%% leak %lld empty %llu\n", applicationTaken, applicationFreed,
			1e2 * applicationFreed / applicationTaken, applicationTaken - applicationFreed, applicationEmpty);
	if (sessionFreed)
		printf("Session     take %llu free %llu %.0f%% leak %lld empty %llu\n", sessionTaken    , sessionFreed    ,
			1e2 * sessionFreed     / sessionTaken    , sessionTaken     - sessionFreed    , sessionEmpty    );

	printf("Block take First %llu Create %llu Replace %llu Overflow %llu\n",
			gFirstBlock, gCreateBlock, gReplaceTake, gOverflowTake);
	printf("Block free Clean %llu Reorder %llu Replace %llu Overflow %llu skip %llu & %llu\n",
			gCleanBlock, gReorderBlock, gReplaceFree, gOverflowFree, gCleanSkiped, gReorderSkip);

	printf("Application DNS %llu/%llu HTTP %llu/%llu MySQL %llu/%llu Custom %llu Other %llu\n",
			gDNSTake, gDNSFree, gHTTPTake, gHTTPFree, gMySQLTake, gMySQLFree, gCustomFree, gOtherFree);

	printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}
#endif
