/*
 * ICMP.c
 *
 *  Created on: Sep 14, 2014
 *      Author: Clark Dong
 */

#include <stdlib.h>
#include <string.h>

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "ICMP.h"
#include "Core.h"
#include "Logic.h"

///////////////////////////////////////////////////////////////////////////////////////////////////


TContainerKey sodero_icmp_keyof(PSoderoICMPSession session) {
	return &session->key;
}

void sodero_icmp_cleaner(TObject item) {
	if (item)
		bzero(item, sizeof(TSoderoICMPSession));
}

TObject sodero_icmp_creater(PSoderoContainer map) {
	TObject result = takeSession(sizeof(TSoderoICMPSession));
	sodero_icmp_cleaner(result);
	return result;
}

void sodero_icmp_releaser(PSoderoContainer map, TObject item) {
	freeSession(item);
}

long sodero_icmp_session_handlor(int index, PSoderoDoubleDatum result, void * data) {
	return 0;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


PSoderoContainer createICMPSession(void) {
	return sodero_container_create(DEFAULT_ICMP_LENGTH, DEFAULT_ICMP_DELTA, DEFAULT_ICMP_SIZE, nullptr,	//	DEFAULT_PARAMETER
				(THashHandlor) sodero_ippair_hasher, (TEqualHandlor) sodero_ippair_equaler, (TKeyDuplicator) sodero_ippair_duplicator
#ifdef __CONTAINER_KEY__
	, (TSoderoObjectKey) sodero_icmp_keyof
#endif
				);
}

PSoderoICMPSession sodero_session_2_icmp(PSoderoSession object) {
	return get_session_type(object) == SESSION_TYPE_MAJOR_UDP ? (PSoderoICMPSession) object : nullptr;
}

PSoderoICMPSession newICMPSession(PPortKey key, int timeout, unsigned char state, PEtherHeader ether) {
	PSoderoICMPSession result = takeSession(sizeof(TSoderoICMPSession));
	newPortSession((PSoderoPortSession)result, key, timeout, state, ether, 0);

	return result;
}

int processICMPPacket(const void * data, int size, int length, PIPHeader ip, PEtherHeader ether) {
	PSoderoICMPPeriodResult result = &getPeriodResult()->protocol.l4.icmp;
	PICMPPacket packet = (PICMPPacket) data;

//	void * payload_data = ICMP_OVERLOAD_DATA(data);
	int    payload_size = ICMP_OVERLOAD_SIZE(size);

	processA(&gICMP, length);

	processA(&result->total, size);

//	printf("ICMP %u.%u.%u.%u-%u/%u -> %u.%u.%u.%u\n",
//		key.s[0], key.s[1], key.s[2], key.s[3], key.sourPort, key.destPort, key.d[0], key.d[1], key.d[2], key.d[3]);

	TPortKey key;
	key.l     = ip->value;
	key.data  = ip->protocol;
	key.dir   = DIR_NONE;
	key.sequence = 0;

	switch(packet->head.type) {
		case ICMP_TYPE_RESPONSE:
			gICMPResponse++;
			processA(&result->response, size);
			key.sourPort     = packet->head.echo.id;
			key.destPort     = packet->head.echo.sequence;
			break;
		case ICMP_TYPE_UNREACHABLE: {
			gICMPUnrechabled++;
			void * payload_data = ICMP_OVERLOAD_DATA(data);
			//	int    payload_size = ICMP_OVERLOAD_SIZE(size);
			PSoderoEvent event = takeEvent(sizeof(TSoderoEvent));
			PIPPacket ip = (PIPPacket)payload_data;
			event->time = gTime;
			event->type = SODERO_EVENT_REPORT;
			event->report.kind = SODERO_REPORT_ICMP;
			event->report.icmp.code = packet->head.code;
			event->report.icmp.info.sequence = 0;
			event->report.icmp.info.proto = ip->head.protocol;
			event->report.icmp.info.sourIP = ip->head.key[0].sourIP;
			event->report.icmp.info.destIP = ip->head.key[0].destIP;

			switch(ip->head.protocol) {
			case IPv4_TYPE_TCP:
			case IPv4_TYPE_UDP:
			case IPv4_TYPE_SCTP:
				event->report.icmp.info.sourPort = ip->head.key[0].sourPort;
				event->report.icmp.info.destPort = ip->head.key[0].destPort;
				break;
			default:
				event->report.icmp.info.sourPort = 0;
				event->report.icmp.info.destPort = 0;
				break;
			}
			sodero_pointer_add(getEvents(), event);
			break;
		}
		case ICMP_TYPE_REQUEST:
			gICMPRequest++;
			processA(&result->request , size);
			key.sourPort     = packet->head.echo.sequence;
			key.destPort     = packet->head.echo.id;
			break;
		default:
			return 0;
	}

	PSoderoICMPSession session = sodero_table_lookup(getSessions(), &key);
	if (!session) {
		session = newICMPSession(&key, gICMPActivedTime, SODERO_ICMP_OPENED, ether);
		session->value.value = packet->head.value;
	}

	switch(packet->head.type) {
		case ICMP_TYPE_REQUEST: {
			session->b = gTime;
			break;
		}
		case ICMP_TYPE_RESPONSE: {
			session->e = gTime;
			break;
		}
		default:
			return 0;
	}

	resetSessionLive(session, gTime + gICMPActivedTime);
	int dir = dir_of_ipv4(&session->key.ipPair, &key.ipPair);
	updatePortSession((PSoderoPortSession)session, dir, payload_size, length, 0);

	if (session->b && session->e)
		session->state = SODERO_ICMP_CLOSED;

	return 0;
}

