/*
 * UDP.c
 *
 *  Created on: Sep 28, 2014
 *      Author: Clark Dong
 */

#include <stdlib.h>
#include <string.h>

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "Stream.h"
#include "UDP.h"
#include "Core.h"


///////////////////////////////////////////////////////////////////////////////////////////////////


TContainerKey sodero_udp_keyof(PSoderoUDPSession session) {
	return &session->key;
}

void sodero_udp_cleaner(TObject item) {
	if (item)
		bzero(item, sizeof(TSoderoUDPSession));
}

TObject sodero_udp_creater(PSoderoContainer map) {
	TObject result = takeSession(sizeof(TSoderoUDPSession));
	sodero_udp_cleaner(result);
	return result;
}

void sodero_udp_releaser(PSoderoContainer map, TObject item) {
	freeSession(item);
}

long sodero_udp_session_handlor(int index, PSoderoUDPSession result, void * data) {
	return 0;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


PSoderoContainer createUDPSession(void) {
	return sodero_container_create(DEFAULT_UDP_LENGTH, DEFAULT_UDP_DELTA, DEFAULT_UDP_SIZE, nullptr,	//	DEFAULT_PARAMETER
				(THashHandlor) sodero_ipport_hasher, (TEqualHandlor) sodero_ipport_equaler, (TKeyDuplicator) sodero_ipport_duplicator
#ifdef __CONTAINER_KEY__
				, (TSoderoObjectKey) sodero_udp_keyof
#endif
				);
}


PSoderoUDPSession sodero_session_2_udp(PSoderoSession object) {
	return get_session_type(object) == SESSION_TYPE_MAJOR_UDP ? (PSoderoUDPSession) object : nullptr;
}

PSoderoUDPSession newUDPSession(PPortKey key, int timeout, unsigned char state, PEtherHeader ether) {
	PSoderoUDPSession result = takeSession(sizeof(TSoderoUDPSession));

	newPortSession((PSoderoPortSession)result, key, timeout, state, ether, gTime);

	return result;
}

int processUDPData(PSoderoUDPSession session, int dir,
		const unsigned char * data, unsigned int size, int length,
		PUDPHeader udp, PIPHeader ip, PEtherHeader ether) {

	updatePortSession((PSoderoPortSession)session, dir, size, length, gTime);

	if (session->flag == SESSION_TYPE_MINOR_UNKNOWN) return 0;

	if (session->flag == SESSION_TYPE_MINOR_UDP) {
		do {
			if (isDNSPacket(udp)) {
				session->flag = SESSION_TYPE_MINOR_DNS;
				break;
			}
			//	So set application to invalid and stop detect.
			session->flag = SESSION_TYPE_MINOR_UNKNOWN;
			return 0;
		} while(false);
	}

	if (session->flag <= SESSION_TYPE_MINOR_CUSTOM) {
		switch(session->flag) {
			case SESSION_TYPE_MINOR_DNS:
				return processDNSPacket(session, data, size, length, udp, ip, ether);
			case SESSION_TYPE_MINOR_CUSTOM:
				break;
			default:
				session->flag = SESSION_TYPE_MINOR_UNKNOWN;
				return 0;
		}
	}

	return 0;
}

int processUDPPacket(const void * data, int size, int length, PIPHeader ip, PEtherHeader ether) {
//	PSoderoUDPPeriodResult result = &gPeriodResult->protocol.l4.udp;
	PUDPPacket packet = (PUDPPacket) data;
//	int bytes = ntohs(packet->head.size) * 4;
	void * payload_data = UDP_OVERLOAD_DATA(data);
	int    payload_size = UDP_OVERLOAD_SIZE(size);

	processA(&gUDP, length);

	TPortKey key;
	key.l        = ip->value;
	key.port     = packet->head.port;
	key.data     = ip->protocol;
	key.dir      = DIR_NONE;
	key.sequence = ip->identify + (ip->check << 16);

//	printf("UDP %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", key.s[0], key.s[1], key.s[2], key.s[3], ntohs(key.sourPort), key.d[0], key.d[1], key.d[2], key.d[3], ntohs(key.destPort));

	PSoderoUDPSession session = sodero_table_lookup(getSessions(), &key);
	if (session) {
		resetSessionLive(session, gTime + gUDPActivedTime);
		session->e = gTime;
	} else {
		session = newUDPSession(&key, gUDPActivedTime, SODERO_UDP_OPENED, ether);
	}

	int dir = dir_of_iport(&session->key, &key);

	return processUDPData(session, dir, payload_data, payload_size, length, &packet->head, ip, ether);
}

