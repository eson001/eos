/*
 * Logic.c
 *
 *  Created on: Jul 24, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>

#include "Type.h"
#include "Parameter.h"
#include "Common.h"
#include "Core.h"
#include "Session.h"
#include "Dump.h"
#include "Ether.h"
#include "IP.h"
#include "Stream.h"
#include "ICMP.h"
#include "TCP.h"
#include "UDP.h"
#include "DNS.h"
#include "HTTP.h"
#include "Logic.h"


int session_type(int type) {
	static int SESSION_SIZES[] = {0, sizeof(TSoderoUDPSession), sizeof(TSoderoTCPSession), -1};

	return SESSION_SIZES[type];
}

///////////////////////////////////////////////////////////////////////////////////////////////////


long sodero_node_hasher(PNodeIndex key) {
#if defined(__i386__)
	return ((long *)key)[0] + ((long *)key)[1] + ((long *)key)[2]
         + ((long *)key)[3] + ((long *)key)[4] + ((long *)key)[5];
#endif
#if defined(__x86_64__)
	return ((long *)key)[0] + ((long *)key)[1] + ((long *)key)[2];
#endif
}

long sodero_node_equaler(PNodeIndex a, PNodeIndex b) {
	if (((long *)a)[0] == ((long *)b)[0])
		if (((long *)a)[1] == ((long *)b)[1])
			return ((long *)a)[2] - ((long *)b)[2];
		else
			return ((long *)a)[1] - ((long *)b)[1];
	else
		return ((long *)a)[0] - ((long *)b)[0];
}

void sodero_node_duplicator(PNodeIndex a, PNodeIndex b) {
	((long *)a)[0] = ((long *)b)[0];
	((long *)a)[1] = ((long *)b)[1];
	((long *)a)[2] = ((long *)b)[2];
}

void sodero_node_cleaner(TContainerKey key, TContainerValue item) {
	if (item)
		bzero(item, sizeof(TNodeValue));
}

TObject sodero_node_creater(PSoderoMap map, TContainerKey k) {
	TObject result = takeMemory(sizeof(TNodeValue));
	sodero_node_cleaner(k, result);
	return result;
}

void sodero_node_releaser(PSoderoMap map, TContainerKey k, TObject item) {
	freeMemory(item);
}

long sodero_node_session_handlor(int index, PSoderoNode result, void * data) {
	return 0;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


long sodero_service_hasher(PServiceIndex key) {
#if defined(__i386__)
	return ((long *)key)[0] + ((long *)key)[1] + ((long *)key)[2] + ((long *)key)[3];
         + ((long *)key)[4] + ((long *)key)[5] + ((long *)key)[6] + ((long *)key)[7];
#endif
#if defined(__x86_64__)
	return ((long *)key)[0] + ((long *)key)[1] + ((long *)key)[2] + ((long *)key)[3];
#endif
}

long sodero_service_equaler(PServiceIndex a, PServiceIndex b) {
	if (((long *)a)[0] == ((long *)b)[0])
		if (((long *)a)[1] == ((long *)b)[1])
			if (((long *)a)[2] == ((long *)b)[2])
				return ((long *)a)[3] - ((long *)b)[3];
			else
				return ((long *)a)[2] - ((long *)b)[2];
		else
			return ((long *)a)[1] - ((long *)b)[1];
	else
		return ((long *)a)[0] - ((long *)b)[0];
}

void sodero_service_duplicator(PServiceIndex a, PServiceIndex b) {
	((long *)a)[0] = ((long *)b)[0];
	((long *)a)[1] = ((long *)b)[1];
	((long *)a)[2] = ((long *)b)[2];
	((long *)a)[3] = ((long *)b)[3];
}

void sodero_service_cleaner(TContainerKey key, TContainerValue item) {
	if (item)
		bzero(item, sizeof(TSoderoDoubleDatum));
}

TObject sodero_service_creater(PSoderoMap map, TContainerKey k) {
	TObject result = takeMemory(sizeof(TSoderoDoubleDatum));
	sodero_service_cleaner(k, result);
	return result;
}

void sodero_service_releaser(PSoderoMap map, TContainerKey k, TObject item) {
	freeMemory(item);
}

long sodero_service_session_handlor(int index, PSoderoDoubleDatum result, void * data) {
	return 0;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


void new_ipport_event(int proto, int event, void * key, void * value, int cause) {
#ifdef __EXPORT_REPORT__
	dump_ipport_event(proto, event, key, value, cause);
#endif
}


///////////////////////////////////////////////////////////////////////////////////////////////////


PNodeValue takeMACNode(PMAC key) {
	if (!isSMAC(key))
		return nullptr;

	TNodeIndex index = {.value = {0, 0, 0}};
	index.mac.b4 = key->b4;
	index.mac.b2 = key->b2;
	PNodeValue value = (PNodeValue)sodero_map_ensure(getPeriodResult()->nodes.items, &index);
	return value;
}

PNodeValue takeIPv4Node(TMACVlan head, TIPv4 key) {
	TNodeIndex index = {.value = {head.value, 0, 0}};

	//	Just set the internal IP, all external IP are calculated to 0.0.0.0
	if (isLIPv4(key))
		index.ip.l.ip = key.ip;

	PNodeValue value = (PNodeValue)sodero_map_ensure(getPeriodResult()->nodes.items, &index);

	return value;
}

PSoderoDoubleDatum takeServiceNode(PServiceIndex index) {
	PSoderoDoubleDatum value = (PSoderoDoubleDatum)sodero_map_ensure(getPeriodResult()->nodes.ports, index);
	return value;
}

///////////////////////////////////////////////////////////////////////////////////////////////////


PSoderoMap createNodePeriodResult(void) {
	return sodero_map_create(DEFAULT_NODE_LENGTH , DEFAULT_NODE_DELTA , DEFAULT_NODE_SIZE , SODERO_MAP_MODE_HOLD, nullptr,	//	DEFAULT_PARAMETER
			(THashHandlor  )sodero_node_hasher , (TEqualHandlor  )sodero_node_equaler , (TKeyDuplicator)sodero_node_duplicator,
			(TCreateHandlor)sodero_node_creater, (TReleaseHandlor)sodero_node_releaser, (TCleanHandlor )sodero_node_cleaner   );
}

PSoderoMap createServicePeriodResult(void) {
	return sodero_map_create(DEFAULT_SERVICE_LENGTH , DEFAULT_SERVICE_DELTA , DEFAULT_SERVICE_SIZE , SODERO_MAP_MODE_HOLD, nullptr,	//	DEFAULT_PARAMETER
			(THashHandlor  )sodero_service_hasher , (TEqualHandlor  )sodero_service_equaler , (TKeyDuplicator)sodero_service_duplicator,
			(TCreateHandlor)sodero_service_creater, (TReleaseHandlor)sodero_service_releaser, (TCleanHandlor )sodero_service_cleaner   );
}

void initial_logic(void) {

	initial_core();

	setpriority(PRIO_PROCESS, getpid(), -20);
}
