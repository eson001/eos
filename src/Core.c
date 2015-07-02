/*
 * Core.c
 *
 *  Created on: Sep 7, 2014
 *      Author: Clark Dong
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>

#include "Type.h"
#include "Parameter.h"
#include "Common.h"
#include "Session.h"
#include "Context.h"
#include "Dump.h"
#include "Report.h"
#include "Logic.h"
#include "Core.h"


TNodeIndex gNode;

//	Core Data!!!
//	All actived sessions hash map BODY
PSoderoTable gSessions;

//	All actived sessions time queue	DONE
PSoderoSessionManager gSessionManager;

//	Created flow for report	HEAD
PSoderoPointerPool gFreshStreams;

//	Created applications for report, HEAD
PSoderoPointerPool gFreshApplications;

//	Closed applications for report, BODY
PSoderoPointerPool gClosedApplications;

PSoderoPointerPool gEvents;

//	Packet statistic result;
PSoderoPeriodResult gPeriodResult = nullptr;
TSoderoPeriodResult gPeriodResults[SODERO_RESULT_COUNT];

#ifndef __SKIP_SPEED__
unsigned long long gHead;
unsigned long long gTail;
unsigned int gBytes = 0;
#endif

unsigned int gIndex = 0;

unsigned int gSeconds;
unsigned long long gTime;	//	Current time
unsigned long long gTick;	//	Event report time
unsigned long long gBase;	//	Periodic report time

 PSoderoPeriodResult getPeriodResult(void) {
	return gPeriodResult;
}

PSoderoSessionManager getSessionManager(void) {
	return gSessionManager;
}

PSoderoPointerPool getFreshStreams(void) {
	return gFreshStreams;
}

PSoderoPointerPool getFreshApplications(void) {
	return gFreshApplications;
}

PSoderoPointerPool getClosedApplications(void) {
	return gClosedApplications;
}

PSoderoPointerPool getEvents(void) {
	return gEvents;
}

PSoderoTable getSessions(void) {
	return gSessions;
}

void reset_period_result(PSoderoPeriodResult result) {
//	CLEAN_VAR(result->nodes.total);
	sodero_map_clean(result->nodes.items);
	sodero_map_clean(result->nodes.ports);

//	sodero_map_clean(result->items.ether);
	sodero_map_clean(result->items.mpls );
	sodero_map_clean(result->items.vlan );

	CLEAN_VAR(result->protocol);

	result->index = 0;
	result->time  = 0;
}

void initial_period_result(int index, PSoderoPeriodResult result) {
	result->index = index;

	result->nodes.items = createNodePeriodResult ();
	result->nodes.ports = createServicePeriodResult ();

	result->items.vlan  = createVLANPeriodResult();
	result->items.mpls  = createMPLSPeriodResult();

	reset_period_result(result);
}

void release_period_result(int index, PSoderoPeriodResult result) {
	sodero_map_destroy(result->nodes.items);
	sodero_map_destroy(result->nodes.ports);

	sodero_map_destroy(result->items.vlan );
	sodero_map_destroy(result->items.mpls );
}

void initial_core(void) {
	for (int i = 0; i < SODERO_RESULT_COUNT; i++)
		initial_period_result(i, &gPeriodResults[i]);

	gSessionManager     = sodero_create_session_manager(DEFAULT_MANAGER_LENGTH);	//	DEFAULT_PARAMETER
	gSessions           = createStreamSession();
	gFreshStreams       = sodero_create_pointer_pool();
	gFreshApplications  = sodero_create_pointer_pool();
	gClosedApplications = sodero_create_pointer_pool();
	gEvents             = sodero_create_pointer_pool();

	gPeriodResult = &gPeriodResults[gIndex % SODERO_RESULT_COUNT];
	gPeriodResult->time = now();
}

void release_core(void) {
	for (int i = 0; i < SODERO_RESULT_COUNT; i++)
		release_period_result(i, &gPeriodResults[i]);

	sodero_destroy_pointer_pool(gEvents            );
	sodero_destroy_pointer_pool(gClosedApplications);
	sodero_destroy_pointer_pool(gFreshApplications );
	sodero_destroy_pointer_pool(gFreshStreams      );
	sodero_table_destroy(gSessions);
	sodero_destroy_session_manager(gSessionManager);
}

long report_event_handlor(PSoderoPointerPool container, int index, PSoderoEvent object, void * data) {
	int result = sodero_report_event(object, (long) data);
	return result ? 0 : -1;
}

long report_stream_handlor(PSoderoPointerPool container, int index, PSoderoSession object, void * data) {
	int result = sodero_report_session(object, (long)data);
	return result ? 0 : -1;
}

long report_application_handlor(PSoderoPointerPool container, int index, PSoderoApplication object, void * data) {
	int result = sodero_report_application(object, (long)data);
	return result ? 0 : -1;
}

long clean_application_handlor(PSoderoPointerPool container, int index, PSoderoApplication object, void * data) {
	freeApplication(object);
	return 0;
}

long clean_event_handlor(PSoderoPointerPool container, int index, PSoderoEvent object, void * data) {
	freeEvent(object);
	return 0;
}

#ifndef __NO_CYCLE__
long session_manager_handlor(PSoderoSessionManager container, int index, PSoderoSession object, void * data) {
	if (gCycle) {
		if (((gTime - object->b) / uSecsPerSec) % gCycle) return 0;
		return sodero_report_session(object, (long)data);
	}
	return 0;
}
#endif

void cleanTimeout(PSoderoSession session) {
//	printf("Free Closed Applications\n");
	sodero_pointer_foreach(gEvents            , (TforeachPointerHandlor) clean_event_handlor      , (void*)SODERO_REPORT_WAY_DONE);
	sodero_pointer_foreach(gClosedApplications, (TforeachPointerHandlor) clean_application_handlor, (void*)SODERO_REPORT_WAY_DONE);

//	printf("Free Timeout Sessions\n");
	while (session) {
		PSoderoSession curr = session;
		session = sodero_session_next(curr);
		sodero_drop_session(curr);
	}

	sodero_pointer_reset(gEvents);
	sodero_pointer_reset(gFreshStreams);
	sodero_pointer_reset(gFreshApplications);
	sodero_pointer_reset(gClosedApplications);
}

void cleanAll(void) {
	PSoderoSession session = sodero_session_clean(gSessionManager);
	cleanTimeout(session);
}

void processTimeout(PSoderoSession session) {
#ifdef __REPORT_DIRECT__
#else

#ifndef __SKIP_DETECT__
	if (sodero_pointer_foreach(gEvents, (TforeachPointerHandlor) report_event_handlor, (void*)SODERO_REPORT_WAY_DONE) < 0) goto error;

	//	New session, report head once.	SODERO_REPORT_WAY_HEAD
//	printf("Report Fresh Streams\n");
	if (sodero_pointer_foreach(gFreshStreams, (TforeachPointerHandlor) report_stream_handlor, (void*)SODERO_REPORT_WAY_HEAD) < 0) goto error;

//	printf("Report Fresh Applicatons\n");
	//	Fresh applications?	SODERO_WAY_HEAD
	if (sodero_pointer_foreach(gFreshApplications, (TforeachPointerHandlor) report_application_handlor, (void*)SODERO_REPORT_WAY_HEAD) < 0) goto error;

//	printf("Report Closed Applicatons\n");
	//	Closed applications?	SODERO_WAY_BODY
	if (sodero_pointer_foreach(gClosedApplications, (TforeachPointerHandlor) report_application_handlor, (void*)SODERO_REPORT_WAY_DONE) < 0) goto error;

	//	Periodic report actived session.	SODERO_REPORT_WAY_BODY
//	printf("Report Periodic Sessions\n");
#ifndef __NO_CYCLE__
	if (sodero_session_foreach(gSessionManager, (TSessionTimeoutHandlor) session_manager_handlor, (void*)SODERO_REPORT_WAY_BODY) < 0) goto error;
#endif

//	printf("Report Timeout Sessions\n");
	//	Report timeout session at last.
	PSoderoSession curr = session;
	while (curr) {
		if (!isEmptyEtherData(&curr->eth)) {
			PNodeValue sourNode = takeIPv4Node((TMACVlan){{curr->eth.ether.sour, curr->eth.ether.type}}, curr->key.sIP);
			PNodeValue destNode = takeIPv4Node((TMACVlan){{curr->eth.ether.dest, curr->eth.ether.type}}, curr->key.dIP);
			switch(curr->key.proto) {
			case IPPROTO_ICMP:
				break;
			case IPPROTO_TCP:
//				sodero_report_tcp_session((PSoderoTCPSession) curr, SODERO_REPORT_WAY_BODY);
				break;
			case IPPROTO_UDP:
				switch (curr->flag) {
					case SESSION_TYPE_MINOR_DNS: {
						sourNode->l4.dns.outgoing.timeout++;
						destNode->l4.dns.incoming.timeout++;
						break;
					}
				}
//				sodero_report_udp_session((PSoderoUDPSession) curr, SODERO_REPORT_WAY_BODY);
				break;
			}
		}
//		sodero_report_application(curr->session, SODERO_REPORT_WAY_DONE);
		int result = sodero_report_session(curr, SODERO_REPORT_WAY_DONE);
		if (result < 0) goto error;
		curr = sodero_session_next(curr);
	}
#endif
	goto clean;

error:
//	printf("Can't send report to server\n");
	sodero_report_disconnect();

clean:
	cleanTimeout(session);
#endif
}

PSoderoPeriodResult timerHandler(long long time) {
	if (gTime < time) {
		gTime = time;
	} else
		return nullptr;

	unsigned int seconds = time / uSecsPerSec;

	if (gSeconds < seconds) {
		gSeconds = seconds;
//		if ((seconds % 5))		//	check timout every 5 seconds;
//			return nullptr;
	} else
		return nullptr;

	unsigned long long b = now();

#ifndef __SKIP_SPEED__
	gTail = b;
#endif

	gE = b;

	gT += gE - gB;

	dpi_check();

	if (gTick) {
		int delta = time_delta(seconds, gTick / uSecsPerSec);
		if (delta > 0) {
			PSoderoSession session = sodero_session_check(gSessionManager, time);
			processTimeout(session);
			gTick = time;
		}
	} else
		gTick = time;

	PSoderoPeriodResult result = getPeriodResult();
	if (gPeriod) {
		if (gBase) {
			if (time >= gBase + gPeriod) {
				gIndex++;
				if (result)
					result->time = gBase;
			} else {
				gB = now();
				gO += gB - gE;
				return nullptr;
			}
		} else {
			printf("Set manager tick to %0.6f\n", time * 1e-6);
			gSessionManager->tick = seconds;
			time -= time % gPeriod;
		}
	} else {
		if (gBase) {
			int delta = time_delta(time, gBase);
			if (delta > 0) {
				gIndex ++;
				if (result)
					result->time = gBase;
			} else {
				gB = now();
				gO += gB - gE;
				return nullptr;
			}
		} else {
			printf("Set manager tick to %0.6f\n", time * 1e-6);
			gSessionManager->tick = time;
		}
	}

	unsigned long long e = now();

	printf("Change time from %0.6f to %0.6f check time %.3fps", 1e-6*gBase, 1e-6*time, 1e-6*(e-b));
#ifndef __SKIP_SPEED__
	if (gTail && gHead) {
		unsigned long long during = gTail - gHead;
		if (during)
			printf(" speed %.3fGbps\n", 8e-3 * gBytes / during);
	}
	gBytes = 0;
	gHead = now();
#else
	putc('\n', stdout);
#endif

	gBase = time;

	gPeriodResult = &gPeriodResults[gIndex % SODERO_RESULT_COUNT];

	return result;
}


int packetHandler(const PEtherPacket packet, int size, int length) {
	sodero_report_result(timerHandler(now())
#ifdef __NO_CYCLE__
			, getSessionManager()
#endif
			);

	if (packet) {
		processEtherPacket(packet, size, length);
#ifndef __SKIP_SPEED__
		gBytes += length;
#endif
	}

	return 0;
}

int simulateHandler(const PEtherPacket packet, PPCAPPacketHeader header) {
	sodero_report_result(timerHandler(header->time.usecond + header->time.seconds * uSecsPerSec)
#ifdef __NO_CYCLE__
			, getSessionManager()
#endif
			);

	if (packet) {
		processEtherPacket(packet, header->size, header->length);
#ifndef __SKIP_SPEED__
		gBytes += header->length;
#endif
	}

	return 0;
}

int pcapHandler(const PEtherPacket packet, PCaptureHeader header) {
	sodero_report_result(timerHandler(header->ts.tv_usec + header->ts.tv_sec * uSecsPerSec)
#ifdef __NO_CYCLE__
			, getSessionManager()
#endif
			);

	if (packet) {
		processEtherPacket(packet, header->caplen, header->len);
#ifndef __SKIP_SPEED__
		gBytes += header->len;
#endif
	}

	return 0;
}
