/*
 * Stream.c
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
#include "Session.h"
#include "Stream.h"
#include "Core.h"
#include "DPI.h"
#include "Logic.h"

///////////////////////////////////////////////////////////////////////////////////////////////////


long sodero_ipport_hasher(PPortKey key) {
	return key->sourIP + key->destIP + key->destPort + key->sourPort + key->data;
}

long sodero_ipport_equaler(PPortKey a, PPortKey b) {
	if (a->data == b->data) {
		if ((a->destIP == b->destIP) && (a->sourIP == b->sourIP) && (a->destPort == b->destPort) && (a->sourPort == b->sourPort)) return 0;
		if ((a->destIP == b->sourIP) && (a->sourIP == b->destIP) && (a->destPort == b->sourPort) && (a->sourPort == b->destPort)) return 0;
		return a - b;
	} else
		return a->data - b->data;
}

void sodero_ipport_duplicator(PPortKey a, PPortKey b) {
	a->l = b->l;
	a->h = b->h;
}

void sodero_ipport_cleaner(TObject item) {

}

TObject sodero_ipport_creater(PSoderoMap map) {
	TObject result = takeMemory(sizeof(TSoderoSingleDatum));
	sodero_ipport_cleaner(result);
	return result;
}

void sodero_ipport_releaser(PSoderoMap map, TObject item) {
	freeMemory(item);
}

long sodero_ipport_session_handlor(int index, PSoderoSingleDatum result, void * data) {
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////

long sodero_key_hasher(PPortKey key) {
	return key->sourIP + key->destIP + key->destPort + key->sourPort;
}

long sodero_key_equaler(PPortKey a, PPortKey b) {
	if (a->proto == b->proto) {
		if ((a->destIP == b->destIP) && (a->sourIP == b->sourIP) && (a->destPort == b->destPort) && (a->sourPort == b->sourPort)) return 0;
		if ((a->destIP == b->sourIP) && (a->sourIP == b->destIP) && (a->destPort == b->sourPort) && (a->sourPort == b->destPort)) return 0;
		return a - b;
	} else
		return a->proto - b->proto;
}

PPortKey sodero_key_keyof(PSoderoPortSession v) {
	return key_of_sesson((PSoderoSession)v);
}

void sodero_key_cleaner(TObject item) {

}

TObject sodero_key_creater(PSoderoMap map) {
	TObject result = takeMemory(sizeof(TSoderoSingleDatum));
	sodero_ipport_cleaner(result);
	return result;
}

void sodero_key_releaser(PSoderoMap map, TObject item) {
	freeMemory(item);
}

long sodero_key_session_handlor(int index, PSoderoSingleDatum result, void * data) {
	return 0;
}

PSoderoTable createStreamSession(void) {
	return sodero_table_create(DEFAULT_STREAM_LENGTH, DEFAULT_STREAM_DELTA, DEFAULT_STREAM_SIZE, SODERO_MAP_MODE_NONE, nullptr,	//	DEFAULT_PARAMETER
				(THashHandlor) sodero_key_hasher, (TEqualHandlor) sodero_key_equaler, (TSoderoObjectKey) sodero_key_keyof,
				nullptr, nullptr, nullptr
				);
}


///////////////////////////////////////////////////////////////////////////////////////////////////


int isSameDir(PIPPair k, PIPPair v) {
	return k->value == v->value;
}

int isPositiveIP(PIPPair k, PIPPair v) {
	return (k->sour == v->sour) && (k->dest == v->dest);
}

int isNegativeIP(PIPPair k, PIPPair v) {
	return (k->sour == v->dest) && (k->sour == v->dest);
}

int dir_of_ipv4(PIPPair k, PIPPair v) {
	if (isPositiveIP(k, v))
		return DIR_CLIENT;
	if (isNegativeIP(k, v))
		return DIR_SERVER;

	return DIR_NONE;
}

//int isSameDir(PPortKey k, PPortKey v) {
//	return k->value == v->value;
//}

int isPositiveIPort(PPortKey k, PPortKey v) {
	return (k->sourIP == v->sourIP) && (k->destIP == v->destIP) && (k->sourPort == v->sourPort) && (k->destPort == v->destPort);
}

int isNegativeIPort(PPortKey k, PPortKey v) {
	return (k->sourIP == v->destIP) && (k->destIP == v->sourIP) && (k->sourPort == v->destPort) && (k->destPort == v->sourPort);
}

int dir_of_iport(PPortKey k, PPortKey v) {
	if (isPositiveIPort(k, v))
		return DIR_CLIENT;
	if (isNegativeIPort(k, v))
		return DIR_SERVER;

	return DIR_NONE;
}

int isPositiveIPPort(PPortHeader k, PPortHeader v) {
	return (k->sourIP == v->sourIP) && (k->destIP == v->destIP) && (k->sourPort == v->sourPort) && (k->destPort == v->destPort);
}

int isNegativeIPPort(PPortHeader k, PPortHeader v) {
	return (k->sourIP == v->destIP) && (k->sourIP == v->destIP) && (k->sourPort == v->destPort) && (k->sourPort == v->destPort);
}

int dir_of_ipv4port(PPortHeader k, PPortHeader v) {
	if (isPositiveIPPort(k, v))
		return DIR_CLIENT;
	if (isNegativeIPPort(k, v))
		return DIR_SERVER;

	return DIR_NONE;
}

int dir_of_session(void * session, PPortKey k) {
	return session ? dir_of_iport(&((PSoderoPortSession)session)->key, k) : DIR_NONE;
}

int isClientDir(int dir) {
	return dir == DIR_CLIENT;
}

int isServerDir(int dir) {
	return dir == DIR_SERVER;
}

void resetSessionLive(void * session, unsigned long long tick) {
	PSoderoSession s = session;
	unsigned int live = tick / uSecsPerSec;
	int delta = s->live > live ? time_delta(live, s->live) : 0;
	s->live = live;
	if (delta < 0) {
		sodero_session_adjust(getSessionManager(), (PSoderoSession)session);
	}
}

int portSessionDPI(PSoderoPortSession session, TDPIKey key) {
	TDPIValue result = dpi_lookup(key);
	if (result.value) {
		session->flag = result.flag;
		session->application = result.application;
		session->major = result.major;
		session->minor = result.minor;
		return true;
	}
	return false;
}

void newPortSession(PSoderoPortSession session, PPortKey key, int timeout, unsigned char state,
	PEtherHeader ether, unsigned long long time) {
	gSession++;

	session->id = random();
	session->key = *key;
	session->live  = (gTime + timeout) / uSecsPerSec;
	session->state = state;
	session->eth.ether = *ether;

	if (dpiValid())
		do {
			if (portSessionDPI(session, (TDPIKey){{key->sourIP, key->sourPort, key->proto, 0}})) break;
			if (portSessionDPI(session, (TDPIKey){{key->destIP, key->destPort, key->proto, 0}})) break;
		} while (false);

	if (time) {
		session->b = time;
		session->e = time;
		sodero_pointer_add(getFreshStreams(), session);
	}

	sodero_table_replace(getSessions(), session);
	sodero_session_insert(getSessionManager(), (PSoderoSession) session);
}

void newApplication(PSoderoApplication application, PSoderoSession owner) {
	application->id = random();
	application->owner = owner;
	application->serial = gTotal.count;
//	application->flag = owner->flag;
	((PSoderoID)&application->id)->type = owner->flag;
}

///////////////////////////////////////////////////////////////////////////////////////////////////


void sodero_drop_session(PSoderoSession session) {
//	printf("Drop session: %p\n", session);
	sodero_table_remove(getSessions(), key_of_sesson(session));
	freeSession(session);
}


void updatePortSession(PSoderoPortSession session, int dir, int size, int length, unsigned long long time) {
	if (time)
		session->e = time;
	processDV(&session->l2, length, dir);
	processDD(&session->traffic, size, dir);
}

