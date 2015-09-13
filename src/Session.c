/*
 * Session.c
 *
 *  Created on: Jul 15, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "Type.h"
#include "Common.h"
#include "Session.h"

const char * error_cause_name(int cause) {
	switch(cause) {
	case CAUSE_PACKET_INVALID_SESSION:
		return "session";
	case CAUSE_PACKET_INVALID_SYN:
		return "syn";
	case CAUSE_PACKET_INVALID_ACK:
		return "ack";
	}
	return "unknown";
}

const char * creat_cause_name(int cause) {
	switch(cause) {
	case CAUSE_SESSION_CREAT_NORMAL:
		return "normal";
	case CAUSE_SESSION_CREAT_ABORT:
		return "abort";
	case CAUSE_SESSION_CREAT_FAILURE:
		return "failure";
	}
	return "unknown";
}

const char * close_cause_name(int cause) {
	switch(cause) {
	case CAUSE_SESSION_CLOSE_NORMAL:
		return "normal";
	case CAUSE_SESSION_CLOSE_TIMEOUT:
		return "timeout";
	case CAUSE_SESSION_CLOSE_RESET:
		return "rest";
	case CAUSE_SESSION_CLOSE_ABORT:
		return "abort";
	case CAUSE_SESSION_CLOSE_BROKEN:
		return "broken";
	}
	return "unknown";
}

const char * tcp_application_name(int type) {
	switch(type) {
		case SESSION_TYPE_MINOR_TCP:
			return "TCP";
		case SESSION_TYPE_MINOR_HTTP:
			return "HTTP";
		case SESSION_TYPE_MINOR_HTTPS:
			return "HTTPS";
		case SESSION_TYPE_MINOR_UNKNOWN:
			return "Unknown";
	}
	return nullptr;
}

const char * udp_application_name(int type) {
	switch(type) {
		case SESSION_TYPE_MINOR_UDP:
			return "UDP";
		case SESSION_TYPE_MINOR_DNS:
			return "DNS";
		case SESSION_TYPE_MINOR_UNKNOWN:
			return "Unknown";
	}
	return nullptr;
}

const char * application_name(int protocol, int type) {
	switch (protocol) {
	case IPv4_TYPE_ICMP:
		return "ICMP";
	case IPv4_TYPE_TCP:
		return tcp_application_name(type);
	case IPv4_TYPE_UDP:
		return udp_application_name(type);
	}
	return nullptr;
}

int get_session_type(TObject object) {
	return sodero_session_type(object);
}

void set_session_type(TObject object, int type) {
	sodero_session_type(object) = type;
}

void merge_flow_datum(PSoderoFlowDatum total, PSoderoFlowDatum value) {
	total->bytes += value->bytes;
	total->count += value->count;
}

void merge_packet_datum(PSoderoPacketDatum total, PSoderoPacketDatum value) {
	merge_flow_datum(&total->total , &value->total );
	merge_flow_datum(&total->b___64, &value->b___64);
	merge_flow_datum(&total->b__128, &value->b__128);
	merge_flow_datum(&total->b__256, &value->b__256);
	merge_flow_datum(&total->b__512, &value->b__512);
	merge_flow_datum(&total->b_1024, &value->b_1024);
	merge_flow_datum(&total->b_1514, &value->b_1514);
	merge_flow_datum(&total->b_1518, &value->b_1518);
	merge_flow_datum(&total->bjumbo, &value->bjumbo);
}

void merge_packet_detail(PSoderoDoubleDetail total, PSoderoDoubleDetail value) {
	merge_packet_datum(&total->incoming, &value->incoming);
	merge_packet_datum(&total->outgoing, &value->outgoing);
}

unsigned long long count_of_datum(PSoderoDoubleDatum value) {
	return value->incoming.count + value->outgoing.count;
}

unsigned long long bytes_of_datum(PSoderoDoubleDatum value) {
	return value->incoming.bytes + value->outgoing.bytes;
}

unsigned long long count_of_detail(PSoderoDoubleDetail value, int index) {
	return value->incoming.ranks[index].count + value->outgoing.ranks[index].count;
}

unsigned long long bytes_of_detail(PSoderoDoubleDetail value, int index) {
	return value->incoming.ranks[index].bytes + value->outgoing.ranks[index].bytes;
}

PSoderoSession sodero_session_next(PSoderoSession session) {
	return session ? session->next : nullptr;
}

long sodero_session_timeout(PSoderoSession session, time_t tick) {
	return (long long) session->live - (long long) tick;
}

void sodero_initialize_session_manager(PSoderoSessionManager object, int count) {
	if (object) {
		object->count = count;

		if (object->count < SecsPerMin)
			object->count = SecsPerMin;

		size_t size = sizeof(*object->heads) * 2 * count;
		object->heads = takeBuffer(size);
		object->tails = takeBuffer(size);
		if (!object->heads || !object->tails) {
			if (object->heads) freeBuffer(object->heads);
			if (object->tails) freeBuffer(object->tails);
		}
		printf("Create session manager head & tail %lu bytes\n", size);
		bzero(object->heads, size);
		bzero(object->tails, size);
//		sodero_initialize_memory_pool(&object->pool, 16, 4 * 1024);
	}
}

void sodero_finalize_session_manager(PSoderoSessionManager object) {
	if (object) {
//		sodero_finalize_memory_pool(&object->pool);
		if (object->heads) freeBuffer(object->heads);
		if (object->tails) freeBuffer(object->tails);
	}
}

PSoderoSessionManager sodero_create_session_manager(int count) {
	PSoderoSessionManager result = takeBuffer(sizeof(*result));

	if (result) {
		bzero(result, sizeof(*result));
		sodero_initialize_session_manager(result, count);
		if (!result->heads || !result->tails) {
			freeBuffer(result);
			return nullptr;
		}
//		sodero_initialize_memory_pool(&result->pool, 16, 4 * 1024);
	}

	return result;
}

void sodero_destroy_session_manager(PSoderoSessionManager object) {
	if (object) {
		sodero_finalize_session_manager(object);
		freeBuffer(object);
	}
}

PSoderoSession sodero_session_append(PSoderoSessionManager object, PSoderoSession session, int offset) {
	int index = time_delta(session->live, object->tick);

//	printf("Insert %p @ %d plus %d\n", session, index, offset);

//	if (index <  0            ) return session;
//	if (index >= object->count) return session;

	if (index <  0            ) {
//		printf("Sodero session %p index overflow: %d\n", session, index);
		return session;
	}
	if (index >= object->count) {
//		printf("Sodero session %p index overflow: %d\n", session, index);
		return session;
	}

	index += offset;

	session->time = session->live + offset;

	if (!object->tails[index])
		object->tails[index] = session;

	session->prev = nullptr;
	session->next = object->heads[index];
	if (object->heads[index])
		object->heads[index]->prev = session;
	object->heads[index] = session;
	return nullptr;
}

size_t sodero_session_count(PSoderoSessionManager object) {
	return object->count;
}

PSoderoSession sodero_session_insert(PSoderoSessionManager object, PSoderoSession session) {
	return sodero_session_append(object, session, 0);
}

PSoderoSession sodero_session_find_next(PSoderoSession head, PSoderoSession item) {
	while(head) {
		if (head == item) return item;
		head = head->next;
	}
	return nullptr;
}

PSoderoSession sodero_session_find_prev(PSoderoSession head, PSoderoSession item) {
	while(head) {
		if (head == item) return item;
		head = head->prev;
	}
	return nullptr;
}

PSoderoSession sodero_session_remove(PSoderoSessionManager object, PSoderoSession session) {
	int index = time_delta(session->time, object->tick);

//	printf("Remove %p @ %d\n", session, index);

	if (index <  0            ) {
//		printf("Sodero session %p index overflow: %d\n", session, index);
		return nullptr;
	}
	if (index >= object->count) {
//		printf("Sodero session %p index overflow: %d\n", session, index);
		return nullptr;
	}
//	if (!sodero_session_find_next(object->heads[index], session)) {
//		printf("Sodero session %p find next failure\n", session);
//		for(int i = 0; i < object->count; i++) {
//			if (sodero_session_find_next(object->heads[i], session))
//				printf("Found head: %d\n", i);
//		}
//		return nullptr;
//	}
//	if (!sodero_session_find_prev(object->tails[index], session)) {
//		printf("Sodero session %p find prev failure\n", session);
//		for(int i = 0; i < object->count; i++) {
//			if (sodero_session_find_prev(object->tails[i], session))
//				printf("Found tail: %d\n", i);
//		}
//		return nullptr;
//	}

	if (session->prev)
		session->prev->next  = session->next;
	else do {
		if (object->heads[index] == session)
			object->heads[index] = session->next;
	} while (false);

	if (session->next)
		session->next->prev  = session->prev;
	else do {
		if (index <  0            ) break;
		if (index >= object->count) break;
		if (object->tails[index] == session)
			object->tails[index] = session->prev;
	} while (false);

	session->prev = nullptr;
	session->next = nullptr;

	return session;
}

PSoderoSession sodero_session_adjust(PSoderoSessionManager object, PSoderoSession session) {
//	printf("Adjust %p\n", session);
	return sodero_session_remove(object, session) ? sodero_session_insert(object, session) : session;
}

PSoderoSession sodero_session_clean(PSoderoSessionManager object) {
	PSoderoSession result = nullptr;
	for (int i = 0; i < object->count; i++) {
		PSoderoSession session = object->heads[i];
		while(session) {
			PSoderoSession curr = session;
			session = sodero_session_next(curr);

			curr->prev = nullptr;
			curr->next = result;
			if (result)
				result->prev = curr;
			result = curr;
		}
	}
	return result;
}

PSoderoSession sodero_session_check(PSoderoSessionManager object, unsigned long long tick) {
	PSoderoSession result = nullptr;
	unsigned int time = tick / uSecsPerSec;
	int step = time_delta(time, object->tick);
//	printf("Check manager %0.6f from %0.6f step %d\n", 1e-6*tick, 1e-6*object->tick, step);

	if (step > 0) {
//		if (step > 1)
//			printf("Session check step %d\n", step);

//		printf("Session step %d\n", step);

		if (step > object->count)
			step = object->count;

//		unsigned long long b = now();
//		unsigned int count = 0;
//		unsigned int total = 0;
		for (int i = 0; i < step; i++) {
			PSoderoSession session = object->heads[i];
//			if (session)
//				count++;
			while(session) {
//				total++;
				PSoderoSession curr = session;
				session = sodero_session_next(curr);

				if (sodero_session_timeout(curr, time) > 0)
					curr = sodero_session_append(object, curr, step);

				if (curr) {
					curr->prev = nullptr;
					curr->next = result;
					if (result)
						result->prev = curr;
					result = curr;
				}
			}
		}

		object->tick = time;
		memmove(object->heads, object->heads + step, object->count * sizeof(*object->heads));
		memmove(object->tails, object->tails + step, object->count * sizeof(*object->tails));
		bzero(object->heads + object->count, step * sizeof(*object->heads));
		bzero(object->tails + object->count, step * sizeof(*object->tails));

//		unsigned long long e = now();
//
//		printf("Session check in %.3f %u/%u\n", 1e-6*(e-b), count, total);
	}
	object->tick = time;
	return result;
}

long sodero_session_foreach(PSoderoSessionManager object, TSessionTimeoutHandlor handlor, void * data) {
	long result = 0;
	for (unsigned int i = 0; i < object->count; i ++) {
		PSoderoSession session = object->heads[i];
		while(session) {
			PSoderoSession curr = session;
			session = sodero_session_next(curr);

			if (handlor(object, result++, curr, data) < 0) return -result;
		}
	}
	return result;
}

long sodero_port_hasher(PPortKey key) {
	return key->sourIP + key->destIP + key->destPort + key->sourPort;
}

long sodero_port_equaler(PPortKey a, PPortKey b) {
	if ((a->destIP == b->destIP) && (a->sourIP == b->sourIP) && (a->destPort == b->destPort) && (a->sourPort == b->sourPort)) return 0;
	if ((a->destIP == b->sourIP) && (a->sourIP == b->destIP) && (a->destPort == b->sourPort) && (a->sourPort == b->destPort)) return 0;
	return a - b;
}
