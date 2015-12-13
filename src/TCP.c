/*
 * TCP.c
 *
 *  Created on: Sep 14, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Type.h"
#include "Parameter.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "Stream.h"
#include "Logic.h"
#include "Core.h"
#include "TCP.h"
#include "MySQL.h"
#include "Tns.h"

TSoderoTCPSet gDefaultTCPProto = {
		.l = ((1 <<SESSION_SET_L_MYSQL) | (1 <<SESSION_SET_L_ORACLE)),
		.h = 0
};


///////////////////////////////////////////////////////////////////////////////////////////////////


//	length must great than value->length, and base must less than value->offset + size
int mergeData(unsigned char * buffer, unsigned int length, PSoderoTCPValue value,
		unsigned int offset, const unsigned char * data, int size) {
	if (offset > value->offset + size         ) return -1;
	if (length < value->offset + size - offset) return -1;

	if (offset > 0) {
		int bytes = value->offset - offset;
		if (bytes > 0) {
			memcpy(buffer, value->buffer + offset, bytes);
			buffer += bytes;
			length -= bytes;
			bytes = 0;
		}

		memcpy(buffer, data - bytes, size + bytes);
		return value->offset + size - offset;
	}

	memcpy(buffer, value->buffer, value->offset);
	buffer += value->offset;
	length -= value->offset;
	memcpy(buffer, data, size);
	return value->offset + size;
}

int pickData(unsigned char * buffer, unsigned int length, PSoderoTCPValue value,
		unsigned int offset, const unsigned char * data, int size) {
	if (offset > value->offset + size         ) return -1;

	int result = 0;
	int bytes = value->offset - offset;
	if (bytes > 0) {
		result = bytes > length ? length : bytes;
		memcpy(buffer, value->buffer + offset, result);
		if (result >= length) return result;
		buffer += result;
		length -= result;
		bytes = 0;
	}
	if (bytes < 0) {
		data -= bytes;
		size += bytes;
	}
	if (length > size)
		length = size;

	memcpy(buffer, data, length);
	return result + length;
}

int pickLine(unsigned char * buffer, unsigned int length, PSoderoTCPValue value,
		unsigned int offset, const unsigned char * data, unsigned int size) {
//	unsigned int result = 0;
//	for (unsigned int i = offset; i < value->offset; i++) {
//		char c = value->buffer[i];
//		buffer[result++] = c;
//		if (c == LF) return result;
//	}
//
//	offset = value->offset - (offset + result);

	int result = value->offset - offset;
	if (result > 0) {
		if (result >= 1024)
			result = 1023;
		memcpy(buffer, value->buffer + offset, result);
		offset = 0;
	} else {
		result = 0;
		offset -= value->offset;
	}

	if (result >= 1024)
			result = 1023;

	for (unsigned int i = offset; i < size; i++) {
		char c = data[i];
		if (result >= 1024)
			result = 1023;
		buffer[result++] = c;
		if (c == LF) return result;
	}
	return 0;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


TContainerKey sodero_tcp_keyof(PSoderoTCPSession session) {
	return &session->key;
}

void sodero_tcp_cleaner(TObject item) {
	if (item)
		bzero(item, sizeof(TSoderoTCPSession));
}

TObject sodero_tcp_creater(PSoderoContainer map) {
	TObject result = takeSession(sizeof(TSoderoTCPSession));
	sodero_tcp_cleaner(result);
	return result;
}

void sodero_tcp_releaser(PSoderoContainer map, TObject item) {
	freeSession(item);
}

long sodero_tcp_session_handlor(int index, PSoderoTCPSession result, void * data) {
	return 0;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


PSoderoContainer createTCPSession(void) {
	return sodero_container_create(DEFAULT_TCP_LENGTH, DEFAULT_TCP_DELTA, DEFAULT_TCP_SIZE, nullptr,	//	DEFAULT_PARAMETER
				(THashHandlor) sodero_ipport_hasher, (TEqualHandlor) sodero_ipport_equaler, (TKeyDuplicator) sodero_ipport_duplicator
#ifdef __CONTAINER_KEY__
				, (TSoderoObjectKey) sodero_tcp_keyof
#endif
				);
}


///////////////////////////////////////////////////////////////////////////////////////////////////


PSoderoTCPSession sodero_session_2_tcp(PSoderoSession object) {
	return get_session_type(object) == SESSION_TYPE_MAJOR_TCP ? (PSoderoTCPSession) object : nullptr;
}

PSoderoTCPSession newTCPSession(PPortKey key, int timeout, unsigned char state, PEtherHeader ether) {
	PSoderoTCPSession result = takeSession(sizeof(TSoderoTCPSession));
	newPortSession((PSoderoPortSession)result, key, timeout, state, ether, gTime);

	result->value.turns_min_time = 0xFFFFFFFFFFFFFFFFULL;
	result->value.turns_max_time = 0x0000000000000000ULL;
	result->value.turns_min_interval = 0xFFFFFFFFFFFFFFFFULL;
	result->value.turns_max_interval = 0x0000000000000000ULL;
	result->value.turns_min_bytes = 0xFFFFFFFFFFFFFFFFULL;
	result->value.turns_max_bytes = 0x0000000000000000ULL;
	result->value.incoming.length = sizeof(result->value.incoming.buffer);
	result->value.outgoing.length = sizeof(result->value.outgoing.buffer);
	result->value.set = gDefaultTCPProto;

	return result;
}

void counterTCPFlag(PSoderoTCPCounter counter, PTCPHeader header) {
	if (header->syn) {
		if (header->ack)
			counter->ackCount++;
		else
			counter->synCount++;
	}

	if (header->fin)
		counter->finCount++;

	if (header->rst)
		counter->rstCount++;

	if (header->urg)
		counter->urgCount++;

	if (header->ecn)
		counter->ecnCount++;

	if (header->cwr)
		counter->cwrCount++;
}

int isRetransmitionSequence(unsigned int o, unsigned n) {
	return (n - o) > 0x7FFFFFFFU;
}

static inline
int isRetransmitionSYN(PSoderoTCPSession session, unsigned int sequence) {
	return (session->state <  SODERO_TCP_ESTABLISHED) && (session->value.incoming.seq == sequence);
}

static inline
int isRetransmitionACK(PSoderoTCPSession session, unsigned int sequence) {
	return (session->state <= SODERO_TCP_ESTABLISHED) && (session->value.outgoing.seq == sequence);
}

int isRetransmition(PSoderoTCPSession session, unsigned int sequence, int dir) {
	switch(dir) {
	case DIR_SERVER:
		return isRetransmitionSequence(session->value.outgoing.seq, sequence);
	case DIR_CLIENT:
		return isRetransmitionSequence(session->value.incoming.seq, sequence);
	}
	return 0;
}

PSoderoTCPValue streamValue(PSoderoTCPSession session, int dir) {
	if (dir < 0)
		return &session->value.incoming;
	if (dir > 0)
		return &session->value.outgoing;
	return nullptr;
}

static inline
int seqOffset(unsigned int base, unsigned int curr) {
	return (int)(curr - base);
}

PSoderoTCPSession processTCPSYN(PSoderoTCPSession session, PPortKey key, PEtherHeader ether, unsigned int seq, unsigned ack) {
	if (session) {
		session->value.incoming.synCount++;
		//	ACK with session
		if (isRetransmitionSYN(session, seq)) {
			//	Same TCP Session, reuse session
			if (isExportVerbose())
				printf("TCP session %p SYN Retransmit\n", session);
		} else {
			new_ipport_event(IPv4_TYPE_TCP, SODERO_LOG_SESSION_CLOSE, key, session, CAUSE_SESSION_CLOSE_BROKEN);
			//	ToDo: Drop Old Session

			//	Create New Session
			session = newTCPSession(key, gTCPOpeningTime, SODERO_TCP_SYN, ether);
			session->value.outgoing.seq = seq;
			session->value.synTime = gTime;
		}
	} else {
		//	Create new session
		session = newTCPSession(key, gTCPOpeningTime, SODERO_TCP_SYN, ether);
		session->value.outgoing.seq = seq;
		session->value.synTime = gTime;
	}
	return session;
}

PSoderoTCPSession processTCPACK(PSoderoTCPSession session, PPortKey key, PEtherHeader ether, unsigned int seq, unsigned ack) {
//	printf("Session %d seq %x/%x - %x\n", session->state, session->value.outgoing.seq, session->value.incoming.seq, ack);

	PSoderoTCPPeriodResult result = &getPeriodResult()->protocol.l4.tcp;
	if (session) {
		session->value.incoming.ackCount++;
		if (session->state == SODERO_TCP_SYN) {
			if (session->value.outgoing.seq + 1 == ack) {
				//	SYN-ACK with SYN and correct seq, it's normal.
				resetSessionLive(session, gTime + gTCPOpeningTime);
				session->state =  SODERO_TCP_ACK;
				session->value.outgoing.ack =  ack;
				session->value.incoming.seq =  seq;
			} else {
				//	Bad seq, drop packet
				new_ipport_event(IPv4_TYPE_TCP, SODERO_LOG_PACKET_ERROR, key, session, CAUSE_PACKET_INVALID_ACK);
				result->counter.ackBroken++;
			}
		} else {
			//	SYN-ACK without SYN state
			if (isRetransmitionACK(session, seq)) {
				//	I's okay, so use this session
				if (isExportVerbose())
					printf("TCP session %p ACK Retransmit\n", session);
			} else {
				//	Bad state, drop packet
				new_ipport_event(IPv4_TYPE_TCP, SODERO_LOG_PACKET_ERROR, key, session, CAUSE_PACKET_INVALID_ACK);
				result->counter.ackBroken++;
			}
		}
	} else {
		//	ACK without session
		result->counter.synBroken++;
		new_ipport_event(IPv4_TYPE_TCP, SODERO_LOG_PACKET_ERROR, key, session, CAUSE_PACKET_INVALID_SESSION);
	}
	return session;
}

void processTCPFIN(PSoderoTCPSession session, PPortKey key, PEtherHeader ether,
		unsigned int seq, unsigned int ack, int dir, unsigned char fin, unsigned char rst) {
	//	The begin of TCP demolish chain
	//	Demolish chain
//	printf("FIN %u.%u.%u.%u -> %u.%u.%u.%u\n", key->s[0], key->s[1], key->s[2], key->s[3], key->d[0], key->d[1], key->d[2], key->d[3]);
	switch (session->state) {
		case SODERO_TCP_ESTABLISHED: {
			session->state = SODERO_TCP_WAITING;
			resetSessionLive(session, gTime + gTCPClosingTime);
			session->cause = dir;
			new_ipport_event(IPv4_TYPE_TCP, SODERO_LOG_SESSION_CLOSE, key, session, CAUSE_SESSION_CLOSE_NORMAL);

			PNodeValue sourNode = takeIPv4Node((TMACVlan){{ether->sour, ether->vlan}}, key->sIP);
			PNodeValue destNode = takeIPv4Node((TMACVlan){{ether->dest, ether->vlan}}, key->dIP);
			if (isExportVerbose())
				printf("TCP Disconnect @ %p & %p\n", sourNode, destNode);

			if (sourNode) sourNode->counter.tcp.outgoing.disconectedCount++;
			if (destNode) destNode->counter.tcp.incoming.disconectedCount++;
			break;
		}

		case SODERO_TCP_WAITING:
			if (!(session->cause + dir)) {
				session->state = SODERO_TCP_CLOSED;
			} else {
				//	fin or rst retransmition
			}
			break;
		case SODERO_TCP_CLOSED:
			//	fin or rst retransmition
			break;
		default:
			//	Demolish chain before handshake success
			session->state = SODERO_TCP_WAITING;
			resetSessionLive(session, gTime + gTCPClosingTime);
			session->cause = dir;
			new_ipport_event(IPv4_TYPE_TCP, SODERO_LOG_SESSION_CLOSE, key, session, CAUSE_SESSION_CLOSE_NORMAL);
			break;
	}

	//	Data Packet
	if (session->state == SODERO_TCP_ESTABLISHED)
		resetSessionLive(session, gTime + gTCPClosingTime);

	PSoderoTCPValue value = streamValue(session, dir);
	if (!value) return;
	if (fin && (value->finCount < 0xFF))
		value->finCount++;
	if (rst && (value->rstCount < 0xFF))
		value->rstCount++;
}

void counterTCPNode(PSoderoTCPSession session, PPortKey key, PEtherHeader ether, int size, int length) {
	TServiceIndex sourIndex = {.node = {.value = {((TMACVlan){{0, ether->vlan}}).value, key->sIP.ip, 0}}, session->key.destPort};
	TServiceIndex destIndex = {.node = {.value = {((TMACVlan){{0, ether->vlan}}).value, key->dIP.ip, 0}}, session->key.destPort};
	PSoderoDoubleDatum sourService = takeServiceNode(&sourIndex);
	PSoderoDoubleDatum destService = takeServiceNode(&destIndex);
	if (sourService) processA(&sourService->outgoing, size);
	if (destService) processA(&destService->incoming, size);
	PNodeValue sourNode = takeIPv4Node((TMACVlan){{ether->sour, ether->vlan}}, key->sIP);
	PNodeValue destNode = takeIPv4Node((TMACVlan){{ether->dest, ether->vlan}}, key->dIP);

	if (isExportVerbose())
		printf("TCP Connect @ %p & %p\n", sourNode, destNode);

	if (session->state == SODERO_TCP_CLOSED) {
		if (sourNode) sourNode->counter.tcp.outgoing.connectedCount++;
		if (destNode) destNode->counter.tcp.incoming.connectedCount++;
	}
}

int isSessionHandshaked(PSoderoTCPSession session, PPortKey key, unsigned int ack) {
	return (session->state == SODERO_TCP_ACK) && (session->value.incoming.seq + 1 == ack) && isSameDir(&session->key.ipPair, &key->ipPair);
}

PSoderoTCPSession processTCPHandshake(PSoderoTCPPeriodResult result, PTCPHeader tcp, int size,
	PPortKey key, PEtherHeader ether, unsigned int seq, unsigned int ack) {

	PSoderoTCPSession session = sodero_table_lookup(getSessions(), key);

	if (tcp->syn) {
//		if (isExportVerbose())
//			printf("TCP: %p SYN - %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n", session,
//					key.s[0], key.s[1], key.s[2], key.s[3], ntohs(key.sourPort), key.d[0], key.d[1], key.d[2], key.d[3], ntohs(key.destPort));

		if (size > 0) {
			result->counter.synMalformed++;
			new_ipport_event(IPv4_TYPE_TCP, SODERO_LOG_PACKET_ERROR, key, session, CAUSE_PACKET_INVALID_SYN);
			return nullptr;
		}

		return tcp->ack ?	//	SYN Packet must not contain data.
				processTCPACK(session, key, ether, seq, ack)	//	SYN-ACK	Second Packet, session must exist.
			:
				processTCPSYN(session, key, ether, seq, ack);	//	SYN only - First Packet, must create a new session.
	}

	if (session) {
		//	Must not include SYN, at least the third packet, TCP connection handshake success.
		if (session->state < SODERO_TCP_ESTABLISHED) {
			//	Need: correct state[SODERO_TCP_ACK], correct seq, correct dir[DIR_CLIENT], and ack flag[almost always]
			if (isSessionHandshaked(session, key, ack)) {
				//	Three-way handshake is completed, obtain TCP establish time.
//				printf("Session %d seq %x/%x - %x", session->state, session->value.outgoing.seq, session->value.incoming.seq, ack);

				session->value.conTime = gTime;
				session->value.incoming.ack = ack;

				session->value.incoming.seq++;
				session->value.outgoing.seq++;

				new_ipport_event(IPv4_TYPE_TCP, SODERO_LOG_SESSION_CREAT, key, session, CAUSE_SESSION_CREAT_NORMAL);
			} else {
				if (session->value.incoming.seq)
					session->value.incoming.seq++;
				if (session->value.outgoing.seq)
					session->value.outgoing.seq++;
			}
			session->state =  SODERO_TCP_ESTABLISHED;
		}
	} else {
		//	Create new session by data packet
		session = newTCPSession(key, gTCPActivedTime, SODERO_TCP_ESTABLISHED, ether);
		session->value.conTime = gTime;
		session->value.incoming.ack = ack;
		session->value.outgoing.seq = seq;
	}

	return session;
}

void processTCPDemolish(PSoderoTCPSession session, PTCPHeader tcp, int size,
		PPortKey key, PEtherHeader ether, int dir, unsigned int seq, unsigned int ack) {
	if (tcp->fin || tcp->rst) {
		processTCPFIN(session, key, ether, seq, ack, dir, tcp->fin, tcp->rst);
	}
}

void processTCPOptions(PTCPHeader tcp, PTCPOption option) {
	int size = tcp->size * 4 - sizeof(*tcp);
	const unsigned char * data = (unsigned char *) (tcp+1);

	//	http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
	while (size > 0) {
		PTCPOValue value = (PTCPOValue) data;
		switch(value->type) {
			case 0x00:		//	-	End of Option
			case 0x01:		//	-	No-Option
				data++;
				size--;
				continue;
			case 0x02: {	//	4	MSS
				option->mss = *(unsigned short *)(value+1);
//				printf("TCP Option: Maximum segment size: %u\n", ntohs(option->mss));
				break;
			}
			case 0x03: {	//	3	Window scale
				option->shift = 0x0F & *(unsigned char *)(value+1);
//				printf("TCP Option: Windows shift %u scale %u\n", shift, 1 << shift);
				break;
			}
			case 0x04: {	//	2	SACK Permitted Option: True
				break;
			}
			case 0x05: {	//	N	SACK
				option->count = (value->size - 2) /sizeof(TTCPOSACK);
				PTCPOSACK acks = (PTCPOSACK)(value+1);
				for (int i = 0; i < option->count; i++) {
					option->acks[i] = (TTCPOSACK){ntohl(acks[i].l), ntohl(acks[i].r)};
//					option->acks[i].l = ntohl(acks[i].l);
//					option->acks[i].r = ntohl(acks[i].r);
//					printf("TCP Option: SACK %u to %u\n", );
				}
				break;
			}
			case 0x08: {	//	Timestamps
				PTCPOTimeStamp ts = (PTCPOTimeStamp)(value+1);
				option->stamp = ntohl(ts->value), ntohl(ts->replay);
//				printf("TCP Option: Time Stamp - %u to %u\n", ntohl(ts->value), ntohl(ts->replay));
				break;
			}
			//	scarce
//			case 0x10:	//		Skeeter
//			case 0x11:	//		Bubba
//			case 0x12:	//	3	Trailer Checksum Option
//			case 0x14:	//		SCPS Capabilities
//			case 0x15:	//		Selective Negative Acknowledgements
//			case 0x16:	//		Record Boundaries
//			case 0x17:	//		Corruption experienced
//			case 0x18:	//		SNAP
//			case 0x19:	//		Unassigned (released 2000-12-18)
//			case 0x1a:	//		TCP Compression Filter
//			case 0x1b:	//	8	Quick-Start Response
//			case 0x1c:	//	4	User Timeout Option (also, other known unauthorized use)
//			case 0x1d:	//		TCP Authentication Option (TCP-AO)	[RFC5925]
//			case 0x1e:	//	N	Multipath TCP (MPTCP)
//				break;
//			case 0x22:	//	TCP Fast Open Cookie
//				break;
//			case 0xfd:	//	N	RFC3692-style Experiment 1 (also improperly used for shipping products)
//			case 0xfe:	//	N	RFC3692-style Experiment 2 (also improperly used for shipping products)
//				break;
			//	obsoleted
//			case 0x06:	//	6	Echo	obsoleted by option 8
//			case 0x07:	//	6	Replay	obsoleted by option 8
//			case 0x09: 	//	2	Partial Order Connection Permitted (obsolete)
//			case 0x0a:	//	2	Partial Order Connection Permitted (obsolete)
//			case 0x0b:	//		CC (obsolete)
//			case 0x0c:	//		CC.NEW (obsolete)
//			case 0x0d:	//		CC.ECHO (obsolete)
//			case 0x0e:	//	3	TCP Alternate Checksum Request (obsolete)
//			case 0x0f:	//	N	TCP Alternate Checksum Data (obsolete)
//			case 0x13:	//	18	MD5 Signature Option (obsoleted by option 29)
			default:
//				printf("Option: %x\n", value->type);
				return;
		}
		data += value->size;
		size -= value->size;
	}

	if (tcp->flag & TCP_FLAG_SYN_RST_FIN)
		option->window = -1;
	else
		option->window <<= option->shift;
}

int isAnswer(unsigned int seq, unsigned int ack, PTCPOption option) {
	if (seqOffset(seq, ack) >= 0) return true;
	for (int i = 0; i < option->count; i++) {
		if (seqOffset(ack, option->acks[i].l) < 0) continue;
		if ((seqOffset(option->acks[i].l, seq) > 0) && (seqOffset(seq, option->acks[i].r)) > 0) return true;
	}
	return false;
}

void updateTCPSessionRTT(PSoderoTCPSession session, PTCPHeader tcp, int dir, unsigned seq, unsigned int ack, PTCPState state) {
	PSoderoTCPValue value = streamValue(session, dir);
	if (!value) return;

	if (!value->rcv_wnd_throttles) {
		if (!value->ack)
			value->ack = ack;

		PSoderoTCPValue other = streamValue(session, -dir);
		if (!other->seq)
			other->seq = seq;
	}

	state->option.window = ntohs(tcp->window);

	processTCPOptions(tcp, &state->option);
	if (state->option.window >= 0) {
		if (state->option.window == 0)
			value->zwnds++;

		if (value->rcv_wnd_throttles < state->option.window)
			value->rcv_wnd_throttles = state->option.window;
	}

	if (seqOffset(value->ack, ack) < 0) return;

	//	Check ACK queue for RTT
	int count = 0;
	while(value->size > 0) {
		PSoderoTCPACK item = &value->acks[value->base];

		if (!isAnswer(item->seq, ack, &state->option)) break;

		long long diff = gTime - item->time;
		if (diff > 0) {
			state->rtt++;
			state->rttTime += diff;
		}
		value->base = step_plus(value->base, TCP_ACK_QUEUE_SIZE);
		value->size--;
		count++;
	}
	value->rttCount += state->rtt;
	value->rttValue += state->rttTime;

//	if (count)
//		printf("No %.8llu: ACK %d from %.8x to %.8x\n", gPacket, count, value->ack, ack);

	if (seqOffset(value->ack, ack) == 0) return;

	value->ack = ack;

	//	Check the ordering queue, delete those data blocks that SEQ less than ACK.
	//	Receive ACK, meaning its data has arrived. Packet loss in the capture time, is an unrecoverable error.
	if (value->count) {
		int i = 0;
		//	Continue process reorder buffer
		while(i < value->count) {
			PSoderoStreamBlock block = value->block[i];
			int length = seqOffset(block->seq + block->size, ack);
			if (length >= 0) {
#ifdef __EXPORT_STATISTICS__
				gCleanBlock++;
#ifdef __EXPORT_DUMP_BLOCK__
				if (gDump)
					fprintf(gDump, "free clean block %p of %p - %p @ index %d\n", block, session, value, i);
#endif
#endif
				freeBlock(block);	//	delete direct
				i++;
				continue;	//	Check Next Block
			}
			gCleanSkiped++;
			break;
		}

		if (i > 0)	{	//	some block be dropped, so pack queue
//			printf("No %.8llu: drop %d unorder block\n", gPacket, i);

			memmove(value->block, value->block + i, sizeof(*value->block) * (value->count - i));
			value->count -= i;
			bzero(value->block + value->count, sizeof(*value->block) * i);
		}
	}
}

void updateTCPValue(PSoderoTCPValue value, unsigned int seq) {

	if (value->time) {
		unsigned long long diff = gTime - value->time;
		if (diff > 0) {
			if (value->nagle_delays > diff)
				value->nagle_delays = diff;
		}
	} else {
		value->time = gTime;
		value->nagle_delays = 0xFFFFFFFF;
	}

	//	Insert ACK in queue?
	for (int i = 0; i < value->size; i++) {
		unsigned char index = value->base + i;
		if (index >= TCP_ACK_QUEUE_SIZE)
			index -= TCP_ACK_QUEUE_SIZE;

		PSoderoTCPACK item = &value->acks[index];

		int offset = seqOffset(item->seq, seq);
		if (!offset) return;	//	same seq
		if (offset < 0) {
			//	Found insert position
//			if (i == 0) {
//				//	Before the head of the queue, retransmition.
//				printf("No %.8llu: drop ACK %.8x @ %u(%u/%u)\n", gPacket, seq, index, value->base, value->size);
//			}

//			printf("No %.8llu: insert ACK %.8x @ %u(%u/%u)\n", gPacket, seq, index, value->base, value->size);
			//	i > 0
			if (value->size < TCP_ACK_QUEUE_SIZE) {	//	queue is not full?
				//	No.
				item->seq  = seq  ;
				item->time = gTime;
				value->size++;
			} else {
				//	Yes.
				if (index >= value->base) {
					memmove(&value->acks[value->base], &value->acks[value->base+1], (index - value->base) * sizeof(TSoderoTCPACK));
				} else {
					memmove(&value->acks[index], &value->acks[index+1], (value->base - index) * sizeof(TSoderoTCPACK));
					value->base = step_plus(value->base, TCP_ACK_QUEUE_SIZE);
				}
				item->seq  = seq  ;
				item->time = gTime;
			}
			return;
		}
	}

	//	Append at queue tail
	unsigned char index = value->base + value->size;
	if (index >= TCP_ACK_QUEUE_SIZE)
		index -= TCP_ACK_QUEUE_SIZE;

//	printf("No %.8llu: append ACK %.8x @ %u(%u/%u)\n", gPacket, seq, index, value->base, value->size);

	PSoderoTCPACK item = &value->acks[index];
	item->seq  = seq  ;
	item->time = gTime;

	if (value->size < TCP_ACK_QUEUE_SIZE)	//	queue is not full?
		value->size++;	//	No.
	else {
		value->base = step_plus(value->base, TCP_ACK_QUEUE_SIZE);	//	Yes
		value->rttDropped++;
	}
}

void restartStream(PSoderoTCPSession session, int dir, PSoderoTCPValue value, unsigned int seq) {

	int bytes = seqOffset(value->seq, seq);
	if (bytes > 0) {
		value->missedBytes += bytes;
		if (session->flag <= SESSION_TYPE_MINOR_CUSTOM) {
			int result = 0;
			switch(session->flag) {
				case SESSION_TYPE_MINOR_HTTP:
					result = skipHTTPPacket(session, dir * session->key.dir, bytes);
					break;
				case  SESSION_TYPE_MINOR_MYSQL:
					result = skipMySQLPacket(session, dir * session->key.dir, bytes);
					break;
				case SESSION_TYPE_MINOR_CUSTOM:
					break;
				default:
					result = PARSE_ERROR;
					break;
			}

			if (result < 0) {
				//	Process ERROR, ignore current session
//				printf("Process TCP restart %d @ %p\n", result, session);
				session->flag = SESSION_TYPE_MINOR_UNKNOWN;
			}

			//	drop all bytes in buffer;
			value->offset = 0;
		}
	}

	// ToDo: else tcp error?
	value->seq = seq;
}

int appendData(PSoderoTCPValue value, const unsigned char * data, int size) {
	int drop = value->offset + size - value->length;

	if (size >= value->length) {
		memcpy(value->buffer, data + drop, value->length);
		value->offset = value->length;

		goto APPEND_OVER;
	}

	//	available buffer size
	int byte = value->length - value->offset;

	//	availbale > want
	if (byte > size) {
		byte = size;
		drop = 0;
	}

	//	want > availble
	if (byte < size) {
		byte = size;
		memmove(value->buffer, value->buffer + drop, value->offset - drop);
		value->offset -= drop;
	}

	if (byte > 0) {
		memcpy(value->buffer + value->offset, data, byte);
		value->offset += byte;
	}

APPEND_OVER:
	value->http = value->http > drop ? value->http - drop : 0;
	return drop;
}

int detectTCP(PSoderoTCPSession session, PSoderoTCPValue value,
		const unsigned char * data, unsigned int size,int length,
		int dir, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {
	//	Detect Application must use valu's buffer
	if ((session->value.set.l&(1 << SESSION_SET_L_ORACLE)) | session->value.set.h)
	do {
	       int byte = detectTNS(session, value, 0, data, size, dir, tcp, ip, ether);
		if (byte > 0) {
			session->flag = SESSION_TYPE_MINOR_ORACLE;
			return byte;
		}
		if (byte < 0) {
			session->value.set.l &= ~ (1 << SESSION_SET_L_ORACLE);
		}
	}while (false);
	if ((session->value.set.l&(1 << SESSION_SET_L_MYSQL)) | session->value.set.h)
	do {
		int byte = detectMySQL(session, value, 0, data, size, dir, tcp, ip, ether);
		if (byte > 0) {
			session->flag = SESSION_TYPE_MINOR_MYSQL;
			return byte;
		}
		if (byte < 0) {
			session->value.set.l &= ~ (1 << SESSION_SET_L_MYSQL);
		}
		
	} while (false);
	

	//	Always check http
	int total = value->offset + size;
	while(value->http < total) {
		int byte = detectHTTP(session, value, value->http, data, size, length, dir, tcp, ip, ether);
		if (byte > 0) {
			session->flag = SESSION_TYPE_MINOR_HTTP;
			((PSoderoID)&((PSoderoApplicationHTTP)session->session)->id)->type = session->flag;
			return byte;
		}
		if (byte < 0) {
			value->http -= byte;
			continue;
		}
		//	byte is zero, pending
		break;
	}
	//	All protocols identification failure.
	return 0;
}

void processTCPData(PSoderoTCPSession session, int dir, PSoderoTCPValue value,
		const unsigned char * data, unsigned int size, int length,
		PTCPState state, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {
//	printf("No %.8llu process %u bytes @ %.8x\n", gPacket, size, value->seq);

	value->streamBytes += size;
	value->seq += size;

	if (session->flag == SESSION_TYPE_MINOR_UNKNOWN) return;

#ifdef __SKIP_DETECT__
	session->flag = SESSION_TYPE_MINOR_UNKNOWN;
#else
	int base = 0;
	if (session->flag == SESSION_TYPE_MINOR_TCP) {
		base = detectTCP(session, value, data, size, length, dir, tcp, ip, ether);
		if (session->flag == SESSION_TYPE_MINOR_TCP)
		do {
			//	Not detected
			if (base > 0)
				break;
			if (base == 0) {
				int drop = appendData(value, data, size);
				//	If detect buffer is full, detect failure.
				if (drop == 0)
					return;
			}
			//	detect buffer overflow, disable all protocol except http
			session->value.set.l = 0;
			session->value.set.h = 0;
			//	set application to invalid and stop detect.
//			session->flag = SESSION_TYPE_MINOR_UNKNOWN;
			return;
		} while (false);

		//	Application detected
		session->key.dir = dir;
	}

	int result = 0;
	if (session->flag <= SESSION_TYPE_MINOR_CUSTOM) {
		switch(session->flag) {
			case SESSION_TYPE_MINOR_HTTP:
				result = processHTTPPacket(session, dir * session->key.dir, value, base, data, size,
					length, state, tcp, ip, ether);
				break;
			case  SESSION_TYPE_MINOR_MYSQL:
				result = processMySQLPacket(session, dir * session->key.dir, value, base, data, size,
					length, state, tcp, ip, ether);
				break;
		       case  SESSION_TYPE_MINOR_ORACLE:
				result = processTNSPacket(session, dir * session->key.dir, value, base, data, size,
					length, state, tcp, ip, ether);
				//value->offset = 0;
				break;
			case SESSION_TYPE_MINOR_CUSTOM:
				break;
			default:
//				printf("Invalid TCP flag %p\n", session);
				session->flag = SESSION_TYPE_MINOR_UNKNOWN;
				value->offset = 0;
				return;
		}

		if (result < 0) {
			//	Process ERROR, ignore current session
//			printf("Process TCP failure %d @ %p\n", gTotal.count, session);
			session->flag = SESSION_TYPE_MINOR_UNKNOWN;
			value->offset = 0;
			return;
		}

		result += base;

		//	Keep left bytes
		if (result > value->offset) {
			result -= value->offset;
			value->offset = 0;
		} else {
			memmove(value->buffer, value->buffer + result, value->offset - result);
			value->offset -= result;
			result = 0;
		}
		appendData(value, data + result, size - result);
	}
#endif
}

void reorderStream(PSoderoTCPSession session, int dir, PSoderoTCPValue value,
		PTCPState state, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {
	if (value->count) {
		int i = 0;
		//	Continue process reorder buffer
		while(i < value->count) {
			PSoderoStreamBlock block = value->block[i];
			int length = seqOffset(block->seq, value->seq);
			if (length >= 0) {	//	is some data left?
//				printf("No %.8llu: reorder block %u %.8x/%u with %.8x offset %d\n",
//					gPacket, i, block->seq, block->size, value->seq, length);

				if (length < block->size)
					processTCPData(session, dir, value, block->data + length, block->size - length,
						length, state, tcp, ip, ether);
#ifdef __EXPORT_STATISTICS__
				gReorderBlock++;
#ifdef __EXPORT_DUMP_BLOCK__
				if (gDump)
					fprintf(gDump, "free reorder block %p of %p - %p @ index %d\n", block, session, value, i);
#endif
#endif
				freeBlock(block);
				i++;
				continue;	//	Check Next Block
			}
			gReorderSkip++;
			break;
		}

		if (i > 0) {	//	Some block be processed, so pack queue
			memmove(value->block, value->block + i, sizeof(*value->block) * (value->count - i));
			value->count -= i;
			bzero(value->block + value->count, sizeof(*value->block) * i);
		}
	}
}


void updateSessionState(PSoderoTCPSession session, int dir, PTCPState state) {
	switch(session->flag) {
//		case SESSION_TYPE_MINOR_TCP:
//			return;
		case SESSION_TYPE_MINOR_HTTP:
			updateHTTPState(session, dir * session->key.dir, state);
			break;
		case SESSION_TYPE_MINOR_MYSQL:
			updateMySQLState(session, dir * session->key.dir, state);
			break;
		case SESSION_TYPE_MINOR_ORACLE:
			updateTnsState(session, dir * session->key.dir, state);
			break;
//		default:
//			return;
	}
}

int processStream(PSoderoTCPSession session, const void * data, int size, int length,
	int dir, unsigned int seq, PTCPState state, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {

	PSoderoTCPValue value = streamValue(session, dir);

	if (value->ack > value->seq) // if drop some packet, this session will be always wrong.
		value->seq = value->ack;

	if (!value) return 0;

	if (tcp->urg) {
		data += state->surgen;
		size -= state->surgen;
		value->urgBytes += state->surgen;
		value->urgCount ++;
	}

	updateSessionState(session, dir, state);

	if (size == 0) return 0;

	unsigned int ack = seq + size;		//	ack = current seq + payload

	if (seqOffset(value->seq, ack) <= 0) {
		value->droppedCount ++;	//	Too late to arrived, ToDo:	retransmition?
		value->droppedBytes += size;
		return 0;
	}

	if (session->value.turn != dir) {
		if (session->value.turnCount) {
			unsigned long long interval = (gTime - session->value.turnE) / uSecsPerMSec;
			unsigned long long duration = (session->value.turnE - session->value.turnB) / uSecsPerMSec;
			session->value.turns_count ++;
			session->value.turns_sum_time += duration;
			if (session->value.turns_min_time > duration)
				session->value.turns_min_time = duration;
			if (session->value.turns_max_time < duration)
				session->value.turns_max_time = duration;
			session->value.turns_sum_interval += interval;
			if (session->value.turns_min_interval > interval)
				session->value.turns_min_interval = interval;
			if (session->value.turns_max_interval < interval)
				session->value.turns_max_interval = interval;
			session->value.turns_sum_bytes += session->value.turnBytes;
			if (session->value.turns_min_bytes > session->value.turnBytes)
				session->value.turns_min_bytes = session->value.turnBytes;
			if (session->value.turns_max_bytes < session->value.turnBytes)
				session->value.turns_max_bytes = session->value.turnBytes;
		}
		session->value.turn = dir;
		session->value.turnB  = gTime;
		session->value.turnBytes = 0;
		session->value.turnCount = 0;
	}
	session->value.turnE = gTime;
	session->value.turnBytes += size;
	session->value.turnCount ++;

	updateTCPValue(value, ack);

	while (value) {		//	fake loop, never be repeated
		int offset = seqOffset(value->seq, seq);
		if (offset < 0) {
			//	Retransmit Packet
			int length = offset + size;
			if (length > 0) {	//	some data is new?
				//	Skip -o bytes transferred
				value->seq -= offset;	//	offset is negative
				data       -= offset;	//	offset is negative
				size       += offset;	//	offset is negative
				offset = 0;
			} else
				break;	//	All data is retransmit;
		}

		if (offset == 0) {
			//	Sequenced Packet, process data.
			processTCPData(session, dir, value, data, size, length, state, tcp, ip, ether);

			//	Check order buffer
			reorderStream(session, dir, value, state, tcp, ip, ether);
			break;
		}

		if (offset > 0) {
			//	Current packet is unordered, look for insert position
			value->reorderedCount ++;
			value->reorderedBytes += size;

			int index = value->count;
			if (value->count > 0) {
				while(index > 0) {
					PSoderoStreamBlock block = value->block[index-1];
					int length = seqOffset(block->seq, seq);
					if (length > 0) {
						//	Break the lookup, insert block in the current position
						break;
					}
					if (length < 0) {
						//	Current packet is before the block, check next block
						index --;
						continue;
					}

					//	length == 0
					//	Same packet, retransmit.
//					printf("No %.8llu: replace %.8x @ %u from %u to %u\n", gPacket, seq, index, block->size, size);

					value->retransmitCount++;
					value->retransmitBytes += size;

					if (size > block->size) {	//	Is some data new?
						//	replace current block
#ifdef __EXPORT_STATISTICS__
						gReplaceFree++;
#ifdef __EXPORT_DUMP_BLOCK__
						if (gDump)
							fprintf(gDump, "free replace block %p of %p - %p @ index %d\n", block, session, value, index - 1);
#endif
#endif
						freeBlock(block);
						block = takeBlock(sizeof(TSoderoStreamBlock) + size);
#ifdef __EXPORT_STATISTICS__
#ifdef __EXPORT_DUMP_BLOCK__
						if (gDump)
							fprintf(gDump, "take replace block %p of %p - %p @ index %d\n", block, session, value, index - 1);
#endif
						gReplaceTake++;
#endif
						block->seq = seq;
//						block->base = 0;
						block->size = size;
						memcpy(block->data, data, size);
						value->block[index-1] = block;
					}
					index = -1;	//	Block has been placed, prevent subsequent insertion operation
					break;
				}

				if (index > 0) {
					//	If index is greater than or equal zero, insert new block at index
					if (value->count < STREAM_REORDER_BLOCK_COUNT) {
						if (value->count > index)
							memmove(value->block + index + 1, value->block + index    , sizeof(*value->block) * (value->count - index));
						value->count++;

						PSoderoStreamBlock block = takeBlock(sizeof(TSoderoStreamBlock) + size);
#ifdef __EXPORT_STATISTICS__
#ifdef __EXPORT_DUMP_BLOCK__
						if (gDump)
							fprintf(gDump, "take create block %p of %p - %p @ index %d\n", block, session, value, index);
#endif
						gCreateBlock++;
#endif
						block->seq = seq;
//						block->base = 0;
						block->size = size;
						value->block[index] = block;
						memcpy(block->data, data, size);
					} else {
						//	Queue overflow, restart from head
//						printf("Drop the head block of reorder buffer: %p\n", value->overflow);
						PSoderoStreamBlock overflow = value->overflow;
//						printf("Force restart at head block of reorder buffer: %p\n", overflow);
						if (overflow) {
							restartStream(session, dir, value, overflow->seq);
							int length = seqOffset(overflow->seq, value->seq);
							processTCPData(session, dir, value, overflow->data + length, overflow->size - length, length, state, tcp, ip, ether);
#ifdef __EXPORT_STATISTICS__
							gOverflowFree++;
#ifdef __EXPORT_DUMP_BLOCK__
							if (gDump)
								fprintf(gDump, "free overflow block %p of %p - %p\n", overflow, session, value);
#endif
#endif
							freeBlock(overflow);		//	delete the head before insert at tail
						}

						index --;
						if (index > 0)
							memmove(value->block, value->block + 1, sizeof(*value->block) * index);

						PSoderoStreamBlock block = takeBlock(sizeof(TSoderoStreamBlock) + size);
#ifdef __EXPORT_STATISTICS__
#ifdef __EXPORT_DUMP_BLOCK__
						if (gDump)
							fprintf(gDump, "take overflow block %p of %p - %p @ index %d\n", block, session, value, index);
#endif
						gOverflowTake++;
#endif
						block->seq = seq;
//						block->base = 0;
						block->size = size;
						block->length = length;
						value->block[index] = block;
						memcpy(block->data, data, size);

						//	Check order buffer
						reorderStream(session, dir, value, state, tcp, ip, ether);
					}
				}
			} else {
				PSoderoStreamBlock block = takeBlock(sizeof(TSoderoStreamBlock) + size);
#ifdef __EXPORT_STATISTICS__
#ifdef __EXPORT_DUMP_BLOCK__
				if (gDump)
					fprintf(gDump, "take first block %p of %p - %p\n", block, session, value);
#endif
				gFirstBlock++;
#endif
				block->seq = seq;
//				block->base = 0;
				block->size = size;
				value->overflow = block;
				memcpy(block->data, data, size);
				value->count++;
			}
			break;
		}

		//Oops, Definitely not execute to here
		printf("Oops: Definitely not execute to here - Process packets %u\n", gTotal.count);
		break;
	}

	return 0;
}

int processTCPPacket(const void * data, int size, int length, PIPHeader ip, PEtherHeader ether) {
	PSoderoTCPPeriodResult result = &getPeriodResult()->protocol.l4.tcp;
	PTCPHeader tcp = (PTCPHeader) data;
	int bytes = tcp->size * 4;
	void * payload_data = TCP_OVERLOAD_DATA(data, bytes);
	int    payload_size = TCP_OVERLOAD_SIZE(size, bytes);

	g_pip = ip;
	g_tcp = tcp;
	processA(&gTCP, length);

	counterTCPFlag(&result->counter, tcp);

	TPortKey key;
	key.l    = ip->value;
	key.port = tcp->port;
	key.data = ip->protocol;
	key.dir   = DIR_NONE;	//	SESSION_TYPE_MINOR_TCP;
	key.sequence = ip->identify + (ip->check << 16);	//	+ tcp->sequence;

	unsigned int seq = ntohl(tcp->   sequence);
	unsigned int ack = ntohl(tcp->ackSequence);

	PSoderoTCPSession session = processTCPHandshake(result, tcp, payload_size, &key, ether, seq, ack);

	if (session) {
		counterTCPNode(session, &key, ether, size, length);
		gCurSession = session;

		int dir = dir_of_ipv4(&session->key.ipPair, &key.ipPair);

		updatePortSession((PSoderoPortSession)session, dir, payload_size, length, gTime);
		if (session->state == SODERO_TCP_ESTABLISHED)
			resetSessionLive(session, gTime + gTCPActivedTime);

		TTCPState state;
		bzero(&state, sizeof(state));

		state.syn = tcp->syn;
		state.fin = tcp->fin;
		state.rst = tcp->rst;
		state.seq = seq;
		state.ack = ack;
		state.payload = payload_size;
		state.length  = length;
		state.surgen  = tcp->surgen;

		processTCPDemolish(session, tcp, size, &key, ether, dir, seq, ack);

		updateTCPSessionRTT(session, tcp, -dir, seq, ack, &state);

		memcpy(&gState, &state, sizeof(state));
		return processStream(session, payload_data, payload_size, length, dir, seq, &state, tcp, ip, ether);
	}
	return 0;
}
