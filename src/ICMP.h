/*
 * ICMP.h
 *
 *  Created on: Sep 14, 2014
 *      Author: Clark Dong
 */

#ifndef ICMP_H_
#define ICMP_H_

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "Stream.h"
#include "DPI.h"

#define DEFAULT_ICMP_LENGTH	(4 * Ki)
#define DEFAULT_ICMP_DELTA	(4 * Ki)
#define DEFAULT_ICMP_SIZE	sizeof(TSoderoICMPSession)


#pragma pack(push, 1)


typedef	struct SODERO_ICMP_COUNTER {

} TSoderoICMPCounter, * PSoderoICMPCounter;


//	ICMP connection element, currently only common field
typedef TSoderoPortConnectionDatum TSoderoICMPConnectionDatum;
typedef PSoderoPortConnectionDatum PSoderoICMPConnectionDatum;

typedef union SODERO_ICMP_RECORD {
	unsigned int value;
	struct {
		unsigned short identify;
		unsigned short sequence;
	} echo;                     // echo datagram
} TSoderoICMPRecord, * PSoderoICMPRecord;


struct SODERO_ICMP_SESSION;
typedef struct SODERO_ICMP_SESSION TSoderoICMPSession, * PSoderoICMPSession;

typedef struct SODERO_ICMP_EVENT {
	TPortKey info;
	unsigned char code;
} TSoderoICMPEvent, * PSoderoICMPEvent;

struct SODERO_ICMP_SESSION {
	//	Session Common Fields
	PSoderoICMPSession  prev;	//	link to prev node of chain
	PSoderoICMPSession  next;	//	link to next node of chain

	unsigned int live;
	unsigned int time;

	unsigned long long id;
	unsigned long long b;		//	Time of First Packet
	unsigned long long e;		//	Time of Last Packet

	void * session;

	TPortKey          key;
	TEtherData        eth;
	unsigned int identify;

	TSoderoDoubleValue l2;
	TSoderoDoubleDatum traffic;	//	connection's traffic
//	TSoderoUnitDatum speed;		//	Transmission speed（Bytes per second）
//	TSoderoUnitDatum count;		//	Transmission speed（packet per second）
//	TSoderoUnitDatum interval;	//	Interval of packet to packet(us)

	unsigned char state;
	unsigned char cause;

	unsigned char flag;
	unsigned char application;
	unsigned short major;
	unsigned short minor;

	TSoderoICMPRecord  value;
};


typedef struct SODERO_ICMP_PERIOD_RESULT {
	TSoderoFlowDatum total;

	union {
		struct {
			TSoderoFlowDatum request ;
			TSoderoFlowDatum response;
		};
		TSoderoFlowDatum values[2];
	};

	TSoderoICMPCounter counter;
} TSoderoICMPPeriodResult, * PSoderoICMPPeriodResult;


struct SODERO_APPLICATION_ICMP;
typedef struct SODERO_APPLICATION_ICMP TSoderoApplicationICMP, * PSoderoApplicationICMP;

struct SODERO_APPLICATION_ICMP {
	char *                 data;
	PSoderoICMPSession    owner;
	PSoderoApplicationICMP next;
	unsigned long long     id;		//	session id
//	unsigned char          flag;
	unsigned long long   serial;

	TSoderoICMPRecord  value;
} TSoderoRecordICMP, * PSoderoRecordICMP;

#pragma pack(pop)


extern PSoderoContainer createICMPSession(void);
extern int processICMPPacket(const void * data, int size, int length, PIPHeader ip, PEtherHeader ether);

#endif /* ICMP_H_ */
