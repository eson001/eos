/*
 * UDP.h
 *
 *  Created on: Sep 28, 2014
 *      Author: Clark Dong
 */

#ifndef UDP_H_
#define UDP_H_

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "Stream.h"
#include "DPI.h"

#define DEFAULT_UDP_LENGTH	(4 * Ki)
#define DEFAULT_UDP_DELTA	(4 * Ki)
#define DEFAULT_UDP_SIZE	sizeof(TSoderoUDPSession)


#pragma pack(push, 1)


//	UDP connection element, currently only common field
typedef TSoderoPortConnectionDatum TSoderoUDPConnectionDatum;
typedef PSoderoPortConnectionDatum PSoderoUDPConnectionDatum;


typedef	struct SODERO_UDP_COUNTER {

} TSoderoUDPCounter, * PSoderoUDPCounter;


typedef TSoderoPortRecord TSoderoUDPRecord;
typedef PSoderoPortRecord PSoderoUDPRecord;


//	UDP Summary Result
typedef struct SODERO_UDP_RESULT {
	unsigned int     count;
	TSoderoUDPRecord items[0];
} TSoderoUDPResult, * PSoderoUDPResult;


struct SODERO_UDP_SESSION;
typedef struct SODERO_UDP_SESSION TSoderoUDPSession, * PSoderoUDPSession;


struct SODERO_UDP_SESSION {
	//	Session Common Fields
	PSoderoUDPSession  prev;	//	link to prev node of chain
	PSoderoUDPSession  next;	//	link to next node of chain

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

	TSoderoUDPRecord  value;
};


typedef struct SODERO_UDP_PERIOD_RESULT {
	TSoderoFlowDatum  total;
	TSoderoUDPCounter counter;
} TSoderoUDPeriodResult, * PSoderoUDPPeriodResult;


#pragma pack(pop)


extern PSoderoContainer createUDPSession(void);

extern int processUDPPacket(const void * data, int size, int length, PIPHeader ip, PEtherHeader ether);

#endif /* UDP_H_ */
