/*
 * Stream.h
 *
 *  Created on: Sep 28, 2014
 *      Author: Clark Dong
 */

#ifndef STREAM_H_
#define STREAM_H_

#include <time.h>

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "DPI.h"

#define STREAM_REORDER_BLOCK_COUNT 128

#define DEFAULT_STREAM_LENGTH	(4 * Ki)
#define DEFAULT_STREAM_DELTA	(4 * Ki)
#define DEFAULT_STREAM_SIZE	sizeof(PPortKey)

#define DEFAULT_MANAGER_LENGTH	(4 * Ki)
#define DEFAULT_MANAGER_DELTA	(4 * Ki)

#pragma pack(push, 1)


//	The value element of port based connection, including general fields.
typedef struct SODERO_PORT_CONNECTION_DATUM {
	TPortKey             index;
	union {
		TSoderoFlowDatum value[2];
		struct {
			TSoderoFlowDatum incoming;		//	O -> I	Inbound Direction
			TSoderoFlowDatum outgoing;		//	I -> O	Outbound direction
		};
	};
} TSoderoPortConnectionDatum, * PSoderoPortConnectionDatum;


//	Common field of port connection summary
typedef struct SODERO_PORT_RECORD {

} TSoderoPortRecord, * PSoderoPortRecord;


//	IPort Summary Result
typedef struct SODERO_PORT_RESULT {
	unsigned int     count;
	TSoderoPortRecord items[0];
} TSoderoPortResult, * PSoderoPortResult;


//	Common fields of Port(UDP & TCP & SCTP) Event
typedef struct SODERO_PORT_EVENT {
	unsigned long long id;	//	session id
	time_t time;            //	Occurrence time, us from 1970-01-01
	unsigned char type;		//	Ether proto, such as TCP/UDP/SCTP ...
	unsigned char event;	//	TSoderoSessionEventType
	unsigned char cause;	//	TSoderoEventCreatCause or TSoderoEventCloseCause or ...

//	optional fields
	TPortHeader header;		//	when event is SODERO_SESSION_CREAT
	unsigned int synTime;	//	when event is SODERO_SESSION_CREAT & type is TCP
	unsigned int ackTime;	//	when event is SODERO_SESSION_CREAT & type is TCP
} TSoderoPortEvent, * PSoderoPortEvent;


struct SODERO_PORT_SESSION;
typedef struct SODERO_PORT_SESSION TSoderoPortSession, * PSoderoPortSession;


struct SODERO_STREAM_SBUFFER;
typedef struct SODERO_STREAM_SBUFFER TSoderoStreamSBuffer, * PSoderoStreamSBuffer;


union SODERO_STREAM_DBUFFER;
typedef union SODERO_STREAM_DBUFFER TSoderoStreamDBuffer, * PSoderoStreamDBuffer;


struct SODERO_PORT_SESSION {
	//	Session Common Fields
	PSoderoPortSession  prev;	//	link to prev node of chain
	PSoderoPortSession  next;	//	link to next node of chain

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

	TSoderoPortRecord value;
};


typedef struct SODERO_STREAM_BLOCK {
	unsigned int   seq;
//	unsigned short base;
	unsigned short size;
	unsigned short length;
	unsigned char  data[0];
} TSoderoStreamBlock, * PSoderoStreamBlock;


struct SODERO_STREAM_SBUFFER {
	union {
		PSoderoStreamBlock overflow;
		PSoderoStreamBlock block[STREAM_REORDER_BLOCK_COUNT];
	};
	unsigned int count;
	unsigned int seq;
	unsigned int ack;
	unsigned int  length;
	unsigned int  offset;
	unsigned char buffer[0];
};


union SODERO_STREAM_DBUFFER {
	struct {
		TSoderoStreamSBuffer incoming;
		TSoderoStreamSBuffer outgoing;
	};
	TSoderoStreamSBuffer value[2];
};


#pragma pack(pop)


///////////////////////////////////////////////////////////////////////////////////////////////////


extern long sodero_ipport_hasher(PPortKey key);
extern long sodero_ipport_equaler(PPortKey a, PPortKey b);
extern void sodero_ipport_duplicator(PPortKey a, PPortKey b);

extern PSoderoTable createStreamSession(void);

extern int isSameDir(PIPPair k, PIPPair v);

extern int isPositiveIP(PIPPair k, PIPPair v);
extern int isNegativeIP(PIPPair k, PIPPair v);
extern int dir_of_ipv4(PIPPair k, PIPPair v);
extern int dir_of_session(void * session, PIPPair k);
extern int isPositiveIPPort(PPortHeader k, PPortHeader v);

extern int isNegativeIPPort(PPortHeader k, PPortHeader v);
extern int dir_of_ipv4port(PPortHeader k, PPortHeader v);
extern int isClientDir(int dir);
extern int isServerDir(int dir);

extern void resetSessionLive(void * session, unsigned long long tick);
extern void newPortSession(PSoderoPortSession session, PPortKey key, int timeout, unsigned char state,
		PEtherHeader ether, unsigned long long time);
extern void newApplication(PSoderoApplication session, PSoderoSession owner);

extern void sodero_drop_session(PSoderoSession session);
extern void updatePortSession(PSoderoPortSession session, int dir, int size, int length, unsigned long long time);

#endif /* STREAM_H_ */
