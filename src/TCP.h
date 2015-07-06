/*
 * TCP.h
 *
 *  Created on: Sep 14, 2014
 *      Author: Clark Dong
 */

#ifndef TCP_H_
#define TCP_H_

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "Stream.h"
#include "DPI.h"


#define DEFAULT_TCP_LENGTH	(4 * Ki)
#define DEFAULT_TCP_DELTA	(4 * Ki)
#define DEFAULT_TCP_SIZE	sizeof(TSoderoTCPSession)

#define TCP_ACK_QUEUE_SIZE      128
#define TCP_REORDER_BLOCK_COUNT 128
#define TCP_REORDER_BLOCK_SIZE  64 * 1024;

#define TCP_FLAG_RST_FIN		0x0500
#define TCP_FLAG_SYN			0x0200
#define TCP_FLAG_SYN_RST_FIN	0x0700

#pragma pack(push, 1)

typedef enum SODERO_ICMP_STATE {
	SODERO_ICMP_NONE,
	SODERO_ICMP_OPENED,
	SODERO_ICMP_CLOSED,
} TSoderoICMPState;

typedef enum SODERO_TCP_STATE {
	SODERO_TCP_NONE,
	SODERO_TCP_SYN,				//	First  packet, client->server flag: syn
	SODERO_TCP_ACK,				//	Second packet, server->client flag: syn & ack
	SODERO_TCP_ESTABLISHED,		//	Third  packet, client->server flag:       ack
	SODERO_TCP_WAITING,         //	flag: first  fin
	SODERO_TCP_CLOSED,          //	flag: second fin
} TSoderoTCPState;

typedef enum SODERO_UDP_STATE {
	SODERO_UDP_NONE,
	SODERO_UDP_OPENED,
	SODERO_UDP_CLOSED,
} TSoderoUDPState;


//	Metric Field Index
typedef enum SODERO_TCP_FIELD {
	TCP_FIELD_WINDOW,
	TCP_FIELD_NAGLE,
	TCP_FIELD_RETRANSMIT,
	TCP_FIELD_REORDERED,
} TSoderoTCPField;


//	TCP connection element, currently only common field
typedef struct SODERO_TCP_CONNECTION_DATUM {
	unsigned long long id;		//	session id
	union {
		TSoderoFlowDatum value[2];
		struct {
			TSoderoFlowDatum incoming;		//	O -> I	Inbound Direction
			TSoderoFlowDatum outgoing;		//	I -> O	Outbound direction
		};
	};

	TSoderoUnitDatum window;
	TSoderoUnitDatum retransmit;
	TSoderoUnitDatum reordered;
} TSoderoTCPConnectionDatum, * PSoderoTCPConnectionDatum;


typedef	struct SODERO_TCP_COUNTER {
	unsigned int synCount;
	unsigned int ackCount;
	unsigned int finCount;
	unsigned int rstCount;
	unsigned int urgCount;
	unsigned int ecnCount;
	unsigned int cwrCount;

	unsigned int synMalformed    ;	//	malformed packet(syn with data)
	unsigned int synBroken       ;	//	malformed session(timeout too long?)
	unsigned int ackBroken       ;
	unsigned int synRetransmit   ;
	unsigned int ackRetransmit   ;
	unsigned int dropCount       ;	//	Number of dropped packet (NULL session)
	unsigned int dropBytes       ;	//	Traffic of dropped packet (NULL session)

	unsigned int activeCount     ;	//	Number of activity (sending or receiving packets) connections
	unsigned int establishedCount;	//  Number of connections
	unsigned int connectedCount  ;	//	Number of new connections. Complete the three-way handshake connections in currently period.
	unsigned int disconectedCount;	//	Number of connections closed. Double FIN or RST。
	unsigned int halfOpenCount   ;	//	Number of half-open connections. SYN without ASK.
	unsigned int halfCloseCount  ;	//	Number of half-closed connections. Only a single FIN/RST。
} TSoderoTCPCounter, * PSoderoTCPCounter;


typedef struct SODERO_TCP_PERIOD_RESULT {
	TSoderoFlowDatum  total;
	TSoderoTCPCounter counter;
} TSoderoTCPPeriodResult, * PSoderoTCPPeriodResult;


typedef struct SODERO_TCP_DISMANTLE {
	unsigned long long req;
	unsigned long long res;
	unsigned int       way;
} TSoderoTCPDismantle, * PSoderoTCPDismantle;

//u_int rtt;
//u_int client_rtos;
//u_int client_zwnds;
//u_int client_nagle_delays;
//u_int client_rcv_wnd_throttles;
//u_int server_rtos;
//u_int server_zwnds;
//u_int server_nagle_delays;
//u_int server_rcv_wnd_throttles;
//u_int turns;
//u_int turns_sum_time;
//u_int turns_min_time;
//u_int turns_max_time;
//u_int turns_sum_interval;
//u_int turns_min_interval;
//u_int turns_max_interval;
//u_quad_t turns_sum_bytes;
//u_quad_t turns_min_bytes;
//u_quad_t turns_max_bytes;

typedef struct SODERO_TCP_ACK {
	unsigned int seq;
	unsigned long long time;
} TSoderoTCPACK, * PSoderoTCPACK;

typedef struct SODERO_TCP_VALUE {
	//	Indications
	unsigned int rtos;
	unsigned int zwnds;
	unsigned int nagle_delays;
	unsigned int rcv_wnd_throttles;

	unsigned long long rttValue;
	unsigned int       rttCount;

	unsigned char synCount;
	unsigned char ackCount;
	unsigned char finCount;
	unsigned char rstCount;

	unsigned int       rttDropped;	//	Drop ack item;

	//	Drop data packet
	unsigned int       droppedCount;
	unsigned long long droppedBytes;
	unsigned int       reorderedCount;
	unsigned long long reorderedBytes;
	unsigned int       retransmitCount;
	unsigned long long retransmitBytes;
	unsigned long long streamBytes;
	unsigned int       missedBytes;


	//	Temporary variables
	unsigned int       seq;		//	Last seq
	unsigned int       ack;		//	Last ack
	unsigned long long time;	//	Lask packet time

	union {
		PSoderoStreamBlock overflow;
		PSoderoStreamBlock block[TCP_REORDER_BLOCK_COUNT];
	};
	unsigned int count;

	unsigned int   urgBytes;
	unsigned short urgCount;
	unsigned char base;		//	First used ACK item in queue
	unsigned char size;		//	free ACK item count in queue
	TSoderoTCPACK acks[TCP_ACK_QUEUE_SIZE];		//	ACK Queue for RTT
//	unsigned int  ;
	unsigned short length;	//	Reorder Buffer Size
	unsigned short offset;	//	Reorder Buffer Idle
	unsigned short http;	//	HTTP Scan position
	unsigned char buffer[4096];	//	Reorder Buffer
} TSoderoTCPValue, * PSoderoTCPValue;

//	TCP Connection
typedef struct SODERO_HTTP_STATUS {

	char * tail;
} TSoderoHTTPStatus, * PSoderoHTTPStatus;

typedef struct SODERO_MYSQL_STATUS {
	char * tail;
	char * version;
	unsigned int server;
	unsigned int client;
	union {
		struct {
			unsigned long long reqTime;
			unsigned long long rspTime;
			char * user;
			char * database;
		} login;
	};
	unsigned char protocol;
	unsigned char serial;
	unsigned char status;
} TSoderoMySQLStatus, * PSoderopMySQLStatus;

typedef struct SODERO_TNS_STATUS {
	char * tail;
	char * version;
	unsigned int server;
	unsigned int client;
	union {
		struct {
			unsigned long long reqTime;
			unsigned long long rspTime;
			char * user;
			char * database;
		} login;
	};
	unsigned char protocol;
	unsigned char serial;
	unsigned char status;
} TSoderoTnsStatus, * PSoderopTnsStatus;

typedef struct SODERO_TCP_SET {
	unsigned long long l;
	unsigned long long h;
} TSoderoTCPSet, * PSoderoTCPSet;

typedef struct SODERO_TCP_RECORD {
	unsigned long long synTime;
	unsigned long long ackTime;
	unsigned long long conTime;

	union {
		struct {
			TSoderoTCPValue incoming;
			TSoderoTCPValue outgoing;
		};
		TSoderoTCPValue links[2];
	};

	unsigned int       turns_count;
	unsigned long long turns_sum_time;
	unsigned long long turns_min_time;
	unsigned long long turns_max_time;
	unsigned long long turns_sum_interval;
	unsigned long long turns_min_interval;
	unsigned long long turns_max_interval;
	unsigned long long turns_sum_bytes;
	unsigned long long turns_min_bytes;
	unsigned long long turns_max_bytes;

	//	Temporary variables
	         char turn;		//	direction of current (turn)
	unsigned char turnB;
	unsigned char turnE;
	unsigned char turnBytes;
	unsigned char turnCount;
	unsigned char dir;		//  direction of session

	union {
		TSoderoTCPSet set;
		unsigned long long flags[4];	//	detect protocol flags
	};
	union {
		TSoderoHTTPStatus  http ;
		TSoderoMySQLStatus mysql;
		TSoderoTnsStatus tns;
	};
	char buffer[2500];
} TSoderoTCPRecord, * PSoderoTCPRecord;


//	TCP Summary Result
typedef struct SODERO_TCP_RESULT {
	unsigned int     count;
	TSoderoTCPRecord items[0];
} TSoderoTCPResult, * PSoderoTCPResult;

struct SODERO_TCP_SESSION;
typedef struct SODERO_TCP_SESSION TSoderoTCPSession, * PSoderoTCPSession;

struct SODERO_TCP_SESSION {
	//	Session Common Fields
	PSoderoTCPSession  prev;	//	link to prev node of chain
	PSoderoTCPSession  next;	//	link to next node of chain

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

	char state;
	char cause;

	unsigned char flag;
	unsigned char application;
	unsigned short major;
	unsigned short minor;

	TSoderoTCPRecord   value;
};

typedef struct TCPO_VALUE {
	unsigned char type;
	unsigned char size;
} TTCPOValue, * PTCPOValue;

typedef struct TCPO_TIMESTAMP {
	unsigned int value;
	unsigned int replay;
} TTCPOTimeStamp, * PTCPOTimeStamp;

typedef struct TCPO_SACK {
	unsigned int l;
	unsigned int r;
} TTCPOSACK, * PTCPOSACK;

typedef struct TCP_OPTION {
	union {
		unsigned long long value;
		struct {
			int   stamp;
			char  shift;
			char  count;	//	sack count
			unsigned short mss;
		};
	};
	int window;
	TTCPOSACK acks[4];
} TTCPOption, * PTCPOption;

typedef struct TCP_STATE {
	TTCPOption option;
	unsigned long long rttTime;
	unsigned char syn;
	unsigned char fin;
	unsigned char rst;
	unsigned char rtt;
	unsigned int seq;
	unsigned int ack;
	unsigned short payload;
	unsigned short length;
	unsigned short surgen;
	void * application;
} TTCPState, * PTCPState;

#pragma pack(pop)

extern int mergeData(unsigned char * buffer, unsigned int length, PSoderoTCPValue value,
		unsigned int offset, const unsigned char * data, int size);
extern int pickData(unsigned char * buffer, unsigned int length, PSoderoTCPValue value,
		unsigned int offset, const unsigned char * data, int size);
extern int pickLine(unsigned char * buffer, unsigned int length, PSoderoTCPValue value,
		unsigned int offset, const unsigned char * data, unsigned int size);
extern void counterTCPFlag(PSoderoTCPCounter counter, PTCPHeader header);

extern int appendData(PSoderoTCPValue value, const unsigned char * data, int size);
extern int processTCPPacket(const void * data, int size, int length, PIPHeader ip, PEtherHeader ether);

#endif /* TCP_H_ */
