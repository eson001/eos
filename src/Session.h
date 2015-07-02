/*
 * Session.h
 *
 *  Created on: Jul 10, 2014
 *      Author: Clark Dong
 */

#ifndef SESSION_H_
#define SESSION_H_

#include <time.h>

#include "Type.h"
#include "Common.h"
#include "Ether.h"
#include "ICMP.h"
#include "DPI.h"

#define SESSION_TYPE_HTTP     0x01
#define SESSION_TYPE_DATABASE 0x02

#define SESSION_SET_L_HTTP     0
#define SESSION_SET_L_MYSQL    1

#define APPLICATION_TYPE_PENDING 0x00
#define APPLICATION_TYPE_INVALID 0xFF

///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	Sodero Session Manager
//
///////////////////////////////////////////////////////////////////////////////////////////////////

//	Enum definitions of events

typedef enum SODDRO_EVENT_TYPE {
	SODERO_EVENT_LOG   ,
	SODERO_EVENT_REPORT,
} TSoderoEventType;

typedef enum SODERO_REPORT_TYPE {
	SODERO_REPORT_ARP,
	SODERO_REPORT_ICMP,
} TSoderoReportType;

typedef enum SODERO_LOG_TYPE {
	SODERO_LOG_PACKET_ERROR ,
	SODERO_LOG_SESSION_CREAT,
	SODERO_LOG_SESSION_CLOSE,
} TSoderoLogType;

typedef enum SODERO_LOG_PACKET_ERROR_CAUSE {
	CAUSE_PACKET_INVALID_SESSION,
	CAUSE_PACKET_INVALID_SYN,
	CAUSE_PACKET_INVALID_ACK,
	CAUSE_PACKET_INVALID_REQ,
	CAUSE_PACKET_INVALID_RES,
} TSoderoLogPacketErrorCause;

typedef enum SODERO_LOG_SESSION_CREAT_CAUSE {
	CAUSE_SESSION_CREAT_NORMAL,
	CAUSE_SESSION_CREAT_ABORT ,		//	TCP connection create by data packet
	CAUSE_SESSION_CREAT_FAILURE,
} TSoderoLogSessionCreatCause;

typedef enum SODERO_LOG_SESSION_CLOSE_CAUSE {
	CAUSE_SESSION_CLOSE_NORMAL ,	//	FIN-FIN
	CAUSE_SESSION_CLOSE_TIMEOUT,	//	None
	CAUSE_SESSION_CLOSE_RESET  ,	//	RST
	CAUSE_SESSION_CLOSE_ABORT  ,	//	Connection Abort by New SYN Flag
	CAUSE_SESSION_CLOSE_BROKEN ,	//	Connection SYN without ACK
} TSoderoLogSessionCloseCause;

//	Common field of event
typedef struct SODERO_EVENT_LOG {
	time_t time;			//	Occurrence time, us from 1970-01-01
	unsigned char type ;	//	TSoderoSessionEventType
	unsigned char cause;	//	TSoderoEventCreatCause or TSoderoEventCloseCause or ...
} TSoderoEventLog, * PSoderoEventLog;

typedef struct SODERO_EVENT_REPORT {
	struct {
		TSoderoReportType kind;
		union {
			TSoderoARPEvent arp;
			TSoderoICMPEvent icmp;
		};
	};
} TSoderoEventReport, * PSoderoEventReport;

typedef struct SODERO_EVENT {
	unsigned long long time;
	TSoderoEventType type;
	union {
		TSoderoEventLog log;
		TSoderoEventReport report;
	};
} TSoderoEvent, * PSoderoEvent;


///////////////////////////////////////////////////////////////////////////////////////////////////


//	Session Summary

struct SODERO_SESSION_MANAGER;
typedef struct SODERO_SESSION_MANAGER TSoderoSessionManager, * PSoderoSessionManager;


typedef enum SODERO_APPLICATION_TYPE {
	APPLICATION_DNS,
	APPLICATION_HTTP,
} TSoderoApplicationType;

typedef enum SODERO_PORT_SESSION_MAJOR_TYPE {
	SESSION_TYPE_MAJOR_NONE    = 0x00,
	SESSION_TYPE_MAJOR_ICMP    = 0x01,
	SESSION_TYPE_MAJOR_TCP     = 0x06,
	SESSION_TYPE_MAJOR_UDP     = 0x11,
	SESSION_TYPE_MAJOR_SCTP    = 0x80,
	SESSION_TYPE_MAJOR_UNKNOWN = 0xFF,
} TSoderoPortSessionMajorType;

typedef enum SODERO_PORT_SESSION_MINOR_TYPE {
	SESSION_TYPE_MINOR_NONE    = 0x00,
	SESSION_TYPE_MINOR_CUSTOM  = 0xC0,
	SESSION_TYPE_MINOR_UNKNOWN = 0xFF,
} TSoderoPortSessionMinorType;

typedef enum SODERO_PORT_SESSION_MINOR_ICMP {
	SESSION_TYPE_MINOR_ICMP = SESSION_TYPE_MINOR_NONE,
} TSoderoPortSessionMinorICMP;


typedef enum SODERO_PORT_SESSION_MINOR_TCP {
	SESSION_TYPE_MINOR_TCP  = SESSION_TYPE_MINOR_NONE,
	SESSION_TYPE_MINOR_HTTP  = 0x01,
	SESSION_TYPE_MINOR_MYSQL = 0x02,
} TSoderoPortSessionMinorTCP;

typedef enum SODERO_PORT_SESSION_MINOR_UDP {
	SESSION_TYPE_MINOR_UDP  = SESSION_TYPE_MINOR_NONE,
	SESSION_TYPE_MINOR_DNS  = 0x01,
} TSoderoPortSessionMinorUDP;

struct SODERO_SESSION_MANAGER {
//	TSoderoMemoryPool  pool;
	unsigned int tick;
	unsigned int count;

	PSoderoSession * heads;
	PSoderoSession * tails;
};


#define sodero_session_type(object)  ((int *)object)[-1]


typedef long (*TSessionTimeoutHandlor)(PSoderoSessionManager container, int index, void * object, void * data);

extern const char * error_cause_name(int cause);
extern const char * creat_cause_name(int cause);
extern const char * close_cause_name(int cause);

extern const char * tcp_application_name(int type);
extern const char * udp_application_name(int type);

extern const char * application_name(int protocol, int type);

extern int get_session_type(TObject object);
extern void set_session_type(TObject object, int type);

extern void merge_flow_datum(PSoderoFlowDatum total, PSoderoFlowDatum value);
extern void merge_packet_datum(PSoderoPacketDatum total, PSoderoPacketDatum value);
extern void merge_packet_detail(PSoderoDoubleDetail total, PSoderoDoubleDetail value);

extern unsigned long long count_of_datum(PSoderoDoubleDatum value);
extern unsigned long long bytes_of_datum(PSoderoDoubleDatum value);

extern unsigned long long count_of_detail(PSoderoDoubleDetail value, int index);
extern unsigned long long bytes_of_detail(PSoderoDoubleDetail value, int index);

extern PSoderoSession sodero_session_next(PSoderoSession session);
extern long sodero_session_timeout(PSoderoSession session, time_t tick);

extern void sodero_initialize_session_manager(PSoderoSessionManager object, int count);
extern void sodero_finalize_session_manager(PSoderoSessionManager object);

extern PSoderoSessionManager sodero_create_session_manager(int count);
extern void sodero_destroy_session_manager(PSoderoSessionManager object);

extern size_t sodero_session_count(PSoderoSessionManager object);

extern PSoderoSession sodero_session_insert(PSoderoSessionManager object, PSoderoSession session);
extern PSoderoSession sodero_session_remove(PSoderoSessionManager object, PSoderoSession session);
extern PSoderoSession sodero_session_adjust(PSoderoSessionManager object, PSoderoSession session);

//extern void sodero_session_free(PSoderoSessionManager object, PSoderoSession session);
//extern PSoderoSession sodero_session_take(PSoderoSessionManager object, time_t tick, int type);

extern PSoderoSession sodero_session_clean(PSoderoSessionManager object);
extern PSoderoSession sodero_session_check(PSoderoSessionManager object, unsigned long long tick);
extern long sodero_session_foreach(PSoderoSessionManager object, TSessionTimeoutHandlor handlor, void * data);

extern long sodero_port_hasher(PPortKey key);
extern long sodero_port_equaler(PPortKey a, PPortKey b);
//extern long sodero_port_session_handlor(int index, PSoderoPortSession session, void * data);

#endif /* SESSION_H_ */
