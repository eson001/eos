/*
 * Report.h
 *
 *  Created on: Aug 25, 2014
 *      Author: Clark Dong
 */

#ifndef REPORT_H_
#define REPORT_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rpc/types.h>
#include <rpc/rpc.h>

#include "Type.h"
#include "XDR.h"
#include "Common.h"
#include "Session.h"
#include "Core.h"
#include "Logic.h"

#define SODERO_REPPORT_SIZE (64 * Ki)

#define SODERO_XDR_SUCCESS 200

#define SODERO_REPORT_VALUE(I, N, V, C)                            \
	{                                                              \
		unsigned long long D = (V);                                \
		if (D) {                                                   \
			checkNodeValue(I, N, D);                               \
			if (!sodero_report_named_value(I, N, D)) return 1;     \
			(*C)++;                                                \
		}                                                          \
	}

#define SODERO_REPORT_GROUP(I, f, N, V, C)                         \
	{                                                              \
	    char name[256];                                            \
	    snprintf(name, sizeof(name)-1, f, N);                      \
		unsigned long long D = (V);                                \
		if (D) {                                                   \
			checkNodeValue(I, name, D);                            \
			if (!sodero_report_named_value(I, name, D)) return 1;  \
			(*C)++;                                                \
		}                                                          \
	}

#define SODERO_REPORT_DATUM(I, N, V, C)                            \
	{                                                              \
	    TSoderoUnitDatum D = (V);                                  \
		if (D.count) {                                             \
			checkNodeDatum(I, N, &D);                              \
			if (!sodero_report_named_datum(I, N, &D)) return 1;    \
			(*C)++;                                                \
		}                                                          \
	}

#define SODERO_SAFE_DIV(a, b)  ((b) ? ((a) / (b)) : 0)

#define SODERO_SAFE_RATE(item, pre)  SODERO_SAFE_DIV((item.pre##Value) , (item.pre##Count))

#define SODERO_SAFE_TEXT(record, name, value)	\
	record->name.name##_val = xdr_store_string(&data.event.data, value, &record->name.name##_len);


typedef enum SODERO_REPORT_WAY {
	SODERO_REPORT_NONE = 0,
	SODERO_REPORT_HEAD = 1,
	SODERO_REPORT_BODY = 2,
	SODERO_REPORT_DONE = 4,
} TSoderorReportWay;

#define SODERO_REPORT_WAY_HEAD (SODERO_REPORT_HEAD)
#define SODERO_REPORT_WAY_BODY (SODERO_REPORT_BODY)
#define SODERO_REPORT_WAY_BOTH (SODERO_REPORT_HEAD | SODERO_REPORT_BODY)
#define SODERO_REPORT_WAY_DONE (SODERO_REPORT_BODY | SODERO_REPORT_DONE)

typedef struct ADDRESS_INFO {
	  int ai_flags;
	  int ai_family;
	  int ai_socktype;
	  int ai_protocol;
	  socklen_t ai_addrlen;
	  struct sockaddr * ai_addr;
	  const char * ai_canonname;
	  struct sockaddr addr;
} TAddressInfo, * PAddressInfo;


#ifdef __ASYNCHRONOUS_TRANSMIT__

#define SODER0_REPORT_BLOCK_COUNT Ki

typedef struct REPORT_BLOCK {
	unsigned int       size;
	unsigned int       used;
	unsigned long long flag;
	unsigned char      data[];
} TReportBlock, * PReportBlock;

extern PReportBlock getReport(void);
extern void initial_report(void);
extern void release_report(void);

extern void flushSocket(int terminated);

extern void * transmitor(void * handler);

extern pthread_mutex_t gTransmitMutex;
extern pthread_cond_t  gTransmitCond ;
#endif

extern void sodero_report_disconnect(void);
extern int sodero_report_connect(void);
extern int sodero_report_check(void);

extern int sodero_report_event(PSoderoEvent result, int way);

extern void sodero_report_result(PSoderoPeriodResult result
#ifdef __NO_CYCLE__
		, PSoderoSessionManager manager
#endif
		);

extern int sodero_report_session(PSoderoSession session, int way);

extern int sodero_report_application(PSoderoApplication application, int flag);

#endif /* REPORT_H_ */
