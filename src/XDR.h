/*
 * XDR.h
 *
 *  Created on: Aug 22, 2014
 *      Author: Clark Dong
 */

#ifndef XDR_H_
#define XDR_H_


#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <rpc/types.h>
#include <rpc/rpc.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "interface.h"

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Core.h"

typedef struct XDR_FIELD_NAME {
	const char * string;
	int          length;
} TXDRFieldName, * PXDRFieldName;

typedef struct XDR_DATA {
	int  length;
	int  offset;
	char buffer[0];
} TXDRData, * PXDRData;

typedef union XDR_EVENT_BUFFER {
	struct {
		TSoderoTCPReportMsg message;
		TXDRData data;
	} event;
	char bytes[8*Ki];
} TXDREventBuffer, * PXDREventBuffer;

extern unsigned gAgentID;

extern unsigned char * xdr_store_string(PXDRData data, const char * string, unsigned int * size);

extern int sodero_init_xdr_encode(XDR * xdrs, char * buffer, unsigned int length);
extern int sodero_init_xdr_decode(XDR * xdrs, char * buffer, unsigned int length);

int xdr_encode_field_value (XDR * xdr, unsigned int time, PNodeIndex index, PXDRFieldName field, unsigned long long value);
int xdr_encode_named_value (XDR * xdr, unsigned int time, PNodeIndex index, const char *  name , unsigned long long value);
int xdr_encode_field_datum (XDR * xdr, unsigned int time, PNodeIndex index, PXDRFieldName field, PSoderoUnitDatum value);
int xdr_encode_named_datum (XDR * xdr, unsigned int time, PNodeIndex index, const char *  name , PSoderoUnitDatum value);

extern int xdr_encode_tcp(XDR * xdr, TSoderoTCPReportMsg * message);
extern int xdr_encode_register(XDR * xdr, unsigned int time, const void * ver, const void * mac, const void * ip, const void * name);
extern int xdr_encode_node(XDR * xdr, unsigned int time, PNodeIndex node, const char * name, int type);
extern int xdr_encode_origin(XDR * xdr, unsigned int time, PNodeIndex node, const char * name);
extern int xdr_encode_finish  (XDR * xdr, unsigned int time, unsigned int count);
extern int xdr_encode_answer(XDR * xdr, unsigned int value);

extern int xdr_answer(XDR * xdr);

#endif /* XDR_H_ */
