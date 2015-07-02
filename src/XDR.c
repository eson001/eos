/*
 * xdr.c
 *
 *  Created on: Aug 22, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <rpc/types.h>
#include <rpc/rpc.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "interface.h"
#include "flow_stats_api.h"

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Logic.h"
#include "XDR.h"

unsigned gAgentID = 0;

unsigned char * xdr_store_string(PXDRData data, const char * string, unsigned int * size) {
	if (string) {
		int left = data->length - data->offset;
		if (left > 1) {
			char * result = data->buffer + data->offset;
			*size = snprintf(result, left - 1, "%s", string) + 1;
			data->offset += *size;
			return (unsigned char *) result;
		}
	}
	return nullptr;
}

int sodero_init_xdr_encode(XDR * xdrs, char * buffer, unsigned int length) {
	bzero(buffer, length);
	xdrmem_create(xdrs, buffer, length, XDR_ENCODE);
	return true;
}

int sodero_init_xdr_decode(XDR * xdrs, char * buffer, unsigned int length) {
	xdrmem_create(xdrs, buffer, length, XDR_DECODE);
	return true;
}


#define xdr_move(dest, sour, size) memcpy(dest, sour, size)
#define xdr_copy(dest, sour) if (sour) xdr_move(dest,  sour, sizeof(dest))
#define xdr_data(dest, sour) xdr_move(&dest, &sour, sizeof(dest))
#define xdr_text(dest, sour) if (sour && dest) strncpy((char*)dest, (char*)sour, strnlen((char*)sour, sizeof(dest)))

#ifdef __ASYNCHRONOUS_TRANSMIT__
int xdr_encode_nodes(XDR * xdr, unsigned int time, unsigned int count, const TSoderoNodeMsg * nodes, int type) {

	if (xdr->x_op != XDR_ENCODE) return false;
	switch(type) {
		TSoderoReportMsg message;
		case SODERO_NODES:
		case ORIGIN_NODES:
			bzero(&message, sizeof(message));
			message.type = type;

			xdr_data(message.TSoderoReportMsg_u.nodes.nodes_len, count);
			xdr_data(message.TSoderoReportMsg_u.nodes.nodes_val, nodes);

			return xdr_TSoderoReportMsg(xdr, &message);
	}
	return false;
}

int xdr_encode_field_value (XDR * xdr, unsigned int time, PNodeIndex index, PXDRFieldName field, unsigned long long value) {
	if (xdr->x_op != XDR_ENCODE) return false;

	TSoderoReportMsg message;
	bzero(&message, sizeof(message));
	message.type = COUNT_METRIC;

	xdr_data(message.TSoderoReportMsg_u.count_metric.agent_id, gAgentID);
	xdr_data(message.TSoderoReportMsg_u.count_metric.time, time);
	xdr_copy(message.TSoderoReportMsg_u.count_metric.mac , index->mac.bytes);
	xdr_data(message.TSoderoReportMsg_u.count_metric.vlan, index->vlan);

	xdr_copy(message.TSoderoReportMsg_u.count_metric.ip  , index->ip .bytes);
	xdr_data(message.TSoderoReportMsg_u.count_metric.metrics.metrics_len , field->length);
	xdr_data(message.TSoderoReportMsg_u.count_metric.metrics.metrics_val , field->string);
	xdr_data(message.TSoderoReportMsg_u.count_metric.count, value);

	return xdr_TSoderoReportMsg(xdr, &message);
}

int xdr_encode_named_value (XDR * xdr, unsigned int time, PNodeIndex index, const char *  name, unsigned long long value) {
//	TXDRFieldName field = {name, strlen(name)};
	char text[256];
	int size = strlen(name);
	strncpy(text, name, size);
	TXDRFieldName field = {text, size};
	return xdr_encode_field_value(xdr, time, index, &field, value);
}

int xdr_encode_field_datum (XDR * xdr, unsigned int time, PNodeIndex index, PXDRFieldName field, PSoderoUnitDatum value) {
	if (xdr->x_op != XDR_ENCODE) return false;

	TSoderoReportMsg message;
	bzero(&message, sizeof(message));
	message.type = PERIODIC_METRIC;

	xdr_data(message.TSoderoReportMsg_u.periodic_metric.agent_id, gAgentID);
	xdr_data(message.TSoderoReportMsg_u.periodic_metric.time, time);
	xdr_copy(message.TSoderoReportMsg_u.periodic_metric.mac , index->mac.bytes);
	xdr_data(message.TSoderoReportMsg_u.periodic_metric.vlan, index->vlan);

	xdr_copy(message.TSoderoReportMsg_u.periodic_metric.ip  , index->ip .bytes);
	xdr_data(message.TSoderoReportMsg_u.periodic_metric.metrics.metrics_len , field->length);
	xdr_data(message.TSoderoReportMsg_u.periodic_metric.metrics.metrics_val , field->string);
	xdr_data(message.TSoderoReportMsg_u.periodic_metric.count, value->count);

	xdr_data(message.TSoderoReportMsg_u.periodic_metric.min, value->min);
	xdr_data(message.TSoderoReportMsg_u.periodic_metric.max, value->max);
	xdr_data(message.TSoderoReportMsg_u.periodic_metric.sum, value->sum);

	return xdr_TSoderoReportMsg(xdr, &message);
}

int xdr_encode_named_datum (XDR * xdr, unsigned int time, PNodeIndex index, const char *  name, PSoderoUnitDatum value) {
//	TXDRFieldName field = {name, strlen(name)};
	char text[256];
	int size = strlen(name);
	strncpy(text, name, size);
	TXDRFieldName field = {text, size};
	return xdr_encode_field_datum(xdr, time, index, &field, value);
}

int xdr_encode_register(XDR * xdr, unsigned int time, const void * ver, const void * mac, const void * ip, const void * name) {
	if (xdr->x_op != XDR_ENCODE) return false;

	TSoderoReportMsg message;
	bzero(&message, sizeof(message));
	message.type = CLIENT_REGISTER;

	xdr_copy(message.TSoderoReportMsg_u.client_register.vrsn , ver );
	xdr_data(message.TSoderoReportMsg_u.client_register.times, time);
	xdr_copy(message.TSoderoReportMsg_u.client_register.mac  , mac );
	xdr_copy(message.TSoderoReportMsg_u.client_register.ip   , ip  );
	xdr_copy(message.TSoderoReportMsg_u.client_register.name , name);

	return xdr_TSoderoReportMsg(xdr, &message);
}

int xdr_encode_node(XDR * xdr, unsigned int time, PNodeIndex node, const char * name, int type) {
	TSoderoNodeMsg message;
	bzero(&message, sizeof(message));

	xdr_copy(message.mac  , node->mac.bytes);
	xdr_copy(message.ip   , node->ip .bytes);
	xdr_copy(message.name , name);

//	printf("Node:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X-%u.%u.%u.%u\n",
//		node->mac.bytes[0], node->mac.bytes[1], node->mac.bytes[2], node->mac.bytes[3], node->mac.bytes[4], node->mac.bytes[5],
//		node->ip.bytes[0], node->ip.bytes[1], node->ip.bytes[2], node->ip.bytes[3]);

	return xdr_encode_nodes(xdr, time, 1, &message, type);
}

int xdr_encode_finish(XDR * xdr, unsigned int time, unsigned int count) {
	if (xdr->x_op != XDR_ENCODE) return false;

	TSoderoReportMsg message;
	bzero(&message, sizeof(message));
	message.type = METRIC_FINISH;

	xdr_data(message.TSoderoReportMsg_u.metric_finish.time , time );
	xdr_data(message.TSoderoReportMsg_u.metric_finish.count, count);

	return xdr_TSoderoReportMsg(xdr, &message);
}

int xdr_encode_answer(XDR * xdr, unsigned int value) {
	if (xdr->x_op != XDR_ENCODE) return false;

	TSoderoReportMsg message;
	bzero(&message, sizeof(message));
	message.type = SERVER_ACK;

	xdr_data(message.TSoderoReportMsg_u.server_ack.ack_val, value);

	return xdr_TSoderoReportMsg(xdr, &message);
}

int xdr_answer(XDR * xdr) {
	if (xdr->x_op != XDR_DECODE) return false;

	TSoderoReportMsg message;
	if (!xdr_TSoderoReportMsg(xdr, &message))
		return false;

	if (message.type != SERVER_ACK)
		return false;

	return message.TSoderoReportMsg_u.server_ack.ack_val;
}

int xdr_encode_msg(XDR * xdr, TSoderoReportMsg * message) {
	return xdr_TSoderoReportMsg(xdr, message);
}
#else
int xdr_encode_nodes(XDR * xdr, unsigned int time, unsigned int count, const TSoderoNodeMsg * nodes, int type) {

	if (xdr->x_op != XDR_ENCODE) return false;
	switch(type) {
		TSoderoTCPReportMsg message;
		case SODERO_NODES:
		case ORIGIN_NODES:
			bzero(&message, sizeof(message));
			message.type = type;

			xdr_data(message.TSoderoTCPReportMsg_u.nodes.nodes_len, count);
			xdr_data(message.TSoderoTCPReportMsg_u.nodes.nodes_val, nodes);

			return xdr_TSoderoTCPReportMsg(xdr, &message);
	}
	return false;
}

int xdr_encode_field_value (XDR * xdr, unsigned int time, PNodeIndex index, PXDRFieldName field, unsigned long long value) {
	if (xdr->x_op != XDR_ENCODE) return false;

	TSoderoUDPReportMsg message;
	bzero(&message, sizeof(message));
	message.type = COUNT_METRIC;

	xdr_data(message.TSoderoUDPReportMsg_u.count_metric.agent_id, gAgentID);
	xdr_data(message.TSoderoUDPReportMsg_u.count_metric.time, time);
	xdr_copy(message.TSoderoUDPReportMsg_u.count_metric.mac , index->mac.bytes);
	xdr_data(message.TSoderoUDPReportMsg_u.count_metric.vlan, index->vlan);

	xdr_copy(message.TSoderoUDPReportMsg_u.count_metric.ip  , index->ip .bytes);
	xdr_data(message.TSoderoUDPReportMsg_u.count_metric.metrics.metrics_len , field->length);
	xdr_data(message.TSoderoUDPReportMsg_u.count_metric.metrics.metrics_val , field->string);
	xdr_data(message.TSoderoUDPReportMsg_u.count_metric.count, value);

	return xdr_TSoderoUDPReportMsg(xdr, &message);
}

int xdr_encode_named_value (XDR * xdr, unsigned int time, PNodeIndex index, const char *  name, unsigned long long value) {
//	TXDRFieldName field = {name, strlen(name)};
	char text[256];
	int size = strlen(name);
	strncpy(text, name, size);
	TXDRFieldName field = {text, size};
	return xdr_encode_field_value(xdr, time, index, &field, value);
}

int xdr_encode_field_datum (XDR * xdr, unsigned int time, PNodeIndex index, PXDRFieldName field, PSoderoUnitDatum value) {
	if (xdr->x_op != XDR_ENCODE) return false;

	TSoderoUDPReportMsg message;
	bzero(&message, sizeof(message));
	message.type = PERIODIC_METRIC;

	xdr_data(message.TSoderoUDPReportMsg_u.periodic_metric.agent_id, gAgentID);
	xdr_data(message.TSoderoUDPReportMsg_u.periodic_metric.time, time);
	xdr_copy(message.TSoderoUDPReportMsg_u.periodic_metric.mac , index->mac.bytes);
	xdr_data(message.TSoderoUDPReportMsg_u.periodic_metric.vlan, index->vlan);

	xdr_copy(message.TSoderoUDPReportMsg_u.periodic_metric.ip  , index->ip .bytes);
	xdr_data(message.TSoderoUDPReportMsg_u.periodic_metric.metrics.metrics_len , field->length);
	xdr_data(message.TSoderoUDPReportMsg_u.periodic_metric.metrics.metrics_val , field->string);
	xdr_data(message.TSoderoUDPReportMsg_u.periodic_metric.count, value->count);

	xdr_data(message.TSoderoUDPReportMsg_u.periodic_metric.min, value->min);
	xdr_data(message.TSoderoUDPReportMsg_u.periodic_metric.max, value->max);
	xdr_data(message.TSoderoUDPReportMsg_u.periodic_metric.sum, value->sum);

	return xdr_TSoderoUDPReportMsg(xdr, &message);
}

int xdr_encode_named_datum (XDR * xdr, unsigned int time, PNodeIndex index, const char *  name, PSoderoUnitDatum value) {
//	TXDRFieldName field = {name, strlen(name)};
	char text[256];
	int size = strlen(name);
	strncpy(text, name, size);
	TXDRFieldName field = {text, size};
	return xdr_encode_field_datum(xdr, time, index, &field, value);
}

int xdr_encode_register(XDR * xdr, unsigned int time, const void * ver, const void * mac, const void * ip, const void * name) {
	if (xdr->x_op != XDR_ENCODE) return false;

	TSoderoTCPReportMsg message;
	bzero(&message, sizeof(message));
	message.type = CLIENT_REGISTER;

	xdr_copy(message.TSoderoTCPReportMsg_u.client_register.vrsn , ver );
	xdr_data(message.TSoderoTCPReportMsg_u.client_register.times, time);
	xdr_copy(message.TSoderoTCPReportMsg_u.client_register.mac  , mac );
	xdr_copy(message.TSoderoTCPReportMsg_u.client_register.ip   , ip  );
	xdr_copy(message.TSoderoTCPReportMsg_u.client_register.name , name);

	return xdr_TSoderoTCPReportMsg(xdr, &message);
}

int xdr_encode_node(XDR * xdr, unsigned int time, PNodeIndex node, const char * name, int type) {
	TSoderoNodeMsg message;
	bzero(&message, sizeof(message));

	xdr_copy(message.mac  , node->mac.bytes);
	xdr_copy(message.ip   , node->ip .bytes);
	xdr_copy(message.name , name);

//	printf("Node:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X-%u.%u.%u.%u\n",
//		node->mac.bytes[0], node->mac.bytes[1], node->mac.bytes[2], node->mac.bytes[3], node->mac.bytes[4], node->mac.bytes[5],
//		node->ip.bytes[0], node->ip.bytes[1], node->ip.bytes[2], node->ip.bytes[3]);

	return xdr_encode_nodes(xdr, time, 1, &message, type);
}

int xdr_encode_finish(XDR * xdr, unsigned int time, unsigned int count) {
	if (xdr->x_op != XDR_ENCODE) return false;

	TSoderoTCPReportMsg message;
	bzero(&message, sizeof(message));
	message.type = METRIC_FINISH;

	xdr_data(message.TSoderoTCPReportMsg_u.metric_finish.time , time );
	xdr_data(message.TSoderoTCPReportMsg_u.metric_finish.count, count);

	return xdr_TSoderoTCPReportMsg(xdr, &message);
}

int xdr_encode_answer(XDR * xdr, unsigned int value) {
	if (xdr->x_op != XDR_ENCODE) return false;

	TSoderoTCPReportMsg message;
	bzero(&message, sizeof(message));
	message.type = SERVER_ACK;

	xdr_data(message.TSoderoTCPReportMsg_u.server_ack.ack_val, value);

	return xdr_TSoderoTCPReportMsg(xdr, &message);
}

int xdr_answer(XDR * xdr) {
	if (xdr->x_op != XDR_DECODE) return false;

	TSoderoTCPReportMsg message;
	if (!xdr_TSoderoTCPReportMsg(xdr, &message))
		return false;

	if (message.type != SERVER_ACK)
		return false;

	return message.TSoderoTCPReportMsg_u.server_ack.ack_val;
}

int xdr_encode_tcp(XDR * xdr, TSoderoTCPReportMsg * message) {
	return xdr_TSoderoTCPReportMsg(xdr, message);
}
int xdr_encode_udp(XDR * xdr, TSoderoUDPReportMsg * message) {
	return xdr_TSoderoUDPReportMsg(xdr, message);
}
#endif
