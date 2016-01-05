/*
 * Report.c
 *
 *  Created on: Aug 25, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <rpc/types.h>
#include <rpc/rpc.h>
#include <ifaddrs.h>
#if defined(__FreeBSD__) || defined(__APPLE__)
#include <net/if_dl.h>
#endif
#include <sys/ipc.h>
#include <sys/shm.h>

#include "interface.h"
#include "flow_stats_api.h"

#include "Type.h"
#include "Parameter.h"
#include "Common.h"
#include "HTTP.h"
#include "Session.h"
#include "Dump.h"
#include "XDR.h"
#include "Logic.h"
#include "Report.h"

extern int sodero_report_udp_application(PSoderoApplication session, int flag);
extern int sodero_report_tcp_application(PSoderoApplication session, int flag);

unsigned long long gReportCounter;

int gTCPSocket;
int gUDPSocket;

int gTCPBytes;
int gUDPBytes;

int  gTCPOffset = 0;
char gTCPBuffer[2 * XDR_BUFFER_SIZE];
TSoderoShmMsg *gShmMsg = NULL;

#define CHECK_SESSION_RECORD_VALUE(type, name, record) \
	checkSessionValue(&value->key, type, #name, record->name);

#define CHECK_SESSION_RECORD_STRING(type, name, record) \
	checkSessionString(&value->key, type, #name, record->name);


#define CHECK_APPLICATION_RECORD_TEXT(type, name, record) \
	checkApplicationString(&owner->key, owner->flag, type, #name, (const char *)record->name);

#define CHECK_APPLICATION_RECORD_VALUE(type, name, record) \
	checkApplicationValue(&owner->key, owner->flag, type, #name, record->name);

#define CHECK_APPLICATION_RECORD_STRING(type, name, record) \
	checkApplicationString(&owner->key, owner->flag, type, #name, (const char *)record->name.name##_val);


#define CHECK_SESSION_VALUE(type, name) \
	checkSessionValue(&value->key, type, #name, record->name);

#define CHECK_SESSION_STRING(type, name) \
	checkSessionString(&value->key, type, #name, record->name);


#define CHECK_APPLICATION_TEXT(type, name) \
	checkApplicationString(&owner->key, owner->flag, type, #name, (const char *)record->name);

#define CHECK_APPLICATION_VALUE(type, name) \
	checkApplicationValue(&owner->key, owner->flag, type, #name, record->name);

#define CHECK_APPLICATION_STRING(type, name) \
	checkApplicationString(&owner->key, owner->flag, type, #name, (const char *)record->name.name##_val);


const char * nodeName(int type) {
	switch(type) {
	case SODERO_NODES:
		return "Sodero";
	case ORIGIN_NODES:
		return "Origin";
	}
	return "Unknown";
}

void checkNode(PNodeIndex index, const char * name, int type) {
	if (!name) name = "";

	if (gCheck) {
		printf("[Test-Node]%.2x:%.2x:%.2x:%.2x:%.2x:%.2x|%u.%u.%u.%u|%s\n",
			index->mac.bytes[0], index->mac.bytes[1], index->mac.bytes[2], index->mac.bytes[3], index->mac.bytes[4], index->mac.bytes[5],
			index->ip.l.s[0], index->ip.l.s[1], index->ip.l.s[2], index->ip.l.s[3], nodeName(type));
	}
}

void checkNodeValue(PNodeIndex index, const char * name, unsigned long long value) {
	if (gCheck && value) {
		struct {
			char sMAC[32], sIP[32];
		} data;
		bzero(&data, sizeof(data));
		if (index->mac.b4 | index->mac.b2)
			snprintf(data.sMAC, sizeof(data.sMAC)-1, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
					index->mac.bytes[0], index->mac.bytes[1], index->mac.bytes[2], index->mac.bytes[3], index->mac.bytes[4], index->mac.bytes[5]);

		if (index->ip.l.ip)
			snprintf(data.sIP, sizeof(data.sIP), "%u.%u.%u.%u",
					index->ip.bytes[0], index->ip.bytes[1], index->ip.bytes[2], index->ip.bytes[3]);
		printf("[TEST-Value]%llu|%s|%s|%s|%llu\n", gReportCounter, data.sMAC, data.sIP, name, value);
	}
}

void checkNodeDatum(PNodeIndex index, const char * name, PSoderoUnitDatum value) {
	if (gCheck && value && value->count) {
		struct {
			char sMAC[32], sIP[32];
		} data;
		bzero(&data, sizeof(data));
		if (index->mac.b4 | index->mac.b2)
			snprintf(data.sMAC, sizeof(data.sMAC)-1, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
					index->mac.bytes[0], index->mac.bytes[1], index->mac.bytes[2], index->mac.bytes[3], index->mac.bytes[4], index->mac.bytes[5]);

		if (index->ip.l.ip)
			snprintf(data.sIP, sizeof(data.sIP), "%u.%u.%u.%u",
					index->ip.bytes[0], index->ip.bytes[1], index->ip.bytes[2], index->ip.bytes[3]);
		printf("[TEST-Value]%llu|%s|%s|%s.count|%llu\n", gReportCounter, data.sMAC, data.sIP, name, value->count);
		printf("[TEST-Value]%llu|%s|%s|%s.sum|%llu\n"  , gReportCounter, data.sMAC, data.sIP, name, value->sum  );
		printf("[TEST-Value]%llu|%s|%s|%s.max|%llu\n"  , gReportCounter, data.sMAC, data.sIP, name, value->max  );
		printf("[TEST-Value]%llu|%s|%s|%s.min|%llu\n"  , gReportCounter, data.sMAC, data.sIP, name, value->min  );
	}
}

void checkSessionValue(PPortKey key, const char * type, const char * name, unsigned long long value) {
	if (gCheck && value) {
		printf("[TEST-Session-%s]%llu|%u.%u.%u.%u:%u|%u.%u.%u.%u:%u|%s|%s|%llu\n", type, gReportCounter,
				key->s[0], key->s[1], key->s[2], key->s[3], key->sourPort,
				key->d[0], key->d[1], key->d[2], key->d[3], key->destPort,
				ipv4_proto_name(key->proto), name, value);
	}
}

void checkSessionString(PPortKey key, const char * type, const char * name, const char * value) {
	if (gCheck && value && *value) {
		printf("[TEST-Session-%s]%llu|%u.%u.%u.%u:%u|%u.%u.%u.%u:%u|%s|%s|%s\n", type, gReportCounter,
				key->s[0], key->s[1], key->s[2], key->s[3], key->sourPort,
				key->d[0], key->d[1], key->d[2], key->d[3], key->destPort,
				ipv4_proto_name(key->proto), name, value);
	}
}


void checkApplicationValue(PPortKey key, unsigned char flag, const char * type, const char * name, unsigned long long value) {
	if (gCheck && value) {
		printf("[TEST-Application-%s]%llu|%u.%u.%u.%u:%u|%u.%u.%u.%u:%u|%s|%s|%llu\n", type, gReportCounter,
				key->s[0], key->s[1], key->s[2], key->s[3], key->sourPort,
				key->d[0], key->d[1], key->d[2], key->d[3], key->destPort,
				application_name(key->proto, flag), name, value);
	}
}

void checkApplicationString(PPortKey key, unsigned char flag, const char * type, const char * name, const char * value) {
	if (gCheck && value && *value) {
		printf("[TEST-Application-%s]%llu|%u.%u.%u.%u:%u|%u.%u.%u.%u:%u|%s|%s|%s\n", type, gReportCounter,
				key->s[0], key->s[1], key->s[2], key->s[3], key->sourPort,
				key->d[0], key->d[1], key->d[2], key->d[3], key->destPort,
				application_name(key->proto, flag), name, value);
	}
}

int isExportFlow(int proto) {
	if ((gCheck & SODERO_CHECK_TCP) && (proto == IPv4_TYPE_TCP)) return true;
	if ((gCheck & SODERO_CHECK_UDP) && (proto == IPv4_TYPE_UDP)) return true;
	return false;
}

int isExportApplication(int proto, int flag) {
	if ((gCheck & SODERO_CHECK_HTTP) && (proto == IPv4_TYPE_TCP) && (flag == SESSION_TYPE_MINOR_HTTP )) return true;
	if ((gCheck & SODERO_CHECK_HTTP) && (proto == IPv4_TYPE_TCP) && (flag == SESSION_TYPE_MINOR_MYSQL)) return true;
	if ((gCheck & SODERO_CHECK_DNS ) && (proto == IPv4_TYPE_UDP) && (flag == SESSION_TYPE_MINOR_DNS  )) return true;
	if ((gCheck & SODERO_CHECK_HTTP) && (proto == IPv4_TYPE_TCP) && (flag == SESSION_TYPE_MINOR_HTTPS )) return true;
	return false;
}

int write2socket(int * fd, void * buffer, int length, int proto) {
	processA(&gReportSend, length);

#ifdef __SKIP_WRITE__
	return TRUE;
#else
#ifdef __DEBUG__
//	usleep(0);
#endif
	if (fd) {
		int offset = 0;
		while(*fd) {
			int result = write(*fd, buffer + offset, length - offset);
			if (result <= 0) {
				return false;
			}

			offset += result;
			if (offset < length) {
				switch (proto) {
				case IPPROTO_TCP:
					continue;
//				case IPPROTO_UDP:
				default:
					return false;
				}
			}
			return TRUE;
		}
	}
	return FALSE;
#endif
}

int sodero_connect2server(const char * server, const char * service, int type) {
    struct addrinfo hints, *servinfo;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type;

    printf("%s connect to %s:%s\n", socket_type_name(type), server, service);

    int result = getaddrinfo(server, service, &hints, &servinfo);
    if (result != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        return 1;
    }

    if (servinfo == NULL) {
        fprintf(stderr, "client: failed to connect %s\n", socket_type_name(type));
        return 2;
    }

    result = -1;

    for(struct addrinfo * p = servinfo; p != NULL; p = p->ai_next) {
    	if (p->ai_addr == NULL) continue;
    	switch(p->ai_family) {
    	case PF_INET: //	same as AF_INET:
        	result = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (result == -1) {
                fprintf(stderr, "client: socket %s\n", socket_type_name(type));
                continue;
            }

            if (connect(result, p->ai_addr, p->ai_addrlen) == -1) {
                close(result);
                fprintf(stderr, "client: connect %s\n", socket_type_name(type));
                continue;
            }

            printf("Connect to server %s @ %d\n", socket_type_name(type), result);
    		break;
    	default:
    		continue;
    	}

    	break;
    }

    freeaddrinfo(servinfo);

   	return result;
}

int sodero_xdr_ack(int * fd) {
#ifdef __SKIP_WRITE__
	return TRUE;
#else
	if (fd)
	while (*fd > 0) {
		if (gTCPOffset > 0) {
			XDR xdr;
			sodero_init_xdr_decode(&xdr, gTCPBuffer, gTCPOffset);
			int result = xdr_answer(&xdr);
			if (result) {
				int length = xdr_getpos(&xdr);
				do {
					if ((length > 0) && (gTCPOffset > length)) {
						memmove(gTCPBuffer, gTCPBuffer + length, gTCPOffset - length);
						gTCPOffset -= length;
						break;
					}
					gTCPOffset = 0;
				} while (false);
				return result;
			}
		}
		int size = read(*fd, gTCPBuffer + gTCPOffset, sizeof(gTCPBuffer) - gTCPOffset);
		if (size <= 0) break;
		processA(&gReportRecv, size);
		gTCPOffset += size;
	}
	return false;
#endif
}

int sodero_xdr_okay(int * fd) {
#ifdef __SKIP_WRITE__
	return TRUE;
#else
	return sodero_xdr_ack(fd) == SODER_XDR_SUCCESS;
#endif
}

int sodero_xdr_cmd_register(int * fd, unsigned int time) {
	XDR xdr;
	char buffer[XDR_BUFFER_SIZE];
	sodero_init_xdr_encode(&xdr, buffer, sizeof(buffer));
	if (xdr_encode_register(&xdr, time, gVersion.s, gMAC.bytes, gHost.bytes, gName)) {
		int length = xdr_getpos(&xdr);
		gTCPBytes += length;
		return write2socket(fd, buffer, length, IPPROTO_TCP);
	}
	return false;
}

int sodero_xdr_cmd_finish(int * fd, unsigned int time, unsigned int count) {
	if (isExportDetail())
		printf("Finisned %d/%d\n", time, count);

	XDR xdr;
	char buffer[XDR_BUFFER_SIZE];
	sodero_init_xdr_encode(&xdr, buffer, sizeof(buffer));
	if (xdr_encode_finish(&xdr, time, count)) {
		int length = xdr_getpos(&xdr);
		gTCPBytes += length;
		return write2socket(fd, buffer, length, IPPROTO_TCP);
	}
	return false;
}

int sodero_xdr_cmd_node(int * fd, unsigned int time, PNodeIndex node, const char * name, int type) {
	if (isExportDetail())
		printf("Node %.2x:%.2x:%.2x:%.2x:%.2x:%.2x-%u.%u.%u.%u\n",
				node->mac.bytes[0], node->mac.bytes[1], node->mac.bytes[2], node->mac.bytes[3], node->mac.bytes[4], node->mac.bytes[5],
				node->ip.l.s[0], node->ip.l.s[1], node->ip.l.s[2], node->ip.l.s[3]);
	 /*write to log file*/
       /*LogDbg("Node %.2x:%.2x:%.2x:%.2x:%.2x:%.2x-%u.%u.%u.%u\n",
				node->mac.bytes[0], node->mac.bytes[1], node->mac.bytes[2], node->mac.bytes[3], node->mac.bytes[4], node->mac.bytes[5],
				node->ip.l.s[0], node->ip.l.s[1], node->ip.l.s[2], node->ip.l.s[3]);*/
       
	XDR xdr;
	char buffer[XDR_BUFFER_SIZE];
	sodero_init_xdr_encode(&xdr, buffer, sizeof(buffer));
	if (xdr_encode_node(&xdr, time, node, name, type)) {
		int length = xdr_getpos(&xdr);
		gTCPBytes += length;
		return write2socket(fd, buffer, length, IPPROTO_TCP);
	}
	return false;
}

int sodero_xdr_tcp_message(int * fd, TSoderoTCPReportMsg * message) {
	XDR xdr;
	char buffer[XDR_BUFFER_SIZE];

	sodero_init_xdr_encode(&xdr, buffer, sizeof(buffer));
	if (xdr_TSoderoTCPReportMsg(&xdr, message)) {
		int length = xdr_getpos(&xdr);
		gTCPBytes += length;
		if (message->type == SESSION_EVENT && !gTCPSession)
		{
			return sodero_write_message(buffer);
		}
		else
		{
            if (message->type == SESSION_EVENT) {
                printf("**********************************************\n");
            }
			return write2socket(fd, buffer, length, IPPROTO_TCP);
		}
	}
	return false;
}

//int sodero_xdr_cmd_nodes(int fd, unsigned int time, int count, PNodeIndex node) {
//	XDR xdr;
//	char buffer[XDR_BUFFER_SIZE];
//	sodero_init_xdr_encode(&xdr, buffer, sizeof(buffer));
//	if (xdr_encode_nodes(&xdr, time, count, node)) {
//		int size = xdr_getpos(&xdr);
//		return write(fd, buffer, size) == size;
//	}
//	return false;
//}

int sodero_xdr_cmd_value(int * fd, unsigned int time, PNodeIndex index, PXDRFieldName name, unsigned long long value) {
	char * l2type = strcasestr(name->string, "l2.");
	if (isExportVerbose())
		printf("Node %.2x:%.2x:%.2x:%.2x:%.2x:%.2x-%u.%u.%u.%u XDR %s %llu\n",
				index->mac.bytes[0], index->mac.bytes[1], index->mac.bytes[2], index->mac.bytes[3], index->mac.bytes[4], index->mac.bytes[5],
				index->ip.l.s[0], index->ip.l.s[1], index->ip.l.s[2], index->ip.l.s[3], name->string, value);

	/*write to log file*/
	if (l2type != NULL){
		LogDbg("[Metric:%d |%s |%.2x:%.2x:%.2x:%.2x:%.2x:%.2x |0.0.0.0 | %llu ]",time, name->string, index->mac.bytes[0], index->mac.bytes[1], 
            index->mac.bytes[2], index->mac.bytes[3], index->mac.bytes[4], index->mac.bytes[5], value);
	}
	else{
		LogDbg("[Metric:%d |%s |00:00:00:00:00:00 |%u.%u.%u.%u | %llu ]",time, name->string, index->ip.l.s[0], index->ip.l.s[1],
			index->ip.l.s[2], index->ip.l.s[3],value);
	}
       
	XDR xdr;
	char buffer[XDR_BUFFER_SIZE];
	sodero_init_xdr_encode(&xdr, buffer, sizeof(buffer));
	if (xdr_encode_field_value(&xdr, time, index, name, value)) {
		int length = xdr_getpos(&xdr);
		gUDPBytes += length;
		return write2socket(fd, buffer, length, IPPROTO_UDP);
	}
	return false;
}

int sodero_xdr_cmd_datum(int * fd, unsigned int time, PNodeIndex index, PXDRFieldName name, PSoderoUnitDatum value) {
	if (isExportVerbose())
		printf("Node %.2x:%.2x:%.2x:%.2x:%.2x:%.2x-%u.%u.%u.%u XDR %s count %llu sum %llu max %llu min %llu\n",
				index->mac.bytes[0], index->mac.bytes[1], index->mac.bytes[2], index->mac.bytes[3], index->mac.bytes[4], index->mac.bytes[5],
				index->ip.l.s[0], index->ip.l.s[1], index->ip.l.s[2], index->ip.l.s[3], name->string, value->count, value->sum, value->max, value->min);

       /*write to log file*/
       LogDbg("[Metric:%d |%s |%.2x:%.2x:%.2x:%.2x:%.2x:%.2x |%u.%u.%u.%u | %llu ]",time, name->string, index->mac.bytes[0], index->mac.bytes[1], 
                            index->mac.bytes[2], index->mac.bytes[3], index->mac.bytes[4], index->mac.bytes[5], index->ip.l.s[0], index->ip.l.s[1], index->ip.l.s[2], index->ip.l.s[3],value);
       
	XDR xdr;
	char buffer[XDR_BUFFER_SIZE];
	sodero_init_xdr_encode(&xdr, buffer, sizeof(buffer));
	if (xdr_encode_field_datum(&xdr, time, index, name, value)) {
		int length = xdr_getpos(&xdr);
		gUDPBytes += length;
		return write2socket(fd, buffer, length, IPPROTO_UDP);
	}
	return false;
}

int sodero_report_shakehand(void) {
	if(sodero_xdr_cmd_register(&gTCPSocket, gReportCounter)) {
		int serial = sodero_xdr_ack(&gTCPSocket);
		if (serial > 0)
			gAgentID = serial;
		return gAgentID > 0;
	}
	return false;
}

int sodero_report_finished(unsigned int count) {
	return sodero_xdr_cmd_finish(&gTCPSocket, gReportCounter, count) && sodero_xdr_okay(&gTCPSocket);
}

int sodero_report_node(PNodeIndex node, const char * name, int type) {
	checkNode(node, name, type);
	return sodero_xdr_cmd_node(&gTCPSocket, gReportCounter, node, name, type);	// && sodero_xdr_okay(gTCPSocket);
}

//int sodero_report_nodes(int count, const PNodeIndex * node) {
//	return sodero_xdr_cmd_nodes(gTCP, gReport, count, node);	// && sodero_xdr_okay(gTCP);
//}

int sodero_report_field_value (PNodeIndex index, PXDRFieldName field, unsigned long long value) {
	if (!field) return false;
	return sodero_xdr_cmd_value(&gUDPSocket, gReportCounter, index, field, value);
}

int sodero_report_named_value (PNodeIndex index, const char *  name, unsigned long long value) {
	if (!name) return false;
	char text[256];
	int size = strlen(name);
	strncpy(text, name, sizeof(text)-1);
	TXDRFieldName field = {text, size};
	return sodero_report_field_value(index, &field, value);
}

int sodero_report_field_datum (PNodeIndex index, PXDRFieldName field, PSoderoUnitDatum value) {
	if (!field) return false;
	return sodero_xdr_cmd_datum(&gUDPSocket, gReportCounter, index, field, value);
}

int sodero_report_named_datum (PNodeIndex index, const char *  name, PSoderoUnitDatum value) {
	if (!name) return false;
	char text[256];
	int size = strlen(name);
	strncpy(text, name, sizeof(text)-1);
	TXDRFieldName field = {text, size};
	return sodero_report_field_datum(index, &field, value);
}

int sodero_report_flow_head(PSoderoPortSession value, int flag) {
	if (value) {
//		printf("Report FLOW Head: %p\n", value);

		TXDREventBuffer data;
		bzero(&data.event, sizeof(data.event));
		data.event.data.length = sizeof(data) - sizeof(data.event);

		TSoderoTCPReportMsg * report = &data.event.message;
		report->type = SESSION_EVENT;

		TSoderoSessionMsg * session = &report->TSoderoTCPReportMsg_u.session_event;
		switch(value->key.proto) {
		case IPv4_TYPE_TCP:
			session->event = EVENT_TYPE_TCP_OPEN;
			break;
		case IPv4_TYPE_UDP:
			session->event = EVENT_TYPE_UDP_OPEN;
			break;
		}

//		printf("Head %s event %d %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", ipv4_proto_name(value->key.proto), session->event,
//				value->key.s[0], value->key.s[1], value->key.s[2], value->key.s[3], ntohs(value->key.sourPort),
//				value->key.d[0], value->key.d[1], value->key.d[2], value->key.d[3], ntohs(value->key.destPort));

		TSoderoTCPSessionContent * content = &session->session_content;
		content->type = SESSION_TYPE_FLOW_HEAD;

		TSoderoFLOWSessionHead * record = &content->TSoderoTCPSessionContent_u.flow_head;

		record->flow_sessin_id = value->id;
		record->age = value->e > value->b ? (value->e - value->b) / uSecsPerMSec : 0;
		record->connect_time = value->b / uSecsPerSec;
		record->vlan = value->eth.vlan;
//		*(PMAC)record->client_mac = value->eth.sour;
		memcpy(record->client_mac, &value->eth.sour, sizeof(value->eth.sour));
//		*(PMAC)record->server_mac = value->eth.dest;
		memcpy(record->server_mac, &value->eth.dest, sizeof(value->eth.dest));
//		*(unsigned int *)record->client_ip = value->key.sourIP;
		memcpy(record->client_ip, &value->key.sourIP, sizeof(value->key.sourIP));
//		*(unsigned int *)record->server_ip = value->key.destIP;
		memcpy(record->server_ip, &value->key.destIP, sizeof(value->key.destIP));
		record->client_port = value->key.sourPort;
		record->server_port = value->key.destPort;
		record->identify = value->key.sequence;

		record->l2_type = L2_TYPE_IPV4;
		record->l3_type = value->key.proto;

		if (isExportFlow(value->key.proto)) {
			checkSessionValue(&value->key, REPORT_TYPE_HEAD, "report_type", report->type);
			checkSessionValue(&value->key, REPORT_TYPE_HEAD, "content_type", content->type);
			checkSessionValue(&value->key, REPORT_TYPE_HEAD, "session_event", session->event);
			CHECK_SESSION_VALUE(REPORT_TYPE_HEAD, flow_sessin_id);
			CHECK_SESSION_VALUE(REPORT_TYPE_HEAD, connect_time);
			CHECK_SESSION_VALUE(REPORT_TYPE_HEAD, age);
			CHECK_SESSION_VALUE(REPORT_TYPE_HEAD, vlan);
		}
		return sodero_xdr_tcp_message(&gTCPSocket, report);
	}
	return false;
}

int sodero_report_flow_body(PSoderoPortSession value, int flag) {
	if (value) {
//		printf("Report FLOW Body: %p\n", value);

		TXDREventBuffer data;
		bzero(&data.event, sizeof(data.event));
		data.event.data.length = sizeof(data) - sizeof(data.event);

		TSoderoTCPReportMsg * report = &data.event.message;
		report->type = SESSION_EVENT;

		TSoderoSessionMsg * session = &report->TSoderoTCPReportMsg_u.session_event;
		if (flag)
			switch(value->key.proto) {
			case IPv4_TYPE_TCP:
				session->event = EVENT_TYPE_TCP_CLOSE;
				break;
			case IPv4_TYPE_UDP:
				session->event = EVENT_TYPE_UDP_CLOSE;
				break;
			}
		TSoderoTCPSessionContent * content = &session->session_content;
		content->type = SESSION_TYPE_FLOW_BODY;

//		printf("Body %s event %d %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", ipv4_proto_name(value->key.proto), session->event,
//				value->key.s[0], value->key.s[1], value->key.s[2], value->key.s[3], ntohs(value->key.sourPort),
//				value->key.d[0], value->key.d[1], value->key.d[2], value->key.d[3], ntohs(value->key.destPort));

		TSoderoFLOWSessionBody * record = &content->TSoderoTCPSessionContent_u.flow_body;
        
		record->l3_type = value->key.proto;

		record->flow_sessin_id = value->id;
		record->client_bytes = value->traffic.outgoing.bytes;
		record->server_bytes = value->traffic.incoming.bytes;
		record->client_pkts  = value->traffic.outgoing.count;
		record->server_pkts  = value->traffic.incoming.count;

		record->client_l2_bytes = value->l2.outgoing;
		record->server_l2_bytes = value->l2.incoming;

		switch(value->key.proto) {
			case IPPROTO_ICMP:
//				PSoderoICMPSession tcp = (PSoderoICMPSession) value;
				break;
			case IPPROTO_TCP: {
				PSoderoTCPSession tcp = (PSoderoTCPSession) value;
				record->expired = tcp->state == SODERO_TCP_ESTABLISHED;
				record->app = tcp->application;
				record->major = tcp->major;
				record->minor = tcp->minor;
				record->client_abort = tcp->value.outgoing.rstCount;
				record->server_abort = tcp->value.incoming.rstCount;

				record->rttValue = tcp->value.outgoing.rttValue + tcp->value.incoming.rttValue;
				record->rttCount = tcp->value.outgoing.rttCount + tcp->value.incoming.rttCount;

				record->droppedCount    = tcp->value.outgoing.droppedCount    + tcp->value.incoming.droppedCount   ;
				record->droppedBytes    = tcp->value.outgoing.droppedBytes    + tcp->value.incoming.droppedBytes   ;
				record->reorderedCount  = tcp->value.outgoing.reorderedCount  + tcp->value.incoming.reorderedCount ;
				record->reorderedBytes  = tcp->value.outgoing.reorderedBytes  + tcp->value.incoming.reorderedBytes ;
				record->retransmitCount = tcp->value.outgoing.retransmitCount + tcp->value.incoming.retransmitCount;
				record->retransmitBytes = tcp->value.outgoing.retransmitBytes + tcp->value.incoming.retransmitBytes;
				record->streamBytes     = tcp->value.outgoing.streamBytes     + tcp->value.incoming.streamBytes    ;
				record->missedBytes     = tcp->value.outgoing.missedBytes     + tcp->value.incoming.missedBytes    ;

				record->client_rtos = SODERO_SAFE_RATE(tcp->value.outgoing, rtt);
				record->client_zwnds = tcp->value.outgoing.zwnds;
				record->client_nagle_delays = tcp->value.outgoing.nagle_delays;
				record->client_rcv_wnd_throttles = tcp->value.outgoing.rcv_wnd_throttles;

				record->server_rtos = SODERO_SAFE_RATE(tcp->value.incoming, rtt);
				record->server_zwnds = tcp->value.incoming.zwnds;
				record->server_nagle_delays = tcp->value.incoming.nagle_delays;
				record->server_rcv_wnd_throttles = tcp->value.incoming.rcv_wnd_throttles;

				record->turns = tcp->value.turns_count;
				record->turns_sum_time = tcp->value.turns_sum_time;
				record->turns_min_time = tcp->value.turns_min_time;
				record->turns_max_time = tcp->value.turns_max_time;
				record->turns_sum_interval = tcp->value.turns_sum_interval;
				record->turns_min_interval = tcp->value.turns_min_interval;
				record->turns_max_interval = tcp->value.turns_max_interval;
				record->turns_sum_bytes = tcp->value.turns_sum_bytes;
				record->turns_min_bytes = tcp->value.turns_min_bytes;
				record->turns_max_bytes = tcp->value.turns_max_bytes;
				break;
			}
			case IPPROTO_UDP: {
//				PSoderoUDPSession tcp = (PSoderoUDPSession) value;
				break;
			}
		}
		if (isExportFlow(value->key.proto)) {
			checkSessionValue(&value->key, REPORT_TYPE_BODY, "report_type", report->type);
			checkSessionValue(&value->key, REPORT_TYPE_BODY, "content_type", content->type);
			checkSessionValue(&value->key, REPORT_TYPE_BODY, "session_event", session->event);

			CHECK_SESSION_VALUE(REPORT_TYPE_BODY, flow_sessin_id);
			CHECK_SESSION_VALUE(REPORT_TYPE_BODY, client_bytes);
			CHECK_SESSION_VALUE(REPORT_TYPE_BODY, server_bytes);
			CHECK_SESSION_VALUE(REPORT_TYPE_BODY, client_pkts);
			CHECK_SESSION_VALUE(REPORT_TYPE_BODY, server_pkts);

			CHECK_SESSION_VALUE(REPORT_TYPE_BODY, client_l2_bytes);
			CHECK_SESSION_VALUE(REPORT_TYPE_BODY, server_l2_bytes);

			switch(value->key.proto) {
				case IPPROTO_ICMP:
					break;
				case IPPROTO_TCP: {
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, expired);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, client_abort);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, server_abort);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, rttValue);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, rttCount);

					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, droppedCount);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, droppedBytes);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, reorderedCount);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, reorderedBytes);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, retransmitCount);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, retransmitBytes);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, streamBytes);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, missedBytes);

					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, client_rtos);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, client_zwnds);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, client_nagle_delays);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, client_rcv_wnd_throttles);

					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, server_rtos);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, server_zwnds);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, server_nagle_delays);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, server_rcv_wnd_throttles);

					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, turns);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, turns_sum_time);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, turns_min_time);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, turns_max_time);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, turns_sum_interval);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, turns_min_interval);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, turns_max_interval);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, turns_sum_bytes);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, turns_min_bytes);
					CHECK_SESSION_VALUE(REPORT_TYPE_BODY, turns_max_bytes);
					break;
				}
				case IPPROTO_UDP: {
					break;
				}
			}
		}
		return sodero_xdr_tcp_message(&gTCPSocket, report);
	}
	return false;
}

int sodero_report_dns_application(PSoderoApplicationDNS value, int flag) {
	int result = 0;
	while (value) {
		PSoderoUDPSession owner = value->owner;
//		printf("Report DNS: %p\n", value);
		TXDREventBuffer data;
		bzero(&data.event, sizeof(data.event));
		data.event.data.length = sizeof(data) - sizeof(data.event);

		TSoderoTCPReportMsg * report = &data.event.message;
		report->type = SESSION_EVENT;

		TSoderoSessionMsg * session = &report->TSoderoTCPReportMsg_u.session_event;
		session->event = EVENT_TYPE_DNS;

		TSoderoTCPSessionContent * content = &session->session_content;
		content->type = SESSION_TYPE_DNS;

		TSoderoDNSSessionMsg * record = &content->TSoderoTCPSessionContent_u.dns;

		record->dns_session_id  = value->id;
		record->flow_session_id = owner->id;
        
        memcpy(record->client_mac, &value->owner->eth.sour, sizeof(value->owner->eth.sour));
        memcpy(record->server_mac, &value->owner->eth.dest, sizeof(value->owner->eth.dest));
        memcpy(record->client_ip, &value->owner->key.sourIP, sizeof(value->owner->key.sourIP));
        memcpy(record->server_ip, &value->owner->key.destIP, sizeof(value->owner->key.destIP));
        record->client_port = value->owner->key.sourPort;
        record->server_port = value->owner->key.destPort;
        

		if (value->b) {
			if (value->e) {
				record->wait_time = (value->e - value->b) / uSecsPerMSec;
				record->rtt       = (value->e - value->b) / uSecsPerMSec;
			} else
				record->req_timeout = true;
		}

		record->req_bytes     = value->traffic.outgoing.bytes;
		record->req_pkts      = value->traffic.outgoing.count;
		record->req_l2_bytes  = value->l2.outgoing;
		record->rsp_bytes     = value->traffic.incoming.bytes;
		record->rsp_pkts      = value->traffic.incoming.count;
		record->rsp_l2_bytes  = value->l2.incoming;

		record->rsp_truncated = value->truncated;
		record->authoritative = value->authoritative;

//		record->qname.qname_val = xdr_store_string(&data.event.data, value->query, &record->qname.qname_len);
		SODERO_SAFE_TEXT(record, qname, value->query);
//		record->qtype.qtype_val = xdr_store_string(&data.event.data, dns_t_name(value->type), &record->qtype.qtype_len);
		SODERO_SAFE_TEXT(record, qtype, dns_t_name(value->type));

		record->opcode = value->ocode;

//		record->error.error_val = xdr_store_string(&data.event.data, dns_r_name(value->rcode), &record->error.error_len);
		SODERO_SAFE_TEXT(record, error, dns_r_name(value->rcode));

		if (value->data) {
			PSoderoDNSAnswerEntry entries = (PSoderoDNSAnswerEntry) value->data;
			record->answers.answers_len = value->answer;
			record->answers.answers_val = (TSoderoDNSAnswer *)(data.event.data.buffer + data.event.data.offset);
			data.event.data.offset += value->answer * sizeof(TSoderoDNSAnswer);
			for (int i = 0; i < value->answer; i++) {
				TSoderoDNSAnswer * answer = &record->answers.answers_val[i];
				PSoderoDNSAnswerEntry entry = &entries[i];
				answer->ttl = entry->time;
//				answer->name.name_val = xdr_store_string(&data.event.data, value->data + entry->name, &answer->name.name_len);
				SODERO_SAFE_TEXT(answer, name, value->data + entry->name);
//				answer->type.type_val = xdr_store_string(&data.event.data, dns_t_name(entry->type), &answer->type.type_len);
				SODERO_SAFE_TEXT(answer, type, dns_t_name(entry->type));
//				answer->data.data_val = xdr_store_string(&data.event.data, value->data + entry->data, &answer->data.data_len);
				SODERO_SAFE_TEXT(answer, data, value->data + entry->data);
			}
		}
//		struct {
//			u_int answers_len;
//			TSoderoDNSAnswer *answers_val;
//		} answers;

		if (isExportReport()) {
			printf("Report DNS: from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u session %llu application %llu @ %llu \n"
					"\ttime %llu to %llu seq %u type %u ocode %u rcode %u domain %s\n",
				owner->key.s[0], owner->key.s[1], owner->key.s[2], owner->key.s[3], ntohs(owner->key.sourPort),
				owner->key.d[0], owner->key.d[1], owner->key.d[2], owner->key.d[3], ntohs(owner->key.destPort),
				owner->id, value->id, value->serial,
				value->b, value->e, value->sequence, value->type, value->ocode, value->rcode, value->query);
		}

		if (isExportApplication(owner->key.proto, owner->flag)) {
			checkSessionValue(&owner->key, REPORT_TYPE_BODY, "report_type"  , report->type  );
			checkSessionValue(&owner->key, REPORT_TYPE_BODY, "content_type" , content->type );
			checkSessionValue(&owner->key, REPORT_TYPE_BODY, "session_event", session->event);

			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, dns_session_id );
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, flow_session_id);

			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, wait_time   );
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rtt         );
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, req_timeout );

			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, req_bytes   );
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, req_pkts    );
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, req_l2_bytes);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rsp_bytes   );
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rsp_pkts    );
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rsp_l2_bytes);

			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rsp_truncated);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, authoritative);

			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, qname);
			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, qtype);

			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, opcode);

			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, error);
			for (int i = 0; i < record->answers.answers_len; i++) {
				TSoderoDNSAnswer * answer = &record->answers.answers_val[i];
				CHECK_APPLICATION_RECORD_VALUE (REPORT_TYPE_BODY, ttl , answer);
				CHECK_APPLICATION_RECORD_STRING(REPORT_TYPE_BODY, name, answer);
				CHECK_APPLICATION_RECORD_STRING(REPORT_TYPE_BODY, type, answer);
				CHECK_APPLICATION_RECORD_STRING(REPORT_TYPE_BODY, data, answer);
			}
		}

		if (sodero_xdr_tcp_message(&gTCPSocket, report))
			result++;

//		value = value->link;
		break;
	}
	return result;
}

int sodero_report_tns_application(PSoderoTnsApplication value, int flag) {
	int result = 0;
	while (value) {
		PSoderoTCPSession owner = value->owner;
		TXDREventBuffer data;
		bzero(&data.event, sizeof(data.event));
		data.event.data.length = sizeof(data) - sizeof(data.event);

		TSoderoTCPReportMsg * report = &data.event.message;
		report->type = SESSION_EVENT;

		TSoderoSessionMsg * msssage = &report->TSoderoTCPReportMsg_u.session_event;
		msssage->event = EVENT_TYPE_DB_ORACLE;

		TSoderoTCPSessionContent * content = &msssage->session_content;
		content->type = SESSION_TYPE_ORACLE;

		if (value->command == TNS_METHOD_LOGIN) {
			content->TSoderoTCPSessionContent_u.tns.type = ORACLE_METHOD_LOGIN;
			TSoderoOracleMsg * record = & content->TSoderoTCPSessionContent_u.tns.oracle_msg;
			record->session_id = owner->id;
			record->flow_id = value->id;
			record->req_time = value->reqLast -  value->reqFirst;
			record->rsp_time = value->rspLast - value->rspFirst;
			record->wait_time = value->rspFirst - value->reqLast;
			SODERO_SAFE_TEXT(record, user, value->user);
			SODERO_SAFE_TEXT(record, database, value->database);
			//record->status = value->status;

			if (isExportReport()) {
				printf("Report - MySQL: from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u session %llu application %llu @ %llu\n"
						"\ttime %llu to %llu status %u user %s database %s\n",
					owner->key.s[0], owner->key.s[1], owner->key.s[2], owner->key.s[3], ntohs(owner->key.sourPort),
					owner->key.d[0], owner->key.d[1], owner->key.d[2], owner->key.d[3], ntohs(owner->key.destPort),
					owner->id, value->id, value->serial,
					value->reqTime, value->rspTime, value->status,
					value->user ? value->user : "", value->database ? value->database : "");
			}
		} else if (value->command == TNS_METHOD_SQL){
			content->TSoderoTCPSessionContent_u.tns.type = ORACLE_METHOD_SQL;
			TSoderoOracleMsg * record = & content->TSoderoTCPSessionContent_u.tns.oracle_msg;
			record->session_id = owner->id;
			record->flow_id = value->id;
			record->req_time = value->reqLast -  value->reqFirst;
			record->rsp_time = value->rspLast - value->rspFirst;
			record->wait_time = value->rspFirst - value->reqLast;
			//record->reqCount = value->traffic.outgoing.count;
			record->req_bytes = value->traffic.outgoing.bytes;
			record->req_pkts = value->traffic.outgoing.count;
			record->req_l2_bytes = value->req_l2_bytes;
			//record->rspCount = value->traffic.incoming.count;
			record->rsp_bytes = value->traffic.incoming.bytes;
			record->rsp_pkts = value->traffic.incoming.count;
			record->rsp_l2_bytes = value->rsp_l2_bytes;
			record->rsp_records = value->rsps;
			record->rsp_datasets = value->set;
			
			//record->row = value->row;
			//record->col = value->col;
			//record->set = value->set;

			if (isExportReport()) {
				printf("Report - MySQL: from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u session %llu application %llu @ %llu\n"
						"\ttime req %llu to %llu rep %llu to %llu command %u status %u result set %u col %u row %llu\n",
					owner->key.s[0], owner->key.s[1], owner->key.s[2], owner->key.s[3], ntohs(owner->key.sourPort),
					owner->key.d[0], owner->key.d[1], owner->key.d[2], owner->key.d[3], ntohs(owner->key.destPort),
					owner->id, value->id, value->serial,
					value->reqFirst, value->reqLast, value->rspFirst, value->rspLast, value->command, value->status, value->set, value->col, value->row);
			}
		}else {
			content->TSoderoTCPSessionContent_u.tns.type = ORACLE_METHOD_PROCEDURE;
			TSoderoOracleMsg * record = & content->TSoderoTCPSessionContent_u.tns.oracle_msg;
			record->session_id = owner->id;
			record->flow_id = value->id;
			record->req_time = value->reqLast -  value->reqFirst;
			record->rsp_time = value->rspLast - value->rspFirst;
			record->wait_time = value->rspFirst - value->reqLast;
			//record->reqCount = value->traffic.outgoing.count;
			record->req_bytes = value->traffic.outgoing.bytes;
			record->req_pkts = value->traffic.outgoing.count;
			record->req_l2_bytes = value->req_l2_bytes;
			//record->rspCount = value->traffic.incoming.count;
			record->rsp_bytes = value->traffic.incoming.bytes;
			record->rsp_pkts = value->traffic.incoming.count;
			record->rsp_l2_bytes = value->rsp_l2_bytes;
			record->rsp_records = value->rsps;
			record->rsp_datasets = value->set;

			if (isExportReport()) {
				printf("Report - MySQL: from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u session %llu application %llu @ %llu\n"
						"\ttime req %llu to %llu rep %llu to %llu command %u status %u result set %u col %u row %llu\n",
					owner->key.s[0], owner->key.s[1], owner->key.s[2], owner->key.s[3], ntohs(owner->key.sourPort),
					owner->key.d[0], owner->key.d[1], owner->key.d[2], owner->key.d[3], ntohs(owner->key.destPort),
					owner->id, value->id, value->serial,
					value->reqFirst, value->reqLast, value->rspFirst, value->rspLast, value->command, value->status, value->set, value->col, value->row);
			}
		}

		if(sodero_xdr_tcp_message(&gTCPSocket, report))
			result++;
		//		value = value->link;
		break;
	}
	return result;
}

int sodero_report_mysql_application(PSoderoMySQLApplication value, int flag) {
	int result = 0;
	while (value) {
		PSoderoTCPSession owner = value->owner;
		TXDREventBuffer data;
		bzero(&data.event, sizeof(data.event));
		data.event.data.length = sizeof(data) - sizeof(data.event);

		TSoderoTCPReportMsg * report = &data.event.message;
		report->type = SESSION_EVENT;

		TSoderoSessionMsg * msssage = &report->TSoderoTCPReportMsg_u.session_event;
		msssage->event = EVENT_TYPE_DB_MYSQL;

		TSoderoTCPSessionContent * content = &msssage->session_content;
		content->type = SESSION_TYPE_MYSQL;

		if (value->command == MYSQL_COM_SODERO_EXTEND) {
			content->TSoderoTCPSessionContent_u.mysql.type = MYSQL_TYPE_LOGIN;
			TSoderoMySQLLoginMsg * record = & content->TSoderoTCPSessionContent_u.mysql.login;
			record->session_id = owner->id;
			record->application_id = value->id;
            memcpy(record->client_mac, &value->owner->eth.sour, sizeof(value->owner->eth.sour));
            memcpy(record->server_mac, &value->owner->eth.dest, sizeof(value->owner->eth.dest));
            memcpy(record->client_ip, &value->owner->key.sourIP, sizeof(value->owner->key.sourIP));
            memcpy(record->server_ip, &value->owner->key.destIP, sizeof(value->owner->key.destIP));
            record->client_port = value->owner->key.sourPort;
            record->server_port = value->owner->key.destPort;
			record->reqTime = value->reqTime;
			record->rspTime = value->rspTime;
			SODERO_SAFE_TEXT(record, user, value->user);
			SODERO_SAFE_TEXT(record, database, value->database);
			record->status = value->status;

			if (isExportReport()) {
				printf("Report - MySQL: from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u session %llu application %llu @ %llu\n"
						"\ttime %llu to %llu status %u user %s database %s\n",
					owner->key.s[0], owner->key.s[1], owner->key.s[2], owner->key.s[3], ntohs(owner->key.sourPort),
					owner->key.d[0], owner->key.d[1], owner->key.d[2], owner->key.d[3], ntohs(owner->key.destPort),
					owner->id, value->id, value->serial,
					value->reqTime, value->rspTime, value->status,
					value->user ? value->user : "", value->database ? value->database : "");
			}
		} else {
			content->TSoderoTCPSessionContent_u.mysql.type = MYSQL_TYPE_COMMAND;
			TSoderoMySQLCommandMsg * record = & content->TSoderoTCPSessionContent_u.mysql.command;
			record->session_id = owner->id;
			record->application_id = value->id;
            memcpy(record->client_mac, &value->owner->eth.sour, sizeof(value->owner->eth.sour));
            memcpy(record->server_mac, &value->owner->eth.dest, sizeof(value->owner->eth.dest));
            memcpy(record->client_ip, &value->owner->key.sourIP, sizeof(value->owner->key.sourIP));
            memcpy(record->server_ip, &value->owner->key.destIP, sizeof(value->owner->key.destIP));
            record->client_port = value->owner->key.sourPort;
            record->server_port = value->owner->key.destPort;
			record->reqFirst = value->reqFirst;
			record->reqLast = value->reqLast;
			record->reqCount = value->traffic.outgoing.count;
			record->reqBytes = value->traffic.outgoing.bytes;
			record->rspCount = value->traffic.incoming.count;
			record->rspBytes = value->traffic.incoming.bytes;
			record->rspFirst  = value->rspFirst;
			record->rspLast = value->rspLast;
			record->row = value->row;
			record->col = value->col;
			record->set = value->set;

			if (isExportReport()) {
				printf("Report - MySQL: from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u session %llu application %llu @ %llu\n"
						"\ttime req %llu to %llu rep %llu to %llu command %u status %u result set %u col %u row %llu\n",
					owner->key.s[0], owner->key.s[1], owner->key.s[2], owner->key.s[3], ntohs(owner->key.sourPort),
					owner->key.d[0], owner->key.d[1], owner->key.d[2], owner->key.d[3], ntohs(owner->key.destPort),
					owner->id, value->id, value->serial,
					value->reqFirst, value->reqLast, value->rspFirst, value->rspLast, value->command, value->status, value->set, value->col, value->row);
			}
		}

		if(sodero_xdr_tcp_message(&gTCPSocket, report))
			result++;
		//		value = value->link;
		break;
	}
	return result;
}

int sodero_report_oracle_application(PSoderoTnsApplication value, int flag) {
	int result = 0;
	while (value) {
		PSoderoTCPSession owner = value->owner;
		TXDREventBuffer data;
		bzero(&data.event, sizeof(data.event));
		data.event.data.length = sizeof(data) - sizeof(data.event);

		TSoderoTCPReportMsg * report = &data.event.message;
		report->type = SESSION_EVENT;

		TSoderoSessionMsg * msssage = &report->TSoderoTCPReportMsg_u.session_event;
		msssage->event = EVENT_TYPE_DB_ORACLE;

		TSoderoTCPSessionContent * content = &msssage->session_content;
		content->type = SESSION_TYPE_ORACLE;

		
		if (value->command == TNS_METHOD_LOGIN) {
					content->TSoderoTCPSessionContent_u.tns.type = ORACLE_METHOD_LOGIN;
					TSoderoOracleMsg * record = & content->TSoderoTCPSessionContent_u.tns.oracle_msg;
					record->session_id = owner->id;
					record->flow_id = value->id;
                    memcpy(record->client_mac, &value->owner->eth.sour, sizeof(value->owner->eth.sour));
                    memcpy(record->server_mac, &value->owner->eth.dest, sizeof(value->owner->eth.dest));
                    memcpy(record->client_ip, &value->owner->key.sourIP, sizeof(value->owner->key.sourIP));
                    memcpy(record->server_ip, &value->owner->key.destIP, sizeof(value->owner->key.destIP));
                    record->client_port = value->owner->key.sourPort;
                    record->server_port = value->owner->key.destPort;
            
					record->req_time = value->reqLast -  value->reqFirst;
					record->rsp_time = value->rspLast - value->rspFirst;
					record->wait_time = value->rspFirst - value->reqFirst;
					SODERO_SAFE_TEXT(record, user, value->user);
					SODERO_SAFE_TEXT(record, database, value->database);
					//record->status = value->status;
		
					if (isExportReport()) {
						printf("Report - oracle: from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u session %llu application %llu @ %llu\n"
								"\ttime %llu to %llu status %u user %s database %s\n",
							owner->key.s[0], owner->key.s[1], owner->key.s[2], owner->key.s[3], ntohs(owner->key.sourPort),
							owner->key.d[0], owner->key.d[1], owner->key.d[2], owner->key.d[3], ntohs(owner->key.destPort),
							owner->id, value->id, value->serial,
							value->reqTime, value->rspTime, value->status,
							value->user ? value->user : "", value->database ? value->database : "");
					}
				} else if (value->command == TNS_METHOD_SQL){
					content->TSoderoTCPSessionContent_u.tns.type = ORACLE_METHOD_SQL;
					TSoderoOracleMsg * record = & content->TSoderoTCPSessionContent_u.tns.oracle_msg;
					record->session_id = owner->id;
					record->flow_id = value->id;
                    memcpy(record->client_mac, &value->owner->eth.sour, sizeof(value->owner->eth.sour));
                    memcpy(record->server_mac, &value->owner->eth.dest, sizeof(value->owner->eth.dest));
                    memcpy(record->client_ip, &value->owner->key.sourIP, sizeof(value->owner->key.sourIP));
                    memcpy(record->server_ip, &value->owner->key.destIP, sizeof(value->owner->key.destIP));
                    record->client_port = value->owner->key.sourPort;
                    record->server_port = value->owner->key.destPort;
                    
					record->req_time = value->reqLast -  value->reqFirst;
					record->rsp_time = value->rspLast - value->rspFirst;
					record->wait_time = value->rspFirst - value->reqFirst;
					SODERO_SAFE_TEXT(record, statement, value->sql);
					SODERO_SAFE_TEXT(record, error_code, value->error_code);
					SODERO_SAFE_TEXT(record, error_msg, value->error_str);
					//record->reqCount = value->traffic.outgoing.count;
					record->req_bytes = value->req_bytes;
					record->req_pkts = value->req_pkts;
					record->req_l2_bytes = value->req_l2_bytes;
					//record->rspCount = value->traffic.incoming.count;
					record->rsp_bytes = value->rsp_bytes;
					record->rsp_pkts = value->rsp_pkts;
					record->rsp_l2_bytes = value->rsp_l2_bytes;
					record->rsp_records = value->rsps; /* not support now */
					record->rsp_datasets = value->set; /* not support now */
		
					if (isExportReport()) {
						printf("Report - oracle: from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u session %llu application %llu @ %llu\n"
								"\ttime req %llu to %llu rep %llu to %llu command %u status %u result set %u col %u row %llu\n",
							owner->key.s[0], owner->key.s[1], owner->key.s[2], owner->key.s[3], ntohs(owner->key.sourPort),
							owner->key.d[0], owner->key.d[1], owner->key.d[2], owner->key.d[3], ntohs(owner->key.destPort),
							owner->id, value->id, value->serial,
							value->reqFirst, value->reqLast, value->rspFirst, value->rspLast, value->command, value->status, value->set, value->col, value->row);
					}
				}else {
					content->TSoderoTCPSessionContent_u.tns.type = ORACLE_METHOD_PROCEDURE;
					TSoderoOracleMsg * record = & content->TSoderoTCPSessionContent_u.tns.oracle_msg;
					record->session_id = owner->id;
					record->flow_id = value->id;
                    memcpy(record->client_mac, &value->owner->eth.sour, sizeof(value->owner->eth.sour));
                    memcpy(record->server_mac, &value->owner->eth.dest, sizeof(value->owner->eth.dest));
                    memcpy(record->client_ip, &value->owner->key.sourIP, sizeof(value->owner->key.sourIP));
                    memcpy(record->server_ip, &value->owner->key.destIP, sizeof(value->owner->key.destIP));
                    record->client_port = value->owner->key.sourPort;
                    record->server_port = value->owner->key.destPort;
                    
					record->req_time = value->reqLast -  value->reqFirst;
					record->rsp_time = value->rspLast - value->rspFirst;
					record->wait_time = value->rspFirst - value->reqFirst;

					SODERO_SAFE_TEXT(record, statement, value->sql);
					SODERO_SAFE_TEXT(record, error_code, value->error_code);
					SODERO_SAFE_TEXT(record, error_msg, value->error_str);
					
					//record->reqCount = value->traffic.outgoing.count;
					
					record->req_bytes = value->req_bytes;
					record->req_pkts = value->req_pkts;
					record->req_l2_bytes = value->req_l2_bytes;
					//record->rspCount = value->traffic.incoming.count;
					record->rsp_bytes = value->rsp_bytes;
					record->rsp_pkts = value->rsp_pkts;
					record->rsp_l2_bytes = value->rsp_l2_bytes;
					record->rsp_records = value->rsps;
					record->rsp_datasets = value->set;
		
					if (isExportReport()) {
						printf("Report - oracle: from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u session %llu application %llu @ %llu\n"
								"\ttime req %llu to %llu rep %llu to %llu command %u status %u result set %u col %u row %llu\n",
							owner->key.s[0], owner->key.s[1], owner->key.s[2], owner->key.s[3], ntohs(owner->key.sourPort),
							owner->key.d[0], owner->key.d[1], owner->key.d[2], owner->key.d[3], ntohs(owner->key.destPort),
							owner->id, value->id, value->serial,
							value->reqFirst, value->reqLast, value->rspFirst, value->rspLast, value->command, value->status, value->set, value->col, value->row);
					}
				}
		

		if(sodero_xdr_tcp_message(&gTCPSocket, report))
			result++;
		//		value = value->link;
		break;
	}
	return result;
}

int sodero_report_http_head(PSoderoApplicationHTTP value, int flag) {
	int result = 0;
	while (value) {
		PSoderoTCPSession owner = value->owner;
//		printf("Report HTTP: %p\n", value);
		TXDREventBuffer data;
		bzero(&data.event, sizeof(data.event));
		data.event.data.length = sizeof(data) - sizeof(data.event);

		TSoderoTCPReportMsg * report = &data.event.message;
		report->type = SESSION_EVENT;

		TSoderoSessionMsg * session = &report->TSoderoTCPReportMsg_u.session_event;
		session->event = EVENT_TYPE_HTTP_REQUEST;

		TSoderoTCPSessionContent * content = &session->session_content;
		content->type = SESSION_TYPE_HTTP_HEAD;

		TSoderoHTTPSessionHead * record = &content->TSoderoTCPSessionContent_u.http_head;
		record->http_session_id = value->id;
		record->flow_session_id = value->owner->id;
        
        memcpy(record->client_mac, &value->owner->eth.sour, sizeof(value->owner->eth.sour));
        memcpy(record->server_mac, &value->owner->eth.dest, sizeof(value->owner->eth.dest));
        memcpy(record->client_ip, &value->owner->key.sourIP, sizeof(value->owner->key.sourIP));
        memcpy(record->server_ip, &value->owner->key.destIP, sizeof(value->owner->key.destIP));
        record->client_port = value->owner->key.sourPort;
        record->server_port = value->owner->key.destPort;
        

		snprintf((char*)record->method, sizeof(record->method) - 1, "%s", nameOfHTTPMethod(value->method_code));

		SODERO_SAFE_TEXT(record, url, value->url);
		SODERO_SAFE_TEXT(record, host, value->host);
		SODERO_SAFE_TEXT(record, user_agent, value->ua);
		SODERO_SAFE_TEXT(record, referer, value->referer);
		SODERO_SAFE_TEXT(record, origin, value->origin);
		SODERO_SAFE_TEXT(record, cookies, value->req_cookies);
		SODERO_SAFE_TEXT(record, soap_action, value->soap_action);
//		SODERO_SAFE_TEXT(record, req_sample, value->req_sample);

		if (isExportApplication(owner->key.proto, owner->flag)) {
			checkSessionValue(&owner->key, REPORT_TYPE_BODY, "report_type", report->type);
			checkSessionValue(&owner->key, REPORT_TYPE_BODY, "content_type", content->type);
			checkSessionValue(&owner->key, REPORT_TYPE_BODY, "session_event", session->event);

			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, http_session_id);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, flow_session_id);

			CHECK_APPLICATION_TEXT(REPORT_TYPE_BODY, method);
			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, url);
			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, host);
			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, user_agent);
			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, referer);
//			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, origin);
//			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, cookies);
//			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, req_sample);
		}

		if (sodero_xdr_tcp_message(&gTCPSocket, report))
			result++;
//		value = value->link;
		break;
	}
	return result;
}

int sodero_report_http_body(PSoderoApplicationHTTP value, int flag) {
	int result = 0;
	while (value) {
		PSoderoTCPSession owner = value->owner;
//		printf("Report HTTP: %p\n", value);
		TXDREventBuffer data;
		bzero(&data.event, sizeof(data.event));
		data.event.data.length = sizeof(data) - sizeof(data.event);

		TSoderoTCPReportMsg * report = &data.event.message;
		report->type = SESSION_EVENT;

		TSoderoSessionMsg * session = &report->TSoderoTCPReportMsg_u.session_event;
		session->event = EVENT_TYPE_HTTP_RESPONSE;

		TSoderoTCPSessionContent * content = &session->session_content;
		content->type = SESSION_TYPE_HTTP_BODY;

		TSoderoHTTPSessionBody * record = &content->TSoderoTCPSessionContent_u.http_body;
		record->http_session_id = value->id;
//		SODERO_SAFE_TEXT(record, title, value->title);
		SODERO_SAFE_TEXT(record, content_type, value->rsp_content_type);
		SODERO_SAFE_TEXT(record, soap_method, value->soap_method);
		SODERO_SAFE_TEXT(record, soap_xmlns, value->soap_xmlns);
		SODERO_SAFE_TEXT(record, soap_fault_code, value->soap_fault_code);
		SODERO_SAFE_TEXT(record, soap_fault_string, value->soap_fault_string);

//		record-> dns_time;
#if 0
		if (value->req_e && value->req_b)
			record->req_time  = (value->req_e - value->req_b) / uSecsPerMSec;
		if (value->rsp_e && value->rsp_b)
			record->rsp_time  = (value->rsp_e - value->rsp_b) / uSecsPerMSec;
		if (value->rsp_b && value->req_e)
			record->wait_time  = (value->rsp_b - value->req_e) / uSecsPerMSec;
#endif

		
		if (value->request.sum)
			record->req_time = value->request.sum / value->request.count;
		
		if (value->response.sum)
			record->rsp_time = value->response.sum / value->response.count;
		
		if (value->wait.sum)
			record->wait_time = value->wait.sum / value->wait.count;

#if 0
		record->req_time_min = value->request.min;
		record->rsp_time_min = value->response.min;
		record->wait_time_min = value->wait.min;

		record->req_time_max = value->request.max;
		record->rsp_time_max = value->response.max;
		record->wait_time_max = value->wait.max;
#endif
		

		record->req_bytes    = value->req_bytes   ;
		record->req_pkts     = value->req_pkts    ;
		record->req_l2_bytes = value->req_l2_bytes;
		record->req_rtos     = SODERO_SAFE_DIV(value->reqRTTValue, value->reqRTTCount);
		record->rsp_bytes    = value->rsp_bytes   ;
		record->rsp_pkts     = value->rsp_pkts    ;
		record->rsp_l2_bytes = value->rsp_l2_bytes;
		record->rso_rtos     = SODERO_SAFE_DIV(value->rspRTTValue, value->rspRTTCount);
		record->rttValue = value->reqRTTValue + value->rspRTTValue;
		record->rttCount = value->reqRTTCount + value->rspRTTCount;

		record->status_code    = value->status_code   ;
		record->pipelined      = value->pipelined     ;
		record->req_aborted    = value->req_aborted   ;
		record->rsp_aborted    = value->rsp_aborted   ;
		record->rsp_chunked    = value->rsp_chunked   ;
		record->rsp_compressed = value->rsp_compressed;
		memset(record->rsp_version, 0, sizeof(record->rsp_version));
		snprintf((char*)record->rsp_version, sizeof(record->rsp_version) - 1, "HTTP/1.%d", value->rsp_version);

		if (flag & SODERO_REPORT_DONE)
		if (isExportReport()) {
			printf("Report - HTTP: from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u session %llu application %llu @ %llu ttime req %llu to %llu rep %llu to %llu\n",
				owner->key.s[0], owner->key.s[1], owner->key.s[2], owner->key.s[3], ntohs(owner->key.sourPort),
				owner->key.d[0], owner->key.d[1], owner->key.d[2], owner->key.d[3], ntohs(owner->key.destPort),
				owner->id, value->id, value->serial,
				value->req_b, value->req_e, value->rsp_b, value->rsp_e);

			if (value->host)
				printf("HOST: %s\n", value->host);
			if (value->url)
				printf("URL: %s\n", value->url);
			if (value->ua)
				printf("ua: %s\n", value->ua);
			if (value->referer)
				printf("referer: %s\n", value->referer);
		}

		if (isExportApplication(owner->key.proto, owner->flag)) {
			checkSessionValue(&owner->key, REPORT_TYPE_BODY, "report_type", report->type);
			checkSessionValue(&owner->key, REPORT_TYPE_BODY, "content_type", content->type);
			checkSessionValue(&owner->key, REPORT_TYPE_BODY, "session_event", session->event);

			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, http_session_id);

//			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, title);
			CHECK_APPLICATION_STRING(REPORT_TYPE_BODY, content_type);

			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, req_time);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rsp_time);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, wait_time);

			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, req_bytes);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, req_pkts);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, req_l2_bytes);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, req_rtos);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rsp_bytes);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rsp_pkts);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rsp_l2_bytes);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rso_rtos);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rttValue);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rttCount);

			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, status_code);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, pipelined);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, req_aborted);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rsp_aborted);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rsp_chunked);
			CHECK_APPLICATION_VALUE(REPORT_TYPE_BODY, rsp_compressed);

			CHECK_APPLICATION_TEXT(REPORT_TYPE_BODY, rsp_version);
		}

		if (sodero_xdr_tcp_message(&gTCPSocket, report))
			result++;
//		value = value->link;
		break;
	}
	return result;
}

void sodero_report_disconnect(void) {
	gAgentID = 0;
	if (gTCPSocket > 0) close(gTCPSocket);
	gTCPSocket = 0;
	if (gUDPSocket > 0) close(gUDPSocket);
	gUDPSocket = 0;
}

#if defined(__FreeBSD__) || defined(__APPLE__)
#define UNIX_INTERFACE_LEN 32
#define UNIX_INTERFACE_MAX 64

typedef struct {
	TNodeIndex node;
	char       name[UNIX_INTERFACE_LEN];
} TUnixNodeItem, * PUnixNodeItem;

TUnixNodeItem items[UNIX_INTERFACE_MAX];

PUnixNodeItem lookupNodeItem(const char * name) {
	for (int i = 0; i < UNIX_INTERFACE_MAX; i++) {
		PUnixNodeItem result = &items[i];
		if (strlen(result->name) > 0) {
			if (same_str(result->name, name))
				return result;
		} else {
			strncpy(result->name, name, sizeof(result->name)-1);
			return result;
		}
	}
	return nullptr;
}
#endif

void sodero_report_self(void) {
#ifdef __linux__
	register int fd, intrface;
	struct ifreq buf[MAXINTERFACES];
	struct ifconf ifc;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
		ifc.ifc_len = sizeof(buf);
		ifc.ifc_buf = (caddr_t) buf;
		if (!ioctl(fd, SIOCGIFCONF, (char *) &ifc)) {
			intrface = ifc.ifc_len / sizeof(struct ifreq);

			while (intrface-- > 0) {
				TNodeIndex node;
				bzero(&node, sizeof(node));
				if (ioctl(fd, SIOCGIFADDR, (char *) &buf[intrface])) {
					printf("cpm: ioctl device %s ip", buf[intrface].ifr_name);
					continue;
				}
				node.ip.l.ip = ((struct sockaddr_in*) (&buf[intrface].ifr_addr))->sin_addr.s_addr;

				if (ioctl(fd, SIOCGIFHWADDR, (char *) &buf[intrface])) {
					printf( "cpm: ioctl device %s mac", buf[intrface].ifr_name);
					continue;
				}
//				node.mac = *(PMAC)buf[intrface].ifr_hwaddr.sa_data;
				memcpy(&node.mac, buf[intrface].ifr_hwaddr.sa_data, sizeof(node.mac));

				sodero_report_node(&node, buf[intrface].ifr_name, ORIGIN_NODES);
			}
		} else
			perror("cpm: ioctl");

	} else
		perror("cpm: socket");

	close(fd);
#endif
#if defined(__FreeBSD__) || defined(__APPLE__)
	struct ifaddrs *ifa,*curifa;

	if(getifaddrs(&ifa) < 0) {
		perror("getifaddrs error");
		return;	//	exit(127);
	}

#define UNIX_INTERFACE_LEN 32
#define UNIX_INTERFACE_MAX 64

	bzero(items, sizeof(items));

	for(curifa = ifa; curifa != NULL; curifa = curifa->ifa_next) {
		if(curifa->ifa_addr->sa_family == AF_INET) {
			PUnixNodeItem item = lookupNodeItem(curifa->ifa_name);
			if (item)
				item->node.ip.l.ip = ((struct sockaddr_in*)curifa->ifa_addr)->sin_addr.s_addr;
		}
		if(curifa->ifa_addr->sa_family == AF_LINK) {
			PUnixNodeItem item = lookupNodeItem(curifa->ifa_name);
			if (item)
				memcpy(&item->node.mac, curifa->ifa_addr, sizeof(item->node.mac));
		}
	}
	freeifaddrs(ifa);

	for (int i = 0; i < UNIX_INTERFACE_MAX; i++) {
		PUnixNodeItem item = &items[i];
		if (strlen(item->name) > 0) {
			if (item->node.ip.l.ip)	//	 && item->node.mac.b4
				sodero_report_node(&item->node, item->name, ORIGIN_NODES);
		}
	}

#endif
}

int sodero_report_connect(void) {
	if (gTCPSocket > 0) close(gTCPSocket);
	gTCPSocket = sodero_connect2server(gServer, gService, SOCK_STREAM);
	if (gTCPSocket < 0) return false;

	if (gUDPSocket > 0) close(gUDPSocket);
	gUDPSocket = sodero_connect2server(gServer, gService, SOCK_DGRAM );
	if (gUDPSocket < 0) return false;

	int flag = 1;
	int ret = setsockopt (gTCPSocket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	if (ret < 0)
		printf("Close nagle failure\n");

	if (!sodero_report_shakehand()) {
		sodero_report_disconnect();
		return false;
	}

	gNode.mac = gMAC;
	gNode.ip  = gHost ;

	sodero_report_self();

	return TRUE;
}

int sodero_report_check(void) {
	if (gTCPSocket | gUDPSocket) return TRUE;
	sodero_report_disconnect();
	return sodero_report_connect();
}

const char * SODERO_REPORT_IDENT_COUNTER_TCP_SYN = "counter.tcp.syn";
const char * SODERO_REPORT_IDENT_COUNTER_TCP_ACK = "counter.tcp.ack";
const char * SODERO_REPORT_IDENT_COUNTER_TCP_FIN = "counter.tcp.fin";
const char * SODERO_REPORT_IDENT_COUNTER_TCP_RST = "counter.tcp.rst";
const char * SODERO_REPORT_IDENT_COUNTER_TCP_URG = "counter.tcp.urg";
const char * SODERO_REPORT_IDENT_COUNTER_TCP_ECN = "counter.tcp.ecn";
const char * SODERO_REPORT_IDENT_COUNTER_TCP_CWR = "counter.tcp.cwr";

const char * SODERO_REPORT_IDENT_ETHER_COUNT = "l2.frames";	//	"ether.packet.count";
const char * SODERO_REPORT_IDENT_ETHER_BYTES = "l2.bytes";	//	"ether.packet.bytes";

const char * SODERO_REPORT_IDENT_ETHER_BCAST_COUNT = "l2.bcast_frames";
const char * SODERO_REPORT_IDENT_ETHER_BCAST_BYTES = "l2.bcast_bytes";
const char * SODERO_REPORT_IDENT_ETHER_MCAST_COUNT = "l2.mcast_frames";
const char * SODERO_REPORT_IDENT_ETHER_MCAST_BYTES = "l2.mcast_bytes";
const char * SODERO_REPORT_IDENT_ETHER_UCAST_COUNT = "l2.ucast_frames";
const char * SODERO_REPORT_IDENT_ETHER_UCAST_BYTES = "l2.ucast_bytes";

const char * SODERO_REPORT_IDENT_ETHER_COUNT_00064 = "l2.frames_64";
const char * SODERO_REPORT_IDENT_ETHER_BYTES_00064 = "l2.bytes_64";
const char * SODERO_REPORT_IDENT_ETHER_COUNT_00128 = "l2.frames_128";
const char * SODERO_REPORT_IDENT_ETHER_BYTES_00128 = "l2.bytes_128";
const char * SODERO_REPORT_IDENT_ETHER_COUNT_00256 = "l2.frames_256";
const char * SODERO_REPORT_IDENT_ETHER_BYTES_00256 = "l2.bytes_256";
const char * SODERO_REPORT_IDENT_ETHER_COUNT_00512 = "l2.frames_512";
const char * SODERO_REPORT_IDENT_ETHER_BYTES_00512 = "l2.bytes_512";
const char * SODERO_REPORT_IDENT_ETHER_COUNT_01024 = "l2.frames_1024";
const char * SODERO_REPORT_IDENT_ETHER_BYTES_01024 = "l2.bytes_1024";
const char * SODERO_REPORT_IDENT_ETHER_COUNT_01514 = "l2.frames_1514";
const char * SODERO_REPORT_IDENT_ETHER_BYTES_01514 = "l2.bytes_1514";
const char * SODERO_REPORT_IDENT_ETHER_COUNT_01518 = "l2.frames_1518";
const char * SODERO_REPORT_IDENT_ETHER_BYTES_01518 = "l2.bytes_1518";
const char * SODERO_REPORT_IDENT_ETHER_COUNT_jumbo= "l2.frames_jumbo";
const char * SODERO_REPORT_IDENT_ETHER_BYTES_jumbo= "l2.bytes_jumbo";

const char * SODERO_REPORT_IDENT_ETHER_ARP_COUNT = "l2.frames|l2_type|ARP";
const char * SODERO_REPORT_IDENT_ETHER_ARP_BYTES = "l2.bytes|l2_type|ARP";
const char * SODERO_REPORT_IDENT_ETHER_IPV4_COUNT = "l2.frames|l2_type|IPV4";
const char * SODERO_REPORT_IDENT_ETHER_IPV4_BYTES = "l2.bytes|l2_type|IPV4";
const char * SODERO_REPORT_IDENT_ETHER_IPV6_COUNT = "l2.frames|l2_type|IPV6";
const char * SODERO_REPORT_IDENT_ETHER_IPV6_BYTES = "l2.bytes|l2_type|IPV6";
const char * SODERO_REPORT_IDENT_ETHER_LACP_COUNT = "l2.frames|l2_type|LACP";
const char * SODERO_REPORT_IDENT_ETHER_LACP_BYTES = "l2.bytes|l2_type|LACP";
const char * SODERO_REPORT_IDENT_ETHER_MPLS_COUNT = "l2.frames|l2_type|MPLS";
const char * SODERO_REPORT_IDENT_ETHER_MPLS_BYTES = "l2.bytes|l2_type|MPLS";
const char * SODERO_REPORT_IDENT_ETHER_RSTP_COUNT = "l2.frames|l2_type|STP";
const char * SODERO_REPORT_IDENT_ETHER_RSTP_BYTES = "l2.bytes|l2_type|STP";
const char * SODERO_REPORT_IDENT_ETHER_OTHER_COUNT = "l2.frames|l2_type|Others";
const char * SODERO_REPORT_IDENT_ETHER_OTHER_BYTES = "l2.bytes|l2_type|Others";

const char * SODERO_REPORT_IDENT_ETHER_OUTGOING_COUNT = "l2.req_frames";
const char * SODERO_REPORT_IDENT_ETHER_OUTGOING_BYTES = "l2.req_frames";
const char * SODERO_REPORT_IDENT_ETHER_INCOMING_COUNT = "l2.rsp_frames";
const char * SODERO_REPORT_IDENT_ETHER_INCOMING_BYTES = "l2.rsp_bytes" ;

const char * SODERO_REPORT_IDENT_IPV4_COUNT = "l3.pkts";	//	"ipv4.packet.count";
const char * SODERO_REPORT_IDENT_IPV4_BYTES = "l3.bytes";	//	"ipv4.packet.bytes";

const char * SODERO_REPORT_IDENT_IPV4_ICMP_COUNT = "l3.pkts|l3_type|ICMP";
const char * SODERO_REPORT_IDENT_IPV4_ICMP_BYTES = "l3.bytes|l3_type|ICMP";
const char * SODERO_REPORT_IDENT_IPV4_TCP_COUNT = "l3.pkts|l3_type|TCP";
const char * SODERO_REPORT_IDENT_IPV4_TCP_BYTES = "l3.bytes|l3_type|TCP";
const char * SODERO_REPORT_IDENT_IPV4_UDP_COUNT = "l3.pkts|l3_type|UDP";
const char * SODERO_REPORT_IDENT_IPV4_UDP_BYTES = "l3.bytes|l3_type|UDP";
const char * SODERO_REPORT_IDENT_IPV4_OTHER_COUNT = "l3.pkts|l3_type|Others";
const char * SODERO_REPORT_IDENT_IPV4_OTHER_BYTES = "l3.bytes|l3_type|Others";

const char * SODERO_REPORT_IDENT_ICMP_COUNT = "";	//	"tcp.packet.count";
const char * SODERO_REPORT_IDENT_ICMP_BYTES = "";	//	"tcp.packet.bytes";
const char * SODERO_REPORT_IDENT_TCP_COUNT = "";	//	"tcp.packet.count";
const char * SODERO_REPORT_IDENT_TCP_BYTES = "";	//	"tcp.packet.bytes";
const char * SODERO_REPORT_IDENT_UDP_COUNT = "";	//	"tcp.packet.count";
const char * SODERO_REPORT_IDENT_UDP_BYTES = "";	//	"tcp.packet.bytes";
const char * SODERO_REPORT_IDENT_SCTP_COUNT = "";	//	"sctp.packet.count";
const char * SODERO_REPORT_IDENT_SCTP_BYTES = "";	//	"sctp.packet.bytes";

const char * SODERO_REPORT_IDENT_TCP_CONNECTED_COUNT = "tcp.connected";
const char * SODERO_REPORT_IDENT_TCP_CLOSED_COUNT    = "tcp.closed"   ;
const char * SODERO_REPORT_IDENT_TCP_RESET_COUNT     = "tcp.reset";

const char * SODERO_REPORT_IDENT_TCP_OUTGOING_COUNT  = "tcp.req_pkts" ;
const char * SODERO_REPORT_IDENT_TCP_OUTGOING_BYTES  = "tcp.req_bytes";
const char * SODERO_REPORT_IDENT_TCP_INCOMING_COUNT  = "tcp.rsp_pkts" ;
const char * SODERO_REPORT_IDENT_TCP_INCOMING_BYTES  = "tcp.rsp_bytes";
const char * SODERO_REPORT_IDENT_UDP_OUTGOING_COUNT  = "udp.req_pkts" ;
const char * SODERO_REPORT_IDENT_UDP_OUTGOING_BYTES  = "udp.req_bytes";
const char * SODERO_REPORT_IDENT_UDP_INCOMING_COUNT  = "udp.rsp_pkts" ;
const char * SODERO_REPORT_IDENT_UDP_INCOMING_BYTES  = "udp.rsp_bytes";

const char * SODERO_REPORT_IDENT_HTTP_REQUEST           = "http.reqs" ;
const char * SODERO_REPORT_IDENT_HTTP_REQUEST_COUNT     = "http.req_pkts" ;
const char * SODERO_REPORT_IDENT_HTTP_REQUEST_BYTES     = "http.req_bytes";
const char * SODERO_REPORT_IDENT_HTTP_REQUEST_L2_BYTES  = "http.req_l2_bytes";
const char * SODERO_REPORT_IDENT_HTTP_RESPONSE          = "http.rsps";
const char * SODERO_REPORT_IDENT_HTTP_RESPONSE_COUNT    = "http.rsp_pkts" ;
const char * SODERO_REPORT_IDENT_HTTP_RESPONSE_BYTES    = "http.rsp_bytes";
const char * SODERO_REPORT_IDENT_HTTP_RESPONSE_L2_BYTES = "http.rsp_l2_bytes";

const char * SODERO_REPORT_IDENT_HTTP_INCOMING_COUNT  = "http.req_pkts" ;
const char * SODERO_REPORT_IDENT_HTTP_INCOMING_BYTES  = "http.req_bytes";
const char * SODERO_REPORT_IDENT_HTTP_INCOMING_L2_BYTE= "http.req_l2_bytes";
const char * SODERO_REPORT_IDENT_HTTP_OUTGOING_COUNT  = "http.rsp_pkts" ;
const char * SODERO_REPORT_IDENT_HTTP_OUTGOING_BYTES  = "http.rsp_bytes";
const char * SODERO_REPORT_IDENT_HTTP_OUTGOING_L2_BYTE= "http.rsp_l2_bytes";

const char * SODERO_REPORT_IDENT_HTTP_STATUS1XX = "http.status.1xx";
const char * SODERO_REPORT_IDENT_HTTP_STATUS2XX = "http.status.2xx";
const char * SODERO_REPORT_IDENT_HTTP_STATUS3XX = "http.status.3xx";
const char * SODERO_REPORT_IDENT_HTTP_STATUS4XX = "http.status.4xx";
const char * SODERO_REPORT_IDENT_HTTP_STATUS5XX = "http.status.5xx";

const char * SODERO_REPORT_IDENT_HTTP_METHOD = "http.method";
const char * SODERO_REPORT_IDENT_HTTP_ERROR  = "http.error" ;
const char * SODERO_REPORT_IDENT_HTTP_RTT    = "http.rtt"   ;

const char * SODERO_REPORT_IDENT_HTTP_REQ_TIME_MIN = "http.req_time.min";
const char * SODERO_REPORT_IDENT_HTTP_REQ_TIME_MAX = "http.req_time.max";
const char * SODERO_REPORT_IDENT_HTTP_REQ_TIME_AVG = "http.req_time.avg";

const char * SODERO_REPORT_IDENT_HTTP_RES_TIME_MIN = "http.res_time.min";
const char * SODERO_REPORT_IDENT_HTTP_RES_TIME_MAX = "http.res_time.max";
const char * SODERO_REPORT_IDENT_HTTP_RES_TIME_AVG = "http.res_time.avg";

const char * SODERO_REPORT_IDENT_HTTP_WAIT_TIME_MIN = "http.wait_time.min";
const char * SODERO_REPORT_IDENT_HTTP_WAIT_TIME_MAX = "http.wait_time.max";
const char * SODERO_REPORT_IDENT_HTTP_WAIT_TIME_AVG = "http.wait_time.avg";

const char * SODERO_REPORT_IDENT_MYSQL_REQUEST_COUNT     = "mysql.req_pkts" ;
const char * SODERO_REPORT_IDENT_MYSQL_REQUEST_BYTES     = "mysql.req_bytes";
const char * SODERO_REPORT_IDENT_MYSQL_REQUEST_L2_BYTES  = "mysql.req_l2_bytes";
const char * SODERO_REPORT_IDENT_MYSQL_RESPONSE_COUNT    = "mysql.rsp_pkts" ;
const char * SODERO_REPORT_IDENT_MYSQL_RESPONSE_BYTES    = "mysql.rsp_bytes";
const char * SODERO_REPORT_IDENT_MYSQL_RESPONSE_L2_BYTES = "mysql.rsp_l2_bytes";

const char * SODERO_REPORT_IDENT_MYSQL_COMMAND = "mysql.reqs";
const char * SODERO_REPORT_IDENT_MYSQL_BLOCK   = "mysql.blocks";
const char * SODERO_REPORT_IDENT_MYSQL_RTT     = "mysql.rtt";

const char * SODERO_REPORT_IDENT_ORACLE_REQUEST_COUNT     = "oracle.reqs" ;
const char * SODERO_REPORT_IDENT_ORACLE_REQUEST_PKT_COUNT = "oracle.req_pkts" ;
const char * SODERO_REPORT_IDENT_ORACLE_REQUEST_BYTES     = "oracle.req_bytes";
const char * SODERO_REPORT_IDENT_ORACLE_REQUEST_L2_BYTES  = "oracle.req_l2_bytes";
const char * SODERO_REPORT_IDENT_ORACLE_RESPONSE_COUNT    = "oracle.rsps" ;
const char * SODERO_REPORT_IDENT_ORACLE_RESPONSE_PKT_COUNT    = "oracle.rsp_pkts" ;
const char * SODERO_REPORT_IDENT_ORACLE_RESPONSE_BYTES    = "oracle.rsp_bytes";
const char * SODERO_REPORT_IDENT_ORACLE_RESPONSE_L2_BYTES = "oracle.rsp_l2_bytes";

const char * SODERO_REPORT_IDENT_ORACLE_COMMAND = "oracle.reqs";
const char * SODERO_REPORT_IDENT_ORACLE_BLOCK   = "oracle.blocks";
const char * SODERO_REPORT_IDENT_ORACLE_RTT     = "oracle.rtt";

const char * SODERO_REPORT_IDENT_ORACLE_REQ_TIME_MIN = "oracle.req_time.min";
const char * SODERO_REPORT_IDENT_ORACLE_REQ_TIME_MAX = "oracle.req_time.max";
const char * SODERO_REPORT_IDENT_ORACLE_REQ_TIME_AVG = "oracle.req_time.avg";

const char * SODERO_REPORT_IDENT_ORACLE_RES_TIME_MIN = "oracle.res_time.min";
const char * SODERO_REPORT_IDENT_ORACLE_RES_TIME_MAX = "oracle.res_time.max";
const char * SODERO_REPORT_IDENT_ORACLE_RES_TIME_AVG = "oracle.res_time.avg";

const char * SODERO_REPORT_IDENT_ORACLE_WAIT_TIME_MIN = "oracle.wait_time.min";
const char * SODERO_REPORT_IDENT_ORACLE_WAIT_TIME_MAX = "oracle.wait_time.max";
const char * SODERO_REPORT_IDENT_ORACLE_WAIT_TIME_AVG = "oracle.wait_time.avg";

const char * SODERO_REPORT_IDENT_DNS_REQUEST_COUNT  = "dns.req_pkts" ;
const char * SODERO_REPORT_IDENT_DNS_REQUEST_BYTES  = "dns.req_bytes";
const char * SODERO_REPORT_IDENT_DNS_RESPONSE_COUNT  = "dns.rsp_pkts" ;
const char * SODERO_REPORT_IDENT_DNS_RESPONSE_BYTES  = "dns.rsp_bytes";

const char * SODERO_REPORT_IDENT_DNS_OUTGOING_TRUNCS  = "dns.req_truncs";
const char * SODERO_REPORT_IDENT_DNS_INCOMING_TRUNCS  = "dns.rsp_truncs";
const char * SODERO_REPORT_IDENT_DNS_OUTGOING_OCODES  = "dns.req_opcodes|dns_opcode|%u";
const char * SODERO_REPORT_IDENT_DNS_INCOMING_OCODES  = "dns.rsp_rcodes|dns_rcode|%u";

const char * SODERO_REPORT_IDENT_DNS_OUTGOING_ERROR   = "dns.rsp_errors";
const char * SODERO_REPORT_IDENT_DNS_INCOMING_TIMEOUT = "dns.req_timeout";

const char * SODERO_REPORT_IDENT_DNS_INCOMING_DURATION = "dns.rtt";


const char * SODERO_REPORT_IDENT_SOAP_REQUEST_COUNT     = "soap.reqs" ;
const char * SODERO_REPORT_IDENT_SOAP_REQUEST_BYTES     = "soap.req_bytes";
const char * SODERO_REPORT_IDENT_SOAP_REQUEST_PKT_COUNT = "soap.req_pkts" ;
const char * SODERO_REPORT_IDENT_SOAP_REQUEST_L2_BYTES  = "soap.req_l2_bytes";
const char * SODERO_REPORT_IDENT_SOAP_RESPONSE_COUNT    = "soap.rsps" ;
const char * SODERO_REPORT_IDENT_SOAP_RESPONSE_BYTES    = "soap.rsp_bytes";
const char * SODERO_REPORT_IDENT_SOAP_RESPONSE_PKT_COUNT    = "soap.rsp_pkts" ;
const char * SODERO_REPORT_IDENT_SOAP_RESPONSE_L2_BYTES = "soap.rsp_l2_bytes";
const char * SODERO_REPORT_IDENT_SOAP_RESPONSE_FAULT = "soap.rsp_fault";

const char * SODERO_REPORT_IDENT_SOAP_REQ_TIME_MIN = "soap.req_time.min";
const char * SODERO_REPORT_IDENT_SOAP_REQ_TIME_MAX = "soap.req_time.max";
const char * SODERO_REPORT_IDENT_SOAP_REQ_TIME_AVG = "soap.req_time.avg";

const char * SODERO_REPORT_IDENT_SOAP_RES_TIME_MIN = "soap.res_time.min";
const char * SODERO_REPORT_IDENT_SOAP_RES_TIME_MAX = "soap.res_time.max";
const char * SODERO_REPORT_IDENT_SOAP_RES_TIME_AVG = "soap.res_time.avg";

const char * SODERO_REPORT_IDENT_SOAP_WAIT_TIME_MIN = "soap.wait_time.min";
const char * SODERO_REPORT_IDENT_SOAP_WAIT_TIME_MAX = "soap.wait_time.max";
const char * SODERO_REPORT_IDENT_SOAP_WAIT_TIME_AVG = "soap.wait_time.avg";



const char * sodero_ident_ipv4_count(int proto) {
	switch(proto) {
	case IPv4_TYPE_ICMP:
		return SODERO_REPORT_IDENT_ICMP_COUNT;
	case IPv4_TYPE_TCP:
		return SODERO_REPORT_IDENT_TCP_COUNT;
	case IPv4_TYPE_UDP:
		return SODERO_REPORT_IDENT_UDP_COUNT;
	case IPv4_TYPE_SCTP:
		return SODERO_REPORT_IDENT_SCTP_COUNT;
	}
	return nullptr;
}

const char * sodero_ident_ipv4_bytes(int proto) {
	switch(proto) {
	case IPv4_TYPE_ICMP:
		return SODERO_REPORT_IDENT_ICMP_BYTES;
	case IPv4_TYPE_TCP:
		return SODERO_REPORT_IDENT_TCP_BYTES;
	case IPv4_TYPE_UDP:
		return SODERO_REPORT_IDENT_UDP_BYTES;
	case IPv4_TYPE_SCTP:
		return SODERO_REPORT_IDENT_SCTP_BYTES;
	}
	return nullptr;
}

long map_node_report_handlor(PSoderoMap container, int index, PNodeIndex k, PNodeValue v, unsigned long long * metricCount) {
#ifdef __EXPORT_REPORT__
	dumpNode(index, k, v);
#endif
	if (k->ip.l.ip) {
//		if (isGIPv4(k->ip.l)) return 0;
	}
	if (count_of_detail(&v->l2.total, SODERO_PACKET_INDEX_TOTAL) >= 0) {
		//	Node
		sodero_report_node(k, nullptr, SODERO_NODES);
		//	L2
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_COUNT, count_of_detail(&v->l2.total, SODERO_PACKET_INDEX_TOTAL), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_BYTES, bytes_of_detail(&v->l2.total, SODERO_PACKET_INDEX_TOTAL), metricCount);

		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_COUNT_00064, count_of_detail(&v->l2.total, SODERO_PACKET_INDEX_00064), metricCount);
//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_BYTES_00064, bytes_of_total(&v->l2.total, SODERO_PACKET_INDEX_00064), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_COUNT_00128, count_of_detail(&v->l2.total, SODERO_PACKET_INDEX_00128), metricCount);
//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_BYTES_00128, bytes_of_total(&v->l2.total, SODERO_PACKET_INDEX_00128), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_COUNT_00256, count_of_detail(&v->l2.total, SODERO_PACKET_INDEX_00256), metricCount);
//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_BYTES_00256, bytes_of_total(&v->l2.total, SODERO_PACKET_INDEX_00256), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_COUNT_00512, count_of_detail(&v->l2.total, SODERO_PACKET_INDEX_00512), metricCount);
//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_BYTES_00512, bytes_of_total(&v->l2.total, SODERO_PACKET_INDEX_00512), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_COUNT_01024, count_of_detail(&v->l2.total, SODERO_PACKET_INDEX_01024), metricCount);
//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_BYTES_01024, bytes_of_total(&v->l2.total, SODERO_PACKET_INDEX_01024), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_COUNT_01514, count_of_detail(&v->l2.total, SODERO_PACKET_INDEX_01514), metricCount);
//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_BYTES_01514, bytes_of_total(&v->l2.total, SODERO_PACKET_INDEX_01514), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_COUNT_01518, count_of_detail(&v->l2.total, SODERO_PACKET_INDEX_01518), metricCount);
//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_BYTES_01518, bytes_of_total(&v->l2.total, SODERO_PACKET_INDEX_01518), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_COUNT_jumbo, count_of_detail(&v->l2.total, SODERO_PACKET_INDEX_JUMBO), metricCount);
//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_BYTES_jumbo, bytes_of_total(&v->l2.total, SODERO_PACKET_INDEX_JUMBO), metricCount);

//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_INCOMING_COUNT, v->l2.total.incoming.total.count, metricCount);
//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_INCOMING_BYTES, v->l2.total.incoming.total.bytes, metricCount);
//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_OUTGOING_COUNT, v->l2.total.incoming.total.count, metricCount);
//		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_OUTGOING_BYTES, v->l2.total.incoming.total.bytes, metricCount);

		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_BCAST_COUNT, count_of_datum(&v->l2.bcast), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_BCAST_BYTES, bytes_of_datum(&v->l2.bcast), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_MCAST_COUNT, count_of_datum(&v->l2.mcast), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_MCAST_BYTES, bytes_of_datum(&v->l2.mcast), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_UCAST_COUNT, count_of_datum(&v->l2.ucast), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_UCAST_BYTES, bytes_of_datum(&v->l2.ucast), metricCount);

		//	L2|l2_type
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_ARP_COUNT  , count_of_datum(&v->l2.arp  ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_ARP_BYTES  , bytes_of_datum(&v->l2.arp  ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_IPV4_COUNT , count_of_datum(&v->l2.ipv4 ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_IPV4_BYTES , bytes_of_datum(&v->l2.ipv4 ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_IPV6_COUNT , count_of_datum(&v->l2.ipv6 ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_IPV6_BYTES , bytes_of_datum(&v->l2.ipv6 ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_LACP_COUNT , count_of_datum(&v->l2.lacp ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_LACP_BYTES , bytes_of_datum(&v->l2.lacp ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_MPLS_COUNT , count_of_datum(&v->l2.mpls ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_MPLS_BYTES , bytes_of_datum(&v->l2.mpls ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_RSTP_COUNT , count_of_datum(&v->l2.rstp ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_RSTP_BYTES , bytes_of_datum(&v->l2.rstp ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_OTHER_COUNT, count_of_datum(&v->l2.other), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ETHER_OTHER_BYTES, bytes_of_datum(&v->l2.other), metricCount);

		//	L3
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_IPV4_COUNT, count_of_datum(&v->l3.total), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_IPV4_BYTES, count_of_datum(&v->l3.total), metricCount);

		//	L3|l3_type
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_IPV4_ICMP_COUNT , count_of_datum(&v->l3.icmp ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_IPV4_ICMP_BYTES , bytes_of_datum(&v->l3.icmp ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_IPV4_TCP_COUNT  , count_of_datum(&v->l3.tcp  ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_IPV4_TCP_BYTES  , bytes_of_datum(&v->l3.tcp  ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_IPV4_UDP_COUNT  , count_of_datum(&v->l3.udp  ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_IPV4_UDP_BYTES  , bytes_of_datum(&v->l3.udp  ), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_IPV4_OTHER_COUNT, count_of_datum(&v->l3.other), metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_IPV4_OTHER_BYTES, bytes_of_datum(&v->l3.other), metricCount);

		// L4
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_TCP_OUTGOING_COUNT  , v->l3.tcp.outgoing.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_TCP_OUTGOING_BYTES  , v->l3.tcp.outgoing.bytes, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_TCP_INCOMING_COUNT  , v->l3.tcp.incoming.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_TCP_INCOMING_BYTES  , v->l3.tcp.incoming.bytes, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_UDP_OUTGOING_COUNT  , v->l3.udp.outgoing.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_UDP_OUTGOING_BYTES  , v->l3.udp.outgoing.bytes, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_UDP_INCOMING_COUNT  , v->l3.udp.incoming.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_UDP_INCOMING_BYTES  , v->l3.udp.incoming.bytes, metricCount);

		if (isExportVerbose())
			printf("Report %p TCP Connect %u Disconntect %u\n", v,
				v->counter.tcp.outgoing.connectedCount + v->counter.tcp.incoming.connectedCount,
				v->counter.tcp.outgoing.disconectedCount + v->counter.tcp.incoming.disconectedCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_TCP_CONNECTED_COUNT, v->counter.tcp.outgoing.connectedCount   + v->counter.tcp.incoming.connectedCount  , metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_TCP_CLOSED_COUNT   , v->counter.tcp.outgoing.disconectedCount + v->counter.tcp.incoming.disconectedCount, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_TCP_RESET_COUNT   , v->counter.tcp.outgoing.rstCount, metricCount);

		//	L7
		//	HTTP
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_REQUEST_COUNT , v->l4.http.outgoing.value.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_REQUEST_BYTES , v->l4.http.outgoing.value.bytes, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_RESPONSE_COUNT, v->l4.http.incoming.value.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_RESPONSE_BYTES, v->l4.http.incoming.value.bytes, metricCount);

		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_REQUEST_L2_BYTES , v->l4.http.outgoing.l2, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_RESPONSE_L2_BYTES, v->l4.http.incoming.l2, metricCount);

		
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_STATUS1XX, v->l4.http.incoming.x10, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_STATUS2XX, v->l4.http.incoming.x20, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_STATUS3XX, v->l4.http.incoming.x30, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_STATUS4XX, v->l4.http.incoming.x40, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_STATUS5XX, v->l4.http.incoming.x50, metricCount);

		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_METHOD, v->l4.http.outgoing.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_ERROR , v->l4.http.incoming.count, metricCount);

		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_REQUEST , v->l4.http.outgoing.action, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_RESPONSE, v->l4.http.incoming.action, metricCount);

		unsigned long long rttValue = v->l4.http.incoming.rttValue + v->l4.http.outgoing.rttValue;
		unsigned int       rttCount = v->l4.http.incoming.rttCount + v->l4.http.outgoing.rttCount;
		if (rttCount)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_RTT, rttValue / rttCount, metricCount);

		//printf("req time %llx, %llx, %llx, %llx\r\n", v->l4.http.outgoing.request.min, v->l4.http.outgoing.request.max, v->l4.http.outgoing.request.sum, v->l4.http.outgoing.request.count);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_REQ_TIME_MIN, v->l4.http.outgoing.request.min, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_REQ_TIME_MAX , v->l4.http.outgoing.request.max, metricCount);
		if (v->l4.http.outgoing.request.count)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_REQ_TIME_AVG , v->l4.http.outgoing.request.sum / (v->l4.http.outgoing.request.count), metricCount);

		
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_WAIT_TIME_MIN, v->l4.http.outgoing.wait.min, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_WAIT_TIME_MAX , v->l4.http.outgoing.wait.max, metricCount);
		if (v->l4.http.outgoing.wait.count)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_WAIT_TIME_AVG , v->l4.http.outgoing.wait.sum / (v->l4.http.outgoing.wait.count), metricCount);

		
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_RES_TIME_MIN, v->l4.http.outgoing.response.min, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_RES_TIME_MAX , v->l4.http.outgoing.response.max, metricCount);
		if (v->l4.http.outgoing.response.count)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_HTTP_RES_TIME_AVG , v->l4.http.outgoing.response.sum / (v->l4.http.outgoing.response.count), metricCount);

		//	MySQL
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_MYSQL_REQUEST_COUNT , v->l4.mysql.outgoing.value.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_MYSQL_REQUEST_BYTES , v->l4.mysql.outgoing.value.bytes, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_MYSQL_RESPONSE_COUNT, v->l4.mysql.incoming.value.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_MYSQL_RESPONSE_BYTES, v->l4.mysql.incoming.value.bytes, metricCount);

		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_MYSQL_REQUEST_L2_BYTES , v->l4.mysql.outgoing.l2, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_MYSQL_RESPONSE_L2_BYTES, v->l4.mysql.incoming.l2, metricCount);

		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_MYSQL_COMMAND, v->l4.mysql.outgoing.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_MYSQL_BLOCK  , v->l4.mysql.incoming.block, metricCount);

		rttValue = v->l4.mysql.incoming.rttValue + v->l4.mysql.outgoing.rttValue;
		rttCount = v->l4.mysql.incoming.rttCount + v->l4.mysql.outgoing.rttCount;
		if (rttCount)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_MYSQL_RTT, rttValue / rttCount, metricCount);

	       //	Oracle
	    SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_REQUEST_COUNT , v->l4.tns.outgoing.reqs, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_REQUEST_PKT_COUNT , v->l4.tns.outgoing.value.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_REQUEST_BYTES , v->l4.tns.outgoing.value.bytes, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_RESPONSE_COUNT, v->l4.tns.incoming.reqs, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_RESPONSE_PKT_COUNT, v->l4.tns.incoming.value.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_RESPONSE_BYTES, v->l4.tns.incoming.value.bytes, metricCount);

		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_REQUEST_L2_BYTES , v->l4.tns.outgoing.l2, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_RESPONSE_L2_BYTES, v->l4.tns.incoming.l2, metricCount);

		//SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_COMMAND, v->l4.tns.outgoing.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_BLOCK  , v->l4.tns.incoming.block, metricCount);

		
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_REQ_TIME_MIN, v->l4.tns.outgoing.request.min, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_REQ_TIME_MAX , v->l4.tns.outgoing.request.max, metricCount);
		if (v->l4.tns.outgoing.request.count)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_REQ_TIME_AVG , v->l4.tns.outgoing.request.sum / (v->l4.tns.outgoing.request.count), metricCount);

		
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_WAIT_TIME_MIN, v->l4.tns.outgoing.wait.min, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_WAIT_TIME_MAX , v->l4.tns.outgoing.wait.max, metricCount);
		if (v->l4.tns.outgoing.wait.count)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_WAIT_TIME_AVG , v->l4.tns.outgoing.wait.sum / (v->l4.tns.outgoing.wait.count), metricCount);

		
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_RES_TIME_MIN, v->l4.tns.outgoing.response.min, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_RES_TIME_MAX , v->l4.tns.outgoing.response.max, metricCount);
		if (v->l4.tns.outgoing.response.count)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_RES_TIME_AVG , v->l4.tns.outgoing.response.sum / (v->l4.tns.outgoing.response.count), metricCount);

		rttValue = v->l4.tns.incoming.rttValue + v->l4.tns.outgoing.rttValue;
		rttCount = v->l4.tns.incoming.rttCount + v->l4.tns.outgoing.rttCount;
		if (rttCount)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_ORACLE_RTT, rttValue / rttCount, metricCount);

		
		//	SOAP
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_REQUEST_COUNT , v->l4.soap.outgoing.action, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_REQUEST_BYTES , v->l4.soap.outgoing.value.bytes, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_REQUEST_PKT_COUNT , v->l4.soap.outgoing.value.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_REQUEST_L2_BYTES , v->l4.soap.outgoing.l2, metricCount);
		
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_RESPONSE_COUNT, v->l4.soap.incoming.action, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_RESPONSE_BYTES, v->l4.soap.incoming.value.bytes, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_RESPONSE_PKT_COUNT , v->l4.soap.incoming.value.bytes, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_RESPONSE_L2_BYTES , v->l4.soap.incoming.l2, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_RESPONSE_FAULT, v->l4.soap.incoming.fault, metricCount);

		//printf("------------------------------req time %llx, %llx, %llx, %llx\r\n", v->l4.http.outgoing.request.min, v->l4.http.outgoing.request.max, v->l4.http.outgoing.request.sum, v->l4.http.outgoing.request.count);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_REQ_TIME_MIN, v->l4.soap.outgoing.request.min, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_REQ_TIME_MAX , v->l4.soap.outgoing.request.max, metricCount);
		if (v->l4.soap.outgoing.request.count)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_REQ_TIME_AVG , v->l4.soap.outgoing.request.sum / (v->l4.soap.outgoing.request.count), metricCount);

		
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_WAIT_TIME_MIN, v->l4.soap.outgoing.wait.min, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_WAIT_TIME_MAX , v->l4.soap.outgoing.wait.max, metricCount);
		if (v->l4.soap.outgoing.wait.count)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_WAIT_TIME_AVG , v->l4.soap.outgoing.wait.sum / (v->l4.soap.outgoing.wait.count), metricCount);
		
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_RES_TIME_MIN, v->l4.soap.outgoing.response.min, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_RES_TIME_MAX , v->l4.soap.outgoing.response.max, metricCount);
		if (v->l4.soap.outgoing.response.count)
			SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_SOAP_RES_TIME_AVG , v->l4.soap.outgoing.response.sum / (v->l4.soap.outgoing.response.count), metricCount);

		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_DNS_REQUEST_COUNT  , v->l4.dns.incoming.request .value.count + v->l4.dns.outgoing.request .value.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_DNS_REQUEST_BYTES  , v->l4.dns.incoming.request .value.bytes + v->l4.dns.outgoing.request .value.bytes, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_DNS_RESPONSE_COUNT , v->l4.dns.incoming.response.value.count + v->l4.dns.outgoing.response.value.count, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_DNS_RESPONSE_BYTES , v->l4.dns.incoming.response.value.bytes + v->l4.dns.outgoing.response.value.bytes, metricCount);

		for (int i = 0; i < 3; i++)
			SODERO_REPORT_GROUP(k, SODERO_REPORT_IDENT_DNS_OUTGOING_OCODES, i, v->l4.dns.incoming.request .codes.o.codes[i], metricCount);
		int errorCount = 0;
		for (int i = 0; i < 6; i++) {
			if (i > 0) {
//				iError += v->l4.dns.incoming.response.codes.r.codes[i];
//				oError += v->l4.dns.outgoing.response.codes.r.codes[i];
				errorCount += v->l4.dns.outgoing.response.codes.r.codes[i];
			}
			SODERO_REPORT_GROUP(k, SODERO_REPORT_IDENT_DNS_INCOMING_OCODES, i, v->l4.dns.outgoing.request .codes.r.codes[i], metricCount);
		}
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_DNS_OUTGOING_ERROR, errorCount, metricCount);
		SODERO_REPORT_VALUE(k, SODERO_REPORT_IDENT_DNS_INCOMING_TIMEOUT, v->l4.dns.incoming.timeout + v->l4.dns.outgoing.timeout, metricCount);

		TSoderoUnitDatum duration = {
				v->l4.dns.incoming.duration.count + v->l4.dns.outgoing.duration.count,
				{{v->l4.dns.incoming.duration.sum + v->l4.dns.outgoing.duration.sum,
				v->l4.dns.incoming.duration.max + v->l4.dns.outgoing.duration.max,
				v->l4.dns.incoming.duration.min + v->l4.dns.outgoing.duration.min}}
		};
		SODERO_REPORT_DATUM(k, SODERO_REPORT_IDENT_DNS_INCOMING_DURATION, duration, metricCount);
	}
	return 0;
}

long map_service_report_handlor(PSoderoMap container, int index, PServiceIndex k, PSoderoDoubleDatum v, unsigned long long * metricCount) {
	if (k->node.ip.l.ip) {
		if (isGIPv4(k->node.ip.l)) return 0;
	}

	char name[256];
	snprintf(name, sizeof(name)-1, "tcp.req_pkts|l4_group|%hu", (unsigned short) htons(k->port));
	SODERO_REPORT_VALUE(&k->node, name, v->outgoing.count, metricCount);
	snprintf(name, sizeof(name)-1, "tcp.req_bytes|l4_group|%hu", (unsigned short) htons(k->port));
	SODERO_REPORT_VALUE(&k->node, name, v->outgoing.bytes, metricCount);
	snprintf(name, sizeof(name)-1, "tcp.rsp_pkts|l4_group|%hu", (unsigned short) htons(k->port));
	SODERO_REPORT_VALUE(&k->node, name, v->incoming.count, metricCount);
	snprintf(name, sizeof(name)-1, "tcp.rsp_bytes|l4_group|%hu", (unsigned short) htons(k->port));
	SODERO_REPORT_VALUE(&k->node, name, v->incoming.bytes, metricCount);

	return 0;
}

#ifdef __NO_CYCLE__
long session_manager_handlor(PSoderoSessionManager container, int index, PSoderoSession object, void * data) {
	return sodero_report_session(object, SODERO_REPORT_WAY_BODY);
}
#endif

int sodero_send(PSoderoPeriodResult result, PSoderoSessionManager manager) {
	unsigned long long metricCount = 0;

#ifdef __NO_CYCLE__
	if (sodero_session_foreach(manager, (TSessionTimeoutHandlor) session_manager_handlor, nullptr) < 0) return false;
#endif
	if (sodero_map_foreach(result->nodes.items, (TforeachMapHandlor)map_node_report_handlor   , &metricCount) < 0) return false;
	if (sodero_map_foreach(result->nodes.ports, (TforeachMapHandlor)map_service_report_handlor, &metricCount) < 0) return false;

	sodero_report_finished(metricCount);
	return true;
}

void sodero_report_result(PSoderoPeriodResult result, PSoderoSessionManager manager) {
	if (!result) return;

	gReportCounter = result->time / uSecsPerSec;

#ifndef __SKIP_REPORT__
	do {
		if (!sodero_report_check()) {
			printf("Can't connect to server\n");
			break;
		}

		long long b = now();
#ifndef __SKIP_WRITE__
		if (!sodero_send(result, manager)) {
			printf("Can't send report to server\n");
			sodero_report_disconnect();
			break;
		}
#endif
		reset_period_result(result);
		long long e = now();

		if (gT)
		printf("Report time %.3fs send %llu/%u recv %llu/%u Data %.3fs %llu/%u\n",
				1e-6*(gO + e-b), gReportSend.bytes, gReportSend.count, gReportRecv.bytes, gReportRecv.count,
				1e-6*(gT      ), gCurrent.bytes, gCurrent.count);
		gReportSend.bytes = 0;
		gReportSend.count = 0;
		gCurrent.bytes = 0;
		gCurrent.count = 0;
		gT = 0;
		gO = 0;
	} while (false);
#endif

	gB = now();
}

int sodero_report_arp_event(PSoderoARPEvent session, unsigned long time) {
	TXDREventBuffer data;
	bzero(&data.event, sizeof(data.event));
	data.event.data.length = sizeof(data) - sizeof(data.event);

	TSoderoTCPReportMsg * report = &data.event.message;
	report->type = SESSION_EVENT;

	TSoderoSessionMsg * msssage = &report->TSoderoTCPReportMsg_u.session_event;
	msssage->event = EVENT_TYPE_ARP;

	TSoderoTCPSessionContent * content = &msssage->session_content;
	content->type = SESSION_TYPE_ARP;

	TSoderoARPThing * record = &content->TSoderoTCPSessionContent_u.arp;
	record->time  = time;
	record->code  = session->opcode;
//	record->senderMAC = session->senderMAC.bytes;
	memcpy(record->client_mac, &session->senderMAC, sizeof(TMAC));
	memcpy(record->client_ip, &session->senderIP.ip, sizeof(session->senderIP.ip));
	memcpy(record->server_mac, &session->targetMAC, sizeof(TMAC));
	memcpy(record->server_ip, &session->targetIP.ip, sizeof(session->targetIP.ip));

	return sodero_xdr_tcp_message(&gTCPSocket, report);
}

int sodero_report_icmp_event(PSoderoICMPEvent session, unsigned long time) {
	TXDREventBuffer data;
	bzero(&data.event, sizeof(data.event));
	data.event.data.length = sizeof(data) - sizeof(data.event);

	TSoderoTCPReportMsg * report = &data.event.message;
	report->type = SESSION_EVENT;

	TSoderoSessionMsg * msssage = &report->TSoderoTCPReportMsg_u.session_event;
	msssage->event = EVENT_TYPE_ICMP;

	TSoderoTCPSessionContent * content = &msssage->session_content;
	content->type = SESSION_TYPE_ICMP;

	content->TSoderoTCPSessionContent_u.icmp.type = ICMP_TYPE_EVENT;
	TSoderoICMPThing * record = &content->TSoderoTCPSessionContent_u.icmp.thing;
	record->time = time;
	record->code = session->code;
	record->proto = session->info.proto;
	memcpy(record->client_ip, &session->info.sourIP, sizeof(session->info.sourIP));
	memcpy(record->server_ip, &session->info.destIP, sizeof(session->info.destIP));
	record->client_port = session->info.sourPort;
	record->server_port = session->info.destPort;
	return sodero_xdr_tcp_message(&gTCPSocket, report);
}

int sodero_report_icmp_session(PSoderoICMPSession session, int way) {

	if (way & SODERO_REPORT_DONE) {
		TXDREventBuffer data;
		bzero(&data.event, sizeof(data.event));
		data.event.data.length = sizeof(data) - sizeof(data.event);

		TSoderoTCPReportMsg * report = &data.event.message;
		report->type = SESSION_EVENT;

		TSoderoSessionMsg * msssage = &report->TSoderoTCPReportMsg_u.session_event;
		msssage->event = EVENT_TYPE_ICMP;

		TSoderoTCPSessionContent * content = &msssage->session_content;
		content->type = SESSION_TYPE_ICMP;

		content->TSoderoTCPSessionContent_u.icmp.type = ICMP_TYPE_SESSION;
		TSoderoICMPMsg * record = &content->TSoderoTCPSessionContent_u.icmp.msg;

		record->id = session->id;
		memcpy(record->client_ip, &session->key.sourIP, sizeof(session->key.sourIP));
		memcpy(record->server_ip, &session->key.destIP, sizeof(session->key.destIP));
		record->reqTime  = session->b;
		record->rspTime  = session->e;
		record->identify = session->value.echo.identify;
		record->sequence = session->value.echo.sequence;
		record->incoming = session->traffic.incoming.bytes;
		record->outgoing = session->traffic.outgoing.bytes;

		return sodero_xdr_tcp_message(&gTCPSocket, report);
	}
	return true;
}

int sodero_report_tcp_session(PSoderoTCPSession session, int way) {
	int flag = way & SODERO_REPORT_DONE;

	if (way & SODERO_REPORT_HEAD) {
		if (!sodero_report_flow_head((PSoderoPortSession)session, flag)) return false;
	}

	if (way & SODERO_REPORT_BODY) {
		if (!sodero_report_flow_body((PSoderoPortSession)session, flag)) return false;
	}

	if (flag) {
		PSoderoApplication application = session->session;
		while(application) {
			if (!sodero_report_tcp_application(application, flag)) return false;
			application = application->link;
		}
	}
	return true;
}

int sodero_report_udp_session(PSoderoUDPSession session, int way) {
	int flag = way & SODERO_REPORT_DONE;
	if (way & SODERO_REPORT_HEAD) {
		if (!sodero_report_flow_head((PSoderoPortSession)session, flag)) return false;
	}

	if (way & SODERO_REPORT_BODY) {
		if (!sodero_report_flow_body((PSoderoPortSession)session, flag)) return false;
	}

	if (flag) {
		PSoderoApplication application = session->session;
		while(application) {
			if (!sodero_report_udp_application(application, flag)) return false;
			application = application->link;
		}
	}
	return true;
}

int sodero_report_event_log(PSoderoEventLog log, unsigned long time) {
	return true;
}

int sodero_report_event_report(PSoderoEventReport report, unsigned long time) {
	switch(report->kind) {
	case SODERO_REPORT_ARP:
		return sodero_report_arp_event(&report->arp, time);
	case SODERO_REPORT_ICMP:
		return sodero_report_icmp_event(&report->icmp, time);
	}
	return true;
}

int sodero_report_event(PSoderoEvent event, int way) {
#ifndef __SKIP_REPORT__
	switch(event->type) {
	case SODERO_EVENT_LOG:
		return sodero_report_event_log(&event->log, event->time);
	case SODERO_EVENT_REPORT:
		return sodero_report_event_report(&event->report, event->time);
	}
#endif
	return true;
}

int sodero_report_session(PSoderoSession session, int way) {
#ifndef __SKIP_REPORT__
//	printf("Report session %p %s %x %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", session, ipv4_proto_name(session->key.proto), way,
//			session->key.s[0], session->key.s[1], session->key.s[2], session->key.s[3], ntohs(session->key.sourPort),
//			session->key.d[0], session->key.d[1], session->key.d[2], session->key.d[3], ntohs(session->key.destPort));

      /*write to log file*/
       LogDbg("[Session |%d |%s | %x | %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d | %d | %d]", session->id, ipv4_proto_name(session->key.proto), way,
			session->key.s[0], session->key.s[1], session->key.s[2], session->key.s[3], ntohs(session->key.sourPort),
			session->key.d[0], session->key.d[1], session->key.d[2], session->key.d[3], ntohs(session->key.destPort),
			session->traffic.outgoing.bytes, session->traffic.incoming.bytes);
	switch(session->key.proto) {
	case IPPROTO_ICMP:
		return sodero_report_icmp_session((PSoderoICMPSession) session, way);
	case IPPROTO_TCP:
		return sodero_report_tcp_session((PSoderoTCPSession) session, way);
	case IPPROTO_UDP:
		return sodero_report_udp_session((PSoderoUDPSession) session, way);
	}
#endif
	return true;
}

int sodero_report_application(PSoderoApplication application, int flag) {
#ifndef __SKIP_REPORT__
	while(application) {
		PSoderoSession session = application->owner;
		if (!session) return true;

		/*write to log file*/
              LogDbg("[Session |%d|%d |%x | %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d | %d | %d]", session->id, session->flag, flag,
			session->key.s[0], session->key.s[1], session->key.s[2], session->key.s[3], ntohs(session->key.sourPort),
			session->key.d[0], session->key.d[1], session->key.d[2], session->key.d[3], ntohs(session->key.destPort),
			session->traffic.outgoing.bytes, session->traffic.incoming.bytes);
			
		switch(session->key.proto) {
		case IPPROTO_ICMP:
			break;
		case IPPROTO_TCP:
			if (!sodero_report_tcp_application(application, flag)) return false;
			break;
		case IPPROTO_UDP:
			if (!sodero_report_udp_application(application, flag)) return false;
			break;
		}
		application = application->link;
	}
#endif
	return true;
}

int sodero_report_udp_application(PSoderoApplication application, int flag) {
	PSoderoSession session = application->owner;
//	printf("Report session %p %s Application %p %d\n", session, ipv4_proto_name(session->key.proto), application, session->flag);

	switch (session->flag) {
		case SESSION_TYPE_MINOR_DNS:
			return sodero_report_dns_application((PSoderoApplicationDNS) application, flag);
	}
	return true;
}

int sodero_report_tcp_application(PSoderoApplication application, int flag) {
	PSoderoSession session = application->owner;
//	printf("Report session %p %s Application %p %d\n", session, ipv4_proto_name(session->key.proto), application, session->flag);

	switch (session->flag) {
		case SESSION_TYPE_MINOR_HTTP:
		case SESSION_TYPE_MINOR_HTTPS:
			if (flag & SODERO_REPORT_HEAD) {
				if (!sodero_report_http_head((PSoderoApplicationHTTP)application, flag)) return false;
				break;
			}

			if (flag & SODERO_REPORT_BODY) {
				if (!sodero_report_http_body((PSoderoApplicationHTTP)application, flag)) return false;
				break;
			}

			if (flag & SODERO_REPORT_DONE) {
				if (!sodero_report_http_body((PSoderoApplicationHTTP)application, flag)) return false;
				break;
			}
			break;
		case SESSION_TYPE_MINOR_MYSQL:
			return sodero_report_mysql_application((PSoderoMySQLApplication)application, flag);
		case SESSION_TYPE_MINOR_ORACLE:
			return sodero_report_oracle_application((PSoderoMySQLApplication)application, flag);
	}
	return true;
}

TSoderoShmMsg *sodero_get_shm(void)
{
	int shm_id = 0;
	int create = 1;
	key_t key;
	TSoderoShmMsg *pShm = NULL;

	key = ftok("/dev/console", 0);
	if (key == -1)
	{
		perror("ftok error");
		return NULL;
	}

	shm_id = shmget(key, sizeof(TSoderoShmMsg), SHM_R|SHM_W|IPC_CREAT|IPC_EXCL);	
	if (shm_id == -1)
	{
		if (errno == EEXIST)
		{
			shm_id = shmget(key, 0, SHM_R|SHM_W);
			create = 0;
		}
		else
		{
			printf("Create Share Memory Error:%s\n", strerror(errno));
			return NULL;
		}
	}

	pShm = (TSoderoShmMsg *)shmat(shm_id, NULL, 0);
	if (pShm == NULL)
	{
		printf("Share Memory Attach Error:%s\n", strerror(errno));
		return NULL;
	}

	if (create == 1)
	{
		memset((char *)pShm, 0, sizeof(TSoderoShmMsg));
	}
	else
	{
		printf("head=%u, tail=%u, write=%llu, read=%llu.\n", 
			pShm->head, pShm->tail, pShm->write_count, pShm->read_count);
	}
	return pShm;
}

int sodero_write_message(char * buffer) 
{
	TSoderoShmMsg *pMsg = gShmMsg;

	if (pMsg == NULL)
	{
		printf("Share Memory Is NULL.\n");
		return false;
	}

	if (pMsg->tail == ((pMsg->head + 1) % MSG_NUM))
	{
		printf("Shared Memory Is Full.\n");
		return true;
	}

	memcpy(&(pMsg->report_msg[pMsg->head]), buffer, XDR_BUFFER_SIZE);
	pMsg->head = (pMsg->head + 1) % MSG_NUM;
	pMsg->write_count++;
    
    if (pMsg->write_count % 10000 == 0) {
        printf("head=%u, tail=%u, write=%llu, read=%llu.\n",
               pMsg->head, pMsg->tail, pMsg->write_count, pMsg->read_count);
    }

	return TRUE;
}

