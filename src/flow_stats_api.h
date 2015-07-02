/*
 * flow_stats_api.hpp
 *
 *  Created on: Aug 24, 2014
 *      Author: Clark Dong
 */

#ifndef FLOW_STATS_API_H_
#define FLOW_STATS_API_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "interface.h"

#define SEND_RECV_BUFFER_SIZE (32 * 1024)

#ifdef __ASYNCHRONOUS_TRANSMIT__

extern int sodero_deserialize_report(char * buffer, int length, int * size, TSoderoReportMsg * message);

extern void sodero_clean_report(TSoderoReportMsg * message);

extern int sodero_serialize_report(char *buffer, int length, int * size, TSoderoReportMsg * message);

#else

int sodero_deserialize_UDP_report_v1(char *buffer, int numbytes, int *start_pos,
		const int num_max_elements, TSoderoUDPReportMsg *data);
void free_UDPreport_data_metrics(int num, TSoderoUDPReportMsg *report_data);

int sodero_deserialize_TCP_report_v1(char *buffer, int numbytes,
		TSoderoTCPReportMsg *stored_data, int *length);
void free_TCPreport_data_metrics(TSoderoTCPReportMsg *report_data);

int sodero_serialize_UDP_report_v1(char *send_buffer, int *numbytes, int num,
		TSoderoUDPReportMsg *report_data);

int sodero_serialize_TCP_report_v1(char *send_buffer, int *numbytes,
		TSoderoTCPReportMsg *report_data);
#endif

#endif /* FLOW_STATS_API_H_ */
