/*
 * flow_stats_api.hpp
 *
 *  Created on: Aug 24, 2014
 *      Author: Clark Dong
 */

/**
 *  For host agent/appliance library. All external calls are declare here.
 *
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

/*                 ------------------------------------          */
/***************** FUNCTIONS called by Analytic Engine  ***********/
/*                 ------------------------------------          */

/* Deserialize received buffer data to the TSoderoReport data structure */
int sodero_deserialize_UDP_report_v1(char *buffer, int numbytes, int *start_pos,
		const int num_max_elements, TSoderoUDPReportMsg *data);
void free_UDPreport_data_metrics(int num, TSoderoUDPReportMsg *report_data);

int sodero_deserialize_TCP_report_v1(char *buffer, int numbytes,
		TSoderoTCPReportMsg *stored_data, int *length);
void free_TCPreport_data_metrics(TSoderoTCPReportMsg *report_data);

/*                 ------------------------------------          */
/***************** FUNCTIONS called by Appliance agent ***********/
/*                 ------------------------------------          */

/* call this to send flow stats sample to the analytic engine */
// void sendSample(int test);
/* call this to serialize UDP data to be sent to the analytic engine */
int sodero_serialize_UDP_report_v1(char *send_buffer, int *numbytes, int num,
		TSoderoUDPReportMsg *report_data);

/* call this to serialize TCP data to be sent to the analytic engine */
int sodero_serialize_TCP_report_v1(char *send_buffer, int *numbytes,
		TSoderoTCPReportMsg *report_data);

#endif /* FLOW_STATS_API_H_ */
