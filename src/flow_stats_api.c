/*
 * flow_stats_api.cpp
 *
 *  Created on: Aug 24, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "flow_stats_api.h"

#ifdef __ASYNCHRONOUS_TRANSMIT__

int sodero_deserialize_report(char * buffer, int length, int * size, TSoderoReportMsg * message) {
	if (length < 2) return 0;

	int bytes = *(unsigned short *) buffer;

	length -= sizeof(unsigned short);
	buffer += sizeof(unsigned short);

	if (length < bytes) return 0;

	XDR xdr_handle;
	xdrmem_create(&xdr_handle, buffer, length, XDR_DECODE);

	xdr_setpos(&xdr_handle, 0);
	memset(message, 0, sizeof(TSoderoReportMsg));

	int result = xdr_TSoderoReportMsg(&xdr_handle, message);

	if (result != TRUE) {
		// error
		printf("Decoding error\n");
		return -1;
	}

	if (*size)
		*size = sizeof(unsigned short) + bytes;	//	xdr_getpos(&xdr_handle);

	xdr_destroy(&xdr_handle);
	return 1;

}

void sodero_clean_report(TSoderoReportMsg * message) {
	xdr_free((xdrproc_t) xdr_TSoderoReportMsg, (char *) message);
}

int sodero_serialize_report(char *buffer, int length, int * size,
		TSoderoReportMsg * message) {
	if (length < 2) return 0;

	length -= sizeof(unsigned short);

	XDR xdr_handle;
	xdrmem_create(&xdr_handle, buffer + sizeof(unsigned short), length, XDR_ENCODE);
	bzero(buffer, length);

	xdr_setpos(&xdr_handle, 0);

	int result = xdr_TSoderoReportMsg(&xdr_handle, message);

	if (result != TRUE) {
		printf("Error during encoding! or Not enought space\n");
		return 0;
	}

	if (size) {
		*(unsigned short*) buffer = xdr_getpos(&xdr_handle);
		*size = sizeof(unsigned short) + *(unsigned short*) buffer;
	};

	return 1;
}

#else

int sodero_serialize_TCP_report_v1(char *send_buffer, int *numbytes,
		TSoderoTCPReportMsg *report_data) {
	int result;
	int size;
	XDR xdr_handle;


	xdrmem_create(&xdr_handle, send_buffer, SEND_RECV_BUFFER_SIZE, XDR_ENCODE);
	bzero(send_buffer, SEND_RECV_BUFFER_SIZE);

	// printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");

	*numbytes = 0;

	xdr_setpos(&xdr_handle, 0);

	result = xdr_TSoderoTCPReportMsg(&xdr_handle, report_data);

	if (result != TRUE) {
		printf("Error during encoding! or Not enought space\n");
		return 0;
	}

	size = xdr_getpos(&xdr_handle);
	// printf("\tSize of encoded data: %d\n", size);

	// printf("-------------------------------------------------------\n");

	*numbytes = size;

	return 1;
}

int sodero_serialize_UDP_report_v1(char *send_buffer, int *numbytes, int num,
		TSoderoUDPReportMsg * report_data) {
	int result;
	int size, prev_pos;
	XDR xdr_handle;
	int idx;

	xdrmem_create(&xdr_handle, send_buffer, SEND_RECV_BUFFER_SIZE, XDR_ENCODE);
	bzero(send_buffer, SEND_RECV_BUFFER_SIZE);

	size = 0;
	prev_pos = 0;
	*numbytes = 0;
	for (idx = 0; idx < num; idx++) {

		printf("[%dth] element\n", idx);

		xdr_setpos(&xdr_handle, prev_pos);

		result = xdr_TSoderoUDPReportMsg(&xdr_handle, &report_data[idx]);

		if (result != TRUE) {
			printf("Error during encoding! or Not enought space\n");
			break;
		}

		size = xdr_getpos(&xdr_handle);
		// printf("\tSize of encoded data: %d\n", size - prev_pos);

		prev_pos = size;
	}
	// printf("-------------------------------------------------------\n");

	*numbytes = size;

	return idx;
}

void copy_udp_count_metric(TSoderoUDPReportMsg *dest, TSoderoUDPReportMsg *src) {
	TSoderoCountMetricMsg *dest_metric;
	TSoderoCountMetricMsg *src_metric;

	dest_metric = &(dest->TSoderoUDPReportMsg_u.count_metric);
	src_metric = &(src->TSoderoUDPReportMsg_u.count_metric);

	/* copy type*/
	dest->type = src->type;

	bzero(dest_metric->mac, sizeof(dest_metric->mac));
	bzero(dest_metric->ip, sizeof(dest_metric->ip));

	strncpy((char *) dest_metric->mac, (char *) src_metric->mac,
			sizeof(src_metric->mac));
	dest_metric->vlan = src_metric->vlan;
	strncpy((char *) dest_metric->ip, (char *) src_metric->ip,
			sizeof(src_metric->ip));

	if (src_metric->metrics.metrics_len
			!= sizeof(src_metric->metrics.metrics_val)) {

		src_metric->metrics.metrics_len =
				sizeof(src_metric->metrics.metrics_val);
	}
	dest_metric->metrics.metrics_len = src_metric->metrics.metrics_len;
	dest_metric->metrics.metrics_val = (u_char *) malloc(
			sizeof(u_char) * dest_metric->metrics.metrics_len);
	strncpy((char *) dest_metric->metrics.metrics_val,
			(char *) src_metric->metrics.metrics_val,
			dest_metric->metrics.metrics_len);

	dest_metric->time = src_metric->time;
	dest_metric->count = src_metric->count;
}

void copy_udp_periodic_metric(TSoderoUDPReportMsg *dest,
		TSoderoUDPReportMsg *src) {
	TSoderoPeriodicMetricMsg *dest_metric;
	TSoderoPeriodicMetricMsg *src_metric;

	printf("here1\n");
	dest_metric = &(dest->TSoderoUDPReportMsg_u.periodic_metric);
	src_metric = &(src->TSoderoUDPReportMsg_u.periodic_metric);
	printf("here2\n");

	dest->type = src->type;
	printf("here3\n");

	bzero(dest_metric->mac, sizeof(dest_metric->mac));
	bzero(dest_metric->ip, sizeof(dest_metric->ip));
	printf("%s\n", src_metric->mac);
	strncpy((char *) dest_metric->mac, (char *) src_metric->mac,
			sizeof(src_metric->mac));
	dest_metric->vlan = src_metric->vlan;
	strncpy((char *) dest_metric->ip, (char *) src_metric->ip,
			sizeof(src_metric->ip));
	printf("here\n");

	/* copy metrics */
	if (src_metric->metrics.metrics_len
			!= sizeof(src_metric->metrics.metrics_val)) {

		src_metric->metrics.metrics_len =
				sizeof(src_metric->metrics.metrics_val);
	}
	printf("len %s\n", src_metric->metrics.metrics_val);
	dest_metric->metrics.metrics_len = src_metric->metrics.metrics_len;
	dest_metric->metrics.metrics_val = (u_char *) malloc(
			sizeof(u_char) * dest_metric->metrics.metrics_len);
	strncpy((char *) dest_metric->metrics.metrics_val,
			(char *) src_metric->metrics.metrics_val,
			dest_metric->metrics.metrics_len);

	dest_metric->time = src_metric->time;
	dest_metric->count = src_metric->count;

	dest_metric->min = src_metric->min;
	dest_metric->max = src_metric->max;
	dest_metric->sum = src_metric->sum;
}

void free_UDPreport_data_metrics(int num, TSoderoUDPReportMsg *report_data) {
	int i;
	TSoderoUDPReportMsg *data;

	for (i = 0; i < num; i++) {
		data = &report_data[i];
		xdr_free((xdrproc_t) xdr_TSoderoUDPReportMsg, (char *) data);
	}
}

void free_TCPreport_data_metrics(TSoderoTCPReportMsg *report_data) {
	xdr_free((xdrproc_t) xdr_TSoderoTCPReportMsg, (char *) report_data);
}

int sodero_deserialize_TCP_report_v1(char *buffer, int numbytes,
		TSoderoTCPReportMsg *stored_data, int *length) {
	XDR xdr_handle;
	int result;

	xdrmem_create(&xdr_handle, buffer, SEND_RECV_BUFFER_SIZE, XDR_DECODE);

	// printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");

	xdr_setpos(&xdr_handle, 0);
	memset(stored_data, 0, sizeof(TSoderoTCPReportMsg));

	result = xdr_TSoderoTCPReportMsg(&xdr_handle, stored_data);

	if (result != TRUE) {
		// error
		printf("Decoding error\n");
		return 0;
	}

	*length = xdr_getpos(&xdr_handle);
//    printf("Decode %d bytes of encoded data\n", *length);

// printf("-------------------------------------------------------\n\n");

	xdr_destroy(&xdr_handle);
	return 1;
}

int sodero_deserialize_UDP_report_v1(char *buffer, int numbytes, int *start_pos,
		const int num_max_elements, TSoderoUDPReportMsg *stored_data) {
	XDR xdr_handle;
	int result, size, num_element;
	TSoderoUDPReportMsg incoming_data;

	xdrmem_create(&xdr_handle, buffer, SEND_RECV_BUFFER_SIZE, XDR_DECODE);

	int curr_pos, prev_pos;
	prev_pos = *start_pos;
	curr_pos = prev_pos;
	num_element = 0;

	for (; curr_pos < numbytes;) {

		// printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");

		xdr_setpos(&xdr_handle, curr_pos);
		memset(&incoming_data, 0, sizeof(TSoderoUDPReportMsg));
		// result = xdr_TSoderoUDPReport(& xdr_handle, &incoming_data);
		result = xdr_TSoderoUDPReportMsg(&xdr_handle,
				&stored_data[num_element]);

		if (result != TRUE) {
			// error
			printf("Decoding error\n");
			return 0;
		}

		size = xdr_getpos(&xdr_handle);
		// printf("Decode %d bytes of encoded data\n", size - curr_pos);

		curr_pos = size;
		num_element++;

		if (num_element == num_max_elements) {
//          printf("Reach max report data elements\n");
//          printf("-------------------------------------------------------\n\n");
			break;
		}
		// printf("-------------------------------------------------------\n\n");
	}

	*start_pos = curr_pos;

	xdr_destroy(&xdr_handle);
	return num_element;
}

#endif
