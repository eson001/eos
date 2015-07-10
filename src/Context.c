/*
 * Context.c
 *
 *  Created on: Jul 4, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>

#include <pcap.h>

#include "Type.h"
#include "Parameter.h"
#include "Common.h"
#include "Sodero.h"
#include "Context.h"

pcap_t * createDevice(const char * device) {
	int ret;
		
	if (!device || strlen(device) == 0) return NULL;
	
	char errBuf[PCAP_ERRBUF_SIZE];
#ifdef __PCAP_EASY__
	pcap_t * pcap = pcap_open_live(device, 65535, 1, 100, errBuf);
	if (!pcap) {
		printf("error: pcap_open_live(): %s\n", errBuf);
		return NULL;
	}
#else
	pcap_t * pcap = pcap_create(device, NULL);

	if(pcap) {
		//printf("pcap_set_snaplen %d\n", pcap_set_snaplen(pcap, 65535));
		//printf("pcap_set_promisc %d\n", pcap_set_promisc(pcap, gCapturePromisc));
//		int	pcap_can_set_rfmon(pcap_t *);
//		int	pcap_set_rfmon(pcap_t *, int);
		//printf("pcap_set_timeout %d\n", pcap_set_timeout(pcap, gCaptureTimeout));
//		pcap_set_tstamp_type(pcap_t *, int);
//		pcap_set_immediate_mode(pcap_t *, int);
		//printf("pcap_set_buffer_size %d\n", pcap_set_buffer_size(pcap, gCaptureBuffer));
//		printf("pcap_set_tstamp_precision %d\n", pcap_set_tstamp_precision(pcap, PCAP_TSTAMP_PRECISION_NANO));

		//printf("pcap_activate %d\n", pcap_activate(pcap));
		ret = pcap_set_snaplen(pcap, 102400);
		if (ret != 0) {
			printf("You have an old version of libpcap:%s\n", pcap_statustostr(ret));
			return NULL;
		}
		
		ret = pcap_set_promisc(pcap, 1);
		if (ret != 0) {
			printf("You have an old version of libpcap\n");
			return NULL;
		}
		
		ret = pcap_set_timeout(pcap, 0);
		if (ret != 0) {
			printf("You have an old version of libpcap\n");
			return NULL;
		}
		
		/* set capture buffer size to 16 MB */
		ret = pcap_set_buffer_size(pcap, (1<<24));
		if (ret != 0) {
			printf("You have an old version of libpcap\n");
			return NULL;
		}
		
		ret = pcap_activate(pcap);
		if (ret != 0) {
			printf("pcap_activate failed '%s'\n", pcap_geterr(pcap));
			return NULL;
		}


//		pcap_set_snaplen(pcap, 65535);
//		pcap_set_promisc(pcap, gCapturePromisc);
//		pcap_set_timeout(pcap, gCaptureTimeout);
//		pcap_set_buffer_size(pcap, gCaptureBuffer);
//		pcap_activate(pcap);

//		unsigned int net, mask;
//		printf("pcap_lookupnet: %d\n", pcap_lookupnet(device, &net, &mask, errBuf));
//		struct bpf_program filter;
//		printf("pcap_compile: %d\n", pcap_compile(pcap, &filter, "host 192.168.3.129", 0, mask));
//		printf("pcap_setfilter: %d\n", pcap_setfilter(pcap, &filter));
	} else {
		printf("error: pcap_create(): fail\n");
		return NULL;
	}
#endif

	return pcap;
}

PCaptureContext createContext(pcap_t * pcap, void * data) {
	PCaptureContext context = (PCaptureContext) takeBuffer(sizeof(*context));
	bzero(context, sizeof(*context));
	context->pcap = pcap;
	context->data = data;
	return context;
}

int destroyContext(PCaptureContext context) {
	if (!context) return SODERO_SUCCESS;

	if (context->pcap)
		pcap_close(context->pcap);

	freeBuffer(context);

	return SODERO_SUCCESS;
}

PEtherPacket takePacket(PCaptureContext context, PCaptureHeader header) {
	return (PEtherPacket) pcap_next(context->pcap, header);
}

int loopDevice(PCaptureContext capture, TSoderoCaptureHandler handler) {
	if (!capture)
		return SODERO_FAILURE;
	if (!handler)
		return SODERO_FAILURE;

#ifdef __USE_USER_LOOP__
	unsigned long long result = 0;
	TCaptureHeader header;
	PSummaryContext summary = capture->data;
	while(capture->running) {
		PEtherPacket packet = takePacket(capture, &header);

		int result = handler(summary, packet, &header);

		if (result < 0)
			return SODERO_ERROR;
		if (capture->running)
			capture->running--;
	}
	return SODERO_SUCCESS;
#else
	return pcap_loop(capture->pcap, -1, (pcap_handler) handler, (u_char *) capture->data);
#endif
}

void stopDevice(PCaptureContext capture) {
#ifdef __USE_USER_LOOP__
	do {} while(__sync_bool_compare_and_swap(&capture->running, capture->running, 0));
#else
	pcap_breakloop(capture->pcap);
#endif
}
