#include <rpc/rpc.h>
#include "interface.h"

#ifdef __linux__
#define xdr_u_int64_t xdr_uint64_t
#define xdr_u_int32_t xdr_uint32_t
#endif


bool_t xdr_TSoderoClientRegisterMsg(XDR *xdrs, TSoderoClientRegisterMsg *objp) {
	if (!xdr_vector(xdrs, (char *) objp->vrsn, 4, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->times))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->mac, 6, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->name, 255, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	return TRUE;
}

bool_t xdr_PSoderoClientRegisterMsg(XDR *xdrs, PSoderoClientRegisterMsg *objp) {
	if (!xdr_pointer(xdrs, (char **) objp, sizeof(TSoderoClientRegisterMsg),
			(xdrproc_t) xdr_TSoderoClientRegisterMsg))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoNodeMsg(XDR *xdrs, TSoderoNodeMsg *objp) {
	if (!xdr_vector(xdrs, (char *) objp->mac, 6, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->vlan))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->name, 255, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoSessionType(XDR *xdrs, TSoderoSessionType *objp) {
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoICMPType(XDR *xdrs, TSoderoICMPType *objp) {
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoMySQLType(XDR *xdrs, TSoderoMySQLType *objp) {
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoSessionEventType(XDR *xdrs, TSoderoSessionEventType *objp) {
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoL2Type(XDR *xdrs, TSoderoL2Type *objp) {
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoL3Type(XDR *xdrs, TSoderoL3Type *objp) {
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoFLOWSessionHead(XDR *xdrs, TSoderoFLOWSessionHead *objp) {
	if (!xdr_u_int64_t(xdrs, &objp->flow_sessin_id))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->age))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->client_mac, 6, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->client_ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->client_port))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->server_mac, 6, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->server_ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->server_port))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->identify))
		return FALSE;
	if (!xdr_TSoderoL2Type(xdrs, &objp->l2_type))
		return FALSE;
	if (!xdr_TSoderoL3Type(xdrs, &objp->l3_type))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->vlan))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->connect_time))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoFLOWSessionBody(XDR *xdrs, TSoderoFLOWSessionBody *objp) {
	if (!xdr_u_int64_t(xdrs, &objp->flow_sessin_id))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->expired))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->app))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->major))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->minor))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->client_abort))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->server_abort))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rttValue))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->rttCount))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->droppedBytes))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->droppedCount))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->reorderedBytes))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->reorderedCount))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->retransmitBytes))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->retransmitCount))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->streamBytes))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->missedBytes))
		return FALSE;

	if (!xdr_u_int64_t(xdrs, &objp->client_bytes))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->client_pkts))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->client_l2_bytes))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->client_rtos))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->client_zwnds))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->client_nagle_delays))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->client_rcv_wnd_throttles))
		return FALSE;

	if (!xdr_u_int64_t(xdrs, &objp->server_bytes))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->server_pkts))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->server_l2_bytes))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->server_rtos))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->server_zwnds))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->server_nagle_delays))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->server_rcv_wnd_throttles))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->turns))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->turns_sum_time))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->turns_min_time))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->turns_max_time))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->turns_sum_interval))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->turns_min_interval))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->turns_max_interval))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->turns_sum_bytes))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->turns_min_bytes))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->turns_max_bytes))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoHTTPSessionHead(XDR *xdrs, TSoderoHTTPSessionHead *objp) {
	if (!xdr_u_int64_t(xdrs, &objp->http_session_id))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->flow_session_id))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->method, 12, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->url.url_val,
			(u_int *) &objp->url.url_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->host.host_val,
			(u_int *) &objp->host.host_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->user_agent.user_agent_val,
			(u_int *) &objp->user_agent.user_agent_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->referer.referer_val,
			(u_int *) &objp->referer.referer_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->origin.origin_val,
			(u_int *) &objp->origin.origin_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->cookies.cookies_val,
			(u_int *) &objp->cookies.cookies_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->req_sample.req_sample_val,
			(u_int *) &objp->req_sample.req_sample_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoHTTPSessionBody(XDR *xdrs, TSoderoHTTPSessionBody *objp) {
	if (!xdr_u_int64_t(xdrs, &objp->http_session_id))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->title.title_val,
			(u_int *) &objp->title.title_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->content_type.content_type_val,
			(u_int *) &objp->content_type.content_type_len, ~0,
			sizeof(u_char), (xdrproc_t) xdr_u_char))
		return FALSE;

	if (!xdr_u_int32_t(xdrs, &objp->dns_time))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->req_time))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->rsp_time))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->wait_time))
		return FALSE;

	if (!xdr_u_int64_t(xdrs, &objp->req_bytes))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->req_pkts))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->req_l2_bytes))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->req_rtos))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rsp_bytes))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rsp_pkts))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rsp_l2_bytes))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->rso_rtos))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rttValue))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->rttCount))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->status_code))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->pipelined))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->req_aborted))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->rsp_aborted))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->rsp_chunked))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->rsp_compressed))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->rsp_version, 12, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoDNSAnswer(XDR *xdrs, TSoderoDNSAnswer *objp) {
	if (!xdr_array(xdrs, (char **) &objp->name.name_val,
			(u_int *) &objp->name.name_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->type.type_val,
			(u_int *) &objp->type.type_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->data.data_val,
			(u_int *) &objp->data.data_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->ttl))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoDNSMsg(XDR *xdrs, TSoderoDNSSessionMsg *objp) {
	if (!xdr_u_int64_t(xdrs, &objp->dns_session_id))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->flow_session_id))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->qname.qname_val,
			(u_int *) &objp->qname.qname_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->qtype.qtype_val,
			(u_int *) &objp->qtype.qtype_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->opcode))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->error.error_val,
			(u_int *) &objp->error.error_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->answers.answers_val,
			(u_int *) &objp->answers.answers_len, ~0, sizeof(TSoderoDNSAnswer),
			(xdrproc_t) xdr_TSoderoDNSAnswer))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->wait_time))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->req_timeout))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->rsp_truncated))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->authoritative))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->req_bytes))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->req_pkts))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->req_l2_bytes))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rsp_bytes))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rsp_pkts))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rsp_l2_bytes))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->rtt))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoARPMsg(XDR * xdrs, TSoderoARPThing *objp) {
	if (!xdr_u_int64_t(xdrs, &objp->time))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->code))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->client_mac, 6, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->client_ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->server_mac, 6, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->server_ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoICMPThing(XDR * xdrs, TSoderoICMPThing *objp) {
	if (!xdr_u_int64_t(xdrs, &objp->time))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->client_ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->server_ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->client_port))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->server_port))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->proto))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->code))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoICMPMsg(XDR * xdrs, TSoderoICMPMsg *objp) {
	if (!xdr_u_int64_t(xdrs, &objp->id))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->client_ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->server_ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->reqTime))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rspTime))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->identify))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->sequence))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->incoming))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->outgoing))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoMySQLLoginMsg(XDR * xdrs, TSoderoMySQLLoginMsg * objp) {
	if (!xdr_u_int64_t(xdrs, &objp->session_id))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->application_id))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->reqTime))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rspTime))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->user.user_val,
			(u_int *) &objp->user.user_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->database.database_val,
			(u_int *) &objp->database.database_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_char(xdrs, &objp->status))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoMySQLCommandMsg(XDR * xdrs, TSoderoMySQLCommandMsg * objp) {
	if (!xdr_u_int64_t(xdrs, &objp->session_id))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->application_id))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->reqFirst))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->reqLast ))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->reqCount))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->reqBytes))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->rspCount))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->rspBytes))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rspFirst))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->rspLast ))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->row ))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->col))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->set))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoMetricFinishMsg(XDR *xdrs, TSoderoMetricFinishMsg *objp) {
	if (!xdr_u_int32_t(xdrs, &objp->time))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->count))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoServerAcknowledgeMsg(XDR *xdrs,
		TSoderoServerAcknowledgeMsg *objp) {
	if (!xdr_u_int32_t(xdrs, &objp->ack_val))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoTCPSessionContent(XDR *xdrs, TSoderoTCPSessionContent *objp) {
	if (!xdr_TSoderoSessionType(xdrs, &objp->type))
		return FALSE;
	switch (objp->type) {
	case SESSION_TYPE_FLOW_HEAD:
		if (!xdr_TSoderoFLOWSessionHead(xdrs,
				&objp->TSoderoTCPSessionContent_u.flow_head))
			return FALSE;
		break;
	case SESSION_TYPE_FLOW_BODY:
		if (!xdr_TSoderoFLOWSessionBody(xdrs,
				&objp->TSoderoTCPSessionContent_u.flow_body))
			return FALSE;
		break;
	case SESSION_TYPE_HTTP_HEAD:
		if (!xdr_TSoderoHTTPSessionHead(xdrs,
				&objp->TSoderoTCPSessionContent_u.http_head))
			return FALSE;
		break;
	case SESSION_TYPE_HTTP_BODY:
		if (!xdr_TSoderoHTTPSessionBody(xdrs,
				&objp->TSoderoTCPSessionContent_u.http_body))
			return FALSE;
		break;
	case SESSION_TYPE_DNS:
		if (!xdr_TSoderoDNSMsg(xdrs, &objp->TSoderoTCPSessionContent_u.dns))
			return FALSE;
		break;
	case SESSION_TYPE_ARP:
		if (!xdr_TSoderoARPMsg(xdrs, &objp->TSoderoTCPSessionContent_u.arp))
			return FALSE;
		break;
	case SESSION_TYPE_ICMP:
		if (!xdr_TSoderoICMPType(xdrs, &objp->TSoderoTCPSessionContent_u.icmp.type))
			return FALSE;
		switch(objp->TSoderoTCPSessionContent_u.icmp.type) {
			case ICMP_TYPE_EVENT:
				if (!xdr_TSoderoICMPThing(xdrs, &objp->TSoderoTCPSessionContent_u.icmp.thing))
					return FALSE;
				break;
			case ICMP_TYPE_SESSION:
				if (!xdr_TSoderoICMPMsg(xdrs, &objp->TSoderoTCPSessionContent_u.icmp.msg))
					return FALSE;
				break;
			default:
				return FALSE;
		}
		break;
	case SESSION_TYPE_MYSQL:
		if (!xdr_TSoderoMySQLType(xdrs, &objp->TSoderoTCPSessionContent_u.mysql.type))
			return FALSE;
		switch(objp->TSoderoTCPSessionContent_u.mysql.type) {
		case MYSQL_TYPE_LOGIN:
			if (!xdr_TSoderoMySQLLoginMsg(xdrs, &objp->TSoderoTCPSessionContent_u.mysql.login))
				return FALSE;
			break;
		case MYSQL_TYPE_COMMAND:
			if (!xdr_TSoderoMySQLCommandMsg(xdrs, &objp->TSoderoTCPSessionContent_u.mysql.command))
				return FALSE;
			break;
		}
		break;
	default:
		break;
	}
	return TRUE;
}

bool_t xdr_TSoderoSessionMsg(XDR *xdrs, TSoderoSessionMsg *objp) {
	if (!xdr_TSoderoSessionEventType(xdrs, &objp->event))
		return FALSE;
	if (!xdr_TSoderoTCPSessionContent(xdrs, &objp->session_content))
		return FALSE;
	return TRUE;
}

bool_t xdr_TCPReportType(XDR *xdrs, TCPReportType *objp) {
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoTCPReportMsg(XDR *xdrs, TSoderoTCPReportMsg *objp) {
	if (!xdr_TCPReportType(xdrs, &objp->type))
		return FALSE;
	switch (objp->type) {
	case CLIENT_REGISTER:
		if (!xdr_TSoderoClientRegisterMsg(xdrs,
				&objp->TSoderoTCPReportMsg_u.client_register))
			return FALSE;
		break;
	case SODERO_NODES:
		if (!xdr_array(xdrs,
				(char **) &objp->TSoderoTCPReportMsg_u.nodes.nodes_val,
				(u_int *) &objp->TSoderoTCPReportMsg_u.nodes.nodes_len, ~0,
				sizeof(TSoderoNodeMsg), (xdrproc_t) xdr_TSoderoNodeMsg))
			return FALSE;
		break;
	case ORIGIN_NODES:
		if (!xdr_array(xdrs,
				(char **) &objp->TSoderoTCPReportMsg_u.origin_nodes.origin_nodes_val,
				(u_int *) &objp->TSoderoTCPReportMsg_u.origin_nodes.origin_nodes_len,
				~0, sizeof(TSoderoNodeMsg), (xdrproc_t) xdr_TSoderoNodeMsg))
			return FALSE;
		break;
	case SESSION_EVENT:
		if (!xdr_TSoderoSessionMsg(xdrs,
				&objp->TSoderoTCPReportMsg_u.session_event))
			return FALSE;
		break;
	case METRIC_FINISH:
		if (!xdr_TSoderoMetricFinishMsg(xdrs,
				&objp->TSoderoTCPReportMsg_u.metric_finish))
			return FALSE;
		break;
	case SERVER_ACK:
		if (!xdr_TSoderoServerAcknowledgeMsg(xdrs,
				&objp->TSoderoTCPReportMsg_u.server_ack))
			return FALSE;
		break;
	default:
		break;
	}
	return TRUE;
}

bool_t xdr_TSoderoCountMetricMsg(XDR *xdrs, TSoderoCountMetricMsg *objp) {
	if (!xdr_u_int32_t(xdrs, &objp->agent_id))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->mac, 6, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->vlan))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->metrics.metrics_val,
			(u_int *) &objp->metrics.metrics_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->time))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->count))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoPeriodicMetricMsg(XDR *xdrs, TSoderoPeriodicMetricMsg *objp) {
	if (!xdr_u_int32_t(xdrs, &objp->agent_id))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->mac, 6, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_short(xdrs, &objp->vlan))
		return FALSE;
	if (!xdr_vector(xdrs, (char *) objp->ip, 16, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_array(xdrs, (char **) &objp->metrics.metrics_val,
			(u_int *) &objp->metrics.metrics_len, ~0, sizeof(u_char),
			(xdrproc_t) xdr_u_char))
		return FALSE;
	if (!xdr_u_int32_t(xdrs, &objp->time))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->count))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->min))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->max))
		return FALSE;
	if (!xdr_u_int64_t(xdrs, &objp->sum))
		return FALSE;
	return TRUE;
}

bool_t xdr_UDPReportType(XDR *xdrs, UDPReportType *objp) {
	if (!xdr_enum(xdrs, (enum_t *) objp))
		return FALSE;
	return TRUE;
}

bool_t xdr_TSoderoUDPReportMsg(XDR *xdrs, TSoderoUDPReportMsg *objp) {
	if (!xdr_UDPReportType(xdrs, &objp->type))
		return FALSE;
	switch (objp->type) {
	case COUNT_METRIC:
		if (!xdr_TSoderoCountMetricMsg(xdrs,
				&objp->TSoderoUDPReportMsg_u.count_metric))
			return FALSE;
		break;
	case PERIODIC_METRIC:
		if (!xdr_TSoderoPeriodicMetricMsg(xdrs,
				&objp->TSoderoUDPReportMsg_u.periodic_metric))
			return FALSE;
		break;
	default:
		break;
	}
	return TRUE;
}
