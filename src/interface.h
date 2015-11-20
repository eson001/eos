/*
 * Interface.h
 *
 *  Created on: Aug 24, 2014
 *      Author: Clark Dong
 */

#ifndef INTERFACE_H_
#define INTERFACE_H_

#include <rpc/rpc.h>

#ifdef __cplusplus
extern "C" {
#endif

struct TSoderoClientRegisterMsg {
	u_char vrsn[4];
	u_int times;
	u_char mac[6];
	u_char ip[16];
	u_char name[255];
};
typedef struct TSoderoClientRegisterMsg TSoderoClientRegisterMsg;

typedef TSoderoClientRegisterMsg *PSoderoClientRegisterMsg;

struct TSoderoNodeMsg {
	u_char mac[6];
	u_short vlan;
	u_char ip[16];
	u_char name[255];
};
typedef struct TSoderoNodeMsg TSoderoNodeMsg;

enum TSoderoSessionType {
	SESSION_TYPE_FLOW_HEAD = 0,
	SESSION_TYPE_FLOW_BODY = 1,
	SESSION_TYPE_HTTP_HEAD = 101,
	SESSION_TYPE_HTTP_BODY = 102,
	SESSION_TYPE_DNS = 201,
	SESSION_TYPE_ARP = 202,
	SESSION_TYPE_ICMP = 203,
	SESSION_TYPE_MYSQL = 204,
	SESSION_TYPE_ORACLE = 205,
};
typedef enum TSoderoSessionType TSoderoSessionType;

enum TSoderoSessionEventType {
	EVENT_TYPE_FLOW_TICK = 0,
	EVENT_TYPE_TCP_OPEN = 101,
	EVENT_TYPE_TCP_CLOSE = 102,
	EVENT_TYPE_UDP_OPEN = 201,
	EVENT_TYPE_UDP_CLOSE = 202,
	EVENT_TYPE_HTTP_REQUEST = 301,
	EVENT_TYPE_HTTP_RESPONSE = 302,
	EVENT_TYPE_DNS = 401,
//	EVENT_TYPE_DB_REQUEST = 501,
//	EVENT_TYPE_DB_RESPONSE = 502,
	EVENT_TYPE_DB_MYSQL = 511,
	EVENT_TYPE_DB_ORACLE= 512,
	EVENT_TYPE_ARP = 601,
	EVENT_TYPE_ICMP = 701,
};
typedef enum TSoderoSessionEventType TSoderoSessionEventType;

enum TSoderoL2Type {
	L2_TYPE_IPV4 = 0, L2_TYPE_IPV6 = 1,
};
typedef enum TSoderoL2Type TSoderoL2Type;

enum TSoderoL3Type {
	L3_TYPE_ICMP = 1, L3_TYPE_TCP = 6, L3_TYPE_UDP = 17,
};
typedef enum TSoderoL3Type TSoderoL3Type;

struct TSoderoFLOWSessionHead {
	u_int64_t flow_sessin_id;
	u_int age;
	u_char client_mac[6];
	u_char client_ip[16];
	u_short client_port;
	u_char server_mac[6];
	u_char server_ip[16];
	u_short server_port;
	u_int identify;
	TSoderoL2Type l2_type;
	TSoderoL3Type l3_type;
	u_short vlan;
	u_int connect_time;
};
typedef struct TSoderoFLOWSessionHead TSoderoFLOWSessionHead;

struct TSoderoFLOWSessionBody {
	u_int64_t flow_sessin_id;
	u_char flag;
	u_char app;
	u_short major;
	u_short minor;
	u_char expired;
	u_char client_abort;
	u_char server_abort;
	u_int64_t rttValue;		//	in us
	u_int  rttCount;
	u_int  droppedCount;
	u_int64_t droppedBytes;
	u_int  reorderedCount;
	u_int64_t reorderedBytes;
	u_int  retransmitCount;
	u_int64_t retransmitBytes;
	u_int64_t streamBytes;
	u_int  missedBytes;
	u_int64_t client_bytes;
	u_int64_t client_pkts;
	u_int64_t client_l2_bytes;
	u_int client_rtos;
	u_int client_zwnds;
	u_int client_nagle_delays;
	u_int client_rcv_wnd_throttles;
	u_int64_t server_bytes;
	u_int64_t server_pkts;
	u_int64_t server_l2_bytes;
	u_int server_rtos;
	u_int server_zwnds;
	u_int server_nagle_delays;
	u_int server_rcv_wnd_throttles;
	u_int turns;
	u_int turns_sum_time;
	u_int turns_min_time;
	u_int turns_max_time;
	u_int turns_sum_interval;
	u_int turns_min_interval;
	u_int turns_max_interval;
	u_int64_t turns_sum_bytes;
	u_int64_t turns_min_bytes;
	u_int64_t turns_max_bytes;
};
typedef struct TSoderoFLOWSessionBody TSoderoFLOWSessionBody;

struct TSoderoHTTPSessionHead {
	u_int64_t http_session_id;
	u_int64_t flow_session_id;
	u_char method[12];
	struct {
		u_int url_len;
		u_char *url_val;
	} url;
	struct {
		u_int host_len;
		u_char *host_val;
	} host;
	struct {
		u_int user_agent_len;
		u_char *user_agent_val;
	} user_agent;
	struct {
		u_int referer_len;
		u_char *referer_val;
	} referer;
	struct {
		u_int origin_len;
		u_char *origin_val;
	} origin;
	struct {
		u_int cookies_len;
		u_char *cookies_val;
	} cookies;
	struct {
		u_int req_sample_len;
		u_char *req_sample_val;
	} req_sample;
};
typedef struct TSoderoHTTPSessionHead TSoderoHTTPSessionHead;

struct TSoderoHTTPSessionBody {
	u_int64_t http_session_id;
	struct {
		u_int title_len;
		u_char *title_val;
	} title;
	struct {
		u_int content_type_len;
		u_char *content_type_val;
	} content_type;
	u_int dns_time;
	u_int req_time;
	u_int rsp_time;
	u_int wait_time;
	#if 0
	u_int req_time_min;
	u_int rsp_time_min;
	u_int wait_time_min;
	u_int req_time_max;
	u_int rsp_time_max;
	u_int wait_time_max;
	#endif
	u_int64_t req_bytes;
	u_int64_t req_pkts;
	u_int64_t req_l2_bytes;
	u_int req_rtos;
	u_int64_t rsp_bytes;
	u_int64_t rsp_pkts;
	u_int64_t rsp_l2_bytes;
	u_int rso_rtos;
	u_int64_t rttValue;
	u_int rttCount;
	u_int status_code;
	u_char pipelined;
	u_char req_aborted;
	u_char rsp_aborted;
	u_char rsp_chunked;
	u_char rsp_compressed;
	u_char rsp_version[12];
};
typedef struct TSoderoHTTPSessionBody TSoderoHTTPSessionBody;

struct TSoderoDNSAnswer {
	struct {
		u_int name_len;
		u_char *name_val;
	} name;
	struct {
		u_int type_len;
		u_char *type_val;
	} type;
	struct {
		u_int data_len;
		u_char *data_val;
	} data;
	u_int ttl;
};
typedef struct TSoderoDNSAnswer TSoderoDNSAnswer;

struct TSoderoDNSMsg {
	u_int64_t dns_session_id;
	u_int64_t flow_session_id;
	struct {
		u_int qname_len;
		u_char *qname_val;
	} qname;
	struct {
		u_int qtype_len;
		u_char *qtype_val;
	} qtype;
	u_int opcode;
	struct {
		u_int error_len;
		u_char *error_val;
	} error;
	struct {
		u_int answers_len;
		TSoderoDNSAnswer *answers_val;
	} answers;
	u_int wait_time;
	u_char req_timeout;
	u_char rsp_truncated;
	u_char authoritative;
	u_int64_t req_bytes;
	u_int64_t req_pkts;
	u_int64_t req_l2_bytes;
	u_int64_t rsp_bytes;
	u_int64_t rsp_pkts;
	u_int64_t rsp_l2_bytes;
	u_int rtt;
};
typedef struct TSoderoDNSMsg TSoderoDNSSessionMsg;

struct TSoderoARPThing {
	u_int64_t time;
	u_short code;
	u_char client_mac[6];
	u_char client_ip[16];
	u_char server_mac[6];
	u_char server_ip[16];
};
typedef struct TSoderoARPThing TSoderoARPThing;

;
enum TSoderoICMPType {
	ICMP_TYPE_EVENT, ICMP_TYPE_SESSION,
};
typedef enum TSoderoICMPType TSoderoICMPType;

struct TSoderoICMPThing {
	u_int64_t time;
	u_char client_ip[16];
	u_char server_ip[16];
	u_short client_port;
	u_short server_port;
	u_char proto;
	u_char code;
};
typedef struct TSoderoICMPThing TSoderoICMPThing;

struct TSoderoICMPMsg {
	u_int64_t id;
	u_char client_ip[16];
	u_char server_ip[16];
	u_int64_t reqTime;
	u_int64_t rspTime;
	u_short identify;
	u_short sequence;
	u_short incoming;
	u_short outgoing;
};
typedef struct TSoderoICMPMsg TSoderoICMPMsg;

enum TSoderoMySQLType {
	MYSQL_TYPE_LOGIN, MYSQL_TYPE_COMMAND,
};
typedef enum TSoderoMySQLType TSoderoMySQLType;

struct TSoderoMySQLLoginMsg {
	u_int64_t session_id;
	u_int64_t application_id;
	u_int64_t reqTime;
	u_int64_t rspTime;
	struct {
		u_int user_len;
		u_char *user_val;
	} user;
	struct {
		u_int database_len;
		u_char *database_val;
	} database;
	u_char status;
};
typedef struct TSoderoMySQLLoginMsg TSoderoMySQLLoginMsg;

struct TSoderoMySQLCommandMsg {
	u_int64_t session_id;
	u_int64_t application_id;
	u_int64_t reqFirst;
	u_int64_t reqLast ;
	u_int  reqCount;		//	Block count
	u_int  reqBytes;		//	Total bytes
	u_int  rspCount;		//	Block count
	u_int  rspBytes;		//	Total bytes
	u_int64_t rspFirst;
	u_int64_t rspLast ;
	u_int64_t row;		//	total row count of result set;
	u_int  col;		//	total col of result set;
	u_int  set;		//	total result set count of command's reponse
};
typedef struct TSoderoMySQLCommandMsg TSoderoMySQLCommandMsg;

/*
enum TSoderoTnsType {
	TNS_TYPE_LOGIN, TNS_TYPE_COMMAND,
};
typedef enum TSoderoTnsType TSoderoTnsType;
*/

enum TSoderoOracleMethod {
	ORACLE_METHOD_LOGIN, ORACLE_METHOD_SQL, ORACLE_METHOD_PROCEDURE,
};
typedef enum TSoderoOracleMethod TSoderoOracleMethod;

/*
struct TSoderoTnsLoginMsg {
	u_int64_t session_id;
	u_int64_t application_id;
	u_int64_t reqTime;
	u_int64_t rspTime;
	struct {
		u_int user_len;
		u_char *user_val;
	} user;
	struct {
		u_int database_len;
		u_char *database_val;
	} database;
	u_char status;
};
typedef struct TSoderoTnsLoginMsg TSoderoTnsLoginMsg;

struct TSoderoTnsCommandMsg {
	u_int64_t session_id;
	u_int64_t application_id;
	u_int64_t reqFirst;
	u_int64_t reqLast ;
	u_int  reqCount;		//	Block count
	u_int  reqBytes;		//	Total bytes
	u_int  rspCount;		//	Block count
	u_int  rspBytes;		//	Total bytes
	u_int64_t rspFirst;
	u_int64_t rspLast ;
	u_int64_t row;		//	total row count of result set;
	u_int  col;		//	total col of result set;
	u_int  set;		//	total result set count of command's reponse
};
typedef struct TSoderoTnsCommandMsg TSoderoTnsCommandMsg;
*/

struct TSoderoOracleMsg {
	u_int64_t session_id;	//	Oracle 的会话ID
	u_int64_t flow_id;	//	对应的TCP连接的flow id
	TSoderoOracleMethod method;	//	登陆或者SQL活着Proc存储过程
	struct {
		u_int user_len;
		u_char *user_val;
	} user;				//	Oracle用户名
	struct {
		u_int database_len;
		u_char *database_val;	//	Oracle数据库名
	} database;
	struct {
		u_int statement_len;
		u_char *statement_val;	//	SQL语句或存储过程名称
	} statement;
	struct {
		u_int error_code_len;
		u_char *error_code_val;	//	错误码
	} error_code;
	struct {
		u_int error_msg_len;
		u_char *error_msg_val;	//	错误信息
	} error_msg;

	u_int  req_time;		//	请求的时间
	u_int  rsp_time;		//	返回的时间
	u_int  wait_time;		//	等待的时间

	u_int64_t req_bytes ;
	u_int64_t req_pkts ;
	u_int64_t reqLast ;
	u_int64_t req_l2_bytes ;
	u_int64_t rsp_bytes ;
	u_int64_t rsp_pkts ;
	u_int64_t rsp_l2_bytes ;
	u_int64_t rsp_records ;	//	返回的记录数
	u_int64_t rsp_fields ;	//	返回的字段数
	u_int64_t rsp_datasets ;//	返回的数据集数
	u_char client_abort;	//	是否客户端终止
	u_char server_abort;	//	是否服务端终止

};
typedef struct TSoderoOracleMsg TSoderoOracleMsg;


struct TSoderoMetricFinishMsg {
	u_int time;
	u_int count;
};
typedef struct TSoderoMetricFinishMsg TSoderoMetricFinishMsg;

struct TSoderoServerAcknowledgeMsg {
	u_int ack_val;
};
typedef struct TSoderoServerAcknowledgeMsg TSoderoServerAcknowledgeMsg;

struct TSoderoTCPSessionContent {
	TSoderoSessionType type;
	union {
		TSoderoFLOWSessionHead flow_head;
		TSoderoFLOWSessionBody flow_body;
		TSoderoHTTPSessionHead http_head;
		TSoderoHTTPSessionBody http_body;
		TSoderoDNSSessionMsg dns;
		TSoderoARPThing arp;
		struct {
			TSoderoICMPType  type;
			union {
				TSoderoICMPThing thing;
				TSoderoICMPMsg   msg;
			};
		} icmp;
		struct {
			TSoderoMySQLType type;
			union {
				TSoderoMySQLLoginMsg   login;
				TSoderoMySQLCommandMsg command;
			};
		} mysql;
		struct {
			TSoderoOracleMethod type;
			TSoderoOracleMsg oracle_msg;
		} tns;
		
	} TSoderoTCPSessionContent_u;
};
typedef struct TSoderoTCPSessionContent TSoderoTCPSessionContent;

struct TSoderoSessionMsg {
	TSoderoSessionEventType event;
	TSoderoTCPSessionContent session_content;
};
typedef struct TSoderoSessionMsg TSoderoSessionMsg;

enum TCPReportType {
	CLIENT_REGISTER = 0,
	SODERO_NODES = 1,
	ORIGIN_NODES = 2,
	METRIC_FINISH = 3,
	SESSION_EVENT = 4,
	SERVER_ACK = 200,
};
typedef enum TCPReportType TCPReportType;

struct TSoderoTCPReportMsg {
	TCPReportType type;
	union {
		TSoderoClientRegisterMsg client_register;
		struct {
			u_int nodes_len;
			TSoderoNodeMsg *nodes_val;
		} nodes;
		struct {
			u_int origin_nodes_len;
			TSoderoNodeMsg *origin_nodes_val;
		} origin_nodes;
		TSoderoSessionMsg session_event;
		TSoderoMetricFinishMsg metric_finish;
		TSoderoServerAcknowledgeMsg server_ack;
	} TSoderoTCPReportMsg_u;
};
typedef struct TSoderoTCPReportMsg TSoderoTCPReportMsg;

#define MSG_NUM 50000
#define MSG_SIZE 32 * 1024ULL
struct TSoderoShmMsg {
    unsigned int head;
    unsigned int tail;
    unsigned long long write_count;
    unsigned long long read_count;
    char report_msg[MSG_NUM][MSG_SIZE];
};
typedef struct TSoderoShmMsg TSoderoShmMsg;

struct TSoderoCountMetricMsg {
	u_int agent_id;
	u_char mac[6];
	u_short vlan;
	u_char ip[16];
	struct {
		u_int metrics_len;
		u_char *metrics_val;
	} metrics;
	u_int time;
	u_int64_t count;
};
typedef struct TSoderoCountMetricMsg TSoderoCountMetricMsg;

struct TSoderoPeriodicMetricMsg {
	u_int agent_id;
	u_char mac[6];
	u_short vlan;
	u_char ip[16];
	struct {
		u_int metrics_len;
		u_char *metrics_val;
	} metrics;
	u_int time;
	u_int64_t count;
	u_int64_t min;
	u_int64_t max;
	u_int64_t sum;
};
typedef struct TSoderoPeriodicMetricMsg TSoderoPeriodicMetricMsg;

enum UDPReportType {
	COUNT_METRIC = 100, PERIODIC_METRIC = 101,
};
typedef enum UDPReportType UDPReportType;

struct TSoderoUDPReportMsg {
	UDPReportType type;
	union {
		TSoderoCountMetricMsg count_metric;
		TSoderoPeriodicMetricMsg periodic_metric;
	} TSoderoUDPReportMsg_u;
};
typedef struct TSoderoUDPReportMsg TSoderoUDPReportMsg;

/* the xdr functions */

extern bool_t xdr_TSoderoClientRegisterMsg(XDR *, TSoderoClientRegisterMsg*);
extern bool_t xdr_PSoderoClientRegisterMsg(XDR *, PSoderoClientRegisterMsg*);
extern bool_t xdr_TSoderoNodeMsg(XDR *, TSoderoNodeMsg*);
extern bool_t xdr_TSoderoSessionType(XDR *, TSoderoSessionType*);
extern bool_t xdr_TSoderoICMPType(XDR *, TSoderoICMPType*);
extern bool_t xdr_TSoderoMySQLType(XDR *, TSoderoMySQLType*);
extern bool_t xdr_TSoderoSessionEventType(XDR *, TSoderoSessionEventType*);
extern bool_t xdr_TSoderoL2Type(XDR *, TSoderoL2Type*);
extern bool_t xdr_TSoderoL3Type(XDR *, TSoderoL3Type*);
extern bool_t xdr_TSoderoFLOWSessionHead(XDR *, TSoderoFLOWSessionHead*);
extern bool_t xdr_TSoderoFLOWSessionBody(XDR *, TSoderoFLOWSessionBody*);
extern bool_t xdr_TSoderoHTTPSessionHead(XDR *, TSoderoHTTPSessionHead*);
extern bool_t xdr_TSoderoHTTPSessionBody(XDR *, TSoderoHTTPSessionBody*);
extern bool_t xdr_TSoderoDNSAnswer(XDR *, TSoderoDNSAnswer*);
extern bool_t xdr_TSoderoDNSMsg(XDR *, TSoderoDNSSessionMsg*);
extern bool_t xdr_TSoderoARPMsg(XDR *, TSoderoARPThing*);
extern bool_t xdr_TSoderoICMPThing(XDR * xdrs, TSoderoICMPThing *objp);
extern bool_t xdr_TSoderoICMPMsg(XDR *, TSoderoICMPMsg*);
extern bool_t xdr_TSoderoMySQLLoginMsg(XDR *, TSoderoMySQLLoginMsg*);
extern bool_t xdr_TSoderoMySQLCommandMsg(XDR *, TSoderoMySQLCommandMsg*);
extern bool_t xdr_TSoderoMetricFinishMsg(XDR *, TSoderoMetricFinishMsg*);
extern bool_t xdr_TSoderoServerAcknowledgeMsg(XDR *, TSoderoServerAcknowledgeMsg*);
extern bool_t xdr_TSoderoTCPSessionContent(XDR *, TSoderoTCPSessionContent*);
extern bool_t xdr_TSoderoSessionMsg(XDR *, TSoderoSessionMsg*);
extern bool_t xdr_TCPReportType(XDR *, TCPReportType*);
extern bool_t xdr_TSoderoTCPReportMsg(XDR *, TSoderoTCPReportMsg*);
extern bool_t xdr_TSoderoCountMetricMsg(XDR *, TSoderoCountMetricMsg*);
extern bool_t xdr_TSoderoPeriodicMetricMsg(XDR *, TSoderoPeriodicMetricMsg*);
extern bool_t xdr_UDPReportType(XDR *, UDPReportType*);
extern bool_t xdr_TSoderoUDPReportMsg(XDR *, TSoderoUDPReportMsg*);
extern bool_t xdr_TSoderoOracleMethod(XDR *, TSoderoOracleMethod*);
extern bool_t xdr_TSoderoOracleMsg(XDR *, TSoderoOracleMsg*);

#ifdef __cplusplus
}
#endif

#endif /* INTERFACE_H_ */
