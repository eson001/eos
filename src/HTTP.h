/*
 * HTTP.h
 *
 *  Created on: Sep 14, 2014
 *      Author: Clark Dong
 */

#ifndef HTTP_H_
#define HTTP_H_

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "Stream.h"
#include "TCP.h"


#define HTTP_CMD_UNKNOWN                0
#define HTTP_CMD_GET                    1
#define HTTP_CMD_POST                   2
#define HTTP_CMD_PUT                    3
#define HTTP_CMD_SEARCH                 4
#define HTTP_CMD_CONNECT                5
#define HTTP_CMD_HEAD                   6

#define HTTP_CMD_RESPONSE               9

#define HTTP_RETRY                  0
#define HTTP_DONE                   1
#define HTTP_NEXT                   2


#define HTTP_HEAD_MIN_LENGTH            15
#define HTTP_HEAD_MAX_LENGTH          4096
#define HTTP_FIELD_MIN_LENGTH            8
#define HTTP_OFFSET_LOCATION             8
#define HTTP_OFFSET_HOST                 4
#define HTTP_OFFSET_ORIGIN               6
#define HTTP_OFFSET_COOKIE               6
#define HTTP_OFFSET_REF                  7
#define HTTP_OFFSET_UA                  10
#define HTTP_OFFSET_X_HOST              13
#define HTTP_OFFSET_CA                  12
#define HTTP_OFFSET_CONTENT_TYPE        12
#define HTTP_OFFSET_CONTENT_LENGTH      15
#define HTTP_OFFSET_CONTENT_ENCODING    16
#define HTTP_OFFSET_TRANSFER_ENCODING   17



struct SODERO_APPLICATION_HTTP;
typedef struct SODERO_APPLICATION_HTTP TSoderoApplicationHTTP, * PSoderoApplicationHTTP;

enum {
	HTTP_STEP_NONE,
	HTTP_STEP_HEAD,
	HTTP_STEP_BODY,
	HTTP_STEP_DONE,
};

enum {
	HTTP_STATUE_REQ,
	HTTP_STATUE_REQ_ACK,
	HTTP_STATUE_RES,
	HTTP_STATUE_RES_ACK,
};


#pragma pack(push, 1)

typedef struct HTTP_DETECT_REQUEST {
	unsigned char method;
	unsigned char version;
	unsigned char url [4090];
	unsigned char pending[4];
} THTTPDetectRequest, * PHTTPDetectRequest;

typedef struct HTTP_DETECT_RESPONSE {
	unsigned short code;
	unsigned char version;
} THTTPDetectResponse, * PHTTPDetectResponse;

typedef struct SODERO_HTTP_DATUM {
	TSoderoFlowDatum   value;
	unsigned int       count;
	unsigned long long rttValue;
	unsigned int       rttCount;
	unsigned int       l2;
	unsigned int       method;
	unsigned int       error;
} TSoderoHTTPDatum, * PSoderoHTTPDatum;

typedef struct SODERO_HTTP_VALUE {
	TSoderoFlowDatum   value;
	unsigned int       count;	//	method or error
	unsigned int       action;	//	request or response
	unsigned long long rttValue;
	unsigned int       rttCount;
	unsigned int       l2;
	unsigned int       x10;
	unsigned int       x20;
	unsigned int       x30;
	unsigned int       x40;
	unsigned int       x50;

	TSoderoUnitDatum request,response,wait;
//	unsigned int       method;
//	unsigned int       error;
//	TSoderoHTTPDatum request, response;
//	TSoderoUnitDatum duration;
} TSoderoHTTPValue, * PSoderoHTTPValue;

struct SODERO_APPLICATION_HTTP {
	char *                 data;
	PSoderoTCPSession     owner;
	PSoderoApplicationHTTP link;
	unsigned long long id;		//	session id
//	unsigned char      flag;
	unsigned long long serial;

	unsigned long long req_b;
	unsigned long long req_e;
	unsigned long long rsp_b;
	unsigned long long rsp_e;

	unsigned char req_step;
	unsigned char rsp_step;

	unsigned short status_code: 12;
	unsigned char  method_code:  4;

	unsigned char req_multipart;
	unsigned char rsp_chunked;	//	If the response is chunked
	unsigned char req_version;
	unsigned char rsp_version;	//	Response http version
	unsigned char req_aborted;	//	If the connection was closed when sending request
	unsigned char rsp_aborted;	//	If the connection was closed when receiving response
	unsigned char req_compressed;	//	If the response is compressed
	unsigned char rsp_compressed;	//	If the response is compressed

//	unsigned short dns_time;	//	dns lookup time(ms)

	unsigned int age_time;	//	Time elapsed since first byte of the request
	unsigned int req_time;	//	Time for sending request(ms)
	unsigned int rsp_time;	//	Time for receiving response(ms)
	unsigned int wait_time;	//	Time for waiting server(ms)

	TSoderoUnitDatum request,response,wait;

	//	pair
	char * req_content_type;
	char * rsp_content_type;
	char * req_content_length;
	char * rsp_content_length;
	char * req_cookies;
	char * rsp_cookies;
	char * transfer_encoding;
	char * content_encoding;

	//	request
	char * host;
	char * url;
	char * ua;
	char * referer;
	char * x_online_host;

	//	response
	char * server;	//	Server
	char * date;	//	Date
	char * expires;	//	Expires
//	char * title;
	char * origin;	//	X-Forwarded-For or true-client-ip
//
//	char * req_sample;	//	N first bytes of HTTP request payload
//	char * rsp_sample;	//	N first bytes of HTTP response payload

	unsigned long long req_bytes;
	unsigned int req_pkts;
	unsigned long long req_l2_bytes;
	unsigned long long rsp_bytes;
	unsigned int rsp_pkts;
	unsigned long long rsp_l2_bytes;

	unsigned long long reqRTTValue;
	unsigned int       reqRTTCount;
	unsigned long long rspRTTValue;
	unsigned int       rspRTTCount;

	char *   multipart;
	PSundayData sunday;

	long long req_size;
	long long rsp_size;
	long long req_fill;
	long long rsp_fill;

	unsigned char pipelined;	//	If the request is pipelined
	int status;
};

#pragma pack(pop)

extern const char * nameOfHTTPMethod (unsigned char method);

extern PSoderoApplicationHTTP getHTTPSession(PSoderoTCPSession session, PHTTPDetectRequest detect);

extern int checkHTTPRequestTitle(PSoderoTCPSession session, PSoderoTCPValue value,
	int base, const unsigned char * data, int size, int length,
	int dir, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether);
extern int checkHTTPResponseTitle(PSoderoTCPSession session, PSoderoTCPValue value,
	int base, const unsigned char * data, int size,
	int dir, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether);

extern void updateHTTPState(PSoderoTCPSession session, int dir, PTCPState state);
extern int processHTTPPacket(PSoderoTCPSession session, int dir, PSoderoTCPValue value,
	unsigned int base, const unsigned char * data, unsigned int size, unsigned int length,
	PTCPState state, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether);

extern int detectHTTP(PSoderoTCPSession session, PSoderoTCPValue value,
	unsigned int base, const unsigned char * data, unsigned int size, int length, int dir,
	PTCPHeader tcp, PIPHeader ip, PEtherHeader ether);

extern int skipHTTPPacket(PSoderoTCPSession session, int dir, unsigned int size);

#endif /* HTTP_H_ */
