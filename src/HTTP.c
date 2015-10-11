/*
 * HTTP.c
 *
 *  Created on: Sep 14, 2014
 *      Author: Clark Dong
 */

#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Core.h"
#include "Logic.h"
#include "Ether.h"
#include "IP.h"
#include "Stream.h"
#include "TCP.h"
#include "HTTP.h"

int methodOfRequest(unsigned long long value) {
	if ((value & 0x00000000FFFFFFFFULL) == 0x0000000000544547ULL) return HTTP_CMD_GET     ;
	if ((value & 0x000000FFFFFFFFFFULL) == 0x0000000054534F50ULL) return HTTP_CMD_POST    ;
	if ((value & 0x00FFFFFFFFFFFFFFULL) == 0x0000484352414553ULL) return HTTP_CMD_SEARCH  ;
	if ( value                          == 0x005443454e4e4f43ULL) return HTTP_CMD_CONNECT ;
	if ((value & 0x000000FFFFFFFFFFULL) == 0x0000000044414548ULL) return HTTP_CMD_HEAD    ;
	if ((value & 0x00000000FFFFFFFFULL) == 0x0000000000545550ULL) return HTTP_CMD_PUT     ;
	return HTTP_CMD_UNKNOWN;
}

int methodOfResponse(unsigned long long value) {
	if ((value & 0xFEFFFFFFFFFFFFFFULL) == 0x100e110f50545448ULL) return HTTP_CMD_RESPONSE;
	return HTTP_CMD_UNKNOWN;
}

const char * nameOfHTTPMethod (unsigned char method) {
	const char * names[] = {"REQUEST", "GET", "POST", "PUT", "SEARCH", "CONNECT", "HEAD", "INVALID"};
	return method < 0x08 ? names[method] : nullptr;
}

int str2method(const void * method) {

	if (method) {
		union {
			char str[9];
			unsigned long long value;
		} a;
		a.value = 0;
		strncpy(a.str, method, 8);
		return methodOfRequest(a.value & 0xDFDFDFDFDFDFDFDF);
	}

	return HTTP_CMD_UNKNOWN;
}

int methodSize(unsigned int method) {

	int METHOD_SIZES[] = {
		0,	//	HTTP_CMD_UNKNOWN
		4,	//	HTTP_CMD_GET
		5,	//	HTTP_CMD_POST
		4,	//	HTTP_CMD_PUT
		6,	//	HTTP_CMD_SEARCH
		7,	//	HTTP_CMD_CONNECT
		5,	//	HTTP_CMD_HEAD
	};

	return method > HTTP_CMD_HEAD ? 0 : METHOD_SIZES[method];
}

int isEndLine(const unsigned char * data) {
	int result = 0;
	switch(data[result++]) {
	case CR:
		if (data[result++] == LF) {
	case LF:
			return result;
		}
		break;
	}
	return 0;
}

PSoderoApplicationHTTP getHTTPSession(PSoderoTCPSession owner, PHTTPDetectRequest detect) {

	PSoderoApplicationHTTP application = takeApplication(sizeof(TSoderoApplicationHTTP));
#ifdef __EXPORT_STATISTICS__
	gHTTPTake++;
#endif

	newApplication((PSoderoApplication)application, (PSoderoSession)owner);
	application->method_code = detect->method;
	application->req_version = detect->version;
	application->url = dup_str((char*)detect->url);
	application->req_step = HTTP_STEP_HEAD;
	application->status =  HTTP_STATUE_REQ;
	application->req_b = gTime;

	if (owner->session) {
		application->pipelined = true;
		PSoderoApplicationHTTP tail = owner->session;
		while(tail->link)
			tail = tail->link;

		tail->link = application;
	} else
		owner->session = application;

	return application;
}

PSoderoApplicationHTTP setHTTPSession(PSoderoTCPSession owner, PHTTPDetectResponse detect) {
	PSoderoApplicationHTTP application = owner->session;
	while(application) {
		if (application->rsp_step == HTTP_STEP_NONE) {
			application->rsp_step  = HTTP_STEP_HEAD;
			application->rsp_b = gTime;
			if (application->req_e) {
				processE(&application->request, application->req_e - application->req_b);
				processE(&application->wait, gTime - application->req_e);
			} else {
				processE(&application->request, gTime - application->req_b);
				processE(&application->wait, gTime - application->req_b);
			}
			application->rsp_e = gTime;
			application->rsp_version = detect->version;
			application->status_code = detect->code;
			return application;
		}
		application = application->link;
	}
	gHTTPSkiped++;
	return application;
}

int isDoneHTTPSession(PSoderoApplicationHTTP application) {
	return (application->req_step == HTTP_STEP_DONE) && (application->rsp_step == HTTP_STEP_DONE);
}

unsigned int pickHTTPField(const unsigned char * text, int size, int base, char * * value) {

	unsigned int i = base;
	while(i < size) {
		if (text[i++] == COLON) break;
	}

	while(i < size) {
		if (text[i] > SPACE) break;

		if (text[i++] == LF) return i;
	}

	unsigned int j = i;
	while(j < size) {
		if (text[j] == LF) {
			if (value)
				for (unsigned int k = j; k > 0; k--) {
					if (text[k] > SPACE) {
						unsigned int length = k - i + 1;
						replace_str(value, (const char *) text + i, length);
						break;
					}
				}
			return j + 1;
		}
		j++;
	}

	return size;	//	All data must be deemed to have been processed
}

void processHTTPNode(int dir, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether, int value) {
	PNodeValue sourNode = takeIPv4Node((TMACVlan){{ether->sour, ether->vlan}}, ip->sIP);
	PNodeValue destNode = takeIPv4Node((TMACVlan){{ether->dest, ether->vlan}}, ip->dIP);
	if (dir > 0) {
		if (sourNode) {	//	request
			sourNode->l4.http.outgoing.action++;
			if(value)
				sourNode->l4.http.outgoing.count++;	//	method in outgoing
		}
		if (destNode) {
			destNode->l4.http.incoming.action++;
			if(value)
				destNode->l4.http.outgoing.count++;	//	method in outgoing
		}
		return;
	}
	if (dir < 0) {	//	response
		if (sourNode) {
			sourNode->l4.http.outgoing.action++;
			
			if (value >= 500)
				sourNode->l4.http.incoming.x50++;
			else if (value >= 400)
				sourNode->l4.http.incoming.x40++;
			else if (value >= 300)
				sourNode->l4.http.incoming.x30++;
			else if (value >= 200) {
				sourNode->l4.http.incoming.x20++;
			} else if (value >= 100)
				sourNode->l4.http.incoming.x10++;
			
			if (value >= 400)
				sourNode->l4.http.incoming.count++;	//	error in incoming
		}

		if (destNode && (sourNode != destNode)) {
			destNode->l4.http.incoming.action++;
			if (value >= 400)
				destNode->l4.http.incoming.count++;	//	error in incoming
				
			if (value >= 500)
				destNode->l4.http.incoming.x50++;
			else if (value >= 400)
				destNode->l4.http.incoming.x40++;
			else if (value >= 300)
				destNode->l4.http.incoming.x30++;
			else if (value >= 200) {
				destNode->l4.http.incoming.x20++;
			} else if (value >= 100)
				destNode->l4.http.incoming.x10++;
		}
		return;
	}

//	if (dir > 0) {
//		if (sourNode) {
//			if(method)
//				sourNode->l4.http.outgoing.request.method++;
//			if (code >= 400)
//				sourNode->l4.http.outgoing.request.error++;
//		}
//		if (destNode) {
//			if(method)
//				destNode->l4.http.incoming.request.method++;
//			if (code >= 400)
//				destNode->l4.http.incoming.request.error++;
//		}
//		return;
//	}
//
//	if (dir < 0) {
//		if (sourNode) {
//			if(method)
//				sourNode->l4.http.outgoing.response.method++;
//			if (code >= 400)
//				sourNode->l4.http.outgoing.response.error++;
//		}
//		if (destNode) {
//			if(method)
//				destNode->l4.http.incoming.response.method++;
//			if (code >= 400)
//				destNode->l4.http.incoming.response.error++;
//		}
//		return;
//	}
}

int doDetectHTTPRequestTitle(PHTTPDetectRequest head, const unsigned char * buffer, unsigned int length) {
	if (length < HTTP_HEAD_MIN_LENGTH)
		return DETECT_PENDING;

	head->method = str2method(buffer);
	if (head->method == HTTP_CMD_UNKNOWN) {
		for (int i = 0; i < length; i++)
			if (buffer[i] == LF)
				return -(i + 1);	//	found LF, skip invalid line
		return -length;	//	not found LF, skip all bytes
	}

	int offset = methodSize(head->method);

	//	Trim head space
	while (offset < length) {
		if (buffer[offset] > SPACE)
			break;
		offset++;
	}

	int size = length;
	buffer += offset;
	length -= offset;

	int i = 0;
	while (i <= length) {
		switch(buffer[i]) {
		case CR:
			if (i < (int)sizeof(head->url))
				head->url[i] = 0;
			break;
		case LF: {
			int base = i;
			while(buffer[base] <= SPACE) {
				base --;
				if (base <= 8)	//	with HTTP/1.x(8bytes)
					return -(i + offset);	//	skip invalid line
			}

			unsigned long long v = 0xDEDFDFDFDFDFDFDFULL & *uchar2ulonglong(buffer + base - 7);	//	HTTP/1.x\n
			if (v == 0x100e110f50545448ULL) {
				head->version = buffer[base] & 0x0F;
				offset += i;

				i = base - 8;
				//	Trim tail space
				if (i >= (int)sizeof(head->url))
					i = sizeof(head->url) - 1;

				while(i > 0)
					if (head->url[i] <= SPACE)
						head->url[i--] = 0;
					else
						break;
				gHTTPRequest++;
				gHTTPMethod[head->method]++;
#ifdef __EXPORT_STATISTICS__
//				printf("HTTP Request %s @ %u\n", nameOfHTTPMethod(head->method), gTotal.count);
#endif
				return offset + 1;
			}

			return -(i + offset);	//	skip invalid line;
		}
		default:
			if (i < (int)sizeof(head->url))
				head->url[i] = buffer[i];
		}
		i++;
	}

	if (size < HTTP_HEAD_MAX_LENGTH)
		return DETECT_PENDING;	//	FALSE	Not Found
	else
		return -size;	//	skip invalid line;
}

int detectHTTPRequest(PHTTPDetectRequest head, PSoderoTCPValue value,
		unsigned int base, const unsigned char * data, unsigned int size) {
	if (value->offset) {
		if (base < value->offset) {
			unsigned char buffer[64*1024];
			int length = mergeData(buffer, sizeof(buffer), value, base, data, size);
			return doDetectHTTPRequestTitle(head, buffer, length);
		} else
			base -= value->offset;
	}
	if (base < size)
		return doDetectHTTPRequestTitle(head, data + base, size - base);
	else
		return -size;
}

void updateHTTPRequestState(PSoderoApplicationHTTP application, PTCPState state) {
	if (application) {
		if (state->application == application) return;
		state->application = application;
		application->status = HTTP_STATUE_REQ;
		application->req_e = gTime;
		
		//if (!application->rsp_b)
			//processE(&application->request, gTime - application->req_b);
		application->req_pkts     ++;
		application->req_bytes    += state->payload;
		application->req_l2_bytes += state->length;
		application->reqRTTValue  += state->rttTime;
		application->reqRTTCount  += state->rtt;
		if (state->rst)
			application->req_aborted++;
	}
}

int checkHTTPRequestTitle(PSoderoTCPSession session, PSoderoTCPValue value,
		int base, const unsigned char * data, int size, int length,
		int dir, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {
	THTTPDetectRequest head;
	int result = detectHTTPRequest(&head, value, base, data, size);

	if (result > 0) {
		PSoderoApplicationHTTP application = getHTTPSession(session, &head);
		processHTTPNode(dir, tcp, ip, ether, head.method);

		if (application){
			application->req_pkts     ++;
			application->req_bytes    += size;
			application->req_l2_bytes += length;
		}
	}

	return result;
}

int doDetectHTTPResponseTitle(PHTTPDetectResponse head, const unsigned char * buffer, int length) {

	if (length < HTTP_HEAD_MIN_LENGTH)
		return DETECT_NEGATIVE;

	unsigned long long v = 0xDFDFDFDFDFDFDFDFULL & *(unsigned long long *)buffer;
	int method = methodOfResponse(v);
	if (method == HTTP_CMD_UNKNOWN)
		return DETECT_NEGATIVE;

	char * code = skip_space((char*) buffer + 8);
	if (code == nullptr) return DETECT_NEGATIVE;

	int size = code - (char *)buffer;

	head->code = atoi(code);

	for (unsigned int i = size + 1; i < length; i++)
		if (buffer[i] == LF) {
			unsigned int index = head->code / 100;
			gHTTPResponse++;
			if (index < 8)
				gHTTPCode[index]++;
#ifdef __EXPORT_STATISTICS__
//			printf("HTTP Response %d @ %u\n", head->code, gTotal.count);
#endif
			return i + 1;
		}

	//	Copy packet data to buffer
	return 0;
}

int detectHTTPResponse(PHTTPDetectResponse head, PSoderoTCPValue value,
		unsigned int base, const unsigned char * data, unsigned int size) {
	if (value->offset) {
		unsigned char buffer[64*1024];
		int length = mergeData(buffer, sizeof(buffer), value, base, data, size);
		return doDetectHTTPResponseTitle(head, buffer, length);
	} else
		return doDetectHTTPResponseTitle(head, data, size);
}

void updateHTTPResponseState(PSoderoApplicationHTTP application, PTCPState state) {
	if (application) {
		if (state->application == application) return;
		state->application = application;
		
		
		if (state->ack && (application->status == HTTP_STATUE_REQ)) {
			application->req_e = gTime;
			application->status = HTTP_STATUE_REQ_ACK;
//			printf("updateHTTPResponseState:: req_e %llx, %llx, %llx, %llx\r\n", gTime, application->req_e, application->owner->value.synTime, application->rsp_b);
		} /*else {
			application->rsp_e = gTime;
			
			if (application->rsp_b)
				processE(&application->response, gTime - application->rsp_b);
		}*/
		
		application->rsp_pkts     ++;
		application->rsp_bytes    += state->payload;
		application->rsp_l2_bytes += state->length;
		application->rspRTTValue  += state->rttTime;
		application->rspRTTCount  += state->rtt;
		if (state->rst)
			application->rsp_aborted++;
	}
}

int checkHTTPResponseTitle(PSoderoTCPSession session, PSoderoTCPValue value,
		int base, const unsigned char * data, int size, int dir, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {
	THTTPDetectResponse head;
	int result = detectHTTPResponse(&head, value, base, data, size);

	if (result > 0) {
		setHTTPSession(session, &head);
		processHTTPNode(dir, tcp, ip, ether, head.code);
	}

	return result;
}

int checkHTTPRequestField(PSoderoApplicationHTTP session, const unsigned char * data, int size) {

	unsigned long long major = 0xDFDFDFDFDFDFDFDFULL & *(unsigned long long *) data;

	if ((major & 0x00000000FFFFFFFFULL) == 0x0000000054534F48ULL) {		//	HOST
		return pickHTTPField(data, size, HTTP_OFFSET_HOST, &session->host);
	}

	if ((major & 0x0000FFFFFFFFFFFFULL) == 0x00004e494749524FULL) {		//	ORIGIN
		return pickHTTPField(data, size, HTTP_OFFSET_ORIGIN, &session->origin);
	}

	if ((major & 0x0000FFFFFFFFFFFFULL) == 0x000045494b4f4f43ULL) {		//	COOKIE
		return pickHTTPField(data, size, HTTP_OFFSET_COOKIE, &session->req_cookies);
	}

	if ((major & 0x00FFFFFFFFFFFFFFULL) == 0x0052455245464552ULL) {		//	REFERER
		return pickHTTPField(data, size, HTTP_OFFSET_REF, &session->referer);
	}

	if  (major                          == 0x0d544e45544e4f43ULL) {		//	CONTEXT-
		unsigned long long minor = 0xDFDFDFDFDFDFDFDFULL & * (unsigned long long *)(data + 8);
		if ((minor & 0x00000000FFFFFFFFULL) == 0x0000000045505954ULL) {	//	TYPE:
			return pickHTTPField(data, size, HTTP_OFFSET_CONTENT_TYPE, &session->req_content_type);
		}

		if ((minor & 0x0000FFFFFFFFFFFFULL) == 0x00004854474e454cULL) {	//	LENGTH:
			return pickHTTPField(data, size, HTTP_OFFSET_CONTENT_TYPE, &session->req_content_length);
		}
		//		if ((minor & 0x000000FFFFFFFFFFULL) == 0x00000045474E4152ULL) 	//	RANGE:
		//		if ((minor & 0x000000FFFFFFFFFFULL) == 0x00000045474E4152ULL) 	//	LOCATION
		//		if ((minor & 0x000000FFFFFFFFFFULL) == 0x00000045474E4152ULL) 	//	LANGUAGE
		//		if ((minor & 0x0000FFFFFFFFFFFFULL) == 0x474E49444F434E45ULL) 	//	ENCODING
		goto SKIP;
	}

	if ( major                          == 0x4547410d52455355ULL) {		//	USER-AGE
		unsigned long long minor = 0xDFDFDFDFDFDFDFDFULL & * (unsigned long long *)(data + sizeof(unsigned long long));
		if ((minor & 0x000000000000FFFFULL) == 0x000000000000544EULL) {	//	NT
			return pickHTTPField(data, size, HTTP_OFFSET_UA, &session->ua);
		}
		goto SKIP;
	}

	if ( major                          == 0x454e494c4e4f0d58ULL) {		//	X-ONLINE
		unsigned long long minor = 0xDFDFDFDFDFDFDFDFULL & * (unsigned long long *)(data + sizeof(unsigned long long));
		if ((minor & 0x000000FFFFFFFFFFULL) == 0x00000054534f480d) {	//	-HOST
			return pickHTTPField(data, size, HTTP_OFFSET_X_HOST, &session->x_online_host);
		}
		goto SKIP;
	}

//	if ((major & 0x00FFFFFFFFFFFFFFULL) == 0x001A545045434341ULL)		//	ACCEPT:
//	if ((major & 0x00FFFFFFFFFFFFFFULL) == 0x000D545045434341ULL) {		//	ACCEPT:-
//		unsigned long long minor = 0xDFDFDFDFDFDFDFDFULL & * (unsigned long long *)(line + 7);
//		if (minor == 0x1a54455352414843ULL);	//	CHARSET:
//		if (minor == 0x474e49444f434e45ULL);	//	ENCODING
//		if (minor == 0x45474155474e414cULL);	//	LANGUAGE
//	}
//	if ((major & 0x0000FFFFFFFFFFFFULL) == 0x00001a45474e4152ULL);		//	RANGE:
//	if  (major                          == 0x495443454E4E4F43ULL);		//	CONNECTI	ON:
//	if ((major & 0x000000FFFFFFFFFFULL) == 0x0000001a45544144ULL);		//	DATE:

SKIP:
	for (int i = 0; i < size; i++)
		if(data[i] == LF) return i+1;

	return 0;
}

int checkHTTPResposneField(PSoderoApplicationHTTP session, const unsigned char * data, int size) {

	unsigned long long major = 0xDFDFDFDFDFDFDFDFULL & *(unsigned long long *) data;
	if  (major                          == 0x0d544e45544e4f43ULL) {		//	CONTENT-
		unsigned long long minor = 0xDFDFDFDFDFDFDFDFULL & * (unsigned long long *)(data + 8);
		if ((minor & 0x00000000FFFFFFFFULL) == 0x0000000045505954ULL) {	//	TYPE:
			return pickHTTPField(data, size, HTTP_OFFSET_CONTENT_TYPE, &session->rsp_content_type);
		}

		if ((minor & 0x0000FFFFFFFFFFFFULL) == 0x00004854474e454cULL) {	//	LENGTH:
			return pickHTTPField(data, size, HTTP_OFFSET_CONTENT_TYPE, &session->rsp_content_length);
		}

		if ((minor & 0xFFFFFFFFFFFFFFFFULL) == 0x474e49444f434e45ULL) {	//	ENCODING
			return pickHTTPField(data, size, HTTP_OFFSET_CONTENT_ENCODING, &session->content_encoding);
		}

//		if ((minor & 0x000000FFFFFFFFFFULL) == 0x00000045474E4152ULL) 	//	RANGE:
//		if ((minor & 0x000000FFFFFFFFFFULL) == 0x00000045474E4152ULL) 	//	LOCATION
//		if ((minor & 0x000000FFFFFFFFFFULL) == 0x00000045474E4152ULL) 	//	LANGUAGE

		goto SKIP;
	}

	if (major == 0x524546534e415254ULL) {	//	TRANSFER
		unsigned long long minor = 0xDFDFDFDFDFDFDFDFULL & * (unsigned long long *)(data + 8);
		if (minor  == 0x4e49444f434e450dULL) {	//	-ENCODIN G
			return pickHTTPField(data, size, HTTP_OFFSET_TRANSFER_ENCODING, &session->transfer_encoding);
		}
		goto SKIP;
	}

SKIP:
	for (int i = 0; i < size; i++)
		if(data[i] == LF) return i+1;

	return 0;
}

void analyzeHTTPRequestHead(PSoderoApplicationHTTP application) {
	sodero_pointer_add(getFreshApplications(), application);
	application->req_step = HTTP_STEP_BODY;

	if (application->method_code != HTTP_CMD_POST) {
		application->req_step = HTTP_STEP_DONE;
		return;
	}

	if (application->req_content_length) {
		application->req_size = atoll(application->req_content_length);
	}

	if (application->req_content_type) {
		if (strncasecmp(application->req_content_type, "multipart/form-data", 19) == 0) {
//			application->req_size = 0;
			char * multipart = application->req_content_type + 19;
			multipart = find_char (multipart, ';');
			multipart = skip_space(multipart + 1);
			unsigned long long major = 0xDFDFDFDFDFDFDFDFULL & *(unsigned long long *) multipart;
			if (major == 0x595241444e554f42ULL) {
				multipart = skip_space(multipart);
				multipart = find_char (multipart, '=');
				multipart = skip_space(multipart + 1);
				application->multipart = multipart;
				application->sunday = sunday_init(application->multipart);
				application->req_multipart = true;
			}
		}
//		if (strncasecmp(application->req_content_type, "application/x-www-form-urlencoded", 33) == 0) {
//			application->req_multipart = true;
//			application->multipart = application->req_content_type + 33;
//			application->multipart = find_char (application->multipart, ';');
//			application->multipart = skip_space(application->multipart);
//			application->sunday = sunday_init(application->multipart);
//		}
	}

	if ((application->req_content_length == 0) && !application->multipart) {
		application->req_step = HTTP_STEP_DONE;
		return;
	}
}

void analyzeHTTPResponseHead(PSoderoApplicationHTTP application) {
	application->rsp_step = HTTP_STEP_BODY;

	if (application->rsp_content_length) {
		application->rsp_size = atoll(application->rsp_content_length);
	}

	if (application->transfer_encoding) {
		unsigned long long major = 0xDFDFDFDFDFDFDFDFULL & *(unsigned long long *) application->transfer_encoding;

		if ((major & 0x00FFFFFFFFFFFFFFULL) == 0x0044454b4e554843ULL) {	//	CHUNKED
			application->rsp_chunked = true;
		}
	}

	if (application->content_encoding) {
		unsigned long long major = 0xDFDFDFDFDFDFDFDFULL & *(unsigned long long *) application->content_encoding;
		do {
			if ((major & 0x00FFFFFFFFFFFFFFULL) == 0x004554414c464544ULL) {	//	DEFLATE
				application->rsp_compressed = true;
			}
			if ((major & 0x00000000FFFFFFFFULL) == 0x0000000050495a47ULL) {	//	GZIP
				application->rsp_compressed = true;
			}
		} while(false);
	}

//	if ((application->rsp_content_length == 0) || !application->rsp_chunked) {
//		application->rsp_step = HTTP_STEP_DONE;
//		return;
//	}
}

typedef int (*TcheckHTTPField)(PSoderoApplicationHTTP session, const unsigned char * data, int size);
typedef void(*TanalyzeHTTPField)(PSoderoApplicationHTTP session);


int checkHTTPHead(PSoderoApplicationHTTP application, int dir, PSoderoTCPValue value,
		int base, const unsigned char * data, int size, TcheckHTTPField checker, TanalyzeHTTPField alalyze) {

	int offset = base;
	char *cookie = NULL;
	int cookie_len = 0;
	
	while(offset < value->offset) {
		unsigned char buffer[64 * 1024];
		int bytes = pickLine(buffer, sizeof(buffer), value, base, data, size);

		//	No line, nothing to do
		if (bytes == 0) return 0;
		//	process current line
		checker(application, data, bytes);
		offset += bytes;
	}

	offset -= value->offset;
	while(offset < size) {
		int eol = isEndLine(data + offset);
		if (eol > 0) {
			offset += eol;
			alalyze(application);
			break;
		}

		int bytes = checker(application, data + offset, size - offset);
		if (application->req_cookies) {
			if (!cookie)
				cookie = malloc(128);
			
			if (cookie && (0 == cookie_len)) {
				memset(cookie, 0, 128);
				cookie_len += snprintf(cookie + cookie_len, 128 - cookie_len, "%s", application->req_cookies);
			} else if (cookie) {
				cookie_len += snprintf(cookie + cookie_len, 128 - cookie_len, ",%s", application->req_cookies);
			}

			application->req_cookies = NULL;
		}
			
		if (bytes > 0)
			offset += bytes;
		else
			break;
	}

	if (cookie) {
		//cookie_len += snprintf(cookie + cookie_len, 128 - cookie_len, ";", application->req_cookies);
		application->req_cookies = cookie;
	}

	return value->offset + offset - base;
}

int checkHTTPRequestHead(PSoderoApplicationHTTP application, PSoderoTCPValue value,
		int base, const unsigned char * data, int size) {
	return checkHTTPHead(application, DIR_REQUEST , value, base, data, size, checkHTTPRequestField , analyzeHTTPRequestHead );
}

int checkHTTPResponseHead(PSoderoApplicationHTTP application, PSoderoTCPValue value,
		int base, const unsigned char * data, int size) {
	return checkHTTPHead(application, DIR_RESPONSE, value, base, data, size, checkHTTPResposneField, analyzeHTTPResponseHead);
}


int checkHTTPRequestBody(PSoderoApplicationHTTP application, PSoderoTCPValue value,
		int base, const unsigned char * data, int size) {
	int gate = value->offset + size;
	if (application->method_code != HTTP_CMD_POST) {
		application->req_step = HTTP_STEP_DONE;
		return 0;
	}

	int byte = gate - base;		//	Byte to be processed

	//	HTTP POST
	if (application->req_size) {
		//	The number of bytes needed
		int need = application->req_size - application->req_fill;

		if (need > 0) {
			if (need > byte) {
				application->req_fill += byte;
				return byte;	//	take away all the data
			}
			//	POST Body is done.
			application->req_fill = application->req_size;	//	req_size - req_fill is need
			application->req_step = HTTP_STEP_DONE;
			return need;	//	Take away some of data
		} else
			return PARSE_ERROR;	//	Parse ERROR
	}

	if (application->req_multipart) {
		PSundayData sunday = application->sunday;

		//	Check the data length
		if (byte < sunday->length)	//	byte must greater than terminalor's length
			return 0;	//	There is not enough data, nothing to do.

		int length = value->offset - base;	//	Check start offset
		if (length > 0) {
			//	There is some data left in value's buffer(from base). ( Length is at least 1 )
			int need = size > (sunday->length - 1) ? sunday->length - 1 : size;

			//	Check multipart with minus one bytes in prev packet.
			memcpy(value->buffer + value->offset, data, need);

			//	Check buffer, length plus need  must be greater than terminalor's length.
			//	Otherwise, the data length can not pass check before.
			int index = sunday_find(sunday, (const char *)value->buffer + base, length + need);

			if (index >= 0) {	//	FOUND multipart terminalor in value's buffer
				application->req_step = HTTP_STEP_DONE;		//	Means POST Body is done.
				return index + sunday->length;
			}
		}

		//	Check current packet
		if (size >= sunday->length) {
			int index = sunday_find(sunday, (const char *)data, size);
			if (index >= 0) {		//	FOUND multipart terminalor in packet
				application->req_step = HTTP_STEP_DONE;		//	Means POST Body is done.
				//	taken bytes in packet plus all bytes in value's buffer.
				return (index + sunday->length) + value->offset - base;
			}
		}

		//	Leaving a maximum possible non-intact terminator.
		return byte - (sunday->length - 1);

	}
	//	Body is continue to end.
	return size;
}

int checkHTTPChunkSize(PSoderoApplicationHTTP application, unsigned char * data, int size) {
	unsigned long long result = 0;
	for(int index = 0; index < size; index++) {
		switch (data[index]) {
			case '0'...'9':
				result = result * 16 + (data[index] - '0');
				break;
			case 'A'...'F':
				result = result * 16 + (data[index] - 'A' + 10);
				break;
			case 'a'...'f':
				result = result * 16 + (data[index] - 'a' + 10);
				break;
			default: {
				int eol = isEndLine(data + index);
				if(eol > 0) {
					application->rsp_fill = result;
					return index + eol;
				}
				return PARSE_ERROR;
			}
		}
	}
	return 0;
}

int checkHTTPResponseBody(PSoderoApplicationHTTP application, PSoderoTCPValue value,
		int base, const unsigned char * data, int size) {
	int gate = value->offset + size;
	if (application->rsp_size) {
		int byte = gate - base;
		int left = application->rsp_size - application->rsp_fill;	//	rsp_size - rsp_fill is need
		if (left > 0) {
			if (byte < left) {
				application->rsp_fill += byte;
				return byte;
			}
			application->rsp_fill = application->rsp_size;
			application->rsp_step = HTTP_STEP_DONE;
			return left;
		}
	}

	if (application->rsp_chunked) {
		//	Transfer in chunked without Content-Length, Check body chunk by chunk
		int result = 0;
		while(base < gate) {
			if (application->rsp_fill <= 0) {
				unsigned char buffer[1024];
				int head = 0;
				if (application->rsp_fill < 0) {
					head = pickLine(buffer, sizeof(buffer), value, base, data, size);
					if (head  < 0) return PARSE_ERROR;
					if (head == 0) return result;
					if (head > 2)  return PARSE_ERROR;

					//	head is 1 or 2
					application->rsp_fill = 0;
				}

				int tail = pickLine(buffer, sizeof(buffer), value, base + head, data, size);

				if (tail  < 0) return PARSE_ERROR;
				if (tail == 0) return result + head;

				if (checkHTTPChunkSize(application, buffer, tail) < 0) return PARSE_ERROR;

				if (application->rsp_fill == 0) {
					//	Check Last empty chunk's CRLF
					int last = pickLine(buffer, sizeof(buffer), value, base + head + tail, data, size);
					if (last < 0) return PARSE_ERROR;
					if (last == 0) return result + head;	//	Wait Terminal chunk
					if (last > 2) return PARSE_ERROR;

					//	head is 1 or 2
					application->rsp_step = HTTP_STEP_DONE;
					return result + head + tail + last;
				}

				int byte = head + tail;
				result += byte;
				base   += byte;
			}

			int left = gate - base;
			if (application->rsp_fill <= left) {
				base   += application->rsp_fill;	//	base <= gate
				result += application->rsp_fill;
//				last = pickLine(buffer, sizeof(buffer), value, base + head + tail, data, size); application->rsp_fill-=2
				application->rsp_fill = -2;			//	CRLF behide block
			} else {
				base                  += left;
				result                += left;
				application->rsp_fill -= left;
			}
		}
		return result;
	}

	//	Body is continue to end.
	return gate - base;
}

int processHTTPRequest(PSoderoTCPSession session, PSoderoTCPValue value,
		unsigned int base, const unsigned char * data, unsigned int size, int length,
		int dir, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {
	PSoderoApplicationHTTP application = session->session;
	while(application) {
		switch(application->req_step) {
			case HTTP_STEP_NONE:
				return PARSE_ERROR;
			case HTTP_STEP_HEAD:
				return checkHTTPRequestHead(application, value, base, data, size);
			case HTTP_STEP_BODY:
				return checkHTTPRequestBody(application, value, base, data, size);
			case HTTP_STEP_DONE:
				application = application->link;
				continue;
		}
	}
	return checkHTTPRequestTitle(session, value, base, data, size, length, dir, tcp, ip, ether);
}

int processHTTPResponse(PSoderoTCPSession session, PSoderoTCPValue value,
		unsigned int base, const unsigned char * data, unsigned int size,
		int dir, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {
	PSoderoApplicationHTTP application = session->session;
	while(application) {
		switch(application->rsp_step) {
			case HTTP_STEP_NONE:
				return checkHTTPResponseTitle(session, value, base, data, size, dir, tcp, ip, ether);
			case HTTP_STEP_HEAD:
				return checkHTTPResponseHead(application, value, base, data, size);
			case HTTP_STEP_BODY:
				return checkHTTPResponseBody(application, value, base, data, size);
			case HTTP_STEP_DONE:
				application = application->link;
				break;
		}
	}
	return PARSE_ERROR;
}

void updateHTTPState(PSoderoTCPSession session, int dir, PTCPState state) {
	do {
		if (dir > 0) {
			PSoderoApplicationHTTP application = session->session;
			while(application) {
				if (application->req_step == HTTP_STEP_DONE)
					if (application->link) {
						application = application->link;
						continue;
					}
				break;
			}
			if (application)
				updateHTTPRequestState (application, state);
			break;
		}
		if (dir < 0) {
			PSoderoApplicationHTTP application = session->session;
			while(application) {
				if (application->rsp_step == HTTP_STEP_DONE)
					if (application->link) {
						application = application->link;
						continue;
					}
				break;
			}
			if (application)
				updateHTTPResponseState(application, state);
			break;
		}
	} while(false);
}

int detectHTTP(PSoderoTCPSession session, PSoderoTCPValue value,
	unsigned int base, const unsigned char * data, unsigned int size, int length, int dir,
	PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {

	return checkHTTPRequestTitle(session, value, base, data, size, length, dir, tcp, ip, ether);
}

int processHTTPPacket(PSoderoTCPSession session, int dir, PSoderoTCPValue value,
	unsigned int base, const unsigned char * data, unsigned int size, unsigned int length,
	PTCPState state, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {

	int gate = value->offset + size;
	int total = base;

	do {
		PNodeValue sourNode = takeIPv4Node((TMACVlan){{ether->sour, ether->vlan}}, ip->sIP);
		PNodeValue destNode = takeIPv4Node((TMACVlan){{ether->dest, ether->vlan}}, ip->dIP);
		
		if (sourNode) {
			processA(&sourNode->l4.http.outgoing.value, size);
			sourNode->l4.http.outgoing.l2 += length;
			sourNode->l4.http.outgoing.rttValue += state->rttTime;
			sourNode->l4.http.outgoing.rttCount += state->rtt;
			
		}
		if (destNode) {
			processA(&destNode->l4.http.incoming.value, size);
			destNode->l4.http.incoming.l2 += length;
			destNode->l4.http.incoming.rttValue += state->rttTime;
			destNode->l4.http.incoming.rttCount += state->rtt;
		}
		if (dir > 0) {
//			if (sourNode) {
//				processA(&sourNode->l4.http.outgoing.value, size);
//				sourNode->l4.http.outgoing.l2 += length;
//				sourNode->l4.http.outgoing.rttValue += state->rttTime;
//				sourNode->l4.http.outgoing.rttCount += state->rtt;
//			}
//			if (destNode) {
//				processA(&destNode->l4.http.incoming.value, size);
//				destNode->l4.http.incoming.l2 += length;
//				destNode->l4.http.incoming.rttValue += state->rttTime;
//				destNode->l4.http.incoming.rttCount += state->rtt;
//			}
			while(total < gate){
				int result = processHTTPRequest (session, value, total, data, size, length, dir, tcp, ip, ether);
				if (result < 0)
					return PARSE_ERROR;
				if (result > 0) {
					total += result;
					continue;
				}
				break;	//	result is zero
			};
			break;
		}
		if (dir < 0) {
//			if (sourNode) {
//				processA(&sourNode->l4.http.outgoing.value, size);
//				sourNode->l4.http.outgoing.l2 += length;
//				sourNode->l4.http.outgoing.rttValue += state->rttTime;
//				sourNode->l4.http.outgoing.rttCount += state->rtt;
//			}
//			if (destNode) {
//				processA(&destNode->l4.http.incoming.value, size);
//				destNode->l4.http.incoming.l2 += length;
//				destNode->l4.http.incoming.rttValue += state->rttTime;
//				destNode->l4.http.incoming.rttCount += state->rtt;
//			}
			while(total < gate){
				int result = processHTTPResponse(session, value, total, data, size, dir, tcp, ip, ether);
				if (result < 0)
					return PARSE_ERROR;
				if (result > 0) {
					total += result;
					continue;
				}
				break;	//	result is zero
			};
			break;
		}
		return size;
	} while(false);

	PSoderoApplicationHTTP application = session->session;
	while (application) {
		if (isDoneHTTPSession(application)) {
			PNodeValue sourNode = takeIPv4Node((TMACVlan){{ether->sour, ether->vlan}}, ip->sIP);
			application->rsp_e = gTime;
			//printf("updateHTTPState:: rsp_e %llx, %llx, %llx\r\n", gTime, application->req_e,application->req_b);
			if (application->rsp_b)
				processE(&application->response, gTime - application->rsp_b);

//			printf("sourNode = %p\r\n", sourNode);
			if (sourNode) {	
				processEE(&sourNode->l4.http.outgoing.request, &(application->request));
				processEE(&sourNode->l4.http.outgoing.wait, &(application->wait));
				processEE(&sourNode->l4.http.outgoing.response, &(application->response));
			}
			PSoderoApplicationHTTP next = application->link;
			application->link = nullptr;
			sodero_pointer_add(getClosedApplications(), application);
			application = next;
			continue;
		} else
			break;
	}
	session->session = application;

	return total - base;
}

int skipHTTPPacket(PSoderoTCPSession session, int dir, unsigned int size) {
	printf("HTTP process abort\n");
	return PARSE_ERROR;
}
