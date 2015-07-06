/*
 * Tns.h
 *
 *  Created on: Apr 27, 2015
 *      Author: Yang Liu
 */

#ifndef TNS_H_
#define TNS_H_

#include <stdbool.h>
#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "Stream.h"
#include "TCP.h"

#pragma pack(push, 1)

#define TNS_BUFFER_SIZE    (4 * 1024)

#define TNS_LOGIN_SUCCESS   +1
#define TNS_LOGIN_FAILURE   -1
#define TNS_STATUS_OK      0x00
#define TNS_STATUS_INFILE  0xFB
#define TNS_STATUS_EOF     0xFE
#define TNS_STATUS_ERROR   0xFF

enum tns_type {
    TNS_CONNECT   =  1,
    TNS_ACCEPT    =  2,
    TNS_ACK       =  3,
    TNS_REFUSE    =  4,
    TNS_REDIRECT  =  5,
    TNS_DATA      =  6,
    TNS_NULL      =  7,
    TNS_ABORT     =  9,
    TNS_RESEND    = 11,
    TNS_MARKER    = 12,
    TNS_ATTENTION = 13,
    TNS_CONTROL   = 14,
    TNS_TYPE_MAX  = 15
};

typedef struct SODERO_TNS_VALUE {
	TSoderoFlowDatum   value;
	unsigned int       count;	//	command count
	unsigned int       block;	//	block count

	unsigned long long rttValue;
	unsigned int       rttCount;
	unsigned int       l2;
} TSoderoTNSValue, * PSoderoTNSValue;

typedef struct SODERO_ORACLE_HEAD {
	unsigned int  length:16;
	unsigned int check_sum:16;
	unsigned char type;
	unsigned char reserved;
	unsigned int header_check_sum:16;
} TOracleHead, * POracleHead;


typedef struct SODERO_ORACLE_CONNECT {
	short version;	//	Protocol Version
	short compatible_version;
	char ser_opt1;
	char ser_opt2;
	short SDU_size;
	short TDU_size;
	char NT_protocol_ch1;
	char NT_protocol_ch2;
	short max_packets;
	short hardware;
	unsigned short data_length;
	unsigned short offset;
	int max_data;
	char flag0;
	char flag1;
	char user[64];
       char dbname[64];
} TSoderoOracleConnect, * PSoderoOracleConnect;

typedef union SODERO_TNS_APPLICATION {
	struct {
		char *             data;
		PSoderoTCPSession    owner;
		PSoderoApplication link;
		unsigned long long id;		//	session id
//		unsigned char      flag;
		unsigned long long serial;

		union {
			struct {
				unsigned long long reqTime;
				unsigned long long rspTime;
				char * user;
				char * database;
				unsigned char status;
			};
			struct {
				TSoderoDoubleDatum traffic;	//	Oracle block count & bytes
				unsigned long long reqFirst;
				unsigned long long reqLast;
				unsigned long long rspFirst;
				unsigned long long rspLast;
				unsigned int       set;		//	total result set count of command's reponse
				unsigned int       col;		//	total col of result set;
				unsigned long long row;		//	Total row count of result set;
			};
		};
		unsigned int reqPending;	//	Oracle Block Pending - Request
		unsigned int rspPending;	//	Oracle Block Pending - Response
//		char * tail;
              char sql[2048];
		unsigned char command;
		unsigned char flow;			//	command flow's branch
		unsigned char step;			//	flow's step
		unsigned char flag;

		char text[0];
	};
	char * buffer[512];
} TSoderoTnsApplication, * PSoderoTnsApplication;

typedef union SODERO_TNS_PACKET_DETAIL {
	unsigned long long value;
	struct {
		unsigned char command;
		unsigned char block;
	};
} TSoderoTnsPacketDetail, * PSoderoTnsPacketDetail;

struct query_candidate {
    unsigned num_candidate_size;
    unsigned long candidate_sizes[10];
    bool is_chunked;
    unsigned query_size;
};

struct cursor {
    unsigned char const *head;
    int cap_len;     // remaining length that can be read
};

struct string_buffer {
    char   *head;
    size_t size;
    size_t pos;
    bool   truncated;
};

unsigned char read_u8(struct cursor *cursor);

unsigned short read_u16(struct cursor *cursor);

extern int detectTNS(PSoderoTCPSession session, PSoderoTCPValue value,
		unsigned int base, const unsigned char * data, unsigned int size, int dir,
		PTCPHeader tcp, PIPHeader ip, PEtherHeader ether);
int parseOracleConnect(PSoderoOracleConnect result, struct cursor *cursor,  int size);
int parseTnsPacket(PSoderoTnsPacketDetail detail, PSoderoTCPSession session, int dir,
	const unsigned char * data, int size, int length);
int processTNSPacket(PSoderoTCPSession session, int dir, PSoderoTCPValue value,
	unsigned int base, const unsigned char * data, unsigned int size, unsigned int length,
	PTCPState state, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether);
void cursor_rollback(struct cursor *cursor, size_t n);

#define CHECK_LEN(cursor, x, rollback) do { \
    if ((cursor)->cap_len  < (x)) { cursor_rollback(cursor, rollback); { \    
        return -1; } \
    } \
} while(0)
#define CHECK(n) CHECK_LEN(cursor, n, 0)

#pragma pack(pop)

#endif /* MYSQL_H_ */

/*
http://dev.mysql.com/doc/internals/en/client-server-protocol.html
*/
