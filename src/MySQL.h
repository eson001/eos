/*
 * MySQL.h
 *
 *  Created on: Dec 16, 2014
 *      Author: Clark Dong
 */

#ifndef MYSQL_H_
#define MYSQL_H_

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "Stream.h"
#include "TCP.h"

#pragma pack(push, 1)

#define MYSQL_BUFFER_SIZE    (4 * 1024)

#define MYSQL_LOGIN_SUCCESS   +1
#define MYSQL_LOGIN_FAILURE   -1
#define MYSQL_STATUS_OK      0x00
#define MYSQL_STATUS_INFILE  0xFB
#define MYSQL_STATUS_EOF     0xFE
#define MYSQL_STATUS_ERROR   0xFF

#define SCRAMBLE_LENGTH      20
#define SCRAMBLE_LENGTH_323  8

#define MYSQL_LE_2     0xFC
#define MYSQL_LE_3     0xFD
#define MYSQL_LE_8     0xFE

enum {
	CLIENT_LONG_PASSWORD                  = 0x00000001,
	CLIENT_FOUND_ROWS                     = 0x00000002,
	CLIENT_LONG_FLAG                      = 0x00000004,
	CLIENT_CONNECT_WITH_DB                = 0x00000008,
	CLIENT_NO_SCHEMA                      = 0x00000010,
	CLIENT_COMPRESS                       = 0x00000020,
	CLIENT_ODBC                           = 0x00000040,
	CLIENT_LOCAL_FILES                    = 0x00000080,
	CLIENT_IGNORE_SPACE                   = 0x00000100,
	CLIENT_PROTOCOL_41                    = 0x00000200,
	CLIENT_INTERACTIVE                    = 0x00000400,
	CLIENT_SSL                            = 0x00000800,
	CLIENT_IGNORE_SIGPIPE                 = 0x00001000,
	CLIENT_TRANSACTIONS                   = 0x00002000,
	CLIENT_RESERVED                       = 0x00004000,
	CLIENT_SECURE_CONNECTION              = 0x00008000,
	CLIENT_MULTI_STATEMENTS               = 0x00010000,
	CLIENT_MULTI_RESULTS                  = 0x00020000,
	CLIENT_PS_MULTI_RESULTS               = 0x00040000,
	CLIENT_PLUGIN_AUTH                    = 0x00080000,
	CLIENT_CONNECT_ATTRS                  = 0x00100000,
	CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000,
	CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS   = 0x00400000,
	CLIENT_SESSION_TRACK                  = 0x00800000,
	CLIENT_DEPRECATE_EOF                  = 0x01000000,
};

enum {
	SERVER_STATUS_IN_TRANS              = 0x0001,
	SERVER_STATUS_AUTOCOMMIT            = 0x0002,
	SERVER_MORE_RESULTS_EXISTS          = 0x0008,
	SERVER_STATUS_NO_GOOD_INDEX_USED    = 0x0010,
	SERVER_STATUS_NO_INDEX_USED         = 0x0020,
	SERVER_STATUS_CURSOR_EXISTS         = 0x0040,
	SERVER_STATUS_LAST_ROW_SENT	        = 0x0080,
	SERVER_STATUS_DB_DROPPED            = 0x0100,
	SERVER_STATUS_NO_BACKSLASH_ESCAPES  = 0x0200,
	SERVER_STATUS_METADATA_CHANGED	    = 0x0400,
	SERVER_QUERY_WAS_SLOW               = 0x0800,
	SERVER_PS_OUT_PARAMS                = 0x1000,
	SERVER_STATUS_IN_TRANS_READONLY	    = 0x2000,
	SERVER_SESSION_STATE_CHANGED        = 0x4000,
};

enum {
	SESSION_TRACK_SYSTEM_VARIABLES	= 0x00,
	SESSION_TRACK_SCHEMA	        = 0x01,
	SESSION_TRACK_STATE_CHANGE	    = 0x02,
};

enum {
	MYSQL_CONNECTION_NONE,
	MYSQL_CONNECTION_LOGIN,
	MYSQL_CONNECTION_DONE,
};

enum {
	  MYSQL_CMD_SLEEP            =  0,	//	ERR_Packet
	  MYSQL_CMD_QUIT             =  1,	//	OK_Packet
	  MYSQL_CMD_INIT_DB          =  2,	//	OK_Packet or ERR_Packet
	  MYSQL_CMD_QUERY            =  3,	//	COM_QUERY_Response
	  MYSQL_CMD_FIELD_LIST       =  4,	//	COM_FIELD_LIST response
	  MYSQL_CMD_CREATE_DB        =  5,	//	OK_Packet or ERR_Packet
	  MYSQL_CMD_DROP_DB          =  6,	//	OK_Packet or ERR_Packet
	  MYSQL_CMD_REFRESH          =  7,	//	OK_Packet or ERR_Packet
	  MYSQL_CMD_SHUTDOWN         =  8,	//	OK_Packet or ERR_Packet
	  MYSQL_CMD_STATISTICS       =  9,	//	string.EOF
	  MYSQL_CMD_PROCESS_INFO     = 10,	//	ProtocolText::Resultset or ERR_Packet on error
	  MYSQL_CMD_CONNECT          = 11,	//	ERR_Packet
	  MYSQL_CMD_PROCESS_KILL     = 12,	//	OK_Packet or ERR_Packet
	  MYSQL_CMD_DEBUG            = 13,	//	OK_Packet or ERR_Packet
	  MYSQL_CMD_PING             = 14,	//	OK_Packet
	  MYSQL_CMD_TIME             = 15,	//	ERR_Packet
	  MYSQL_CMD_DELAYED_INSERT   = 16,	//	ERR_Packet
	  MYSQL_CMD_CHANGE_USER      = 17,	//	Authentication Method Switch Request Packet or ERR_Packet on error
	  MYSQL_CMD_BINLOG_DUMP      = 18,	//	EOF_Packet or ERR_Packet
	  MYSQL_CMD_TABLE_DUMP       = 19,	//	table dump or ERR_Packet
	  MYSQL_CMD_CONNECT_OUT      = 20,	//	ERR_Packet
	  MYSQL_CMD_REGISTER_SLAVE   = 21,	//	OK_Packet or ERR_Packet
	  MYSQL_CMD_PREPARE          = 22,	//	COM_STMT_PREPARE_OK on success, ERR_Packet otherwise
	  MYSQL_CMD_EXECUTE          = 23,	//	COM_STMT_EXECUTE Response
	  MYSQL_CMD_LONG_DATA        = 24,
	  MYSQL_CMD_CLOSE_STMT       = 25,
	  MYSQL_CMD_RESET_STMT       = 26,	//	OK_Packet or ERR_Packet
	  MYSQL_CMD_SET_OPTION       = 27,	//	OK_Packet or ERR_Packet
	  MYSQL_CMD_FETCH_STMT       = 28,	//	COM_STMT_FETCH response
	  MYSQL_COM_DAEMON           = 29,	//	ERR_Packet
	  MYSQL_COM_BINLOG_DUMP_GTID = 30,	//	Binlog Network Stream, EOF_Packet or ERR_Packet
	  MYSQL_COM_RESET_CONNECTION = 31,	//	OK_Packet or ERR_Packet
	  MYSQL_COM_SODERO_EXTEND      = 255	//	FOR login
};

enum {
	MYSQL_FLOW_NONE,
	MYSQL_FLOW_CMD_FIELDS   ,
	MYSQL_FLOW_CMD_RESULTSET,
	MYSQL_FLOW_CMD_INLINE   ,
	MYSQL_FLOW_DONE = 0xFF,
};

enum {
//	MYSQL_RS_NONE,
	MYSQL_RS_HEADER,
	MYSQL_RS_COLUMN,
	MYSQL_RS_ROW,
	MYSQL_RS_DONE,
};

enum {
	MYSQL_IL_REQ,
	MYSQL_IL_RSP,
};

typedef struct SODERO_MYSQL_HEAD {
	unsigned int  length: 24;
	unsigned char serial;
} TMySQLHead, * PMySQLHead;

typedef struct SODERO_MYSQL_COMPRESS {
	unsigned int  length: 24;
} TSoderoMySQLCompress, * PSoderoMySQLCompress;

typedef struct SODERO_MYSQL_GREETING {
	         char   protocol       ;	//	Protocol Version
	const unsigned char * database ;	//	Database Version
	unsigned int id                ;	//	Connection ID
	unsigned long long salt1       ;	//	First half of the encryption key
//	unsigned char filler           ;	//	Must be ZERO
	union {
		struct {
			unsigned short capability1;	//	Low 16bits server attributes
			unsigned short capability2;	//	High 16bits server attributes
		};
		unsigned int capability;
	};
	unsigned char charset          ;	//
	unsigned short status          ;	//	Server Status
//	unsigned short capability2     ;	//	High 16bits server attributes
	unsigned char length           ;	//	length of slat
//	unsigned char filler[10]       ;	//	11 bytes filled with zeros
	const unsigned char * salt2    ;	//	Latter part of the encryption key
	const unsigned char * plugin   ;
} TSoderoMySQLGreeting, * PSoderoMySQLGreeting;

typedef struct SODERO_MYSQL_LOGING {
	unsigned int capability  ;	//	client attributes
	unsigned int length      ;	//	Maximum packet length
	unsigned char charset    ;	//
//	unsigned char padding[23];	//	23 bytes filled with zeros
	const unsigned char * user     ;	//	Unsername
	unsigned char         size     ;	//	Password string size
	const unsigned char * pass     ;	//	HASH of password
	const unsigned char * database ;	//	The initial database
	const unsigned char * plugin   ;
} TSoderoMySQLLogin, * PSoderoMySQLLogin;

typedef struct SODERO_MYSQL_COMMAND {
	unsigned char command;
	union {
		const unsigned char * database;		//	MYSQL_CMD_INIT_DB & MYSQL_CMD_CREATE_DB & MYSQL_CMD_DROP_DB
		const unsigned char * sql     ;		//	MYSQL_CMD_QUERY & MYSQL_CMD_PREPARE
		struct {				//	MYSQL_CMD_FIELD_LIST
			const unsigned char * table;
			const unsigned char * field;
		};
		unsigned char refresh ;	//	MYSQL_CMD_RELOAD
		unsigned char shutdown;	//	MYSQL_CMD_SHUTDOWN
		unsigned int  id      ;	//	MYSQL_CMD_CONNECT & MYSQL_CMD_CLOSE_STMT & MYSQL_CMD_RESET_STMT
		struct {				//	MYSQL_CMD_CHANGE_USER
			const unsigned char * user;
			unsigned long long salt;
			const unsigned char * salt2;
			const unsigned char * database;
			unsigned short charset;
		} change;
		struct {				//	MYSQL_CMD_BINLOG_DUMP
			unsigned int start;	//
			unsigned int flags;	//	Must be ZERO
			unsigned int id;
			const unsigned char * file;
		} log;
		struct {				//	COM_TABLE_DUMP
			const unsigned char * database;
			const unsigned char * table;
		} dump;
		struct {				//	MYSQL_CMD_REGISTER_SLAVE
			unsigned int id;
			const unsigned char * masterIP;
			const unsigned char * masterUser;
			const unsigned char * masterPass;
			unsigned short masterPort;
			unsigned int security;
		} slave;
		struct {               //	MYSQL_CMD_EXECUTE
			unsigned int id;
			unsigned char flag;
			unsigned int reserved;
		} execute;
		struct {              //	MYSQL_CMD_LONG_DATA
			unsigned int id;
			unsigned short serial;
			unsigned short type  ;	//	Not used
			const unsigned char * payload;
		} data;
		unsigned short option;
		struct {              //	MYSQL_CMD_FETCH_STMT
			unsigned int id;
			unsigned int count;
		} fetch;
		struct {
			unsigned short flags;
			unsigned int id;
			unsigned int size;
//			const unsigned char * name;
			unsigned long long position;
			unsigned int count;
//			const unsigned char * value;
		} gtid;
	};
} TSoderoMySQLCommand, * PSoderoMySQLCommand;

typedef struct SODERO_MYSQL_RESPONSE {
	unsigned char type;
	union {
		struct {
			unsigned short  code     ;	//	Error Code
			unsigned char   marker   ;	//	Fixed: #?
			unsigned char   status[5];	//	Fixed: 28000?
			const unsigned char * message  ;	//	Error message
		} error;	//	when state is 0xff
		struct {
			unsigned long long affect;	//	Affected Rows
			unsigned long long insert;	//	Inserted ID
			unsigned short status    ;	//	Server Status
			unsigned short warning   ;	//	Warning Status
			const unsigned char * info     ;
			const unsigned char * message  ;	//	Option inof
		} ok ;	//	when state is 0x00
		struct {
			unsigned short count;	//	warning count
			unsigned short state;	//
		} eof;
		struct {
			unsigned long long field;
			unsigned long long count;
		} header;
		struct {
			const unsigned char * catalog;
			const unsigned char * datbase;
			const unsigned char * alias  ;
			const unsigned char * table  ;
			const unsigned char * column ;
//			unsigned char filler   ;
			unsigned char charset  ;
			unsigned int length    ;
			unsigned char type     ;
			unsigned short flags   ;
			unsigned char decimal  ;
//			unsigned short filler  ;
			unsigned char value    ;	//	Default value;
		} field;
		struct {
			const unsigned char * data;
		} record;
	};
} TSoderoMySQLResponse, * PSoderoMySQLResponse;

typedef struct SODERO_MYSQL_FIELD {
	const unsigned char * dir;
	const unsigned char * database;
	const unsigned char * tableAlias;
	const unsigned char * tableName;
	const unsigned char * fieldAlias;
	const unsigned char * fieldName;
//	unsigned char filler;
	unsigned short charset;
	unsigned int fieldLength;
	unsigned char fieldType;
	unsigned short fieldFlag;
	unsigned char decimal;
//	unsigned short filler2;
	const unsigned char * value;
} TSoderoMySQLField, * PSoderoMySQLField;

typedef struct SODERO_MYSQL_VALUE {
	TSoderoFlowDatum   value;
	unsigned int       count;	//	command count
	unsigned int       block;	//	block count

	unsigned long long rttValue;
	unsigned int       rttCount;
	unsigned int       l2;
} TSoderoMySQLValue, * PSoderoMySQLValue;

typedef struct SODERO_MYSQL_PREPARE {
	unsigned char  status;
	unsigned int   id;
	unsigned short column;
	unsigned short parameter;
	unsigned char  filler;
	unsigned short warning;
} TSoderoMySQLPrepare, * PSoderoMySQLPrepare;

typedef struct SODERO_MYSQL_PARAMETER {
	unsigned short type     ;
	unsigned short attribute;
	unsigned char  precision;
	unsigned int   length   ;
} TSoderoMySQLParameter, * PSoderoMySQLParameter;

typedef union SODERO_MYSQL_APPLICATION {
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
				TSoderoDoubleDatum traffic;	//	MySQL block count & bytes
				unsigned long long reqFirst;
				unsigned long long reqLast;
				unsigned long long rspFirst;
				unsigned long long rspLast;
				unsigned int       set;		//	total result set count of command's reponse
				unsigned int       col;		//	total col of result set;
				unsigned long long row;		//	Total row count of result set;
			};
		};
		unsigned int reqPending;	//	MySQL Block Pending - Request
		unsigned int rspPending;	//	MySQL Block Pending - Response
//		char * tail;
		unsigned char command;
		unsigned char flow;			//	command flow's branch
		unsigned char step;			//	flow's step
		unsigned char flag;

		char text[0];
	};
	char * buffer[512];
} TSoderoMySQLApplication, * PSoderoMySQLApplication;

typedef union SODERO_MYSQL_PACKET_DETAIL {
	unsigned long long value;
	struct {
		unsigned char command;
		unsigned char block;
	};
} TSoderoMySQLPacketDetail, * PSoderoMySQLPacketDetail;

extern int processMySQLPacket(PSoderoTCPSession session, int dir, PSoderoTCPValue value,
	unsigned int base, const unsigned char * data, unsigned int size, unsigned int length,
	PTCPState state, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether);

extern void updateMySQLState(PSoderoTCPSession session, int dir, PTCPState state);

extern int detectMySQL(PSoderoTCPSession session, PSoderoTCPValue value,
		unsigned int base, const unsigned char * data, unsigned int size, int dir,
		PTCPHeader tcp, PIPHeader ip, PEtherHeader ether);
extern int skipMySQLPacket(PSoderoTCPSession session, int dir, unsigned int size);

#pragma pack(pop)

#endif /* MYSQL_H_ */

/*
http://dev.mysql.com/doc/internals/en/client-server-protocol.html
*/
