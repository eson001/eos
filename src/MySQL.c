/*
 * MySQL.c
 *
 *  Created on: Dec 16, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Type.h"
#include "Common.h"
#include "Core.h"
#include "TCP.h"
#include "Logic.h"
#include "MySQL.h"

#define skipData(count) {                                                                \
	base += sizeof(result->count);                                                       \
	}

#define parseZero() {                                                                    \
		if (data[base]) return false;                                                    \
		base++;                                                                          \
	}

#define parseZEROType(count, type)                                                       \
	while(count >= sizeof(type)) {                                                       \
		if (*(type*)(data + base)) return false;                                         \
		base += sizeof(type);                                                            \
		count -= sizeof(type);                                                           \
	}

#define parseZEROs(count) {                                                              \
		if (base + count > size) return false;                                           \
		int value = count;                                                               \
		parseZEROType(value, long long);                                                 \
		parseZEROType(value, int);                                                       \
		parseZEROType(value, short);                                                     \
		parseZEROType(value, char);                                                      \
	}

#define pickInteger(value) {                                                             \
		if ((base + sizeof(value)) > size) return false;                                 \
		value = *(unsigned long long *)(data + base);                                    \
		base += sizeof(value);                                                           \
	}

#define pickLEInteger(value) {                                                           \
	unsigned char v = data[base];                                                        \
	base ++;                                                                             \
	switch(v) {                                                                          \
	case MYSQL_LE_2:                                                                     \
		value = *(unsigned short *) (data + base);                                       \
		base += sizeof(unsigned short);                                                  \
		break;                                                                           \
	case MYSQL_LE_3:                                                                     \
		value = ((PMySQLHead) (data + base))->length;                                    \
		base += sizeof(int) - 1;                                                         \
		break;                                                                           \
	case MYSQL_LE_8:                                                                     \
		value = *(long long *) (data + base);                                            \
		base += sizeof(long long);                                                       \
		break;                                                                           \
	case 0xFF:                                                                           \
		return false;                                                                    \
	default:                                                                             \
		value = v;                                                                       \
		break;                                                                           \
	}                                                                                    \
}

#define pickBuffer(field) {                                                              \
		if ((base + sizeof(field)) > size) return false;                                 \
		memcpy((void*)field, (const void *)(data + base), sizeof(field));                \
		base += sizeof(field);                                                           \
	}

#define pickMemory(field, count) {                                                       \
		if (count > 0) {                                                                 \
			if ((base + count) > size) return false;                                     \
			memcpy(text, (const void *)(data + base), count);                            \
			field = text;                                                                \
			text += count;                                                               \
			base += count;                                                               \
		}                                                                                \
	}

#define parseInteger(field) {                                                            \
		pickInteger(result->field);                                                      \
	}

#define parseLEInteger(field) {                                                          \
	pickLEInteger(result->field);                                                        \
}

#define pickVARString(field, count) {                                                    \
		pickMemory(result->field, count)                                                 \
		*text++ = 0;                                                                     \
	}

#define parseVARString(field, count) {                                                   \
		pickMemory(result->field, result->count)                                         \
		*text++ = 0;                                                                     \
	}

#define parseFIXString(field) {                                                          \
		if ((base + sizeof(result->field)) > size) return false;                         \
		memcpy((void*)result->field, (const void *)(data + base), sizeof(result->field));\
		base += sizeof(result->field);                                                   \
	}

#define skipNULString() {                                                                \
		while(base < size) {                                                             \
			unsigned char value = data[base++];                                          \
			if (!value) break;                                                           \
		}                                                                                \
	}

#define parseNULString(field) {                                                          \
		int length = cpy_text((char*)text, (const char*)(data + base), size - base);     \
		if ((base + length) >= size) return false;                                       \
		result->field = text;                                                            \
		text += length + 1;                                                              \
		base += length + 1;                                                              \
	}

#define skipLEString() {                                                                 \
		int size;                                                                        \
		pickLEInteger(size);                                                             \
		if (base > size) return false;                                                   \
		base += size;                                                                    \
	}

#define parseLEString(field) {                                                           \
		int size;                                                                        \
		pickLEInteger(size);                                                             \
		if (base > size) return false;                                                   \
		pickMemory(result->field, size)                                                  \
		*text++ = 0;                                                                     \
	}

#define skipEOFString()       {                                                          \
		base = size;                                                                     \
	}

#define parseEOFString(field) {                                                          \
		int length = size - base;                                                        \
		if (length < 0) return false;                                                    \
		memcpy(text, data + base, length);                                               \
		result->field = text;                                                            \
		base = size;                                                                     \
		text += length;                                                                  \
		*text++ = 0;                                                                     \
	}

#define copyField(buffer, value, size) ({                                                \
	char * r = value ? buffer : nullptr;                                                 \
	if (r) {                                                                             \
		int c = snprintf(buffer, size, "%s", value);                                     \
		buffer[c] = 0;                                                                   \
		buffer += c + 1;                                                                 \
	}                                                                                    \
	r;                                                                                   \
})



int parseKeyValue(const unsigned char * data, int size) {
	int base = 0;

	int length;
	while(size > base) {
		pickLEInteger(length);
		if (base + length > size) return false;
		base += length;

		pickLEInteger(length);
		if (base + length > size) return false;
		base += length;
	}
	return true;
}

int parseMySQLField(PSoderopMySQLStatus status, PMySQLSoderoField result, const unsigned char * data, int size) {
//	int base = 0;
//	unsigned char * text = (unsigned char *)(result + 1);
//
//	parseString(dir);
//	parseString(database);
//	parseString(tableAlias);
//	parseString(tableName);
//	parseString(fieldAlias);
//	parseString(fieldName);
//	parseZero();
//	parseInteger(charset);
//	parseInteger(fieldLength);
//	parseInteger(fieldType);
//	parseInteger(fieldFlag);
//	parseInteger(decimal);
//	parseZEROs(2);
//	parseString(value);
//	return base == size;
	return true;
}

int parseMySQLValue(PSoderopMySQLStatus status, PMySQLSoderoValue result, const unsigned char * data, int size) {
	return true;
}

int parseMySQLOK(PSoderopMySQLStatus status, PSoderoResponseMySQL result, const unsigned char * data, int size) {
	int base = 0;
	unsigned char * text = (unsigned char *)(result + 1);
	parseLEInteger(ok.affect);
	parseLEInteger(ok.insert);
	if (status->client & CLIENT_PROTOCOL_41) {
		parseInteger(ok.status);
		parseInteger(ok.warning);
	} else if (status->client & CLIENT_TRANSACTIONS) {
		parseInteger(ok.status);
	}
	if (base == size) return true;

	if (status->client & CLIENT_SESSION_TRACK) {
		parseLEString(ok.info);
		if (base == size) return true;
		if (status->server & SERVER_SESSION_STATE_CHANGED) {
			parseLEString(ok.message);
//			switch(result->ok.message) {
//			case SESSION_TRACK_SYSTEM_VARIABLES:	//	k(LEString) & v(LEString)
//			case SESSION_TRACK_SCHEMA: //	schema(LEString)
//			case SESSION_TRACK_STATE_CHANGE:	//	byte & flag(LEString)
//			}
		}
	} else {
		parseEOFString(ok.info);
	}
	return base == size;
}

int parseMySQLEOF(PSoderopMySQLStatus status, PSoderoResponseMySQL result, const unsigned char * data, int size) {
	int base = 0;
//	unsigned char * text = (unsigned char *)(result + 1);

	parseInteger(eof.count);
	parseInteger(eof.state);
	return base == size;
}

int parseMySQLError(PSoderopMySQLStatus status, PSoderoResponseMySQL result, const unsigned char * data, int size) {
	int base = 0;
	unsigned char * text = (unsigned char *)(result + 1);

	parseInteger(error.code   );
	if (status->client & CLIENT_PROTOCOL_41) {
//		parseZeros(6);	//	#28000
		parseInteger(error.marker );
		parseFIXString (error.status );
	}
	if (base == size) return true;
	parseEOFString(error.message);

	return base == size;
}

int parseMySQLGreetingV10(PSoderoMySQLGreeting result, const unsigned char * data, int size) {
	int base = 0;
	unsigned char * text = (unsigned char *)(result + 1);

	parseNULString(database   );
	parseInteger(id         );
	parseInteger(salt1      );
	parseZero();
	parseInteger(capability1);
	if (base == size) return true;

	parseInteger(charset    );
	if (base == size) return true;

	parseInteger(status     );
	if (base == size) return true;

	parseInteger(capability2);
	if (base == size) return true;

//	if (result->capability & CLIENT_PLUGIN_AUTH)
	parseInteger(length     );
	parseZEROs(10);
//	if (result->capability & CLIENT_SECURE_CONNECTION)
	int left = (result->length ? result->length : SCRAMBLE_LENGTH) - SCRAMBLE_LENGTH_323;
	if (left < (SCRAMBLE_LENGTH - SCRAMBLE_LENGTH_323))
		left = (SCRAMBLE_LENGTH - SCRAMBLE_LENGTH_323);
	pickVARString(salt2, left);
//	if (result->capability & CLIENT_PLUGIN_AUTH      )
	parseNULString (plugin);
	return base == size;
}

int parseMySQLGreetingV9(PSoderoMySQLGreeting result, const unsigned char * data, int size) {
	int base = 0;
	unsigned char * text = (unsigned char *)(result + 1);
	parseNULString (database);
	parseInteger(id      );

	if (base == size) return true;

	parseNULString (plugin  );
	return base == size;
}

int parseMySQLGreeting(PSoderoMySQLGreeting result, const unsigned char * data, int size) {
	int base = 0;
//	unsigned char * text = (unsigned char *)(result + 1);
	parseInteger(protocol);
	switch(result->protocol) {
	case 10:
		return parseMySQLGreetingV10(result, data + base, size - base);
	case  9:
		return parseMySQLGreetingV9(result, data + base, size - base);
	}
	return false;
}

int parseMySQLLoginV41(PSoderopMySQLStatus status, PSoderoMySQLLogin result, const unsigned char * data, int size) {
	int base = 0;
	unsigned char * text = (unsigned char *)(result + 1);

	parseInteger(capability);
	parseInteger(length   );
	parseInteger(charset  );
	parseZEROs(23);
	if (base == size) return true;

	parseNULString (user     );
	if (base == size) return true;

	if (result->capability & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
		parseLEInteger(size);
		parseVARString(pass, size);
	} else if (result->capability & CLIENT_SECURE_CONNECTION) {
		parseInteger(size);
		parseVARString(pass, size);
	} else {
		parseNULString(pass);
	}
	if (base == size) return true;

	if (result->capability & CLIENT_CONNECT_WITH_DB) {
		parseNULString (database );
		if (base == size) return true;
	}
	if (result->capability & CLIENT_PLUGIN_AUTH) {
		parseNULString (plugin );
		if (base == size) return true;
	}

	if (result->capability & CLIENT_CONNECT_ATTRS) {
		unsigned int length;
		pickLEInteger(length);
		if (base + length > size) return false;
//		if (parseKeyValue(data, length))
		base += length;
	}
	return base == size;
}

int parseMySQLLoginV320(PSoderopMySQLStatus status, PSoderoMySQLLogin result, const unsigned char * data, int size) {
	int base = 0;
	unsigned char * text = (unsigned char *)(result + 1);

	result->capability = 0;
	memcpy(&result->capability, data + base, 2);
	base += 2;
	result->length     = 0;
	memcpy(&result->length    , data + base, 3);
	base += 3;

	if (base == size) return true;
	parseNULString(user);

	if (base == size) return true;
	parseNULString(pass);

	if (base == size) return true;
	if (result->capability & CLIENT_CONNECT_WITH_DB) {
		parseNULString(database);
	}

	return base == size;
}

int parseMySQLLoginRequest(PSoderopMySQLStatus status, PSoderoMySQLLogin result, const unsigned char * data, int size) {
	unsigned short capability = *(unsigned short*) data;
	if (capability & CLIENT_PROTOCOL_41)
		return parseMySQLLoginV41(status, result, data, size);
	else
		return parseMySQLLoginV320(status, result, data, size);
}

int parseMySQLLogingResponse(PSoderopMySQLStatus status, PSoderoResponseMySQL result, const unsigned char * data, int size) {
	int base = 0;
	parseInteger(type);
	switch(result->type) {
	case MYSQL_STATUS_OK:
		return parseMySQLOK   (status, result, data + base, size - base);
	case MYSQL_STATUS_ERROR:
		return parseMySQLError(status, result, data + base, size - base);
	}
	return false;
}

int parseMySQLCommandRequest(PSoderopMySQLStatus status, PSoderoMySQLApplication application, PSoderoMySQLCommand result, const unsigned char * data, int size) {
	int base = 0;
	unsigned char * text = (unsigned char *)(result + 1);

	parseInteger(command);
	switch(result->command) {
	case MYSQL_CMD_SLEEP           :	//	No parameter
		base = size;
		break;
	case MYSQL_CMD_QUIT            :	//	No parameter
		break;
	case MYSQL_CMD_INIT_DB         :	//	obsoleted, same as sql: USE database;
		parseNULString (database);
		break;
	case MYSQL_CMD_QUERY           :
		parseEOFString (sql);
		break;
	case MYSQL_CMD_FIELD_LIST      :	//	obsoleted, same as sql: SHOW [FULL] FIELDS FROM ...
		parseNULString (table);
		if (base == size) return true;
		parseNULString (field);
		break;
	case MYSQL_CMD_CREATE_DB       :	//	obsoleted, same as sql: CREATE DATABASE
		parseNULString (database);
		break;
	case MYSQL_CMD_DROP_DB         :	//	obsoleted, same as sql: DROP DATABASE
		parseNULString (database);
		break;
	case MYSQL_CMD_REFRESH         :	//	obsoleted, same as sql: FLASH
		parseInteger(refresh);
		break;
	case MYSQL_CMD_SHUTDOWN        :
		parseInteger(shutdown);
		break;
	case MYSQL_CMD_STATISTICS      :	//	No parameter
		break;
	case MYSQL_CMD_PROCESS_INFO    :	//	No parameter
		break;
	case MYSQL_CMD_CONNECT         :	//	No parameter
		break;
	case MYSQL_CMD_PROCESS_KILL    :
		parseInteger(id);
		break;
	case MYSQL_CMD_DEBUG           :	//	No parameter
		break;
	case MYSQL_CMD_PING            :	//	No parameter
		break;
	case MYSQL_CMD_TIME            :	//	No parameter
	case MYSQL_CMD_DELAYED_INSERT  :	//	No parameter
	case MYSQL_CMD_CHANGE_USER     :
		parseNULString(change.user);
		parseInteger(change.salt);
		parseZero();
		parseNULString(change.salt2);
		parseNULString(change.database);
		parseInteger(change.charset);
		break;
	case MYSQL_CMD_BINLOG_DUMP     :
		parseInteger(log.start);
		parseInteger(log.flags);
		parseInteger(log.id);
		if (base == size) return true;
		parseNULString(log.file);
		break;
	case MYSQL_CMD_TABLE_DUMP      :
		parseNULString(dump.database);
		parseNULString(dump.table);
		break;
	case MYSQL_CMD_CONNECT_OUT     :	//	No parameter
	case MYSQL_CMD_REGISTER_SLAVE  :
		parseInteger(slave.id);
		parseNULString(slave.masterIP);
		parseNULString(slave.masterUser);
		parseNULString(slave.masterPass);
		parseInteger(slave.masterPort);
		parseInteger(slave.security);
		break;
	case MYSQL_CMD_PREPARE         :
		parseNULString(sql);
		break;
	case MYSQL_CMD_EXECUTE         :
		parseInteger(execute.id);
		parseInteger(execute.flag);
		parseInteger(execute.reserved);
		break;
	case MYSQL_CMD_LONG_DATA       :
		parseInteger(data.id);
		parseInteger(data.serial);
		parseInteger(data.type);
		parseNULString(data.payload);
		break;
	case MYSQL_CMD_CLOSE_STMT      :
		parseInteger(id);
		break;
	case MYSQL_CMD_RESET_STMT      :
		parseInteger(id);
		break;
	case MYSQL_CMD_SET_OPTION      :
		parseInteger(option);
		break;
	case MYSQL_CMD_FETCH_STMT      :
		parseInteger(fetch.id);
		parseInteger(fetch.count);
		break;
	case MYSQL_COM_DAEMON          :	//	No parameter
		break;
	case MYSQL_COM_BINLOG_DUMP_GTID:
		parseInteger(gtid.flags);
		parseInteger(gtid.id);
		parseInteger(gtid.size);
//		parseMemory(gtid.name, gtid.size);
		skipData(gtid.size);
		parseInteger(gtid.position);
		parseInteger(gtid.count);
//		parseMemory(gtid.value, gtid.count);
		skipData(gtid.count);
		break;
	case MYSQL_COM_RESET_CONNECTION:	//	No parameter
		break;
	}

	return base == size;
}

int parseMySQLResultHead(PSoderopMySQLStatus status, PSoderoResponseMySQL result, const unsigned char * data, int size) {
	int base = 0;
//	unsigned char * text = (unsigned char *)(result + 1);

	parseLEInteger(header.field);
	if (base == size) return true;
	parseLEInteger(header.count);

	return base == size;
}

int parseMySQLResultColumn(PSoderopMySQLStatus status, PSoderoResponseMySQL result, const unsigned char * data, int size) {
	return false;
}

int parseMySQLResultRow(PSoderopMySQLStatus status, PSoderoResponseMySQL result, const unsigned char * data, int size) {
	return false;
}

int parseMySQLCols(PSoderopMySQLStatus status, PSoderoMySQLApplication application, PSoderoResponseMySQL result,
		const unsigned char * data, int size, int next) {
	int base = 0;
//	unsigned char * text = (unsigned char *)(result + 1);

	parseInteger(type);
	switch(result->type) {
		case MYSQL_STATUS_EOF:
			if (parseMySQLEOF(status, result, data + base, size - base)) {
				application->step = next;
				return true;
			}
			break;
	}
	char buffer[MYSQL_BUFFER_SIZE];
	PMySQLSoderoField field = (PMySQLSoderoField) buffer;
	return parseMySQLField(status, field, data, size);
}

int parseMySQLRows(PSoderopMySQLStatus status, PSoderoMySQLApplication application, PSoderoResponseMySQL result,
		const unsigned char * data, int size, int next, int head) {
	int base = 0;
//	unsigned char * text = (unsigned char *)(result + 1);

	parseInteger(type);
	switch(result->type) {
		case MYSQL_STATUS_EOF:
			if (parseMySQLEOF(status, result, data + base, size - base)) {
				if (result->eof.state & SERVER_MORE_RESULTS_EXISTS)
					application->step = head;
				else
					application->step = next;
				return true;
			}
			break;
		case MYSQL_STATUS_ERROR:
			if (parseMySQLEOF(status, result, data + base, size - base)) {
				application->step = next;
				return true;
			}
			break;
	}
	char buffer[MYSQL_BUFFER_SIZE];
	PMySQLSoderoValue value = (PMySQLSoderoValue) buffer;
	return parseMySQLValue(status, value, data, size);
}

int parseMySQLResultset(PSoderopMySQLStatus status, PSoderoMySQLApplication application, PSoderoResponseMySQL result,
		const unsigned char * data, int size) {
//	int base = 0;
//	unsigned char * text = (unsigned char *)(result + 1);
	switch(application->step) {
	case MYSQL_RS_HEADER:
		if (parseMySQLResultHead(status, result, data, size)) {
			application->set++;
			application->flow = MYSQL_FLOW_CMD_RESULTSET;
			application->step = MYSQL_RS_COLUMN;
			return true;
		}
		break;
	case MYSQL_RS_COLUMN:
		if (parseMySQLCols(status, application, result, data, size, MYSQL_RS_ROW)) {
			if (result->type == MYSQL_STATUS_EOF)
				application->step = MYSQL_RS_ROW;
			else
				application->col++;
			return true;
		}
		break;
	case MYSQL_RS_ROW:
		if (parseMySQLRows(status, application, result, data, size, MYSQL_RS_DONE, MYSQL_RS_HEADER)) {
			if (result->type == MYSQL_STATUS_EOF) {
				if (result->eof.state & SERVER_MORE_RESULTS_EXISTS)
					application->step = MYSQL_RS_HEADER;
				else
					application->step = MYSQL_RS_DONE;
			} else
				application->row++;
			return true;
		}
		break;
	case MYSQL_RS_DONE:
		return false;
	}
	return false;
}

int parseMySQLCommandResponse(PSoderopMySQLStatus status, PSoderoMySQLApplication application, PSoderoResponseMySQL result,
		const unsigned char * data, int size) {
	int base = 0;
//	unsigned char * text = (unsigned char *)(result + 1);

	switch(application->flow) {
	case MYSQL_FLOW_NONE:
		parseInteger(type);
		switch(result->type) {
			case MYSQL_STATUS_OK:			//	OK Packet
				if (parseMySQLOK(status, result, data + base, size - base)) {
					application->flow = MYSQL_FLOW_DONE;
					return true;
				}
				break;
			case MYSQL_STATUS_INFILE:
				application->flow = MYSQL_FLOW_CMD_INLINE;
				application->step = MYSQL_IL_REQ;
				break;
			case MYSQL_STATUS_ERROR:		//	Err Packet
				if (parseMySQLError(status, result, data + base, size - base)) {
					application->flow = MYSQL_FLOW_DONE;
					return true;
				}
				break;
			default:
				application->flow = MYSQL_FLOW_CMD_RESULTSET;
				application->step = MYSQL_RS_HEADER;
				if (parseMySQLResultset(status, application, result, data, size)) {
					if (application->step == MYSQL_RS_DONE)
						application->flow = MYSQL_FLOW_DONE;
					return true;
				}
				break;
		}
		break;
	case MYSQL_FLOW_CMD_RESULTSET:
		if (parseMySQLResultset(status, application, result, data, size)) {
			if (application->step == MYSQL_RS_DONE)
				application->flow = MYSQL_FLOW_DONE;
			return true;
		}
		break;
	case MYSQL_FLOW_CMD_INLINE   :
		parseInteger(type);
		switch(result->type) {
			case MYSQL_STATUS_OK:			//	OK Packet
				if (parseMySQLOK(status, result, data + base, size - base)) {
					application->flow = MYSQL_FLOW_DONE;
					return true;
				}
				break;
			case MYSQL_STATUS_ERROR:		//	Err Packet
				if (parseMySQLError(status, result, data + base, size - base)) {
					application->flow = MYSQL_FLOW_DONE;
					return true;
				}
				break;
			default:
				break;
		}
		break;
	case MYSQL_FLOW_DONE:
		break;
	}
	application->flow = MYSQL_FLOW_DONE;
	return false;
}

void updateMySQLState(PSoderoTCPSession session, int dir, PTCPState state) {

}

int detectMySQL(PSoderoTCPSession session, PSoderoTCPValue value,
	unsigned int base, const unsigned char * data, unsigned int size, int dir,
	PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {

	//	First Packet ?
	if ((session->traffic.incoming.bytes + session->traffic.outgoing.bytes) > size) {
//		printf("MySQL: Error detect on packet data %u - %u\n",
//			session->traffic.incoming.bytes, session->traffic.outgoing.bytes);
		return DETECT_NEGATIVE;
	}
	if (size < sizeof(TMySQLHead)) {
//		printf("MySQL: Error detect on packet size: %d\n", size);
		return DETECT_NEGATIVE;
	}

	const PMySQLHead head = (PMySQLHead)data;
	data += sizeof(TMySQLHead);
	size -= sizeof(TMySQLHead);

	if (head->serial) {
//		printf("MySQL: Error detect on packet serial\n");
		return DETECT_NEGATIVE;
	}
	if (size < head->length) {
//		printf("MySQL: Error Detect packet size %d - %u\n", size, head->length);
		return DETECT_NEGATIVE;
	}

	char buffer[MYSQL_BUFFER_SIZE];
	PSoderoMySQLGreeting result = (PSoderoMySQLGreeting)buffer;
	if (parseMySQLGreeting(result, data, size)) {
		session->value.mysql.protocol = result->protocol;
		session->value.mysql.server = result->capability;
		session->value.mysql.tail = session->value.buffer;
		if (result->database) {
			int count = cpy_text(session->value.mysql.tail, (const char *)result->database, 32);
			session->value.mysql.version = session->value.mysql.tail;
			session->value.mysql.tail += count + 1;
		};
		return sizeof(TMySQLHead) + head->length;
	}

	return DETECT_NEGATIVE;
}


int parseMySQLLogon(PSoderoMySQLPacketDetail detail, PSoderoTCPSession session, int dir,
	PMySQLHead const head, const unsigned char * data, int size, int total) {
	//	Login request or response must in one packet.
	if (size < total) {
		printf("MySQL: Invalid packet Size %d - %u\n", size, total);
		return DETECT_NEGATIVE;
	}

	do {
		if (dir > 0) {
		//	Check login response
//			if (session->value.mysql.login.rspTime) return DETECT_NEGATIVE;
//			if (dir != session->key.dir) return DETECT_NEGATIVE;
			char buffer[MYSQL_BUFFER_SIZE];
			PSoderoResponseMySQL result = (PSoderoResponseMySQL) buffer;
			if (parseMySQLLogingResponse(&session->value.mysql, result, data, size)) {
				switch(result->type) {
				case MYSQL_STATUS_OK:
					session->value.mysql.status = MYSQL_LOGIN_SUCCESS;
					break;
				case MYSQL_STATUS_ERROR:
					session->value.mysql.status = MYSQL_LOGIN_FAILURE;
					break;
				default:
					printf("MySQL: Login response type is invalid - %x\n", result->type);
					return PARSE_ERROR;
				}
				session->value.mysql.login.rspTime = gTime;
				PSoderoMySQLApplication application = takeApplication(sizeof(TSoderoMySQLApplication));
				detail->command++;
				gMySQLTake++;
				newApplication((PSoderoApplication)application, (PSoderoSession)session);
//				printf("MySQL: create & close login application %p with session %p @ %llu\n", application, session, gPacket);
				char * tail = application->text;
				application->command = MYSQL_COM_SODERO_EXTEND;
				application->status = session->value.mysql.status;
				application->reqTime = session->value.mysql.login.reqTime;
				application->rspTime = session->value.mysql.login.rspTime;
				application->user     = copyField(tail, session->value.mysql.login.user    , 128);
				application->database = copyField(tail, session->value.mysql.login.database, 128);
				sodero_pointer_add(getClosedApplications(), application);
				session->session = nullptr;
				session->value.mysql.serial = 0;
				application = nullptr;
				bzero(&session->value.mysql.login, sizeof(session->value.mysql.login));
				return size + sizeof(*head);
			} else {
				printf("MySQL: Login response parse failure\n");
				return PARSE_ERROR;
			}
			break;
		}

		if (dir < 0) {
			//	Check login request, must in one packet
//			if (session->value.mysql.login.reqTime) return DETECT_NEGATIVE;
//			if (dir == session->key.dir) return DETECT_NEGATIVE;
			char buffer[MYSQL_BUFFER_SIZE];
			PSoderoMySQLLogin result = (PSoderoMySQLLogin) buffer;
			if(parseMySQLLoginRequest(&session->value.mysql, result, data, size)) {
				session->value.mysql.client = result->capability;
				session->value.mysql.login.reqTime = gTime;
				char * tail = session->value.mysql.tail;
				session->value.mysql.login.user     = copyField(tail, result->user    , 128);
				session->value.mysql.login.database = copyField(tail, result->database, 128);
				return size + sizeof(*head);
			} else {
				printf("MySQL: Login request parse failure\n");
				return PARSE_ERROR;
			}
		}
	} while (false);
	printf("MySQL: logon dir error\n");
	return PARSE_ERROR;
}

int parseMySQLCommand(PSoderoMySQLPacketDetail detail, PSoderoTCPSession session, int dir,
	PMySQLHead const head, const unsigned char * data, int size, int total) {
	PSoderoMySQLApplication application = session->session;
	if (dir > 0) {	//	Response
		if (application) {
//				if (((application->rspCount + 1) & 0xFF) != head->serial)
//					return PARSE_ERROR;
			processA(&application->traffic.incoming, total);
			if (!application->rspFirst)
				application->rspFirst = gTime;
			if (application->rspLast < gTime)
				application->rspLast = gTime;
			if (total > size)
				application->rspPending += total - size;
		} else {
			//	ToDo: Error Protocol
			printf("MySQL: Empty applicaton on response\n");
			return PARSE_ERROR;
		}

		char buffer[MYSQL_BUFFER_SIZE];
		PSoderoResponseMySQL result = (PSoderoResponseMySQL) buffer;
		if (parseMySQLCommandResponse(&session->value.mysql, application, result, data, total)) {
			if (application->flow == MYSQL_FLOW_DONE) {
//					printf("MySQL: close command %d application %p with session %p @ %llu\n",
//							application->command, application, session, gPacket);
				sodero_pointer_add(getClosedApplications(), application);
				session->session = nullptr;
				session->value.mysql.serial = 0;
				application = nullptr;
			}
			return (size <= total ? size : total) + sizeof(*head);
		}
		printf("MySQL: parse command response failure\n");
		return PARSE_ERROR;
	}

	if (dir < 0) {	//	Request
		if (application) {
			//	Check subsequent packets
//				if (((application->reqCount + 1) & 0xFF) != head->serial)
//					return PARSE_ERROR;
			if (application->flow == MYSQL_FLOW_CMD_INLINE) {
				if (total == 0)
					application->step = MYSQL_IL_RSP;
				return total + sizeof(*head);
			}
		} else {
			//	The request first packet's serial must be ZERO.
			if (head->serial) {
				printf("MySQL: Error command first packet\n");
				return DETECT_NEGATIVE;
			}
		}

		char buffer[MYSQL_BUFFER_SIZE];
		PSoderoMySQLCommand result = (PSoderoMySQLCommand) buffer;
		if (parseMySQLCommandRequest(&session->value.mysql, application, result, data, total)) {
			application = takeApplication(sizeof(TSoderoMySQLApplication));
			detail->command++;
			gMySQLTake++;
			newApplication((PSoderoApplication)application, (PSoderoSession)session);
//				printf("MySQL: create command %d application %p with session %p @ %llu\n",
//						application->command, application, session, gPacket);
			application->command = result->command;
			session->session = application;
			session->value.mysql.serial = head->serial;

			processA(&application->traffic.outgoing, total);
			if (!application->reqFirst)
				application->reqFirst = gTime;
			if (application->reqLast < gTime)
				application->reqLast = gTime;
			if (total > size)
				application->reqPending += total - size;

			return (size <= total ? size : total) + sizeof(*head);
		}
		printf("MySQL: parse command request failure\n");
		return PARSE_ERROR;
	}
	printf("MySQL: command dir error\n");
	return PARSE_ERROR;
}

int parseMySQLApplication(PSoderoMySQLPacketDetail detail, PSoderoTCPSession session,
	int dir, const unsigned char * data, int size, int length) {

	PMySQLHead head = (PMySQLHead)data;
	data += sizeof(TMySQLHead);
	size -= sizeof(TMySQLHead);
	length -= sizeof(TMySQLHead);
	int total = head->length;

	PSoderoMySQLApplication application = session->session;
	if (application) {
		if ((session->value.mysql.serial & 0xFF) != head->serial) {
			printf("MySQL: invalid block serial %u to %u @ %u\n", session->value.mysql.serial, head->serial, gTotal.count);
			sodero_pointer_add(getClosedApplications(), application);
			printf("MySQL: abort command %d application %p with session %p @ %u\n",
					application->command, application, session, gTotal.count);
			session->value.mysql.serial = 0;
			session->session = nullptr;
			application = nullptr;
			return PARSE_ERROR;
		}
	}

//	Incomplete MySQL packets, and there is not enough number of bytes
	if ((size < total) && (size < MYSQL_BUFFER_SIZE)) return PARSE_PENDING;

	if (session->value.mysql.status) {
		//	Already login, process MySQL Command
		return parseMySQLCommand(detail, session, dir, head, data, size, total);
	}

	return parseMySQLLogon(detail, session, dir, head, data, size, total);
}

int parseMySQLPacket(PSoderoMySQLPacketDetail detail, PSoderoTCPSession session, int dir,
	const unsigned char * data, int size, int length) {

	int bytes = size;
	while(size > (int) sizeof(TMySQLHead)) {
		int result = parseMySQLApplication(detail, session, dir, data, size, length);
		if (result > 0) {
			session->value.mysql.serial++;
			detail->block++;
			data += result;
			size -= result;
			length -= result;
			PSoderoMySQLApplication application = session->session;
			if (application) continue;
		}
		if (result < 0) return result;
		break;	//	result is ZERO(PENDING)
	}
	PSoderoMySQLApplication application = session->session;
	if (application) {

	}
	return bytes - size;
}

int processMySQLPacket(PSoderoTCPSession session, int dir, PSoderoTCPValue value,
	unsigned int base, const unsigned char * data, unsigned int size, unsigned int length,
	PTCPState state, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {

	int done = 0;
	int total = size + value->offset - base;

	PNodeValue sourNode = takeIPv4Node((TMACVlan){{ether->sour, ether->vlan}}, ip->sIP);
	PNodeValue destNode = takeIPv4Node((TMACVlan){{ether->dest, ether->vlan}}, ip->dIP);
	if (dir > 0) {
		if (sourNode) {
			processA(&sourNode->l4.mysql.outgoing.value, size);
			sourNode->l4.mysql.outgoing.l2 += length;
			sourNode->l4.mysql.outgoing.rttValue += state->rttTime;
			sourNode->l4.mysql.outgoing.rttCount += state->rtt;
		}
		if (destNode) {
			processA(&destNode->l4.mysql.incoming.value, size);
			destNode->l4.mysql.incoming.l2 += length;
			destNode->l4.mysql.incoming.rttValue += state->rttTime;
			destNode->l4.mysql.incoming.rttCount += state->rtt;
		}
	};
	if (dir < 0) {
		if (sourNode) {
			processA(&sourNode->l4.mysql.outgoing.value, size);
			sourNode->l4.mysql.outgoing.l2 += length;
			sourNode->l4.mysql.outgoing.rttValue += state->rttTime;
			sourNode->l4.mysql.outgoing.rttCount += state->rtt;
		}
		if (destNode) {
			processA(&destNode->l4.mysql.incoming.value, size);
			destNode->l4.mysql.incoming.l2 += length;
			destNode->l4.mysql.incoming.rttValue += state->rttTime;
			destNode->l4.mysql.incoming.rttCount += state->rtt;
		}
	}

	PSoderoMySQLApplication application = session->session;
	while (application) {
		//	Check Session Pending Data
		if (dir > 0) {	//	Request
			if (application->reqPending) {
				if (application->reqPending >= total) {
					application->reqPending -= total;
					return total;
				}
				done  = application->reqPending;
				application->reqPending = 0;
			}
			break;
		}
		if (dir < 0) {	//	Response
			if (application->rspPending) {
				if (application->rspPending < size) {
					application->rspPending -= size;
					return size;
				}
				done  = application->rspPending;
				application->rspPending = 0;
			}
			break;
		}
		printf("MySQL: parse application dir error\n");
		return PARSE_ERROR;
	}

	base   += done;
	total  -= done;

	//	The remaining of bytes is too few
	if (total < sizeof(TMySQLHead)) return done;

	TSoderoMySQLPacketDetail detail = {0};

	int result = 0;
	//	Now, there must be a MySQL packet is parsed.
	if (base < value->offset) {
		//	Merge legacy data and current packet
		unsigned char buffer[MYSQL_BUFFER_SIZE];
		int bytes = pickData(buffer, sizeof(buffer), value, base, data, size);
		result = parseMySQLPacket(&detail, session, dir, buffer, bytes, total);
	} else {
		//	Directly process current packet
		const unsigned char * buffer = data + base - value->offset;
		result = parseMySQLPacket(&detail, session, dir, buffer, total, total);
	}
	if (result > 0) {
		if (sourNode) {
			sourNode->l4.mysql.outgoing.count += detail.command;
			sourNode->l4.mysql.outgoing.block += detail.block  ;
		}
		if (destNode) {
			destNode->l4.mysql.incoming.count += detail.command;
			sourNode->l4.mysql.outgoing.block += detail.block  ;
		}
//		if (dir > 0) {
//			if (sourNode) {
//				sourNode->l4.mysql.outgoing.count += detail.command;
//				sourNode->l4.mysql.outgoing.block += detail.block  ;
//			}
//			if (destNode) {
//				destNode->l4.mysql.incoming.count += detail.command;
//				sourNode->l4.mysql.outgoing.block += detail.block  ;
//			}
//		};
//		if (dir < 0) {
//			if (sourNode) {
//				sourNode->l4.mysql.outgoing.count += detail.command;
//				sourNode->l4.mysql.outgoing.block += detail.block  ;
//			}
//			if (destNode) {
//				destNode->l4.mysql.incoming.count += detail.command;
//				sourNode->l4.mysql.outgoing.block += detail.block  ;
//			}
//		}
	}
	return result < 0 ? result : done + result;
}

int skipMySQLPacket(PSoderoTCPSession session, int dir, unsigned int size) {
	return PARSE_ERROR;
}
