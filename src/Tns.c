/*
 * Tns.c
 *
 *  Created on: Apr 27, 2015
 *      Author: Yang Liu
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "Type.h"
#include "Common.h"
#include "Core.h"
#include "TCP.h"
#include "Logic.h"
#include "Tns.h"

#define USER_TOKEN  "(USER="
#define DBNAME_TOKEN   "(SERVICE_NAME="

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

#   define MAX(a, b) (((a) >= (b) ? (a) : (b)))
#   define MIN(a, b) (((a) < (b) ? (a) : (b)))

void cursor_rollback(struct cursor *cursor, size_t n)
{
    cursor->cap_len += n;
    cursor->head -= n;
}

#define DROP_FIX(cursor, len)                                                       \
    if (cursor->cap_len < len)                                                      \
        return 0;                                                     \
    cursor_drop(cursor, len);

#define NB_ELEMS(array) (sizeof array / sizeof array[0])

unsigned char read_u8(struct cursor *cursor)
{
    assert(cursor->cap_len >= 1);
    cursor->cap_len --;
    return *cursor->head++;
}

unsigned short read_u16(struct cursor *cursor)
{
    unsigned int a = read_u8(cursor);
    unsigned int b = read_u8(cursor);
    return (a << 8) | b;
}

unsigned int read_u24(struct cursor *cursor)
{
    unsigned int  a = read_u8(cursor);
    unsigned int  b = read_u8(cursor);
    unsigned int  c = read_u8(cursor);
    return (a << 16) | (b << 8) | c;
}


unsigned int read_u32(struct cursor *cursor)
{
    unsigned int a = read_u16(cursor);
    unsigned int b = read_u16(cursor);
    return (a << 16) | b;
}

unsigned long read_u64(struct cursor *cursor)
{
    unsigned long a = read_u32(cursor);
    unsigned long b = read_u32(cursor);
    return (a << 32) | b;
}

void cursor_drop(struct cursor *cursor, size_t n)
{
    if (cursor->cap_len <= n)
	return ;
		
//    assert(cursor->cap_len >= n);
    cursor->cap_len -= n;
    cursor->head += n;
}

void cursor_copy(void *dst, struct cursor *cursor, size_t n)
{
    assert(cursor->cap_len >= n);
    memcpy(dst, cursor->head, n);
    cursor->head += n;
    cursor->cap_len -= n;
}

int cursor_read_fixed_string(struct cursor *cursor, char *out_buf, size_t size_buf,
        size_t str_len)
{
    if (cursor->cap_len < str_len) return -1;
    if (!out_buf) {
        cursor_drop(cursor, str_len);
        return 0;
    }
    unsigned copied_len = MIN(str_len, size_buf - 1);
    cursor_copy(out_buf, cursor, copied_len);
    out_buf[copied_len] = '\0';
    if (copied_len < str_len) {
        cursor_drop(cursor, str_len - copied_len);
    }
    return copied_len;
}

/* Read a string prefixed by 1 byte size
 * Size  String-------------
 * 0x04  0x41 0x42 0x42 0x40
 */
static bool cursor_read_variable_string(struct cursor *cursor,
        char *buf, size_t size_buf, unsigned *out_str_len)
{
    unsigned str_len;
    CHECK(1);
    str_len = read_u8(cursor);
    if (out_str_len) *out_str_len = str_len;
    int ret = cursor_read_fixed_string(cursor, buf, size_buf, str_len);
    if (ret == -1) return false;
    else return true;
}

void string_buffer_ctor(struct string_buffer *buffer, char *head, size_t size)
{
    assert(size > 0);
    buffer->head = head;
    buffer->pos = 0;
    // We keep a byte for '\0'
    buffer->size = size - 1;
    buffer->truncated = false;
    buffer->head[0] = '\0';
}

size_t buffer_append_stringn(struct string_buffer *buffer, char const *src, size_t src_max)
{
    if (!buffer) return 0;
    size_t left_size = buffer->size - buffer->pos;
    size_t src_len = strnlen(src, src_max);
    size_t size = MIN(left_size, src_len);
    memcpy(buffer->head + buffer->pos, src, size);
    if (size != src_len)
        buffer->truncated = true;
    buffer->pos += size;
    return size;
}

char *buffer_get_string(struct string_buffer *buffer)
{
    assert(buffer->pos <= buffer->size);
    buffer->head[buffer->pos] = '\0';
    char* first_null = rawmemchr(buffer->head, '\0');
    if (first_null != (buffer->head + buffer->pos)) {
        buffer->pos = first_null - buffer->head;
    }
    return buffer->head;
}

/* Read a string splitted in chunk prefixed by 1 byte size
 * Chunk have a maximum size of 0x40 bytes
 * If there are more than one chunk, a 0x00 end it
 *
 * a multi chunked string
 *
 * Size  String---------    Size  String  End
 * 0x40  0x41 0x42 0x..     0x01  0x49    0x00
 *
 * a single chunked string
 *
 * Size  String---------
 * 0x20  0x41 0x42 0x..
 *
 * The global size might be unknown, so we try to guess it. We will have a parse problem
 * for string of size 0x40
 */
static bool cursor_read_chunked_string(struct cursor *cursor,
        char *buf, size_t size_buf, size_t max_chunk)
{
    unsigned str_len = 0;
    struct string_buffer string_buf;
    if (buf) string_buffer_ctor(&string_buf, buf, size_buf);
    do {
        if (cursor->cap_len < 1) break;
        str_len = read_u8(cursor);
        size_t available_bytes = MIN(cursor->cap_len, str_len);
        if (buf) buffer_append_stringn(&string_buf, (char const *)cursor->head, available_bytes);
        cursor_drop(cursor, available_bytes);
    } while (str_len >= max_chunk);
    // There seems to be an null terminator when string length is > 0x40
    // However, it can be a flag after the string. Ignore it for now.
    if (buf) buffer_get_string(&string_buf);
    return true;
}

bool cursor_read_fixed_int_n(struct cursor *cursor, unsigned long *out_res, unsigned len)
{
    unsigned long res;
    if (cursor->cap_len < len) return false;
    switch (len) {
        case 0:
            res = 0;
            break;
        case 1:
            res = read_u8(cursor);
            break;
        case 2:
            res = read_u16(cursor);
            break;
        case 3:
            res = read_u24(cursor);
            break;
        case 4:
            res = read_u32(cursor);
            break;
        case 8:
            res = read_u64(cursor);
            break;
        default:
            return false;
    }
    if (out_res) *out_res = res;
    return true;
}

/* Read an int prefixed by 1 byte size
 * | Size | Int------ |
 * | 0x02 | 0x01 0xdd |
 */
static bool cursor_read_variable_int(struct cursor *cursor, uint_least64_t *res)
{
    CHECK(1);
    unsigned len =read_u8(cursor);
    return cursor_read_fixed_int_n(cursor, res, len);
}

static char is_delim(char c)
{
    return c == ')' || c == '\0'; 
}

static void copy_token(char *dst, size_t dst_len, char const *src, size_t src_len)
{
    assert(dst_len > 0);
    while (src_len > 0 && dst_len > 1 && !is_delim(*src)) {
        *dst++ = *src++;
        dst_len --;
        src_len --;
    }
    *dst = '\0';
}

int parseOracleConnect(PSoderoOracleConnect result, struct cursor *cursor, int size) {

       int pdu_len = cursor->cap_len;

       if (pdu_len < 26)
       {
           return PARSE_ERROR;
       }
       cursor_drop(cursor, 16);
       result->data_length = read_u16(cursor);
       result->offset = read_u16(cursor);
       
       if (result->offset > pdu_len || result->offset < 26 + 8) 
       {
           LogErr("The TNS connect packet error, offset = %x, pdu_len=%d,%x", result->offset, cursor->cap_len,result->data_length);
           return PARSE_ERROR;
       }
       if (result->data_length + result->offset > pdu_len + 8) 
       {
           return PARSE_ERROR;
       }
       cursor_drop(cursor, result->offset - 20 - 8);  
       
       char const *data_end = (char const *)(cursor->head + result->data_length);
       char const *str;
       if (NULL != (str = strstr((char const *)cursor->head, USER_TOKEN))) {
            str += strlen(USER_TOKEN);
            copy_token(result->user, sizeof(result->user), str, data_end-str);
        }
        if (NULL != (str = strstr((char const *)cursor->head, DBNAME_TOKEN))) {
            str += strlen(DBNAME_TOKEN);
            copy_token(result->dbname, sizeof(result->dbname), str, data_end-str);
        }

        LogDbg("user=%s, DBname=%s", result->user, result->dbname);
        return PARSE_SUCCESS;

}

int detectTNS(PSoderoTCPSession session, PSoderoTCPValue value,
	unsigned int base, const unsigned char * data, unsigned int size, int dir,
	PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {

       TOracleHead head;
       struct cursor cursor; 

       if ((ntohs(tcp->sour) != 1521) && (ntohs(tcp->dest)!= 1521))
       {
           return DETECT_NEGATIVE;
       }
       
	//	First Packet ?
	if ((session->traffic.incoming.bytes + session->traffic.outgoing.bytes) > size) {
		LogErr("MySQL: Error detect on packet data %u - %u\n",
			session->traffic.incoming.bytes, session->traffic.outgoing.bytes);
		return DETECT_NEGATIVE;
	}
	if (size < sizeof(TOracleHead)) {
		LogErr("MySQL: Error detect on packet size: %d\n", size);
		return DETECT_NEGATIVE;
	}

       cursor.cap_len = size;
       cursor.head = data;
       
       head.length = read_u16(&cursor);
       head.check_sum = read_u16(&cursor);
       head.type = read_u8(&cursor);
       head.reserved = read_u8(&cursor);
       head.header_check_sum = read_u16(&cursor);

	//data += sizeof(TOracleHead);
	//size -= sizeof(TOracleHead);

	if (head.check_sum || head.header_check_sum) {
		LogErr("%s","check number is not zero\n");
		return DETECT_NEGATIVE;
	}

	char buffer[MYSQL_BUFFER_SIZE];
	PSoderoOracleConnect result = (PSoderoOracleConnect)buffer;
	if (head.type == 1)
	{
	    if (parseOracleConnect(result, &cursor, size - sizeof(TOracleHead)) ==PARSE_SUCCESS)
	    {
	        session->value.tns.tail = session->value.buffer;
	        session->value.tns.login.reqTime = gTime;
	        char * tail = session->value.mysql.tail;
	        session->value.tns.login.user     = copyField(tail, result->user    , 64);
	        session->value.tns.login.database = copyField(tail, result->dbname, 64);
	        return sizeof(TOracleHead) + head.length;
	    }
	}
	else
	{
	    session->value.tns.tail = session->value.buffer;
	    session->value.tns.login.reqTime = gTime;
	    char * tail = session->value.mysql.tail;

	    return sizeof(TOracleHead) + head.length;
	}

	return DETECT_NEGATIVE;
}

static unsigned char parse_query_header(struct cursor *cursor)
{
    unsigned char  const *new_head = cursor->head;
    unsigned char  query_size = 0;
    for (unsigned i = 0; i < 10 && new_head; i++) {
        char pattern[8] = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        new_head = memmem(cursor->head, cursor->cap_len, pattern, sizeof(pattern));
        if (new_head) {
            size_t gap_size = new_head - cursor->head;
            DROP_FIX(cursor, gap_size + sizeof(pattern));
            if (i == 0) {
                query_size = read_u8(cursor);
            }
        }
    };
    return query_size;
}

unsigned char cursor_peek_u8(struct cursor *cursor, size_t offset)
{
    assert(offset < cursor->cap_len);
    return *(cursor->head + offset);
}

static void insert_array_sorted(struct query_candidate *candidate, unsigned element)
{
    unsigned tmp;
    for (unsigned i = 0; i < candidate->num_candidate_size; ++i) {
        if (element > candidate->candidate_sizes[i]) {
            tmp = candidate->candidate_sizes[i];
            candidate->candidate_sizes[i] = element;
            element = tmp;
        }
    }
    candidate->candidate_sizes[candidate->num_candidate_size++] = element;
}

static bool is_print(char c)
{
    return (c != 0x40) && (isprint(c) || c == '\n' || c == '\r');
}

static bool  is_range_print(struct cursor *cursor, size_t size, size_t offset)
{

    for (size_t i = 0; i < size; i++) {
        unsigned char chr = cursor_peek_u8(cursor, i + offset);
        if (!is_print(chr)) {
            return false;
        }
    }
    return true;
}

static bool is_query_valid(struct cursor *cursor, unsigned long potential_size, unsigned char offset)
{
    // We check if last character is printable
    unsigned long  last_char_pos = MIN(cursor->cap_len, potential_size) - 1;
     unsigned char  last_char = cursor_peek_u8(cursor, last_char_pos);
    if (!is_print(last_char)) {
        return false;
    }
    // We check if last character + 1 is not printable. If it is printable, size might be incorrect
    // We assume chunked string if size >= 0x40
    if (potential_size < 0x40 && potential_size < cursor->cap_len) {
        if (cursor->cap_len - 1 > potential_size)  {
            char next_char = cursor_peek_u8(cursor, potential_size + 1);
            if (is_print(next_char)) {
                return false;
            }
        }
    }
    // We check if first characters are printable
    if (true == is_range_print(cursor, 10, offset)) {
        return true;
    }
    return false;
}

static bool check_chuncked_query(struct cursor *cursor, unsigned char current,
        unsigned char  next, struct query_candidate *candidate)
{
    if (is_print(next) && current > 10 && is_query_valid(cursor, current, 1)) {

        candidate->query_size = current;
        candidate->is_chunked = true;
        return true;
    }
    return false;
}

static bool check_fixed_query(struct cursor *cursor, unsigned char  current,
        unsigned char  next, struct query_candidate *candidate)
{
    if (is_print(current) && is_print(next)) {
        for (unsigned i = 0; i < candidate->num_candidate_size; ++i) {
            unsigned long size = candidate->candidate_sizes[i];
            if (is_query_valid(cursor, size, 0)) {
                candidate->query_size = candidate->candidate_sizes[i];
                candidate->is_chunked = false;
                return true;
            }
        }
    }
    return false;
}
static bool lookup_query(struct cursor *cursor, struct query_candidate *candidate)
{
    unsigned char current;
    unsigned char  next;

    while (cursor->cap_len > 12) {
        current = cursor_peek_u8(cursor, 0);
        next = cursor_peek_u8(cursor, 1);
        if (current == 0x07 && next > 0 && next <= 4) {
            return false;
        }
        if (current > 0 && current < 3 && next > 10
                && candidate->num_candidate_size < NB_ELEMS(candidate->candidate_sizes)) {
            unsigned long buf = 0;
            // Copy cursor since we might have pattern like 0x01 Size Query
            struct cursor cursor_copy = *cursor;
            if (true == cursor_read_variable_int(&cursor_copy, &buf)) {
                insert_array_sorted(candidate, buf);
            }
        }
        if (candidate->num_candidate_size == 0 || current >= candidate->candidate_sizes[0]) {
            if (check_chuncked_query(cursor, current, next, candidate)) return true;
            if (check_fixed_query(cursor, current, next, candidate)) return true;
        } else {
            if (check_fixed_query(cursor, current, next, candidate)) return true;
            if (check_chuncked_query(cursor, current, next, candidate)) return true;
        }
        cursor_drop(cursor, 1);
    }
    return false;
}

bool tns_parse_sql_query_oci(PSoderoTnsApplication application, struct cursor *cursor)
{
    unsigned char query_size = parse_query_header(cursor);
    struct query_candidate candidate = {.num_candidate_size = 0};
    if (query_size > 0) {
        candidate.candidate_sizes[candidate.num_candidate_size++] = query_size;
    }

    bool has_query = lookup_query(cursor, &candidate);
    application->sql[0] = '\0';
    if (has_query) {

        if (candidate.is_chunked) {
            cursor_read_chunked_string(cursor, application->sql, sizeof(application->sql), 0x40);
        } else {
            cursor_read_fixed_string(cursor, application->sql, sizeof(application->sql), candidate.query_size);
        }
    }

    // Drop the rest
    if(cursor->cap_len > 0) cursor_drop(cursor, cursor->cap_len - 1);
    return true;
}

void updateTnsRequestState(PSoderoTnsApplication application, PTCPState state) {
	if (application) {
		if (state->application == application) return;
		state->application = application;
		application->req_pkts     ++;
		application->req_bytes    += state->payload;
		application->req_l2_bytes += state->length;
		//application->reqRTTValue  += state->rttTime;
		//application->reqRTTCount  += state->rtt;
		if (state->rst)
			application->req_aborted++;
	}
}

void updateTnsResponseState(PSoderoTnsApplication application, PTCPState state) {
	if (application) {
		if (state->application == application) return;
		state->application = application;
		
		application->rsp_pkts     ++;
		application->rsp_bytes    += state->payload;
		application->rsp_l2_bytes += state->length;
		//application->rspRTTValue  += state->rttTime;
		//application->rspRTTCount  += state->rtt;
		if (state->rst)
			application->rsp_aborted++;
	}
}

void updateTnsState(PSoderoTCPSession session, int dir, PTCPState state) {
	if (state->fin) {
		free(session->session);
		session->session = NULL;
	}

	do {
		if (dir > 0) {
			PSoderoTnsApplication application = session->session;
			
			if (application)
				updateTnsRequestState (application, state);
			break;
		}
		if (dir < 0) {
			PSoderoTnsApplication application = session->session;
			
			if (application)
				updateTnsResponseState(application, state);
			break;
		}
	} while(false);
}


/*
 * If oci, we will fallback on start query guesstimation
 * | 1 byte                        |
 * | Some flags (generally > 0x04) |
 *
 * If jdbc:
 * | 1 byte      | 0-4 bytes | 1 byte   | 0-4 bytes |
 * | Option size | Options   | Var size | Var value |
 */
static bool is_oci(struct cursor *cursor)
{
    unsigned option_size = read_u8(cursor);

    if (option_size > 0x04 || cursor_peek_u8(cursor, 1) == 0x00) 
    {
        return true;
    }
    cursor_drop(cursor, option_size);

    // Should be a var here
    unsigned var_size = read_u8(cursor);
    CHECK(MAX(var_size, 2));
    if (var_size > 0x04 || cursor_peek_u8(cursor, 1) == 0x00) 
    {
        return true;
    }
    cursor_drop(cursor, var_size);

    return false;
}


int parseTnsData(struct cursor *cursor, PSoderoTnsPacketDetail detail, PSoderoTCPSession session, int dir,
        POracleHead const head, const unsigned char * data, int size, int total) 
{
    PSoderoTnsApplication application = session->session;
    unsigned short data_flag = read_u16(cursor);

	if (data_flag) {
		detail->reqs++;
		if (application) {
			sodero_pointer_add(getClosedApplications(), application);
	        session->session = nullptr;
	        session->value.tns.serial = 0;
	        application = nullptr;
		}
		return (size <= total ? size : total) + sizeof(*head);
	}
    unsigned char ttc_code = read_u8(cursor);
    unsigned char ttc_subcode = read_u8(cursor);

    if (dir < 0)//	Response
    {
        if (application) 
        {
        	detail->block++;
			application->rsps++;
            processA(&application->traffic.incoming, total);
            if (!application->rspFirst)
                application->rspFirst = gTime;
            if (application->rspLast < gTime)
                application->rspLast = gTime;
            if (total > size)
                application->rspPending += total - size;
            if ((ttc_code == 0x04) && (ttc_subcode == 0x01 || ttc_subcode == 0x02 || ttc_subcode == 0x05)
				|| (ttc_code == 0x06) || (ttc_code == 0x08))
            {
            	//end
            	if (application && ((application->step == TNS_STEP_REQ_START) || (application->step == TNS_STEP_REQ_MORE))) {
					detail->app_end = 1;
					detail->rsps++;
					//processE(&application->request, application->reqLast - application->reqFirst);
					//processE(&application->wait, application->rspFirst - application->reqLast);
					//processE(&application->response, application->rspLast - application->rspFirst);
				}
           }
/*
		   if ((ttc_code == 0x10) && (ttc_subcode == 0x17)) {
		   		//response for 1169;
		   }*/
/*
		   if ((ttc_code == 0x06) || (ttc_code == 0x08)) {
		   		//query end now
		   		if (application && ((application->step == TNS_STEP_REQ_START) || (application->step == TNS_STEP_REQ_MORE))) {
	                sodero_pointer_add(getClosedApplications(), application);
	                session->session = nullptr;
	                session->value.tns.serial = 0;
	                application = nullptr;
				}
		   		
		   }*/
       } 
       else 
       {
           //	ToDo: Error Protocol
           LogErr("%s", "Empty applicaton on response\n");
		   return (size <= total ? size : total) + sizeof(*head);
           //return PARSE_ERROR;
       }

        return (size <= total ? size : total) + sizeof(*head);
    }

    if (dir > 0) //	Request
    {
        if ((ttc_code == 0x03) && (ttc_subcode == 0x5e || ttc_subcode == 0x47 || ttc_subcode == 0x05))
        {
        	detail->reqs = 1;
        	if (application && (application->step == TNS_STEP_REQ_START)) {
				application->step = TNS_STEP_REQ_MORE;
        	} else {
        		//query start 
        		application = takeApplication(sizeof(TSoderoTnsApplication));
				newApplication((PSoderoApplication)application, (PSoderoSession)session);
				application->command = TNS_METHOD_SQL;
				session->session = application;
				application->step = TNS_STEP_REQ_START;
				application->reqFirst = gTime;
        	}

			DROP_FIX(cursor, 1);
            if (is_oci(cursor)) 
            {
                // Option is not prefix based, seems like an oci query
                tns_parse_sql_query_oci(application, cursor);
                      
            }

			if (strstr(application, "PROCEDURE"))
				application->command = TNS_METHOD_PROCEDURE;
			
        }

		if ((ttc_code == 0x11) && ((ttc_subcode == 0x69) || (ttc_subcode == 0x78))) {
			printf("parseTnsData:1169\r\n");
			detail->reqs = 1;
			application = takeApplication(sizeof(TSoderoTnsApplication));
			newApplication((PSoderoApplication)application, (PSoderoSession)session);
			session->session = application;
			application->command = TNS_METHOD_SQL;
			application->step = TNS_STEP_REQ_START;
			application->reqFirst = gTime;

			DROP_FIX(cursor, 1);
            if (is_oci(cursor)) 
            {
                // Option is not prefix based, seems like an oci query
                tns_parse_sql_query_oci(application, cursor);
                      
            }

			if (strstr(application, "PROCEDURE"))
				application->command = TNS_METHOD_PROCEDURE;

		}

		printf("parseTnsData: application = %p\r\n", application);
		if (application) 
		{
			if (application->step != TNS_STEP_REQ_MORE)
		    	detail->command++;
			application->reqLast = gTime;
		} 
		else 
		{
			 //	ToDo: Error Protocol
			LogErr("%s", "Empty applicaton on request\n");
			return (size <= total ? size : total) + sizeof(*head);
           //return PARSE_ERROR;
		}
         return (size <= total ? size : total) + sizeof(*head);

    }

    return PARSE_ERROR;

}
int parseTnsConnect(PSoderoTnsPacketDetail detail, int size, int total) 
{
	detail->reqs++;
	return size;
}

int parseTnsAccept(PSoderoTnsPacketDetail detail, PSoderoTCPSession session, int size, int total) {
	//	Login request or response must in one packet.
	//if (size < total) {
		//LogErr("Invalid packet Size %d - %u", size, total);
		//return DETECT_NEGATIVE;
	//}
		
	session->value.tns.status = TNS_LOGIN_SUCCESS;
	detail->reqs++;
	session->value.tns.login.rspTime = gTime;
	PSoderoTnsApplication application = takeApplication(sizeof(TSoderoTnsApplication));
	
	detail->command++;
	//gMySQLTake++;
	newApplication((PSoderoApplication)application, (PSoderoSession)session);

	char * tail = application->text;
	application->command = TNS_METHOD_LOGIN;
	application->status = session->value.tns.status;
	application->reqTime = session->value.tns.login.reqTime;
	application->rspTime = session->value.tns.login.rspTime;
	application->user     = copyField(tail, session->value.tns.login.user    , 128);
	application->database = copyField(tail, session->value.tns.login.database, 128);
	sodero_pointer_add(getClosedApplications(), application);
	session->session = nullptr;
	session->value.tns.serial = 0;
	application = nullptr;
	bzero(&session->value.tns.login, sizeof(session->value.tns.login));
	return size + sizeof(TOracleHead);

}
int parseTnsOther(PSoderoTnsPacketDetail detail, PSoderoTCPSession session, int dir,
	POracleHead const head, const unsigned char * data, int size, int total)
{
       PSoderoTnsApplication application = session->session;
	if (dir > 0) {	//	Response
		if (application) {
			processA(&application->traffic.incoming, total);
			if (!application->rspFirst)
				application->rspFirst = gTime;
			if (application->rspLast < gTime)
				application->rspLast = gTime;
			if (total > size)
				application->rspPending += total - size;
		} else {
			//	ToDo: Error Protocol
			LogErr("%s", "Empty applicaton on response\n");
			//return PARSE_ERROR;
			return 0;
		}

		return (size <= total ? size : total) + sizeof(*head);
	}

	if (dir < 0) {	//	Request
		if (application) {
			processA(&application->traffic.incoming, total);
			if (!application->reqFirst)
				application->reqFirst = gTime;
			if (application->reqLast< gTime)
				application->reqLast = gTime;
			if (total > size)
				application->reqPending += total - size;
		} else {
			//	ToDo: Error Protocol
			LogErr("%s", "Empty applicaton on request\n");
			//return PARSE_ERROR;
			return 0;
		}

		return (size <= total ? size : total) + sizeof(*head);

	}
	LogErr("%s","command dir error");
	//return PARSE_ERROR;
	return 0;
}

int parseTnsApplication(PSoderoTnsPacketDetail detail, PSoderoTCPSession session,
	int dir, const unsigned char * data, int size, int length) {

       struct cursor cursor; 
	POracleHead head = (POracleHead)data;
	data += sizeof(POracleHead);
	size -= sizeof(POracleHead);
	length -= sizeof(POracleHead);
	head->length = ntohs(head->length);
	int total = head->length;
	

       cursor.cap_len = size;
       cursor.head = data;
	cursor_drop(&cursor, 4);

	PSoderoTnsApplication application = session->session;

//	Incomplete MySQL packets, and there is not enough number of bytes
	if ((size > total)) return PARSE_PENDING;
       switch (head->type)
       {
		   case TNS_CONNECT:
		   	   return parseTnsConnect(detail, size, total);
               break;
           case TNS_ACCEPT:
               return parseTnsAccept(detail, session, size, total);
               break;
           case TNS_REFUSE:
               break;
           case TNS_DATA:
               return parseTnsData(&cursor, detail, session, dir, head, data, size, total);
               break;    
           default:
               return parseTnsOther(detail, session, dir, head, data, size, total);
       }
}

int parseTnsPacket(PSoderoTnsPacketDetail detail, PSoderoTCPSession session, int dir,
	const unsigned char * data, int size, int length) {

	int bytes = size;
	while(size > (int) sizeof(TOracleHead)) {
		int result = parseTnsApplication(detail, session, dir, data, size, length);
		if (result > 0) {
			//session->value.mysql.serial++;
			detail->block++;
			data += result;
			size -= result;
			length -= result;
			PSoderoTnsApplication application = session->session;
			if (application) continue;
		}
		if (result < 0) return result;
		break;	//	result is ZERO(PENDING)
	}
	
	return bytes - size;
}

int processTNSPacket(PSoderoTCPSession session, int dir, PSoderoTCPValue value,
	unsigned int base, const unsigned char * data, unsigned int size, unsigned int length,
	PTCPState state, PTCPHeader tcp, PIPHeader ip, PEtherHeader ether) {

	int done = 0;
	int total = size + value->offset - base;


	PNodeValue sourNode = takeIPv4Node((TMACVlan){{ether->sour, ether->vlan}}, ip->sIP);
	PNodeValue destNode = takeIPv4Node((TMACVlan){{ether->dest, ether->vlan}}, ip->dIP);

	if (sourNode) {
		processA(&sourNode->l4.tns.outgoing.value, size);
		sourNode->l4.tns.outgoing.l2 += length;
		sourNode->l4.tns.outgoing.rttValue += state->rttTime;
		sourNode->l4.tns.outgoing.rttCount += state->rtt;
		
	}
	
	if (destNode) {
		processA(&destNode->l4.tns.incoming.value, size);
		destNode->l4.tns.incoming.l2 += length;
		destNode->l4.tns.incoming.rttValue += state->rttTime;
		destNode->l4.tns.incoming.rttCount += state->rtt;
	}

	#if 0
	if (dir > 0) {
		if (sourNode) {
			processA(&sourNode->l4.tns.outgoing.value, size);
			sourNode->l4.tns.outgoing.l2 += length;
			sourNode->l4.tns.outgoing.rttValue += state->rttTime;
			sourNode->l4.tns.outgoing.rttCount += state->rtt;
		}
		if (destNode) {
			processA(&destNode->l4.tns.incoming.value, size);
			destNode->l4.tns.incoming.l2 += length;
			destNode->l4.tns.incoming.rttValue += state->rttTime;
			destNode->l4.tns.incoming.rttCount += state->rtt;
		}
	}
	if (dir < 0) {
		if (sourNode) {
			processA(&sourNode->l4.tns.outgoing.value, size);
			sourNode->l4.tns.outgoing.l2 += length;
			sourNode->l4.tns.outgoing.rttValue += state->rttTime;
			sourNode->l4.tns.outgoing.rttCount += state->rtt;
		}
		if (destNode) {
			processA(&destNode->l4.tns.incoming.value, size);
			destNode->l4.tns.incoming.l2 += length;
			destNode->l4.tns.incoming.rttValue += state->rttTime;
			destNode->l4.tns.incoming.rttCount += state->rtt;
		}
	}
	#endif
	
	PSoderoTnsApplication application = session->session;
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
		LogErr("%s", "Parse application dir error");
		return PARSE_ERROR;
	}

	base   += done;
	total  -= done;

	//	The remaining of bytes is too few
	if (total < sizeof(TOracleHead)) return done;

	TSoderoTnsPacketDetail detail = {0};

	int result = 0;
	//	Now, there must be a Oracle packet is parsed.
	if (base < value->offset) {
		//	Merge legacy data and current packet
		unsigned char buffer[TNS_BUFFER_SIZE];
		int bytes = pickData(buffer, sizeof(buffer), value, base, data, size);
		result = parseTnsPacket(&detail, session, dir, buffer, bytes, total);
	} else {
		//	Directly process current packet
		const unsigned char * buffer = data + base - value->offset;
		result = parseTnsPacket(&detail, session, dir, buffer, total, total);
	}

	if (detail.app_end == 1) {
		//PNodeValue sourNode = takeIPv4Node((TMACVlan){{ether->sour, ether->vlan}}, ip->sIP);

		application = session->session;
		if (application) {
					
	        sodero_pointer_add(getClosedApplications(), application);
	        session->session = nullptr;
	        session->value.tns.serial = 0;
	       
			if (sourNode) {	
				//processEE(&sourNode->l4.tns.outgoing.request, &(application->request));
				//processEE(&sourNode->l4.tns.outgoing.wait, &(application->wait));
				//processEE(&sourNode->l4.tns.outgoing.response, &(application->response));
				//printf("processTNSPacket: +++w+++++%llx, %llx, %llx, %llx\r\n", application->reqFirst, application->reqLast, application->rspFirst, application->rspLast);
				//printf("processTNSPacket: +++w+++++%llx, %llx, %llx\r\n", application->reqLast - application->reqFirst, application->rspFirst - application->reqFirst, application->rspLast - application->rspFirst);
				processE(&sourNode->l4.tns.outgoing.request, application->reqLast - application->reqFirst);
				processE(&sourNode->l4.tns.outgoing.wait, application->rspFirst - application->reqFirst);
				processE(&sourNode->l4.tns.outgoing.response, application->rspLast - application->rspFirst);
			}
			
			application = nullptr;
		}
	}
	
	if (dir > 0) {
		if (sourNode) {
			sourNode->l4.tns.outgoing.reqs += detail.reqs;
		}
		if (destNode) {
			sourNode->l4.tns.incoming.rsps += detail.rsps; 
		}
		return;
	}
	
	if (dir < 0) {	//	response
		if (sourNode) {
			sourNode->l4.tns.outgoing.reqs += detail.reqs;
		}
		if (destNode) {
			sourNode->l4.tns.incoming.rsps += detail.rsps; 
		}
		return;
	}
	
	if (result > 0) {
		if (sourNode) {
			sourNode->l4.tns.outgoing.count += detail.command;
			sourNode->l4.tns.outgoing.block += detail.block  ;
		}
		if (destNode) {
			destNode->l4.tns.incoming.count += detail.command;
			sourNode->l4.tns.outgoing.block += detail.block  ;
		}
	}
	
	return result < 0 ? result : done + result;
}

