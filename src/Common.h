/*
 * Common.h
 *
 *  Created on: Jul 8, 2014
 *      Author: Clark Dong
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "Type.h"
#include "DPI.h"

typedef void * TObject;

typedef struct SUNDAY_DATA {
	unsigned char steps[256];
	int  length;
	char string[0];
} TSundayData, * PSundayData;


#define MAXINTERFACES   64

#define DaiesPerWeek    7ULL

#define HoursPerDay    24ULL
#define HoursPerWeek   (HoursPerDay * DaiesPerWeek)

#define MinsPerHour    60ULL
#define MinsPerDay     (HoursPerDay * MinsPerHour )
#define MinsPerWeek    (DaiesPerWeek* MinsPerDay  )

#define SecsPerMin     60ULL
#define SecsPerHour    (MinsPerHour * SecsPerMin  )
#define SecsPerDay     (HoursPerDay * SecsPerHour )
#define SecsPerWeek    (DaiesPerWeek* SecsPerDay  )

#define mSecsPerSec    _K
#define mSecsPerMin    (SecsPerMin  * mSecsPerSec )
#define mSecsPerHour   (MinsPerHour * mSecsPerMin )
#define mSecsPerDay    (HoursPerDay * mSecsPerHour)
#define mSecsPerWeek   (DaiesPerWeek* mSecsPerDay )

#define uSecsPerMSec   _K
#define uSecsPerSec    (mSecsPerSec * uSecsPerMSec)
#define uSecsPerMin    (SecsPerMin  * uSecsPerSec )
#define uSecsPerHour   (MinsPerHour * uSecsPerMin )

#define nSecsPerUSec   _K
#define nSecsPerMSec   (uSecsPerMSec * nSecsPerUSec)
#define nSecsPerSec    (mSecsPerSec  * nSecsPerMSec)
#define nSecsPerMin    (SecsPerMin   * nSecsPerSec )
#define nSecsPerHour   (MinsPerHour  * nSecsPerMin )

#define uSecsPerDay    (HoursPerDay * uSecsPerHour)
#define uSecsPerWeek   (DaiesPerWeek * HoursPerDay)

#define DEFAULT_SESSION_ICMP_ACTIVED_TIMEOUT  5

#ifdef __DEBUG__
#define DEFAULT_SESSION_TCP_OPENING_TIMEOUT   5
#define DEFAULT_SESSION_TCP_CLOSING_TIMEOUT   5
#else
#define DEFAULT_SESSION_TCP_OPENING_TIMEOUT  15
#define DEFAULT_SESSION_TCP_CLOSING_TIMEOUT  60
#endif
#define DEFAULT_SESSION_TCP_ACTIVED_TIMEOUT 600

#define DEFAULT_SESSION_UDP_ACTIVED_TIMEOUT 600

#define DEFAULT_SESSION_DNS_OPEN_TIMEOUT     5
#define DEFAULT_SESSION_DNS_DONE_TIMEOUT     2

#define SODERO_CHECK_ALL      0xFFFFFFFFU
#define SODERO_CHECK_NODE     0x00000001U
#define SODERO_CHECK_TCP      0x00000100U
#define SODERO_CHECK_UDP      0x00000200U
#define SODERO_CHECK_HTTP     0x00010000U
#define SODERO_CHECK_MYSQL    0x00020000U
#define SODERO_CHECK_DNS      0x0100000U
#define SODERO_CHECK_FLOW     0x0000FF00U
#define SODERO_CHECK_APP      0xFFFF0000U

extern void * takeMemory(size_t size);
extern void freeMemory(void * ptr);

extern void * takeBlock(size_t size);
extern void freeBlock(void * ptr);

void * takeBuffer(size_t size);
extern void freeBuffer(void * ptr);

extern void * takeSession(size_t size);
extern void freeSession(void * ptr);

extern void * takeApplication(size_t size);
extern void freeApplication(void * ptr);

extern void * takeEvent(size_t size);
extern void freeEvent(void * ptr);

typedef struct SODERO_FLOW_DATUM {
	unsigned int       count;	//	packet count
	unsigned long long bytes;	//	total bytes
} TSoderoFlowDatum, * PSoderoFlowDatum;


typedef struct SODERO_EXTEND_DATUM {
	unsigned long long max;
	unsigned long long min;
	unsigned long long sum;
} TSoderoExtendDatum, * PSoderoExtendDatum;


//	Smallest indicator element.
//	Note: Only declare integer, in fact, and single-precision float also occupy 4 bytes, can be mixed storage.
typedef struct SODERO_UNIT_DATUM {
	unsigned long long count;
	union {
		struct {
			unsigned long long sum;
			unsigned long long max;
			unsigned long long min;
		};
		TSoderoExtendDatum extend;
	};

} TSoderoUnitDatum, * PSoderoUnitDatum;


#define SODERO_PACKET_INDEX_TOTAL 0
#define SODERO_PACKET_INDEX_00064 1
#define SODERO_PACKET_INDEX_00128 2
#define SODERO_PACKET_INDEX_00256 3
#define SODERO_PACKET_INDEX_00512 4
#define SODERO_PACKET_INDEX_01024 5
#define SODERO_PACKET_INDEX_01514 6
#define SODERO_PACKET_INDEX_01518 7
#define SODERO_PACKET_INDEX_JUMBO 8


typedef union SODERO_PACKET_DATUM {
	TSoderoFlowDatum ranks[9];
	struct {
		TSoderoFlowDatum total;	//	all packet
		TSoderoFlowDatum b___64;
		TSoderoFlowDatum b__128;
		TSoderoFlowDatum b__256;
		TSoderoFlowDatum b__512;
		TSoderoFlowDatum b_1024;
		TSoderoFlowDatum b_1514;
		TSoderoFlowDatum b_1518;
		TSoderoFlowDatum bjumbo;
	};

//	TSoderoFlowDatum fragment;	//	Fragmented packets
} TSoderoPacketDatum, * PSoderoPacketDatum;


//	undirected statistics element
typedef struct SODERO_SINGLE_DETAIL {
	TSoderoPacketDatum value;		//
} TSoderoSingleDetail, * PSoderoSingleDetail;

typedef struct SODERO_DOUBLE_VALUE {
	unsigned long long value[2];
	struct {
		unsigned long long incoming;		//	O -> I	Inbound Direction
		unsigned long long outgoing;		//	I -> O	Outbound direction
	};
} TSoderoDoubleValue, * PSoderoDoubleValue;

//	directed statistics element
typedef union SODERO_DOUBLE_DETAIL {
	TSoderoPacketDatum value[2];
	struct {
		TSoderoPacketDatum incoming;		//	O -> I	Inbound Direction
		TSoderoPacketDatum outgoing;		//	I -> O	Outbound direction
	};
} TSoderoDoubleDetail, * PSoderoDoubleDetail;

//	undirected statistics element
typedef struct SODERO_SINGLE_DATUM {
	TSoderoFlowDatum value;		//
} TSoderoSingleDatum, * PSoderoSingleDatum;


//	directed statistics element
typedef struct SODERO_DOUBLE_DATUM {
	union {
		TSoderoFlowDatum value[2];
		struct {
			TSoderoFlowDatum incoming;		//	O -> I	Inbound Direction
			TSoderoFlowDatum outgoing;		//	I -> O	Outbound direction
		};
	};
} TSoderoDoubleDatum, * PSoderoDoubleDatum;

extern unsigned long long now(void);
extern int time_delta(unsigned int a, unsigned int b);
extern int time_inter(unsigned long long a, unsigned long long b);
extern char * find_char(char * p, char c);
extern char * find_text(char * p, int length, char c);
extern char * skip_space(char * str);
extern int str_len(const char *str);
extern int cpy_str(char * dest, const char * sour);
extern int cpy_text(char * dest, const char * sour, int size);
extern int cmp_str(const char * sour, const char * dest);
extern int cmp_text(const char * sour, const char * dest);
extern int same_str(const char * a, const char * b);
extern int same_text(const char * a, const char * b);

extern char * dup_str(const char * src);
extern char * replace_str(char * * value, const char * buffer, int length);

extern PSundayData sunday_init(const char * string);
extern int sunday_find(const PSundayData sunday, const char *string, int length);

extern void enum_interfaces(void);

extern int isBMAC(PMAC mac);
extern int isMMAC(PMAC mac);
extern int isSMAC(PMAC mac);

extern int isSTPMAC(PMAC mac);
extern int isLinkSTP(PLinkRSTPHeader header);

extern int isIPv4ARP(PARPHeader header);

extern int isBIPv4(TIPv4 ipv4);
extern int isMIPv4(TIPv4 ipv4);
extern int isSIPv4(TIPv4 ipv4);
extern int isLIPv4(TIPv4 ipv4);
extern int isGIPv4(TIPv4 ipv4);

extern int isEmptyEtherData(PEtherData value);

extern void * get_in_addr(struct sockaddr *sa);

extern int proto_index(const char * name);

extern const char * ipv4_proto_name(int proto);
extern const char * ether_proto_name(int proto);
extern const char * socket_type_name(int type);

#if defined(__i386__)
static inline
	unsigned int rdtsc(void) {
		unsigned int x;
		asm volatile (".byte 0x0f, 0x31" : "=A" (x));
		return x;
	}
#endif

#if defined(__x86_64__)
static inline
	unsigned long long rdtsc(void) {
		unsigned int l, h;
		asm volatile ("rdtsc" : "=a" (l), "=d" (h));
		return (((unsigned long long) h) << 32) | ((unsigned long long)l);
	}
#endif

#define I8_INC(x) \
	asm volatile ("incb %0" : "=g" (x))
#define I16_INC(x) \
	asm volatile ("incw %0" : "=g" (x))
#define I32_INC(x) \
	asm volatile ("incl %0" : "=g" (x))
#define I64_INC(x) \
	asm volatile ("incq %0" : "=g" (x))

#define I8_DEC(x) \
	asm volatile ("decb %0" : "=g" (x))
#define I16_DEC(x) \
	asm volatile ("decw %0" : "=g" (x))
#define I32_DEC(x) \
	asm volatile ("decl %0" : "=g" (x))
#define I64_DEC(x) \
	asm volatile ("decq %0" : "=g" (x))

static inline
unsigned long long * uchar2ulonglong(const unsigned char * p) {
	return (unsigned long long *) p;
}

#define CLEAN_VAR(x) bzero(&(x), sizeof(x))
#define CLEAN_ARR(x) bzero( (x), sizeof(x))

extern void processA(PSoderoFlowDatum datum, int value);
extern void processE(PSoderoUnitDatum datum, int value);
extern void processP(PSoderoPacketDatum datum, int value);
extern void processDV(PSoderoDoubleValue datum, int size, int dir);
extern void processSD(PSoderoSingleDatum datum, int size);
extern void processDD(PSoderoDoubleDatum datum, int size, int dir);
extern void processSP(PSoderoSingleDetail datum, int size);
extern void processDP(PSoderoDoubleDetail datum, int size, int dir);


///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	Sodero Memory (Block) Buffer
//
///////////////////////////////////////////////////////////////////////////////////////////////////


struct SODERO_MEMORY_BLOCK;
typedef struct SODERO_MEMORY_BLOCK TSoderoMemoryBlock, * PSoderoMemoryBlock;

struct SODERO_MEMORY_BUFFER;
typedef struct SODERO_MEMORY_BUFFER TSoderoMemoryBuffer, * PSoderoMemoryBuffer;

struct SODERO_MEMORY_BLOCK {
	PSoderoMemoryBlock link;
};

struct SODERO_MEMORY_BUFFER {
	PSoderoMemoryBlock root;
	size_t             size;
};

extern void sodero_initialize_memory_buffer(PSoderoMemoryBuffer object, size_t size);
extern void sodero_finalize_memory_buffer(PSoderoMemoryBuffer object);

extern PSoderoMemoryBuffer sodero_create_memory_buffer(size_t size);
extern void sodero_destroy_memory_buffer(PSoderoMemoryBuffer object);


extern TObject sodero_buffer_shrink(PSoderoMemoryBuffer object, int count);
extern void sodero_buffer_memory_clean(PSoderoMemoryBuffer object);

extern TObject sodero_buffer_create_block(PSoderoMemoryBuffer object, size_t size);
extern TObject sodero_buffer_create_chunk(PSoderoMemoryBuffer object);


///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	Sodero Memory Manager
//
///////////////////////////////////////////////////////////////////////////////////////////////////


struct SODERO_MEMORY_MANAGER;
typedef struct SODERO_MEMORY_MANAGER TSoderoMemoryManager, * PSoderoMemoryManager;

struct SODERO_MEMORY_MANAGER {
	TSoderoMemoryBuffer buffer;
	long base;
	size_t left;
};

extern void sodero_initialize_memory_manager(PSoderoMemoryManager object, size_t size);
extern void sodero_finalize_memory_manager(PSoderoMemoryManager object);

extern PSoderoMemoryManager sodero_create_memory_manager(size_t size);
extern void sodero_destroy_memory_manager(PSoderoMemoryManager object);

extern void sodero_memory_clean(PSoderoMemoryManager object);
extern TObject sodero_memory_take(PSoderoMemoryManager object, size_t size);


///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	Sodero Object Stack
//
///////////////////////////////////////////////////////////////////////////////////////////////////


struct SODERO_STACK;
typedef struct SODERO_STACK TSoderoStack, * PSoderoStack;

struct SODERO_STACK {
	TSoderoMemoryBuffer buffer;
	TObject *    items;
	size_t       count;
	unsigned int index;
};

extern void sodero_initialize_stack(PSoderoStack object, size_t size);
extern void sodero_finalize_stack(PSoderoStack object);

extern PSoderoStack sodero_create_stack(size_t size);
extern void sodero_destroy_stack(PSoderoStack object);

extern void sodero_stack_clean(PSoderoStack object);

extern size_t sodero_stack_size(PSoderoStack object);
extern void sodero_stack_push(PSoderoStack object, TObject value);
extern TObject sodero_stack_pop(PSoderoStack object);


///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	Sodero Memory Pool
//
///////////////////////////////////////////////////////////////////////////////////////////////////


struct SODERO_MEMORY_POOL;
typedef struct SODERO_MEMORY_POOL TSoderoMemoryPool, *PSoderoMemoryPool;

struct SODERO_MEMORY_POOL {
	TSoderoMemoryManager memory;
	TObject *    items;
	unsigned int level;
	unsigned int bytes;
	size_t       count;
};

extern void sodero_initialize_memory_pool(PSoderoMemoryPool object, size_t level, size_t size);
extern void sodero_finalize_memory_pool(PSoderoMemoryPool object);

extern PSoderoMemoryPool sodero_create_memory_pool(size_t level, size_t size);
extern void sodero_destroy_memory_pool(PSoderoMemoryPool object);

extern void sodero_pool_clean(PSoderoMemoryPool object);
extern size_t sodero_pool_size(PSoderoMemoryPool object);

extern void sodero_pool_free(PSoderoMemoryPool object, TObject value);
extern TObject sodero_pool_take(PSoderoMemoryPool object, size_t size);


///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	Sodero Pointer Vector
//
///////////////////////////////////////////////////////////////////////////////////////////////////


struct SODERO_POINTER_POOL;
typedef struct SODERO_POINTER_POOL TSoderoPointerPool, * PSoderoPointerPool;

typedef void * TSoderoPointerBlock[65536];
typedef TSoderoPointerBlock * TSoderoPointerIndex[65535];

struct SODERO_POINTER_POOL {
	TSoderoPointerBlock block;
	union {
		struct {
			unsigned int        id;
			unsigned int        count;
		};
		TSoderoPointerIndex index;
	};
};

typedef long (*TforeachPointerHandlor)(PSoderoPointerPool container, int index, void * object, void * data);

extern PSoderoPointerPool sodero_create_pointer_pool(void);
extern void sodero_destroy_pointer_pool(PSoderoPointerPool object);

extern size_t sodero_pointer_count(PSoderoPointerPool object);
extern void sodero_pointer_clean(PSoderoPointerPool object);
extern void sodero_pointer_shrink(PSoderoPointerPool object);
extern void sodero_pointer_reset(PSoderoPointerPool object);
extern void * sodero_pointer_get(PSoderoPointerPool object, unsigned int index);
extern long sodero_pointer_add(PSoderoPointerPool object, void * pointer);
extern long sodero_pointer_foreach(PSoderoPointerPool object, TforeachPointerHandlor handlor, void * data);

///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	Sodero HASH Common
//
///////////////////////////////////////////////////////////////////////////////////////////////////


typedef TObject TContainerValue;
typedef TObject TContainerKey  ;

typedef unsigned long (*THashHandlor)(TContainerKey item);
typedef long (*TEqualHandlor)(TContainerKey a, TContainerKey b);
typedef void (*TKeyDuplicator)(TContainerValue dest, TContainerValue sour);
typedef TContainerKey(*TSoderoObjectKey)(TContainerValue);
typedef TObject (*TCreateHandlor)(TObject container, TContainerKey k);
typedef void    (*TReleaseHandlor)(TObject container, TContainerKey k, TContainerValue item);
typedef void    (*TCleanHandlor)(TContainerKey k, TContainerValue item);


///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	Sodero HASH Map
//
///////////////////////////////////////////////////////////////////////////////////////////////////


#define SODERO_MAP_BUCKET_LENGTH_MIN    65536
#define SODERO_MAP_BLOCK_COUNT_MIN       1024

#define SODERO_MAP_MODE_NONE 0
#define SODERO_MAP_MODE_HOLD 1

struct SODERO_MAP_NODE;
typedef struct SODERO_MAP_NODE TSoderoMapNode, * PSoderoMapNode;

struct SODERO_MAP;
typedef struct SODERO_MAP TSoderoMap, * PSoderoMap;

typedef long (*TforeachMapHandlor)(PSoderoMap container, int index, TContainerKey k, TContainerValue v, void * data);

struct SODERO_MAP_NODE {
	PSoderoMapNode link;	//	link to next node of bucket or nodes
	PSoderoMapNode next;	//	link to next node of chain
	PSoderoMapNode prev;	//	link to prev node of chain
	TObject        value;
	char           key[0];
};

struct SODERO_MAP {
	PSoderoMemoryBlock  block;
	PSoderoMapNode      head;
	PSoderoMapNode      tail;
	PSoderoMapNode     nodes;		//	available nodes;
	PSoderoMapNode * buckets;		//	bucket of node

	void * data;		//	user data

	long length;		//	length of bucket
	long count;			//	count of item in map
	int  delta;			//	delta node a block
	int  size ;			//	size of key
	int  mode ;			//
	int  room ;

	THashHandlor         scatter;
	TEqualHandlor        comparer;
	TKeyDuplicator duplicator;

	TCleanHandlor   cleaner;
	TCreateHandlor  creater;
	TReleaseHandlor releaser;
};

extern PSoderoMap sodero_map_create(long length, int delta, int size, int mode, void * data,
	THashHandlor scatter, TEqualHandlor comparer, TKeyDuplicator duplicator,
	TCreateHandlor creater, TReleaseHandlor releaser, TCleanHandlor cleaner);
extern PSoderoMap sodero_map_create_simple(long length, int delta, int size);

extern void sodero_map_destroy(PSoderoMap container);

extern void sodero_map_clean(PSoderoMap container);

extern size_t sodero_map_count(PSoderoMap container);

extern TContainerValue sodero_map_lookup(PSoderoMap container, TContainerValue k);
extern TContainerValue sodero_map_append(PSoderoMap container, TContainerKey k, TContainerValue v);
extern TContainerValue sodero_map_insert(PSoderoMap container, TContainerKey k, TContainerValue v);
extern TContainerValue sodero_map_remove(PSoderoMap container, TContainerKey k);
extern TContainerValue sodero_map_replace(PSoderoMap container, TContainerKey k, TContainerValue v);

extern TContainerValue sodero_map_ensure(PSoderoMap container, TContainerKey k);

extern long sodero_map_foreach(PSoderoMap container, TforeachMapHandlor handlor, void * data);


///////////////////////////////////////////////////////////////////////////////////////////////////

#define SODERO_TABLE_BUCKET_LENGTH_MIN    65536
#define SODERO_TABLE_BLOCK_COUNT_MIN       1024

#define SODERO_TABLE_MODE_NONE 0
#define SODERO_TABLE_MODE_HOLD 1

struct SODERO_TABLE_NODE;
typedef struct SODERO_TABLE_NODE TSoderoTableNode, * PSoderoTableNode;

struct SODERO_TABLE;
typedef struct SODERO_TABLE TSoderoTable, * PSoderoTable;

typedef long (*TforeachTableHandlor)(PSoderoTable container, int index, TContainerValue v, void * data);

struct SODERO_TABLE_NODE {
	PSoderoTableNode link;	//	link to next node of bucket or nodes
	PSoderoTableNode next;	//	link to next node of chain
	PSoderoTableNode prev;	//	link to prev node of chain
	TObject        value;
};

struct SODERO_TABLE {
	PSoderoMemoryBlock  block;
	PSoderoTableNode      head;
	PSoderoTableNode      tail;
	PSoderoTableNode     nodes;		//	available nodes;
	PSoderoTableNode * buckets;		//	bucket of node

	void * data;		//	user data

	long length;		//	length of bucket
	long count;			//	count of item in table
	int  delta;			//	delta node a block
	int  size ;			//	size of key
	int  mode ;			//
	int  room ;

	THashHandlor         scatter;
	TEqualHandlor        comparer;
	TSoderoObjectKey     keyof;

	TCleanHandlor   cleaner;
	TCreateHandlor  creater;
	TReleaseHandlor releaser;
};

extern int sodero_table_init(PSoderoTable container, long length, int delta, int size, int mode, void * data,
	THashHandlor scatter, TEqualHandlor comparer, TSoderoObjectKey keyof,
	TCreateHandlor creater, TReleaseHandlor releaser, TCleanHandlor cleaner);

extern PSoderoTable sodero_table_create(long length, int delta, int size, int mode, void * data,
	THashHandlor scatter, TEqualHandlor comparer, TSoderoObjectKey keyof,
	TCreateHandlor creater, TReleaseHandlor releaser, TCleanHandlor cleaner);
extern PSoderoTable sodero_table_create_simple(long length, int delta, int size);

extern void sodero_table_destroy(PSoderoTable container);

extern void sodero_table_clean(PSoderoTable container);

extern size_t sodero_table_count(PSoderoTable container);

extern TContainerValue sodero_table_lookup(PSoderoTable container, TContainerKey k);
extern TContainerValue sodero_table_append(PSoderoTable container, TContainerValue v);
extern TContainerValue sodero_table_insert(PSoderoTable container, TContainerValue v);
extern TContainerValue sodero_table_remove(PSoderoTable container, TContainerKey k);
extern TContainerValue sodero_table_delete(PSoderoTable container, TContainerValue k);
extern TContainerValue sodero_table_replace(PSoderoTable container, TContainerValue v);

extern TContainerValue sodero_table_ensure(PSoderoTable container, TContainerKey k);

extern long sodero_table_foreach(PSoderoTable container, TforeachTableHandlor handlor, void * data);


///////////////////////////////////////////////////////////////////////////////////////////////////
//
//	Sodero HASH Container
//
///////////////////////////////////////////////////////////////////////////////////////////////////


#define SODERO_CONTAINER_BUCKET_LENGTH_MIN    65536
#define SODERO_CONTAINER_BLOCK_COUNT_MIN       1024

struct SODERO_CONTAINER_NODE;
typedef struct SODERO_CONTAINER_NODE TSoderoContainerNode, * PSoderoContainerNode;

struct SODERO_CONTAINER;
typedef struct SODERO_CONTAINER TSoderoContainer, * PSoderoContainer;

typedef long (*TforeachContainerHandlor)(PSoderoContainer container, int index, TContainerValue v, void * data);

struct SODERO_CONTAINER_NODE {
	PSoderoContainerNode link;	//	link to next node of bucket or nodes
	PSoderoContainerNode next;	//	link to next node of chain
	PSoderoContainerNode prev;	//	link to prev node of chain
	PSoderoContainerNode time;
	void *               data[0];
};

struct SODERO_CONTAINER {
	PSoderoMemoryBlock       block;
	PSoderoContainerNode      head;
	PSoderoContainerNode      tail;
	PSoderoContainerNode     nodes;		//	available nodes;
	PSoderoContainerNode * buckets;		//	bucket of node

	void * data;		//	user data

	long length;		//	length of bucket
	long count;			//	count of item in map
	int  delta;			//	delta node a block
	int  size ;			//	size of object
	int  room ;

	THashHandlor   scatter;
	TEqualHandlor  comparer;
	TKeyDuplicator duplicator;
#ifdef __CONTAINER_KEY__
	TSoderoObjectKey keyof;
#endif
};

PSoderoContainer sodero_container_create(long length, int delta, int size, void * data,
	THashHandlor scatter, TEqualHandlor comparer, TKeyDuplicator duplicator
#ifdef __CONTAINER_KEY__
	, TSoderoObjectKey keyof
#endif
);

extern PSoderoContainer sodero_container_create_simple(long length, int delta, int size);

extern void sodero_container_destroy(PSoderoContainer container);

extern void sodero_container_clean(PSoderoContainer container);

extern size_t sodero_container_count(PSoderoContainer container);

extern TContainerValue sodero_container_lookup(PSoderoContainer container, TContainerKey k);
extern TContainerValue sodero_container_remove(PSoderoContainer container, TContainerKey k);

extern TContainerValue sodero_container_ensure(PSoderoContainer container, TContainerKey k);
extern TContainerValue sodero_container_build(PSoderoContainer container, TContainerKey k);

extern TContainerValue sodero_container_delete(PSoderoContainer container, TContainerValue v);

extern long sodero_container_foreach(PSoderoContainer container, TforeachContainerHandlor handlor, void * data);

///////////////////////////////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)

//	Smallest flow element
struct SODERO_SESSION;
typedef struct SODERO_SESSION TSoderoSession, * PSoderoSession;

struct SODERO_APPLICATION;
typedef struct SODERO_APPLICATION  TSoderoApplication, * PSoderoApplication;

typedef union SODERO_ID {
	unsigned long long value;
	struct {
		unsigned serial;
		unsigned short time;
		unsigned short step;
		unsigned char  type;
	};
} TSoderoID, * PSoderoID;

//	Session common fields
struct SODERO_SESSION {
	PSoderoSession  prev;	//	link to prev node of chain
	PSoderoSession  next;	//	link to next node of chain

	unsigned int live;
	unsigned int time;

	unsigned long long id;
	unsigned long long b;		//	Time of First Packet
	unsigned long long e;		//	Time of Last Packet

	void * session;

	TPortKey          key;
	TEtherData        eth;
	unsigned int identify;

	TSoderoDoubleValue l2;
	TSoderoDoubleDatum traffic;	//	connection's traffic
//	TSoderoUnitDatum speed;		//	Transmission speed（Bytes per second）
//	TSoderoUnitDatum count;		//	Transmission speed（packet per second）
//	TSoderoUnitDatum interval;	//	Interval of packet to packet(us)

	unsigned char state;
	unsigned char cause;

	unsigned char flag;
	unsigned char application;
	unsigned short major;
	unsigned short minor;
};

struct SODERO_APPLICATION {
	char *             data;
	PSoderoSession    owner;
	PSoderoApplication link;
	unsigned long long id;		//	session id
//	unsigned char      flag;
	unsigned long long serial;
};

#pragma pack(pop)

PPortKey key_of_sesson(PSoderoSession session);

extern int gRunning;

extern TEtherData EMPTY_ETHER_DATA;

#ifdef __DEBUG__
extern void * gDebugSession;
#endif

extern const char * REPORT_TYPE_HEAD;
extern const char * REPORT_TYPE_BODY;

extern unsigned long long gICMPActivedTime;
extern unsigned long long gTCPOpeningTime;
extern unsigned long long gTCPActivedTime;
extern unsigned long long gTCPClosingTime;
extern unsigned long long gUDPActivedTime;
extern unsigned long long gDNSOpenTime;
extern unsigned long long gDNSDoneTime;

extern unsigned long long gID;
extern unsigned long long gB, gE, gT, gO;

extern TSoderoFlowDatum gTotal;

extern TSoderoFlowDatum gARP, gVLAN, gMPLS, gLACP, gRSTP, gOtherEther;
extern TSoderoFlowDatum gIPv4, gIPv6, gICMP, gTCP, gUDP, gOtherIPv4;
//extern TSoderoFlowDatum gHTTP, gDNS, gMySQL;

extern unsigned long long gSession, gApplication;

extern unsigned long long gICMPRequest, gICMPResponse, gICMPUnrechabled;
extern unsigned long long gDNSRequest, gDNSResponse, gHTTPSkiped;
extern unsigned long long gHTTPRequest, gHTTPResponse;
extern unsigned long long gHTTPMethod[], gHTTPCode[];

extern TSoderoFlowDatum gCurrent, gReportSend, gReportRecv;

#ifdef __EXPORT_STATISTICS__

extern unsigned long long tempTaken;
extern unsigned long long tempFreed;
extern unsigned long long tempEmpty;
extern unsigned long long memoryTaken;
extern unsigned long long memoryFreed;
extern unsigned long long memoryEmpty;
extern unsigned long long blockTaken;
extern unsigned long long blockFreed;
extern unsigned long long blockEmpty;
extern unsigned long long bufferTaken;
extern unsigned long long bufferFreed;
extern unsigned long long bufferEmpty;
extern unsigned long long eventTaken;
extern unsigned long long eventFreed;
extern unsigned long long eventEmpty;
extern unsigned long long applicationTaken;
extern unsigned long long applicationFreed;
extern unsigned long long applicationEmpty;
extern unsigned long long sessionTaken;
extern unsigned long long sessionFreed;
extern unsigned long long sessionEmpty;

extern unsigned long long gFirstBlock  ;
extern unsigned long long gCleanBlock  ;
extern unsigned long long gCloseBlock  ;
extern unsigned long long gCleanSkiped ;
extern unsigned long long gCreateBlock ;
extern unsigned long long gReorderBlock;
extern unsigned long long gReorderSkip ;
extern unsigned long long gReplaceTake ;
extern unsigned long long gReplaceFree ;
extern unsigned long long gOverflowTake;
extern unsigned long long gOverflowFree;

extern unsigned long long gDNSTake   ;
extern unsigned long long gDNSFree   ;
extern unsigned long long gHTTPTake  ;
extern unsigned long long gHTTPFree  ;
extern unsigned long long gMySQLTake ;
extern unsigned long long gMySQLFree ;
extern unsigned long long gCustomFree;
extern unsigned long long gOtherFree ;

extern FILE * gDump;

#endif

#endif /* COMMON_H_ */
