/*
 * Debug.c
 *
 *  Created on: Jul 15, 2014
 *      Author: Clark Dong
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <rpc/types.h>
#include <rpc/rpc.h>

#include "interface.h"
#include "flow_stats_api.h"
#include "Type.h"
#include "Parameter.h"
#include "Common.h"
#include "Session.h"
#include "Context.h"
#include "Carry.h"
#include "XDR.h"
#include "Logic.h"
#include "Core.h"
#include "DPI.h"
#include "MySQL.h"
#include "Report.h"
#include "Dump.h"
#include "https.h"
#include "sslol.h"

#define __SIMLATE_DROP

#define DEBUG_BUFF_COUNT 256

#define DEBUG_BUFF_SIZE (4 * 1024 * 1024)
#define DEBUG_TAKE_SIZE 2048
#define RANDOM_SIZE (random() / (RAND_MAX / DEBUG_TAKE_SIZE))

void testBuffer(void) {
	PSoderoMemoryBuffer object = sodero_create_memory_buffer(DEBUG_BUFF_SIZE);
	for (int i = 0; i < 16; i++)
		sodero_buffer_create_chunk(object);
	sodero_destroy_memory_buffer(object);
}

void testManager(void) {
	PSoderoMemoryManager object = sodero_create_memory_manager(DEBUG_BUFF_SIZE);
	for (int i = 0; i < 16; i++) {
		sodero_memory_take(object, RANDOM_SIZE);
	}
	sodero_destroy_memory_manager(object);
}

void testStack(void) {
	PSoderoStack object = sodero_create_stack(DEBUG_BUFF_SIZE);
	for (int i = 0; i < 15; i++) {
		void * value = (void *) random();
		sodero_stack_push(object, value);
		printf("push %p size %lu\n", value, sodero_stack_size(object));
	}
	for (int i = 0; i < 16; i++) {
		void * value = sodero_stack_pop(object);
		printf("pop %p size %lu\n", value, sodero_stack_size(object));
	}
	sodero_destroy_stack(object);
}

void testPool(void) {
	PSoderoStack stack = sodero_create_stack(DEBUG_BUFF_SIZE);
	PSoderoMemoryPool object = sodero_create_memory_pool(24, DEBUG_BUFF_SIZE);
	for (int i = 0; i < DEBUG_BUFF_COUNT - 1; i++) {
		void * value = sodero_pool_take(object, RANDOM_SIZE);
		sodero_stack_push(stack, value);
		printf("push %p size %lu\n", value, sodero_stack_size(stack));
	}
	for (int i = 0; i < DEBUG_BUFF_COUNT; i++) {
		void * value = sodero_stack_pop(stack);
		printf("pop %p size %lu\n", value, sodero_stack_size(stack));
		sodero_pool_free(object, value);
	}
	for (int i = 0; i < DEBUG_BUFF_COUNT - 1; i++) {
		void * value = sodero_pool_take(object, RANDOM_SIZE);
		sodero_stack_push(stack, value);
		printf("push %p size %lu\n", value, sodero_stack_size(stack));
	}
	for (int i = 0; i < DEBUG_BUFF_COUNT; i++) {
		void * value = sodero_stack_pop(stack);
		printf("pop %p size %lu\n", value, sodero_stack_size(stack));
		sodero_pool_free(object, value);
	}

	sodero_destroy_memory_pool(object);
}

typedef int TDebugMapKey, * PDebugMapKey;
typedef struct DEBUG_MAP_VALUE {
	int index;
} TDebugMapValue, PDebugMapValue;

unsigned long sodero_map_test_hasher(PDebugMapKey key) {
	return *key;
}

unsigned long sodero_map_test_equaler(PDebugMapKey a, PDebugMapKey b) {
	return *a - *b;
}

void sodero_map_test_duplicator(PDebugMapKey a, PDebugMapKey b) {
	*a = *b;
}

void sodero_map_test_cleaner(TObject item) {
	if (item)
		bzero(item, sizeof(TDebugMapValue));
}

TObject sodero_map_test_creater(PSoderoMap map) {
	TObject result = malloc(sizeof(TDebugMapValue));
	sodero_map_test_cleaner(result);
	return result;
}

void sodero_map_test_releaser(PSoderoMap map, TObject item) {
	free(item);
}

long sodero_map_test_session_handlor(int index, PDebugMapValue result, void * data) {
	return 0;
}

void testMap(void) {
	PSoderoMap object = sodero_map_create(DEFAULT_IPV4_LENGTH, DEFAULT_IPV4_DELTA, DEFAULT_IPV4_SIZE, SODERO_MAP_MODE_NONE, nullptr,
		(THashHandlor) sodero_map_test_hasher, (TEqualHandlor) sodero_map_test_equaler, (TKeyDuplicator) sodero_map_test_duplicator,
		(TCreateHandlor)sodero_map_test_creater, (TReleaseHandlor)sodero_map_test_releaser, (TCleanHandlor) sodero_map_test_cleaner);

	TDebugMapKey   k;
	TDebugMapValue v;
	k = random();
	v.index = 1;

	TObject r = sodero_map_insert(object, &k, &v);
	printf("insert %p\n", r);

	r = sodero_map_insert(object, &k, &v);
	printf("insert %p\n", r);

	sodero_map_destroy(object);

	object = sodero_map_create(DEFAULT_IPV4_LENGTH, DEFAULT_IPV4_DELTA, DEFAULT_IPV4_SIZE, SODERO_MAP_MODE_HOLD, nullptr,
			(THashHandlor) sodero_map_test_hasher, (TEqualHandlor) sodero_map_test_equaler, (TKeyDuplicator) sodero_map_test_duplicator,
			(TCreateHandlor)sodero_map_test_creater, (TReleaseHandlor)sodero_map_test_releaser, (TCleanHandlor) sodero_map_test_cleaner);


	TObject n = sodero_map_ensure(object, &k);
	printf("ensure %p\n", n);

	n = sodero_map_ensure(object, &k);
	printf("ensure %p\n", n);

	n = sodero_map_insert(object, &k, &n);
	printf("insert %p\n", n);

	sodero_map_destroy(object);
}


unsigned long sodero_container_test_hasher(PPortKey key) {
	return key->l + key->h;
}

unsigned long sodero_container_test_equaler(PSoderoPortSession session, PPortKey key) {
	return (session->key.h == key->h) ? (session->key.l - key->l) : (session->key.h - key->h);
}

void sodero_container_test_duplicator(PSoderoPortSession session, PPortKey key) {
	session->key.h = key->h;
	session->key.l = key->l;
}

long sodero_container_test_session_handlor(int index, PSoderoPortSession session, void * data) {
	return 0;
}

//PSoderoContainer sodero_container_create(long length, int delta, int size, void * data,
//	THashHandlor scatter, TEqualHandlor comparer, TSoderoKeyDuplicator duplicator, TSoderoObjectKey keyof) {
void testContainer(void) {
	PSoderoContainer container = sodero_container_create(DEFAULT_IPV4_LENGTH, DEFAULT_IPV4_DELTA, sizeof(TSoderoPortSession), nullptr,
		(THashHandlor) sodero_container_test_hasher, (TEqualHandlor) sodero_container_test_equaler,
		(TKeyDuplicator) sodero_container_test_duplicator
#ifdef __CONTAINER_KEY__
		, (TSoderoObjectKey) nullptr
#endif
	);

	TPortKey key;
	key.h = 0x0123456789ABCDEFULL;
	key.l = 0xFEDCBA9876543210ULL;
	PSoderoPortSession session = sodero_container_ensure(container, &key);

	printf("%p @ %p\n", session, &key);
	session = sodero_container_ensure(container, &key);
	printf("%p @ %p\n", session, &key);

	key.l = 0x0123456789ABCDEFULL;
	key.h = 0xFEDCBA9876543210ULL;
	session = sodero_container_ensure(container, &key);
	printf("%p @ %p\n", session, &key);

	sodero_container_delete(container, &session->key);

	key.h = 0x0123456789ABCDEFULL;
	key.l = 0xFEDCBA9876543210ULL;
	sodero_container_delete(container, &session->key);

	key.l = 0x0123456789ABCDEFULL;
	key.h = 0xFEDCBA9876543210ULL;
	session = sodero_container_ensure(container, &key);
	printf("%p @ %p\n", session, &key);

	sodero_container_destroy(container);
}

long sodero_ipport_test_hasher(PPortHeader key) {
	return key->ip + key->port;
}

long sodero_ipport_test_equaler(PPortHeader a, PPortHeader b) {
	return ((a->destIP == b->destIP) && (a->sourIP == b->sourIP) && (a->destPort == b->destPort) && (a->sourPort == b->sourPort))
		|| ((a->destIP == b->sourIP) && (a->sourIP == b->destIP) && (a->destPort == b->sourPort) && (a->sourPort == b->destPort));
}

void sodero_ipport_test_duplicator(PPortHeader a, PPortHeader b) {
	a->ip   = b->ip  ;
	a->port = b->port;
}

TContainerKey sodero_tcp_test_keyof(PSoderoTCPSession session) {
	return &session->key;
}

void sodero_tcp_test_cleaner(TObject item) {
	if (item)
		bzero(item, sizeof(TSoderoTCPSession));
}

TObject sodero_tcp_test_creater(PSoderoContainer map) {
	TObject result = malloc(sizeof(TSoderoTCPSession));
	sodero_tcp_test_cleaner(result);
	return result;
}

void sodero_tcp_test_releaser(PSoderoContainer map, TObject item) {
	free(item);
}

long sodero_tcp_session_test_handlor(PSoderoTCPSession result, void * data) {
	printf("Session %p Timeout\n", result);
	return 0;
}


TSoderoSessionManager gDebugManager;
PSoderoContainer gDebugSessions;

PSoderoTCPSession test_create_session(PPortKey key, time_t t, int live) {
	PSoderoTCPSession session = sodero_container_ensure(gDebugSessions, key);
	session->key = *key;
	session->live = t + live * uSecsPerSec;
	printf("Session %p created port %d live %u step %d\n", session, session->key.port, session->live, live);
	sodero_session_insert(&gDebugManager, (PSoderoSession) session);
	return session;
}


void testXDRNodes(void) {
	XDR xdr;
	char buffer[XDR_BUFFER_SIZE];
	sodero_init_xdr_encode(&xdr, buffer, XDR_BUFFER_SIZE);
	TSoderoTCPReportMsg message;
	TSoderoTCPReportMsg * pointer = & message;
	bzero(pointer, sizeof(message));

	message.type = SODERO_NODES;
	message.TSoderoTCPReportMsg_u.nodes.nodes_len = 3;
	message.TSoderoTCPReportMsg_u.nodes.nodes_val = (TSoderoNodeMsg*) calloc(3, sizeof(TSoderoNodeMsg));
	for (int i = 0; i < message.TSoderoTCPReportMsg_u.nodes.nodes_len; i++)
		snprintf((char*)message.TSoderoTCPReportMsg_u.nodes.nodes_val[i].name, sizeof(message.TSoderoTCPReportMsg_u.nodes.nodes_val[i].name), "Node%d", i);

	xdr_TSoderoTCPReportMsg(&xdr, pointer);
	printf("Poisition is %u\n", xdr_getpos(&xdr));
}

void testXDRRegisger(void) {
	XDR xdr;
	char buffer[XDR_BUFFER_SIZE];
	sodero_init_xdr_encode(&xdr, buffer, XDR_BUFFER_SIZE);
	TSoderoClientRegisterMsg message;
	PSoderoClientRegisterMsg pointer = & message;
	bzero(pointer, sizeof(message));
	strncpy((char*)message.name, "Test String", sizeof(message.name) - 1);

	printf("TSoderoClientRegisterMessage is %lu\n", sizeof(TSoderoClientRegisterMsg));
	xdr_TSoderoClientRegisterMsg(&xdr, pointer);
	printf("Poisition is %u\n", xdr_getpos(&xdr));
}

void testXDR(void) {
//	testXDRRegisger();
//	testXDRNodes();

	sodero_report_connect();

	sodero_report_disconnect();
}

void testSesions(void) {
	sodero_initialize_session_manager(&gDebugManager, SecsPerHour);
	gDebugSessions = sodero_container_create(DEFAULT_TCP_LENGTH, DEFAULT_TCP_DELTA, DEFAULT_TCP_SIZE, nullptr,
					(THashHandlor) sodero_ipport_test_hasher, (TEqualHandlor) sodero_ipport_test_equaler, (TKeyDuplicator) sodero_ipport_test_duplicator
#ifdef __CONTAINER_KEY__
					, (TSoderoObjectKey) sodero_tcp_test_keyof
#endif
					);

	unsigned long long t = now();
	TPortKey key;
	key.l = 0;
	key.h = 0;
	key.port = random();
	gDebugManager.tick = t / uSecsPerSec;

	test_create_session(&key, t,  2);
	test_create_session(&key, t,  7);
	test_create_session(&key, t, 12);
	test_create_session(&key, t,  7);
	test_create_session(&key, t,  2);
	test_create_session(&key, t,  7);
	test_create_session(&key, t, 12);
	test_create_session(&key, t, 12);
	test_create_session(&key, t,  2);
	test_create_session(&key, t,  2);
	test_create_session(&key, t,  7);
	test_create_session(&key, t, 12);

	while(TRUE) {
		t ++;
//		printf("Tick: %llu\n", t);
		sodero_session_check(&gDebugManager, t);
	};
}

PCaptureContext gContext;

int gRunning = TRUE;

unsigned long long gRealBase;
unsigned long long gDataBase;
double gScale   = 0;

void alarm_handlor(int sig) {
	alarm(60);
#ifdef __EXPORT_STATISTICS__
	dumpStatistics();
#endif
}

void closeAll(void) {
	long long b = now();
	cleanAll();
	long long e = now();

	printf("Clean all sessions in %.3fs\n", 1e-6*(e-b));

	dpiClose();

	size_t session_count = sodero_table_count(getSessions());
	size_t application_fresh = sodero_pointer_count(getFreshApplications());
	size_t application_close = sodero_pointer_count(getClosedApplications());
	size_t stream_count = sodero_pointer_count(getFreshStreams());
	size_t events_count = sodero_pointer_count(getEvents());

	release_core();
#ifdef __EXPORT_STATISTICS__
	dumpStatistics();
#endif
	printf("Alive session %lu application create %lu close %lu stream create %lu event %lu\n",
			session_count, application_fresh, application_close, stream_count, events_count);
}

void sig_ignore(int sig) {
	sodero_report_disconnect();
}

void sig_handlor(int sig) {
	if (!gRunning) return;
	gRunning = 0;
	sodero_report_disconnect();
	stopDevice(gContext);
	closeAll();
	sslol_deinit();
}

void scale_time(PTimeStamp stamp) {
	if (gScale) {
		unsigned long long delta = (stamp->usecond * uSecsPerSec + stamp->usecond) - gDataBase;
		unsigned long long time = gRealBase + gScale * delta;
		while(now() < time)
			usleep(1);
		stamp->seconds = time / uSecsPerSec;
		stamp->usecond = time % uSecsPerSec;
	}
}

void prepare(void) {
	gContext = (PCaptureContext) malloc(sizeof(*gContext));
	bzero(gContext, sizeof(*gContext));
	initial_logic();
	if (gDPIRulesTable) {
		dpiInitModule();
		dpi_upgrade(gDPIRulesTable);
	}
}

pthread_t gCapturer;
char * gBuffer;
unsigned int gBufferLength;
unsigned int gBufferHeadBlock;
unsigned int gBufferHeadOffset;
unsigned int gBufferTailBlock;
unsigned int gBufferTailOffset;

void init_buffer(void) {
	gBufferLength = 128 * Mi;
	gBufferHeadBlock  = 0;
	gBufferHeadOffset = 0;
	gBufferTailBlock  = 0;
	gBufferTailOffset = 0;
	gBuffer = (char*)malloc(gBufferLength + 64 * Ki);
}

void init_thread(void *(*routine) (void *), void * arg) {
    pthread_t result = 0;
    pthread_attr_t attr;
    struct sched_param param;

    pthread_attr_init(&attr);
    pthread_attr_setschedpolicy(&attr, SCHED_RR);
    param.sched_priority = sched_get_priority_max(SCHED_RR);
    pthread_attr_setschedparam(&attr, &param);
    if (pthread_create(&gCapturer, &attr, routine, arg)) {
        printf("Create capture thread success\n");
        pthread_detach(result);
    }
    pthread_attr_destroy(&attr);
}

void data_receiver(PPCAPPacketHeader header, const void * data, unsigned int size) {
	if (size > MAX_PACKET_SIZE) return;
	while (gBufferHeadBlock < gBufferTailBlock) {
		if ((gBufferHeadOffset - gBufferTailBlock) > (size + sizeof(*header)))
			break;
		usleep(1);
	}

	memcpy(gBuffer + gBufferHeadOffset, data, size);
	gBufferHeadOffset += size;
	if (gBufferHeadOffset > gBufferLength) {
		gBufferHeadOffset = 0;
		gBufferHeadBlock++;
	}
}

void data_handler(void) {
	while (gBufferHeadBlock <= gBufferTailBlock) {
		if (gBufferHeadOffset > gBufferTailOffset)
			break;
		usleep(1);
	}
	PPCAPPacketHeader header = (PPCAPPacketHeader) (gBuffer + gBufferHeadOffset);
	PEtherPacket packet = (PEtherPacket) (header + 1);
	pcapHandler(packet, header);
}

void simulate(const char * file) {
	int fd = open(file, O_RDONLY);
	printf("Process file: %s @ %d\n", file, fd);
	if (fd > 0) {
		unsigned int index = 0;
		do {
			char buffer [1024 * 1024];
			lseek(fd, 0, SEEK_SET);
			unsigned int length = read(fd, buffer, sizeof(buffer));
			unsigned int offset = sizeof(TPCAPFileHeader);
			//memcpy(buffer, buffer+236, sizeof(buffer)-236);

			if (gLoop) gScale = 0;

			if (length > sizeof(TPCAPFileHeader)) {

				unsigned int size = length;
				long long b = now();
				PPCAPPacketHeader header = (PPCAPPacketHeader) (buffer + offset);
				if (!gDataBase && gScale)
					gDataBase = header->time.usecond * uSecsPerSec + header->time.usecond;
				while(size > sizeof(TPCAPPacketHeader)) {
					unsigned int gate = size - sizeof(TPCAPPacketHeader);
					while (offset < gate) {
						header = (PPCAPPacketHeader) (buffer + offset);
						if (offset + header->length <= gate) {
							PEtherPacket packet = (PEtherPacket) (header + 1);
							offset += sizeof(*header) + header->length;

							if (gLoop) {
								struct timeval tv;
//								struct timezone tz;
								gettimeofday(&tv, NULL);

								header->time.seconds = tv.tv_sec ;	//	+ 60 * (tz.tz_dsttime);
								header->time.usecond = tv.tv_usec;
							}

							scale_time(&header->time);

#ifdef __SIMLATE_DROP__
							if (random() < RAND_MAX / 200) {
								continue;
							}
#endif
							pcapHandler(packet, header);
						} else
							break;
					}

					size -= offset;
					memmove(buffer, buffer + offset, size);
					bzero  (        buffer + size, offset);
					offset = 0;

					int bytes = read(fd, buffer + size, sizeof(buffer) - size);
					if (bytes > 0) {
						size   += bytes;
						length += bytes;
					} else
						break;
				};
				sodero_report_result(getPeriodResult(), getSessionManager());
				long long e = now();

				printf("No: %u process %u packet %.3fMB in %.3fs %.3fMbps\n",
						index++, gTotal.count, 1e-6*gTotal.bytes, 1e-6*(e-b), 8.0 * gTotal.bytes / (e-b));
			}
			if (gLoop > 0) gLoop--;
		} while(gLoop);
	}
}

void capture(void) {

	gContext = createContext(createDevice(gDevice), nullptr);
	if (!gContext) {
		return;
	}

	printf("Start with device %s @ %p - capture %p\n", gDevice, gContext, gContext->pcap);
	initial_logic();

	alarm(60);

	while(gRunning) {
		TCaptureHeader header;
		PEtherPacket packet = takePacket(gContext, &header);
//		if (packet) {
////			printf("Capture packet %p - %lu.%lu %u/%u\n", packet,
////					header.ts.tv_sec, header.ts.tv_usec, header.caplen, header.len);
//			pcapHandler(packet, &header);
//		};
		packetHandler(packet, header.caplen, header.len);
//		if (packet)
//			processA(&gTotal, header.len);
	}

	destroyContext(gContext);
	printf("Shutdown\n");
}

void testSearch(PSundayData sunday, const char * text) {
	int result = sunday_find(sunday, text, strlen(text));
	printf("sundy %4d in %s\n", result, text);
}

void testSunday(void) {
	PSundayData sunday = sunday_init("----------KM7ei4Ef1gL6ae0ei4gL6GI3GI3gL6");

	testSearch(sunday, "----------KM7ei4Ef1gL6ae0ei4gL6GI3GI3gL6");
	testSearch(sunday, "----------KM7ei4Ef1gL6ae0ei4gL6GI3GI3gL6--");
	testSearch(sunday, "------------KM7ei4Ef1gL6ae0ei4gL6GI3GI3gL6");
	testSearch(sunday, "----------KM7ei4Ef1gL6ae0ei4gL6GI3GI3gL6--BB");
	testSearch(sunday, "==----------KM7ei4Ef1gL6ae0ei4gL6GI3GI3gL6--");
	testSearch(sunday, "==----------KM7ei4Ef1gL6ae0ei4gL6GI3GI3gL6----");
	testSearch(sunday, "==----------KM7ei4Ef1gL6ae0ei4gL6GI3GI3gL6--==");
}

void testDPI(void) {
	dpiInitModule();
	loadDPIEntries("ip-port.tsv", DPI_ENTRIES_RELOAD);
	TIPv4 ip;
	TDPIValue result;
	sscanf("54.92.46.172", "%hhu.%hhu.%hhu.%hhu", ip.s + 0, ip.s + 1, ip.s + 2, ip.s + 3);
	printf("%u.%u.%u.%u\n", ip.s[0], ip.s[1], ip.s[2], ip.s[3]);
	result = dpi_lookup_ippf(ip.ip, htons(22), 6, 0);
	if (result.value)
		printf("flag %u application %u category %u-%u attribute %u\n",
				result.flag, result.application, result.major, result.minor, result.attribute);
	else
		printf("Not found\n");
}

void debug(int argc, char * argv[]) {
//	testBuffer();
//	testManager();
//	testStack();
//	testPool();
//	testContainer();
//	testSesions();
//	testXDR();

//	testSunday();

//	testDPI();
       DPI_LogInit("dpi_metric.log");
       DPI_Log(0, "%s","DPI Logging File Format----SysTime    [logging level]    Function:Line    TraceContent\n\
                    TraceContent Format: \n                    1.Metric---[Metric:Time|Item|MacAddr|IPAddr|Value]\n\
                    2.Session---[Session:ID|Session type|Event type|SourIP:SourPort->DstIP:DstPort|ReqBytes|RspBytes]\n\
                    3.Event---event info");
                    
	enum_interfaces();
#ifdef __EXPORT_STATISTICS__
	gDump = fopen("memory.log", "w");
	printf("Open dump log @ %p\n", gDump);
#endif

	printf("nice %d\n", nice(-20));

	printf("UDP %lu Record %lu DNS %lu\n",
			sizeof(TSoderoUDPSession), sizeof(TSoderoUDPRecord), sizeof(TSoderoApplicationDNS));
	printf("TCP %lu Record %lu Value %lu HTTP %lu MySQL %lu\n",
		sizeof(TSoderoTCPSession), sizeof(TSoderoUDPRecord), sizeof(TSoderoTCPValue), sizeof(TSoderoApplicationHTTP), sizeof(TSoderoMySQLApplication));

	srandom(time(NULL));

	signal(SIGPIPE, sig_ignore);

	signal(SIGHUP , sig_handlor);
	signal(SIGINT , sig_handlor);
	signal(SIGABRT, sig_handlor);
	signal(SIGQUIT, sig_handlor);
	signal(SIGTERM, sig_handlor);

	signal(SIGALRM, alarm_handlor);

	initArguments(argc, argv);
	sslol_init();
	sodero_report_check();
	if (gDebug) {
		prepare();
		simulate(gDebug);
		closeAll();
	} else
		capture();
#ifdef __EXPORT_STATISTICS__
	if (gDump) {
		fflush(gDump);
		fclose(gDump);
	}
	DPI_LogClose();
#endif
}
