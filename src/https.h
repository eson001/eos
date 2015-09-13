#ifndef __HTTPS_H__
#define __HTTPS_H__

#ifdef	__cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <pcap.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <stdlib.h>
#ifdef _DEBUG
#include <assert.h>
#define FALSE 0
#define _ASSERT( exp ) assert( exp )
#else
#define _ASSERT( exp ) ((void)0)
#endif
#define HTTPS_STRDUP(x) strdup(x)

#ifndef FIELD_OFFSET
#define FIELD_OFFSET( t, f ) ((int) &(((t*)NULL)->f))
#endif

#if defined(__linux)
  #include <features.h>
  #define __FAVOR_BSD
  #include <netinet/ether.h>
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  #include <netinet/udp.h>
  #define ETHER_HDRLEN	14
  #define TH_ECNECHO	0x40  
  #define TH_CWR		0x80 

#elif defined(__FreeBSD__) || defined(__APPLE__)
  #include <netinet/in_systm.h>
  #include <netinet/in.h>
  #include <net/ethernet.h>
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  #include <netinet/udp.h>
  #define ETHER_HDRLEN	14
  #define TH_ECNECHO	0x40
  #define TH_CWR		0x80

#else
  #include <netinet/ether.h>
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  #include <netinet/udp.h>
#endif

/*222*/

typedef enum DPI_SessionType_
{
	eSessTypeNull = 0,
	eSessTypeTcp = 1,
	eSessTypeSSL = 2,
	eSessTypeTBD = 3
} DPI_SessionType;

typedef enum DPI_PacketDir_
{
	ePktDirInvalid,
	ePktDirFromClient,
	ePktDirFromServer
} DPI_PacketDir;

typedef enum DPI_SessionEvents_
{
	eNull,					
	eHttpsHandshakeComplete,
	eHttpsMappedKeyFailed,	
	eHttpsMappingDiscovered,	
	eHttpsMissingServerKey	
} DPI_SessionEvents;


struct HTTPS_Pkt_;
typedef struct HTTPS_Pkt_ HTTPS_Pkt;

struct HTTPS_Session_;
typedef struct HTTPS_Session_ HTTPS_Session;

struct HTTPS_ServerInfo_;
typedef struct HTTPS_ServerInfo_ HTTPS_ServerInfo;

struct https_SessionKeyTable_;
typedef struct https_SessionKeyTable_ https_SessionKeyTable;

typedef struct https_SessionTable_ https_SessionTable;

struct	_HTTPS_SessionTicketTable;
typedef struct _HTTPS_SessionTicketTable  HTTPS_SessionTicketTable;

struct _TcpSession;
typedef struct _TcpSession TcpSession;

struct HttpsEnv_;
typedef struct HttpsEnv_ HttpsEnv;

struct _TcpStream;
typedef struct _TcpStream TcpStream;

struct _HTTPS_CipherSuite;
typedef struct _HTTPS_CipherSuite HTTPS_CipherSuite;

struct https_decoder_;
typedef struct https_decoder_ https_decoder;

struct https_decoder_stack_;
typedef struct https_decoder_stack_ https_decoder_stack;

typedef void (*DataCallbackProc)( DPI_PacketDir dir, void* user_data, u_char* data, uint32_t len, HTTPS_Pkt* pkt );
typedef void (*ErrorCallbackProc)( void* user_data, int error_code );

typedef int (*MissingPacketCallbackProc)( DPI_PacketDir dir, void* user_data, uint32_t seq, uint32_t len );

typedef void (*EventCallbackProc)(void* user_data, int event_code, const void* event_data);

#define IS_ENOUGH_LENGTH( org_data, org_len, cur_data, size_needed ) ( (org_data) + (org_len) >= (cur_data) + (size_needed) )
#define _ASSERT_STATIC(e) 1/(e)
#define UNUSED_PARAM( p ) (p)


#define SSL3_HEADER_LEN 	5
#define SSL20_CLIENT_HELLO_HDR_LEN		2
#define SSL20_SERVER_HELLO_MIN_LEN		10
#define SSL3_SERVER_HELLO_MIN_LEN		38
#define SSL3_HANDSHAKE_HEADER_LEN		4
#define SSL2_KEYARG_MAX_LEN 8

#define HTTPS_SESSION_ID_SIZE	32

#define RFC_2246_MAX_RECORD_LENGTH	16384

#ifdef HTTPS_NO_COMPRESSION
	#define RFC_2246_MAX_COMPRESSED_LENGTH	RFC_2246_MAX_RECORD_LENGTH
#else
	#define RFC_2246_MAX_COMPRESSED_LENGTH	(RFC_2246_MAX_RECORD_LENGTH + 1024)
#endif

#define HTTPS_MAX_RECORD_LENGTH	32767
#define HTTPS_MAX_COMPRESSED_LENGTH (HTTPS_MAX_RECORD_LENGTH	+ 1024)

#define HTTPS_DEFAULT_MISSING_PACKET_COUNT		100
#define HTTPS_DEFAULT_MISSING_PACKET_TIMEOUT 	180

#define HTTPS_CACHE_CLEANUP_INTERVAL 	180


/*222*/

struct HTTPS_ServerInfo_
{
	struct in_addr	server_ip;
	uint16_t		port;
	EVP_PKEY*		pkey;
};


typedef struct _HTTPS_Env
{
	HTTPS_ServerInfo**		servers;
	int 					server_count;

	HTTPS_ServerInfo**		missing_key_servers;
	int 					missing_key_server_count;

	https_SessionKeyTable*		session_cache;
	HTTPS_SessionTicketTable*	ticket_cache;

	EVP_PKEY**				keys;
	int 					key_count;
	int 					keys_try_index; 

	u_char			decompress_buffer[HTTPS_MAX_RECORD_LENGTH];
	u_char			decrypt_buffer[HTTPS_MAX_COMPRESSED_LENGTH];

} HTTPS_Env;


HTTPS_Env* HTTPS_EnvCreate( int session_cache_size, uint32_t cache_timeout_interval );
void HTTPS_EnvDestroy( HTTPS_Env* env );


int HTTPS_EnvSetServerInfoWithKey( HTTPS_Env* env, const struct in_addr* ip_address,
	uint16_t port, EVP_PKEY *pkey );

int HTTPS_EnvSetServerInfo( HTTPS_Env* env, const struct in_addr* ip_address, uint16_t port, 
			const char* keyfile, const char* password );
			
HTTPS_ServerInfo* HTTPS_EnvFindServerInfo( const HTTPS_Env* env, struct in_addr server_ip, uint16_t port );

HTTPS_Session* HTTPS_EnvCreateSession( HTTPS_Env* env, struct in_addr dst_ip, uint16_t dst_port,
									struct in_addr src_ip, uint16_t src_port );
void HTTPS_EnvOnSessionClosing( HTTPS_Env* env, HTTPS_Session* sess );

void HTTPS_ServerInfoFree( HTTPS_ServerInfo* si );

int HTTPS_AddSSLKey(HTTPS_Env* env, EVP_PKEY* pkey);

/*222*/

struct HttpsEnv_;

#define HTTPS_EVENT_NEW_SESSION			0
#define HTTPS_EVENT_SESSION_CLOSING		1
#define HTTPS_EVENT_SESSION_LIMIT		2

typedef void (*HttpsEnvSessionCallback)( struct HttpsEnv_* env, TcpSession* sess, char event );

typedef void (*HttpsEnvDatagramCallback)( struct HttpsEnv_* env, const u_char* data, uint32_t len, HTTPS_Pkt* pkt );

struct HttpsEnv_
{
	pcap_t* 			pcap_adapter;
	pcap_handler		handler;
	
	https_SessionTable*	sessions;
	HTTPS_Env*			ssl_env;

	DPI_SessionType (*ForReassemble)( struct HttpsEnv_* env, HTTPS_Pkt* pkt );
	
	HttpsEnvSessionCallback	session_callback;

	HttpsEnvDatagramCallback	datagram_callback;
	void* env_user_data;
#ifdef DPI_TRACE_FRAME_COUNT
	uint32_t				frame_cnt; 
#endif
};


HttpsEnv* HttpsEnvCreate( pcap_t* adapter, int sessionTableSize, uint32_t key_timeout_interval, uint32_t tcp_timeout_interval);
void HttpsEnvDestroy( HttpsEnv* env );

void HttpsEnvSetSessionCallback( HttpsEnv* env, HttpsEnvSessionCallback callback, void* user_data );

int HttpsEnvSetSSL_ServerInfo( HttpsEnv* env, const struct in_addr* ip_address, uint16_t port, 
			const char* keyfile, const char* password );

HTTPS_ServerInfo* HttpsEnvFindHTTPS_ServerInfo( const HttpsEnv* env, const struct in_addr* server_ip, uint16_t server_port );

int HttpsEnvIsSSLPacket( const HttpsEnv* env, const HTTPS_Pkt* pkt );

void HttpsEnvProcessPacket( HttpsEnv* env, HTTPS_Pkt* pkt );

/*222*/

typedef enum SSL_KeyExchangeMethod_
{
	SSL_KEX_RSA,
	SSL_KEX_DH
} SSL_KeyExchangeMethod;

typedef enum SSL_SignatureMethod_
{
	SSL_SIG_RSA,
	SSL_SIG_DSS
} SSL_SignatureMethod;


struct _HTTPS_CipherSuite
{
	uint16_t				id;
	uint16_t				ssl_version;

	uint16_t				key_ex;

	int 					export_key_bits;

	const char* 			enc;
	const char* 			digest;
};

HTTPS_CipherSuite* HTTPS_GetSSL3CipherSuite( uint16_t id );

HTTPS_CipherSuite* HTTPS_GetSSL2CipherSuite( uint16_t id );

int HTTPS_ConvertSSL2CipherSuite( u_char cs[3], uint16_t* pcs );

int HTTPS_CipherSuiteExportable( HTTPS_CipherSuite* ss );

/*222*/

int https_compr_init( u_char compr_method, void** compr_state );
void https_compr_deinit( u_char compr_method, void* compr_state );

int https_decompress( u_char compr_method, void* compr_state, u_char* in_data, uint32_t in_len,
					u_char* out_data, uint32_t* out_len );
/*222*/

void DecodeIpPacket( HttpsEnv* env, HTTPS_Pkt* pkt, const uint8_t* data, const int len );
void DecodeTcpPacket( HttpsEnv* env, HTTPS_Pkt* pkt, const uint8_t* data, const int len );

/*222*/

typedef int (*sslc_decode_proc)( void* state,
		DPI_PacketDir dir, u_char* data, uint32_t len, uint32_t* processed );

struct https_decoder_
{
	void*				handler_data;
	sslc_decode_proc	handler;
	uint32_t			buff_len;
	uint32_t			buff_used_len;
	u_char* 			buff;
};

void https_decoder_init( https_decoder* decoder, sslc_decode_proc handler, void* handler_data );
void https_decoder_deinit( https_decoder* decoder );

int https_decoder_process( https_decoder* decoder, DPI_PacketDir dir, u_char* data, uint32_t len );

int https_decoder_add_to_buffer( https_decoder* decoder, u_char* data, uint32_t len );
int https_decoder_shift_buffer( https_decoder* decoder, uint32_t processed_len );


/*222*/

typedef enum SSL_SessionState_
{
	SS_Initial,
	SS_SeenClientHello,
	SS_SeenServerHello,
	SS_Established,
	SS_FatalAlert,
	SS_SeenCloseNotify
}SSL_SessionState; 

struct https_decoder_stack_
{
	SSL_SessionState state;
	https_decoder	drecord;
	https_decoder	dhandshake;
	https_decoder	dappdata;
	https_decoder	dalert;
	https_decoder	dcss;

	EVP_CIPHER_CTX* cipher;
	const EVP_MD*	md;

	uint64_t		seq_num;
	u_char			mac_key[EVP_MAX_MD_SIZE];

	EVP_CIPHER_CTX* cipher_new;
	const EVP_MD*	md_new;
	u_char			mac_key_new[EVP_MAX_MD_SIZE];

	char			compression_method;
	void*			compression_data; 

	char			compression_method_new;
	void*			compression_data_new;

	HTTPS_Session*	sess;
};


void https_decoder_stack_init( https_decoder_stack* stack );
void https_decoder_stack_deinit( https_decoder_stack* stack );
int https_decoder_stack_process( https_decoder_stack* stack, DPI_PacketDir dir, u_char* data, uint32_t len );

int sslc_is_decoder_stack_set( https_decoder_stack* s );

int https_decoder_stack_set( https_decoder_stack* s, HTTPS_Session* sess, uint16_t version );

int https_decoder_stack_flip_cipher( https_decoder_stack* s );


/*222*/

#define DPI_IS_FAILED( rc ) ((rc) < 0) 

#define HTTPS_RC_WOULD_BLOCK 					1
#define HTTPS_RC_OK								0
#define HTTPS_E_OUT_OF_MEMORY					(-1)
//#define HTTPS_E_SSL_LOAD_CERTIFICATE				(-3)
#define HTTPS_E_SSL_LOAD_PRIVATE_KEY 			(-4)
#define HTTPS_E_SSL_UNKNOWN_VERSION				(-5)
#define HTTPS_E_INVALID_PARAMETER				(-6)
#define HTTPS_E_SSL_PROTOCOL_ERROR				(-7)
#define HTTPS_E_SSL_INVALID_RECORD_LENGTH		(-8)
#define HTTPS_E_UNSPECIFIED_ERROR				(-9)
#define HTTPS_E_NOT_IMPL 						(-10)
#define HTTPS_E_SSL_SERVER_KEY_UNKNOWN			(-11)
#define HTTPS_E_SSL_CANNOT_DECRYPT				(-12)
#define HTTPS_E_SSL_CORRUPTED_PMS				(-13)
#define HTTPS_E_SSL_PMS_VERSION_ROLLBACK 		(-14)
#define HTTPS_E_SSL_DECRYPTION_ERROR 			(-15)
#define HTTPS_E_SSL_BAD_FINISHED_DIGEST			(-16)
#define HTTPS_E_TCP_CANT_REASSEMBLE				(-17)
#define HTTPS_E_SSL_UNEXPECTED_TRANSMISSION		(-18)
#define HTTPS_E_SSL_INVALID_MAC					(-19)
#define HTTPS_E_SSL_SESSION_NOT_IN_CACHE 		(-20)
#define HTTPS_E_SSL_PRIVATE_KEY_FILE_OPEN		(-21)
#define HTTPS_E_SSL_INVALID_CERTIFICATE_RECORD	(-22)
#define HTTPS_E_SSL_INVALID_CERTIFICATE_LENGTH	(-23)
#define HTTPS_E_SSL_BAD_CERTIFICATE				(-24)
#define HTTPS_E_UNINITIALIZED_ARGUMENT			(-25)
#define HTTPS_E_SSL_CANNOT_DECRYPT_EPHEMERAL 	(-26)
#define HTTPS_E_SSL_CANNOT_DECRYPT_NON_RSA		(-27)
#define HTTPS_E_SSL_CERTIFICATE_KEY_MISMATCH 	(-28)
#define HTTPS_E_UNSUPPORTED_COMPRESSION			(-29)
#define HTTPS_E_DECOMPRESSION_ERROR				(-30)
#define HTTPS_E_SSL2_INVALID_CERTIFICATE_TYPE	(-31)
#define HTTPS_E_SSL2_UNKNOWN_CIPHER_KIND 		(-32)
#define HTTPS_E_SSL2_BAD_SERVER_VERIFY			(-33)
#define HTTPS_E_SSL2_BAD_CLIENT_FINISHED 		(-34)
#define HTTPS_E_TCP_REASSEMBLY_QUEUE_FULL		(-35)
#define HTTPS_E_TCP_MISSING_PACKET_DETECTED		(-36)
#define HTTPS_E_SSL_SESSION_TICKET_NOT_CACHED	(-37)
#define HTTPS_E_SSL_DUPLICATE_SERVER 			(-38)
#define HTTPS_E_TCP_GLOBAL_REASSEMBLY_QUEUE_LIMIT (-39)

#ifdef _DEBUG
	int NmDebugCatchError( int rc );
	#define DPI_ERROR( rc ) NmDebugCatchError( rc )
#else
	#define DPI_ERROR( rc ) (rc)
#endif

/*222*/


#define FNV_32_PRIME ((uint32_t)0x01000193)
#define FNV1_32_INIT ((uint32_t)0x811c9dc5)

uint32_t fnv_32_buf(const void *buf, size_t len, uint32_t hval);

/*222*/

/*
#define DPI_TRACE_SSL
#define DPI_TRACE_TCP
*/

#ifdef DPI_TRACE_SSL
	#define DPI_TRACE_SSL_HANDSHAKE
	#define DPI_TRACE_SSL_RECORD
	#define DPI_TRACE_SSL_SESSIONS
	#define DPI_TRACE_SSL_SESSION_CACHE
#endif

#ifdef DPI_TRACE_TCP
	#define DPI_TRACE_FRAME_COUNT
	#define DPI_TRACE_TCP_STREAMS
	#define DPI_TRACE_TCP_SESSIONS
	#define DPI_TRACE_MEMORY_USAGE
#endif

void nmLogMessage( uint32_t category, const char* fmt, ... );

#define LG_SEVERITY_MESSAGE 0x1000
#define LG_SEVERITY_WARNING 0x2000
#define LG_SEVERITY_ERROR	0x3000

#define LG_SEVERITY_MASK	0xf000

#define LG_CATEGORY_GENERAL 0x0000
#define LG_CATEGORY_CAPTURE 0x0001

#define ERR_GENERAL (LG_SEVERITY_ERROR | LG_CATEGORY_GENERAL)
#define ERR_CAPTURE (LG_SEVERITY_ERROR | LG_CATEGORY_CAPTURE)

#ifdef _DEBUG
	#define DPI_ENABLE_TRACE
#endif

#ifdef DPI_ENABLE_TRACE
	#define DEBUG_TRACE0( fmt ) printf( fmt )
	#define DEBUG_TRACE1( fmt, p1 ) printf( fmt, p1 )
	#define DEBUG_TRACE2( fmt, p1, p2 ) printf( fmt, p1, p2 )
	#define DEBUG_TRACE3( fmt, p1, p2, p3 ) printf( fmt, p1, p2, p3 )
	#define DEBUG_TRACE4( fmt, p1, p2, p3, p4 ) printf( fmt, p1, p2, p3, p4 )
#else
	#define DEBUG_TRACE0( fmt )
	#define DEBUG_TRACE1( fmt, p1 ) 
	#define DEBUG_TRACE2( fmt, p1, p2 ) 
	#define DEBUG_TRACE3( fmt, p1, p2, p3 )
	#define DEBUG_TRACE4( fmt, p1, p2, p3, p4 )
#endif

/*222*/

#define MAKE_IP( b1, b2, b3, b4 ) ((uint32_t)(b1 | ((uint32_t)b2 << 8) | ((uint32_t)b3 << 16) | ((uint32_t)b4 << 24 )))

#if defined (__linux)
  #define INADDR_IP( _inaddr ) ((_inaddr).s_addr)
  #define DPI_TCP_HDR_LEN( hdr ) (((u_char)(hdr)->th_off ) << 2 )
  #define IP_V(ip ) ((ip)->ip_v)
  #define IP_HL(ip) ((ip)->ip_hl)
#elif defined(__FreeBSD__) || defined(__APPLE__)
  #define INADDR_IP( _inaddr ) ((_inaddr).s_addr)
  #define DPI_TCP_HDR_LEN( hdr ) (((u_char)(hdr)->th_off ) << 2 )
  #define IP_V(ip ) ((ip)->ip_v)
  #define IP_HL(ip) ((ip)->ip_hl)
#endif

/*222*/


#define HTTPS_PKT_ACK_MATCH		1

struct HTTPS_Pkt_
{
	const u_char*				pcap_ptr;
	struct pcap_pkthdr			pcap_header;

	uint8_t 					link_type;
	struct ether_header*		ether_header;
	struct ip*					ip_header;
	struct tcphdr*				tcp_header;
	struct udphdr*				udp_header;

	TcpSession* 				session;

	struct HTTPS_Pkt_*			next;
	struct HTTPS_Pkt_*			prev;

	struct timeval				ack_time;	
	uint16_t					data_len;
	uint16_t					flags;
};

#define PKT_TCP_SEQ( p ) ntohl( (p)->tcp_header->th_seq )
#define PKT_TCP_ACK( p ) ntohl( (p)->tcp_header->th_ack )
#define PKT_TCP_DPORT( p ) ntohs( (p)->tcp_header->th_dport )
#define PKT_TCP_SPORT( p ) ntohs( (p)->tcp_header->th_sport )
#define PKT_HAS_TCP_ACK( p ) (p->tcp_header->th_flags & TH_ACK)

#define PKT_TCP_PAYLOAD( p ) ((u_char*)((p)->tcp_header) + DPI_TCP_HDR_LEN( (p)->tcp_header ))

uint32_t PktNextTcpSeqExpected( const HTTPS_Pkt* pkt );

HTTPS_Pkt* PktClone( const HTTPS_Pkt* src );
int PktCloneChunk(const HTTPS_Pkt* src, int tail_len, HTTPS_Pkt** rc);
void PktFree( HTTPS_Pkt* pkt );

int PktCompareTimes( const HTTPS_Pkt* pkt1, const HTTPS_Pkt* pkt2 );

/*222*/


#define HTTPS_TCPSTREAM_SENT_SYN 	1
#define HTTPS_TCPSTREAM_SENT_FIN 	2
#define HTTPS_TCPSTREAM_SENT_RST 	4

#define HTTPS_STREAM_MAX_REASSEMBLY_DEPTH	1024

#define HTTPS_ACK_TIME_BUFFER_SIZE			2

typedef struct _PktAckTime
{
	uint32_t			seq;
	struct timeval		ack_time;
} PktAckTime;

typedef struct _TcpStreamStats
{
	uint32_t	data_pkt_count;
	uint32_t	ack_pkt_count;
	uint32_t	retrans_pkt_count;
} TcpStreamStats;

struct _TcpStream
{
	uint32_t		ip_addr;
	uint16_t		port;
	uint16_t		flags;
	HTTPS_Pkt*		pktHead;
	HTTPS_Pkt*		pktTail;
	uint32_t		nextSeqExpected;
	uint32_t		lastPacketAck;
	TcpSession* 	session;
	uint32_t		queue_size;
	uint32_t		initial_seq;
	struct timeval	syn_time; 
	struct timeval	first_ack_time; 

	PktAckTime		acks[HTTPS_ACK_TIME_BUFFER_SIZE];
	int 			ack_idx;

	TcpStreamStats	stats;
};


void StreamInit( TcpStream* stream, TcpSession* sess, uint32_t ip, uint16_t port );
void StreamFreeData( TcpStream* stream );

int StreamProcessPacket( TcpStream* stream, HTTPS_Pkt* pkt, int* new_ack );

TcpStream* StreamGetPeer( const TcpStream* stream );
int StreamConsumeHead( TcpStream* stream, int* new_ack );

int StreamPollPackets( TcpStream* stream, int* new_ack );

/*222*/

#define MAKE_UINT16( high, low ) ((((uint16_t)high) << 8) | (low))
#define MAKE_UINT24( b1, b2, b3 ) ( (((uint32_t)(b1)) << 16) | (((uint32_t)(b2)) << 8) | ((uint32_t)(b3)) )

/*222*/

struct _TcpSession
{
	DPI_SessionType		type;
	TcpStream			clientStream;
	TcpStream			serverStream;
	struct _TcpSession* next;
	int 				closing;
	DataCallbackProc	data_callback;
	ErrorCallbackProc	error_callback;
	EventCallbackProc	event_callback;
	void*				user_data;
	struct timeval		packet_time;		
	time_t				last_update_time; 
	int (*OnNewPacket)( struct _TcpStream* stream, HTTPS_Pkt* pkt );
	struct HTTPS_Session_*	ssl_session;
	HttpsEnv* 			env;
	int 						missing_packet_timeout; 
	uint32_t					missing_packet_count;
	MissingPacketCallbackProc	missing_callback;
};

void AddressToString( uint32_t ip, uint16_t port, char* buff );

const char* SessionToString( TcpSession* sess, char* buff );

int SessionInit( HttpsEnv* env, TcpSession* s, HTTPS_Pkt* pkt, DPI_SessionType s_type );
void SessionFree( TcpSession* s );

DPI_PacketDir SessionGetPacketDirection(const TcpSession* sess, const HTTPS_Pkt* pkt );

void SessionProcessPacket( struct HttpsEnv_* env, HTTPS_Pkt* pkt );

void TouchSession( TcpSession* s );

void SessionSetCallback( TcpSession* sess, DataCallbackProc data_callback, 
			ErrorCallbackProc error_callback, void* user_data );

void SessionSetMissingPacketCallback( TcpSession* sess, MissingPacketCallbackProc missing_callback,
			int missing_packet_count, int timeout_sec );

void SessionSetEventCallback( TcpSession* sess, EventCallbackProc event_callback );

void* SessionGetUserData( const TcpSession* sess );

/* */
void SessionFlushPacketQueue( TcpSession* sess );

int IsNewTcpSessionPacket( const HTTPS_Pkt* pkt );

/*222*/

#define HTTPS_SESSION_CLEANUP_INTERVAL	300

struct HttpsEnv_;

struct https_SessionTable_
{
	TcpSession**			table;
	int 					tableSize;
	volatile int			sessionCount;
	struct HttpsEnv_* 		env;
	time_t					timeout_interval;
	time_t					last_cleanup_time;

	volatile int			packet_cache_count; 
	volatile uint64_t		packet_cache_mem;	

	int 					maxSessionCount; 
	int 					maxCachedPacketCount; 
	TcpSession* (*FindSession)( struct https_SessionTable_* tbl, HTTPS_Pkt* pkt );
	TcpSession* (*CreateSession)( struct https_SessionTable_* tbl, HTTPS_Pkt* pkt, DPI_SessionType s_type );
	void		(*DestroySession)( struct https_SessionTable_* tbl, TcpSession* sess );
	void		(*RemoveAll)( struct https_SessionTable_* tbl );
	void		(*Cleanup)(struct https_SessionTable_* tbl );
};

https_SessionTable* CreateSessionTable( int tableSize, uint32_t timeout_int );
void DestroySessionTable( https_SessionTable* tbl );

/*222*/

int ssl2_record_layer_decoder( void* decoder_stack, DPI_PacketDir dir, 
		u_char* data, uint32_t len, uint32_t* processed );

/*222*/

int ssl2_handshake_record_decode_wrapper( void* decoder_stack, DPI_PacketDir dir,
								 u_char* data, uint32_t len, uint32_t* processed );

int ssl2_decode_handshake( HTTPS_Session* sess, DPI_PacketDir dir, u_char* data, uint32_t len, uint32_t* processed );

/*222*/


int ssl3_record_layer_decoder( void* decoder_stack, DPI_PacketDir dir, 
		u_char* data, uint32_t len, uint32_t* processed );

int ssl3_change_cipher_spec_decoder( void* decoder_stack, DPI_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed );

int ssl_application_data_decoder( void* decoder_stack, DPI_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed );

int ssl3_alert_decoder( void* decoder_stack, DPI_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed );

/*222*/

int ssl3_decode_handshake_record( void* decoder_stack, DPI_PacketDir dir, 
		u_char* data, uint32_t len, uint32_t* processed );

int ssl_decode_first_client_hello( HTTPS_Session* sess, u_char* data, 
		uint32_t len, uint32_t* processed );

int ssl_detect_client_hello_version( u_char* data, uint32_t len, uint16_t* ver );

int ssl_detect_server_hello_version( u_char* data, uint32_t len, uint16_t* ver );

void ssl3_init_handshake_digests( HTTPS_Session* sess );
void ssl3_update_handshake_digests( HTTPS_Session* sess, u_char* data, uint32_t len );


/*222*/

int ssl3_calculate_mac( https_decoder_stack* stack, u_char type, 
						 u_char* data, uint32_t len, u_char* mac );

int tls1_calculate_mac( https_decoder_stack* stack, u_char type, 
						 u_char* data, uint32_t len, u_char* mac );

int ssl2_calculate_mac( https_decoder_stack* stack, u_char type,
						u_char* data, uint32_t len, u_char* mac );

int tls1_decode_finished( HTTPS_Session* sess, DPI_PacketDir dir, u_char* data, uint32_t len );
int ssl3_decode_finished( HTTPS_Session* sess, DPI_PacketDir dir, u_char* data, uint32_t len );

/*222*/

#define SSF_CLIENT_SESSION_ID_SET		0x0001
#define SSF_CLOSE_NOTIFY_RECEIVED		0x0002		
#define SSF_FATAL_ALERT_RECEIVED		0x0004
#define SSF_TEST_SSL_KEY				0x0008
#define SSF_SSLV2_CHALLENGE 			0x0010
#define SSF_TLS_SESSION_TICKET_SET		0x0020
#define SSF_TLS_SERVER_SESSION_TICKET	0x0040

struct HTTPS_Session_
{
	HTTPS_Env*			env;

	uint16_t			version;		
	uint16_t			client_version; 
	
	https_decoder_stack	c_dec; 
	https_decoder_stack	s_dec; 

	u_char				client_random[SSL3_RANDOM_SIZE]; 
	u_char				server_random[SSL3_RANDOM_SIZE]; 

	u_char				PMS[SSL_MAX_MASTER_KEY_LENGTH];
	u_char				master_secret[SSL3_MASTER_SECRET_SIZE];

	u_char				ssl2_key_arg[SSL2_KEYARG_MAX_LEN];

	u_char				session_id[HTTPS_SESSION_ID_SIZE];
	uint32_t			flags;
	
	HTTPS_ServerInfo*	ssl_si;

	uint16_t			cipher_suite;
	uint16_t			ssl2_key_arg_len;

	u_char				compression_method;

	EVP_MD_CTX			handshake_digest_sha;
	EVP_MD_CTX			handshake_digest_md5;

	int (*decode_finished_proc)( struct HTTPS_Session_* sess, DPI_PacketDir dir, u_char* data, uint32_t len );
	int (*caclulate_mac_proc)( https_decoder_stack* stack, u_char type, u_char* data, 
								uint32_t len, u_char* mac );

	DataCallbackProc	data_callback;
	ErrorCallbackProc	error_callback;
	EventCallbackProc	event_callback;
	void*				user_data;

	uint32_t			client_challenge_len; 
	uint32_t			server_connection_id_len; 
	uint32_t			master_key_len;

	struct timeval		handshake_start;

	HTTPS_Pkt*			last_packet;

	u_char* 			session_ticket; 
	uint32_t			session_ticket_len; 
};


void HTTPS_SessionInit( HTTPS_Env* env, HTTPS_Session* s, HTTPS_ServerInfo* si );
void HTTPS_SessionDeInit( HTTPS_Session* s );

void HTTPS_SessionSetCallback( HTTPS_Session* sess, DataCallbackProc data_callback, 
		ErrorCallbackProc error_callback, void* user_data );

void HTTPS_SessionSetEventCallback(HTTPS_Session* sess, EventCallbackProc proc);

int HTTPS_SessionProcessData( HTTPS_Session* sess, DPI_PacketDir dir, u_char* data, uint32_t len );

EVP_PKEY* ssls_get_session_private_key( HTTPS_Session* sess );
int ssls_decode_master_secret( HTTPS_Session* sess );
int ssls_generate_keys( HTTPS_Session* sess );
int ssls2_generate_keys( HTTPS_Session* sess, u_char* keyArg, uint32_t keyArgLen );
int ssls_set_session_version( HTTPS_Session* sess, uint16_t ver );

int ssls_get_decrypt_buffer( HTTPS_Session* sess, u_char** data, uint32_t len );

int ssls_get_decompress_buffer( HTTPS_Session* sess, u_char** data, uint32_t len );

int ssls_lookup_session( HTTPS_Session* sess );
void ssls_store_session( HTTPS_Session* sess );
void ssls_handshake_done( HTTPS_Session* sess );
EVP_PKEY* ssls_try_ssl_keys( HTTPS_Session* sess, u_char* data, uint32_t len);
int ssls_register_ssl_key( HTTPS_Session* sess,EVP_PKEY* pk );

void ssls_free_extension_data(HTTPS_Session* sess);

int ssls_init_from_tls_ticket( HTTPS_Session* sess );
int ssls_store_new_ticket(HTTPS_Session* sess, u_char* ticket, uint32_t len);

/*222*/

typedef struct _HTTPS_SessionKeyData
{
	u_char							id[HTTPS_SESSION_ID_SIZE];
	u_char							master_secret[SSL3_MASTER_SECRET_SIZE];
	uint32_t						master_secret_len; 
	u_char							ssl2_key_arg[SSL2_KEYARG_MAX_LEN];
	uint16_t						ssl2_key_arg_length;
	uint16_t						ssl2_cipher_suite;
	volatile uint32_t				refcount;
	time_t							released_time;
	struct _HTTPS_SessionKeyData*	next;
} HTTPS_SessionKeyData;

struct https_SessionKeyTable_
{
	HTTPS_SessionKeyData**	table;
	volatile int			count;
	int 					table_size;
	time_t					timeout_interval;
	time_t					last_cleanup_time;
};

https_SessionKeyTable* https_SessionKT_Create( int table_size, uint32_t timeout_int );
void https_SessionKT_Destroy( https_SessionKeyTable* tbl );

void https_SessionKT_AddRef( HTTPS_SessionKeyData* sess_data );
void https_SessionKT_Release( https_SessionKeyTable* tbl, u_char* session_id );
void https_SessionKT_CleanSessionCache( https_SessionKeyTable* tbl );

HTTPS_SessionKeyData* https_SessionKT_Find( https_SessionKeyTable* tbl, u_char* session_id );
void https_SessionKT_Add( https_SessionKeyTable* tbl, HTTPS_Session* sess );
void https_SessionKT_Remove( https_SessionKeyTable* tbl, u_char* session_id );
void https_SessionKT_RemoveAll( https_SessionKeyTable* tbl );

/*222*/

int ssl3_PRF( const u_char* secret, uint32_t secret_len, 
		const u_char* random1, uint32_t random1_len,
		const u_char* random2, uint32_t random2_len,
		u_char* out, uint32_t out_len );

int tls1_PRF( const u_char* secret, uint32_t secret_len,
		const char* label, u_char* random1, uint32_t random1_len,
		u_char* random2, uint32_t random2_len,
		u_char *out, uint32_t out_len );

int ssl2_PRF( const u_char* secret, uint32_t secret_len,
		const u_char* challenge, uint32_t challenge_len, 
		const u_char* conn_id, uint32_t conn_id_len,
		u_char* out, uint32_t out_len );

/*222*/

typedef struct _HTTPS_SessionTicketData
{
	u_char*							ticket;
	uint32_t						ticket_size;

	uint16_t						protocol_version;
	uint16_t						cipher_suite;
	u_char							compression_method;
	u_char							master_secret[SSL3_MASTER_SECRET_SIZE];
	time_t							timestamp;
	struct _HTTPS_SessionTicketData*	next;
} HTTPS_SessionTicketData;

struct _HTTPS_SessionTicketTable
{
	HTTPS_SessionTicketData**	table;
	volatile int				count;
	int							table_size;
	time_t						timeout_interval;	
	time_t						last_cleanup_time;
};

HTTPS_SessionTicketTable* https_SessionTicketTable_Create( int table_size, uint32_t timeout_int );
void https_SessionTicketTable_Destroy( HTTPS_SessionTicketTable* tbl );
void https_SessionTicketTable_RemoveAll( HTTPS_SessionTicketTable* tbl );

HTTPS_SessionTicketData* https_SessionTicketTable_Find( HTTPS_SessionTicketTable* tbl, const u_char* ticket, uint32_t len );
int https_SessionTicketTable_Add( HTTPS_SessionTicketTable* tbl, HTTPS_Session* sess, const u_char* ticket, uint32_t len);
void https_SessionTicketTable_Remove( HTTPS_SessionTicketTable* tbl, const u_char* ticket, uint32_t len );
void https_SessionTicketTable_CleanSessionCache( HTTPS_SessionTicketTable* tbl );


#ifdef  __cplusplus
}
#endif

#endif
