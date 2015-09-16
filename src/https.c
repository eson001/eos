
#include <string.h>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "https.h"

/*111*/
int HttpsEnvIsSSLPacket( const HttpsEnv* env, const HTTPS_Pkt* pkt )
{
	uint16_t port = PKT_TCP_DPORT( pkt );

	if( HttpsEnvFindHTTPS_ServerInfo( env, &pkt->ip_header->ip_dst, port ) ) 
		return 1;
	
	port = PKT_TCP_SPORT( pkt );
	if( HttpsEnvFindHTTPS_ServerInfo( env, &pkt->ip_header->ip_src, port ) ) 
		return 1;

	return 0;
}

DPI_SessionType _HttpsEnv_ForReassemble( struct HttpsEnv_* env, struct HTTPS_Pkt_* pkt )
{
	if( HttpsEnvIsSSLPacket( env, pkt ) ) return eSessTypeSSL;

	return eSessTypeNull;
}

HttpsEnv* HttpsEnvCreate( pcap_t* adapter, int sessionTableSize, uint32_t key_timeout_interval, uint32_t tcp_timeout_interval)
{
	HttpsEnv* env;

	if( key_timeout_interval == 0 ) key_timeout_interval = 60*60;
	if( tcp_timeout_interval == 0 ) tcp_timeout_interval = 180;

	env = (HttpsEnv*) malloc( sizeof(HttpsEnv) );
	memset( env, 0, sizeof(*env) );

	env->pcap_adapter = adapter;

	if( env->pcap_adapter != NULL )
	{
		env->handler = NULL;
	}

	env->ForReassemble = _HttpsEnv_ForReassemble;
	
	env->sessions = CreateSessionTable( sessionTableSize, tcp_timeout_interval );
	env->sessions->env = env;
	env->session_callback = NULL;
	env->env_user_data = NULL;

	env->ssl_env = HTTPS_EnvCreate( sessionTableSize, key_timeout_interval );

	return env;
}


void HttpsEnvDestroy( HttpsEnv* env )
{
	DestroySessionTable( env->sessions );

	if( env->ssl_env ) 
	{
		HTTPS_EnvDestroy( env->ssl_env );
		env->ssl_env = NULL;
	}

	free( env );
}

static int NewSessionPacket( const HTTPS_Pkt* pkt, DPI_SessionType s_type )
{
	switch( s_type )
	{
	case eSessTypeTcp:
	case eSessTypeSSL:
	case eSessTypeTBD:
		return IsNewTcpSessionPacket( pkt );
	case eSessTypeNull:
		return 0;
	}

	_ASSERT( 0 ); 
	return 0;
}

void HttpsEnvProcessPacket( HttpsEnv* env, HTTPS_Pkt* pkt )
{
	DPI_SessionType s_type = env->ForReassemble( env, pkt );

	if( s_type == eSessTypeNull ) return;

	pkt->session = env->sessions->FindSession( env->sessions, pkt );

	if( !pkt->session && NewSessionPacket( pkt, s_type ) ) 
	{
		pkt->session = env->sessions->CreateSession( env->sessions, pkt, s_type );
	}
	if( pkt->session ) SessionProcessPacket( env, pkt );
}

int HttpsEnvSetSSL_ServerInfo( HttpsEnv* env, const struct in_addr* ip_address, uint16_t port, 
			const char* keyfile, const char* password )
{
	if( env->ssl_env == NULL ) return DPI_ERROR( HTTPS_E_UNINITIALIZED_ARGUMENT );

	return HTTPS_EnvSetServerInfo( env->ssl_env, ip_address, port, keyfile, password );
}

void HttpsEnvSetSessionCallback( HttpsEnv* env, HttpsEnvSessionCallback callback, void* user_data )
{
	_ASSERT( env );
	
	env->session_callback = callback;
	env->env_user_data = user_data;
}

HTTPS_ServerInfo* HttpsEnvFindHTTPS_ServerInfo( const HttpsEnv* env, 
		const struct in_addr* server_ip, uint16_t server_port )
{
	if( env->ssl_env ) 
		return HTTPS_EnvFindServerInfo( env->ssl_env, *server_ip, server_port );
	else
		return NULL;
}

/*111*/

static HTTPS_CipherSuite ssl3suites[] = 
{
	{ 0x01, SSL3_VERSION, SSL_KEX_RSA, 0, "NULL", "MD5" },
	{ 0x02, SSL3_VERSION, SSL_KEX_RSA, 0, "NULL", "SHA1" },
	{ 0x03, SSL3_VERSION, SSL_KEX_RSA,	40, "RC4", "MD5" },
	{ 0x04, SSL3_VERSION, SSL_KEX_RSA, 0, "RC4", "MD5" },
	{ 0x05, SSL3_VERSION, SSL_KEX_RSA, 0, "RC4", "SHA1" },
	{ 0x06, SSL3_VERSION, SSL_KEX_RSA, 40, "RC2", "MD5" },
	{ 0x07, SSL3_VERSION, SSL_KEX_RSA, 0, "IDEA", "SHA1" },
	{ 0x08, SSL3_VERSION, SSL_KEX_RSA, 40, "DES", "SHA1" },
	{ 0x09, SSL3_VERSION, SSL_KEX_RSA, 0, "DES", "SHA1" },
	{ 0x0A, SSL3_VERSION, SSL_KEX_RSA, 0, "DES3", "SHA1" },
	{ 0x2F, TLS1_VERSION, SSL_KEX_RSA, 0, SN_aes_128_cbc, "SHA1" },
	{ 0x35, TLS1_VERSION, SSL_KEX_RSA,	0, SN_aes_256_cbc, "SHA1" }
};

static int compare_cipher_suites( const void* key, const void* elem )
{
	uint16_t id = *((uint16_t*)key);
	HTTPS_CipherSuite* cs = (HTTPS_CipherSuite*) elem;

	return id - cs->id;
}

HTTPS_CipherSuite* HTTPS_GetSSL3CipherSuite( uint16_t id )
{
	return (HTTPS_CipherSuite*) bsearch( &id, ssl3suites, 
			sizeof(ssl3suites)/sizeof(ssl3suites[0]), sizeof(ssl3suites[0]),
			compare_cipher_suites );
}

static HTTPS_CipherSuite ssl2suites[] = 
{
	{ 0x01, SSL2_VERSION, SSL_KEX_RSA, 0, "RC4", "MD5" },
	{ 0x02, SSL2_VERSION, SSL_KEX_RSA, 40, "RC4", "MD5" },
	{ 0x03, SSL2_VERSION, SSL_KEX_RSA, 0, "RC2", "MD5" },
	{ 0x04, SSL2_VERSION, SSL_KEX_RSA, 40, "RC2", "MD5" },
	{ 0x05, SSL2_VERSION, SSL_KEX_RSA, 0, "IDEA", "MD5" },
	{ 0x06, SSL2_VERSION, SSL_KEX_RSA, 0, "DES", "MD5" },
	{ 0x07, SSL2_VERSION, SSL_KEX_RSA, 0, SN_des_ede3_cbc, "MD5" }
};

int HTTPS_ConvertSSL2CipherSuite( u_char cs[3], uint16_t* pcs )
{
	_ASSERT( pcs );

	if(cs[0] > 0x07 ) return DPI_ERROR( HTTPS_E_SSL2_UNKNOWN_CIPHER_KIND );
	if(cs[1] != 0 ) return DPI_ERROR( HTTPS_E_SSL2_UNKNOWN_CIPHER_KIND );
	switch(cs[2])
	{
	case 0x80: if( cs[0] > 0x05 ) { return DPI_ERROR( HTTPS_E_SSL2_UNKNOWN_CIPHER_KIND ); } break;
	case 0x40: if( cs[0] != 0x06 ) { return DPI_ERROR( HTTPS_E_SSL2_UNKNOWN_CIPHER_KIND ); } break;
	case 0xC0: if( cs[0] != 0x07 ) { return DPI_ERROR( HTTPS_E_SSL2_UNKNOWN_CIPHER_KIND ); } break;
	default: return DPI_ERROR( HTTPS_E_SSL2_UNKNOWN_CIPHER_KIND );
	}

	_ASSERT( cs[0] <= sizeof(ssl2suites)/sizeof(ssl2suites[0]) );

	*pcs = cs[0];

	return HTTPS_RC_OK;
}

HTTPS_CipherSuite* HTTPS_GetSSL2CipherSuite( uint16_t id )
{
	if( id == 0 || id > sizeof(ssl2suites)/sizeof(ssl2suites[0]) )
	{
		_ASSERT( FALSE );
		return NULL;
	}

	return &ssl2suites[id-1];
}

int HTTPS_CipherSuiteExportable( HTTPS_CipherSuite* ss )
{
	return ss->export_key_bits != 0;
}

/*111*/

#define COMPRESSION_DEFLATE 	1

int https_compr_init( u_char compr_method, void** compr_state )
{
	int rc = HTTPS_RC_OK;

	switch( compr_method )
	{
	case 0: break;
	case COMPRESSION_DEFLATE:
		{
			z_stream * zs = (z_stream*) malloc( sizeof(z_stream) );
			int err = Z_OK;

			zs->zalloc = Z_NULL;
			zs->zfree = Z_NULL;
			zs->opaque = Z_NULL;
			zs->next_in = Z_NULL;
			zs->next_out = Z_NULL;
			zs->avail_in = 0;
			zs->avail_out = 0;
			err = inflateInit(zs);

			if( err != Z_OK ) 
			{
				free( zs );
				rc = DPI_ERROR( HTTPS_E_DECOMPRESSION_ERROR );
			}
			else
			{
				rc = HTTPS_RC_OK;
				(*compr_state) = zs;
			}
		}
		break;

	default:
		rc = DPI_ERROR( HTTPS_E_UNSUPPORTED_COMPRESSION ); 
		break;
	}

	return rc;
}

void https_compr_deinit( u_char compr_method, void* compr_state )
{
	if( compr_state == NULL ) return;

	switch( compr_method )
	{
	case 0: break;
	case COMPRESSION_DEFLATE:
		{
			z_stream* zs = (z_stream*) compr_state;
			_ASSERT( zs );

			inflateEnd( zs );
			free( zs );
		}
		break;

	default:
		_ASSERT( FALSE ); 
		break;
	}
}

int https_decompress( u_char compr_method, void* compr_state, u_char* in_data, uint32_t in_len,
					u_char* out_data, uint32_t* out_len )
{
	int rc = HTTPS_RC_OK;
	z_stream * zs = (z_stream*) compr_state;

	if( compr_method != COMPRESSION_DEFLATE ) return DPI_ERROR( HTTPS_E_UNSUPPORTED_COMPRESSION );

	_ASSERT( zs );

	zs->next_in = in_data;
	zs->avail_in = in_len;
	zs->next_out = out_data;
	zs->avail_out = *out_len;

	if( in_len > 0 )
	{
		int zlib_rc = inflate( zs, Z_SYNC_FLUSH );
		if( zlib_rc != Z_OK ) { rc = DPI_ERROR( HTTPS_E_DECOMPRESSION_ERROR ); }
	}

	if( rc == HTTPS_RC_OK )
	{
		(*out_len) = (*out_len) - zs->avail_out;
	}

	return rc;

}

/*111*/

void DecodeTcpPacket( HttpsEnv* env, HTTPS_Pkt* pkt, const uint8_t* data, const int len )
{
	int tcp_hdr_len;

	if( len < sizeof(struct tcphdr) )
	{
		nmLogMessage( ERR_CAPTURE, 
			"DecodeTcpPacket: packet lenght (%d) is less than minimal TCP header size", len );
		return;
	}

	pkt->tcp_header = (struct tcphdr*) data;

	tcp_hdr_len = DPI_TCP_HDR_LEN( pkt->tcp_header );

	if( len < tcp_hdr_len )
	{
		nmLogMessage( ERR_CAPTURE, 
			"DecodeTcpPacket: packet lenght (%d) is less than TCP header size specified (%d)", 
			len, tcp_hdr_len );
		return;
	}

	pkt->data_len = (uint16_t)( len - tcp_hdr_len );

	HttpsEnvProcessPacket( env, pkt );
}

void DecodeIpPacket( HttpsEnv* env, HTTPS_Pkt* pkt, const uint8_t* data, const int len )
{
	int ip_len, ip_hdrlen;

	pkt->ip_header = (struct ip*) data;

	if( len < sizeof(struct ip) )
	{
		nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Invalid IP header length!" );
		return;
	}

	if( IP_V(pkt->ip_header) != 4 )
	{
		nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Unsupported IP version: %d",
				(int)IP_V(pkt->ip_header) );
		return;
	}


	ip_len = ntohs(pkt->ip_header->ip_len);
	ip_hdrlen = IP_HL(pkt->ip_header) << 2;

	if( ip_hdrlen < sizeof(struct ip) )
	{
		nmLogMessage( ERR_CAPTURE, "ProcessIpPacket: Bogus IP header!" );
		return;
	}

	if( pkt->ip_header->ip_p == IPPROTO_TCP )
	{
		DecodeTcpPacket( env, pkt, data + ip_hdrlen, ip_len - ip_hdrlen );
	}

}


/*111*/

void https_decoder_init( https_decoder* decoder, sslc_decode_proc handler, void* handler_data )
{
	_ASSERT( decoder );

	memset( decoder, 0, sizeof(decoder) );
	decoder->handler = handler;
	decoder->handler_data = handler_data;
}


void https_decoder_deinit( https_decoder* d )
{
	_ASSERT( d );

	if( d->buff ) free( d->buff );

	d->buff = NULL;
	d->buff_len = 0;
	d->buff_used_len = 0;
}

static int realloc_buffer( https_decoder* d, uint32_t new_len )
{
	u_char* new_buff = NULL;

	_ASSERT( new_len > 0 );
	_ASSERT( d->buff_len == 0 || new_len > d->buff_len );

	if( d->buff != NULL )
		new_buff = (u_char*) realloc( d->buff, new_len );
	else
		new_buff = (u_char*) malloc( new_len );

	if( new_buff == NULL ) return DPI_ERROR( HTTPS_E_OUT_OF_MEMORY );

	d->buff_len = new_len;
	d->buff = new_buff;

	return HTTPS_RC_OK;
}

int https_decoder_add_to_buffer( https_decoder* d, u_char* data, uint32_t len )
{
	int rc = HTTPS_RC_OK;

	if( d->buff_len < d->buff_used_len + len )
	{
		rc = realloc_buffer( d, d->buff_used_len + len );
	}

	if( rc == HTTPS_RC_OK )
	{
		_ASSERT( d->buff_len >= d->buff_used_len + len );

		memcpy( d->buff + d->buff_used_len, data, len );
		d->buff_used_len += len;
	}

	return rc;
}

int https_decoder_shift_buffer( https_decoder* d, uint32_t processed_len )
{
	_ASSERT( d->buff );
	_ASSERT( d->buff_used_len >= processed_len );

	if( d->buff_used_len > processed_len )
	{
		memmove( d->buff, d->buff + processed_len, d->buff_used_len - processed_len );
	}

	d->buff_used_len -= processed_len;

	return HTTPS_RC_OK;
}

int https_decoder_process( https_decoder* d, DPI_PacketDir dir, u_char* data, uint32_t len )
{
	uint32_t processed = 0;
	int rc = HTTPS_RC_OK;

	if( !d->handler ) return DPI_ERROR( HTTPS_E_NOT_IMPL );

	if( d->buff_used_len > 0 ) 
	{
		rc = https_decoder_add_to_buffer( d, data, len );

		if( rc == HTTPS_RC_OK )
		{
			data = d->buff;
			len = d->buff_used_len; 
		}
	}

	while( rc == HTTPS_RC_OK && processed < len )
	{
		uint32_t p = 0;
		rc = d->handler( d->handler_data, dir, data + processed, len - processed, &p );
		processed += p;

		if( p == 0 && rc == HTTPS_RC_OK ) { rc = DPI_ERROR( HTTPS_E_UNSPECIFIED_ERROR ); }
	}

	if( !DPI_IS_FAILED( rc ) )
	{
		if( d->buff_used_len > 0 )
		{
			rc = https_decoder_shift_buffer( d, processed );
		}
		else if( processed < len )
		{
			rc = https_decoder_add_to_buffer( d, data + processed, len - processed );
		}
	}

	return rc;
}


/*111*/

void https_decoder_stack_init( https_decoder_stack* stack )
{
	memset( stack, 0, sizeof(stack) );
	stack->state = SS_Initial;
}

void https_decoder_stack_deinit( https_decoder_stack* stack )
{
	https_decoder_deinit( &stack->dalert );
	https_decoder_deinit( &stack->dappdata );
	https_decoder_deinit( &stack->dcss );
	https_decoder_deinit( &stack->dhandshake );
	https_decoder_deinit( &stack->drecord );

	if( stack->cipher )
	{
		EVP_CIPHER_CTX_cleanup( stack->cipher );
		free( stack->cipher );
		stack->cipher = NULL;
	}

	if( stack->cipher_new )
	{
		EVP_CIPHER_CTX_cleanup( stack->cipher_new );
		free( stack->cipher_new );
		stack->cipher_new = NULL;
	}

	if( stack->compression_method != 0 )
	{
		https_compr_deinit( stack->compression_method, stack->compression_data );
	}

	if( stack->compression_method_new != 0 )
	{
		https_compr_deinit( stack->compression_method_new, stack->compression_data_new );
	}

	stack->md = stack->md_new = NULL;
}


int sslc_is_decoder_stack_set( https_decoder_stack* s)
{
	return s->sess != NULL;
}

int https_decoder_stack_set( https_decoder_stack* d, HTTPS_Session* sess, uint16_t version )
{
	int rc = HTTPS_RC_OK;

	d->sess = NULL;

	switch( version )
	{
	case SSL3_VERSION:
	case TLS1_VERSION:
	case TLS1_1_VERSION:
	case TLS1_2_VERSION:
		https_decoder_init( &d->drecord, ssl3_record_layer_decoder, d );
		https_decoder_init( &d->dhandshake, ssl3_decode_handshake_record, d );
		https_decoder_init( &d->dcss, ssl3_change_cipher_spec_decoder, d );
		https_decoder_init( &d->dappdata, ssl_application_data_decoder, d );
		https_decoder_init( &d->dalert, ssl3_alert_decoder, d );
		break;

	case SSL2_VERSION:
		https_decoder_init( &d->drecord, ssl2_record_layer_decoder, d );
		https_decoder_init( &d->dhandshake, ssl2_handshake_record_decode_wrapper, d );
		https_decoder_init( &d->dappdata, ssl_application_data_decoder, d );
		break;

	default:
		rc = DPI_ERROR( HTTPS_E_SSL_UNKNOWN_VERSION );
		break;
	}

	if( rc == HTTPS_RC_OK ) { d->sess = sess; }

	return rc;
}

int https_decoder_stack_process( https_decoder_stack* stack, DPI_PacketDir dir, u_char* data, uint32_t len )
{
	return https_decoder_process( &stack->drecord, dir, data, len );
}


int https_decoder_stack_flip_cipher( https_decoder_stack* stack )
{
	if( stack->compression_method != 0 )
	{
		https_compr_deinit( stack->compression_method, stack->compression_data );
	}

	if( stack->cipher )
	{
		EVP_CIPHER_CTX_cleanup( stack->cipher );
		free( stack->cipher );
		stack->cipher = NULL;
	}

	stack->compression_method = stack->compression_method_new;
	stack->compression_method_new = 0;

	stack->compression_data = stack->compression_data_new;
	stack->compression_data_new = NULL;

	stack->cipher = stack->cipher_new;

	if(  stack->md_new != NULL && stack->sess && 
		(stack->sess->version == SSL3_VERSION || stack->sess->version == TLS1_VERSION) )
	{
		memcpy( stack->mac_key, stack->mac_key_new, EVP_MD_size( stack->md_new ) );
	}

	stack->md = stack->md_new;

	stack->cipher_new = NULL;
	stack->md_new = NULL;

	return HTTPS_RC_OK;
}

/*111*/

uint32_t fnv_32_buf(const void *buf, size_t len, uint32_t hval)
{
	unsigned char *bp = (unsigned char *)buf;	
	unsigned char *be = bp + len;		

	while (bp < be) {

#if defined(NO_FNV_GCC_OPTIMIZATION)
	hval *= FNV_32_PRIME;
#else
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif

	hval ^= (uint32_t)*bp++;
	}

	return hval;
}

/*111*/

#ifdef _DEBUG
int NmDebugCatchError( int rc )
{
	printf( "\nHTTPS error: %d\n", rc );
	return rc;
}

#endif

void nmLogMessage( uint32_t category, const char* fmt, ... )
{
	return;
}

/*111*/

uint32_t PktNextTcpSeqExpected( const HTTPS_Pkt* pkt )
{
	uint32_t th_seq;
	th_seq = ntohl( pkt->tcp_header->th_seq );

	if( (pkt->tcp_header->th_flags & TH_SYN) || (pkt->tcp_header->th_flags & TH_FIN) )
		return th_seq + pkt->data_len + 1;
	else
		return th_seq + pkt->data_len;
}

HTTPS_Pkt* PktClone( const HTTPS_Pkt* src )
{
	HTTPS_Pkt* pClone;

	pClone = malloc( sizeof( HTTPS_Pkt ) + src->pcap_header.caplen );
	memcpy( &pClone->pcap_header, &src->pcap_header, sizeof( struct pcap_pkthdr ) );
	memcpy( (u_char*)pClone + sizeof(*pClone), src->pcap_ptr, src->pcap_header.caplen );

	pClone->data_len = src->data_len;
	pClone->pcap_ptr = (u_char*) pClone + sizeof(*pClone);
	pClone->session = src->session;
	pClone->link_type = src->link_type;
	
	pClone->ether_header = (struct ether_header*)
			( pClone->pcap_ptr + ((u_char*)src->ether_header - src->pcap_ptr ) );
	pClone->ip_header = (struct ip*) 
			( pClone->pcap_ptr + ((u_char*) src->ip_header - src->pcap_ptr ) );
	pClone->tcp_header = (struct tcphdr*)
			( pClone->pcap_ptr + ((u_char*) src->tcp_header - src->pcap_ptr ) );

	pClone->udp_header = (struct udphdr*)
			( pClone->pcap_ptr + ((u_char*) src->udp_header - src->pcap_ptr ) );

	pClone->prev = pClone->next = NULL;
	pClone->ack_time = src->ack_time;
	pClone->flags = src->flags;

	return pClone;
}

int PktCloneChunk(const HTTPS_Pkt* src, int tail_len, HTTPS_Pkt** rc)
{
	HTTPS_Pkt* pClone = NULL;
	uint32_t newSeq = 0;
	u_char* d1 = NULL;
	u_char* d2 = NULL;
	int hdr_len = 0;

	_ASSERT(rc);
	_ASSERT(src);

	if(tail_len <= 0 || tail_len > (int)src->data_len )
	{
		return DPI_ERROR(HTTPS_E_INVALID_PARAMETER);
	}

	d1 = PKT_TCP_PAYLOAD(src);
	d2 = d1 + src->data_len - tail_len;
	hdr_len = d1 - src->pcap_ptr;

	_ASSERT(d2 <= d1);
	_ASSERT(d2 + tail_len <= d1 + src->data_len);
	_ASSERT(d2 + tail_len <= src->pcap_ptr + src->pcap_header.caplen);

	pClone = malloc( sizeof( HTTPS_Pkt ) + src->pcap_header.caplen );
	memcpy( &pClone->pcap_header, &src->pcap_header, sizeof( struct pcap_pkthdr ) );
	memcpy( (u_char*)pClone + sizeof(*pClone), src->pcap_ptr, hdr_len);
	memcpy( (u_char*)pClone + sizeof(*pClone) + hdr_len, d2, tail_len);

	pClone->data_len = (uint16_t) tail_len;
	pClone->pcap_ptr = (u_char*) pClone + sizeof(*pClone);
	pClone->session = src->session;
	pClone->link_type = src->link_type;
	
	pClone->ether_header = (struct ether_header*)
			( pClone->pcap_ptr + ((u_char*)src->ether_header - src->pcap_ptr ) );
	pClone->ip_header = (struct ip*) 
			( pClone->pcap_ptr + ((u_char*) src->ip_header - src->pcap_ptr ) );
	pClone->tcp_header = (struct tcphdr*)
			( pClone->pcap_ptr + ((u_char*) src->tcp_header - src->pcap_ptr ) );

	pClone->udp_header = (struct udphdr*)
			( pClone->pcap_ptr + ((u_char*) src->udp_header - src->pcap_ptr ) );

	pClone->prev = pClone->next = NULL;
	pClone->ack_time = src->ack_time;
	pClone->flags = src->flags;

	newSeq = PKT_TCP_SEQ(src) + src->data_len - tail_len;
	pClone->tcp_header->th_seq = htonl(newSeq);

	(*rc) = pClone;

	return HTTPS_RC_OK;
}

void PktFree( HTTPS_Pkt* pkt )
{
	free( pkt );
}

int PktCompareTimes( const HTTPS_Pkt* pkt1, const HTTPS_Pkt* pkt2 )
{
	if( pkt1->pcap_header.ts.tv_sec > pkt2->pcap_header.ts.tv_sec )
		return 1;
	else if ( pkt1->pcap_header.ts.tv_sec < pkt2->pcap_header.ts.tv_sec )
		return -1;
	else return pkt1->pcap_header.ts.tv_usec - pkt2->pcap_header.ts.tv_usec;
}

/*111*/

void sslol_process_ethernet( u_char *ptr, const struct pcap_pkthdr *header, const u_char *pkt_data )
{
	HttpsEnv* env = (HttpsEnv*)ptr;
	HTTPS_Pkt packet;
	int len = header->caplen;
	int m_link_protocol_offset = 12;
	int m_link_len = ETHER_HDRLEN;
	int pkt_link_len = m_link_len;

#ifdef DPI_TRACE_FRAME_COUNT
	DEBUG_TRACE1("\n-=ETH-FRAME: %u", env->frame_cnt);
	++env->frame_cnt;
#endif

	memset( &packet, 0, sizeof( packet ) );
	memcpy( &packet.pcap_header, header, sizeof(packet.pcap_header) );

	packet.pcap_ptr = pkt_data;
	packet.link_type = 0;

	packet.ether_header = (struct ether_header*) pkt_data;

	if( len < ETHER_HDRLEN )
	{
		nmLogMessage( ERR_CAPTURE, "sslol_process_ethernet: Invalid ethernet header length!" );
		return;
	}

	if (pkt_data[m_link_protocol_offset]!=0x08 || pkt_data[m_link_protocol_offset+1]!=0x00) {
		if ( pkt_data[m_link_protocol_offset]==0x81 && pkt_data[m_link_protocol_offset+1]==0x00 	// is vlan packet
			&& pkt_data[m_link_protocol_offset+4]==0x08 && pkt_data[m_link_protocol_offset+5]==0x00)	// AND is IP packet
		{
			// adjust for vlan (801.1q) packet headers
			pkt_link_len += 4;
		} else {
			// not an ethernet packet or non-IP vlan packet
			return;
		}
	}
//	if( ntohs(packet.ether_header->ether_type) == ETHERTYPE_IP )
	{
		DecodeIpPacket( env, &packet, pkt_data + pkt_link_len, len - ETHER_HDRLEN );
	}
}


/*111*/

static int OnNewPlainTextPacket( TcpStream* stream, HTTPS_Pkt* pkt );
static int OnNewSSLPacket( TcpStream* stream, HTTPS_Pkt* pkt );
static void SessionInitDecoders( TcpSession* sess, HTTPS_Pkt* pkt );
static int DetectSessionTypeCallback(struct _TcpStream* stream, HTTPS_Pkt* pkt );

void AddressToString( uint32_t ip_addr, uint16_t port, char* buff )
{
	uint32_t ip = ntohl(ip_addr);
	sprintf( buff, "%d.%d.%d.%d:%d",
		((ip >> 24)), ((ip >> 16) & 0xFF),
		((ip >> 8) & 0xFF), (ip & 0xFF),
		(int) port );
}

const char* SessionToString( TcpSession* sess, char* buff )
{
	char addr1[32], addr2[32];

	addr1[0] = 0;
	addr2[0] = 0;

	AddressToString( sess->serverStream.ip_addr, sess->serverStream.port, addr1 );
	AddressToString( sess->clientStream.ip_addr, sess->clientStream.port, addr2 );

	sprintf( buff, "%s<->%s", addr1, addr2 );
	return buff;
}

DPI_PacketDir SessionGetPacketDirection( const TcpSession* sess,  const HTTPS_Pkt* pkt)
{
	uint32_t ip1, ip2;
	uint16_t port1, port2;

	_ASSERT( sess );
	_ASSERT( pkt );

	_ASSERT( pkt->ip_header );
	_ASSERT( pkt->tcp_header );

	ip1 = INADDR_IP( pkt->ip_header->ip_src );
	ip2 = INADDR_IP( pkt->ip_header->ip_dst );

	port1 = PKT_TCP_SPORT( pkt );
	port2 = PKT_TCP_DPORT( pkt );

	if( sess->clientStream.ip_addr == ip1 && sess->serverStream.ip_addr == ip2 && 
		sess->clientStream.port == port1 && sess->serverStream.port == port2 )
	{
		return ePktDirFromClient;
	} 
	else if( sess->clientStream.ip_addr == ip2 && sess->serverStream.ip_addr == ip1 &&
			sess->clientStream.port == port2 && sess->serverStream.port == port1 )
	{
		return ePktDirFromServer;
	}
	else
	{
		return ePktDirInvalid;
	}
}


int SessionInit( HttpsEnv* env, TcpSession* sess, HTTPS_Pkt* pkt, DPI_SessionType s_type )
{
	int is_server = 0;
	_ASSERT( pkt );

	memset( sess, 0, sizeof(*sess) );

	TouchSession(sess);

	sess->type = s_type;
	if( s_type != eSessTypeSSL && s_type != eSessTypeTcp
		&& s_type != eSessTypeTBD ) return DPI_ERROR( HTTPS_E_INVALID_PARAMETER );

	sess->env = env;

	switch( pkt->tcp_header->th_flags & ~(TH_ECNECHO | TH_CWR) )
	{
	case TH_SYN:
		StreamInit( &sess->clientStream, sess,
			INADDR_IP( pkt->ip_header->ip_src ), PKT_TCP_SPORT( pkt ) );
		StreamInit( &sess->serverStream, sess, 
			INADDR_IP( pkt->ip_header->ip_dst ), PKT_TCP_DPORT( pkt ) );

		is_server = 0;
		break;

	case TH_SYN | TH_ACK:
		StreamInit( &sess->serverStream, sess, 
			INADDR_IP( pkt->ip_header->ip_src ), PKT_TCP_SPORT( pkt ) );
		StreamInit( &sess->clientStream, sess,
			INADDR_IP( pkt->ip_header->ip_dst ), PKT_TCP_DPORT( pkt ) );

		is_server = 1;
		break;

	default:
		StreamInit( &sess->serverStream, sess, 
			INADDR_IP( pkt->ip_header->ip_src ), PKT_TCP_SPORT( pkt ) );
		StreamInit( &sess->clientStream, sess, 
			INADDR_IP( pkt->ip_header->ip_dst ), PKT_TCP_DPORT( pkt ) );

		if( sess->type == eSessTypeSSL ) 
		{
#ifdef DPI_TRACE_SSL_SESSIONS
			char _trace_buff[1024];
			DEBUG_TRACE1( "\n==>Can't reassemble the SSL session from the middle, dropping: ", SessionToString(sess, _trace_buff) );
#endif
			sess->type = eSessTypeNull;
		}
		break;
	}

	SessionInitDecoders( sess, pkt );

	return HTTPS_RC_OK;
}


static void SessionInitDecoders( TcpSession* sess, HTTPS_Pkt* pkt )
{
	HttpsEnv* env = NULL;
	_ASSERT(sess && sess->env);
	env = sess->env;

	switch( sess->type )
	{
	case eSessTypeTBD:
		sess->OnNewPacket = DetectSessionTypeCallback;
		break;

	case eSessTypeTcp:
		sess->OnNewPacket = OnNewPlainTextPacket;
		break;

	case eSessTypeSSL:
		if( env->ssl_env != NULL ) 
		{
			sess->ssl_session = HTTPS_EnvCreateSession( env->ssl_env, 
					pkt->ip_header->ip_dst, PKT_TCP_DPORT( pkt ),
					pkt->ip_header->ip_src, PKT_TCP_SPORT( pkt ));
		}
		else
		{
			sess->ssl_session = NULL;
		}

		if( sess->ssl_session != NULL )
		{
			sess->OnNewPacket = OnNewSSLPacket;
			HTTPS_SessionSetCallback( sess->ssl_session, sess->data_callback, 
					sess->error_callback, sess->user_data );
			HTTPS_SessionSetEventCallback( sess->ssl_session, sess->event_callback );
		}
		else
		{
			sess->type = eSessTypeNull; 
		}
		break;

	case eSessTypeNull:
		break;

	default:
		_ASSERT( FALSE );
		break;
	}
}

static void SessionDeInit( TcpSession* sess )
{
	_ASSERT( sess );

	if( sess->ssl_session )
	{
		HTTPS_SessionDeInit( sess->ssl_session );
		free( sess->ssl_session );
		sess->ssl_session = NULL;
	}

	StreamFreeData( &sess->clientStream );
	StreamFreeData( &sess->serverStream );

	sess->type = eSessTypeNull;
}


void SessionFree( TcpSession* sess )
{
	SessionDeInit( sess );
	free( sess );
}

static void SessionOnError( TcpSession* sess, int error_code )
{
	if( sess->error_callback )
	{
		sess->error_callback( sess->user_data, error_code );
	}
}

static int SessionDecodable( const TcpSession* sess )
{
	return sess->type != eSessTypeNull;
}

static TcpStream* GetPacketStream( const HTTPS_Pkt* pkt )
{
	TcpStream* retval = NULL;
	const TcpSession* sess;
	int dir = 0;

	sess = pkt->session;
	_ASSERT(sess);

	dir = SessionGetPacketDirection( sess, pkt );
	switch( dir )
	{
	case ePktDirFromClient:
		retval = &pkt->session->clientStream;
		break;
	case ePktDirFromServer:
		retval = &pkt->session->serverStream;
		break;

	default:
		_ASSERT( FALSE ); 
		retval = NULL;
		break;
	}

	return retval;
}

void SessionProcessPacket( HttpsEnv* env, HTTPS_Pkt* pkt )
{
	TcpStream* stream = NULL;
	int rc = HTTPS_RC_OK;
	int new_packets = 0;

	_ASSERT( pkt );
	_ASSERT( pkt->session );

	TouchSession( pkt->session );

	if( !SessionDecodable( pkt->session ) ) return;

	stream = GetPacketStream( pkt );
	if( stream == NULL ) { _ASSERT( stream ); return; }

	rc = StreamProcessPacket( stream, pkt, &new_packets );

	new_packets=1;
	while( new_packets && rc == HTTPS_RC_OK)
	{
		if(new_packets) { stream = StreamGetPeer(stream); }
		new_packets = 0;
		rc = StreamPollPackets( stream, &new_packets );
	}

	if( rc != HTTPS_RC_OK && rc != HTTPS_E_SSL_SERVER_KEY_UNKNOWN )
	{
		SessionOnError( pkt->session, rc );
	}

	if( rc != HTTPS_RC_OK || pkt->session->closing)
	{
		if (rc == HTTPS_RC_OK)
			SessionFlushPacketQueue( pkt->session );
		env->sessions->DestroySession( env->sessions, pkt->session );
	}
}



void SessionSetCallback( TcpSession* sess, DataCallbackProc data_callback, ErrorCallbackProc error_callback,
						void* user_data )
{
	_ASSERT( sess );

	sess->data_callback = data_callback;
	sess->error_callback = error_callback;
	sess->user_data = user_data;
	
	if( sess->ssl_session != NULL )
	{
		HTTPS_SessionSetCallback( sess->ssl_session, data_callback, error_callback, user_data );
	}
}

void SessionSetMissingPacketCallback( TcpSession* sess, MissingPacketCallbackProc missing_callback,
		int missing_packet_count, int timeout_sec )
{
	_ASSERT( sess );
	sess->missing_callback = missing_callback;
	sess->missing_packet_count = missing_packet_count;
	sess->missing_packet_timeout = timeout_sec;
}

void SessionSetEventCallback( TcpSession* sess, EventCallbackProc event_callback )
{
	_ASSERT( sess );

	sess->event_callback = event_callback;
	
	if( sess->ssl_session != NULL )
	{
		HTTPS_SessionSetEventCallback( sess->ssl_session, event_callback );
	}
}

static int DetectSessionTypeCallback(struct _TcpStream* stream, HTTPS_Pkt* pkt )
{
	TcpSession* sess = NULL; 
	DPI_PacketDir dir = ePktDirInvalid;
	int is_ssl = 0;

	_ASSERT(stream);
	_ASSERT(pkt);

	sess = stream->session;
	_ASSERT(sess && sess->type == eSessTypeTBD);

	dir = SessionGetPacketDirection(sess, pkt);
	if(dir == ePktDirFromClient)
	{
		uint16_t ver = 0;
		u_char* data = PKT_TCP_PAYLOAD( pkt );
		uint32_t len = pkt->data_len;
		int rc = ssl_detect_client_hello_version(data, len, &ver);
		is_ssl = (rc == HTTPS_RC_OK);
	}
	else if(dir == ePktDirFromServer)
	{
		is_ssl = 0; 
	}
	else
	{
		_ASSERT(SessionGetPacketDirection(sess, pkt) != ePktDirInvalid);
		return DPI_ERROR(HTTPS_E_INVALID_PARAMETER);
	}

#ifdef DPI_TRACE_TCP_SESSIONS
	DEBUG_TRACE1( "\nTCP Session Type detected: %s", is_ssl ? "SSL" : "PlainText" ); 
#endif

	sess->type = is_ssl ? eSessTypeSSL : eSessTypeTcp;
	SessionInitDecoders( sess, pkt);
	if(sess->type != eSessTypeNull)
		return sess->OnNewPacket( stream, pkt );
	else
		return HTTPS_RC_OK; 
}

static int OnNewPlainTextPacket( struct _TcpStream* stream, HTTPS_Pkt* pkt )
{
	TcpSession* sess;

	_ASSERT( stream );
	_ASSERT( pkt );

	sess = stream->session;
	_ASSERT( sess );

	if ( sess->data_callback )
	{
		sess->data_callback( SessionGetPacketDirection( sess, pkt ),
			sess->user_data, PKT_TCP_PAYLOAD( pkt ), pkt->data_len, pkt );
	}

	return 0;
}

static int OnNewSSLPacket( struct _TcpStream* stream, HTTPS_Pkt* pkt )
{
	TcpSession* sess = NULL;
	HTTPS_Session* ssl_sess = NULL;
	u_char* data = NULL;
	uint32_t len = 0;
	DPI_PacketDir dir = ePktDirInvalid;
	int rc = HTTPS_RC_OK;

	_ASSERT( stream );
	_ASSERT( pkt );

	sess = stream->session;
	_ASSERT( sess );

	ssl_sess = sess->ssl_session;
	if( !ssl_sess )
	{
		_ASSERT( FALSE );
		return DPI_ERROR( HTTPS_E_UNSPECIFIED_ERROR );
	}

	ssl_sess->last_packet = pkt;
	data = PKT_TCP_PAYLOAD( pkt );
	len = pkt->data_len;
	dir = SessionGetPacketDirection( sess, pkt );

	rc = HTTPS_SessionProcessData( ssl_sess, dir, data, len );

	if( ssl_sess->flags & ( SSF_CLOSE_NOTIFY_RECEIVED | SSF_FATAL_ALERT_RECEIVED ) )
	{
		sess->closing = 1;
	}

	return rc;
}

void* SessionGetUserData( const TcpSession* sess )
{
	_ASSERT( sess );
	return sess->user_data;
}

void TouchSession( TcpSession* sess )
{
	_ASSERT( sess );
	sess->last_update_time = time(NULL);
}

void SessionFlushPacketQueue( TcpSession* sess )
{
	TcpStream* stream = NULL;
	if(sess->type != eSessTypeTcp || sess->missing_callback == NULL ) return;

	if(sess->clientStream.pktHead && !sess->serverStream.pktHead) {
		stream = &sess->clientStream;
	} else if(sess->serverStream.pktHead && !sess->clientStream.pktHead) {
		stream = &sess->serverStream;
	} else if(sess->serverStream.pktHead && sess->clientStream.pktHead) {
		stream = &sess->clientStream;
		if(PKT_TCP_SEQ( stream->pktHead ) - stream->nextSeqExpected == 0 )
			stream = StreamGetPeer(stream);

		if(PKT_TCP_SEQ( stream->pktHead ) - stream->nextSeqExpected == 0)
			stream = NULL; 
		
		if(stream == NULL) {
			stream = PktCompareTimes( sess->serverStream.pktHead, sess->clientStream.pktHead ) < 0 ?
				&sess->clientStream : &sess->serverStream;
		}
	} else {
		return; 
	}

	while( sess->clientStream.pktHead || sess->serverStream.pktHead )
	{
		uint32_t len;
		if( stream->pktHead == NULL )
		{
			stream = StreamGetPeer( stream );
			continue;
		}

		if (PKT_TCP_SEQ( stream->pktHead ) > stream->nextSeqExpected) {
			len = PKT_TCP_SEQ( stream->pktHead ) - stream->nextSeqExpected;
		} else {
			len = 0;
		}
		if( len == 0 || sess->missing_callback( SessionGetPacketDirection(sess, stream->pktHead), SessionGetUserData(sess),
				PKT_TCP_SEQ(stream->pktHead), len) != 0)
		{
			int new_ack = 0; TcpStream* str = stream;

			int rc = StreamConsumeHead( str, &new_ack );
			if(rc == HTTPS_RC_OK ) rc = StreamPollPackets( str, &new_ack );

			while( new_ack && rc == HTTPS_RC_OK )
			{
				str = StreamGetPeer(str);
				new_ack = 0;
				rc = StreamPollPackets( str, &new_ack );
			}

			if( rc != HTTPS_RC_OK ) break;
		}
		else
		{
			break;
		}

		stream = StreamGetPeer(stream);
	}
}

int IsNewTcpSessionPacket( const HTTPS_Pkt* pkt )
{
	return pkt->tcp_header->th_flags & TH_SYN ? 1 : 0;
}

/*111*/

static uint32_t getTcpSessionHash( uint32_t ip1, uint16_t port1, uint32_t ip2, uint16_t port2 )
{
	uint32_t hash;

	if( ip1 < ip2 )
	{
		hash = fnv_32_buf( &ip1, sizeof(ip1), FNV1_32_INIT );
		hash = fnv_32_buf( &port1, sizeof(port1), hash );
		hash = fnv_32_buf( &ip2, sizeof(ip2), hash );
		hash = fnv_32_buf( &port2, sizeof(port2), hash );
	}
	else 
	{
		hash = fnv_32_buf( &ip2, sizeof(ip2), FNV1_32_INIT );
		hash = fnv_32_buf( &port2, sizeof(port2), hash );
		hash = fnv_32_buf( &ip1, sizeof(ip1), hash );
		hash = fnv_32_buf( &port1, sizeof(port1), hash );
	}
	return hash;
}


static uint32_t getPktSessionHash( const HTTPS_Pkt* pkt )
{
	uint32_t ip1, ip2;
	uint16_t port1, port2;

	_ASSERT( pkt );
	_ASSERT( pkt->ip_header );
	_ASSERT( pkt->tcp_header );


	if( INADDR_IP( pkt->ip_header->ip_src ) < INADDR_IP( pkt->ip_header->ip_dst ) )
	{
		ip1 = INADDR_IP( pkt->ip_header->ip_src );
		ip2 = INADDR_IP( pkt->ip_header->ip_dst );
		port1 = PKT_TCP_SPORT( pkt );
		port2 = PKT_TCP_DPORT( pkt );
	}
	else if( INADDR_IP( pkt->ip_header->ip_src ) > INADDR_IP( pkt->ip_header->ip_dst ) )
	{
		ip2 = INADDR_IP( pkt->ip_header->ip_src );
		ip1 = INADDR_IP( pkt->ip_header->ip_dst );
		port2 = PKT_TCP_SPORT( pkt );
		port1 = PKT_TCP_DPORT( pkt );
	}
	else
	{
		ip1 = ip2 = INADDR_IP( pkt->ip_header->ip_src );

		if( PKT_TCP_SPORT( pkt ) < PKT_TCP_DPORT( pkt ) )
		{
			port1 = PKT_TCP_SPORT( pkt );
			port2 = PKT_TCP_DPORT( pkt );
		}
		else
		{
			port2 = PKT_TCP_SPORT( pkt );
			port1 = PKT_TCP_DPORT( pkt );
		}
	}

	return getTcpSessionHash( ip1, port1, ip2, port2 );
}


static uint32_t getSessionHash( TcpSession* sess )
{
	uint32_t ip1, ip2;
	uint16_t port1, port2;

	_ASSERT( sess );

	if( sess->clientStream.ip_addr < sess->serverStream.ip_addr )
	{
		ip1 = sess->clientStream.ip_addr;
		ip2 = sess->serverStream.ip_addr;

		port1 = sess->clientStream.port;
		port2 = sess->serverStream.port;
	}
	else if( sess->clientStream.ip_addr > sess->serverStream.ip_addr )
	{
		ip2 = sess->clientStream.ip_addr;
		ip1 = sess->serverStream.ip_addr;

		port2 = sess->clientStream.port;
		port1 = sess->serverStream.port;
	}
	else
	{
		ip1 = ip2 = sess->clientStream.ip_addr;
		
		if( sess->clientStream.port < sess->serverStream.port )
		{
			port1 = sess->clientStream.port;
			port2 = sess->serverStream.port;
		}
		else
		{
			port2 = sess->clientStream.port;
			port1 = sess->serverStream.port;
		}
	}

	return getTcpSessionHash( ip1, port1, ip2, port2 );
}


static const TcpStream* GetStream(const HTTPS_Pkt* pkt, const TcpSession* sess )
{
	DPI_PacketDir dir = SessionGetPacketDirection( sess, pkt );

	_ASSERT( dir != ePktDirInvalid );
	return (dir == ePktDirFromClient) ? & sess->clientStream : &sess->serverStream;
}

static const TcpStream* GetPeerStream(const HTTPS_Pkt* pkt, const TcpSession* sess )
{
	DPI_PacketDir dir = SessionGetPacketDirection( sess, pkt );

	_ASSERT( dir != ePktDirInvalid );
	return (dir == ePktDirFromClient) ? & sess->clientStream : &sess->serverStream;
}

static int PacketSessionMatch( const TcpSession* sess, const HTTPS_Pkt* pkt )
{
	if( (SessionGetPacketDirection( sess, pkt ) != ePktDirInvalid)) {
		if(IsNewTcpSessionPacket(pkt)) {
			const TcpStream* stream = GetStream( pkt, sess );
			if( stream ) {
				uint32_t seq = PKT_TCP_SEQ(pkt);
				return ((stream->flags & HTTPS_TCPSTREAM_SENT_SYN) == 0) || (seq == stream->initial_seq);
			} else {
				return 0;
			}
		} else {
			return 1;
		}
	} else {
		return 0;
	}
}

static int GetSessionCountForPacket( const https_SessionTable* tbl, const HTTPS_Pkt* pkt, 
									TcpSession** psess )
{
	uint32_t hash = getPktSessionHash( pkt ) % tbl->tableSize;
	TcpSession* sess;
	int cnt = 0;

	if(psess) { *psess = NULL; }

	sess = tbl->table[hash];

	while( sess ) {
		if(PacketSessionMatch(sess, pkt)) {
			++ cnt;
			if(psess) { *psess = sess; }
		}
		sess = sess->next;
	}
	return cnt;
}

static TcpSession* FindBestSessionForPacket( const https_SessionTable* tbl, const HTTPS_Pkt* pkt,
											int cnt )
{
	TcpSession** sessions = (TcpSession**) alloca( sizeof(TcpSession*)*cnt );
	uint32_t hash = 0; int i = 0;
	TcpSession* sess = NULL;
	uint32_t pktSeq = PKT_TCP_SEQ(pkt);
	uint32_t* offsets = (uint32_t*) alloca(sizeof(uint32_t)*cnt);
	int best_sess_idx = 0;

	memset( sessions, 0, sizeof(TcpSession*)*cnt );
	memset( offsets, 0, sizeof(uint32_t)*cnt );

	hash = getPktSessionHash( pkt ) % tbl->tableSize;

	sess = tbl->table[hash];
	i = 0;
	while( sess ) {
		if(PacketSessionMatch(sess, pkt)) {
			_ASSERT( i < cnt );
			sessions[i] = sess;
			++ i;
		}
		sess = sess->next;
	}

	_ASSERT( i == cnt );

	for(i = 0; i < cnt; ++i) {
		TcpSession* s = sessions[i];
		const TcpStream* stream = GetStream( pkt, s);
		if( !stream ) { _ASSERT(FALSE); continue; }
		if( stream->nextSeqExpected == pktSeq ) return s;
		if( stream->pktTail && PktNextTcpSeqExpected(stream->pktTail) == pktSeq) return s;
	}

	for(i = 0; i < cnt; ++i) {
		TcpSession* s = sessions[i];
		const TcpStream* stream = GetStream( pkt, s);
		uint32_t seqBegin = 0; 
		uint32_t seqEnd = 0;

		if( !stream ) { _ASSERT(FALSE); continue; }

		seqBegin = stream->initial_seq;
		seqEnd = stream->pktTail ? PktNextTcpSeqExpected(stream->pktTail) : stream->nextSeqExpected;

		if(seqBegin <= seqEnd ) {
			if( pktSeq >= seqBegin && pktSeq <= seqEnd ) 
				return s;
			if( seqBegin && pktSeq >= seqEnd ) offsets[i] = pktSeq - seqEnd;
		} else { 
			if( pktSeq > seqBegin || pktSeq <= seqEnd ) 
				return s;
			if( seqBegin && pktSeq < seqBegin && pktSeq >= seqEnd ) offsets[i] = pktSeq - seqEnd;
		}
	}

	best_sess_idx = 0;
#ifdef DPI_TRACE_TCP_SESSIONS
	DEBUG_TRACE1("\n[**]? TCP Session ambiguity: choosing between %d sessions:", cnt );
	for(i=0; i < cnt; i++) {
		char buff[128];
		SessionToString(sessions[i], buff);
		DEBUG_TRACE2("\n\t%s at %p", buff, sessions[i] );
	}
#endif

	for(i=0; i < cnt;i++) {
		if( offsets[i] && offsets[i] < offsets[best_sess_idx] ) 
			best_sess_idx = i;
	}
	#ifdef DPI_TRACE_TCP_SESSIONS
		DEBUG_TRACE2("\nbest offset is %d for %d", offsets[best_sess_idx], best_sess_idx );
	#endif

	return sessions[best_sess_idx];
}

static TcpSession* _SessionTable_FindSession( https_SessionTable* tbl, HTTPS_Pkt* pkt )
{
	TcpSession* sess = NULL;
	int existingSessionCnt = 0;
	_ASSERT( pkt->ip_header );
	_ASSERT( pkt->tcp_header );

	existingSessionCnt = GetSessionCountForPacket( tbl, pkt, &sess );

	if( existingSessionCnt == 0 ) {
		return NULL;
	}

	if( existingSessionCnt == 1 ) {
		_ASSERT( sess ); 
		sess;
	} else {  
		sess = FindBestSessionForPacket( tbl, pkt, existingSessionCnt );
	}

	return sess;
}


static void _SessionTable_addSession( https_SessionTable* tbl, TcpSession* sess )
{
	uint32_t hash;
	TcpSession** prevSession;

	_ASSERT( tbl );
	_ASSERT( sess );

#ifdef DPI_TRACE_TCP_SESSIONS
	{
		char _trace_buff[512];
		DEBUG_TRACE2( "\n-->New  TCP Session: type: %d %s", (int)sess->type, SessionToString(sess, _trace_buff) );
	}
#endif
	sess->next = NULL;
	hash = getSessionHash( sess ) % tbl->tableSize;

	prevSession = &tbl->table[hash];

	while( (*prevSession) != NULL ) prevSession = &(*prevSession)->next;

	(*prevSession) = sess;
}


static TcpSession* _SessionTable_CreateSession( https_SessionTable* tbl, HTTPS_Pkt* pkt, DPI_SessionType s_type )
{
	TcpSession* sess = NULL;

	_ASSERT( tbl ); _ASSERT( pkt );

	if( s_type == eSessTypeNull )
	{
		_ASSERT( s_type != eSessTypeNull );
		return NULL;
	}

	if( tbl->timeout_interval != 0 && 
		time( NULL ) - tbl->last_cleanup_time > HTTPS_SESSION_CLEANUP_INTERVAL )
	{
		tbl->Cleanup( tbl );
	}

	if( tbl->maxSessionCount > 0 && tbl->sessionCount >= tbl->maxSessionCount )
	{
		if( tbl->env && tbl->env->session_callback )
		{
			tbl->env->session_callback( tbl->env, NULL, HTTPS_EVENT_SESSION_LIMIT );
		}
		return NULL;
	}

	sess = (TcpSession*) malloc( sizeof(*sess) );

	if( sess == NULL ) return NULL;

	if( SessionInit( tbl->env, sess, pkt, s_type ) != HTTPS_RC_OK )
	{
		free( sess );
		return NULL;
	}

	sess->packet_time = pkt->pcap_header.ts;

	if( sess && sess->type != eSessTypeNull && tbl->env && tbl->env->session_callback )
	{
		tbl->env->session_callback( tbl->env, sess, HTTPS_EVENT_NEW_SESSION );
	}

	_SessionTable_addSession( tbl, sess );

	++ tbl->sessionCount;

	return sess;
}


static void SessionTableFreeSession( https_SessionTable* tbl, TcpSession* sess )
{
#ifdef DPI_TRACE_TCP_SESSIONS
	{
		char _trace_buff[512];
		DEBUG_TRACE2( "\n-->Free TCP Session: type: %d %s", (int)sess->type, SessionToString(sess, _trace_buff) );
	}
#endif

	if( tbl->env && tbl->env->session_callback )
	{
		tbl->env->session_callback( tbl->env, sess, HTTPS_EVENT_SESSION_CLOSING );
	}
	SessionFree( sess );
}

static void _SessionTable_DestroySession( https_SessionTable* tbl, TcpSession* sess )
{
	uint32_t hash;
	TcpSession** s;
	_ASSERT( tbl ); _ASSERT( sess );

	hash = getSessionHash( sess ) % tbl->tableSize;
	s = &tbl->table[hash];

	while( (*s) &&	(*s) != sess ) 
		s = &(*s)->next;

	if( *s )
	{
		(*s) = (*s)->next;
		SessionTableFreeSession( tbl, sess );
		-- tbl->sessionCount;
	}
	else
	{
		_ASSERT( FALSE ); 
	}
}


static void _SessionTable_RemoveAll( https_SessionTable* tbl )
{
	int i;
	_ASSERT( tbl );

	for( i=0; i < tbl->tableSize; ++i )
	{
		TcpSession* s = tbl->table[i];
		while( s )
		{
			TcpSession* ss = s;
			s = s->next;
			SessionFlushPacketQueue( ss );
			SessionTableFreeSession( tbl, ss );
		}
	}

	memset( tbl->table, 0, sizeof(tbl->table[0])*tbl->tableSize );
	tbl->sessionCount = 0;
}

static void _SessionTable_Cleanup( https_SessionTable* tbl )
{
	int i;
	time_t cur_time = time( NULL );
	_ASSERT( tbl );

	for( i=0; i < tbl->tableSize && tbl->sessionCount > 0; ++i )
	{
		TcpSession** s = &tbl->table[i];
		while( *s )
		{
			if( (*s)->last_update_time != 0 && 
				cur_time - (*s)->last_update_time > tbl->timeout_interval )
			{
				TcpSession* sess = *s;
				(*s) = (*s)->next;
				#ifdef DPI_TRACE_TCP_SESSIONS
				{
					char _trace_buff[512];
					DEBUG_TRACE2( "\n-->TCP Session cleanup: type: %d %s", (int)sess->type, SessionToString(sess, _trace_buff) );
				}
				#endif
				SessionFlushPacketQueue( sess );
				SessionTableFreeSession( tbl, sess );
				-- tbl->sessionCount;
			}
			else
			{
				s = &(*s)->next;
			}
		}
	}

	tbl->last_cleanup_time = cur_time;
}


https_SessionTable* CreateSessionTable( int tableSize, uint32_t timeout_int )
{
	https_SessionTable* tbl;

	_ASSERT( tableSize > 0 );

	tbl = (https_SessionTable*) malloc( sizeof(https_SessionTable) );
	memset( tbl, 0, sizeof(*tbl) );

	tbl->FindSession = _SessionTable_FindSession;
	tbl->CreateSession = _SessionTable_CreateSession;
	tbl->DestroySession = _SessionTable_DestroySession;
	tbl->RemoveAll = _SessionTable_RemoveAll;
	tbl->Cleanup = _SessionTable_Cleanup;

	tbl->table = (TcpSession**) malloc( sizeof(tbl->table[0])*tableSize );
	memset( tbl->table, 0, sizeof(tbl->table[0])*tableSize );

	tbl->tableSize = tableSize;
	tbl->timeout_interval = timeout_int;
	tbl->last_cleanup_time = time( NULL );
	tbl->maxSessionCount = 0;
	tbl->maxCachedPacketCount = 0;

	return tbl;
}


void DestroySessionTable( https_SessionTable* tbl )
{
#ifdef DPI_TRACE_TCP_SESSIONS
	{
		DEBUG_TRACE1( "\n-->Destroying TCP Session Table, remaining session count %d", (int)tbl->sessionCount);
	}
#endif

	tbl->RemoveAll( tbl );
	free( tbl->table );
	free( tbl );
}


/*111*/

static int ssl2_decrypt_record( https_decoder_stack* stack, u_char* data, uint32_t len, 
					  u_char** out, int *buffer_aquired )
{
	u_char* buf = NULL;
	uint32_t buf_len = len;
	int rc = HTTPS_RC_OK;
	int block_size;
	const EVP_CIPHER* c = NULL;


	_ASSERT( stack );
	_ASSERT( stack->sess );
	_ASSERT( stack->cipher );

	rc = ssls_get_decrypt_buffer( stack->sess, &buf, buf_len );
	if( rc != HTTPS_RC_OK ) return rc;

	*buffer_aquired = 1;

	c = EVP_CIPHER_CTX_cipher( stack->cipher );
	block_size = EVP_CIPHER_block_size( c );

	if( block_size != 1 )
	{
		if( len == 0 || (len % block_size) != 0 )
		{
			return DPI_ERROR( HTTPS_E_SSL_DECRYPTION_ERROR );
		}
	}

	EVP_Cipher(stack->cipher, buf, data, len );

	*out = buf;

	return HTTPS_RC_OK;
}


int ssl2_record_layer_decoder( void* decoder_stack, DPI_PacketDir dir, 
		u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = HTTPS_RC_OK;
	uint32_t recLen = 0;
	uint32_t totalRecLen = 0;
	uint32_t hdrLen = 0;
	uint32_t padding = 0;
	https_decoder_stack* stack = (https_decoder_stack*) decoder_stack;
	https_decoder* next_decoder = NULL;
	int decrypt_buffer_aquired = 0;

	dir; 

	_ASSERT( stack );
	_ASSERT( processed );
	_ASSERT( stack->sess );


	if( len < 2 ) { return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH ); }

	if( data[0] & 0x80 )
	{
		hdrLen = 2;
		recLen = ((data[0] & 0x7f) << 8) | data[1];
		padding = 0;
	}
	else
	{
		hdrLen = 3;
		if (len < 3 ) { return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH ); }
		recLen = ((data[0] & 0x3f) << 8) | data[1];
		padding = data[2];
	}

	totalRecLen = recLen; 

#ifdef DPI_TRACE_SSL_RECORD
	DEBUG_TRACE1( "\n==>Decoding SSL v2 Record; len: %d\n{", (int) recLen );
#endif

	if( len < recLen ) { rc = HTTPS_RC_WOULD_BLOCK; }
	data += hdrLen; 

	if( rc == HTTPS_RC_OK && stack->cipher )
	{
		rc = ssl2_decrypt_record( stack, data, recLen, &data, &decrypt_buffer_aquired );
	}

	if( rc == HTTPS_RC_OK && stack->md )
	{
		data += EVP_MD_size( stack->md );
		recLen -= EVP_MD_size( stack->md );
	}

	if( rc == HTTPS_RC_OK && padding )
	{
		if( padding >= recLen ) 
		{
			rc = DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
		}
		else
		{
			recLen -= padding;
		}
	}

	if( rc == HTTPS_RC_OK )
	{
		switch( stack->state )
		{
		case SS_Initial:
		case SS_SeenClientHello:
		case SS_SeenServerHello:
			next_decoder = &stack->dhandshake;
			break;
		case SS_Established:
			next_decoder = &stack->dappdata;
			break;

		default:
			rc = DPI_ERROR( HTTPS_E_SSL_UNEXPECTED_TRANSMISSION );
			break;
		}
	}

	if( rc == HTTPS_RC_OK )
	{
		_ASSERT( next_decoder != NULL );
		rc = https_decoder_process( next_decoder, dir, data, recLen );
	}

	if( rc == HTTPS_RC_OK )
	{
		*processed = totalRecLen + hdrLen;
	}

#ifdef DPI_TRACE_SSL_RECORD
	DEBUG_TRACE1( "\n} rc: %d\n", (int) rc);
#endif

	return rc;

}

/*111*/

#define SSL20_CLIENT_HELLO_MIN_LEN			8
#define SSL20_CLIENT_MASTER_KEY_MIN_LEN 	9

#ifdef DPI_TRACE_SSL_HANDSHAKE
static const char* SSL2_HandshakeTypeToString( int hs_type )
{
	static const char* HandshakeCodes[] = 
	{
		"ERROR", "CLIENT-HELLO", "CLIENT-MASTER-KEY", "CLIENT-FINISHED",
		"SERVER-HELLO", "SERVER-VERIFY", "SERVER-FINISHED", 
		"REQUEST-CERTIFICATE", "CLIENT-CERTIFICATE"
	};

	if( hs_type >= 0 && hs_type < sizeof( HandshakeCodes ) / sizeof(HandshakeCodes[0] ) )
	{
		return HandshakeCodes[hs_type];
	}
	else
	{
		return "INVALID";
	}
}
#endif


int ssl2_handshake_record_decode_wrapper( void* decoder_stack, DPI_PacketDir dir,
								 u_char* data, uint32_t len, uint32_t* processed )
{
	https_decoder_stack* stack = (https_decoder_stack* )decoder_stack;
	return ssl2_decode_handshake( stack->sess, dir, data, len, processed );
}


static int ssl2_decode_client_hello( HTTPS_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = HTTPS_RC_OK;
	uint32_t sessionIdLen = 0, challengeLen = 0, cipherSpecLen = 0;

	_ASSERT( processed && data && sess );

	sess->handshake_start = sess->last_packet->pcap_header.ts;

	if( len < SSL20_CLIENT_HELLO_MIN_LEN ) return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH ); 

	if( data[0] == 0 && data[1] == 2 )
	{
		sess->client_version = SSL2_VERSION;
		rc = ssls_set_session_version( sess, SSL2_VERSION );
	}
	else if( data[0] == 3 ) 
	{
		sess->client_version = MAKE_UINT16(data[0], data[1]);
		rc = ssls_set_session_version( sess, MAKE_UINT16(data[0], data[1]) );
	}
	else
	{
		rc = DPI_ERROR( HTTPS_E_SSL_UNKNOWN_VERSION );
	}

	if( rc == HTTPS_RC_OK )
	{
		cipherSpecLen = MAKE_UINT16( data[2], data[3] );
		sessionIdLen = MAKE_UINT16( data[4], data[5] ); 
		challengeLen = MAKE_UINT16( data[6], data[7] ); 

		if( challengeLen + sessionIdLen + cipherSpecLen + SSL20_CLIENT_HELLO_MIN_LEN != len ) 
		{
			rc = DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
		}
	}

	
	if( rc == HTTPS_RC_OK )
	{
		if( sessionIdLen == 16 )
		{
			u_char* sessionId = data + SSL20_CLIENT_HELLO_MIN_LEN + cipherSpecLen;

			_ASSERT( sessionIdLen <= sizeof( sess->session_id ) );
			memset( sess->session_id, 0, sizeof( sess->session_id ) );
			memcpy( sess->session_id, sessionId, sessionIdLen );
			sess->flags |= SSF_CLIENT_SESSION_ID_SET;

		}
		else
		{
			sess->flags &= ~SSF_CLIENT_SESSION_ID_SET;
			if (sessionIdLen != 0 )
			{
				rc = DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );
			}
		}
	}

	if( rc == HTTPS_RC_OK )
	{
		if( challengeLen < 16 || challengeLen > 32 )
		{
			rc = DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );
		}
		else
		{
			u_char* challenge = data + SSL20_CLIENT_HELLO_MIN_LEN + cipherSpecLen + sessionIdLen;
			_ASSERT( challengeLen <= sizeof( sess->client_random ) );
			memset( sess->client_random, 0, sizeof( sess->client_random ) );
			memcpy( sess->client_random,  challenge, challengeLen );
			sess->client_challenge_len = challengeLen;
			sess->flags |= SSF_SSLV2_CHALLENGE;
		}
	}

	if( rc == HTTPS_RC_OK ) { *processed = len; }

	return rc;
}

static int ssl2_decode_server_hello( HTTPS_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = HTTPS_RC_OK;
	uint16_t certLen = 0;
	uint16_t cipherSpecLen = 0;
	uint16_t connectionIdLen = 0;
	int session_id_hit = 0;

	_ASSERT( processed && data && sess );

	if( len < SSL20_SERVER_HELLO_MIN_LEN ) { return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH ); }

	session_id_hit = data[0];

	if( rc == HTTPS_RC_OK && (data[1] && data[1] != SSL2_CT_X509_CERTIFICATE) ) 
	{
		rc = DPI_ERROR( HTTPS_E_SSL2_INVALID_CERTIFICATE_TYPE ); 
	}


	if( rc == HTTPS_RC_OK )
	{
		certLen = MAKE_UINT16( data[4], data[5] );
		cipherSpecLen = MAKE_UINT16( data[6], data[7] );
		connectionIdLen = MAKE_UINT16( data[8], data[9] );

		if( (uint32_t)certLen + cipherSpecLen + connectionIdLen + SSL20_SERVER_HELLO_MIN_LEN != len )
		{
			rc = DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
		}
		else if( connectionIdLen < 16 || connectionIdLen > 32 )
		{
			rc = DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );
		}

		if( rc == HTTPS_RC_OK ) 
		{
			u_char* connIdData = data + SSL20_SERVER_HELLO_MIN_LEN + certLen + cipherSpecLen;
			sess->server_connection_id_len = connectionIdLen; 
			memset( sess->server_random, 0, sizeof(sess->server_random) );
			memcpy( sess->server_random, connIdData, connectionIdLen );
		}
	}

	if( rc == HTTPS_RC_OK )
	{
	}

	if( session_id_hit )
	{
		if( sess->flags & SSF_CLIENT_SESSION_ID_SET )
		{
			rc = ssls_lookup_session( sess );
			if( rc == HTTPS_RC_OK)
			{
				rc = ssls2_generate_keys( sess, sess->ssl2_key_arg, sess->ssl2_key_arg_len );
			}
			if( rc == HTTPS_RC_OK ) 
			{
				rc = https_decoder_stack_flip_cipher( &sess->c_dec );
				if (rc == HTTPS_RC_OK ) { rc = https_decoder_stack_flip_cipher( &sess->s_dec ); }
			}
		}
		else
		{
			rc = DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );
		}
	}


	if( rc == HTTPS_RC_OK )
	{
		*processed = certLen + cipherSpecLen + connectionIdLen + SSL20_SERVER_HELLO_MIN_LEN;
	}

	return rc;
}

static int ssl2_decode_client_master_key(  HTTPS_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = HTTPS_RC_OK;
	uint16_t clearKeyLen = 0;
	uint16_t encKeyLen = 0;
	uint16_t keyArgLen = 0;
	u_char* pClearKey = NULL;
	u_char* pEncKey = NULL;
	u_char* pKeyArg = NULL;

	_ASSERT( processed && data && sess );
	if( len < SSL20_CLIENT_MASTER_KEY_MIN_LEN ) { return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH ); }

	rc = HTTPS_ConvertSSL2CipherSuite( data, &sess->cipher_suite );

	if( rc == HTTPS_RC_OK )
	{
		clearKeyLen = MAKE_UINT16( data[3], data[4] );
		encKeyLen = MAKE_UINT16( data[5], data[6] );
		keyArgLen = MAKE_UINT16( data[7], data[8] );

		if( len != (uint32_t)clearKeyLen + encKeyLen + keyArgLen + SSL20_CLIENT_MASTER_KEY_MIN_LEN )
		{
			rc = DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
		}

		*processed = len;

	}
	
	if( rc == HTTPS_RC_OK )
	{
		EVP_PKEY *pk = NULL;

		pClearKey = data + SSL20_CLIENT_MASTER_KEY_MIN_LEN;
		pEncKey = pClearKey + clearKeyLen;
		pKeyArg = pEncKey + encKeyLen;

		if( clearKeyLen ) { memcpy( sess->master_secret, pClearKey, clearKeyLen ); }

		pk = ssls_get_session_private_key( sess );
		
		if(pk == NULL) 
		{
			u_char buff[1024];
			_ASSERT( sess->last_packet);

			memcpy(buff, pEncKey, encKeyLen);
			pk = ssls_try_ssl_keys( sess, pEncKey, encKeyLen );

			if(pk != NULL)
			{
				if( ssls_register_ssl_key( sess, pk ) == HTTPS_RC_OK)
				{
				}
				else
				{
					pk = NULL;
				}
			}
		}

		if( pk )
		{
			uint32_t encLen2 = RSA_private_decrypt( encKeyLen, pEncKey, 
					sess->master_secret + clearKeyLen, pk->pkey.rsa, RSA_PKCS1_PADDING );

			if( clearKeyLen + encLen2 >= sizeof( sess->master_secret ) )
			{
				rc = DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );
			}

			sess->master_key_len = clearKeyLen + encLen2;
		}
		else
		{
			rc = DPI_ERROR( HTTPS_E_SSL_SERVER_KEY_UNKNOWN );
		}
	}

	if( rc == HTTPS_RC_OK )
	{
		rc = ssls2_generate_keys( sess, pKeyArg, keyArgLen );
	}

	if( rc == HTTPS_RC_OK ) 
	{
		rc = https_decoder_stack_flip_cipher( &sess->c_dec );
		if (rc == HTTPS_RC_OK ) { rc = https_decoder_stack_flip_cipher( &sess->s_dec ); }
	}

	return rc;
}


static int ssl2_decode_client_finished(  HTTPS_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	_ASSERT( processed && data && sess );

	if( len != sess->server_connection_id_len ) { return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH ); }

	if( memcmp( data, sess->server_random, sess->server_connection_id_len ) != 0 )
	{
		return DPI_ERROR( HTTPS_E_SSL2_BAD_CLIENT_FINISHED ); 
	}

	*processed = len;

	return HTTPS_RC_OK;
}

static int ssl2_decode_server_verify(  HTTPS_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{	
	_ASSERT( processed && data && sess );

	if( len != sess->client_challenge_len ) { return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH ); }

	if( memcmp( data, sess->client_random, sess->client_challenge_len ) != 0 )
	{
		return DPI_ERROR( HTTPS_E_SSL2_BAD_SERVER_VERIFY ); 
	}

	*processed = len;

	return HTTPS_RC_OK;
}

static int ssl2_decode_server_finished(  HTTPS_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	_ASSERT( processed && data && sess );

	if( len > sizeof( sess->session_id ) ) { return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH ); }

	memset( sess->session_id, 0, sizeof(sess->session_id ) );
	memcpy( sess->session_id, data, len );
	ssls_store_session( sess );

	sess->c_dec.state = SS_Established;
	sess->s_dec.state = SS_Established;
	ssls_handshake_done( sess );

	*processed = len;

	return HTTPS_RC_OK;
}

static int ssl2_decode_error(  HTTPS_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	data; 
	sess->flags |= SSF_FATAL_ALERT_RECEIVED;

	*processed = len;
	return HTTPS_RC_OK;
}


int ssl2_decode_handshake( HTTPS_Session* sess, DPI_PacketDir dir, 
		u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = HTTPS_RC_OK;
	int hs_type = 0;

	_ASSERT( processed );
	_ASSERT( data );

	if( len < 1 ) { return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH ); }
	hs_type = data[0];
	data += 1;
	len -= 1;

#ifdef DPI_TRACE_SSL_HANDSHAKE
	DEBUG_TRACE1( "\n===>Decoding SSL v2 handshake message: %s", SSL2_HandshakeTypeToString( hs_type ) );
#endif

	switch(hs_type)
	{
	case SSL2_MT_CLIENT_HELLO:
	case SSL2_MT_CLIENT_MASTER_KEY:
	case SSL2_MT_CLIENT_FINISHED:
	case SSL2_MT_CLIENT_CERTIFICATE:
		if( dir != ePktDirFromClient ) { rc = DPI_ERROR( HTTPS_E_SSL_UNEXPECTED_TRANSMISSION ); }
		break;

	case SSL2_MT_SERVER_HELLO:
	case SSL2_MT_SERVER_VERIFY:
	case SSL2_MT_SERVER_FINISHED:
		if( dir != ePktDirFromServer ) { rc = DPI_ERROR( HTTPS_E_SSL_UNEXPECTED_TRANSMISSION ); }
		break;
	}

	if( rc == HTTPS_RC_OK )
	{
		switch( hs_type )
		{
		case SSL2_MT_ERROR:
			rc = ssl2_decode_error( sess, data, len, processed );
			break;

		case SSL2_MT_CLIENT_HELLO:
			rc = ssl2_decode_client_hello( sess, data, len, processed );
			break;

		case SSL2_MT_SERVER_HELLO:
			sess->s_dec.state = SS_SeenServerHello;
			rc = ssl2_decode_server_hello( sess, data, len, processed );
			break;

		case SSL2_MT_CLIENT_MASTER_KEY:
			rc = ssl2_decode_client_master_key( sess, data, len, processed );
			break;

		case SSL2_MT_CLIENT_FINISHED:
			rc = ssl2_decode_client_finished( sess, data, len, processed );
			break;

		case SSL2_MT_SERVER_VERIFY:
			rc = ssl2_decode_server_verify( sess, data, len, processed );
			break;

		case SSL2_MT_SERVER_FINISHED:
			rc = ssl2_decode_server_finished( sess, data, len, processed );
			break;

		case SSL2_MT_CLIENT_CERTIFICATE:
		case SSL2_MT_REQUEST_CERTIFICATE:
			*processed = len;
			rc = HTTPS_RC_OK;
			break;

		default:
			rc = DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );
			break;
		}

		if( rc == HTTPS_RC_OK )
		{
			*processed += 1;
		}
	}

	return rc;
}


/*111*/

void HTTPS_ServerInfoFree( HTTPS_ServerInfo* si )
{
	if( si == NULL ) return;

	if( si->pkey != NULL )
	{
		EVP_PKEY_free( si->pkey );
		si->pkey = NULL;
	}

	free( si );
}

static void HTTPS_ServerInfoFreeArray( HTTPS_ServerInfo** si, int size )
{
	int i;
	_ASSERT( si );
	_ASSERT( size > 0 );

	for( i = 0; i < size; i++ ) 
	{
		HTTPS_ServerInfoFree( si[i] );
	}

	free( si );
}


static int password_cb_direct( char *buf, int size, int rwflag, void *userdata )
{
	char* pwd = (char*) userdata;
	int len = (int) strlen( pwd );

	rwflag;

	strncpy( buf, pwd, size );
	return len;
}

static int ServerInfo_LoadPrivateKey( EVP_PKEY **pkey, const char *keyfile, const char *pwd )
{
	FILE* f = NULL;
	int rc = HTTPS_RC_OK;

	f = fopen( keyfile, "r" );
	if( !f ) return DPI_ERROR( HTTPS_E_SSL_PRIVATE_KEY_FILE_OPEN );

	if( rc == HTTPS_RC_OK && PEM_read_PrivateKey( f, pkey, password_cb_direct, (void *)pwd ) == NULL )
	{
		rc = DPI_ERROR( HTTPS_E_SSL_LOAD_PRIVATE_KEY );
	}

	fclose( f );

	return rc;
}


HTTPS_Session* HTTPS_EnvCreateSession( HTTPS_Env* env, struct in_addr dst_ip, uint16_t dst_port,
									struct in_addr src_ip, uint16_t src_port)
{

	HTTPS_ServerInfo* si = HTTPS_EnvFindServerInfo( env, dst_ip, dst_port );
	HTTPS_Session* sess = NULL;
	
	if(!si) si = HTTPS_EnvFindServerInfo( env, src_ip, src_port );
	
	sess = malloc( sizeof( HTTPS_Session) );
	HTTPS_SessionInit( env, sess, si );

	return sess;
}


void HTTPS_EnvOnSessionClosing( HTTPS_Env* env, HTTPS_Session* s )
{
	_ASSERT( env );
	_ASSERT( s );

	if( env->session_cache )
	{
		https_SessionKT_Release( env->session_cache, s->session_id );
	}
}


HTTPS_Env* HTTPS_EnvCreate( int session_cache_size, uint32_t cache_timeout_interval )
{
	HTTPS_Env* env = (HTTPS_Env*) malloc( sizeof( HTTPS_Env ) );
	if( !env ) return NULL;

	memset( env, 0, sizeof( *env ) );

	env->session_cache = https_SessionKT_Create( session_cache_size, cache_timeout_interval );
	env->ticket_cache = https_SessionTicketTable_Create( session_cache_size, cache_timeout_interval );

	return env;
}


void HTTPS_EnvDestroy( HTTPS_Env* env )
{
	if( env->servers ) 
	{
		_ASSERT( env->server_count > 0 );
		HTTPS_ServerInfoFreeArray( env->servers, env->server_count );
		env->server_count = 0;
		env->servers = NULL;
	}

	if( env->missing_key_servers )
	{
		_ASSERT( env->missing_key_server_count > 0 );
		HTTPS_ServerInfoFreeArray( env->missing_key_servers, env->missing_key_server_count );
		env->missing_key_server_count = 0;
		env->missing_key_servers = NULL;
	}

	if( env->session_cache )
	{
		https_SessionKT_Destroy( env->session_cache );
	}

	if( env->ticket_cache )
	{
		https_SessionTicketTable_Destroy( env->ticket_cache );
	}

	if( env->keys )
	{
		int i = 0;
		_ASSERT( env->key_count > 0 );
		for(i = 0; i < env->key_count; i++)
		{
			EVP_PKEY_free( env->keys[i] );
		}

		free( env->keys);
		env->keys = NULL; env->key_count = 0;
	}

	free( env );
}

int HTTPS_EnvAddServer( HTTPS_Env* env, HTTPS_ServerInfo* server )
{
	HTTPS_ServerInfo** new_servers = NULL;
	int i = 0;

	for(i = 0; i < env->server_count; i++)
	{
		_ASSERT( env->servers && env->servers[i]);
		if(env->servers[i]->port == server->port && INADDR_IP(env->servers[i]->server_ip) == INADDR_IP(server->server_ip))
			return DPI_ERROR( HTTPS_E_SSL_DUPLICATE_SERVER );
	}

	new_servers = realloc( env->servers, (env->server_count + 1)*sizeof(*env->servers) );

	if( new_servers == NULL ) return DPI_ERROR( HTTPS_E_OUT_OF_MEMORY );

	new_servers[env->server_count] = server;
	env->servers = new_servers;
	env->server_count++;

	return HTTPS_RC_OK;
}


int HTTPS_EnvSetServerInfoWithKey( HTTPS_Env* env, const struct in_addr* ip_address,
	uint16_t port, EVP_PKEY *pkey )
{
	HTTPS_ServerInfo* server = NULL;
	int rc = HTTPS_RC_OK;

	if( !pkey ) return DPI_ERROR( HTTPS_E_INVALID_PARAMETER );

	server = (HTTPS_ServerInfo*) calloc( 1, sizeof( HTTPS_ServerInfo ) );
	
	if( !server ) return DPI_ERROR( HTTPS_E_OUT_OF_MEMORY );

	memcpy( &server->server_ip,  ip_address, sizeof(server->server_ip) ) ;
	server->port = port;
	server->pkey = pkey;

	rc = HTTPS_EnvAddServer( env, server );

	if( rc != HTTPS_RC_OK )
	{
		HTTPS_ServerInfoFree( server );
	}

	return HTTPS_RC_OK;
}


int HTTPS_EnvSetServerInfo( HTTPS_Env* env, const struct in_addr* ip_address, uint16_t port, 
			const char* keyfile, const char* password )
{
	int rc = HTTPS_RC_OK;
	EVP_PKEY *pkey = NULL;

	if ( !keyfile )
		return DPI_ERROR( HTTPS_E_INVALID_PARAMETER );

	if ( !password )
		password = "";

	rc = ServerInfo_LoadPrivateKey( &pkey, keyfile, password );
	if( rc != HTTPS_RC_OK ) 
	{
		return rc;
	}

	rc = HTTPS_EnvSetServerInfoWithKey( env, ip_address, port, pkey );
	return rc;
}


HTTPS_ServerInfo* HTTPS_EnvFindServerInfo( const HTTPS_Env* env, struct in_addr ip_address, uint16_t port )
{
	int i;
	for( i = 0; i < env->server_count; i++ )
	{
		HTTPS_ServerInfo* si = env->servers[i];

		if( INADDR_IP( si->server_ip ) == INADDR_IP( ip_address ) &&
			port == si->port ) return si;
	}

	return NULL;
}

int HTTPS_GetSSLKeyIndex( const HTTPS_Env* env, EVP_PKEY* pkey)
{
	int i = 0;

	for(i = 0; i < env->key_count; i++)
	{
		if( pkey == env->keys[i] ) return i;
	}

	return -1;
}

int HTTPS_AddSSLKey(HTTPS_Env* env, EVP_PKEY* pkey)
{
	int i = HTTPS_GetSSLKeyIndex(env, pkey);
	EVP_PKEY** new_keys = NULL;
	_ASSERT(env && pkey);

	if(i != -1) return HTTPS_RC_OK;
	
	new_keys = realloc(env->keys, (env->key_count+1)*sizeof(*env->keys));
	if(new_keys == NULL) return DPI_ERROR(HTTPS_E_OUT_OF_MEMORY); 

	new_keys[env->key_count] = pkey;
	env->keys = new_keys;
	++env->key_count;

	return HTTPS_RC_OK;
}

/*111*/

int ssl3_change_cipher_spec_decoder( void* decoder_stack, DPI_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed )
{
	https_decoder_stack* stack = (https_decoder_stack*) decoder_stack;

	dir;

	if( len != 1 ) return DPI_ERROR( DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH ) );
	if(data[0] != 1 ) return DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );

	*processed = 1;

	return https_decoder_stack_flip_cipher( stack );
}

char decode_buf[81920]={0};
int decode_len = 0;
int ssl_application_data_decoder( void* decoder_stack, DPI_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed )
{
	https_decoder_stack* stack = (https_decoder_stack*) decoder_stack;
	HTTPS_Session* sess;

	memcpy(&decode_buf[decode_len], data, len);
	decode_len += len;

	*processed = len;
	return HTTPS_RC_OK;
}

int ssl3_alert_decoder( void* decoder_stack, DPI_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed )
{
	https_decoder_stack* stack = (https_decoder_stack*) decoder_stack;

	UNUSED_PARAM(dir);

	if( len != 2 ) return DPI_ERROR( DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH ) );

	if( data[0] == 2 )
	{
		stack->state = SS_FatalAlert;
	}

	if( data[1] == 0 )
	{
		stack->state = SS_SeenCloseNotify;
	}

#ifdef DPI_TRACE_SSL_RECORD
	DEBUG_TRACE2( "\nAlert received: %s (%d)", 
			( (stack->state == SS_FatalAlert) ? "fatal alert" : 
			((stack->state == SS_SeenCloseNotify) ? "close_notify alert" : "unknown alert")), 
			(int) MAKE_UINT16( data[0], data[1] ) );
#endif

		(*processed) = len;
	return HTTPS_RC_OK;
}


static int ssl_decrypt_record( https_decoder_stack* stack, u_char* data, uint32_t len, 
					  u_char** out, uint32_t* out_len, int *buffer_aquired )
{
	u_char* buf = NULL;
	uint32_t buf_len = len;
	int rc = HTTPS_RC_OK;
	int block_size;
	const EVP_CIPHER* c = NULL;


	_ASSERT( stack );
	_ASSERT( stack->sess );
	_ASSERT( stack->cipher );

	rc = ssls_get_decrypt_buffer( stack->sess, &buf, buf_len );
	if( rc != HTTPS_RC_OK ) return rc;

	*buffer_aquired = 1;

	c = EVP_CIPHER_CTX_cipher( stack->cipher );
	block_size = EVP_CIPHER_block_size( c );

	if( block_size != 1 )
	{
		if( len == 0 || (len % block_size) != 0 )
		{
			return DPI_ERROR( HTTPS_E_SSL_DECRYPTION_ERROR );
		}
	}

	EVP_Cipher(stack->cipher, buf, data, len );

	buf_len = len;
	if( block_size != 1 )
	{
		if( buf[len-1] >= buf_len - 1 ) return DPI_ERROR( HTTPS_E_SSL_DECRYPTION_ERROR );
		buf_len -= buf[len-1] + 1;
	}

	*out = buf;
	*out_len = buf_len;

	return HTTPS_RC_OK;
}

static int ssl_decompress_record( https_decoder_stack* stack, u_char* data, uint32_t len, 
					  u_char** out, uint32_t* out_len, int *buffer_aquired )
{
	int rc = HTTPS_RC_OK;
	u_char* buf = NULL;
	uint32_t buf_len = HTTPS_MAX_RECORD_LENGTH;

	_ASSERT( stack );
	_ASSERT( stack->sess );

	rc = ssls_get_decompress_buffer( stack->sess, &buf, buf_len );
	if( rc != HTTPS_RC_OK ) return rc;

	*buffer_aquired = 1;

	rc = https_decompress( stack->compression_method, stack->compression_data,
			data, len, buf, &buf_len );

	if( rc == HTTPS_RC_OK ) 
	{
		*out = buf;
		*out_len = buf_len;
	}

	return rc;
}


int ssl3_record_layer_decoder( void* decoder_stack, DPI_PacketDir dir,
		u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = HTTPS_E_UNSPECIFIED_ERROR;
	uint32_t recLen = 0, totalRecLen = 0;
	uint8_t record_type = 0;
	https_decoder_stack* stack = (https_decoder_stack*) decoder_stack;
	https_decoder* next_decoder = NULL;
	int decrypt_buffer_aquired = 0;
	int decompress_buffer_aquired = 0;

	_ASSERT( stack );
	_ASSERT( processed );
	_ASSERT( stack->sess );

	if( stack->state > SS_Established )
	{
#ifdef DPI_TRACE_SSL_RECORD
		DEBUG_TRACE1( "[!]Unexpected SSL record after %s", 
			( (stack->state == SS_FatalAlert) ? "fatal alert" : "close_notify alert") );
#endif
		return DPI_ERROR( HTTPS_E_SSL_UNEXPECTED_TRANSMISSION );
	}

	if( stack->sess->version == 0 )
	{
		_ASSERT( dir == ePktDirFromClient );
		rc = ssl_decode_first_client_hello( stack->sess, data, len, processed );
		return rc;
	}

	if( len < SSL3_HEADER_LEN ) return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
	if( data[1] != 3) return DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );

	record_type = data[0];
	totalRecLen = recLen = MAKE_UINT16( data[3], data[4] );

	data += SSL3_HEADER_LEN;
	len -= SSL3_HEADER_LEN;

#ifdef DPI_TRACE_SSL_RECORD
	DEBUG_TRACE2( "\n==>Decoding SSL v3 Record, type: %d, len: %d\n{\n", (int) record_type, (int) recLen );
#endif

	rc = HTTPS_RC_OK;
	if( len < recLen ) { rc = HTTPS_RC_WOULD_BLOCK; }

	if( rc == HTTPS_RC_OK && stack->cipher )
	{
		rc = ssl_decrypt_record( stack, data, recLen, &data, &recLen, &decrypt_buffer_aquired );
	}

	if( rc == HTTPS_RC_OK && (recLen > RFC_2246_MAX_COMPRESSED_LENGTH || 
		recLen > len || (stack->md && recLen < EVP_MD_size(stack->md))) )
	{
		rc = DPI_ERROR(HTTPS_E_SSL_INVALID_RECORD_LENGTH);
	}

	if( rc == HTTPS_RC_OK && stack->md )
	{
		u_char mac[EVP_MAX_MD_SIZE];
		u_char* rec_mac = NULL;
		
		recLen -= EVP_MD_size( stack->md );
		rec_mac = data+recLen;

		memset(mac, 0, sizeof(mac) );
		rc = stack->sess->caclulate_mac_proc( stack, record_type, data, recLen, mac );

		if( rc == HTTPS_RC_OK )
		{
			rc = memcmp( mac, rec_mac, EVP_MD_size(stack->md) ) == 0 ? HTTPS_RC_OK : DPI_ERROR( HTTPS_E_SSL_INVALID_MAC );
		}
	}

	if( rc == HTTPS_RC_OK && stack->compression_method != 0 )
	{
		rc = ssl_decompress_record( stack, data, recLen, &data, &recLen, &decompress_buffer_aquired );
	}

	if( rc == HTTPS_RC_OK )
	{
		switch( record_type )
		{
			case SSL3_RT_HANDSHAKE:
				next_decoder = &stack->dhandshake;
				break;

			case SSL3_RT_CHANGE_CIPHER_SPEC:
				next_decoder = &stack->dcss;
				break;

			case SSL3_RT_APPLICATION_DATA:
				next_decoder = &stack->dappdata;
				break;
			case SSL3_RT_ALERT:
				next_decoder = &stack->dalert;
				break;

			default:
				rc = DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );
		}
	}

	if( rc == HTTPS_RC_OK )
	{
		_ASSERT( next_decoder != NULL );
		rc = https_decoder_process( next_decoder, dir, data, recLen );
	}

	if( rc == HTTPS_RC_OK )
	{
		*processed = totalRecLen + SSL3_HEADER_LEN;
	}

#ifdef DPI_TRACE_SSL_RECORD
	DEBUG_TRACE1( "\n} rc: %d\n", (int) rc);
#endif

	if( stack->state == SS_SeenCloseNotify )
	{
		stack->sess->flags |= SSF_CLOSE_NOTIFY_RECEIVED;
	} else if ( stack->state == SS_FatalAlert )
	{
		stack->sess->flags |= SSF_FATAL_ALERT_RECEIVED;
	}

	return rc;
}

/*111*/

#ifndef SSL3_MT_NEWSESSION_TICKET
	#define SSL3_MT_NEWSESSION_TICKET		4
#endif

#ifdef DPI_TRACE_SSL_HANDSHAKE
static const char* SSL3_HandshakeTypeToString( int hs_type )
{
	switch(hs_type) {
		case SSL3_MT_HELLO_REQUEST: return "HelloRequest"; 
		case SSL3_MT_CLIENT_HELLO: return "ClientHello";
		case SSL3_MT_SERVER_HELLO: return "ServerHello";
		case SSL3_MT_NEWSESSION_TICKET: return "NewSessionTicket (unsupported!)";
		case SSL3_MT_CERTIFICATE: return "Sertificate";
		case SSL3_MT_SERVER_KEY_EXCHANGE: return "ServerKeyExchange";
		case SSL3_MT_CERTIFICATE_REQUEST: return "CertificateRequest";
		case SSL3_MT_SERVER_DONE: return "ServerHelloDone";
		case SSL3_MT_CERTIFICATE_VERIFY: return "CertificateVerify";
		case SSL3_MT_CLIENT_KEY_EXCHANGE: return "ClientKeyExchange";
		case SSL3_MT_FINISHED: return "Finished";
		case DTLS1_MT_HELLO_VERIFY_REQUEST: return "HelloVerifyRequest";
		default: return "Unknown";
	}
}

static const char* SSL3_ExtensionTypeToString( int ext_type )
{
	static char buff[64];
	switch(ext_type) {
		case 0x0000: return "server_name"; 
		case 0x000a: return "elliptic_curves";
		case 0x000b: return "ec_point_format";
		case 0x0023: return "Session Ticket TLS";
		default:
			sprintf(buff, "Unknown (%x)", ext_type);
			return buff;
	}
}

#endif

static int ssl3_decode_client_hello( HTTPS_Session* sess, u_char* data, uint32_t len )
{
	u_char* org_data = data;
	int t_len = 0;

	sess->handshake_start = sess->last_packet->pcap_header.ts;

	if( data[0] != 3 || data[1] > 3) return DPI_ERROR( HTTPS_E_SSL_UNKNOWN_VERSION );

	sess->client_version = MAKE_UINT16( data[0], data[1] );
	ssls_set_session_version( sess, MAKE_UINT16( data[0], data[1] ) );

	data+= 2;

	if( data + 32 > org_data + len ) return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );

	memcpy( sess->client_random, data, 32 );
	data+= 32;

	if( data[0] > 32 ) return DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );

	if( data[0] > 0 )
	{
		if( data + data[0] > org_data + len ) 
			return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );

		memcpy( sess->session_id, data+1, data[0] );
		sess->flags |= SSF_CLIENT_SESSION_ID_SET;

		data += data[0] + 1;
	}
	else
	{
		sess->flags &= ~SSF_CLIENT_SESSION_ID_SET;
		++data;
	}

	if(data + 1 >= org_data + len) return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
	t_len = MAKE_UINT16(data[0], data[1]) + 2; 

	data += t_len;

	if(data >= org_data + len) return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
	if(data + data[0] + 1 > org_data + len) return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
	t_len = data[0] + 1;

	data += t_len;


	ssls_free_extension_data(sess);

	if(data >= org_data + len) return HTTPS_RC_OK;

	if(data + 2 > org_data + len) return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
	t_len = MAKE_UINT16(data[0], data[1]);

	data += 2; 
	while(t_len >= 4)
	{
		int ext_type = MAKE_UINT16(data[0], data[1]); 
		int ext_len = MAKE_UINT16(data[2], data[3]);
		#ifdef DPI_TRACE_SSL_HANDSHAKE
			DEBUG_TRACE2( "\nSSL extension: %s len: %d", SSL3_ExtensionTypeToString( ext_type ), ext_len );
		#endif

		if( ext_type == 0x0023)
		{
			if(ext_len > 0)
			{
				sess->flags |= SSF_TLS_SESSION_TICKET_SET;
				sess->session_ticket = (u_char*) malloc(ext_len);
				if(sess->session_ticket == NULL) return DPI_ERROR(HTTPS_E_OUT_OF_MEMORY);
				memcpy(sess->session_ticket, data+4, ext_len);
				sess->session_ticket_len = ext_len;
			}
		}

		data += ext_len + 4;
		if(data > org_data + len) return DPI_ERROR(HTTPS_E_SSL_INVALID_RECORD_LENGTH);
		t_len -= ext_len + 4;
	}

	return HTTPS_RC_OK;
}


static int ssl3_decode_server_hello( HTTPS_Session* sess, u_char* data, uint32_t len )
{
	uint16_t server_version = 0;
	u_char* org_data = data;
	uint16_t session_id_len = 0;
	int session_id_match = 0;

	if( data[0] != 3 || data[1] > 1) return DPI_ERROR( HTTPS_E_SSL_UNKNOWN_VERSION );
	if( len < SSL3_SERVER_HELLO_MIN_LEN ) return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );

	server_version = MAKE_UINT16( data[0], data[1] );
	if( sess->version == 0 || server_version < sess->version )
	{
		ssls_set_session_version( sess, server_version );
	}
	data+= 2;

	_ASSERT_STATIC( sizeof(sess->server_random) == 32 );

	memcpy( sess->server_random, data, sizeof( sess->server_random ) );
	data+= 32;


	_ASSERT_STATIC( sizeof(sess->session_id) == 32 );
	session_id_len = data[0];
	data++;

	if( session_id_len > 0 )
	{
		if ( session_id_len > 32 ) return DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );

		if( !IS_ENOUGH_LENGTH( org_data, len, data, session_id_len ) ) 
		{
			return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
		}

		if( sess->flags & SSF_CLIENT_SESSION_ID_SET 
			&& memcmp( sess->session_id, data, session_id_len ) == 0 )
		{
			session_id_match = 1;
		}
		else
		{
			sess->flags &= ~SSF_CLIENT_SESSION_ID_SET;
			memcpy( sess->session_id, data, session_id_len );
		}

		data += session_id_len;
	}

	if( !IS_ENOUGH_LENGTH( org_data, len, data, 3 ) ) 
	{
		return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
	}

	sess->cipher_suite = MAKE_UINT16( data[0], data[1] );
	sess->compression_method = data[2];

	data += 3;
	sess->flags &= ~SSF_TLS_SERVER_SESSION_TICKET; 
	if(IS_ENOUGH_LENGTH( org_data, len, data, 2 )) 
	{
		int t_len = MAKE_UINT16(data[0], data[1]);
		data += 2;
		if(!IS_ENOUGH_LENGTH( org_data, len, data, t_len)) 
			return DPI_ERROR(HTTPS_E_SSL_INVALID_RECORD_LENGTH);

		while(t_len >= 4)
		{
			int ext_type = MAKE_UINT16(data[0], data[1]); 
			int ext_len = MAKE_UINT16(data[2], data[3]);
			#ifdef DPI_TRACE_SSL_HANDSHAKE
				DEBUG_TRACE2( "\nSSL extension: %s len: %d", SSL3_ExtensionTypeToString( ext_type ), ext_len );
			#endif

			if( ext_type == 0x0023)
			{
				sess->flags |= SSF_TLS_SERVER_SESSION_TICKET;
			}

			data += ext_len + 4;
			if(data > org_data + len) return DPI_ERROR(HTTPS_E_SSL_INVALID_RECORD_LENGTH);
			t_len -= ext_len + 4;
		}
	}

	if( session_id_match )
	{
		if( sess->flags & SSF_TLS_SESSION_TICKET_SET)
		{
			int rc = ssls_init_from_tls_ticket( sess );
			if( DPI_IS_FAILED( rc ) ) 
				return rc;
		}
		else
		{
			int rc = ssls_lookup_session( sess );
			if( DPI_IS_FAILED( rc ) ) 
				return rc;
		}
	}

	if( sess->flags & SSF_CLIENT_SESSION_ID_SET )
	{
		int rc = ssls_generate_keys( sess );
		if( DPI_IS_FAILED( rc ) ) return rc;
	}

	return HTTPS_RC_OK;
}


int ssl_decode_first_client_hello( HTTPS_Session* sess, u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = HTTPS_RC_OK;
	
	if( data[0] & 0x80 && len >= 3 && data[2] == SSL2_MT_CLIENT_HELLO )
	{
		int hdrLen = SSL20_CLIENT_HELLO_HDR_LEN;
		uint32_t recLen = len - hdrLen;

		rc = ssl2_decode_handshake( sess, ePktDirFromClient, data + hdrLen, recLen, processed );

		if( rc == HTTPS_RC_OK )
		{
			if( sess->version >= SSL3_VERSION && sess->version <= TLS1_VERSION )
			{
				ssl3_init_handshake_digests( sess );
				ssl3_update_handshake_digests( sess, data + hdrLen, recLen );
			}

			*processed += hdrLen;
		}
	}
	else if( data[0] == SSL3_RT_HANDSHAKE && len > 6 && 
		data[1] == SSL3_VERSION_MAJOR && data[5] == SSL3_MT_CLIENT_HELLO )
	{
		uint32_t recLen = 0;
		u_char* org_data;

		data += SSL3_HEADER_LEN;
		recLen = (((int32_t)data[1]) << 16) | (((int32_t)data[2]) << 8) | data[3];
		org_data = data;

		data += SSL3_HANDSHAKE_HEADER_LEN;
		len -= SSL3_HANDSHAKE_HEADER_LEN;
		
		rc = ssl3_decode_client_hello( sess, data, recLen );
		if( rc == HTTPS_RC_OK )
		{
			*processed = recLen + SSL3_HANDSHAKE_HEADER_LEN + SSL3_HEADER_LEN;
			ssl3_init_handshake_digests( sess );
			ssl3_update_handshake_digests( sess, org_data, recLen + SSL3_HANDSHAKE_HEADER_LEN );
		}
	}
	else
	{
		rc = DPI_ERROR( HTTPS_E_SSL_UNKNOWN_VERSION );
	}

	return rc;
}


int ssl_detect_client_hello_version( u_char* data, uint32_t len, uint16_t* ver )
{
	int rc = HTTPS_RC_OK;

	_ASSERT( ver != NULL );
	_ASSERT( data != NULL );

	if( data[0] & 0x80 && len >= 3 && data[2] == SSL2_MT_CLIENT_HELLO )
	{
		*ver = MAKE_UINT16( data[3], data[4] );
	}
	else if ( data[0] == SSL3_RT_HANDSHAKE && len > 11 && 
		data[1] == SSL3_VERSION_MAJOR && data[5] == SSL3_MT_CLIENT_HELLO )
	{
		uint16_t client_hello_ver = MAKE_UINT16( data[9], data[10] );
		*ver = MAKE_UINT16( data[1], data[2] );

		if( *ver != client_hello_ver ) rc = HTTPS_E_SSL_PROTOCOL_ERROR;
	}
	else
	{
		rc = HTTPS_E_SSL_UNKNOWN_VERSION;
	}

	return rc;
}

int ssl_detect_server_hello_version( u_char* data, uint32_t len, uint16_t* ver )
{
	int rc = HTTPS_RC_OK;

	_ASSERT( ver != NULL );
	_ASSERT( data != NULL );
	
	if( data[0] & 0x80 && len >= SSL20_SERVER_HELLO_MIN_LEN && data[2] == SSL2_MT_SERVER_HELLO )
	{
		*ver = MAKE_UINT16( data[5], data[6] );
	}
	else if( data[0] == SSL3_RT_HANDSHAKE && len > 11 && 
		data[1] == SSL3_VERSION_MAJOR && data[5] == SSL3_MT_SERVER_HELLO )
	{
		uint16_t sever_hello_ver = MAKE_UINT16( data[9], data[10] );
		*ver = MAKE_UINT16( data[1], data[2] );

		if( *ver != sever_hello_ver ) rc = DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );
	}
	else if( data[0] == SSL3_RT_ALERT && len == 7 && data[1] == SSL3_VERSION_MAJOR &&
			MAKE_UINT16( data[3], data[4] ) == 2 )
	{
		*ver = MAKE_UINT16( data[1], data[2] );
	}
	else
	{
		rc = DPI_ERROR( HTTPS_E_SSL_UNKNOWN_VERSION );
	}

	return rc;
}


int ssl3_decode_client_key_exchange( HTTPS_Session* sess, u_char* data, uint32_t len )
{
	EVP_PKEY *pk = NULL;
	u_char* org_data = data;
	uint32_t org_len = len;
	int pms_len = 0;
	int rc = HTTPS_RC_OK;

	if( sess->version < SSL3_VERSION || sess->version > TLS1_VERSION )
	{
		return DPI_ERROR( HTTPS_E_SSL_UNKNOWN_VERSION );
	}


	if( sess->version > SSL3_VERSION )
	{
		uint16_t recLen = 0;
		if( !IS_ENOUGH_LENGTH( org_data, org_len, data, 2 ) ) 
		{
			return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
		}

		recLen = MAKE_UINT16( data[0], data[1] );
		if( len != (uint32_t)recLen + 2 )
		{
			return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
		}

		data += len - recLen;
		len = recLen;
	}

	if( !IS_ENOUGH_LENGTH( org_data, org_len, data, SSL_MAX_MASTER_KEY_LENGTH ) )
	{
		return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
	}

	pk = ssls_get_session_private_key( sess );

	if(pk == NULL) 
	{
		_ASSERT( sess->last_packet);
		pk = ssls_try_ssl_keys( sess, data, len );

		if(pk != NULL)
		{
			if( ssls_register_ssl_key( sess, pk ) == HTTPS_RC_OK)
			{
				pk = ssls_get_session_private_key( sess );
			}
			else
			{
				pk = NULL;
			}
		}
	}

	if(!pk) 
	{
		return DPI_ERROR( HTTPS_E_SSL_SERVER_KEY_UNKNOWN );
	}

	if(pk->type != EVP_PKEY_RSA) return DPI_ERROR( HTTPS_E_SSL_CANNOT_DECRYPT_NON_RSA );

	pms_len = RSA_private_decrypt( len, data, sess->PMS, pk->pkey.rsa, RSA_PKCS1_PADDING );

	if( pms_len != SSL_MAX_MASTER_KEY_LENGTH )
	{
		return DPI_ERROR( HTTPS_E_SSL_CORRUPTED_PMS );
	}

	if( MAKE_UINT16( sess->PMS[0], sess->PMS[1] ) != sess->client_version )
	{
		return DPI_ERROR( HTTPS_E_SSL_PMS_VERSION_ROLLBACK );
	}

	rc = ssls_decode_master_secret( sess );
	OPENSSL_cleanse(sess->PMS, sizeof(sess->PMS) );

	if( rc != HTTPS_RC_OK ) return rc;

	rc = ssls_generate_keys( sess );
	if( rc == HTTPS_RC_OK )
	{
		ssls_store_session( sess );
	}
	return rc;
}


static int ssl3_decode_dummy( HTTPS_Session* sess, u_char* data, uint32_t len )
{
	UNUSED_PARAM( sess );
	UNUSED_PARAM( data );
	UNUSED_PARAM( len );

	return HTTPS_RC_OK;
}


static int ssl3_decode_server_certificate( HTTPS_Session* sess, u_char* data, uint32_t len )
{
	X509 *x=NULL;
	uint32_t llen = 0;
	int rc = HTTPS_RC_OK;

	if( !sess ) return DPI_ERROR( HTTPS_E_INVALID_PARAMETER );

	//TBD: skip server certificate check if SSL key has not yet been mapped for this server
	if( !sess->ssl_si ) return HTTPS_RC_OK;

	if( !sess->ssl_si->pkey ) return DPI_ERROR( HTTPS_E_UNINITIALIZED_ARGUMENT );

	if( len < 3 ) return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );
	
	llen = MAKE_UINT24( data[0], data[1], data[2] );
	data+=3;
	if( llen + 3 != len || llen < 3 ) return DPI_ERROR( HTTPS_E_SSL_INVALID_CERTIFICATE_RECORD );

	llen = MAKE_UINT24( data[0], data[1], data[2] );
	data+=3;
	if( llen > len ) return DPI_ERROR( HTTPS_E_SSL_INVALID_CERTIFICATE_LENGTH );

	x = d2i_X509( NULL, (const unsigned char **)&data, llen );
	if( !x ) 
	{
		rc = DPI_ERROR( HTTPS_E_SSL_BAD_CERTIFICATE );
	}

	if( rc == HTTPS_RC_OK && !X509_check_private_key(x, ssls_get_session_private_key( sess )) )
	{
		rc = DPI_ERROR( HTTPS_E_SSL_CERTIFICATE_KEY_MISMATCH );
	}

	if( x ) X509_free( x );

	return rc;
}

static int ssl3_decode_new_session_ticket(HTTPS_Session* sess, u_char* data, uint32_t len )
{
	uint16_t sz = 0;
	if(len < 6) return DPI_ERROR(HTTPS_E_SSL_INVALID_RECORD_LENGTH);

	sz = MAKE_UINT16(data[4], data[5]);

	if(len != sz + 6) return DPI_ERROR(HTTPS_E_SSL_PROTOCOL_ERROR);

	return ssls_store_new_ticket( sess, data + 6, sz );
}

void ssl3_init_handshake_digests( HTTPS_Session* sess )
{
	EVP_DigestInit_ex( &sess->handshake_digest_md5, EVP_md5(), NULL );
	EVP_DigestInit_ex( &sess->handshake_digest_sha, EVP_sha1(), NULL );
}


void ssl3_update_handshake_digests( HTTPS_Session* sess, u_char* data, uint32_t len )
{
	if( sess->handshake_digest_md5.digest == NULL
		|| sess->handshake_digest_sha.digest == NULL)
	{
		ssl3_init_handshake_digests( sess );
	}
	EVP_DigestUpdate( &sess->handshake_digest_md5, data, len );
	EVP_DigestUpdate( &sess->handshake_digest_sha, data, len );
}


int ssl3_decode_handshake_record( void* decoder_stack, DPI_PacketDir dir,
								 u_char* data, uint32_t len, uint32_t* processed )
{
	int rc = HTTPS_E_UNSPECIFIED_ERROR;
	uint32_t recLen = 0;
	u_char hs_type = 0;
	u_char* org_data = data;
	https_decoder_stack* stack = (https_decoder_stack *)decoder_stack;
	HTTPS_Session* sess = stack->sess;
	_ASSERT( processed != NULL );
	_ASSERT((sess->flags & SSF_SSLV2_CHALLENGE) == 0);

	if( sess->version == 0 )
	{
		return ssl_decode_first_client_hello( sess, data, len, processed );
	}

	if( len < SSL3_HANDSHAKE_HEADER_LEN ) return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );

	recLen = (((int32_t)data[1]) << 16) | (((int32_t)data[2]) << 8) | data[3];
	hs_type = data[0];

	data += SSL3_HANDSHAKE_HEADER_LEN;
	len -= SSL3_HANDSHAKE_HEADER_LEN;

	if( len < recLen )return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );

#ifdef DPI_TRACE_SSL_HANDSHAKE
	DEBUG_TRACE2( "===>Decoding SSL v3 handshake: %s len: %d...", SSL3_HandshakeTypeToString( hs_type ), (int) recLen );
#endif

	switch( hs_type )
	{
	case SSL3_MT_HELLO_REQUEST:
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_CLIENT_HELLO:
		rc = ssl3_decode_client_hello( sess, data, recLen );
		break;

	case SSL3_MT_SERVER_HELLO:
		stack->state = SS_SeenServerHello;
		rc = ssl3_decode_server_hello( sess, data, recLen );
		break;

	case SSL3_MT_CERTIFICATE:
		if( dir == ePktDirFromServer )
		{
			rc = ssl3_decode_server_certificate( sess, data, recLen );
		}
		else
		{
			rc = ssl3_decode_dummy( sess, data, recLen );
		}
		break;

	case SSL3_MT_SERVER_DONE:
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_CLIENT_KEY_EXCHANGE:
		rc = ssl3_decode_client_key_exchange( sess, data, recLen );
		break;

	case SSL3_MT_FINISHED:
		rc = (*sess->decode_finished_proc)( sess, dir, data, recLen );
		if( rc == HTTPS_RC_OK ) {
			stack->state = SS_Established;
			ssls_handshake_done( sess );
		}
		break;

	case SSL3_MT_SERVER_KEY_EXCHANGE:
		rc = DPI_ERROR( HTTPS_E_SSL_CANNOT_DECRYPT_EPHEMERAL );
		break;

	case SSL3_MT_CERTIFICATE_REQUEST:
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_CERTIFICATE_VERIFY:
		rc = ssl3_decode_dummy( sess, data, recLen );
		break;

	case SSL3_MT_NEWSESSION_TICKET:
		rc = ssl3_decode_new_session_ticket( sess, data, recLen );
		break;

	default:
		rc = DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );
		break;
	}

	if( rc == HTTPS_RC_OK )
	{
		*processed = recLen + SSL3_HANDSHAKE_HEADER_LEN;

		if( hs_type == SSL3_MT_CLIENT_HELLO ) 
		{
			ssl3_init_handshake_digests( sess );
		}

		if( hs_type != SSL3_MT_HELLO_REQUEST )
		{
			ssl3_update_handshake_digests( sess, org_data, *processed );
		}
	}

#ifdef DPI_TRACE_SSL_HANDSHAKE
	if( rc == HTTPS_RC_OK )
	{
		DEBUG_TRACE0( "OK\n" );
	}
	else
	{
		DEBUG_TRACE1( "Error! (%d)\n", (int)rc );
	}
#endif

	return rc;
}

void ssls_handshake_done( HTTPS_Session* sess )
{

	if(sess->flags & SSF_TEST_SSL_KEY && sess->c_dec.state == SS_Established 
		&& sess->s_dec.state == SS_Established)
	{
		sess->flags &= ~SSF_TEST_SSL_KEY;
		_ASSERT(sess->ssl_si);
		if(sess->event_callback && sess->ssl_si)
		{
			(*sess->event_callback)( sess->user_data, eHttpsMappingDiscovered, sess->ssl_si );
		}
	}

	if( sess->event_callback && sess->c_dec.state == SS_Established && sess->s_dec.state == SS_Established )
	{
		struct timeval t = sess->last_packet->pcap_header.ts;

		t.tv_sec -= sess->handshake_start.tv_sec;

		if(t.tv_usec < sess->handshake_start.tv_usec)
		{
			--t.tv_sec;
			t.tv_usec = t.tv_usec  + 1000000 - sess->handshake_start.tv_usec;
		}
		else
		{
			t.tv_usec -= sess->handshake_start.tv_usec;
		}
		(*sess->event_callback)( sess->user_data, eHttpsHandshakeComplete, &t );
	}
}

/*111*/

static void fmt_seq( uint64_t n, u_char* buf )
{
	buf[7] = (u_char)(n & 0xff);
	buf[6] = (u_char)(( n >> 8)& 0xff );
	buf[5] = (u_char)(( n >> 16)& 0xff );
	buf[4] = (u_char)(( n >> 24)& 0xff );
	buf[3] = (u_char)(( n >> 32)& 0xff );
	buf[2] = (u_char)(( n >> 40)& 0xff );
	buf[1] = (u_char)(( n >> 48)& 0xff );
	buf[0] = (u_char)(( n >> 56)& 0xff );
}

static u_char ssl3_pad_1[48]={
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,
	0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36 };

static u_char ssl3_pad_2[48]={
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,
	0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c };


int ssl3_calculate_mac( https_decoder_stack* stack, u_char type, 
						 u_char* data, uint32_t len, u_char* mac )
{
	uint32_t mac_size = 0, pad_size = 0;
	const EVP_MD* md = stack->md;
	EVP_MD_CTX	md_ctx;
	u_char hdr[3];
	u_char seq_buf[8];

	_ASSERT( stack->md != NULL );
	_ASSERT_STATIC( sizeof(stack->seq_num) == 8 );

	mac_size = EVP_MD_size( md );
	pad_size = (48/mac_size)*mac_size;

	hdr[0] = type; 
	hdr[1] = (u_char)(len >> 8);
	hdr[2] = (u_char)(len &0xff);

	fmt_seq( stack->seq_num, seq_buf );
	++stack->seq_num;

	EVP_MD_CTX_init( &md_ctx );
	EVP_DigestInit_ex( &md_ctx, md, NULL );

	EVP_DigestUpdate( &md_ctx, stack->mac_key, mac_size );
	EVP_DigestUpdate( &md_ctx, ssl3_pad_1, pad_size );
	EVP_DigestUpdate( &md_ctx, seq_buf, 8 );
	EVP_DigestUpdate( &md_ctx, hdr, sizeof(hdr) );
	EVP_DigestUpdate( &md_ctx, data, len );
	EVP_DigestFinal_ex( &md_ctx, mac, NULL );

	EVP_DigestInit_ex( &md_ctx, md, NULL);
	EVP_DigestUpdate( &md_ctx, stack->mac_key, mac_size );
	EVP_DigestUpdate( &md_ctx, ssl3_pad_2, pad_size );
	EVP_DigestUpdate( &md_ctx, mac, mac_size );
	EVP_DigestFinal_ex( &md_ctx, mac, NULL );

	EVP_MD_CTX_cleanup(&md_ctx);

	return HTTPS_RC_OK;
}


static int ssl3_calculate_handshake_hash( HTTPS_Session* sess, DPI_PacketDir dir, 
										 EVP_MD_CTX* ctx, u_char* out)
{
	EVP_MD_CTX md_ctx;
	uint32_t md_size = 0, pad_size = 0;
	u_char* sender; uint32_t sender_len;
	static u_char sender_c[] = "\x43\x4c\x4e\x54";
	static u_char sender_s[] = "\x53\x52\x56\x52";
	const EVP_MD* md = EVP_MD_CTX_md( ctx );

	_ASSERT( dir == ePktDirFromClient || dir == ePktDirFromServer );

	md_size = EVP_MD_size( md );
	pad_size = (48/md_size)*md_size;

	sender = ( dir == ePktDirFromClient ) ? sender_c : sender_s;
	sender_len = 4;

	EVP_MD_CTX_init( &md_ctx );
	EVP_MD_CTX_copy_ex( &md_ctx, ctx );

	EVP_DigestUpdate( &md_ctx, sender, sender_len );
	EVP_DigestUpdate( &md_ctx, sess->master_secret, sizeof( sess->master_secret ) );
	EVP_DigestUpdate( &md_ctx, ssl3_pad_1, pad_size );
	EVP_DigestFinal_ex( &md_ctx, out, NULL );

	EVP_DigestInit_ex( &md_ctx, md, NULL);
	EVP_DigestUpdate( &md_ctx, sess->master_secret, sizeof( sess->master_secret ) );
	EVP_DigestUpdate( &md_ctx, ssl3_pad_2, pad_size );
	EVP_DigestUpdate( &md_ctx, out, md_size );

	EVP_DigestFinal_ex( &md_ctx, out, &md_size );

	EVP_MD_CTX_cleanup( &md_ctx );

	return md_size;
}


int ssl3_decode_finished( HTTPS_Session* sess, DPI_PacketDir dir, u_char* data, uint32_t len )
{
	u_char hash[EVP_MAX_MD_SIZE*2];
	uint32_t md5_hash_len = 0, sha_hash_len=0;
	int rc = HTTPS_RC_OK;

	md5_hash_len = ssl3_calculate_handshake_hash( sess, dir, 
			&sess->handshake_digest_md5, hash );
	
	sha_hash_len = ssl3_calculate_handshake_hash( sess, dir, 
		&sess->handshake_digest_sha, hash + md5_hash_len );
	
	if( len != sha_hash_len + md5_hash_len ) rc = DPI_ERROR( HTTPS_E_SSL_BAD_FINISHED_DIGEST );

	if( rc == HTTPS_RC_OK && memcmp( hash, data, len ) != 0 )
	{
		rc = DPI_ERROR( HTTPS_E_SSL_BAD_FINISHED_DIGEST );
	}

	return rc;
}


int tls1_calculate_mac( https_decoder_stack* stack, u_char type, 
						 u_char* data, uint32_t len, u_char* mac )
{
	HMAC_CTX hmac;
	uint32_t mac_size = 0;
	const EVP_MD* md = stack->md;
	u_char seq_buf[8];
	u_char hdr[5];

	_ASSERT( stack->md != NULL );
	_ASSERT_STATIC( sizeof(stack->seq_num) == 8 );

	if( md == NULL ) return DPI_ERROR( HTTPS_E_INVALID_PARAMETER );

	mac_size = EVP_MD_size( md );
	HMAC_CTX_init( &hmac );
	HMAC_Init_ex( &hmac, stack->mac_key, mac_size, md , NULL );

	fmt_seq( stack->seq_num, seq_buf );
	++stack->seq_num;

	HMAC_Update( &hmac, seq_buf, 8 );

	hdr[0] = type; 
	hdr[1] = (u_char)(stack->sess->version >> 8);
	hdr[2] = (u_char)(stack->sess->version & 0xff);
	hdr[3] = (u_char)((len & 0x0000ff00) >> 8);
	hdr[4] = (u_char)(len & 0xff);

	HMAC_Update( &hmac, hdr, sizeof(hdr) );
	HMAC_Update( &hmac, data, len );
	HMAC_Final( &hmac, mac, &mac_size );
	HMAC_CTX_cleanup( &hmac );

	return HTTPS_RC_OK;
}

int ssl2_calculate_mac( https_decoder_stack* stack, u_char type, 
						 u_char* data, uint32_t len, u_char* mac )
{
	uint32_t seq = (uint32_t) stack->seq_num;

	++seq;
	stack->seq_num = seq;

	type; data; len; mac;
	return DPI_ERROR( HTTPS_E_NOT_IMPL );
}


int tls1_decode_finished( HTTPS_Session* sess, DPI_PacketDir dir, u_char* data, uint32_t len )
{
	u_char buf[TLS_MD_MAX_CONST_SIZE + MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
	u_char* cur_ptr = NULL;
	u_char prf_out[12];
	EVP_MD_CTX digest;
	uint32_t sz = 0;
	const char* label;
	int rc = HTTPS_RC_OK;

	_ASSERT( sess->version >= TLS1_VERSION );
	if( len != 12 ) return DPI_ERROR( HTTPS_E_SSL_INVALID_RECORD_LENGTH );

	label = (dir == ePktDirFromClient) ? "client finished" : "server finished";
	
	EVP_MD_CTX_init( &digest );

	EVP_MD_CTX_copy_ex(&digest, &sess->handshake_digest_md5 );

	cur_ptr = buf;
	EVP_DigestFinal_ex( &digest, cur_ptr, &sz );
	cur_ptr += sz;

	EVP_MD_CTX_copy_ex(&digest, &sess->handshake_digest_sha );
	EVP_DigestFinal_ex( &digest, cur_ptr, &sz );
	cur_ptr += sz;

	EVP_MD_CTX_cleanup( &digest );

	rc = tls1_PRF( sess->master_secret, sizeof( sess->master_secret ),
			label, 
			buf, (uint32_t)(cur_ptr - buf),
			NULL, 0, 
			prf_out, sizeof( prf_out) );

	if( rc != HTTPS_RC_OK ) return rc;

	if( memcmp( data, prf_out, 12 ) != 0 ) return DPI_ERROR( HTTPS_E_SSL_BAD_FINISHED_DIGEST );

	return HTTPS_RC_OK;
}

/*111*/

void HTTPS_SessionInit( HTTPS_Env* env, HTTPS_Session* s, HTTPS_ServerInfo* si )
{
	_ASSERT( s );

#ifdef DPI_TRACE_SSL_SESSIONS
	DEBUG_TRACE0( "HTTPS_SessionInit\n" );
#endif
	memset( s, 0, sizeof(*s) );

	s->ssl_si = si;
	s->env = env;

	https_decoder_stack_init( &s->c_dec );
	https_decoder_stack_init( &s->s_dec );

	EVP_MD_CTX_init( &s->handshake_digest_md5 );
	EVP_MD_CTX_init( &s->handshake_digest_sha );
}


void HTTPS_SessionDeInit( HTTPS_Session* s )
{
#ifdef DPI_TRACE_SSL_SESSIONS
	DEBUG_TRACE0( "HTTPS_SessionDeInit\n" );
#endif

	if( s->env ) HTTPS_EnvOnSessionClosing( s->env, s );

	https_decoder_stack_deinit( &s->c_dec );
	https_decoder_stack_deinit( &s->s_dec );

	ssls_free_extension_data(s);

	EVP_MD_CTX_cleanup( &s->handshake_digest_md5 );
	EVP_MD_CTX_cleanup( &s->handshake_digest_sha );
}


void HTTPS_SessionSetCallback( HTTPS_Session* sess, DataCallbackProc data_callback, 
							ErrorCallbackProc error_callback, void* user_data )
{
	_ASSERT( sess );
	
	sess->data_callback = data_callback;
	sess->error_callback = error_callback;
	sess->user_data = user_data;
}


void HTTPS_SessionSetEventCallback(HTTPS_Session* sess, EventCallbackProc event_callback)
{
	_ASSERT( sess );
	sess->event_callback = event_callback;
}

extern char decode_buf[81920];
extern int decode_len;

int HTTPS_SessionProcessData( HTTPS_Session* sess, DPI_PacketDir dir, u_char* data, uint32_t len )
{
	int rc = HTTPS_RC_OK;
	https_decoder_stack* dec = NULL;
	memset(&decode_buf, 0, sizeof(decode_buf));
	decode_len = 0;

	if( dir == ePktDirInvalid ) return DPI_ERROR( HTTPS_E_INVALID_PARAMETER );

	dec = (dir == ePktDirFromClient) ? &sess->c_dec : &sess->s_dec;

	if( !sslc_is_decoder_stack_set( dec ) )
	{
		uint16_t ver = 0;

		if( dir == ePktDirFromClient )
		{
			rc = ssl_detect_client_hello_version( data, len, &ver );
		}
		else
		{
			rc = ssl_detect_server_hello_version( data, len, &ver );

			if( rc == HTTPS_RC_OK && sess->version != ver )
			{
				rc = https_decoder_stack_set( &sess->c_dec, sess, ver );
			}
			ssls_set_session_version( sess, ver );
		}

		if( rc == HTTPS_RC_OK ) 
		{
			rc = https_decoder_stack_set( dec, sess, ver );
		}
	}

	if( rc == HTTPS_RC_OK ) rc = https_decoder_stack_process( dec, dir, data, len );

	if( DPI_IS_FAILED( rc ) && sess->flags & SSF_TEST_SSL_KEY )
	{
		if(sess->event_callback)
		{
			(*sess->event_callback)( sess->user_data, eHttpsMappedKeyFailed, sess->ssl_si );
		}
		sess->ssl_si = NULL;
	}

	if( DPI_IS_FAILED( rc ) && sess->error_callback && rc != HTTPS_E_SSL_SERVER_KEY_UNKNOWN )
	{
		sess->error_callback( sess->user_data, rc );
	}

	if (( sess->data_callback ) &&( decode_len != 0))
	{
		sess->data_callback( dir, sess->user_data, decode_buf, decode_len, sess->last_packet);
	}

	return rc;
}


EVP_PKEY* ssls_get_session_private_key( HTTPS_Session* sess )
{
	if( sess->ssl_si == NULL ) return NULL;
	return sess->ssl_si->pkey;
}

static void ssls_convert_v2challenge(HTTPS_Session* sess)
{
	u_char buff[SSL3_RANDOM_SIZE];

	_ASSERT(sess->flags & SSF_SSLV2_CHALLENGE);
	_ASSERT(sess->client_challenge_len != 0);

	memset(buff, 0, sizeof(buff));
	memcpy(buff, sess->client_random, sess->client_challenge_len);

	memset(sess->client_random, 0, SSL3_RANDOM_SIZE);
	memcpy(sess->client_random + SSL3_RANDOM_SIZE - sess->client_challenge_len, 
		buff, sess->client_challenge_len);

	sess->flags &= ~SSF_SSLV2_CHALLENGE;

}

int ssls_set_session_version( HTTPS_Session* sess, uint16_t ver )
{
	int rc = HTTPS_RC_OK;

	sess->version = ver;

	switch( ver )
	{
	case SSL3_VERSION:
		sess->decode_finished_proc = ssl3_decode_finished;
		sess->caclulate_mac_proc  = ssl3_calculate_mac;
		if(sess->flags & SSF_SSLV2_CHALLENGE) 
			ssls_convert_v2challenge(sess);
		break;

	case TLS1_VERSION:
	case TLS1_1_VERSION:
	case TLS1_2_VERSION:		
		sess->decode_finished_proc = tls1_decode_finished;
		sess->caclulate_mac_proc = tls1_calculate_mac;
		if(sess->flags & SSF_SSLV2_CHALLENGE) 
			ssls_convert_v2challenge(sess);
		break;

	case SSL2_VERSION:
		sess->decode_finished_proc = NULL;
		sess->caclulate_mac_proc = ssl2_calculate_mac;
		break;

	default:
		rc = DPI_ERROR( HTTPS_E_SSL_UNKNOWN_VERSION );
		break;
	}

	return rc;
}


int ssls_decode_master_secret( HTTPS_Session* sess )
{
	switch( sess->version )
	{
	case SSL3_VERSION:
		return ssl3_PRF( sess->PMS, SSL_MAX_MASTER_KEY_LENGTH, 
					sess->client_random, SSL3_RANDOM_SIZE, 
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->master_secret, sizeof( sess->master_secret ) );

	case TLS1_VERSION:
		return tls1_PRF( sess->PMS, SSL_MAX_MASTER_KEY_LENGTH, 
					"master secret", 
					sess->client_random, SSL3_RANDOM_SIZE, 
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->master_secret, sizeof( sess->master_secret ) );

	default:
		return DPI_ERROR( HTTPS_E_NOT_IMPL );
	}
}


static void ssl3_generate_export_iv( u_char* random1, u_char* random2, u_char* out )
{
	MD5_CTX md5;
	
	MD5_Init( &md5 );
	MD5_Update( &md5, random1, SSL3_RANDOM_SIZE );
	MD5_Update( &md5, random2, SSL3_RANDOM_SIZE );
	MD5_Final( out, &md5 );
}

#define TLS_MAX_KEYBLOCK_LEN ((EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH + EVP_MAX_MD_SIZE)*2)
int ssls_generate_keys( HTTPS_Session* sess )
{
	HTTPS_CipherSuite* suite = NULL;
	const EVP_CIPHER* c = NULL;
	const EVP_MD* digest = NULL;
	u_char* c_mac = NULL;
	u_char* c_wk = NULL;
	u_char* c_iv = NULL;
	u_char* s_mac = NULL;
	u_char* s_wk = NULL;
	u_char* s_iv = NULL;
	u_char export_iv_block[EVP_MAX_IV_LENGTH*2];

	u_char export_c_wk[EVP_MAX_KEY_LENGTH];
	u_char export_s_wk[EVP_MAX_KEY_LENGTH];
	
	u_char keyblock[ TLS_MAX_KEYBLOCK_LEN ];
	uint32_t keyblock_len = 0;

	uint32_t iv_len = 0;
	uint32_t wk_len = 0;
	uint32_t digest_len = 0;

	EVP_CIPHER_CTX* c_cipher = NULL;
	EVP_CIPHER_CTX* s_cipher = NULL;

	int rc = HTTPS_RC_OK;

	_ASSERT( sess->c_dec.compression_data_new == NULL );
	_ASSERT( sess->s_dec.compression_data_new == NULL );
	_ASSERT( sess->c_dec.compression_method_new == 0 );
	_ASSERT( sess->s_dec.compression_method_new == 0 );

	if( sess->compression_method != 0 )
	{
		sess->s_dec.compression_method_new = sess->compression_method;
		sess->c_dec.compression_method_new = sess->compression_method;

		https_compr_init( sess->s_dec.compression_method_new, &sess->s_dec.compression_data_new );
		https_compr_init( sess->c_dec.compression_method_new, &sess->c_dec.compression_data_new );
	}

	if( sess->c_dec.cipher_new != NULL )
	{
//		_ASSERT( FALSE );
		EVP_CIPHER_CTX_cleanup( sess->c_dec.cipher_new );
		free( sess->c_dec.cipher_new );
		sess->c_dec.cipher_new = NULL;
	}

	if( sess->s_dec.cipher_new != NULL )
	{
//		_ASSERT( FALSE );
		EVP_CIPHER_CTX_cleanup( sess->s_dec.cipher_new );
		free( sess->s_dec.cipher_new );
		sess->s_dec.cipher_new = NULL;
	}

	suite = HTTPS_GetSSL3CipherSuite( sess->cipher_suite );
	if( !suite ) return DPI_ERROR( HTTPS_E_SSL_CANNOT_DECRYPT );

	c = EVP_get_cipherbyname( suite->enc );
	digest = EVP_get_digestbyname( suite->digest );

	if( c != NULL ) 
	{
		if( HTTPS_CipherSuiteExportable( suite ) )
		{ wk_len = suite->export_key_bits / 8; }
		else 
		{ wk_len = EVP_CIPHER_key_length( c ); }

		iv_len = EVP_CIPHER_iv_length( c );
	}
	if( digest != NULL ) digest_len = EVP_MD_size( digest );

	keyblock_len = (wk_len + digest_len + iv_len)*2;
	if( !keyblock_len ) return HTTPS_RC_OK;

	if( sess->version == TLS1_VERSION )
	{
		rc = tls1_PRF( sess->master_secret, sizeof( sess->master_secret ), 
					"key expansion", 
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->client_random, SSL3_RANDOM_SIZE,
					keyblock, keyblock_len );
	}
	else
	{
		rc = ssl3_PRF( sess->master_secret, sizeof( sess->master_secret ),
					sess->server_random, SSL3_RANDOM_SIZE,
					sess->client_random, SSL3_RANDOM_SIZE,
					keyblock, keyblock_len );
	}

	if( rc == HTTPS_RC_OK )
	{
		u_char* p = keyblock;

		if( digest_len )
		{
			c_mac = p; p+= digest_len;
			s_mac = p; p+= digest_len;
		}

		if( c != NULL )
		{
			c_wk = p; p+= wk_len;
			s_wk = p; p+= wk_len;

			if( HTTPS_CipherSuiteExportable( suite ) )
			{
				int final_wk_len =	EVP_CIPHER_key_length( c );
				if( sess->version == TLS1_VERSION )
				{
					tls1_PRF( c_wk, wk_len, "client write key", 
							sess->client_random, SSL3_RANDOM_SIZE,
							sess->server_random, SSL3_RANDOM_SIZE,
							export_c_wk, final_wk_len );
					
					tls1_PRF( s_wk, wk_len, "server write key", 
							sess->client_random, SSL3_RANDOM_SIZE,
							sess->server_random, SSL3_RANDOM_SIZE,
							export_s_wk, final_wk_len );
				}
				else
				{
					MD5_CTX md5;

					_ASSERT( sess->version == SSL3_VERSION );
					MD5_Init( &md5 );
					MD5_Update( &md5, c_wk, wk_len );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_c_wk, &md5 );

					MD5_Init( &md5 );
					MD5_Update( &md5, s_wk, wk_len );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_s_wk, &md5 );

				}
				c_wk = export_c_wk;
				s_wk = export_s_wk;
				wk_len = final_wk_len;
			}
		}
		
		if( iv_len )
		{
			if( HTTPS_CipherSuiteExportable( suite ) )
			{
				if( sess->version == TLS1_VERSION )
				{
					tls1_PRF( NULL, 0, "IV block",
							sess->client_random, SSL3_RANDOM_SIZE, 
							sess->server_random, SSL3_RANDOM_SIZE,
							export_iv_block, iv_len*2 );
				}
				else
				{
					MD5_CTX md5;

					_ASSERT( sess->version == SSL3_VERSION );

					MD5_Init( &md5 );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_iv_block, &md5 );

					MD5_Init( &md5 );
					MD5_Update( &md5, sess->server_random, SSL3_RANDOM_SIZE );
					MD5_Update( &md5, sess->client_random, SSL3_RANDOM_SIZE );
					MD5_Final( export_iv_block + iv_len, &md5 );
				}
				c_iv = export_iv_block;
				s_iv = export_iv_block + iv_len;
			}
			else
			{
				c_iv = p; p+= iv_len;
				s_iv = p; p+= iv_len;
			}
		}
		else
		{
			c_iv = s_iv = NULL;
		}
	}

	if(  c != NULL && rc == HTTPS_RC_OK )
	{
		c_cipher = (EVP_CIPHER_CTX*) malloc( sizeof(EVP_CIPHER_CTX) );
		s_cipher = (EVP_CIPHER_CTX*) malloc( sizeof(EVP_CIPHER_CTX) );

		if( !c_cipher || !s_cipher ) 
		{
			rc = DPI_ERROR( HTTPS_E_OUT_OF_MEMORY );
		}
	}

	if( c != NULL && rc == HTTPS_RC_OK )
	{
		EVP_CIPHER_CTX_init( c_cipher );
		EVP_CipherInit( c_cipher, c, c_wk, c_iv, 0 );

		EVP_CIPHER_CTX_init( s_cipher );
		EVP_CipherInit( s_cipher, c, s_wk, s_iv, 0 );
	}

	if( rc == HTTPS_RC_OK )
	{
		_ASSERT( sess->c_dec.cipher_new == NULL );
		_ASSERT( sess->s_dec.cipher_new == NULL );

		sess->c_dec.cipher_new = c_cipher; c_cipher = NULL;
		sess->s_dec.cipher_new = s_cipher; s_cipher = NULL;

		if( digest )
		{
			_ASSERT( EVP_MD_size( digest ) == (int)digest_len );
			sess->c_dec.md_new = digest;
			sess->s_dec.md_new = digest;
			memcpy( sess->c_dec.mac_key_new, c_mac, digest_len );
			memcpy( sess->s_dec.mac_key_new, s_mac, digest_len );
		}
	}

	OPENSSL_cleanse( keyblock, keyblock_len );

	if( c_cipher )
	{
		free( c_cipher );
		c_cipher = NULL;
	}

	if( s_cipher )
	{
		free( c_cipher );
		c_cipher = NULL;
	}

	return rc;
}

#define SSL2_MAX_KEYBLOCK_LEN	48
int ssls2_generate_keys( HTTPS_Session* sess, u_char* keyArg, uint32_t keyArgLen )
{
	HTTPS_CipherSuite* suite = NULL;
	const EVP_CIPHER* c = NULL;
	const EVP_MD* digest = NULL;
	int rc = HTTPS_RC_OK;
	uint32_t iv_len = 0;
	EVP_CIPHER_CTX* c_cipher = NULL;
	EVP_CIPHER_CTX* s_cipher = NULL;
	int keyLen = 0;
	u_char keydata[SSL2_MAX_KEYBLOCK_LEN];

	if(keyArgLen > SSL2_KEYARG_MAX_LEN)
	{
		return DPI_ERROR(HTTPS_E_SSL_PROTOCOL_ERROR);
	}

	if( sess->c_dec.cipher_new != NULL )
	{
		_ASSERT( FALSE );
		EVP_CIPHER_CTX_cleanup( sess->c_dec.cipher_new );
		free( sess->c_dec.cipher_new );
		sess->c_dec.cipher_new = NULL;
	}

	if( sess->s_dec.cipher_new != NULL )
	{
		_ASSERT( FALSE );
		EVP_CIPHER_CTX_cleanup( sess->s_dec.cipher_new );
		free( sess->s_dec.cipher_new );
		sess->s_dec.cipher_new = NULL;
	}

	suite = HTTPS_GetSSL2CipherSuite( sess->cipher_suite );
	if( !suite ) return DPI_ERROR( HTTPS_E_SSL_CANNOT_DECRYPT );

	c = EVP_get_cipherbyname( suite->enc );
	if( c == NULL )
	{ 
		_ASSERT( FALSE );
		return DPI_ERROR( HTTPS_E_UNSPECIFIED_ERROR );
	}

	digest = EVP_get_digestbyname( suite->digest );

	iv_len = EVP_CIPHER_iv_length( c );
	if( iv_len && iv_len != keyArgLen )
	{
		return DPI_ERROR( HTTPS_E_SSL_PROTOCOL_ERROR );
	}

	keyLen = c->key_len;

	_ASSERT( keyLen*2 <= sizeof(keydata) );

	if( rc == HTTPS_RC_OK )
	{
		rc = ssl2_PRF( sess->master_secret, sess->master_key_len, sess->client_random, sess->client_challenge_len,
				sess->server_random, sess->server_connection_id_len, keydata, keyLen * 2 );
	}

	if( rc == HTTPS_RC_OK )
	{
		c_cipher = (EVP_CIPHER_CTX*) malloc( sizeof(EVP_CIPHER_CTX) );
		s_cipher = (EVP_CIPHER_CTX*) malloc( sizeof(EVP_CIPHER_CTX) );


		if( !c_cipher || !s_cipher ) 
		{
			rc = DPI_ERROR( HTTPS_E_OUT_OF_MEMORY );
		}

		EVP_CIPHER_CTX_init( c_cipher );
		EVP_CIPHER_CTX_init( s_cipher );
	}

	if( rc == HTTPS_RC_OK )
	{
		EVP_DecryptInit_ex( s_cipher, c, NULL, keydata, keyArg );
		EVP_DecryptInit_ex( c_cipher, c, NULL, keydata + keyLen, keyArg );

		sess->c_dec.cipher_new = c_cipher; c_cipher = NULL;
		sess->s_dec.cipher_new = s_cipher; s_cipher = NULL;

		sess->c_dec.md_new = digest;
		sess->s_dec.md_new = digest;
	}

	if( rc != HTTPS_RC_OK )
	{
		if( c_cipher ) { free( c_cipher ); c_cipher = NULL; }
		if( s_cipher ) { free( s_cipher ); s_cipher = NULL; }
	}

	if( rc == HTTPS_RC_OK)
	{
		memset(sess->ssl2_key_arg, 0, SSL2_KEYARG_MAX_LEN);
		memcpy(sess->ssl2_key_arg, keyArg, keyArgLen);
		sess->ssl2_key_arg_len = keyArgLen;
	}

	return rc;
}


int ssls_lookup_session( HTTPS_Session* sess )
{
	HTTPS_SessionKeyData* sess_data = NULL;

	_ASSERT( sess );
	_ASSERT( sess->env );
	
	if( sess->env->session_cache )
	{
		sess_data = https_SessionKT_Find( sess->env->session_cache, sess->session_id );
	}

	if( !sess_data ) return DPI_ERROR( HTTPS_E_SSL_SESSION_NOT_IN_CACHE );

	https_SessionKT_AddRef( sess_data );
	memcpy( sess->master_secret, sess_data->master_secret, SSL3_MASTER_SECRET_SIZE );
	sess->master_key_len = sess_data->master_secret_len;

	if(sess->version == SSL2_VERSION)
	{
		memcpy(sess->ssl2_key_arg, sess_data->ssl2_key_arg, SSL2_KEYARG_MAX_LEN );
		sess->ssl2_key_arg_len = sess_data->ssl2_key_arg_length;
		sess->cipher_suite = sess_data->ssl2_cipher_suite;
	}

	return HTTPS_RC_OK;
}

void ssls_store_session( HTTPS_Session* sess )
{
	HTTPS_SessionKeyData* sess_data = NULL;

	_ASSERT( sess );
	_ASSERT( sess->env );
	if( !sess->env->session_cache ) return;

	sess_data = https_SessionKT_Find( sess->env->session_cache, sess->session_id );

	if( sess_data )
	{
		memcpy( sess_data->master_secret, sess->master_secret, SSL3_MASTER_SECRET_SIZE );
		sess_data->master_secret_len = sess->master_key_len;
	}
	else
	{
		https_SessionKT_Add( sess->env->session_cache, sess );
	}
}

int ssls_get_decrypt_buffer( HTTPS_Session* sess, u_char** data, uint32_t len )
{
	if(!data || !len ) return DPI_ERROR( HTTPS_E_INVALID_PARAMETER );

	if( len > sizeof(sess->env->decrypt_buffer))
	{
		_ASSERT( FALSE );
		return DPI_ERROR( HTTPS_E_OUT_OF_MEMORY );
	}

	(*data) = sess->env->decrypt_buffer;
	return HTTPS_RC_OK;
}

int ssls_get_decompress_buffer( HTTPS_Session* sess, u_char** data, uint32_t len )
{
	if(!data || !len ) return DPI_ERROR( HTTPS_E_INVALID_PARAMETER );

	if( len > sizeof(sess->env->decompress_buffer))
	{
		_ASSERT( FALSE ); 
		return DPI_ERROR( HTTPS_E_OUT_OF_MEMORY );
	}

	(*data) = sess->env->decompress_buffer;
	return HTTPS_RC_OK;
}

EVP_PKEY* ssls_try_ssl_keys( HTTPS_Session* sess, u_char* data, uint32_t len)
{
	HTTPS_Env* env = NULL;
	int i = 0;
	EVP_PKEY *pk = NULL;
	u_char	pms_buff[1024];
	_ASSERT(sess);

	env = sess->env;
	_ASSERT(env);

	for(i = 0; i < env->key_count; i++)
	{
		int idx = (i + env->keys_try_index) % env->key_count;

		int pms_len = RSA_private_decrypt( len, data, pms_buff, 
				env->keys[idx]->pkey.rsa, RSA_PKCS1_PADDING );

		if( pms_len != -1 )
		{
			pk = env->keys[idx];
			break;
		}
	}

	++env->keys_try_index;
	if(env->keys_try_index >= env->key_count) env->keys_try_index = 0;

	return pk;

}

static EVP_PKEY* ssls_dup_PrivateRSA_ENV_PKEY( EVP_PKEY* src )
{
	EVP_PKEY* pDupKey = EVP_PKEY_new();
	RSA* pRSA = EVP_PKEY_get1_RSA(src);
	RSA* pRSADupKey = RSAPrivateKey_dup(pRSA);
	RSA_free(pRSA);
	EVP_PKEY_set1_RSA(pDupKey, pRSADupKey);
	RSA_free(pRSADupKey);
	return(pDupKey);
}


int ssls_register_ssl_key( HTTPS_Session* sess,EVP_PKEY* pk )
{
	struct in_addr server_ip = sess->last_packet->ip_header->ip_dst;
	uint16_t server_port = ntohs(sess->last_packet->tcp_header->th_dport);
	EVP_PKEY* dup_key = ssls_dup_PrivateRSA_ENV_PKEY( pk );
	int rc = HTTPS_RC_OK;

#if !defined(__APPLE__)
	_ASSERT( EVP_PKEY_cmp(pk, dup_key) == 1);
#endif

	rc = HTTPS_EnvSetServerInfoWithKey(sess->env, &server_ip, server_port, dup_key);
	if( rc == HTTPS_RC_OK)
	{
		sess->flags |= SSF_TEST_SSL_KEY; 
		sess->ssl_si = HTTPS_EnvFindServerInfo( sess->env, server_ip, server_port);
		_ASSERT(sess->ssl_si);
	}
	else
	{
		EVP_PKEY_free(dup_key);
		dup_key = NULL;
	}

	return rc;
}


void ssls_free_extension_data(HTTPS_Session* sess)
{
	_ASSERT(sess);

	sess->flags &= ~SSF_TLS_SESSION_TICKET_SET;
	if(sess->session_ticket) { 
		free(sess->session_ticket); 
	}
	sess->session_ticket = 0;
	sess->session_ticket_len = 0;
}


int ssls_init_from_tls_ticket( HTTPS_Session* sess )
{
	HTTPS_SessionTicketData* ticket_data = NULL;

	_ASSERT( sess );
	_ASSERT( sess->env );
	
	if( sess->env->ticket_cache )
	{
		ticket_data = https_SessionTicketTable_Find( sess->env->ticket_cache, 
			sess->session_ticket, sess->session_ticket_len );
	}

	if( !ticket_data ) return DPI_ERROR( HTTPS_E_SSL_SESSION_TICKET_NOT_CACHED );

	memcpy( sess->master_secret, ticket_data->master_secret, SSL3_MASTER_SECRET_SIZE );
	sess->master_key_len = SSL3_MASTER_SECRET_SIZE;

	sess->cipher_suite = ticket_data->cipher_suite;
	sess->version = ticket_data->protocol_version;
	sess->compression_method = ticket_data->compression_method;

	return HTTPS_RC_OK;
}

int ssls_store_new_ticket(HTTPS_Session* sess, u_char* ticket, uint32_t len)
{
	_ASSERT(sess && ticket && len);

	if( sess->env->ticket_cache )
	{
		return https_SessionTicketTable_Add( sess->env->ticket_cache, sess, ticket, len );
	}
	else
	{
		_ASSERT( FALSE );
		return DPI_ERROR( HTTPS_E_UNSPECIFIED_ERROR );
	}
}


/*111*/


https_SessionKeyTable* https_SessionKT_Create( int table_size, uint32_t timeout_int )
{
	https_SessionKeyTable* retval = NULL;

	if( table_size < 111 ) table_size = 111;

	retval = (https_SessionKeyTable*) malloc( sizeof( https_SessionKeyTable ) );
	if(! retval ) return NULL;

	memset(retval, 0, sizeof(*retval) );

	retval->timeout_interval = timeout_int;
	retval->last_cleanup_time = time( NULL );

	retval->table = (HTTPS_SessionKeyData**) malloc( sizeof(HTTPS_SessionKeyData*) * table_size );
	if( !retval->table )
	{
		free( retval );
		return NULL;
	}

	memset( retval->table, 0, sizeof(HTTPS_SessionKeyData*) * table_size );
	retval->table_size = table_size;
	retval->count = 0;

	return retval;
}


void https_SessionKT_Destroy( https_SessionKeyTable* tbl )
{
	https_SessionKT_RemoveAll( tbl );
	free( tbl->table );
	free( tbl );
}


static uint32_t GetSessionIDCache1( u_char* session_id )
{
	return fnv_32_buf( session_id, HTTPS_SESSION_ID_SIZE, FNV1_32_INIT );
}


HTTPS_SessionKeyData* https_SessionKT_Find( https_SessionKeyTable* tbl, u_char* session_id )
{
	HTTPS_SessionKeyData* key = NULL;
	uint32_t hash = 0;
	
	_ASSERT( session_id );
	_ASSERT( tbl );

	hash = GetSessionIDCache1( session_id ) % tbl->table_size;
	key = tbl->table[hash];

	while( key && memcmp( key->id, session_id, sizeof(key->id) ) != 0 ) key = key->next;

	return key;
}


static HTTPS_SessionKeyData* CreateSessionKeyData( HTTPS_Session* sess )
{
	HTTPS_SessionKeyData* new_data;

	_ASSERT( sess );

	new_data = (HTTPS_SessionKeyData*) malloc( sizeof(HTTPS_SessionKeyData) );
	if(!new_data) return NULL;

	_ASSERT_STATIC( sizeof(new_data->id) == sizeof(sess->session_id ) );
	memcpy( new_data->id, sess->session_id, sizeof(new_data->id) );

	_ASSERT_STATIC( sizeof(new_data->master_secret) == sizeof(sess->master_secret ) );
	memcpy( new_data->master_secret, sess->master_secret, sizeof(new_data->master_secret) );
	new_data->master_secret_len = sess->master_key_len;

	memcpy(new_data->ssl2_key_arg, sess->ssl2_key_arg, SSL2_KEYARG_MAX_LEN);
	new_data->ssl2_key_arg_length = sess->ssl2_key_arg_len;

	new_data->ssl2_cipher_suite = sess->cipher_suite;

	new_data->refcount = 1;
	new_data->next = NULL;
	new_data->released_time = 0;
	return new_data;
}


static void SessionKT_RemoveKey( https_SessionKeyTable* tbl, HTTPS_SessionKeyData** key )
{
	HTTPS_SessionKeyData* temp = (*key);
	(*key) = (*key)->next;
	
	free( temp );
	-- tbl->count;
}


void https_SessionKT_CleanSessionCache( https_SessionKeyTable* tbl )
{
	int i;
	time_t cur_time;
	
	_ASSERT( tbl );

	if( tbl->count == 0 ) return;

	cur_time = tbl->last_cleanup_time = time( NULL );

	for( i=0; i < tbl->table_size; ++i )
	{
		HTTPS_SessionKeyData** d = &tbl->table[i];
		while( *d )
		{
			if( (*d)->released_time != 0 && 
				cur_time - (*d)->released_time > tbl->timeout_interval )
			{
				SessionKT_RemoveKey( tbl, d );
			}
			else
			{
				d = &(*d)->next;
			}
		}
	}
}


void https_SessionKT_Add( https_SessionKeyTable* tbl, HTTPS_Session* sess )
{
	uint32_t hash;
	HTTPS_SessionKeyData* new_data;

	_ASSERT( tbl );
	_ASSERT( sess );

	if( tbl->timeout_interval != 0 && 
		time( NULL ) - tbl->last_cleanup_time > HTTPS_CACHE_CLEANUP_INTERVAL )
	{
		https_SessionKT_CleanSessionCache( tbl );
	}

	new_data = CreateSessionKeyData( sess );
	if( !new_data )
	{
		return;
	}

	hash = GetSessionIDCache1( new_data->id ) % tbl->table_size;
	new_data->next = tbl->table[hash];
	tbl->table[hash] = new_data;
	++ tbl->count;
}

void https_SessionKT_Remove( https_SessionKeyTable* tbl, u_char* session_id )
{
	uint32_t hash;
	HTTPS_SessionKeyData** s;
	_ASSERT( tbl ); _ASSERT( session_id );

	hash = GetSessionIDCache1( session_id ) % tbl->table_size;
	s = &tbl->table[hash];

	while( (*s) &&	memcmp((*s)->id, session_id, sizeof((*s)->id) ) != 0 )
	{
		s = &(*s)->next;
	}

	if( *s )
	{
		SessionKT_RemoveKey( tbl, s );
	}
}

void https_SessionKT_RemoveAll( https_SessionKeyTable* tbl )
{
	int i;
	for( i=0; i < tbl->table_size; ++i )
	{
		HTTPS_SessionKeyData* d = tbl->table[i];
		while( d )
		{
			HTTPS_SessionKeyData* dd = d;
			d = d->next;
			free( dd );
		}
	}

	memset( tbl->table, 0, sizeof(tbl->table[0])*tbl->table_size );
	tbl->count = 0;
}

void https_SessionKT_AddRef( HTTPS_SessionKeyData* sess_data )
{
	sess_data->refcount++;
}

void https_SessionKT_Release( https_SessionKeyTable* tbl, u_char* session_id )
{
	HTTPS_SessionKeyData* sess_data = https_SessionKT_Find( tbl, session_id );

	if( sess_data )
	{
		sess_data->refcount--;
		if(sess_data->refcount == 0 )
		{
			time( &sess_data->released_time );
		}
	}
}



/*111*/

int ssl3_PRF( const u_char* secret, uint32_t secret_len, 
		const u_char* random1, uint32_t random1_len,
		const u_char* random2, uint32_t random2_len,
		u_char* out, uint32_t out_len )
{
	MD5_CTX md5;
	SHA_CTX sha;
	u_char buf[20];
	uint32_t off;
	u_char i;

	if( !out ) return DPI_ERROR( HTTPS_E_INVALID_PARAMETER );

	for( off=0, i = 1; off < out_len; off+=16, ++i )
	{
		u_char md5_buf[16];
		uint32_t cnt;
		uint32_t j;

		MD5_Init(&md5);
		SHA1_Init(&sha);

		for( j=0; j < i; j++ ) buf[j]='A' + (i-1);

		SHA1_Update( &sha, buf, i );
		if( secret ) SHA1_Update( &sha, secret, secret_len );
		SHA1_Update( &sha, random1, random1_len );
		SHA1_Update( &sha, random2, random2_len );
		SHA1_Final( buf, &sha );

		MD5_Update( &md5, secret, secret_len );
		MD5_Update( &md5, buf, 20 );
		MD5_Final( md5_buf, &md5 );

		cnt = out_len - off < 16 ? out_len - off : 16;
		memcpy( out + off, md5_buf, cnt );
	}

	return HTTPS_RC_OK;
}


static void tls1_P_hash( const EVP_MD *md, const unsigned char *sec,
						int sec_len, unsigned char *seed, int seed_len,
						unsigned char *out, int olen)
{
	int chunk,n;
	unsigned int j;
	HMAC_CTX ctx;
	HMAC_CTX ctx_tmp;
	unsigned char A1[EVP_MAX_MD_SIZE];
	unsigned int A1_len;

	chunk=EVP_MD_size(md);

	HMAC_CTX_init(&ctx);
	HMAC_CTX_init(&ctx_tmp);
	HMAC_Init_ex(&ctx,sec,sec_len,md, NULL);
	HMAC_Init_ex(&ctx_tmp,sec,sec_len,md, NULL);
	HMAC_Update(&ctx,seed,seed_len);
	HMAC_Final(&ctx,A1,&A1_len);

	n=0;
	for (;;)
	{
		HMAC_Init_ex(&ctx,NULL,0,NULL,NULL); 
		HMAC_Init_ex(&ctx_tmp,NULL,0,NULL,NULL);
		HMAC_Update(&ctx,A1,A1_len);
		HMAC_Update(&ctx_tmp,A1,A1_len);
		HMAC_Update(&ctx,seed,seed_len);

		if (olen > chunk)
		{
			HMAC_Final(&ctx,out,&j);
			out+=j;
			olen-=j;
			HMAC_Final(&ctx_tmp,A1,&A1_len); 
		}
		else	
		{
			HMAC_Final(&ctx,A1,&A1_len);
			memcpy(out,A1,olen);
			break;
		}
	}
	HMAC_CTX_cleanup(&ctx);
	HMAC_CTX_cleanup(&ctx_tmp);
	OPENSSL_cleanse(A1,sizeof(A1));
}

int tls1_PRF( const u_char* secret, uint32_t secret_len, const char* label, 
		u_char* random1, uint32_t random1_len, u_char* random2, uint32_t random2_len,
		u_char *out, uint32_t out_len )
{
	uint32_t len;
	uint32_t i;
	const u_char *S1,*S2;
	u_char* out_tmp;
	u_char* seed;
	uint32_t seed_len;
	u_char* p;

	if( !label || !out || out_len == 0 ) { _ASSERT( FALSE); return DPI_ERROR( HTTPS_E_INVALID_PARAMETER ); }

	out_tmp = (u_char*) malloc( out_len );
	if( !out_tmp ) return DPI_ERROR( HTTPS_E_OUT_OF_MEMORY );

	seed_len = (uint32_t)strlen( label ) + random1_len + random2_len;
	seed = (u_char*) malloc( seed_len );
	if( !seed ) 
	{
		free( out_tmp );
		return DPI_ERROR( HTTPS_E_OUT_OF_MEMORY );
	}

	p = seed;
	memcpy( p, label, strlen( label ) ); p+= strlen( label );
	memcpy( p, random1, random1_len ); p+= random1_len;
	memcpy( p, random2, random2_len );

	len = (secret_len / 2) + (secret_len % 2);
	S1 = secret;
	S2 = secret + secret_len - len;

	tls1_P_hash( EVP_md5(), S1, len, seed, seed_len, out, out_len );
	tls1_P_hash( EVP_sha1(), S2, len, seed, seed_len, out_tmp, out_len );

	for( i=0; i < out_len; i++ ) out[i] ^= out_tmp[i];

	free( seed );
	free( out_tmp );

	return HTTPS_RC_OK;
}


int ssl2_PRF( const u_char* secret, uint32_t secret_len,
		const u_char* challenge, uint32_t challenge_len, 
		const u_char* conn_id, uint32_t conn_id_len,
		u_char* out, uint32_t out_len )
{
	u_char c= '0';
	int repeat = 0;
	int i = 0;
	const EVP_MD *md5 = NULL;
	EVP_MD_CTX ctx;

	md5 = EVP_md5();

	if( !out ) return DPI_ERROR( HTTPS_E_INVALID_PARAMETER );
	if( out_len % EVP_MD_size(md5) != 0 ) { return DPI_ERROR( HTTPS_E_INVALID_PARAMETER ); }

	repeat = out_len / EVP_MD_size(md5);
	EVP_MD_CTX_init( &ctx );
	for( i = 0; i < repeat; i++ )
	{
		EVP_DigestInit_ex( &ctx, md5, NULL );
		EVP_DigestUpdate( &ctx, secret, secret_len );
		EVP_DigestUpdate( &ctx, &c, 1);
		c++; 
		EVP_DigestUpdate( &ctx, challenge, challenge_len );
		EVP_DigestUpdate( &ctx, conn_id, conn_id_len );
		EVP_DigestFinal_ex( &ctx, out, NULL );
		out += EVP_MD_size( md5 );
	}

	EVP_MD_CTX_cleanup( &ctx );
	return HTTPS_RC_OK;
}

/*111*/

#define STREAM_PKT_NOT_ACKED( pkt ) ((pkt)->ack_time.tv_sec == 0 && (pkt)->ack_time.tv_usec == 0)

TcpStream* StreamGetPeer( const TcpStream* stream );
static int IsNextPacket( const TcpStream* stream, const HTTPS_Pkt* pkt );
static void StreamDiscardHead(TcpStream* stream);

static void CountPktIn( TcpStream* stream, const HTTPS_Pkt* pkt)
{
	_ASSERT(stream);
	_ASSERT(pkt);
	++stream->queue_size;

	if( stream->session && stream->session->env )
	{
		https_SessionTable* tbl = stream->session->env->sessions;
		_ASSERT(tbl);
		++tbl->packet_cache_count;
		tbl->packet_cache_mem += pkt->data_len;
#ifdef DPI_TRACE_MEMORY_USAGE
		DEBUG_TRACE2("\n:: ++ %d bytes, %ld now", pkt->data_len, tbl->packet_cache_mem);
#endif
	}
}

static void CountPktOut(TcpStream* stream, const HTTPS_Pkt* pkt)
{
	_ASSERT(stream);
	_ASSERT(pkt);
	--stream->queue_size;

	if( stream->session && stream->session->env )
	{
		https_SessionTable* tbl = stream->session->env->sessions;
		_ASSERT(tbl);
		--tbl->packet_cache_count;
		tbl->packet_cache_mem -= pkt->data_len;
#ifdef DPI_TRACE_MEMORY_USAGE
		DEBUG_TRACE2("\n:: -- %d bytes, %ld left", pkt->data_len, tbl->packet_cache_mem);
#endif
	}
}

#ifdef DPI_TRACE_TCP_STREAMS

static const char* StreamToString( const TcpStream* str )
{
	static char buff[512];
	char addr1[32], addr2[32];

	addr1[0] = 0;
	addr2[0] = 0;

	AddressToString( str->ip_addr, str->port, addr1 );
	AddressToString( StreamGetPeer(str)->ip_addr, StreamGetPeer(str)->port, addr2 );

	sprintf( buff, "%s->%s", addr1, addr2 );

	return buff;
}
#endif

void StreamInit( TcpStream* stream, TcpSession* sess, uint32_t ip, uint16_t port )
{
	_ASSERT( stream );

	memset(stream, 0, sizeof(*stream) );

	stream->ip_addr = ip;
	stream->port = port;
	stream->pktHead = NULL;
	stream->pktTail = NULL;
	stream->nextSeqExpected = 0;
	stream->session = sess;
	stream->queue_size = 0;
}

static int StreamGetPacketCount( TcpStream* stream )
{
	int cnt = 0;
	HTTPS_Pkt* pkt = stream->pktHead;

	while( pkt )
	{
		cnt++;
		pkt = pkt->next;
	}

	return cnt;
}


void StreamFreeData( TcpStream* stream )
{
	HTTPS_Pkt* pkt = stream->pktHead;

#ifdef DPI_TRACE_TCP_STREAMS
	DEBUG_TRACE2( "\nFreeStreamData: stream %s; %d packets freed",
		StreamToString(stream), StreamGetPacketCount( stream ) );
#endif

	while( pkt ) 
	{
		HTTPS_Pkt* t = pkt->next;
		CountPktOut(stream, pkt);
		PktFree( pkt );
		pkt = t;
	}

	stream->pktTail = stream->pktHead = NULL;
	stream->nextSeqExpected = 0;
	_ASSERT(stream->queue_size == 0);
}


static void StreamInsertAfter( TcpStream* stream, HTTPS_Pkt* pktInsert, HTTPS_Pkt* pktAfter )
{
	if( pktAfter->next && PKT_TCP_SEQ(pktAfter->next) < PktNextTcpSeqExpected(pktInsert) )
	{
#ifdef DPI_TRACE_TCP_STREAMS
		DEBUG_TRACE3( "\n%s: Overlapping packet seq:%u, len %d", StreamToString(stream), 
			PKT_TCP_SEQ( pktInsert ) - stream->initial_seq, pktInsert->data_len );
		DEBUG_TRACE2( " between seq:%u, len %d", PKT_TCP_SEQ(pktAfter)- stream->initial_seq, pktAfter->data_len );
		DEBUG_TRACE2( " and seq:%u, len %d", PKT_TCP_SEQ(pktAfter->next)- stream->initial_seq, pktAfter->next->data_len );
#endif
		return;
	}

	pktInsert = PktClone( pktInsert );

#ifdef DPI_TRACE_TCP_STREAMS
	{
		uint32_t seq = PKT_TCP_SEQ( pktInsert );
		uint32_t seq_after = PKT_TCP_SEQ( pktAfter );
		DEBUG_TRACE3( "\n%s: Insert seq:%u  after: %u", StreamToString(stream), (unsigned int) seq - stream->initial_seq, 
			(unsigned int) seq_after - stream->initial_seq);
		DEBUG_TRACE1( " q size=%u", stream->queue_size);
	}
#endif

	pktInsert->prev = pktAfter;
	pktInsert->next = pktAfter->next;
	pktAfter->next = pktInsert;

	if( pktInsert->next ) { pktInsert->next->prev = pktInsert; }
	if( pktAfter == stream->pktTail ) { stream->pktTail = pktInsert; }
	CountPktIn(stream, pktInsert);
}


static void StreamInsertBefore( TcpStream* stream, HTTPS_Pkt* pktInsert, HTTPS_Pkt* pktBefore )
{
	_ASSERT( pktBefore && pktInsert && stream );

	if(pktBefore->prev && PktNextTcpSeqExpected(pktBefore->prev) > PKT_TCP_SEQ(pktInsert) )
	{
#ifdef DPI_TRACE_TCP_STREAMS
		DEBUG_TRACE3( "\n%s: Overlapping packet seq:%u, len %d", StreamToString(stream), 
			PKT_TCP_SEQ( pktInsert ) - stream->initial_seq, pktInsert->data_len );
		DEBUG_TRACE2( " between seq:%u, len %d", PKT_TCP_SEQ(pktBefore->prev)- stream->initial_seq, pktBefore->prev->data_len );
		DEBUG_TRACE2( " and seq:%u, len %d", PKT_TCP_SEQ(pktBefore)- stream->initial_seq, pktBefore->data_len );
#endif
		return;
	}

	pktInsert = PktClone( pktInsert );

#ifdef DPI_TRACE_TCP_STREAMS
	{
		uint32_t seq = PKT_TCP_SEQ( pktInsert );
		uint32_t seq_before = PKT_TCP_SEQ( pktBefore );
		DEBUG_TRACE3( "\n%s: Insert seq:%u  before: %u", StreamToString(stream),
			(unsigned int)seq- stream->initial_seq,
			(unsigned int)seq_before - stream->initial_seq);
		DEBUG_TRACE1( " q size=%u", stream->queue_size);
	}
#endif

	pktInsert->prev = pktBefore->prev;

	if( pktBefore->prev )
	{
		_ASSERT( pktBefore->prev->next == pktBefore );
		pktBefore->prev->next = pktInsert;
	}
	else
	{
		_ASSERT( pktBefore == stream->pktHead );
		stream->pktHead = pktInsert;
	}

	pktBefore->prev = pktInsert;
	pktInsert->next = pktBefore;

	CountPktIn(stream, pktInsert);
}


TcpStream* StreamGetPeer( const TcpStream* stream )
{
	if( stream == &stream->session->clientStream)
		return &stream->session->serverStream;
	else if( stream == &stream->session->serverStream )
		return &stream->session->clientStream;
	else
	{
		_ASSERT(0);
		return NULL;
	}
}

int FindPacketAckTime( const TcpStream* stream, HTTPS_Pkt* pkt)
{
		uint32_t pkt_seq = PktNextTcpSeqExpected(pkt);
	TcpStream* peer_stream = StreamGetPeer( stream );
	if( !peer_stream || !(peer_stream->flags & HTTPS_TCPSTREAM_SENT_SYN) ) return 0;

	if( pkt->data_len != 0 && STREAM_PKT_NOT_ACKED(pkt) )
	{
		TcpStream* peer = StreamGetPeer(stream);
		int i = 0;

		_ASSERT(peer);
		for(i = 0; i < HTTPS_ACK_TIME_BUFFER_SIZE; ++i)
		{
			int idx = ( peer->ack_idx + i ) % HTTPS_ACK_TIME_BUFFER_SIZE;
			if( peer->acks[idx].seq >= pkt_seq )
			{
				pkt->ack_time = peer->acks[idx].ack_time;
				return 1;
			}
		}
	}

	if( pkt->data_len != 0 && STREAM_PKT_NOT_ACKED(pkt) )
	{
		TcpStream* peer = StreamGetPeer(stream);
		HTTPS_Pkt* peer_pkt = peer->pktHead;

		while( peer_pkt )
		{
			if( PKT_TCP_ACK( peer_pkt ) >= pkt_seq )
			{
				pkt->ack_time = peer_pkt->pcap_header.ts;
				return 1;
			}

			peer_pkt = peer_pkt->next;
		}
	}

	return 0;
}

static int GetAcknowledgingPacketIndex( const HTTPS_Pkt* queue_head, uint32_t seq)
{
	int ack_idx = -1;
	int idx = 0;
	const HTTPS_Pkt* pkt = queue_head;
	while( pkt && ack_idx == -1) {
		if(PKT_HAS_TCP_ACK(pkt)) {
			if(PKT_TCP_ACK(pkt) >= seq) 
				ack_idx = idx;
		}
		pkt = pkt->next;
		idx++;
	}

	return ack_idx;
}

static int IsDeadlocked( const TcpStream* stream )
{
	//return 0;
	const TcpStream* peer = NULL;
	if(!stream) {
		_ASSERT(stream != NULL);
		return 0;
	}

	peer = StreamGetPeer( stream );
	if( peer == NULL) {
		_ASSERT( peer != NULL );
		return 0;
	}

	if(peer->queue_size < 2 || stream->queue_size < 2) 
		return 0;

	if(peer->nextSeqExpected != PKT_TCP_SEQ(peer->pktHead) || stream->nextSeqExpected != PKT_TCP_SEQ(stream->pktHead) )
		return 0;

	if(IsNextPacket(peer, peer->pktHead))
		return 0;

	return GetAcknowledgingPacketIndex(peer->pktHead, PktNextTcpSeqExpected(stream->pktHead)) > 0 &&
		GetAcknowledgingPacketIndex(stream->pktHead, PktNextTcpSeqExpected(peer->pktHead)) > 0 &&
		PktCompareTimes(stream->pktHead, peer->pktHead) < 0;
}

int IsPacketAcknowledged( const TcpStream* stream, const HTTPS_Pkt* pkt )
{
	TcpStream* peer_stream = StreamGetPeer( stream );
	_ASSERT(peer_stream);

	if(PktNextTcpSeqExpected(pkt) <= peer_stream->lastPacketAck)
		return 1;

	if( peer_stream->pktHead )
	{
		int acked = PKT_TCP_ACK(peer_stream->pktHead) >= PktNextTcpSeqExpected(pkt);
		return acked && PktCompareTimes( pkt, peer_stream->pktHead ) < 0;
	}
	return 0;
}

static int IsNextPacket( const TcpStream* stream, const HTTPS_Pkt* pkt )
{
	uint32_t seq = PKT_TCP_SEQ( pkt );
	TcpStream* peer_stream = StreamGetPeer( stream );
	
	if( !peer_stream || !(peer_stream->flags & HTTPS_TCPSTREAM_SENT_SYN) ) return 0;
	if( (stream->nextSeqExpected == seq ) && IsPacketAcknowledged(stream, pkt) )
	{
		if( PKT_HAS_TCP_ACK(pkt) && pkt->data_len != 0 )
		{
			uint32_t ack = PKT_TCP_ACK(pkt);
			if( ack <= peer_stream->nextSeqExpected )
				return 1;
			else
				return 0;
		}
		else
			return 1;
	}
	else
	{
		return 0;
	}
}

#define PREPROC_ACTION_CLOSE			1

static uint32_t PreProcessPacket( HTTPS_Pkt* pkt )
{
	int dir;
	TcpStream* sender, *receiver;
	int th_flags;
	uint32_t th_seq;
	TcpSession* sess = pkt->session;

	dir = SessionGetPacketDirection( sess, pkt );
	if( dir == ePktDirInvalid ) {
		_ASSERT( dir != ePktDirInvalid );
		return PREPROC_ACTION_CLOSE;
	}

	if( dir == ePktDirFromClient ) {
		sender = &sess->clientStream;
		receiver = &sess->serverStream;
	} else if( dir == ePktDirFromServer ) {
		sender = &sess->serverStream;
		receiver = &sess->clientStream;
	} else {
		_ASSERT( FALSE );
		return PREPROC_ACTION_CLOSE;
	}

	th_flags = pkt->tcp_header->th_flags;
	th_seq = ntohl( pkt->tcp_header->th_seq );

	if( th_flags & TH_RST ) {
		sender->flags |= HTTPS_TCPSTREAM_SENT_RST; 
		return PREPROC_ACTION_CLOSE;
	}

	if( th_flags & TH_SYN ) { 
		sender->flags |= HTTPS_TCPSTREAM_SENT_SYN; 
	}
	if( th_flags & TH_FIN ) {
		sender->flags |= HTTPS_TCPSTREAM_SENT_FIN;
	}
	if( (sender->flags & HTTPS_TCPSTREAM_SENT_FIN) && (receiver->flags & HTTPS_TCPSTREAM_SENT_FIN) ) {
		return PREPROC_ACTION_CLOSE;
	}

	return 0;
}

static void StreamUpdateACK( TcpStream* stream, uint32_t new_ack, struct timeval* ack_time )
{
	TcpStream* peer = StreamGetPeer( stream );
	stream->lastPacketAck = new_ack;
	_ASSERT(ack_time);

	stream->acks[stream->ack_idx].seq = new_ack;
	stream->acks[stream->ack_idx].ack_time = (*ack_time);
	++ stream->ack_idx; if( stream->ack_idx == HTTPS_ACK_TIME_BUFFER_SIZE ) stream->ack_idx = 0;

	if(peer && (peer->flags & HTTPS_TCPSTREAM_SENT_SYN) && peer->initial_seq + 1 == new_ack)
	{
		peer->first_ack_time = *ack_time;
#ifdef DPI_TRACE_TCP_STREAMS
		DEBUG_TRACE3( "\n%s: Stream's first ACK time set: %ld:%ld", StreamToString(peer), 
			ack_time->tv_sec, ack_time->tv_usec );
#endif
	}

	if( peer ) 
	{
		HTTPS_Pkt* pkt = peer->pktHead;
		while( pkt )
		{
			if( PktNextTcpSeqExpected(pkt) <= new_ack )
			{
				if(pkt->ack_time.tv_sec == 0  && pkt->ack_time.tv_usec == 0)
					pkt->ack_time = *ack_time;
				if(PktNextTcpSeqExpected(pkt) == new_ack)
					pkt->flags |= HTTPS_PKT_ACK_MATCH; 
			}
			else
			{
				break;
			}
			pkt = pkt->next;
		}
	}
}

static int StreamConsumePacket( TcpStream* stream, HTTPS_Pkt* pkt, int* new_ack )
{	
#ifdef DPI_TRACE_TCP_STREAMS
		DEBUG_TRACE3( "\n%s: Consuming seq:%u, len: %d", StreamToString(stream), 
			PKT_TCP_SEQ( pkt )- stream->initial_seq, pkt->data_len );
		DEBUG_TRACE2( " q size=%u ack=%u", stream->queue_size, (uint32_t)PKT_TCP_ACK(pkt) - StreamGetPeer(stream)->initial_seq);
#endif
	_ASSERT( new_ack );

	if( PreProcessPacket(pkt) == PREPROC_ACTION_CLOSE)
	{
		stream->session->closing = 1;
	}

	if( pkt->data_len != 0 && STREAM_PKT_NOT_ACKED(pkt) )
	{
		FindPacketAckTime( stream, pkt );
	}

#ifdef DPI_TRACE_TCP_STREAMS
	if( pkt->data_len != 0 && STREAM_PKT_NOT_ACKED(pkt))
	{
		DEBUG_TRACE0(" not acked ");
	}
#endif

	if( pkt->data_len )
	{
		++ stream->stats.data_pkt_count;
	}
	else if( PKT_HAS_TCP_ACK(pkt) ) 
	{
		++ stream->stats.ack_pkt_count;
	}

	stream->nextSeqExpected = PktNextTcpSeqExpected(pkt);
	stream->session->packet_time = pkt->pcap_header.ts;
	if( PKT_HAS_TCP_ACK(pkt) ) 
	{
		uint32_t pkt_ack = PKT_TCP_ACK(pkt);
		if( stream->lastPacketAck != pkt_ack ) 
		{ 
			(*new_ack) = 1;
		}
		if(stream->lastPacketAck < pkt_ack ) 
		{ 
			StreamUpdateACK(stream, pkt_ack, &pkt->pcap_header.ts);
		}
#ifdef DPI_TRACE_TCP_STREAMS
		else if(stream->lastPacketAck > pkt_ack)
		{
			DEBUG_TRACE2( " ===> OLD ACK %u, already know: %u", PKT_TCP_ACK(pkt) - StreamGetPeer(stream)->initial_seq,
				stream->lastPacketAck - StreamGetPeer(stream)->initial_seq);
		}
#endif
	}

#ifdef DPI_TRACE_TCP_STREAMS
	if( *new_ack ) { DEBUG_TRACE0( " New ACK" ); }
#endif

	if( pkt->data_len )
	{
		return stream->session->OnNewPacket( stream, pkt );
	}
	else
	{
		return HTTPS_RC_OK;
	}
}

static int StreamEnqueue( TcpStream* stream, HTTPS_Pkt* pkt )
{
	HTTPS_Pkt* p = NULL;
	uint32_t seq = PKT_TCP_SEQ( pkt );
	int processed = 0;

	if( stream->queue_size + 1 >= HTTPS_STREAM_MAX_REASSEMBLY_DEPTH )
	{
#ifdef DPI_TRACE_TCP_STREAMS
		DEBUG_TRACE1( "\n%s: Error: reassembly queue limit reached, dropping the session", StreamToString(stream));
#endif
		return DPI_ERROR( HTTPS_E_TCP_REASSEMBLY_QUEUE_FULL );
	}

	if( stream->session && stream->session->env)
	{
		https_SessionTable* tbl = stream->session->env->sessions;
		_ASSERT(tbl);
		if( tbl->maxCachedPacketCount > 0 && tbl->packet_cache_count >= tbl->maxCachedPacketCount)
		{
			return DPI_ERROR( HTTPS_E_TCP_GLOBAL_REASSEMBLY_QUEUE_LIMIT );
		}
	}

	if( seq < stream->nextSeqExpected )
	{
		++ stream->stats.retrans_pkt_count;
#ifdef DPI_TRACE_TCP_STREAMS
		DEBUG_TRACE3( "\n%s: Dropping a packet (retransmission), seq:%u, next_seq: %u",
			StreamToString(stream), seq- stream->initial_seq, stream->nextSeqExpected - stream->initial_seq);
		DEBUG_TRACE1( " q size=%u", stream->queue_size);
#endif
		return HTTPS_RC_OK;
	}

	if( seq == stream->nextSeqExpected && stream->lastPacketAck < PKT_TCP_ACK(pkt))
	{
		stream->lastPacketAck = PKT_TCP_ACK(pkt);
	}

	if( stream->pktHead == NULL )
	{
#ifdef DPI_TRACE_TCP_STREAMS
		DEBUG_TRACE2( "\n%s: Adding the head at seq:%u", StreamToString(stream), seq - stream->initial_seq);
#endif
		_ASSERT( stream->pktTail == NULL);
		
		p = PktClone( pkt );
		p->next = p->prev = NULL;
		stream->pktHead = stream->pktTail = p;
		processed = 1;
		_ASSERT( !stream->queue_size ); 
		CountPktIn(stream, p);
	}
	else if( seq == PktNextTcpSeqExpected( stream->pktTail ) )
	{
#ifdef DPI_TRACE_TCP_STREAMS
		DEBUG_TRACE2( "\n%s: Adding to the tail at seq:%u", StreamToString(stream), seq - stream->initial_seq);
		DEBUG_TRACE1( " q size=%u", stream->queue_size);
#endif
		StreamInsertAfter( stream, pkt, stream->pktTail );
		processed = 1;
	}
	else
	{
		p = stream->pktHead;
		while( p && !processed )
		{
			uint32_t seq_p = PKT_TCP_SEQ( p );
			if( seq_p == seq )
			{
				if( p->data_len != 0 )
				{
				#ifdef DPI_TRACE_TCP_STREAMS
					DEBUG_TRACE3( "\n%s: Dropping retransmission, seq:%u, len: %d", 
						StreamToString(stream), seq - stream->initial_seq, (int) pkt->data_len );
					DEBUG_TRACE1( " q size=%u", stream->queue_size);
				#endif
					++ stream->stats.retrans_pkt_count;
				}
				else
				{
					StreamInsertAfter( stream, pkt, p );
				}
				processed = 1;
			}
			else if( seq_p > seq )
			{
				StreamInsertBefore( stream, pkt, p );
				processed = 1;
			}
			else
			{
				p = p->next;
			}
		}

		if( !processed )
		{
			StreamInsertAfter( stream, pkt, stream->pktTail );
			processed = 1;
		}
	}

	_ASSERT( processed );
	return HTTPS_RC_OK;
}


static HTTPS_Pkt* StreamDequeue( TcpStream* stream )
{
	HTTPS_Pkt* retval = stream->pktHead;
	
	if( stream->pktHead ) { stream->pktHead = stream->pktHead->next; }
	if( stream->pktHead ) {
		stream->pktHead->prev = NULL;
	} else {
		stream->pktTail = NULL;
	}


	if(retval) 
	{
		_ASSERT( stream->queue_size ); 
		CountPktOut(stream, retval);
	}
	else
	{
		_ASSERT( !stream->queue_size ); 
	}

	return retval;
}


static DPI_PacketDir StreamGetPacketDirection( TcpStream* stream )
{
	if( stream == &stream->session->clientStream )
		return ePktDirFromClient;
	else if( stream == &stream->session->serverStream )
		return ePktDirFromServer;
	else {
		_ASSERT( FALSE );
		return ePktDirInvalid;
	}
}


int StreamHasMissingPacket(TcpStream* stream, HTTPS_Pkt* pkt)
{
	TcpSession* s = stream->session;
	_ASSERT(s);

	if(s->type != eSessTypeTcp || s->missing_callback == NULL ) return 0;
	if( stream->pktHead == NULL || PKT_TCP_SEQ(stream->pktHead) == stream->nextSeqExpected) return 0;
	if( s->missing_packet_count && stream->queue_size >= s->missing_packet_count ) 
		return 1;

	if( s->missing_packet_timeout && pkt->pcap_header.ts.tv_sec - stream->pktHead->pcap_header.ts.tv_sec 
			> s->missing_packet_timeout )
		return 1;

	return 0;
}


int StreamConsumeHeadOverlap( TcpStream* stream, int* new_ack, int data_to_proc )
{
	int rc = HTTPS_RC_OK;
	HTTPS_Pkt* p = NULL;
	HTTPS_Pkt* pClone = NULL;
	
	if(data_to_proc > 65535) {
		return DPI_ERROR(HTTPS_E_INVALID_PARAMETER);
	}

	p = StreamDequeue( stream );

#ifdef DPI_TRACE_TCP_STREAMS
	DEBUG_TRACE4( "\n  %s:Processing the last %d bytes from a packet seq:%u", StreamToString(stream), 
		data_to_proc, PKT_TCP_SEQ( p )- stream->initial_seq, p->data_len );
#endif

	rc = PktCloneChunk(p, data_to_proc, &pClone);
	if(rc != HTTPS_RC_OK) return rc;

	PktFree(p); p = NULL;
	if(pClone == NULL) {
		return DPI_ERROR(HTTPS_E_OUT_OF_MEMORY);
	}

	rc = StreamConsumePacket( stream, pClone, new_ack );
	PktFree(pClone);
	return rc;
}

int StreamConsumeHead( TcpStream* stream, int* new_ack )
{
	int rc = HTTPS_RC_OK;
	HTTPS_Pkt* p = StreamDequeue( stream );

#ifdef DPI_TRACE_TCP_STREAMS
	DEBUG_TRACE3( "\n  %s:Processing a packet seq:%u, len: %d", StreamToString(stream), 
		PKT_TCP_SEQ( p )- stream->initial_seq, p->data_len );
#endif

	rc = StreamConsumePacket( stream, p, new_ack );

	PktFree(p); 
	return rc;
}

int StreamProcessPacket( TcpStream* stream, HTTPS_Pkt* pkt, int* new_ack )
{
	int rc = HTTPS_RC_OK;
	
	if( pkt->tcp_header->th_flags & TH_SYN )
	{
		_ASSERT( stream->initial_seq == 0 || stream->initial_seq == PKT_TCP_SEQ(pkt));
		_ASSERT( pkt->data_len == 0 );
		stream->initial_seq = PKT_TCP_SEQ(pkt);
		stream->syn_time = pkt->pcap_header.ts;

		// check if this is SYN+ACK packet and SYN packet was missing
		if(pkt->tcp_header->th_flags & TH_ACK && StreamGetPeer(stream))
		{
			TcpStream* peer = StreamGetPeer(stream);
			if(peer->initial_seq == 0 && !(peer->flags & HTTPS_TCPSTREAM_SENT_SYN))
			{
				#ifdef DPI_TRACE_TCP_STREAMS
					DEBUG_TRACE1("\n%s: missing or out-of-order SYN detected", StreamToString(peer));
				#endif
				peer->initial_seq = PKT_TCP_ACK(pkt);
				peer->nextSeqExpected = peer->initial_seq;
				peer->flags |= HTTPS_TCPSTREAM_SENT_SYN;
			}
		}
		return StreamConsumePacket( stream, pkt, new_ack );
	}

	if(stream->initial_seq == 0)
	{
		const TcpStream* peer = StreamGetPeer( stream );
		if(peer && (peer->flags & HTTPS_TCPSTREAM_SENT_SYN) && peer->pktHead)
		{
			HTTPS_Pkt* ph = peer->pktHead;
			_ASSERT( PKT_TCP_SEQ(ph) == peer->initial_seq + 1 ); 
		#ifdef DPI_TRACE_TCP_STREAMS
			DEBUG_TRACE1("\n%s: missing SYN+ACK detected", StreamToString(stream));
		#endif
			stream->initial_seq = PKT_TCP_ACK(ph);
			stream->nextSeqExpected = stream->initial_seq;
			stream->flags |= HTTPS_TCPSTREAM_SENT_SYN;
		}
	}

	if( IsNextPacket( stream, pkt ) )
	{
		rc = StreamConsumePacket( stream, pkt, new_ack );
	}
	else
	{
		_ASSERT( !(pkt->tcp_header->th_flags & TH_SYN) );
		rc = StreamEnqueue( stream, pkt );

		if( rc == HTTPS_RC_OK && StreamHasMissingPacket(stream, pkt) )
		{
			uint32_t len = 0; int retcode = 0;
			_ASSERT( stream->pktHead );

			if (PKT_TCP_SEQ( stream->pktHead ) > stream->nextSeqExpected) {
				len = PKT_TCP_SEQ( stream->pktHead ) - stream->nextSeqExpected;
				
				#ifdef DPI_TRACE_TCP_STREAMS
				DEBUG_TRACE3("\n%s: missing packet found at seq: %u, len = %u", StreamToString(stream), 
					PKT_TCP_SEQ(stream->pktHead), len );
				#endif
				
				retcode = stream->session->missing_callback( StreamGetPacketDirection(stream),
					stream->session->user_data, PKT_TCP_SEQ( stream->pktHead ), len );
				if( retcode ) {
					rc = StreamConsumeHead( stream, new_ack );
				} else {
					rc = DPI_ERROR( HTTPS_E_TCP_MISSING_PACKET_DETECTED );
				}
			} else {
				int headNextSeq = PktNextTcpSeqExpected(stream->pktHead);

				if(headNextSeq <= (int)stream->nextSeqExpected) {
					StreamDiscardHead(stream);
				} else {
					int dataToProc = PKT_TCP_SEQ(stream->pktHead) + 
						stream->pktHead->data_len - stream->nextSeqExpected;
					if(dataToProc > 0) {
						rc = StreamConsumeHeadOverlap(stream, new_ack, dataToProc);
					}
				}
			}
		}
	}

	if( rc == HTTPS_RC_OK ) rc = StreamPollPackets( stream, new_ack );

	return rc;
}

int StreamPollPackets( TcpStream* stream, int* new_ack )
{
	int rc = HTTPS_RC_OK;
	int hit = 0;
	while( rc == HTTPS_RC_OK && stream->pktHead && IsNextPacket( stream, stream->pktHead ) )
	{
		rc = StreamConsumeHead( stream, new_ack );
#ifdef DPI_TRACE_TCP_STREAMS
		hit = 1;
#endif
	}

#ifdef DPI_TRACE_TCP_STREAMS
	{
		uint32_t headSeq = stream->pktHead ? PKT_TCP_SEQ( stream->pktHead ) : stream->initial_seq;
		uint32_t peerInitSec = StreamGetPeer(stream)->initial_seq;
		uint32_t headAck = stream->pktHead ? PKT_TCP_ACK( stream->pktHead ) - peerInitSec : 0;
		if(!hit)  DEBUG_TRACE1("\n	 %s no packets dequeued", StreamToString(stream));
		DEBUG_TRACE3( "|| Next seq: %u, head: (s:%u ack:%u)", stream->nextSeqExpected - stream->initial_seq, 
			headSeq - stream->initial_seq, headAck);
	}
#endif
	
	if(rc == HTTPS_RC_OK && !hit && IsDeadlocked(stream)) {
#ifdef DPI_TRACE_TCP_STREAMS
		DEBUG_TRACE1("\n %s - deadlock detected, processing the front of the queue", StreamToString(stream) );
#endif
		rc = StreamConsumeHead(stream, new_ack );
	}

	return rc;
}

static void StreamDiscardHead(TcpStream* stream)
{
	HTTPS_Pkt* p = StreamDequeue( stream );

#ifdef DPI_TRACE_TCP_STREAMS
	DEBUG_TRACE3( "\n  %s:Dumping a packet seq:%u, len: %d", StreamToString(stream), 
		PKT_TCP_SEQ( p )- stream->initial_seq, p->data_len );
#endif


	PktFree(p); 
}

/*111*/

HTTPS_SessionTicketTable* https_SessionTicketTable_Create( int table_size, uint32_t timeout_int )
{
	HTTPS_SessionTicketTable* retval = NULL;

	if( table_size < 111 ) table_size = 111;

	retval = (HTTPS_SessionTicketTable*) malloc( sizeof( HTTPS_SessionTicketTable ) );
	if(! retval ) return NULL;

	memset(retval, 0, sizeof(*retval) );

	retval->timeout_interval = timeout_int;
	retval->last_cleanup_time = time( NULL );

	retval->table = (HTTPS_SessionTicketData**) malloc( sizeof(HTTPS_SessionTicketData*) * table_size );
	if( !retval->table )
	{
		free( retval );
		return NULL;
	}

	memset( retval->table, 0, sizeof(HTTPS_SessionTicketData*) * table_size );
	retval->table_size = table_size;
	retval->count = 0;

	return retval;
}


void https_SessionTicketTable_Destroy( HTTPS_SessionTicketTable* tbl )
{
	https_SessionTicketTable_RemoveAll( tbl );
	free( tbl->table );
	free( tbl );
}

static uint32_t GetSessionIDCache( const u_char* ticket, int len )
{
	_ASSERT(ticket);
	return fnv_32_buf( ticket, len, FNV1_32_INIT );
}

HTTPS_SessionTicketData* https_SessionTicketTable_Find( HTTPS_SessionTicketTable* tbl, const u_char* ticket, uint32_t len )
{
	HTTPS_SessionTicketData* ticket_data = NULL;
	uint32_t hash = 0;
	
	_ASSERT( ticket );
	_ASSERT( tbl );
	_ASSERT( len > 0 );

	hash = GetSessionIDCache( ticket, len ) % tbl->table_size;
	ticket_data = tbl->table[hash];

	while( ticket_data && (ticket_data->ticket_size != len ||
		memcmp( ticket_data->ticket, ticket, len ) != 0) ) 
	{
		ticket_data = ticket_data->next;
	}
	return ticket_data;
}


static HTTPS_SessionTicketData* CreateSessionTicketData( HTTPS_Session* sess, const u_char* ticket, uint32_t len )
{
	HTTPS_SessionTicketData* new_data;

	_ASSERT( sess && ticket && len );

	if(ticket == NULL || len == 0 ) return NULL;

	new_data = (HTTPS_SessionTicketData*) malloc( sizeof(HTTPS_SessionTicketData) );
	if(!new_data) return NULL;

	new_data->ticket = (u_char*) malloc( len );
	if(!new_data->ticket) {
		free(new_data);
		return NULL;
	}
	memcpy( new_data->ticket, ticket, len );
	new_data->ticket_size = len;

	_ASSERT_STATIC( sizeof(new_data->master_secret) == sizeof(sess->master_secret ) );
	memcpy( new_data->master_secret, sess->master_secret, sizeof(new_data->master_secret) );

	new_data->cipher_suite = sess->cipher_suite;
	new_data->compression_method = sess->compression_method;
	new_data->protocol_version = sess->version;
	
	time(&new_data->timestamp);
	new_data->next = NULL;
	return new_data;
}

static void DestroySessionTicketData( HTTPS_SessionTicketData* td )
{
	_ASSERT( td && td->ticket);
	free(td->ticket);
	free(td);
}

static void SessionTicketTable_RemoveKey( HTTPS_SessionTicketTable* tbl, HTTPS_SessionTicketData** key )
{
	HTTPS_SessionTicketData* temp = (*key);
	(*key) = (*key)->next;
	
	DestroySessionTicketData( temp );
	-- tbl->count;
}


int https_SessionTicketTable_Add( HTTPS_SessionTicketTable* tbl, HTTPS_Session* sess, const u_char* ticket, uint32_t len)
{
	uint32_t hash;
	HTTPS_SessionTicketData* new_data;

	_ASSERT( tbl );
	_ASSERT( sess );

	if( tbl->timeout_interval != 0 && 
		time( NULL ) - tbl->last_cleanup_time > HTTPS_CACHE_CLEANUP_INTERVAL )
	{
		https_SessionTicketTable_CleanSessionCache( tbl );
	}

	new_data = CreateSessionTicketData( sess, ticket, len );
	if( !new_data )
	{
		return DPI_ERROR(HTTPS_E_OUT_OF_MEMORY);
	}

	hash = GetSessionIDCache( new_data->ticket, new_data->ticket_size ) % tbl->table_size;
	new_data->next = tbl->table[hash];
	tbl->table[hash] = new_data;
	++ tbl->count;

	return HTTPS_RC_OK;
}

void https_SessionTicketTable_Remove( HTTPS_SessionTicketTable* tbl, const u_char* ticket, uint32_t len )
{
	uint32_t hash;
	HTTPS_SessionTicketData** s;
	_ASSERT( tbl ); _ASSERT( ticket && len );

	hash = GetSessionIDCache( ticket, len ) % tbl->table_size;
	s = &tbl->table[hash];

	while( (*s) && ((*s)->ticket_size != len || memcmp((*s)->ticket, ticket, len ) != 0) )
	{
		s = &(*s)->next;
	}

	if( *s )
	{
		SessionTicketTable_RemoveKey( tbl, s );
	}
}

void https_SessionTicketTable_RemoveAll( HTTPS_SessionTicketTable* tbl )
{
	int i;
	for( i=0; i < tbl->table_size; ++i )
	{
		HTTPS_SessionTicketData* d = tbl->table[i];
		while( d )
		{
			HTTPS_SessionTicketData* dd = d;
			d = d->next;
			DestroySessionTicketData( dd );
		}
	}

	memset( tbl->table, 0, sizeof(tbl->table[0])*tbl->table_size );
	tbl->count = 0;
}


void https_SessionTicketTable_CleanSessionCache( HTTPS_SessionTicketTable* tbl )
{
	int i;
	time_t cur_time = tbl->last_cleanup_time = time( NULL );

	for( i=0; i < tbl->table_size; ++i )
	{
		HTTPS_SessionTicketData** d = &tbl->table[i];
		while( *d )
		{
			if( (*d)->timestamp != 0 && 
				cur_time - (*d)->timestamp > tbl->timeout_interval )
			{
				SessionTicketTable_RemoveKey( tbl, d );
			}
			else
			{
				d = &(*d)->next;
			}
		}
	}
}

