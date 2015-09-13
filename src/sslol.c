
#include <string.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "https.h"
#include "sslol.h"

#include "Core.h"

static SSLOLGlobal Globals;

void sslol_dump( u_char* data, uint32_t sz )
{
	uint32_t i;

	for( i = 0; i < sz; i++ )
	{
		if( isprint(data[i]) || data[i] == '\n' || data[i] == '\t' || data[i] == '\r' ) 
			putc( data[i], stdout );
		else
			putc( '.', stdout );
	}
}

static void sslol_data_callback( DPI_PacketDir dir, void* user_data, u_char* pkt_payload,
							  uint32_t pkt_size, HTTPS_Pkt* last_packet )
{
	int dir_old = 0;
	PSoderoTCPSession session = gCurSession;
	PTCPState state = &gState;
	TSoderoTCPValue value;
	PTCPHeader tcp = g_tcp;
	PIPHeader ip = g_pip;
	PEtherHeader ether = g_ether;
	int length = last_packet->pcap_header.len;
 	int base = 0;

	switch(dir)
	{
		case ePktDirFromClient:
			//printf( "\nC->S:\n" );
			dir_old = 1;
			break;
		case ePktDirFromServer:
			//printf( "\nS->C:\n" );
			dir_old = -1;
			break;
		default:
			//printf( "\nUnknown packet direction!" );
			return;
	}

	memset(&value, 0, sizeof(TSoderoTCPValue));
	session->flag = SESSION_TYPE_MINOR_HTTPS;
	if (NULL != session->session)
	{
		((PSoderoID)&((PSoderoApplicationHTTP)session->session)->id)->type = session->flag;
	}

	processHTTPPacket(session, dir_old, &value, base, pkt_payload, pkt_size,
		length, state, tcp, ip, ether); 
	//sslol_dump( pkt_payload, pkt_size );
}

static int missing_pkt_callback(DPI_PacketDir dir, void* user_data, uint32_t pkt_seq, uint32_t pkt_size)
{
	return 1;
}

static void session_event_handler( HttpsEnv* env, TcpSession* sess, char event )
{
	char buff[512];
	switch( event )
	{
		case HTTPS_EVENT_NEW_SESSION:
			SessionToString(sess, buff);
			//printf( "\n=> New Session: %s\n", buff );
			SessionSetCallback( sess, sslol_data_callback, NULL, sess );
			SessionSetMissingPacketCallback( sess, missing_pkt_callback, 100, 10 );
			break;

		case HTTPS_EVENT_SESSION_CLOSING:
			SessionToString(sess, buff);
			//printf( "\n<= Session closing: %s\n", buff );
			break;

		default:
			//fprintf( stderr, "ERROR: Unknown session event code (%d)\n", (int)event );
			break;
	}
}

static void rmspace(char *str)
{
	char	*buff = malloc((MAXLEN+1) * sizeof(char));
	register int	i, j = 0;

	for (i=0; str[i]; i++)
	{
		if (str[i] == '\\')
		{
			if (isspace(str[i+1]))
				buff[j++] = str[i+1];
			else if (str[i+1] == '\\')
				buff[j++] = str[i+1];
		}
		else if (!isspace(str[i]))
			buff[j++] = str[i];

		if (i >= MAXLEN)
			break;
	}

	buff[j] = '\0';
	
	strcpy(str, buff);
}

void sslol_print_conf(const char *path, SSLOLConfig *config)
{
	int index;

	printf("Config file: %s\n", path);
	printf("server count: %d\n", config->server_cnt);
	printf("-------------------------------------------------\n");

	for (index=0; index<config->server_cnt; index++)
	{
		printf("-------------------------------------------------\n");
		printf("Server IP address: %s\n", inet_ntoa(config->server[index]->server_ip));
		printf("TCP Port: %d\n",config->server[index]->port);
		printf("Keyfile: %s\n", config->server[index]->keyfile);
		printf("-------------------------------------------------\n");
	}
}

int sslol_load_conf(const char *path, SSLOLConfig *config)
{
	char	strbuf[MAXLEN];
	FILE	*fd = NULL;
	int 	n = 0, line = 0, index=0;
	
	fd = fopen(path, "r");
	if (fd == NULL)
	{
		fprintf(stderr, "ERROR: Can't open config file \"%s\".\n", path);
		return(-1);
	}

	while(!feof(fd))
	{
		register char	*p = strbuf;
		register char	*key = malloc((STRLEN256+1) * sizeof(char));
		register char	*val = malloc((STRLEN256+1) * sizeof(char));
		char	title[STRLEN256];

		*key = '\0';
		*val = '\0';
		*title = '\0';

		line++;

		if (fgets(strbuf, sizeof(strbuf)-1, fd) == NULL)
			continue;

		rmspace(p);

		/* blank lines and comments get ignored */
		if (!*p || *p == '#')
			continue;

		if (p[0] == '[' && p[strlen(p)-1] == ']')
		{
			sscanf(p, "[%255[^]]", title);
			index = config->server_cnt;

			config->server[index] = malloc(sizeof(SSLOL_ARGS));
			if (config->server_cnt == 0)
				memset(config->server[index],0,sizeof(SSLOL_ARGS));
			else
			{
				memcpy(config->server[index],config->server[index-1],sizeof(SSLOL_ARGS));
				memset(config->server[index],0,sizeof(SSLOL_ARGS));
			}

			strcpy(config->server[index]->title, title);

			config->server_cnt++;
			continue;
		}

		n = sscanf(p, "%255[^=\n\r\t]=%255[^\n\r\t]", key, val);

		if (n != 2)
		{
			fprintf(stderr, "ERROR: Can't parse config file %s at line %d.\n", path, line);
			continue;
		}
		
		if (!strcmp(key,"ip"))
		{
			if (inet_aton(val, &config->server[index]->server_ip) == 0)
			{
				fprintf(stderr, "Invalid IP address format \"%s\".\n", val);
				return(-1);
			}
		}
		else if (!strcmp(key,"port"))
		{
			config->server[index]->port = (uint16_t) atoi(val);
			if (config->server[index]->port == 0) 
			{
				fprintf(stderr, "Invalid TCP port value \"%d\".\n", config->server[index]->port);
				return(-1);
			}
		}				
		else if (!strcmp(key,"key"))
		{
			strcpy(config->server[index]->keyfile, val);
		}
		else if (!strcmp(key,"pwd"))
		{
			strcpy(config->server[index]->pwd, val);
		}	

		free(key);
		free(val);

	}

	fclose(fd);
	sslol_print_conf(path, config);
	return(0);

}

int sslol_init( void )
{
	int rc = 0;
	int indx = 0;
	char ErrBuffer[2048] = {0};
	SSLOLConfig *config = &Globals.config;

	sslol_load_conf(gSslolConf, config);

	Globals.HttpsEnv = HttpsEnvCreate( NULL, 100, 0, 0 );

	for ( indx = 0; indx < config->server_cnt; indx++ )
	{
		rc = HttpsEnvSetSSL_ServerInfo( Globals.HttpsEnv, 
			                          &config->server[indx]->server_ip, 
			                          config->server[indx]->port,
									  config->server[indx]->keyfile,
		  				              config->server[indx]->pwd 
									 );
		if (rc != HTTPS_RC_OK)
		{			
			char err_str[255];
			memset( err_str, 0, sizeof(err_str) );
			printf( err_str,"Error loading SSL server configuration at pos[%i]; error code=%d\n", indx+1, rc );
		}
	}
	
	if (rc == 0 ) 
	{
		HttpsEnvSetSessionCallback( Globals.HttpsEnv, session_event_handler, NULL );
	}

	SSL_library_init(); 
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

	return rc;
}

int sslol_deinit()
{
	HttpsEnv*  env = Globals.HttpsEnv;

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();

	if( env ) 
	{
		HttpsEnvDestroy( env );
		env = NULL;
	}

	return 0;
}

int sslol_process( const struct pcap_pkthdr *header, const u_char *pkt_data )
{
	int rc = 0;

	rc = sslol_process_ethernet(Globals.HttpsEnv, header, pkt_data);

	return rc;
}

