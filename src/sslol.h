
#ifndef __SSL_OL_H__
#define __SSL_OL_H__

#define MAX_SSL_SERVERS    5
#define CHAR_PER_LINE	   80
#define MAXLEN		1024
#define STRLEN256	256

/* A structure to place parsed command line argument */
typedef struct ssltrace_args
{
	char		    title[STRLEN256];
	char			keyfile[MAXLEN];	/* SSL server's private key file path */
	char			pwd[MAXLEN];		/*Keyfile password, if present; NULL otherwise */
	char			src[MAXLEN];		/* Input source - a capture file in tcpdump format or a network interface name */
	int				src_type;			/* Input source type - SRCTYPE_FILE or SCRTYPE_LIVE */
	struct in_addr	server_ip;			/* SSL server's IP address */
	uint16_t		port;				/* SSL server's port */
} SSLOL_ARGS;

typedef struct _SSLOLConfig
{
	int 		 server_cnt;
	SSLOL_ARGS*  server[MAX_SSL_SERVERS];
} SSLOLConfig;

typedef struct _SSLOLGlobal
{
	SSLOLConfig	config;
	HttpsEnv* 	HttpsEnv;
} SSLOLGlobal;

extern int sslol_process( const struct pcap_pkthdr *header, const u_char *pkt_data );
extern int sslol_init( void );
extern int sslol_deinit();
#endif
