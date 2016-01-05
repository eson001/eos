/*
 * Parameter.c
 *
 *  Created on: Aug 7, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <getopt.h>

#include "Type.h"
#include "Common.h"
#include "Parameter.h"

int gTCPSession = false;
int gExport = SODERO_EXPORT_NONE;
int gAlign = false;

//	Statistics Period
long long gPeriod = uSecsPerSec * SODERO_DEFAULT_PERIOD;
//	Flow Tick Period
int gCycle  = SODERO_DEFAULT_CYCLE;

int gCapturePromisc = CAPTURE_PROMISC;
int gCaptureTimeout = CAPTURE_TIMEOUT;
int gCaptureBuffer  = CAPTURE_BUFFER ;

int gCheck = 0;
const char * gDebug   = nullptr;
const char * gSslolConf = nullptr;
const char * gDevice  = "eth9";
const char * gServer  = "localhost";
const char * gService = SODERO_REPORT_SERVICE;
const char * gDPIRulesTable = "ip-port.tsv";

unsigned int gReportHost;

TVersion gVersion = {SODERO_REPORT_VERSION};
TMAC gMAC = {.bytes = SODERO_REPORT_MAC   };
TIP  gHost  = {.bytes = SODERO_REPORT_CLIENT};

const char * gName = "demo";

int gLoop = 0;

struct option longopts[] = {
		{ "check"    , required_argument, NULL, 'k'},
		{ "debug"    , required_argument, NULL, 'g'},
		{ "interface", required_argument, NULL, 'i'},
		{ "name"     , required_argument, NULL, 'n'},
		{ "align"    ,       no_argument, NULL, 'a'},
		{ "period"   , required_argument, NULL, 's'},
		{ "cycle"    , required_argument, NULL, 'c'},
		{ "promisc"  ,       no_argument, NULL, 'p'},
		{ "timeout"  , required_argument, NULL, 't'},
		{ "buffer"   , required_argument, NULL, 'b'},
		{ "loop"     , required_argument, NULL, 'l'},
		{ "rule"     , required_argument, NULL, 'r'},
//		{ "device"   , required_argument, NULL, 'd'},
              {"logging"  ,  required_argument, NULL, 'd'},
		{ "server"   , required_argument, NULL, 'h'},
		{ "service"  , required_argument, NULL, 'v'},
		{ "dump"     , required_argument, NULL, 'e'},
		{ "sslol"	 , required_argument, NULL, 'x'},
		{ "tcpsession" , required_argument, NULL, 'o'},
	};

void usege(void) {
	printf("Usege:\n");
	printf("-k --check       export check log\n");
	printf("                 [all|tcp|udp|dns|http]");
	printf("-g --debug       enter debug mode\n");
	printf("-i --interface   capture interface\n");
	printf("-a --align       align to period\n");
	printf("-s --period      report interval\n");
	printf("-c --cycle       flow tick interval\n");
	printf("-p --promisc     libpcap's interface mode\n");
	printf("-t --timeout     libpcap's capture timeout\n");
	printf("-b --buffer      libpcap's buffer size\n");
	printf("-r --rule        IP-Port rules table file\n");
	printf("-l --loop        Repeat pcap file\n");
	printf("-n --name        Report name\n");
//	printf("-d --device      Report device\n");
	printf("-h --server      Report server\n");
	printf("-v --service     Report service\n");
	printf("-d --logging     logging level\n");
	printf("                 [Err:0, Wrnn:1, Info:2, Dbg:3]\n");
	printf("-e --dump        dump level\n");
	printf("                 [verbose|detail|report]\n");
	printf("-x --httpsconf   https offload config file\n");
	printf("-o --tcpsession  use tcp to send session data\n");
	exit(0);
}

void initArguments(int argc, char** argv) {
	srandom(time(NULL));
	int result;
	while((result = getopt_long(argc, argv, "ab:c:e:g:h:i:l:n:ps:t:v:d:x:", longopts, NULL)) != -1) {
		switch (result) {
		case 'a':
			gAlign = true;
			break;
		case 'b':
			gCaptureBuffer = atoi(optarg);
			break;
		case 'c':
			gCycle = atoi(optarg);
			break;
//		case 'd':
//			gDevice = optarg;
//			break;
		case 'e':
			if (strcasecmp(optarg, "verbose") == 0) {
				gExport = SODERO_EXPORT_VERBOSE;
				break;
			}
			if (strcasecmp(optarg, "detail") == 0) {
				gExport = SODERO_EXPORT_DETAIL;
				break;
			}
			if (strcasecmp(optarg, "report") == 0) {
				gExport = SODERO_EXPORT_REPORT;
				break;
			}
			gExport = atoi(optarg);
			break;
		case 'g':
			gDebug = optarg;
			break;
		case 'h':
			gServer = optarg;
			break;
		case 'i':
			gDevice = optarg;
			break;
		case 'k':
			do {
				if (same_text(optarg, "all")) {
					gCheck |= SODERO_CHECK_ALL;
					break;
				}
				if (same_text(optarg, "tcp")) {
					gCheck |= SODERO_CHECK_TCP;
					break;
				}
				if (same_text(optarg, "udp")) {
					gCheck |= SODERO_CHECK_UDP;
					break;
				}
				if (same_text(optarg, "http")) {
					gCheck |= SODERO_CHECK_HTTP;
					break;
				}
				if (same_text(optarg, "mysql")) {
					gCheck |= SODERO_CHECK_MYSQL;
					break;
				}
				if (same_text(optarg, "dns")) {
					gCheck |= SODERO_CHECK_DNS;
					break;
				}
			} while(false);
			break;
		case 'l':
			gLoop = atoi(optarg);
			break;
		case 'n':
			gName = optarg;
			break;
		case 'p':
			gCapturePromisc = CAPTURE_NORMAL;
			break;
		case 'r':
			gDPIRulesTable = optarg;
			break;
		case 's':
			gPeriod = (unsigned long long)(uSecsPerSec * atof(optarg));
			break;
		case 't':
			gCaptureTimeout = uSecsPerSec * atoi(optarg);
			break;
		case 'v':
			gService = optarg;
			break;
		case 'd':
			do {
				if (atoi(optarg) <= LOG_DBG) {
					g_config_log_level = atoi(optarg);
					printf("The configure level:%d\n", g_config_log_level);
					break;
				}
				else{
					g_config_log_level = LOG_DBG;
					break;
				}	
			} while(false);
			break;
		case 'x':
			gSslolConf = optarg;
			break;
        case 'o':
            gTCPSession = true;
            break;
		default:
			usege();
		}
	}

	printf("export %d align %d period %lld capture promisc %d timeout %d buffer %d\n",
			gExport, gAlign, gPeriod, gCapturePromisc, gCaptureTimeout, gCaptureBuffer);
}

