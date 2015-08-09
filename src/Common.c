/*
 * Common.c
 *
 *  Created on: Jul 8, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdarg.h>

#include <ifaddrs.h>
#if defined(__FreeBSD__) || defined(__APPLE__)
#include <net/if_dl.h>
#endif

#include "Type.h"
#include "Session.h"
#include "Common.h"
#include "HTTP.h"

#ifdef __EXPORT_STATISTICS__
FILE * gDump = nullptr;
#endif

FILE* gLogFile = nullptr;
TSodero_logging_level g_config_log_level = LOG_DBG;
#define LOG_BUF_LEN 1024

const char * REPORT_TYPE_HEAD = "Head";
const char * REPORT_TYPE_BODY = "Body";


TEtherData EMPTY_ETHER_DATA = {{0ULL, 0ULL}};

unsigned long long gICMPActivedTime = uSecsPerSec * DEFAULT_SESSION_ICMP_ACTIVED_TIMEOUT;
unsigned long long gTCPOpeningTime = uSecsPerSec * DEFAULT_SESSION_TCP_OPENING_TIMEOUT;
unsigned long long gTCPActivedTime = uSecsPerSec * DEFAULT_SESSION_TCP_ACTIVED_TIMEOUT;
unsigned long long gTCPClosingTime = uSecsPerSec * DEFAULT_SESSION_TCP_CLOSING_TIMEOUT;
unsigned long long gUDPActivedTime = uSecsPerSec * DEFAULT_SESSION_UDP_ACTIVED_TIMEOUT;

unsigned long long gDNSOpenTime    = uSecsPerSec * DEFAULT_SESSION_DNS_OPEN_TIMEOUT   ;
unsigned long long gDNSDoneTime    = uSecsPerSec * DEFAULT_SESSION_DNS_DONE_TIMEOUT   ;

unsigned long long gID = 0;

unsigned long long gB, gE, gT, gO;

TSoderoFlowDatum gTotal;
TSoderoFlowDatum gARP, gVLAN, gMPLS, gLACP, gRSTP, gOtherEther;
TSoderoFlowDatum gIPv4, gIPv6, gICMP, gTCP, gUDP, gOtherIPv4;
//TSoderoFlowDatum gHTTP, gDNS, gMySQL;

unsigned long long gSession     = 0;
unsigned long long gApplication = 0;

unsigned long long gICMPRequest     = 0;
unsigned long long gICMPResponse    = 0;
unsigned long long gICMPUnrechabled = 0;

unsigned long long gDNSRequest  = 0;
unsigned long long gDNSResponse = 0;

unsigned long long gHTTPRequest  = 0;
unsigned long long gHTTPResponse = 0;
unsigned long long gHTTPSkiped   = 0;
unsigned long long gHTTPMethod[8], gHTTPCode[8];

TSoderoFlowDatum gCurrent, gReportSend, gReportRecv;

#ifdef __EXPORT_STATISTICS__

unsigned long long tempTaken = 0;
unsigned long long tempFreed = 0;
unsigned long long tempEmpty = 0;
unsigned long long memoryTaken = 0;
unsigned long long memoryFreed = 0;
unsigned long long memoryEmpty = 0;
unsigned long long blockTaken = 0;
unsigned long long blockFreed = 0;
unsigned long long blockEmpty = 0;
unsigned long long bufferTaken = 0;
unsigned long long bufferFreed = 0;
unsigned long long bufferEmpty = 0;
unsigned long long eventTaken = 0;
unsigned long long eventFreed = 0;
unsigned long long eventEmpty = 0;
unsigned long long applicationTaken = 0;
unsigned long long applicationFreed = 0;
unsigned long long applicationEmpty = 0;
unsigned long long sessionTaken = 0;
unsigned long long sessionFreed = 0;
unsigned long long sessionEmpty = 0;

unsigned long long gFirstBlock  = 0;
unsigned long long gCleanBlock  = 0;
unsigned long long gCloseBlock  = 0;
unsigned long long gCleanSkiped = 0;
unsigned long long gCreateBlock = 0;
unsigned long long gReorderBlock  = 0;
unsigned long long gReorderSkip  = 0;
unsigned long long gReplaceTake = 0;
unsigned long long gReplaceFree = 0;
unsigned long long gOverflowTake = 0;
unsigned long long gOverflowFree = 0;

unsigned long long gDNSTake = 0;
unsigned long long gDNSFree = 0;
unsigned long long gHTTPTake = 0;
unsigned long long gHTTPFree = 0;
unsigned long long gMySQLTake = 0;
unsigned long long gMySQLFree = 0;
unsigned long long gCustomFree = 0;
unsigned long long gOtherFree = 0;

#endif

///////////////////////////////////////////////////////////////////////////////////////////////////
int DPI_LogInit(char *szFName)
{
	gLogFile = fopen(szFName,"wb");
	if (gLogFile==nullptr)
	{
		perror("open");
		return -1;
	}
	setvbuf(gLogFile, nullptr, _IONBF, 0);
    return true;
}

int DPI_Log(TSodero_logging_level log_level, char *fmt,...)
{
    char txtBuf[LOG_BUF_LEN+1];
    static int file_len = 0;
    va_list ap;
    int ret = 0;
    time_t t;
    struct tm *timenow;

    if (log_level > g_config_log_level)
    {
       return true;
    }

    if (gLogFile)
    {
    	va_start(ap,fmt);	
    	ret = vsnprintf(txtBuf, sizeof(txtBuf)-1,fmt,ap);
    	va_end(ap);
    	txtBuf[LOG_BUF_LEN]='\0';
    	time(&t);
       timenow   =   localtime(&t);
       file_len += strlen(txtBuf);

       if (file_len >= LOG_FILE_LEN)
       {
           fseek(gLogFile,0,SEEK_SET);
           file_len = 0;
       }
    	fprintf(gLogFile,"%d-%.2d-%.2d %.2d:%.2d:%.2d  %s\r\n",1990+timenow->tm_year,timenow->tm_mon,timenow->tm_mday,timenow->tm_hour,timenow->tm_min,timenow->tm_sec, txtBuf);        
    }
    return ret;
}
void DPI_LogClose()
{
	if (gLogFile) {
		fflush(gLogFile);
		fclose(gLogFile);
	}
}

void * takeMemory(size_t size) {
#ifdef __EXPORT_STATISTICS__
	memoryTaken++;
#endif
	return malloc(size);
}

void freeMemory(void * ptr) {
	if (ptr)
#ifdef __EXPORT_STATISTICS__
	{
		memoryFreed++;
#endif
		free(ptr);
#ifdef __EXPORT_STATISTICS__
	} else
		memoryEmpty++;
#endif
}

void * takeTemp(size_t size) {
#ifdef __EXPORT_STATISTICS__
	tempTaken++;
#endif
	return malloc(size);
}

void freeTemp(void * ptr) {
	if (ptr)
#ifdef __EXPORT_STATISTICS__
	{
		tempFreed++;
#endif
		free(ptr);
#ifdef __EXPORT_STATISTICS__
	} else
		tempEmpty++;
#endif
}

void * takeBlock(size_t size) {
#ifdef __EXPORT_STATISTICS__
	blockTaken++;
#endif
	return malloc(size);
}

void freeBlock(void * ptr) {
	if (ptr)
#ifdef __EXPORT_STATISTICS__
	{
		blockFreed++;
#endif
		free(ptr);
#ifdef __EXPORT_STATISTICS__
	} else
		blockEmpty++;
#endif
}

void * takeBuffer(size_t size) {
#ifdef __EXPORT_STATISTICS__
	bufferTaken++;
#endif
	return malloc(size);
}

void freeBuffer(void * ptr) {
	if (ptr)
#ifdef __EXPORT_STATISTICS__
	{
		bufferFreed++;
#endif
		free(ptr);
#ifdef __EXPORT_STATISTICS__
	} else
		bufferEmpty++;
#endif
}

void * takeEvent(size_t size) {
#ifdef __EXPORT_STATISTICS__
	eventTaken++;
#endif
	return malloc(size);
}

void freeEvent(void * ptr) {
	if (ptr)
#ifdef __EXPORT_STATISTICS__
	{
		eventFreed++;
#endif
		free(ptr);
#ifdef __EXPORT_STATISTICS__
	} else
		eventEmpty++;
#endif
}

void * takeApplication(size_t size) {
#ifdef __EXPORT_STATISTICS__
	applicationTaken++;
#endif
	void * result = malloc(size);
	if (result)
		bzero(result, size);
	return result;
}

void freeApplicationHTTP(PSoderoApplicationHTTP application) {
	freeTemp(application->req_content_type);
	freeTemp(application->rsp_content_type);
	freeTemp(application->req_content_length);
	freeTemp(application->rsp_content_length);
//	freeTemp(application->req_cookies);
//	freeTemp(application->rsp_cookies);
	freeTemp(application->transfer_encoding);
	freeTemp(application->content_encoding);

	//	request
	freeTemp(application->host);
	if (application->url)
		free(application->url);
	freeTemp(application->ua);
	freeTemp(application->referer);
	freeTemp(application->x_online_host);

	//	response
	freeTemp(application->server);
	freeTemp(application->date);
	freeTemp(application->expires);

	freeMemory(application->sunday);
}

void freeApplicationData(PSoderoApplication application) {
	if (application->data)
		freeMemory(application->data);
	PSoderoSession session = application->owner;
	unsigned char flag = ((PSoderoID)&application->id)->type;
	switch(session->key.proto) {
	case IPv4_TYPE_TCP:
		switch(flag) {
			case SESSION_TYPE_MINOR_HTTP:
				freeApplicationHTTP((PSoderoApplicationHTTP)application);
#ifdef __EXPORT_STATISTICS__
				gHTTPFree++;
				break;
			case SESSION_TYPE_MINOR_MYSQL:
				gMySQLFree++;
				break;
			case SESSION_TYPE_MINOR_UNKNOWN:
				gCustomFree++;
				break;
			default:
				gOtherFree++;
#endif
				break;
		}
#ifdef __EXPORT_STATISTICS__
		break;
	case IPv4_TYPE_UDP:
		switch(flag) {
		case SESSION_TYPE_MINOR_DNS:
			gDNSFree++;
			break;
		case SESSION_TYPE_MINOR_UNKNOWN:
			gCustomFree++;
			break;
		default:
			gOtherFree++;
		}
		break;
	default:
		gOtherFree++;
#endif
		break;
	}
}

void freeApplication(void * ptr) {
	if (ptr) {
#ifdef __EXPORT_STATISTICS__
		applicationFreed++;
#endif
		PSoderoApplication application = ptr;

//		printf("Free Application: %p\n", application);

		ptr = application->link;
		freeApplicationData(application);
		free(application);
	}
#ifdef __EXPORT_STATISTICS__
	else
		applicationEmpty++;
#endif
}

void * takeSession(size_t size) {
#ifdef __EXPORT_STATISTICS__
	sessionTaken++;
#endif
	void * result = malloc(size);
	if (result)
		bzero(result, size);
	return result;
}

void freeSession(void * ptr) {
	if (ptr) {
#ifdef __EXPORT_STATISTICS__
		sessionFreed++;
#endif
		PSoderoSession session = ptr;
		PSoderoApplication application = session->session;
		while(application) {
			ptr = application->link;
			freeApplication(application);
			application = ptr;
		}
		switch(session->key.proto) {
			case IPPROTO_ICMP: {
				break;
			}
			case IPPROTO_TCP: {
				PSoderoTCPSession tcp = (PSoderoTCPSession) session;
				for (int i = 0; i < TCP_REORDER_BLOCK_COUNT; i++) {
					if (tcp->value.incoming.block[i]) {
#ifdef __EXPORT_STATISTICS__
						gCloseBlock++;
#ifdef __EXPORT_DUMP_BLOCK__
						if (gDump)
							fprintf(gDump, "free reorder block %p of %p - %p @ index %d\n",
								tcp->value.incoming.block[i], tcp, &tcp->value.incoming, i);
#endif
#endif
						freeBlock(tcp->value.incoming.block[i]);
					}
					if (tcp->value.outgoing.block[i]) {
#ifdef __EXPORT_STATISTICS__
						gCloseBlock++;
#ifdef __EXPORT_DUMP_BLOCK__
						if (gDump)
							fprintf(gDump, "free reorder block %p of %p - %p @ index %d\n",
									tcp->value.outgoing.block[i], tcp, &tcp->value.outgoing, i);
#endif
#endif
						freeBlock(tcp->value.outgoing.block[i]);
					}
				}
				break;
			}
			case IPPROTO_UDP: {
				break;
			}
		}
		free(session);
	}
#ifdef __EXPORT_STATISTICS__
	else
		sessionEmpty++;
#endif
}


///////////////////////////////////////////////////////////////////////////////////////////////////


unsigned long long now(void) {
	struct timeval tv;
	struct timezone tz;
	gettimeofday(&tv, &tz);

	unsigned long long result = 1000000;
	return result * (tv.tv_sec + 60 * (tz.tz_dsttime)) + tv.tv_usec;
}

int time_delta(unsigned int a, unsigned int b) {
	return ((long long) a) - ((long long) b);
}

int time_inter(unsigned long long a, unsigned long long b) {
	return ( ((long long) a) - ((long long)b) ) / uSecsPerSec;
}

char * find_char(char * p, char c) {
	if (p) {
		while(*p) {
			if (*p == c) {
				return p;
			}
			p++;
		}
	}
	return nullptr;
}

char * find_text(char * p, int length, char c) {
	if (p) {
		for (int i = 0; i < length; i++)
			if (p[i] == c) {
				length -= i;
				return p + i;
			}
		length = 0;
	}
	return nullptr;
}

char * skip_space(char * str) {
	if (str)
		while(*str) {
			if (SPACE >= (unsigned char)*str)
				str++;
			else
				return str;
		}
	return nullptr;
}

#define BITWIDTHMASK 7
#define BITWIDTHSIZE 4
int str_len(const char *str) {
	if (!str) return 0;

    unsigned v;
    const char *p = str;

    while(*p && ((unsigned long)p & BITWIDTHMASK))
        p ++;

    if (*p == 0)
        return (int)(p - str);

    for (v = 0; !v; p += 4) {
        v = (*(unsigned*)p - 0x01010101) & 0x80808080;
        if (v)
            v &= ~*(unsigned*)p;
    }

    for (; (v & 0xff) == 0; p ++)
        v >>= 8;

    return (int)(p - str - 4);
}

int cpy_str(char * dest, const char * sour) {
	int result = 0;
	do {
		dest[result] = sour[result];
	} while(sour[result++]);
	return result;
}

int cpy_text(char * dest, const char * sour, int size) {
	for (int i = 0; i < size; i++) {
		dest[i] = sour[i];
		if (!sour[i])
			return i;
	}
	dest[size] = 0;
	return size;
}

int cmp_str(const char * sour, const char * dest) {
  if (!sour && !dest) return 0;
  if (!sour)
      return -1;
  if (!dest)
      return +1;
  return strcmp(sour, dest);
}

int cmp_text(const char * sour, const char * dest) {
  if (!sour && !dest) return 0;
  if (!sour)
      return -1;
  if (!dest)
      return +1;
  return strcasecmp(sour, dest);
}

int same_str(const char * a, const char * b) {
	return cmp_str(a, b) == 0;
}

int same_text(const char * a, const char * b) {
	return cmp_text(a, b) == 0;
}

char * dup_str(const char * src) {
	if (src && *src)
		return strdup(src);

	return nullptr;
}

char * replace_str(char * * value, const char * buffer, int length) {
	char * string = takeTemp(length + 1);
	if (string) {
		if (*value)
			freeTemp(*value);	//	free old

		memcpy(string, buffer, length);
		string[length] = 0;
		*value = string;		//	take new
	}
	return string;
}

PSundayData sunday_init(const char * string) {
	if (string && *string) {
		int length = strlen(string);
		PSundayData result = takeMemory(sizeof(TSundayData) + length + 5);
		result->string[0] = '-';
		result->string[1] = '-';
		memcpy(result->string + 2, string, length);
		length += 2;
		result->string[length++] = '-';
		result->string[length++] = '-';
		result->string[length  ] = '\0';
		result->length = length;
		const unsigned char * buffer = (const unsigned char *)result->string;

		for(int i = 0; i < 256; i++)
			result->steps[i] = length + 1;

		for(int i = 0; i < length; i++)
			result->steps[buffer[i]] = length - i;

		return result;
	} else
		return nullptr;
}

int sunday_find(const PSundayData sunday, const char * string, int length) {
	int mIndex = 0;
	int sIndex = 0;

	while(mIndex < length) {
		int temp = mIndex;
		while(sIndex < sunday->length) {
			if(string[mIndex] == sunday->string[sIndex]) {
				mIndex++;
				sIndex++;
				continue;
			}
			if(temp + sunday->length > length) return -1;
			mIndex = temp + sunday->steps[(unsigned char)string[temp + sunday->length]];
			sIndex = 0;
			break;
		}
		if(sIndex == sunday->length)
			return mIndex - sunday->length;
	}
	return -1;
}

void enum_interfaces(void) {
#ifdef __linux__
	register int fd, intrface;
	struct ifreq buf[MAXINTERFACES];
	struct ifconf ifc;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
		ifc.ifc_len = sizeof buf;
		ifc.ifc_buf = (caddr_t) buf;
		if (!ioctl(fd, SIOCGIFCONF, (char *) &ifc)) {
			intrface = ifc.ifc_len / sizeof(struct ifreq);
			printf("interface num is intrface = %d\n", intrface);
			LogInf("Interface num:%d", intrface);
			while (intrface-- > 0) {
				printf("net device %s is ", buf[intrface].ifr_name);
				

				if (ioctl(fd, SIOCGIFFLAGS, (char *) &buf[intrface])) {
					char str[256];
					sprintf(str, "cpm: ioctl device %s", buf[intrface].ifr_name);
					perror(str);
				}

				printf("%s%s\n", buf[intrface].ifr_flags & IFF_UP ? "UP" : "DOWN", buf[intrface].ifr_flags & IFF_PROMISC ? " & PROMISC" : "");
				LogInf("net device %s is %s%s", buf[intrface].ifr_name, buf[intrface].ifr_flags & IFF_UP ? "UP" : "DOWN", buf[intrface].ifr_flags & IFF_PROMISC ? " & PROMISC" : "");
				//	Get IP of the net card
				if (ioctl(fd, SIOCGIFADDR, (char *) &buf[intrface])) {
					char str[256];
					sprintf(str, "cpm: ioctl device %s", buf[intrface].ifr_name);
					perror(str);
				}
//				printf("IP address is: %s\n", inet_ntoa(((struct sockaddr_in*)&(buf[intrface].ifr_addr))->sin_addr));
				//	This section can't get Hardware Address, I don't know whether the reason is module driver.
				//  ((struct sockaddr_in*)&arp.arp_pa)->;sin_addr=((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr;
#if 0
				//	Get HW ADDRESS of the net card
				if (!(ioctl (fd, SIOCGENADDR, (char *) &buf[intrface])))
				{
					puts ("HW address is:");

					printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
							(unsigned char)buf[intrface].ifr_enaddr[0],
							(unsigned char)buf[intrface].ifr_enaddr[1],
							(unsigned char)buf[intrface].ifr_enaddr[2],
							(unsigned char)buf[intrface].ifr_enaddr[3],
							(unsigned char)buf[intrface].ifr_enaddr[4],
							(unsigned char)buf[intrface].ifr_enaddr[5]);

					puts("");
					puts("");
				}
#endif
				if (ioctl(fd, SIOCGIFHWADDR, (char *) &buf[intrface])) {
					char str[256];
					sprintf(str, "cpm: ioctl device %s", buf[intrface].ifr_name);
					perror(str);
				}

				printf("HW address is: %02x:%02x:%02x:%02x:%02x:%02x\n",
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[0],
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[1],
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[2],
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[3],
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[4],
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[5]);
			      LogInf("HW address is: %02x:%02x:%02x:%02x:%02x:%02x",
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[0],
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[1],
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[2],
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[3],
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[4],
						(unsigned char) buf[intrface].ifr_hwaddr.sa_data[5]);
			}
		} else
			perror("cpm: ioctl");

	} else
		perror("cpm: socket");

	close(fd);
#endif
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__sun)
	struct ifaddrs *ifa;

	if(getifaddrs(&ifa) < 0) {
		perror("getifaddrs error");
		exit(127);
	}

	for(struct ifaddrs * curifa = ifa; curifa != NULL; curifa = curifa->ifa_next) {
		printf("Interface %p - %x\n", curifa, curifa->ifa_addr->sa_family);
		if(curifa->ifa_addr->sa_family == AF_INET) {
			printf("%s: < ", curifa->ifa_name);
			if(curifa->ifa_flags&IFF_UP)
				printf("UP ");
			if(curifa->ifa_flags&IFF_BROADCAST)
				printf("BCAST ");
			if(curifa->ifa_flags&IFF_MULTICAST)
				printf("MCAST ");
			if(curifa->ifa_flags&IFF_LOOPBACK)
				printf("LOOP ");
			if(curifa->ifa_flags&IFF_POINTOPOINT)
				printf("P2P ");
			printf(">\n");

			struct sockaddr_in addr;
			char paddr[256];
			memcpy(&addr, curifa->ifa_addr, sizeof(struct sockaddr_in));
			printf("\tIP addr: %s\n",
			inet_ntop(AF_INET, &addr.sin_addr, paddr, sizeof(paddr)));
			memcpy(&addr, curifa->ifa_netmask, sizeof(struct sockaddr_in));
			printf("\tnetmask: %s\n",
			inet_ntop(AF_INET, &addr.sin_addr, paddr, sizeof(paddr)));
			memcpy(&addr, curifa->ifa_broadaddr, sizeof(struct sockaddr_in));
			printf("\tbroadaddr: %s\n",
			inet_ntop(AF_INET, &addr.sin_addr, paddr, sizeof(paddr)));
			//printf("\tflags=%d\n",curifa->ifa_flags);
		}

		if(curifa->ifa_addr->sa_family == AF_LINK) {
			struct sockaddr_dl dladdr;
			memcpy(&dladdr, curifa->ifa_addr, sizeof(struct sockaddr_dl));
			if(dladdr.sdl_alen < 6) continue;
			u_char pdladdr[16];
			memcpy(&pdladdr, dladdr.sdl_data + dladdr.sdl_nlen, dladdr.sdl_alen);
			printf("%s:\t", curifa->ifa_name);
			for(int i = 0; i < dladdr.sdl_alen; i++)
				printf("%x:", pdladdr[i]);

			printf("\n");
		}
	}
	freeifaddrs(ifa);
#endif
}

int isBMAC(PMAC mac) {
	return (mac->b2 == 0xFFFF) && (mac->b4 == 0xFFFFFFFF);
}

int isMMAC(PMAC mac) {
	return (mac->b2 & 0x0001) && !isBMAC(mac);
}

int isSMAC(PMAC mac) {
	return !(mac->b2 & 0x0001);
}

int isSTPMAC(PMAC mac) {	//	01:80:c2:00:00:00
	return (mac->b2 == 0x8001) && (mac->b4 == 0x000000c2);
}

int isLinkSTP(PLinkRSTPHeader header) {
	return (header->b4 == 0x00034242) && ((header->b2 & 0xFD) == 0x0000);
}

int isIPv4ARP(PARPHeader header) {
	return (header->hwType == ARP_HW_TYPE_ETHER   ) && (header->hwSize == ARP_HW_SIZE_ETHER   )
		&& (header-> pType == ARP_PROTOCOL_TYPE_IP) && (header-> pSize == ARP_PROTOCOL_SIZE_IP);
}

int isBIPv4(TIPv4 ipv4) {
	return ipv4.ip = 0xFFFFFFFF;
}

int isMIPv4(TIPv4 ipv4) {
	return (ipv4.s[0] >= 0xF0) & !isBIPv4(ipv4);
}

int isSIPv4(TIPv4 ipv4) {
	return ipv4.s[0] < 0xF0;
}

int isLIPv4(TIPv4 ipv4) {
	return (ipv4.s[0] == 0x0A) || (ipv4.l == 0xA8C0) || ((ipv4.l & 0xF0FF) == 0x10AC); //((ipv4[3] == 0xAC)
}

int isGIPv4(TIPv4 ipv4) {
	return !isLIPv4(ipv4);
}

int isEmptyEtherData(PEtherData value) {
	return (value->l == 0) && (value->h == 0);
}

int proto_index(const char * name) {
	if (name) {
		if (same_text(name, "TCP"))
			return IPv4_TYPE_TCP;
		if (same_text(name, "UDP"))
			return IPv4_TYPE_UDP;
		if (same_text(name, "SCTP"))
			return IPv4_TYPE_SCTP;
	}

	return 0;
}

const char * socket_type_name(int type) {
	switch (type) {
	case SOCK_DGRAM:
		return "UDP";
	case SOCK_STREAM:
		return "TCP";
	case SOCK_RAW:
		return "RAW";
	case SOCK_RDM:
		return "RDM";
	case SOCK_SEQPACKET:
		return "SEQ";
#ifdef __linux__
	case SOCK_DCCP:
		return "DCCP";
	case SOCK_PACKET:
		return "PACKET";
#endif
	}
	return "Unknown";
}

const char * ipv4_proto_name(int proto) {
	switch(proto) {
	case IPv4_TYPE_ICMP:
		return "icmp";
	case IPv4_TYPE_TCP:
		return "tcp";
	case IPv4_TYPE_UDP:
		return "udp";
	case IPv4_TYPE_SCTP:
		return "sctp";
	}
	return "other";
}

const char * ether_proto_name(int proto) {
	switch(proto) {
	case ETHER_TYPE_ARP:
		return "arp";
	case ETHER_TYPE_IPv4:
		return "ipv4";
	case ETHER_TYPE_VLAN:
		return "vlan";
	}
	return "other";
}

void * get_in_addr(struct sockaddr *sa) {
	switch (sa->sa_family) {
	case AF_INET:
		return &(((struct sockaddr_in *) sa)->sin_addr );
	case AF_INET6:
		return &(((struct sockaddr_in6*) sa)->sin6_addr);
	}
	return NULL;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


void processA(PSoderoFlowDatum datum, int value) {
	datum->bytes += value;
	datum->count ++;
}

void processE(PSoderoUnitDatum datum, int value) {
	if (datum->count) {
		datum->sum += value;
		if (datum->min > value)
			datum->min = value;
		if (datum->max < value)
			datum->max = value;
	} else {
		datum->sum += value;
		datum->min = value;
		datum->max = value;
	}
	datum->count ++;
}

void processEE(PSoderoUnitDatum datum1, PSoderoUnitDatum datum2)
{
	if (!datum2->count)
		return;

	//printf("processEE:: %llx, %llx, %llx, %llx\r\n", datum2->count, datum2->max, datum2->min, datum2->sum);
	if (datum1->count) {
		datum1->sum += datum2->sum;
		datum1->count += datum2->count;
		if (datum1->min > datum2->min)
			datum1->min = datum2->min;
		if (datum1->max < datum2->max)
			datum1->max = datum2->max;
	} else {
		datum1->sum = datum2->sum;
		datum1->min = datum2->min;
		datum2->max = datum2->max;
		datum1->count = datum2->count;
	}

	datum2->count = 0;
	datum2->min = 0;
	datum2->max = 0;
	datum2->sum = 0;
}

void processP(PSoderoPacketDatum datum, int value) {
	processA(&datum->total, value);


#ifdef __PACKET_RANKS__
	int index = value / CACHE_LINE;
	if (index >= IP_PACKET_SIZE_LEVEL) index = IP_PACKET_SIZE_LEVEL - 1;
	processA(&datum->ranks[index], value);
#else
	do {
		if (value <=   64) {
			processA(&datum->b___64, value);
			break;
		}
		if (value <=  128) {
			processA(&datum->b__128, value);
			break;
		}
		if (value <=  256) {
			processA(&datum->b__256, value);
			break;
		}
		if (value <=  512) {
			processA(&datum->b__512, value);
			break;
		}
		if (value <= 1024) {
			processA(&datum->b_1024, value);
			break;
		}
		if (value <= 1514) {
			processA(&datum->b_1514, value);
			break;
		}
		if (value <= 1518) {
			processA(&datum->b_1518, value);
			break;
		}
		processA(&datum->bjumbo, value);
	} while (false);
#endif
}

void processDV(PSoderoDoubleValue datum, int size, int dir) {
	if (dir < 0) {
		datum->incoming += size;
		return;
	}
	if (dir > 0) {
		datum->outgoing += size;
		return;
	}
}

void processSD(PSoderoSingleDatum datum, int size) {
	processA(&datum->value, size);
}

void processDD(PSoderoDoubleDatum datum, int size, int dir) {
	if (dir < 0) {
		processA(&datum->incoming, size);
		return;
	}
	if (dir > 0) {
		processA(&datum->outgoing, size);
		return;
	}
}

void processSP(PSoderoSingleDetail datum, int size) {
	processP(&datum->value, size);
}

void processDP(PSoderoDoubleDetail datum, int size, int dir) {
	if (dir < 0) {
		processP(&datum->incoming, size);
		return;
	}
	if (dir > 0) {
		processP(&datum->outgoing, size);
		return;
	}
}


///////////////////////////////////////////////////////////////////////////////////////////////////


void sodero_initialize_memory_buffer(PSoderoMemoryBuffer object, size_t size) {
	if (object) {
		object->size = size;
		object->root = nullptr;
	}
}

void sodero_finalize_memory_buffer(PSoderoMemoryBuffer object) {
	sodero_buffer_memory_clean(object);
}

PSoderoMemoryBuffer sodero_create_memory_buffer(size_t size) {
	PSoderoMemoryBuffer result = (PSoderoMemoryBuffer) takeBuffer(sizeof(*result));
	if (result) {
		bzero(result, sizeof(*result));
		sodero_initialize_memory_buffer(result, size);
	}
	return result;
}

void sodero_destroy_memory_buffer(PSoderoMemoryBuffer object) {
	if (object) {
		sodero_finalize_memory_buffer(object);
		freeBuffer(object);
	}
}

TObject sodero_buffer_shrink(PSoderoMemoryBuffer object, int count) {
	if (object) {
		PSoderoMemoryBlock block = object->root;

		while(block) {
			PSoderoMemoryBlock next = block->link;
			freeBuffer(block);
			block = next;

			if (count < 0) continue;
			if (count > 0) {
				count--;
				continue;
			}
			break;
		}

		object->root = block;
		return block ? block+1 : nullptr;
	}
	return nullptr;
}

void sodero_buffer_memory_clean(PSoderoMemoryBuffer object) {
	if (object)
		sodero_buffer_shrink(object, -1);
}

TObject sodero_buffer_create_block(PSoderoMemoryBuffer object, size_t size) {
	if (object) {
		size += object->size;
		PSoderoMemoryBlock result = takeBuffer(size);

		if (result) {
			printf("Create buffer block %lu bytes @ %p\n", size, result);
			bzero(result, size);
			result->link = object->root;
			object->root = result;
			return result+1;
		}
	}
	return nullptr;
}

TObject sodero_buffer_create_chunk(PSoderoMemoryBuffer object) {
	return sodero_buffer_create_block(object, object->size);
}


///////////////////////////////////////////////////////////////////////////////////////////////////


void sodero_initialize_memory_manager(PSoderoMemoryManager object, size_t size) {
	if (object)
		sodero_initialize_memory_buffer(&object->buffer, size);
}

void sodero_finalize_memory_manager(PSoderoMemoryManager object) {
	if (object)
		sodero_memory_clean(object);
}

PSoderoMemoryManager sodero_create_memory_manager(size_t size) {
	PSoderoMemoryManager result = takeBuffer(sizeof(*result));

	if (result) {
		bzero(result, sizeof(*result));
		sodero_initialize_memory_manager(result, size);
	}

	return result;
}

void sodero_destroy_memory_manager(PSoderoMemoryManager object) {
	if (object) {
		sodero_finalize_memory_manager(object);
		freeBuffer(object);
	}
}

void sodero_memory_clean(PSoderoMemoryManager object) {
	if (object)
		sodero_buffer_memory_clean(&object->buffer);
}

TObject sodero_memory_take(PSoderoMemoryManager object, size_t size) {
	if (object) {
		if (size > (object->buffer.size / 16))
			return sodero_buffer_create_block(&object->buffer, size);

		if (object->left < size) {
			object->base = (long) sodero_buffer_create_chunk(&object->buffer);
			object->left = object->buffer.size;
		}

		if (object->base) {
			TObject result = (TObject) object->base;
			object->base += size;
			object->left -= size;
			return result;
		}
	}
	return nullptr;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


void sodero_initialize_stack(PSoderoStack object, size_t size) {
	if (object)
		sodero_initialize_memory_buffer(&object->buffer, size);
}

void sodero_finalize_stack(PSoderoStack object) {
	if (object)
		sodero_finalize_memory_buffer(&object->buffer);
}

PSoderoStack sodero_create_stack(size_t size) {
	PSoderoStack result = takeBuffer(sizeof(*result));

	if (result) {
		bzero(result, sizeof(*result));
		sodero_initialize_stack(result, size);
	}

	return result;
}

void sodero_destroy_stack(PSoderoStack object) {
	if (object) {
		sodero_finalize_stack(object);
		freeBuffer(object);
	}
}

void sodero_stack_clean(PSoderoStack object) {
	object->items = nullptr;
	object->count = 0;
	object->index = 0;

	sodero_buffer_memory_clean(&object->buffer);
}

size_t sodero_stack_size(PSoderoStack object) {
	return object ? object->count : 0;
}

void sodero_stack_push(PSoderoStack object, TObject value) {
	if(object) {
		if (object->index == 0) {
			object->items = (TObject*) sodero_buffer_create_block(&object->buffer, object->buffer.size * sizeof(TObject));
			object->index = object->buffer.size;
		}
		if (object->items) {
			object->index--;
			object->items[object->index] = value;
			object->count++;
		}
	}
}

TObject sodero_stack_pop(PSoderoStack object) {
	if (object) {
		if (object->index >= object->buffer.size) {
			object->items = sodero_buffer_shrink(&object->buffer, 1);
			object->index = 0;
		}
		if (object->items) {
			object->count--;
			TObject result = object->items[object->index];
			object->index++;
			return result;
		}
	}
	return nullptr;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


void sodero_initialize_memory_pool(PSoderoMemoryPool object, size_t level, size_t size) {
	if (object) {
		object->level = level;
		object->bytes = level * CACHE_LINE;
		object->items = takeBuffer(level * sizeof(*object->items));
		if (!object->items) return;
		printf("Create memory pool %lu bytes @ %p\n", level * sizeof(*object->items), object->items);
		bzero(object->items, level * sizeof(*object->items));
		sodero_initialize_memory_manager(&object->memory, size);
	}
}

void sodero_finalize_memory_pool(PSoderoMemoryPool object) {
	if (object) {
		sodero_finalize_memory_manager(&object->memory);
		freeBuffer(object->items);
	}
}

PSoderoMemoryPool sodero_create_memory_pool(size_t level, size_t size) {
	PSoderoMemoryPool result = takeBuffer(sizeof(*result));

	if (result) {
		bzero(result, sizeof(*result));
		sodero_initialize_memory_pool(result, level, size);
		if (!result->items) {
			freeBuffer(result);
			return nullptr;
		}
	}

	return result;
}

void sodero_destroy_memory_pool(PSoderoMemoryPool object) {
	if (object) {
		sodero_finalize_memory_pool(object);
		freeBuffer(object);
	}
}

void sodero_pool_clean(PSoderoMemoryPool object) {

}

size_t sodero_pool_size(PSoderoMemoryPool object) {
	return object ? object->count : 0;
}


static inline
int sodero_pool_size2index(size_t size) {
	return CACHE_ALIGN(size);
}

static inline
void sodero_pool_put(PSoderoMemoryPool object, TObject value, size_t size) {
	int index = sodero_pool_size2index(size);
	*(TObject*) value = object->items[index];
	object->items[index] = value;

	object->count--;
}


static inline
TObject sodero_pool_get(PSoderoMemoryPool object, size_t size) {
	int index = sodero_pool_size2index(size);

	TObject result = object->items[index];
	if (result)
		object->items[index] = *(TObject*) result;
	else
		result = sodero_memory_take(&object->memory, size);

	object->count++;

	return result;
}

void sodero_pool_free(PSoderoMemoryPool object, TObject value) {
	if (value) {
		value -= 1;
		unsigned int size = *(unsigned int *) value;
		if (size > object->bytes)
			freeBuffer(value);
		else
			sodero_pool_put(object, value, size);
	}
}

TObject sodero_pool_take(PSoderoMemoryPool object, size_t size) {
	size = CACHE_ALIGN(size + sizeof(TObject));

	TObject result = (TObject)(size > object->bytes ? ({
			TObject temp = takeBuffer(size);
			printf("Create pool take %lu bytes @ %p\n", size, temp);
			temp;
		}) : sodero_pool_get(object, size));

	if (result) {
		bzero(result, size);
		*(unsigned int *)result = size;
		object->count++;
		return result+1;
	}

	return nullptr;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


PSoderoPointerPool sodero_create_pointer_pool(void) {
	PSoderoPointerPool result = (PSoderoPointerPool) takeBuffer(sizeof(TSoderoPointerPool));
	if (result) {
		bzero(result, sizeof(*result));
	}
	return result;
}

void sodero_destroy_pointer_pool(PSoderoPointerPool object) {
	if (object) {
		sodero_pointer_clean(object);
		freeBuffer(object);
	}
}

size_t sodero_pointer_count(PSoderoPointerPool object) {
	return object->count;
}

void sodero_pointer_clean(PSoderoPointerPool object) {
	sodero_pointer_reset(object);
	sodero_pointer_shrink(object);
}

void sodero_pointer_shrink(PSoderoPointerPool object) {
	if (object->count > 65536) {
		unsigned int count = object->count / 65536;
		for (unsigned int i = count; i < 65535; i++) {
			TSoderoPointerBlock * block = object->index[i];
			if (block) {
				object->index[i] = nullptr;
				freeBuffer(block);
			} else
				break;
		}
	}
}

void sodero_pointer_reset(PSoderoPointerPool object) {
	if (object->count > 65536) {
		bzero(object->block, sizeof(*object->block));
		unsigned int count = object->count / 65536;
		for (unsigned int i = 1; i <= count; i++) {
			TSoderoPointerBlock * block = object->index[i];
			if (block)
				bzero(block, sizeof(*block));
		}
	} else
		bzero(object->block, object->count * sizeof(void*));

	object->count = 0;
}

void * sodero_pointer_get(PSoderoPointerPool object, unsigned int index) {
	if (index < object->count) {
		if (index > 65536) {
			unsigned int serial = index / 65536;
			unsigned int offset = index % 65536;
			TSoderoPointerBlock * block = object->index[serial];
			return block ? block[offset] : nullptr;
		}
		return object->block[index];
	}
	return nullptr;
}

long sodero_pointer_add(PSoderoPointerPool object, void * pointer) {
	if (object->count >= 65536) {
		unsigned int serial = object->count / 65536;
		unsigned int offset = object->count % 65536;
		TSoderoPointerBlock * block = object->index[serial];
		if (!block) {
			block = takeBuffer(sizeof(*block));
			if (!block) return -1;
			printf("Create pointer block %lu bytes @ %p to %u\n", sizeof(*block), block, serial);
			bzero(block, sizeof(*block));
			object->index[serial] = block;
		}
		(*block)[offset] = pointer;
	} else
		object->block[object->count] = pointer;
	object->count++;
	return object->count;
}

long sodero_pointer_foreach(PSoderoPointerPool object, TforeachPointerHandlor handlor, void * data) {
	long result = 0;
	if (object->count > 65536) {
		for (unsigned int i = 0; i < 65536; i++)
			handlor(object, i, object->block[i], data);

		unsigned int serial = object->count / 65536;
		unsigned int offset = object->count % 65536;
		for (unsigned int i = 1; i < serial - 1; i++) {
			TSoderoPointerBlock * block = object->index[i];
			for (unsigned int j = 0; j < 65536; j++)
				if(handlor(object, result++, (*block)[j], data)) return -result;
		}

		TSoderoPointerBlock * block = object->index[serial];
		for (unsigned int i = 0; i < offset; i++)
			if (handlor(object, result++, (*block)[i], data)) return -result;
	} else
		for (unsigned int i = 0; i < object->count; i++)
			if (handlor(object, result++, object->block[i], data)) return -result;

	return object->count;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct SODERO_MAP_NODE_PAIR {
	PSoderoMapNode link;
	PSoderoMapNode node;
} TSoderoMapNodePair, * PSoderoMapNodePair;

static inline
void map_link_node(PSoderoMapNode root, PSoderoMapNode leaf) {
	root->link = leaf;
}

static inline
TContainerKey map_node_key(PSoderoMapNode node) {
	return (TContainerKey)node->key;
}

static inline
TContainerValue map_node_value(PSoderoMapNode node) {
	return node->value;
}

static inline
PSoderoMapNode map_node_next(PSoderoMapNode node) {
	return node ? node->link : nullptr;
}

//static inline
//PSoderoMapNode map_slide_prev(PSoderoMapNode node) {
//	return node ? node->prev : nullptr;
//}

static inline
PSoderoMapNode map_slide_next(PSoderoMapNode node) {
	return node ? node->next : nullptr;
}

static inline
unsigned long sodero_map_hash(PSoderoMap container, TContainerKey key) {
	return container->scatter ? container->scatter(key) : (long) key;
}

static inline
unsigned long sodero_map_index(PSoderoMap container, TContainerKey key) {
	return sodero_map_hash(container, key) % container->length;
}

static inline
long sodero_map_compare(PSoderoMap container, TContainerKey a, TContainerKey b) {
	return container->comparer ? container->comparer(a, b) : ((long) a) - ((long)b);
}

static inline
void sodero_map_duplicator(PSoderoMap container, TContainerKey dest, TContainerKey sour) {
	if (container->duplicator)
		container->duplicator(dest, sour);
	else
		memcpy(dest, sour, container->size);
}

static inline
void sodero_map_drop_node(PSoderoMap container, PSoderoMapNode node) {
	if (node) {
		if (container->mode) {
			TContainerKey   key   = map_node_key  (node);
			TContainerValue value = map_node_value(node);
			if (value) {
				if (container->releaser)
					container->releaser(container, key, value);
				else
					freeBuffer(value);
			}
		}

		if (node->prev)
			node->prev->next = node->next;
		if (node->next)
			node->next->prev = node->prev;

		if (container->head == node)
			container->head = node->next;
		if (container->tail == node)
			container->tail = node->prev;

		node->next = nullptr;
		node->prev = nullptr;

		node->link = container->nodes;
		container->nodes = node;
	}
}

static inline
void sodero_map_init_nodes(PSoderoMap container) {
	if (container->delta) {
		size_t length = container->room;
		size_t size = container->delta * length + sizeof(TSoderoMemoryBlock);
		PSoderoMemoryBlock block = takeBuffer(size);
		if (block) {
			printf("Create map nodes %lu bytes @ %p\n", size, block);
			bzero(block, size);
			block->link = container->block;
			container->block = block;

			long nodes = (long)(block+1);
			for (int i = 0; i < container->delta; i++) {
				sodero_map_drop_node(container, (PSoderoMapNode) nodes);
				nodes += length;
			}
		}
	}
}

static inline
void sodero_map_check_nodes(PSoderoMap container) {
	if (container->nodes) return;
	sodero_map_init_nodes(container);
}

static inline
PSoderoMapNode sodero_map_take_node(PSoderoMap container) {
	sodero_map_check_nodes(container);

	PSoderoMapNode result = container->nodes;

	if (result) {
		container->nodes = map_node_next(result);
		bzero(result, container->room);

		result->next = nullptr;
		result->prev = container->tail;

		if (container->tail)
			container->tail->next = result;
		else
			container->head = result;

		container->tail = result;
	}

	return result;
}

PSoderoMap sodero_map_create(long length, int delta, int size, int mode, void * data,
	THashHandlor scatter, TEqualHandlor comparer, TKeyDuplicator duplicator,
	TCreateHandlor creater, TReleaseHandlor releaser, TCleanHandlor cleaner) {
	PSoderoMap result = (PSoderoMap) takeBuffer(sizeof(*result));
	if (result) {
		if (length < SODERO_MAP_BUCKET_LENGTH_MIN)
			length = SODERO_MAP_BUCKET_LENGTH_MIN;
		if (delta < SODERO_MAP_BLOCK_COUNT_MIN)
			delta = SODERO_MAP_BLOCK_COUNT_MIN;

		bzero(result, sizeof(*result));
		result->length = length;
		result->delta  = delta ;
		result->size   = size  ;
		result->data   = data  ;
		result->mode   = mode  ;

		result->room = CACHE_ALIGN(sizeof(TSoderoMapNode) + size);

		result->buckets = (PSoderoMapNode*) takeBuffer(length * sizeof(PSoderoMapNode));
		if (!result->buckets) {
			freeBuffer(result);
			return nullptr;
		}
		printf("Create buffer buckets %lu bytes @ %p\n", length * sizeof(PSoderoMapNode), result->buckets);
		bzero(result->buckets, length * sizeof(PSoderoMapNode));

		result->scatter  = scatter ;
		result->comparer = comparer;
		result->duplicator = duplicator;

		result->creater = creater;
		result->cleaner = cleaner;
		result->releaser = releaser;

		sodero_map_init_nodes(result);
	}
	return result;
}

PSoderoMap sodero_map_create_simple(long length, int delta, int size) {
	return sodero_map_create(length, delta, size, SODERO_MAP_MODE_NONE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

void sodero_map_destroy(PSoderoMap container) {
	sodero_map_clean(container);
	if (container) {
		if (container->block  ) freeBuffer(container->block  );
		if (container->buckets) freeBuffer(container->buckets);
		freeBuffer(container);
	}
}

void sodero_map_clean(PSoderoMap container) {
	for (long i = 0; i < container->length; i++) {
		PSoderoMapNode node = container->buckets[i];
		while(node) {
			PSoderoMapNode next = map_node_next(node);
			sodero_map_drop_node(container, node);
			node = next;
		}
	}
	bzero(container->buckets, container->length * sizeof(*container->buckets));

	container->count = 0;
}

#ifdef __TAIL__
PSoderoMapNode sodero_map_bucket_tail (PSoderoMap container, long index) {
	PSoderoMapNode prev = nullptr;
	PSoderoMapNode curr = container->buckets[index];
	while(curr) {
		prev = curr;
		curr = map_node_next(curr);
	}
	return prev;
}
#endif

static
TContainerValue sodero_map_add (PSoderoMap container, long index, TContainerKey k, TContainerValue v
#ifdef __TAIL__
		, PSoderoMapNode prev
#endif
		) {
	PSoderoMapNode node = sodero_map_take_node(container);

	if (!node)
		return v;

	node->value = v;
	sodero_map_duplicator(container, map_node_key(node), k);

#ifdef __TAIL__
	if (prev)
		map_link_node(prev, node);
	else
		container->buckets[index] = node;
#else
	map_link_node(node, container->buckets[index]);
	container->buckets[index] = node;

	container->count++;
#endif
	return nullptr;
}

TSoderoMapNodePair sodero_map_find(PSoderoMap container, long index, TContainerKey k) {
	TSoderoMapNodePair result = {nullptr, container->buckets[index]};
	while(result.node) {
		if (sodero_map_compare(container, map_node_key(result.node), k) == 0) break;
		result.link = result.node;
		result.node = result.node->link;
	}
	return result;
}

size_t sodero_map_count(PSoderoMap container) {
	return container ? container->count : 0;
}

TContainerValue sodero_map_lookup(PSoderoMap container, TContainerKey k) {
	if (container) {
		long index = sodero_map_index(container, k);

		PSoderoMapNode curr = container->buckets[index];
		while(curr) {
			if (sodero_map_compare(container, map_node_key(curr), k) == 0) {
//				sodero_map_duplicator(container, map_node_key(curr), k);
				return map_node_value(curr);
			}
			curr = map_node_next(curr);
		}
	}
	return nullptr;
}

TContainerValue sodero_map_append(PSoderoMap container, TContainerKey k, TContainerValue v) {
	if (container) {
		long index = sodero_map_index(container, k);

#ifdef __TAIL__
		return sodero_map_add(container, index, k, v, sodero_map_bucket_tail(container, index));
#else
		return sodero_map_add(container, index, k, v);
#endif

	}
	return nullptr;
}

TContainerValue sodero_map_insert(PSoderoMap container, TContainerKey k, TContainerValue v) {
	if (container) {
		long index = sodero_map_index(container, k);

#ifdef __TAIL__
		PSoderoMapNode prev = nullptr;
#endif
		PSoderoMapNode curr = container->buckets[index];
		while(curr) {
			if (sodero_map_compare(container, map_node_key(curr), k) == 0) break;
#ifdef __TAIL__
			prev = curr;
#endif
			curr = map_node_next(curr);
		}

		if (curr) {
//			sodero_map_duplicator(container, map_node_key(curr), k);
			return map_node_value(curr);	 //	Key already exists
		}

#ifdef __TAIL__
		return sodero_map_add(container, index, k, v, sodero_map_bucket_tail(container, index));
#else
		return sodero_map_add(container, index, k, v);
#endif
	}
	return nullptr;
}

TContainerValue sodero_map_remove(PSoderoMap container, TContainerKey k) {
	if (container) {
		long index = sodero_map_index(container, k);

		PSoderoMapNode prev = nullptr;
		PSoderoMapNode curr = container->buckets[index];
		while(curr) {
			if (sodero_map_compare(container, map_node_key(curr), k) == 0) break;
			prev = curr;
			curr = map_node_next(curr);
		}

		if (curr) {
			if (prev)
				map_link_node(prev, map_node_next(curr));
			else
				container->buckets[index] = map_node_next(curr);

			container->count--;

			TContainerValue result = map_node_value(curr);
			sodero_map_drop_node(container, curr);
			return result;
		}

	}
	return nullptr;
}

TContainerValue sodero_map_replace(PSoderoMap container, TContainerKey k, TContainerValue v) {
	if (container) {
		long index = sodero_map_index(container, k);

#ifdef __TAIL__
		PSoderoMapNode prev = nullptr;
#endif
		PSoderoMapNode curr = container->buckets[index];
		while(curr) {
			if (sodero_map_compare(container, map_node_key(curr), k) == 0) break;
#ifdef __TAIL__
			prev = curr;
#endif
			curr = map_node_next(curr);
		}

		if (curr) {
			TContainerValue result = map_node_value(curr);
			sodero_map_duplicator(container, map_node_key(curr), k);
			curr->value = v;
			return result;
		}

#ifdef __TAIL__
		return sodero_map_add(container, index, k, v, prev);
#else
		return sodero_map_add(container, index, k, v);
#endif
	}
	return nullptr;
}


TContainerValue sodero_map_ensure(PSoderoMap container, TContainerKey k) {
	if (container) {
		long index = sodero_map_index(container, k);

#ifdef __TAIL__
		PSoderoMapNode prev = nullptr;
#endif
		PSoderoMapNode curr = container->buckets[index];
		while(curr) {
			if (sodero_map_compare(container, map_node_key(curr), k) == 0) break;
#ifdef __TAIL__
			prev = curr;
#endif
			curr = map_node_next(curr);
		}

		if (curr) {
//			sodero_map_duplicator(container, map_node_key(curr), k);
			return map_node_value(curr);
		}

		TContainerValue v = container->creater ? container->creater(k, container) : nullptr;

		if (v)
			return sodero_map_add(container, index, k, v
#ifdef __TAIL__
					,prev
#endif
			) ? nullptr : v;
	}
	return nullptr;
}

long sodero_map_foreach(PSoderoMap container, TforeachMapHandlor handlor, void * data) {
	if (!handlor) return -1;
	long result = 0;
//	for (long i = 0; i < container->length; i++) {
//		PSoderoMapNode node = container->buckets[i];
//		while(node) {
//			if (handlor(container, result++, map_node_key(node), map_node_value(node), data)) return -result;
//			node = map_node_next(node);
//		}
//	}
	PSoderoMapNode node = container->head;
	while(node) {
		if (handlor(container, result++, map_node_key(node), map_node_value(node), data)) return -result;
		node = map_slide_next(node);
	}

	return result;
}


///////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct SODERO_TABLE_NODE_PAIR {
	PSoderoTableNode link;
	PSoderoTableNode node;
} TSoderoTableNodePair, * PSoderoTableNodePair;

static inline
void table_link_node(PSoderoTableNode root, PSoderoTableNode leaf) {
	root->link = leaf;
}

static inline
TContainerValue table_node_value(PSoderoTableNode node) {
	return node->value;
}

static inline
PSoderoTableNode table_node_next(PSoderoTableNode node) {
	return node ? node->link : nullptr;
}

//static inline
//PSoderoTableNode table_slide_prev(PSoderoTableNode node) {
//	return node ? node->prev : nullptr;
//}

static inline
PSoderoTableNode table_slide_next(PSoderoTableNode node) {
	return node ? node->next : nullptr;
}

static inline
unsigned long sodero_table_hash(PSoderoTable container, TContainerKey key) {
	return container->scatter ? container->scatter(key) : *(unsigned long long *) key;
}

static inline
unsigned long sodero_table_index(PSoderoTable container, TContainerKey key) {
	return sodero_table_hash(container, key) % container->length;
}

static inline
long sodero_table_compare(PSoderoTable container, TContainerKey a, TContainerKey b) {
	return container->comparer ? container->comparer(a, b) : *((unsigned long long *) a) - *((unsigned long long *)b);
}

static inline
TContainerKey sodero_table_keyof(PSoderoTable container, TContainerValue value) {
	return container->keyof ? container->keyof(value) : (TContainerKey) value;
}

static inline
void sodero_table_drop_node(PSoderoTable container, PSoderoTableNode node) {
	if (node) {
		if (container->mode) {
			TContainerKey key = sodero_table_keyof(container, node);
			TContainerValue value = table_node_value(node);
			if (value) {
				if (container->releaser)
					container->releaser(container, key, value);
				else
					freeMemory(value);
			}
		}

		if (node->prev)
			node->prev->next = node->next;
		if (node->next)
			node->next->prev = node->prev;

		if (container->head == node)
			container->head = node->next;
		if (container->tail == node)
			container->tail = node->prev;

		node->next = nullptr;
		node->prev = nullptr;

		node->link = container->nodes;
		container->nodes = node;
	}
}

static inline
void sodero_table_init_nodes(PSoderoTable container) {
	if (container->delta) {
		size_t length = container->room;
		size_t size = container->delta * length + sizeof(TSoderoMemoryBlock);
		PSoderoMemoryBlock block = takeBuffer(size);
		if (block) {
			bzero(block, size);
			block->link = container->block;
			container->block = block;

			long nodes = (long)(block+1);
			for (int i = 0; i < container->delta; i++) {
				sodero_table_drop_node(container, (PSoderoTableNode) nodes);
				nodes += length;
			}
		}
	}
}

static inline
void sodero_table_check_nodes(PSoderoTable container) {
	if (container->nodes) return;
	sodero_table_init_nodes(container);
}

static inline
PSoderoTableNode sodero_table_take_node(PSoderoTable container) {
	sodero_table_check_nodes(container);

	PSoderoTableNode result = container->nodes;

	if (result) {
		container->nodes = table_node_next(result);
		bzero(result, container->room);

		result->next = nullptr;
		result->prev = container->tail;

		if (container->tail)
			container->tail->next = result;
		else
			container->head = result;

		container->tail = result;
	}

	return result;
}

int sodero_table_init(PSoderoTable container, long length, int delta, int size, int mode, void * data,
	THashHandlor scatter, TEqualHandlor comparer, TSoderoObjectKey keyof,
	TCreateHandlor creater, TReleaseHandlor releaser, TCleanHandlor cleaner) {
	if (container) {
		if (length < SODERO_TABLE_BUCKET_LENGTH_MIN)
			length = SODERO_TABLE_BUCKET_LENGTH_MIN;
		if (delta < SODERO_TABLE_BLOCK_COUNT_MIN)
			delta = SODERO_TABLE_BLOCK_COUNT_MIN;

		bzero(container, sizeof(*container));
		container->length = length;
		container->delta  = delta ;
		container->size   = size  ;
		container->data   = data  ;
		container->mode   = mode  ;

		container->room = CACHE_ALIGN(sizeof(TSoderoTableNode) + size);

		container->buckets = (PSoderoTableNode*) takeBuffer(length * sizeof(PSoderoTableNode));
		if (!container->buckets)
			return false;
		printf("Create table buckets %lu bytes @ %p\n", length * sizeof(PSoderoMapNode), container->buckets);
		bzero(container->buckets, length * sizeof(PSoderoTableNode));

		container->scatter  = scatter ;
		container->comparer = comparer;
		container->keyof = keyof;

		container->creater = creater;
		container->cleaner = cleaner;
		container->releaser = releaser;

		sodero_table_init_nodes(container);
	}
	return true;
}


PSoderoTable sodero_table_create(long length, int delta, int size, int mode, void * data,
	THashHandlor scatter, TEqualHandlor comparer, TSoderoObjectKey keyof,
	TCreateHandlor creater, TReleaseHandlor releaser, TCleanHandlor cleaner) {
	PSoderoTable result = (PSoderoTable) takeBuffer(sizeof(*result));
	int ret = sodero_table_init(result, length, delta, size, mode, data, scatter, comparer, keyof, creater, releaser, cleaner);
	if (ret)
		return result;
	freeBuffer(result);
	return nullptr;
}

PSoderoTable sodero_table_create_simple(long length, int delta, int size) {
	return sodero_table_create(length, delta, size, SODERO_TABLE_MODE_NONE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

void sodero_table_destroy(PSoderoTable container) {
	sodero_table_clean(container);
	if (container) {
		if (container->block  ) freeBuffer(container->block  );
		if (container->buckets) freeBuffer(container->buckets);
		freeBuffer(container);
	}
}

void sodero_table_clean(PSoderoTable container) {
	for (long i = 0; i < container->length; i++) {
		PSoderoTableNode node = container->buckets[i];
		while(node) {
			PSoderoTableNode next = table_node_next(node);
			sodero_table_drop_node(container, node);
			node = next;
		}
	}
	bzero(container->buckets, container->length * sizeof(*container->buckets));

	container->count = 0;
}

#ifdef __TAIL__
PSoderoTableNode sodero_table_bucket_tail (PSoderoTable container, long index) {
	PSoderoTableNode prev = nullptr;
	PSoderoTableNode curr = container->buckets[index];
	while(curr) {
		prev = curr;
		curr = table_node_next(curr);
	}
	return prev;
}
#endif

static
TContainerValue sodero_table_add (PSoderoTable container, long index, TContainerKey k, TContainerValue v
#ifdef __TAIL__
		, PSoderoTableNode prev
#endif
		) {
	PSoderoTableNode node = sodero_table_take_node(container);

	if (!node)
		return v;

	node->value = v;

#ifdef __TAIL__
	if (prev)
		table_link_node(prev, node);
	else
		container->buckets[index] = node;
#else
	table_link_node(node, container->buckets[index]);
	container->buckets[index] = node;

	container->count++;
#endif
	return nullptr;
}

TSoderoTableNodePair sodero_table_find(PSoderoTable container, long index, TContainerKey k) {
	TSoderoTableNodePair result = {nullptr, container->buckets[index]};
	while(result.node) {
		TContainerValue v = table_node_value(result.node);
		if (sodero_table_compare(container, sodero_table_keyof(container, v), k) == 0) break;
		result.link = result.node;
		result.node = result.node->link;
	}
	return result;
}

size_t sodero_table_count(PSoderoTable container) {
	return container ? container->count : 0;
}

TContainerValue sodero_table_lookup(PSoderoTable container, TContainerKey k) {
	if (container) {
		long index = sodero_table_index(container, k);

		PSoderoTableNode curr = container->buckets[index];
		while(curr) {
			TContainerValue v = table_node_value(curr);
			if (sodero_table_compare(container, sodero_table_keyof(container, v), k) == 0) {
				return v;
			}
			curr = table_node_next(curr);
		}
	}
	return nullptr;
}

TContainerValue sodero_table_append(PSoderoTable container, TContainerValue v) {
	if (container) {
		TContainerKey k = sodero_table_keyof(container, v);
		long index = sodero_table_index(container, k);

#ifdef __TAIL__
		return sodero_table_add(container, index, k, v, sodero_table_bucket_tail(container, index));
#else
		return sodero_table_add(container, index, k, v);
#endif

	}
	return nullptr;
}

TContainerValue sodero_table_insert(PSoderoTable container, TContainerValue v) {
	if (container) {
		TContainerKey k = sodero_table_keyof(container, v);
		long index = sodero_table_index(container, k);

#ifdef __TAIL__
		PSoderoTableNode prev = nullptr;
#endif
		PSoderoTableNode curr = container->buckets[index];
		while(curr) {
			TContainerValue v = table_node_value(curr);
			if (sodero_table_compare(container, sodero_table_keyof(container, v), k) == 0) break;
#ifdef __TAIL__
			prev = curr;
#endif
			curr = table_node_next(curr);
		}

		if (curr) {
			return table_node_value(curr);	 //	Key already exists
		}

#ifdef __TAIL__
		return sodero_table_add(container, index, k, v, sodero_table_bucket_tail(container, index));
#else
		return sodero_table_add(container, index, k, v);
#endif
	}
	return nullptr;
}

TContainerValue sodero_table_remove(PSoderoTable container, TContainerKey k) {
	if (container) {
		long index = sodero_table_index(container, k);

		PSoderoTableNode prev = nullptr;
		PSoderoTableNode curr = container->buckets[index];
		while(curr) {
			TContainerValue v = table_node_value(curr);
			if (sodero_table_compare(container, sodero_table_keyof(container, v), k) == 0) break;
			prev = curr;
			curr = table_node_next(curr);
		}

		if (curr) {
			if (prev)
				table_link_node(prev, table_node_next(curr));
			else
				container->buckets[index] = table_node_next(curr);

			container->count--;

			TContainerValue result = table_node_value(curr);
			sodero_table_drop_node(container, curr);
			return result;
		}

	}
	return nullptr;
}

TContainerValue sodero_table_delete(PSoderoTable container, TContainerValue v) {
	TContainerKey k = sodero_table_keyof(container, v);
	return sodero_table_remove(container, k);
}

TContainerValue sodero_table_replace(PSoderoTable container, TContainerValue v) {
	if (container) {
		TContainerKey k = sodero_table_keyof(container, v);
		long index = sodero_table_index(container, k);

#ifdef __TAIL__
		PSoderoTableNode prev = nullptr;
#endif
		PSoderoTableNode curr = container->buckets[index];
		while(curr) {
			TContainerValue v = table_node_value(curr);
			if (sodero_table_compare(container, sodero_table_keyof(container, v), k) == 0) break;
#ifdef __TAIL__
			prev = curr;
#endif
			curr = table_node_next(curr);
		}

		if (curr) {
			TContainerValue result = table_node_value(curr);
			curr->value = v;
			return result;
		}

#ifdef __TAIL__
		return sodero_table_add(container, index, k, v, prev);
#else
		return sodero_table_add(container, index, k, v);
#endif
	}
	return nullptr;
}


TContainerValue sodero_table_ensure(PSoderoTable container, TContainerKey k) {
	if (container) {
		long index = sodero_table_index(container, k);

#ifdef __TAIL__
		PSoderoTableNode prev = nullptr;
#endif
		PSoderoTableNode curr = container->buckets[index];
		while(curr) {
			TContainerValue v = table_node_value(curr);
			if (sodero_table_compare(container, sodero_table_keyof(container, v), k) == 0) break;
#ifdef __TAIL__
			prev = curr;
#endif
			curr = table_node_next(curr);
		}

		if (curr) {
			return table_node_value(curr);
		}

		TContainerValue v = container->creater ? container->creater(k, container) : nullptr;

		if (v)
			return sodero_table_add(container, index, k, v
#ifdef __TAIL__
					,prev
#endif
			) ? nullptr : v;
	}
	return nullptr;
}

long sodero_table_foreach(PSoderoTable container, TforeachTableHandlor handlor, void * data) {
	if (!handlor) return -1;
	long result = 0;
//	for (long i = 0; i < container->length; i++) {
//		PSoderoTableNode node = container->buckets[i];
//		while(node) {
//			if (handlor(container, result++, table_node_key(node), table_node_value(node), data)) return -result;
//			node = table_node_next(node);
//		}
//	}
	PSoderoTableNode node = container->head;
	while(node) {
		if (handlor(container, result++, table_node_value(node), data)) return -result;
		node = table_slide_next(node);
	}

	return result;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct SODERO_CONTAINER_NODE_PAIR {
	PSoderoContainerNode link;
	PSoderoContainerNode node;
} TSoderoContainerNodePair, * PSoderoContainerNodePair;


static inline
void container_link_node(PSoderoContainerNode root, PSoderoContainerNode leaf) {
	root->link = leaf;
}

static inline
TContainerValue container_node_data(PSoderoContainerNode node) {
	return (TContainerKey)node->data;
}

static inline
PSoderoContainerNode container_node_next(PSoderoContainerNode node) {
	return node ? node->link : nullptr;
}

//static inline
//PSoderoContainerNode container_slide_prev(PSoderoContainerNode node) {
//	return node ? node->prev : nullptr;
//}

static inline
PSoderoContainerNode container_slide_next(PSoderoContainerNode node) {
	return node ? node->next : nullptr;
}

#ifdef __CONTAINER_KEY__
static inline
TContainerKey container_keyof(PSoderoContainer container, TContainerValue data) {
	return container->keyof ? container->keyof(data) : (TContainerKey) data;
}
#endif

static inline
TContainerKey container_node_key(PSoderoContainer container, PSoderoContainerNode node) {
	TContainerValue value = container_node_data(node);
#ifdef __CONTAINER_KEY__
	return container_keyof(container, value);
#else
	return (TContainerKey) value;
#endif
}

static inline
unsigned long container_hash(PSoderoContainer container, TContainerKey key) {
	return container->scatter ? container->scatter(key) : (long) key;
}

static inline
unsigned long sodero_container_index(PSoderoContainer container, TContainerKey key) {
	return container_hash(container, key) % container->length;
}

static inline
long sodero_container_compare(PSoderoContainer container, TContainerKey a, TContainerKey b) {
	return container->comparer ? container->comparer(a, b) : ((long) a) - ((long)b);
}

static inline
void sodero_container_duplicator(PSoderoContainer container, TContainerKey dest, TContainerKey sour) {
	if (container->duplicator)
		container->duplicator(dest, sour);
	else
		memcpy(dest, sour, container->size);
}

static inline
void sodero_container_cut_node(PSoderoContainer container, PSoderoContainerNode node) {
	if (node->prev)
		node->prev->next = node->next;
	if (node->next)
		node->next->prev = node->prev;

	if (container->head == node)
		container->head = node->next;
	if (container->tail == node)
		container->tail = node->prev;

	node->time = nullptr;
	node->next = nullptr;
	node->prev = nullptr;
}

static inline
void sodero_container_drop_node(PSoderoContainer container, PSoderoContainerNode node) {
	if (node) {
		sodero_container_cut_node(container, node);
		node->link = container->nodes;
		container->nodes = node;
	}
}

static inline
void sodero_container_init_nodes(PSoderoContainer container) {
	if (container->delta) {
		size_t length = container->room;
		size_t size = container->delta * length + sizeof(TSoderoMemoryBlock);
		PSoderoMemoryBlock block = takeBuffer(size);
		if (block) {
			printf("Create container nodes %lu bytes @ %p\n", size, block);
			bzero(block, size);
			block->link = container->block;
			container->block = block;

			long nodes = (long)(block+1);
			for (int i = 0; i < container->delta; i++) {
				sodero_container_drop_node(container, (PSoderoContainerNode) nodes);
				nodes += length;
			}
		}
	}
}

static inline
void sodero_container_check_nodes(PSoderoContainer container) {
	if (container->nodes) return;
	sodero_container_init_nodes(container);
}

static inline
PSoderoContainerNode sodero_container_take_node(PSoderoContainer container) {
	sodero_container_check_nodes(container);

	PSoderoContainerNode result = container->nodes;
	if (result) {
		container->nodes = container_node_next(result);
		bzero(result, container->room);

		result->next = nullptr;
		result->prev = container->tail;

//		printf("Take node %p next %p prev %p\n", result, result->next, result->prev);

		if (container->tail)
			container->tail->next = result;
		else
			container->head = result;
		container->tail = result;
	}

//	printf("Take Session: %p\n", result);

	return result;
}

PSoderoContainer sodero_container_create(long length, int delta, int size, void * data,
	THashHandlor scatter, TEqualHandlor comparer, TKeyDuplicator duplicator
#ifdef __CONTAINER_KEY__
	, TSoderoObjectKey keyof
#endif
	) {
	PSoderoContainer result = (PSoderoContainer) takeBuffer(sizeof(*result));
	if (result) {
		if (length < SODERO_MAP_BUCKET_LENGTH_MIN)
			length = SODERO_MAP_BUCKET_LENGTH_MIN;
		if (delta < SODERO_MAP_BLOCK_COUNT_MIN)
			delta = SODERO_MAP_BLOCK_COUNT_MIN;

		bzero(result, sizeof(*result));
		result->length = length;
		result->delta  = delta ;
		result->size   = size  ;
		result->data   = data  ;
		result->buckets = (PSoderoContainerNode*) takeMemory(length * sizeof(PSoderoContainerNode));
		result->room   = CACHE_ALIGN(sizeof(TSoderoContainerNode) + size);
		if (!result->buckets) {
			freeBuffer(result);
			return nullptr;
		}
		bzero(result->buckets, length * sizeof(PSoderoContainerNode));

		result->scatter  = scatter ;
		result->comparer = comparer;

		result->duplicator = duplicator;
#ifdef __CONTAINER_KEY__
		result->keyof      = keyof;
#endif

		sodero_container_init_nodes(result);
	}
	return result;
}

PSoderoContainer sodero_container_create_simple(long length, int delta, int size) {
	return sodero_container_create(length, delta, size, nullptr, nullptr, nullptr, nullptr
#ifdef __CONTAINER_KEY__
			, nullptr
#endif
	);
}

void sodero_container_destroy(PSoderoContainer container) {
	sodero_container_clean(container);
	if (container) {
		if (container->block  ) freeBuffer(container->block  );
		if (container->buckets) freeBuffer(container->buckets);
		freeBuffer(container);
	}
}

void sodero_container_clean(PSoderoContainer container) {
	for (long i = 0; i < container->length; i++) {
		PSoderoContainerNode node = container->buckets[i];
		while(node) {
			PSoderoContainerNode next = container_node_next(node);

//			printf("Clean node %p next %p prev %p\n", node, node->next, node->prev);

			sodero_container_drop_node(container, node);
			node = next;
		}
	}
	bzero(container->buckets, container->length * sizeof(*container->buckets));

	container->count = 0;
}

#ifdef __TAIL__
PSoderoContainerNode sodero_container_bucket_tail (PSoderoContainer container, long index) {
	PSoderoContainerNode prev = nullptr;
	PSoderoContainerNode curr = container->buckets[index];
	while(curr) {
		prev = curr;
		curr = container_node_next(curr);
	}
	return prev;
}
#endif

static
TContainerValue sodero_container_add (PSoderoContainer container, long index, TContainerKey k
#ifdef __TAIL__
		, PSoderoContainerNode prev
#endif
		) {
	PSoderoContainerNode node = sodero_container_take_node(container);

	if (node) {
		TContainerValue v = container_node_data(node);
		sodero_container_duplicator(container, container_keyof(container, v), k);

#ifdef __TAIL__
		if (prev)
			container_link_node(prev, node);
		else
			container->buckets[index] = node;
#else
		container_link_node(node, container->buckets[index]);
		container->buckets[index] = node;

		container->count++;
		return v;
#endif
	}
	return nullptr;
}

static inline
TContainerValue sodero_container_del (PSoderoContainer container, long index,
		TContainerValue curr, PSoderoContainerNode prev) {
	if (curr) {
		PSoderoContainerNode next = container_node_next(curr);

//		printf("Del node %p next %p prev %p\n", curr, next, prev);

		if (prev)
			container_link_node(prev, next);
		else
			container->buckets[index] = next;
		TContainerValue result = container_node_data(curr);
		sodero_container_drop_node(container, curr);
		container->count--;
		return result;
	}
	return nullptr;
}

TSoderoContainerNodePair sodero_container_find(PSoderoContainer container, long index, TContainerKey k) {
	TSoderoContainerNodePair result = {nullptr, container->buckets[index]};
	while(result.node) {
		if (sodero_container_compare(container, container_node_key(container, result.node), k) == 0) break;
		result.link =                     result.node;
		result.node = container_node_next(result.node);
	}
	return result;
}

size_t sodero_container_count(PSoderoContainer container) {
	return container ? container->count : 0;
}

TContainerValue sodero_container_lookup(PSoderoContainer container, TContainerKey k) {
	if (container) {
		long index = sodero_container_index(container, k);

		PSoderoContainerNode curr = container->buckets[index];
		while(curr) {
			if (sodero_container_compare(container, container_node_key(container, curr), k) == 0)
				return container_node_data(curr);
			curr = container_node_next(curr);
		}
	}
	return nullptr;
}

TContainerValue sodero_container_remove(PSoderoContainer container, TContainerKey k) {
	if (container) {
		long index = sodero_container_index(container, k);

		PSoderoContainerNode prev = nullptr;
		PSoderoContainerNode curr = container->buckets[index];
		while(curr) {
			if (sodero_container_compare(container, container_node_key(container, curr), k) == 0) break;
			prev = curr;
			curr = container_node_next(curr);
		}

		return sodero_container_del(container, index, curr, prev);
	}
	return nullptr;
}

TContainerValue sodero_container_ensure(PSoderoContainer container, TContainerKey k) {
	if (container) {
		long index = sodero_container_index(container, k);

#ifdef __TAIL__
		PSoderoContainerNode prev = nullptr;
#endif
		PSoderoContainerNode curr = container->buckets[index];
		while(curr) {
			if (sodero_container_compare(container, container_node_key(container, curr), k) == 0) break;
#ifdef __TAIL__
			prev = curr;
#endif
			curr = container_node_next(curr);
		}

		if (curr)
			return container_node_data(curr);

		return sodero_container_add(container, index, k
#ifdef __TAIL__
					,prev
#endif
			);
	}
	return nullptr;
}

TContainerValue sodero_container_build(PSoderoContainer container, TContainerKey k) {
	if (container) {
		long index = sodero_container_index(container, k);

		PSoderoContainerNode prev = nullptr;
		PSoderoContainerNode next = nullptr;
		PSoderoContainerNode curr = container->buckets[index];
		while(curr) {
			if (sodero_container_compare(container, container_node_key(container, curr), k) == 0) break;
			prev = curr;
			curr = container_node_next(curr);
		}

		if (curr) {
			next = container_node_next(curr);
			if (prev)
				container_link_node(prev, next);
			else
				container->buckets[index] = next;

//			printf("Build node %p next %p prev %p\n", curr, curr->next, curr->prev);

			sodero_container_cut_node(container, curr);
		}

		PSoderoContainerNode node = sodero_container_take_node(container);
		if (node) {
			TContainerValue v = container_node_data(node);
			sodero_container_duplicator(container, container_keyof(container, v), k);

#ifdef __TAIL__
			if (prev) {
				while((next = container_node_next(prev->link)))
					prev = next;
				container_link_node(prev, node);
			} else
				container->buckets[index] = node;
#else
			container_link_node(node, container->buckets[index]);
			container->buckets[index] = node;

			container->count++;
			return v;
#endif
		}
	}
	return nullptr;
}

TContainerValue sodero_container_delete(PSoderoContainer container, TContainerValue v) {
#ifdef __CONTAINER_KEY__
	return sodero_container_remove(container, container_keyof(container, v));
#else
	return sodero_container_remove(container, (TContainerKey) v);
#endif
}

long sodero_container_foreach(PSoderoContainer container, TforeachContainerHandlor handlor, void * data) {
	if (!handlor) return -1;
	long result = 0;
//	for (long i = 0; i < container->length; i++) {
//		PSoderoContainerNode node = container->buckets[i];
//		while(node) {
//			handlor(container, result++, container_node_data(node), data);
//			node = container_node_next(node);
//		}
//	}
	PSoderoContainerNode node = container->head;
	while(node) {
		if (handlor(container, result++, container_node_data(node), data)) return -result;
		node = container_slide_next(node);
	}

	return result;
}


PPortKey key_of_sesson(PSoderoSession session) {
	return session ? & session->key : nullptr;
}
