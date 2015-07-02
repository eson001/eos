/*
 * DNS.c
 *
 *  Created on: Sep 14, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "Type.h"
#include "Common.h"
#include "DNS.h"
#include "Core.h"
#include "Logic.h"

#define __DNS_VERBOSE

const char * dns_t_name(int type) {
	switch(type) {
		case DNS_TYPE_A:
			return "Address";
		case DNS_TYPE_NS:
			return "Name Server";
		case DNS_TYPE_MD:	//	Obsoleted
			return "Mail Destination";
		case DNS_TYPE_MF:	//	Obsoleted
			return "Mail Forwarder";
		case DNS_TYPE_CNAME:
			return "Canonical Name";
		case DNS_TYPE_SOA:
			return "Start of Zone";
		case DNS_TYPE_MB:	//	EXPERIMENTAL
			return "Mail Box";
		case DNS_TYPE_MG:	//	EXPERIMENTAL
			return "Mail Group";
		case DNS_TYPE_MR:	//	EXPERIMENTAL
			return "Mail Rename";
		case DNS_TYPE_NULL:
			return "Null";
		case DNS_TYPE_WKS:
			return "Well Known Service";
		case DNS_TYPE_PTR:
			return "Domain Name Pointer";
		case DNS_TYPE_HINFO:
			return "Host Information";
		case DNS_TYPE_MINFO:
			return "Mail Information";
		case DNS_TYPE_MX:
			return "Mail Exchange";
		case DNS_TYPE_TXT:
			return "Text";
		default:
			return "Unknown";
	}
}

const char * dns_q_name(int type) {
	switch(type) {
		case DNS_QTYPE_AXFR:
			return "AXFR";
		case DNS_QTYPE_MAILB:
			return "Mail Box";
		case DNS_QTYPE_MAILA:	//	Obsoleted
			return "Mail Agent";
		case DNS_QTYPE_ANY:
			return "Any";
		default:
			return "Unknown";
	}
}

const char * dns_c_name(int type) {
	switch(type) {
	case DNS_CLASS_IN:
		return "Internet";
	case DNS_CLASS_CS:	//	Obsoleted
		return "CSNET";
	case DNS_CLASS_CH:
		return "CHAOS";
	case DNS_CLASS_HS:
		return "Hesiod";
	default:
		return "Unknown";
	}
}

const char * dns_o_name(int code) {
	switch(code) {
		case DNS_OP_QUERY:
			return "Query";
		case DNS_OP_IQUERY:
			return "I Query";
		case DNS_OP_STATUS:
			return "Status";
		default:
			return "Unknown";
	}
}

const char * dns_r_name(int code) {
	switch(code) {
		case DNS_RC_OKAY:
			return "Okay";
		case DNS_RC_FORMAT:
			return "Format";
		case DNS_RC_SERVER:
			return "Server";
		case DNS_RC_NAME:
			return "Name";
		case DNS_RC_IMPLEMENTED:
			return "Implemented";
		case DNS_RC_REFURED:
			return "Refured";
		default:
			return "Unknown";
	}
}

PSoderoApplicationDNS newDNSApplication(PSoderoUDPSession owner) {
	PSoderoApplicationDNS result = takeApplication(sizeof(TSoderoApplicationDNS));
#ifdef __EXPORT_STATISTICS__
	gDNSTake++;
#endif
	newApplication((PSoderoApplication)result, (PSoderoSession)owner);

	return result;
}

int parseDNSName(char * name, char * data, int size, int offset, int length, int ident) {
	int result = 0;
	while(offset + result < size) {
		int pos = (unsigned char) data[offset + result];
		if (pos == 0) break;
		if (0xc0 == (0xc0 & pos)) {
			int position = ntohs(*(unsigned short*)(data + offset + result)) & 0x3FFF;
			if (position < size) {
				parseDNSName(name, data, size, position, length, ident);
				result ++;
				break;
			} else
				return size - offset;
		} else {
			result++;
			if (name && length > 1) {
				if (ident > 0)
					*name++ = PERIOD;
				ident++;
				length --;
				int count = min(length, pos);
				if (offset + result + count < size) {
					memcpy(name, data + offset + result, count);
					name   += count;
					length -= count;
					*name = 0;
				} else
					return size - offset;
			}
			result += pos;
		}
	}
	return result + 1;
}

int parseDNSQuesition(PSoderoApplicationDNS dns, char * name, char * data, int size, int offset, int length) {
	int current = parseDNSName(name, data, size, offset, length, 0);
	unsigned short type  = ntohs(*((unsigned short*)(data + offset + current)));
	current += 2;
#ifdef __DNS_VERBOSE__
	unsigned short clasz = ntohs(*((unsigned short*)(data + offset + current)));
#endif
	current += 2;

	if (!dns->type)
		dns->type = type;
	if (!*dns->query)
		strncpy(dns->query, name, sizeof(dns->query) - 1);

#ifdef __DNS_VERBOSE__
	printf("%s %s - %s\n", dns_c_name(clasz), dns_t_name(type), name);
#endif

	return current;
}

int parseDNSAnswer(PSoderoApplicationDNS dns, char * data, int s, int offset, int length,
	PSoderoDNSAnswerEntry entry, char * text, unsigned short * base) {
	char domain[128], primary[128];
	int current = offset;

	bzero(domain, sizeof(domain));
	current += parseDNSName(domain, data, s, current, 128, 0);

	unsigned short type = ntohs(*((unsigned short*)(data + current)));
	current += 2;
	unsigned short claz = ntohs(*((unsigned short*)(data + current)));
	current += 2;
	unsigned int   time  = ntohl(*((unsigned int  *)(data + current)));
	current += 4;
	unsigned short size  = ntohs(*((unsigned short*)(data + current)));
	current += 2;

	int postion = current;
	if (claz == DNS_CLASS_IN) {
		switch(type) {
		case DNS_TYPE_A:
			if (size == 4) {	//	IPv4
				TIPv4 ip = {*(unsigned int*)(data + postion)};
#ifdef __DNS_VERBOSE__
				printf("type A class IN time %u - %s is %u.%u.%u.%u\n", time, domain, ip.s[0], ip.s[1], ip.s[2], ip.s[3]);
#endif
				entry->type = type;
				entry->claz = claz;
				entry->time = time;

				entry->name = (*base);
				(*base) += cpy_str(text + (*base), domain);

				entry->data = (*base);
				(*base) += sprintf(text + (*base), "%u.%u.%u.%u%c", ip.s[0], ip.s[1], ip.s[2], ip.s[3], 0);
				break;
			}
			return 0;
			case DNS_TYPE_MX:
//				unsigned short preference  = ntohs(*((unsigned short*)(data + current)));
				postion += 2;
				/* no break */
			case DNS_TYPE_NS:
			case DNS_TYPE_CNAME:
			case DNS_TYPE_PTR:
				bzero(primary, sizeof(primary));
				parseDNSName(primary, data, s, postion, 1024, 0);
#ifdef __DNS_VERBOSE__
				printf("type %s class IN time %u - %s is %s\n", dns_t_name(type), time, domain, primary);
#endif
				// CNAME make domain alias here

				entry->type = type;
				entry->claz = claz;
				entry->time = time;

				entry->name = (*base);
				(*base) += cpy_str(text + (*base), domain);

				entry->data = (*base);
				(*base) += cpy_str(text + (*base), primary);
				break;
			case DNS_TYPE_TXT:
				entry->type = type;
				entry->claz = claz;
				entry->time = time;

				entry->name = (*base);
				(*base) += cpy_str(text + (*base), domain);
				{
				unsigned char l = *(data + postion++);
				entry->data = (*base);
				memcpy(text + (*base), data + postion, l);
				(*base) += l;
				*(text + (*base)) = 0;
				(*base) ++;
				}
				break;
			case DNS_TYPE_AAAA:
				if (size == 16) {	//	IPv6
					entry->claz = claz;
					entry->time = time;

					entry->name = (*base);
					(*base) += cpy_str(text + (*base), domain);

					unsigned short * ip = (unsigned short*)(data + postion);
					entry->data = (*base);
					(*base) += sprintf(text + (*base), "%x:%x:%x:%x:%x:%x:%x:%x%c", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], 0);
					break;
				}
				return 0;
			default:
#ifdef __DNS_VERBOSE__
				printf("Internet %s %d\n", dns_t_name(type), time);
#endif
				break;
		}
#ifdef __DNS_VERBOSE__
	} else {
		printf("%s %u\n", dns_c_name(claz), time);
#endif
	}
	current += size;

	return current - offset;
}

void parseDNSPacket(PSoderoApplicationDNS dns, PDNSPacket packet, int size) {
	char * buffer = (char *) packet;

	char name[Ki];
	bzero(name, sizeof(name));

	int offset = sizeof(TDNSHeader);

//	unsigned char type;
//	unsigned char ocode;
//	unsigned char rcode;

	if (offset < size) {
#ifdef __DNS_VERBOSE__
		printf("DNS - sequence %.4x flag %.4x - "
				"qr %d, op %d, a %d, tc %d, rd %d, ra %d, z %d, aa %d, nd %d, r %d\n",
			packet->head.sequence, packet->head.flag,
			packet->head.qr, packet->head.op, packet->head.a, packet->head.tc, packet->head.rd,
			packet->head.ra, packet->head.z, packet->head.aa, packet->head.nd, packet->head.r);
#endif
		dns->ocode = packet->head.op;
		if (packet->head.qr) {
			dns->rcode =  packet->head.r;
			dns->authoritative = packet->head.a;
			dns->truncated = packet->head.tc;
		}

		unsigned int questions  = ntohs(packet->head.questions );
		unsigned int answers    = ntohs(packet->head.answers   );
#ifdef __DNS_VERBOSE__
		unsigned int authoritis = ntohs(packet->head.authoritis);
		unsigned int additions  = ntohs(packet->head.additions );
#endif

#ifdef __DNS_VERBOSE__
		printf("DNS - Q %u A %u & %u %u\n",
				questions, answers, authoritis, additions);
		printf("==================================================\n");
#endif

		do {
			while(questions-- > 0) {
				int bytes = parseDNSQuesition(dns, name, buffer, size, offset, 1024);
				if (bytes > 0) {
					offset += bytes;
				} else
					goto done;
			}

#ifdef __DNS_VERBOSE__
			printf("--------------------------------------------------\n");
#endif

			char data[4096];
			unsigned short base = answers * sizeof(TSoderoDNSAnswerEntry);
			PSoderoDNSAnswerEntry entry = (PSoderoDNSAnswerEntry)data;
			bzero(entry, base);

			int index = 0;
			int count = answers;
//			if (packet->head.qr)
			while(count-- > 0) {
				int bytes = parseDNSAnswer(dns, buffer, size, offset, 1024, &entry[index], data, &base);
				if (bytes > 0) {
					offset += bytes;
				} else
					break;
				if (entry[index].type) index++;
			}

//			for (int i = 0; i < index; i++) {
//				printf("No: %2d - %s %s %d %s -> %s\n",
//					i, dns_t_name(entry[i].type), dns_c_name(entry[i].claz), entry[i].time,
//					data  + entry[i].name, data + entry[i].data);
//			}
			count = answers - index;
			if (count > 0) {
				unsigned short length = count * sizeof(TSoderoDNSAnswerEntry);
				for (int i = 0; i < index; i++) {
					if ((entry[i].name > 0) && (entry[i].name < length)) goto done;
					if ((entry[i].data > 0) && (entry[i].data < length)) goto done;

					entry[i].name -= length;
					entry[i].data -= length;
				}
				base -= answers * sizeof(TSoderoDNSAnswerEntry);
				memmove(entry + index, entry + answers, base);
				base += count   * sizeof(TSoderoDNSAnswerEntry);
			}


			if (index > 0) {
				dns->data = (char*)takeMemory(base);
				if (dns->data) {
					memcpy(dns->data, data, base);
					dns->answer = index;
//					entry = (PSoderoDNSAnswerEntry) dns->data;
//					for (int i = 0; i < index; i++) {
//						printf("No: %2d - %s %s %d %s -> %s\n",
//							i, dns_t_name(entry[i].type), dns_c_name(entry[i].claz), entry[i].time,
//							data  + entry[i].name, data + entry[i].data);
//					}
				}
			}

		} while (false);
done:;

#ifdef __DNS_VERBOSE__
		printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	} else {
		printf("Invalid DNS Packet\n");
#endif
	}
}

int isDNSPacket(PUDPHeader header) {
	if (header->sour == DNS_PORT) return true;
	if (header->dest == DNS_PORT) return true;
	return false;
}

PSoderoApplicationDNS takeApplicationDNS(PSoderoUDPSession session, unsigned short sequence) {
	PSoderoApplicationDNS head = nullptr;
	PSoderoApplicationDNS tail = session->session;
	while(tail) {
		if (tail->sequence == sequence) {
			if (head)
				head->link = tail->link;
			else
				session->session = tail->link;		//	tail is first
			tail->link = nullptr;
			return tail;
		}
		head = tail;
		tail = tail->link;
	}
	return tail;
}

unsigned long long session_live_dns(PSoderoUDPSession session) {
	unsigned long long result = 0;
	PSoderoApplicationDNS dns = session->session;
	while(dns) {
		if ((!dns->b) || (!dns->e)) {
			unsigned long long live = 0;

			do {
				if (dns->e) {
					live = dns->e + gDNSDoneTime;
					break;
				}
				if (dns->b) {
					live = dns->b + gDNSOpenTime;
					break;
				}
			} while(false);

			if (result < live) result = live;
		}
		dns = dns->link;
	}

	if (result == 0)
		result = gTime + gDNSOpenTime;

	return result;
}

int processDNSPacket(PSoderoUDPSession session, const void * data, int size, int length,
	PUDPHeader udp, PIPHeader ip, PEtherHeader ether) {
	PDNSPacket packet = (PDNSPacket) data;

	PSoderoApplicationDNS dns = takeApplicationDNS(session, packet->head.sequence);
	PNodeValue sourNode = takeIPv4Node((TMACVlan){{ether->sour, ether->vlan}}, ip->sIP);
	PNodeValue destNode = takeIPv4Node((TMACVlan){{ether->dest, ether->vlan}}, ip->dIP);

	int dir = DIR_NONE;
	if (packet->head.qr) {
		//	DNS Response
		gDNSResponse++;
		dir = DIR_SERVER;
		if (!dns) {
			//	ToDo:	DNS response retransmited?
			new_ipport_event(IPv4_TYPE_UDP, SODERO_LOG_PACKET_ERROR, &session->key, session, CAUSE_PACKET_INVALID_REQ);
			dns = newDNSApplication(session);
		}

		dns->e = gTime;

		if (sourNode)
			processA(&sourNode->l4.dns.outgoing.response.value, size);
		if (destNode)
			processA(&destNode->l4.dns.incoming.response.value, size);
		if (packet->head.op < 4) {
			if (sourNode)
				sourNode->l4.dns.outgoing.response.codes.o.codes[packet->head.op]++;
			if (destNode)
				destNode->l4.dns.incoming.response.codes.o.codes[packet->head.op]++;
		}
		if (packet->head.r < 7) {
			if (sourNode)
				sourNode->l4.dns.outgoing.response.codes.r.codes[packet->head.r ]++;
			if (destNode)
				destNode->l4.dns.incoming.response.codes.r.codes[packet->head.r ]++;
		}
	} else {
		//	DNS Query
		gDNSRequest++;
		dir = DIR_CLIENT;
		if (!dns) {
			dns = newDNSApplication(session);
		} else {
			//	ToDo:	DNS request retransmited?
			new_ipport_event(IPv4_TYPE_UDP, SODERO_LOG_PACKET_ERROR, &session->key, session, CAUSE_PACKET_INVALID_RES);
		}

		dns->b = gTime;
		dns->sequence = packet->head.sequence;

		if (sourNode)
			processA(&sourNode->l4.dns.outgoing.request.value, size);
		if (destNode)
			processA(&destNode->l4.dns.incoming.request.value, size);
		if (packet->head.op < 4) {
			if (sourNode)
				sourNode->l4.dns.outgoing.request.codes.o.codes[packet->head.op]++;
			if (destNode)
				destNode->l4.dns.incoming.request.codes.o.codes[packet->head.op]++;
		}
		if (packet->head.r < 7) {
			if (sourNode)
				sourNode->l4.dns.outgoing.request.codes.r.codes[packet->head.r ]++;
			if (destNode)
				destNode->l4.dns.incoming.request.codes.r.codes[packet->head.r]++;
		}
	}

	parseDNSPacket(dns, packet, size);
	processDV(&dns->l2, length, dir);
	processDD(&dns->traffic, size, dir);
	if (dns->b && dns->e) {
		long long value = dns->e - dns->b;
		if (value < 0) value = 0;
		processE(&sourNode->l4.dns.incoming.duration, value);
		processE(&destNode->l4.dns.outgoing.duration, value);
		sodero_pointer_add(getClosedApplications(), dns);
	} else {
		dns->link = session->session;
		session->session = dns;
	}

	resetSessionLive(session, session_live_dns(session));	//	Reset timeout

//	printf("Reset DNS session timeout to %llu.%llu\n", session->live / uSecsPerSec, session->live % uSecsPerSec);

	return 0;
}


