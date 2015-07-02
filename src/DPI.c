/*
 * DPI.c
 *
 *  Created on: Dec 3, 2014
 *      Author: Clark Dong
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "Type.h"
#include "Common.h"
#include "Parameter.h"
#include "DPI.h"

time_t gDPITime;
off_t  gDPISize;
PSoderoTable gDPIEntries;

int dpiValid(void) {
	return gDPIEntries != nullptr;
}

void dpiClose(void) {
	if (dpiValid())
		sodero_table_destroy(gDPIEntries);
}

char * readFile(const char *path) {
   FILE *file = fopen(path, "rb");
   if (!file)
      return nullptr;
   fseek(file, 0, SEEK_END);
   long size = ftell(file);
   fseek(file, 0, SEEK_SET);
   char * buffer = (char*) takeMemory(size + 1);
   buffer[size] = 0;
   if (fread(buffer, 1, size, file) != (unsigned long)size) {
      freeMemory(buffer);
      buffer = nullptr;
   }
   fclose(file);
   return buffer;
}

char * loadFields(char * line, char * fields[], int count) {
	if (!fields) return line;

	int result = 0;
	char c;
	char * head = line;
	while((c = *line)) {
		switch(c) {
		case TAB:
			*line++ = 0;
			if (result < count)
				fields[result++] = head;
			head = line;
			break;
		case CR:
			*line++ = 0;
			break;
		case LF:
			*line = 0;
			if (line > head) {
				if (result < count)
					fields[result++] = head;
			}
			return line + 1;
		default:
			line++;
			break;
		}
	}

	if (line > head) {
		if (result < count)
			fields[result++] = head;
	}
	return nullptr;
}

int parseDPIEntry(PDPIEntry entry, char * fields[]) {
	if (fields[DPI_FIELD_PROTO]) {
		entry->proto = proto_index(fields[DPI_FIELD_PROTO]);
	}
	if (fields[DPI_FIELD_IP]) {
		if (sscanf(fields[DPI_FIELD_IP],"%hhu.%hhu.%hhu.%hhu", entry->s + 0, entry->s + 1, entry->s + 2, entry->s + 3) < 4) return 0;
	}
	if (fields[DPI_FIELD_PORT]) {
		entry->port = atoi(fields[DPI_FIELD_PORT]);
	}
	if (fields[DPI_FIELD_FLAG]) {
		entry->flag = atoi(fields[DPI_FIELD_FLAG]);
	}
	if (fields[DPI_FIELD_APPLICATION]) {
		entry->application = atoi(fields[DPI_FIELD_APPLICATION]);
	}
	if (fields[DPI_FIELD_MAJOR]) {
		entry->major = atoi(fields[DPI_FIELD_MAJOR]);
	}
	if (fields[DPI_FIELD_MINOR]) {
		entry->minor = atoi(fields[DPI_FIELD_MINOR]);
	}
	if (fields[DPI_FIELD_ATTRIBUTE]) {
		entry->attribute = atoi(fields[DPI_FIELD_ATTRIBUTE]);
	}

	entry->port = htons(entry->port);

	return entry->l && entry->h;
}

void dpiInitModule(void) {
	if (gDPIEntries) return;
	gDPIEntries = sodero_table_create_simple(DEFAULT_DPI_LENGTH, DEFAULT_DPI_DELTA, DEFAULT_DPI_SIZE);	//	DEFAULT_PARAMETER
//					sodero_table_create(DEFAULT_DPI_LENGTH, DEFAULT_DPI_DELTA, DEFAULT_DPI_SIZE, SODERO_MAP_MODE_NONE, nullptr,
//					(THashHandlor) sodero_dpi_hasher, (TEqualHandlor) sodero_key_equaler, (TSoderoObjectKey) sodero_dpi_keyof,
//					nullptr, nullptr, nullptr
//					);
}


void dpiResetModule(void) {
	sodero_table_clean(gDPIEntries);
}

void dpi_report(TDPIKey key, TDPIValue value, char * name) {
	printf("DPI [%s]%u.%u.%u.%u:%u -> %s flag %u application %u major %u minor %u attribute %u\n",
			ipv4_proto_name(key.proto), key.s[0], key.s[1], key.s[2], key.s[3], ntohs(key.port),
			name ? name : "[No Name]", value.flag, value.application, value.major, value.minor, value.attribute);
}

TDPIValue dpi_lookup(TDPIKey key) {
	if (gDPIEntries) {
		PDPIEntry entry = sodero_table_lookup(gDPIEntries, &key);
		if (entry) {
			dpi_report(key, entry->value, entry->name);
			return entry->value;
		}

		//	just port & proto
		key.ip = 0;
		entry = sodero_table_lookup(gDPIEntries, &key);

		if (entry) {
			dpi_report(key, entry->value, entry->name);
			return entry->value;
		}
	}
	return (TDPIValue) {.value = 0};
}

TDPIValue dpi_lookup_ippf(unsigned int ip, unsigned short port, unsigned char proto, unsigned char flag) {
	return dpi_lookup((TDPIKey){{ip, port, proto, flag}});
}

int loadDPIEntries(const char * file, int mode) {
	dpiInitModule();
	if (mode == DPI_ENTRIES_RELOAD) {
		dpiResetModule();
	}

	char * data = readFile(file);

	if (data) {
		char * line = skip_space(data);
		if (line)
			do {
				if (*line == '#') {
					line = find_char(line, LF);
					if (line)
						line++;
				} else {
					TDPIEntry entry;
					char * fields[DPI_FIELD_COUNT];
					bzero(fields, sizeof(fields));
					line = loadFields(line, fields, DPI_FIELD_COUNT);
					if (parseDPIEntry(&entry, fields)) {
						char * name = fields[DPI_FIELD_NAME];
						int size = name ? strlen(name) : 0;
						PDPIEntry item = (PDPIEntry) takeMemory(sizeof(*item) + size);
						item->l = entry.l;
						item->h = entry.h;
						if (size)
							memcpy(item->name, name, size);
						item->name[size] = 0;
						sodero_table_insert(gDPIEntries, item);
					}
				}
			} while((line = skip_space(line)));
		freeMemory(data);
		return true;
	} else {
		printf("Load DPI rules %s failure\n", file);
		return false;
	}
}

void dpi_upgrade(const char * file) {
	struct stat s;
	int ret = stat(file, &s);
	if (ret) return;
	if (gDPITime && gDPISize) {
		if ((s.st_mtime == gDPITime) && (s.st_size == gDPISize)) return;
	}

	if (loadDPIEntries(file, DPI_ENTRIES_RELOAD)) {
		gDPITime = s.st_mtime;
		gDPISize = s.st_size;
	}
}

void dpi_check(void) {
	if (gDPIRulesTable)
		dpi_upgrade(gDPIRulesTable);
}
