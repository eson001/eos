/*
 * DPI.h
 *
 *  Created on: Dec 3, 2014
 *      Author: Clark Dong
 */

#ifndef DPI_H_
#define DPI_H_

#pragma pack(push, 1)

#define DPI_FIELD_PROTO       0
#define DPI_FIELD_IP          1
#define DPI_FIELD_PORT        2
#define DPI_FIELD_FLAG        3
#define DPI_FIELD_APPLICATION 4
#define DPI_FIELD_MAJOR       5
#define DPI_FIELD_MINOR       6
#define DPI_FIELD_ATTRIBUTE   7
#define DPI_FIELD_NAME        8

#define DPI_FIELD_COUNT 9

#define DPI_ENTRIES_APPEND 0
#define DPI_ENTRIES_RELOAD 1

#define DEFAULT_DPI_LENGTH	(4 * Ki)
#define DEFAULT_DPI_DELTA	(4 * Ki)

#define DEFAULT_DPI_SIZE	8	//	sizeof DPI_ENTRY.key

typedef union DPI_KEY {
	struct {
		unsigned int ip;
		unsigned short port;
		unsigned char proto;
		unsigned char  type;
	};
	unsigned long long value;
	unsigned char s[4];
} TDPIKey, * PDPIKey;

typedef union DPI_VALUE {
	unsigned long long value;
	struct {
		unsigned char flag;
		unsigned char application;
		unsigned short major;
		unsigned short minor;
		unsigned short attribute;
	};
} TDPIValue, * PDPIValue;

typedef struct DPI_ENTRY {
	union {
		unsigned long long l;
		struct {
			unsigned int ip;
			unsigned short port;
			unsigned char proto;
			unsigned char type;
		};
		unsigned char s[4];
		TDPIKey key;
	};
	union {
		unsigned long long h;
		struct {
			unsigned char flag;
			unsigned char application;
			unsigned short major;
			unsigned short minor;
			unsigned short attribute;
		};
		TDPIValue value;
	};
	char name[1];
} TDPIEntry, * PDPIEntry;

#pragma pack(pop)


extern TDPIValue dpi_lookup(TDPIKey key);
extern TDPIValue dpi_lookup_ippf(unsigned int ip, unsigned short port, unsigned char proto, unsigned char flag);

extern int dpiValid(void);
extern void dpiClose(void);
extern void dpiInitModule(void);
extern void dpiResetModule(void);
extern int loadDPIEntries(const char * file, int mode);
extern void dpi_upgrade(const char * file);
extern void dpi_check(void);

#endif /* DPI_H_ */
