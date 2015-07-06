/*
 * Parameter.h
 *
 *  Created on: Aug 7, 2014
 *      Author: Clark Dong
 */

#ifndef PARAMETER_H_
#define PARAMETER_H_

#include "Type.h"

#define SODERO_DEFAULT_PERIOD 30
#define SODERO_DEFAULT_CYCLE 10
#define SODERO_REPORT_MAC    "NodeX"
#define SODERO_REPORT_CLIENT "localhost"

#define CAPTURE_NORMAL  0
#define CAPTURE_PROMISC 1
#define CAPTURE_TIMEOUT 20
#define CAPTURE_BUFFER (128*Mi)

//	port of the analytic agent
#define SODERO_REPORT_VERSION 0x00000001

#define SODERO_REPORT_SERVICE "9900"


enum {
	SODERO_EXPORT_NONE,
	SODERO_EXPORT_REPORT,
	SODERO_EXPORT_DETAIL,
	SODERO_EXPORT_VERBOSE,
};

extern const char * gDevice;
extern int gCheck;
extern int gCycle;
extern int gAlign;
extern int gExport;
extern int gCapturePromisc;
extern int gCaptureTimeout;
extern int gCaptureBuffer ;

extern long long gPeriod;

extern const char * gDebug  ;
extern const char * gServer ;
extern const char * gService;

extern unsigned int gReportIP;

extern TVersion gVersion;
extern TMAC gMAC;
extern TIP  gHost;
extern const char * gName;
extern int gLoop;
extern const char * gDPIRulesTable;

static inline
int isExportReport (void) { return gExport >= SODERO_EXPORT_REPORT ; }
static inline
int isExportDetail (void) { return gExport >= SODERO_EXPORT_DETAIL ; }
static inline
int isExportVerbose(void) { return gExport >= SODERO_EXPORT_VERBOSE; }

extern void initArguments(int argc, char** argv);

#endif /* PARAMETER_H_ */
