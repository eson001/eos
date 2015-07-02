/*
 * Dump.h
 *
 *  Created on: Aug 10, 2014
 *      Author: Clark Dong
 */

#ifndef DUMP_H_
#define DUMP_H_

#include "Type.h"
#include "Parameter.h"
#include "Common.h"
#include "Core.h"
#include "Session.h"
#include "Context.h"

#ifdef __EXPORT_REPORT__

extern void verboseMACNode(PMAC key, PSoderoDoubleDatum datum);
extern void verboseIPv4Node(PIPv4 key, PSoderoDoubleDatum datum);

extern void dumpNode(int index, PNodeIndex k, PNodeValue v);

extern void dumpEtherProtocol(int index, PSoderoFlowDatum datum);
extern void dumpMacNode(int index, PMAC k, PSoderoDoubleDatum v);

extern void dumpIPv4Protocol(int index, PSoderoFlowDatum datum);
extern void dumpIPv4Node(int index, PIPv4 k, PSoderoDoubleDatum v);

extern void dumpCounter(PSoderoPeriodSingleCounter counter);

extern void dump_ipport_event(int proto, int event, void * key, void * value, int cause);

#endif

#ifdef __EXPORT_STATISTICS__

extern void dumpStatistics(void);

#endif

#endif /* DUMP_H_ */
