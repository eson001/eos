/*
 * Logic.h
 *
 *  Created on: Jul 24, 2014
 *      Author: Clark Dong
 */

#ifndef LOGIC_H_
#define LOGIC_H_

#include "Type.h"
#include "Common.h"
#include "Session.h"
#include "Ether.h"
#include "IP.h"
#include "Stream.h"
#include "ICMP.h"
#include "TCP.h"
#include "UDP.h"
#include "DNS.h"
#include "HTTP.h"
#include "MySQL.h"
#include "Core.h"

extern int session_type(int type);

///////////////////////////////////////////////////////////////////////////////////////////////////

extern void new_ipport_event(int proto, int event, void * key, void * value, int cause);

extern PSoderoMap createNodePeriodResult(void);
extern PSoderoMap createServicePeriodResult(void);

///////////////////////////////////////////////////////////////////////////////////////////////////

extern PNodeValue takeMACNode(PMAC key);
extern PNodeValue takeIPv4Node(TMACVlan head, TIPv4 key);
extern PSoderoDoubleDatum takeServiceNode(PServiceIndex index);

extern void initial_logic(void);

#endif /* LOGIC_H_ */
