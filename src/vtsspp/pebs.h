/*
    Copyright (C) 2010-2023 Intel Corporation.  All Rights Reserved.

    This file is part of SEP Development Kit.

    SEP Development Kit is free software; you can redistribute it
    and/or modify it under the terms of the GNU General Public License
    version 2 as published by the Free Software Foundation.

    SEP Development Kit is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with SEP Development Kit; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    As a special exception, you may use this file as part of a free software
    library without restriction.  Specifically, if other files instantiate
    templates or use macros or inline functions from this file, or you compile
    this file and link it with other files to produce an executable, this
    file does not by itself cause the resulting executable to be covered by
    the GNU General Public License.  This exception does not however
    invalidate any other reasons why the executable file might be covered by
    the GNU General Public License.
*/

#ifndef _VTSS_PEBS_H_
#define _VTSS_PEBS_H_

#include "config.h"

/* DS save area MSR */
#define VTSS_IA32_DS_AREA 0x0600

#pragma pack(push, 1)
struct vtss_dsa {
	void *bts_base;
	void *bts_index;
	void *bts_absmax;
	void *bts_threshold;
	void *pebs_base;
	void *pebs_index;
	void *pebs_absmax;
	void *pebs_threshold;
	unsigned long long pebs_reset[0];
};
#pragma pack(pop)

/* PEBS control MSR */
#define VTSS_IA32_PEBS_ENABLE 0x3f1

/* Enable PEBS on IA32_PMC0 */
#define VTSS_PEBS_ENABLE_PMC0 0x1ULL

#pragma pack(push, 1)
struct vtss_pebs {
	/* Merom fields */
	unsigned long long flags;
	unsigned long long ip;
	unsigned long long ax;
	unsigned long long bx;
	unsigned long long cx;
	unsigned long long dx;
	unsigned long long si;
	unsigned long long di;
	unsigned long long bp;
	unsigned long long sp;
	unsigned long long r8;
	unsigned long long r9;
	unsigned long long r10;
	unsigned long long r11;
	unsigned long long r12;
	unsigned long long r13;
	unsigned long long r14;
	unsigned long long r15;
	/* Nehalem fields */
	unsigned long long applicable_counter;
	unsigned long long data_linear_address;
	unsigned long long data_source_encoding;
	unsigned long long latency_value;
	/* Haswell fields */
	unsigned long long eventing_ip;
	unsigned long long tx_abort_info;
	/* Skylake field */
	unsigned long long tsc;
};
#pragma pack(pop)

extern atomic_t vtss_pebs_active;
#define vtss_pebs_set_disabled() atomic_set(&vtss_pebs_active, -1)

int vtss_pebs_init(void);
void vtss_pebs_cleanup(void);
void vtss_pebs_enable(int cpu);
void vtss_pebs_disable(void);
unsigned long vtss_pebs_get_ip(int cpu);

#endif
