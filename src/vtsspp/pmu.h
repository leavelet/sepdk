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

#ifndef _VTSS_PMU_H_
#define _VTSS_PMU_H_

#include "config.h"

/* Global performance counter status */
#define VTSS_IA32_PERF_GLOBAL_STATUS 0x38e

/* Global performance counter control */
#define VTSS_IA32_PERF_GLOBAL_CTRL 0x38f

/* Global performance counter overflow control */
#define VTSS_IA32_PERF_GLOBAL_OVF_CTRL 0x390

/* Layout of global performance status register */
#define VTSS_PMU_GLOBAL_OVF_DSA   (1ULL << 62)
#define VTSS_PMU_GLOBAL_COND_CHGD (1ULL << 63)

/* Fixed-function performance counter control */
#define VTSS_IA32_FIXED_CTR_CTRL 0x38d

/* Fixed-function performance counter 0 */
#define VTSS_IA32_FIXED_CTR0 0x309

/* Layout of fixed control register */
#define VTSS_PMU_FIXED_CTRL_PMI  0x8ULL
#define VTSS_PMU_FIXED_CTRL_MASK 0xfULL

/* Performance event select register 0 */
#define VTSS_IA32_PERFEVTSEL0 0x186

/* General performance counter 0 */
#define VTSS_IA32_PMC0 0x0c1

/* Layout of event select register */
#define VTSS_PMU_PERFEVTSEL_INT  0x00100000ULL
#define VTSS_PMU_PERFEVTSEL_MASK 0xffffffffULL

/* Interval threshold */
#define VTSS_PMU_CLK_THRESHOLD 5000

/* Counter threshold */
#define VTSS_PMU_CNT_THRESHOLD 0x80000000LL

/* Default number of counters */
#define VTSS_PMU_V3_NR_FX_COUNTERS 3
#define VTSS_PMU_V3_NR_GP_COUNTERS 4
#define VTSS_PMU_V5_NR_FX_COUNTERS 4
#define VTSS_PMU_V5_NR_GP_COUNTERS 8

/* PMU core type */
#define VTSS_PMU_CORE 0
#define VTSS_PMU_ATOM 1
#define VTSS_PMU_SIZE 2

struct vtss_pmu_event {

	/* for debug purposes */
	char *name;

	/* counting support */
	long long count;
	long long frozen_count;
	long long sampled_count;
	long long interval;
	long long aux_interval;

	/* multiplexion algorithm data */
	int group_id;
	int mux_alg;
	int mux_arg;

	/* processor specific registers/masks */
	int selmsr;
	int cntmsr;
	int extmsr;
	unsigned long long selmsk;
	unsigned long long cntmsk;
	unsigned long long extmsk;

	/* event interface */
	void (*restart)(struct vtss_pmu_event *event);
	void (*sample)(struct vtss_pmu_event *event);
	bool (*overflowed)(struct vtss_pmu_event *event);

	/* PMU core type */
	int pmu_id;
};

struct vtss_pmu_events {
	int pmu_id;
	int nr_events;
	int nr_groups;
	int group_id;
	int mux_alg;
	int mux_arg;
	int mux_count;
	unsigned long long mux_time;
	struct vtss_pmu_event evbuf[0];
};

#define vtss_pmu_for_each_event(events, event)\
	for ((event) = (events)->evbuf; (event) < (events)->evbuf + (events)->nr_events; (event)++)

#define vtss_pmu_for_each_active_event(events, event)\
	vtss_pmu_for_each_event(events, event)\
		if ((event)->group_id == (events)->group_id)

#define vtss_pmu_event_fixed(event) ((event)->selmsr == VTSS_IA32_FIXED_CTR_CTRL)

extern int vtss_pmu_version;
extern int vtss_pmu_nr_fx_counters[VTSS_PMU_SIZE];
extern int vtss_pmu_nr_gp_counters[VTSS_PMU_SIZE];

static inline unsigned long long vtss_pmu_counters_mask(int pmu_id, bool fixed, bool generic)
{
	unsigned long long mask = 0;

	if (generic)
		mask |= ((1ULL << vtss_pmu_nr_gp_counters[pmu_id]) - 1);
	if (fixed)
		mask |= ((1ULL << vtss_pmu_nr_fx_counters[pmu_id]) - 1) << 32;
	return mask;
}

int vtss_nmi_init(void);
void vtss_nmi_cleanup(void);

int vtss_pmu_init(void);
void vtss_pmu_enable(void);
void vtss_pmu_disable(void);

void vtss_pmu_events_init(struct vtss_pmu_events *events, int pmu_id);
void vtss_pmu_events_restart(struct vtss_pmu_events *events);
void vtss_pmu_events_sample(struct vtss_pmu_events *events);

#endif
