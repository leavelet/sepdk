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

#ifndef _VTSS_MODCFG_H_
#define _VTSS_MODCFG_H_

#include "config.h"
#include "cpu.h"
#include "pmu.h"

#include <linux/cpumask.h>	/* for cpumask_t */

/* collection configuration */
struct vtss_reqcfg {

	/* CPU events configuration */
	int events_size;
	char events_space[VTSS_CFG_CHAIN_SPACE_SIZE];
	int nr_events[VTSS_PMU_SIZE];
	int group_offset[VTSS_PMU_SIZE];

	/* last branch tracing configuration */
	lbr_cfg_t lbr_cfg;

	/* processor tracing configuration */
	ipt_cfg_t ipt_cfg;

	/* tracing configuration */
	trace_cfg_t trace_cfg;
	unsigned char trace_space[VTSS_CFG_SPACE_SIZE];

	/* stack configuration */
	unsigned long stk_sz[vtss_stk_last];
	unsigned long stk_pg_sz[vtss_stk_last];
};

extern struct vtss_reqcfg vtss_reqcfg;

#define vtss_reqcfg_for_each_event(evcfg)\
	for ((evcfg) = (cpuevent_cfg_v1_t *)vtss_reqcfg.events_space;\
	     (char *)(evcfg) < vtss_reqcfg.events_space + vtss_reqcfg.events_size;\
	     (evcfg) = (cpuevent_cfg_v1_t *)((char *)((evcfg) + 1) + (evcfg)->name_len))

#define vtss_reqcfg_ctx_mode()      (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CTX)
#define vtss_reqcfg_stk_mode()      (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_STACKS)
#define vtss_reqcfg_fpstk_mode()    (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_FPSTK)
#define vtss_reqcfg_lbr_mode()      (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_LASTBR)
#define vtss_reqcfg_lbrstk_mode()   (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_LBRSTK)
#define vtss_reqcfg_ipt_mode()      (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT)
#define vtss_reqcfg_pwract_mode()   (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_PWRACT)
#define vtss_reqcfg_pwridle_mode()  (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_PWRIDLE)
#define vtss_reqcfg_ehfi_mode()     (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_EHFI)
#define vtss_reqcfg_ipt_mode_full() (vtss_reqcfg_ipt_mode() && (vtss_reqcfg.ipt_cfg.mode & vtss_iptmode_full))
#define vtss_reqcfg_rb_mode()       (vtss_reqcfg.ipt_cfg.size > 0)
#define vtss_reqcfg_rb_size()       (vtss_reqcfg.ipt_cfg.size)

int vtss_reqcfg_init(void);
void vtss_reqcfg_fixup_flags(void);
void vtss_reqcfg_print_events(void);
void vtss_reqcfg_fixup_events(void);
int vtss_reqcfg_append_events(void);
int vtss_reqcfg_verify(void);

extern vtss_fmtcfg_t  vtss_fmtcfg[2];
extern vtss_syscfg_t  vtss_syscfg;
extern vtss_hardcfg_t vtss_hardcfg;
extern vtss_cpuinfo_t vtss_cpuinfo;
extern vtss_iptcfg_t  vtss_iptcfg;

#define vtss_nr_cpus() vtss_hardcfg.cpu_no

extern cpumask_t vtss_cpumask;

#define vtss_nr_active_cpus() cpumask_weight(&vtss_cpumask)
#define vtss_cpu_active(cpu) cpumask_test_cpu((cpu), &vtss_cpumask)

extern bool vtss_cpu_hybrid_mode;

#define vtss_cpu_type(cpu)\
	vtss_cpuid_cpu_type(vtss_cpuinfo.cpus[cpu].leafs[0].out_eax)

#define vtss_pmu_id(cpu)\
	((vtss_cpu_hybrid_mode && vtss_cpu_type(cpu) == VTSS_CPU_TYPE_ATOM) ?\
	 VTSS_PMU_ATOM : VTSS_PMU_CORE)

int vtss_modcfg_init(void);

#endif
