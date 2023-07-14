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

#ifndef _VTSS_PCB_H_
#define _VTSS_PCB_H_

#include "config.h"
#include "ipt.h"

#include <linux/percpu.h>	/* for per_cpu */

struct vtss_pcb {
	/* saved registers */
	unsigned long long msr_ovf;	/* saved IA32_PERF_GLOBAL_OVF_CTRL */
	unsigned long long msr_ctrl;	/* saved IA32_PERF_GLOBAL_CTRL */
	unsigned long long msr_debug;	/* saved IA32_DEBUGCTL */
	unsigned long long msr_dsa;	/* saved IA32_DS_AREA */
	unsigned long apic_lvtpc;	/* saved APIC_LVTPC */
	unsigned long pce_state;	/* saved PCE state */

	/* DS area addresses */
	void *dsa;			/* address of DS area mapped to user and kernel space */
	void *dsa_virt;			/* kernel address of DS area */
	void *pebs;			/* address of PEBS buffer mapped to user and kernel space */
	void *pebs_virt;		/* kernel address of PEBS buffer */

	/* IPT memory addresses */
	void *topa_virt;		/* virtual address of IPT ToPA */
	void *iptbuf_virt;		/* virtual address of IPT output buffer */
	unsigned long long topa_phys;	/* physical address of IPT ToPA */
	unsigned long long iptbuf_phys[VTSS_IPT_NR_BUFFERS]; /* physical address of IPT output buffer */
};

DECLARE_PER_CPU_SHARED_ALIGNED(struct vtss_pcb, vtss_pcb_var);

#ifndef __get_cpu_var
#define __get_cpu_var(var) (*this_cpu_ptr(&(var)))
#endif
#define vtss_pcb(cpu) per_cpu(vtss_pcb_var, cpu)
#define vtss_pcb_cpu __get_cpu_var(vtss_pcb_var)

int vtss_pcb_init(void);

#endif
