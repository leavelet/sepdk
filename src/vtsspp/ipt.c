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

#include "debug.h"
#include "ipt.h"
#include "kmem.h"
#include "modcfg.h"
#include "pcb.h"
#include "regs.h"
#include "stat.h"
#include "time.h"
#include "user.h"

#include <asm/io.h>	/* for virt_to_phys */

static atomic_t vtss_ipt_active = ATOMIC_INIT(0);
#define vtss_ipt_set_active() atomic_set(&vtss_ipt_active, 1)
#define vtss_ipt_set_inactive() (atomic_cmpxchg(&vtss_ipt_active, 1, 0) == 1)

static int vtss_ipt_register(int cpu)
{
	int i;

	vtss_pcb(cpu).topa_virt = vtss_alloc_pages(PAGE_SIZE, GFP_KERNEL, cpu);
	if (vtss_pcb(cpu).topa_virt) {
		vtss_pcb(cpu).topa_phys =
			(unsigned long long)virt_to_phys(vtss_pcb(cpu).topa_virt);
	} else {
		vtss_pr_error("Not enough memory for IPT ToPA buffer");
		return -ENOMEM;
	}
	vtss_pcb(cpu).iptbuf_virt = vtss_alloc_pages(VTSS_IPT_NR_BUFFERS*PAGE_SIZE,
						     GFP_KERNEL, cpu);
	if (vtss_pcb(cpu).iptbuf_virt) {
		for (i = 0; i < VTSS_IPT_NR_BUFFERS; i++)
			vtss_pcb(cpu).iptbuf_phys[i] =
				(unsigned long long)virt_to_phys(vtss_pcb(cpu).iptbuf_virt +
								 i*PAGE_SIZE);
	} else {
		vtss_pr_error("Not enough memory for IPT output buffer");
		return -ENOMEM;
	}
	return 0;
}

static void vtss_ipt_unregister(int cpu)
{
	vtss_free_pages(vtss_pcb(cpu).topa_virt, PAGE_SIZE);
	vtss_pcb(cpu).topa_virt = NULL;
	vtss_pcb(cpu).topa_phys = 0;
	vtss_free_pages(vtss_pcb(cpu).iptbuf_virt, VTSS_IPT_NR_BUFFERS*PAGE_SIZE);
	vtss_pcb(cpu).iptbuf_virt = NULL;
	memset(vtss_pcb(cpu).iptbuf_phys, 0, sizeof(vtss_pcb(cpu).iptbuf_phys));
}

int vtss_ipt_init(void)
{
	int rc;
	int cpu;

	if (!vtss_ipt_supported()) {
		vtss_pr_error("IPT not supported");
		return -EINVAL;
	}
	for (cpu = 0; cpu < vtss_nr_cpus(); cpu++) {
		rc = vtss_ipt_register(cpu);
		if (rc) goto out_fail;
	}
	vtss_ipt_set_active();
	vtss_pr_notice("IPT: mode: 0x%x", vtss_reqcfg.ipt_cfg.mode);
	return 0;

out_fail:
	vtss_ipt_cleanup();
	return -ENOMEM;
}

static void vtss_ipt_ctl_init(void)
{
	unsigned long long iptctl;

	rdmsrl(VTSS_IA32_RTIT_CTL, iptctl);
	wrmsrl(VTSS_IA32_RTIT_CTL, iptctl & ~VTSS_IPT_CTL_TRACE);
	/* clear MSRs */
	wrmsrl(VTSS_IA32_RTIT_CTL, 0);
	wrmsrl(VTSS_IA32_RTIT_STATUS, 0);
	wrmsrl(VTSS_IA32_RTIT_OUTPUT_BASE, 0);
	wrmsrl(VTSS_IA32_RTIT_OUTPUT_MASK_PTRS, 0);
}

static void vtss_ipt_disable_cb(void *ctx)
{
	vtss_ipt_disable();
}

void vtss_ipt_cleanup(void)
{
	int cpu;

	if (vtss_ipt_set_inactive())
		on_each_cpu(vtss_ipt_disable_cb, NULL, 1);
	for (cpu = 0; cpu < vtss_nr_cpus(); cpu++)
		vtss_ipt_unregister(cpu);
}

void vtss_ipt_enable(unsigned int mode)
{
	int i;
	struct vtss_pcb *pcb = &vtss_pcb_cpu;
	unsigned long long *topa_virt = pcb->topa_virt;

	unsigned long long iptctl;

	rdmsrl(VTSS_IA32_RTIT_CTL, iptctl);
	wrmsrl(VTSS_IA32_RTIT_CTL, iptctl & ~VTSS_IPT_CTL_TRACE);
	/* disable LBRs and BTS */
	wrmsrl(VTSS_IA32_DEBUGCTL, 0);

	iptctl = VTSS_IPT_CTL_TOPA | VTSS_IPT_CTL_TSC | VTSS_IPT_CTL_BRANCH;

	/* form ToPA, and initialize status, base and mask pointers and control MSR */
	for (i = 0; i < VTSS_IPT_NR_BUFFERS; i++)
		topa_virt[i] = pcb->iptbuf_phys[i];
	if (mode & vtss_iptmode_full) {
		topa_virt[VTSS_IPT_NR_BUFFERS/4*3] |= VTSS_IPT_TOPA_INT;
		topa_virt[VTSS_IPT_NR_BUFFERS - 1] |= VTSS_IPT_TOPA_STOP;
	} else {
		topa_virt[0] |= VTSS_IPT_TOPA_STOP;
	}
	topa_virt[i] = pcb->topa_phys | VTSS_IPT_TOPA_END;

	wrmsrl(VTSS_IA32_RTIT_OUTPUT_MASK_PTRS, VTSS_IPT_LOWER_MASK);
	wrmsrl(VTSS_IA32_RTIT_OUTPUT_BASE, pcb->topa_phys);
	wrmsrl(VTSS_IA32_RTIT_STATUS, 0);

	iptctl |= VTSS_IPT_CTL_USER;
	if (mode & vtss_iptmode_ring0)
		iptctl |= VTSS_IPT_CTL_KERNEL;
	if (mode & vtss_iptmode_time)
		iptctl |= VTSS_IPT_CTL_CYCLE;
	if (mode & vtss_iptmode_rets)
		iptctl |= VTSS_IPT_CTL_NORETC;

	wrmsrl(VTSS_IA32_RTIT_CTL, iptctl);
	wrmsrl(VTSS_IA32_RTIT_CTL, iptctl | VTSS_IPT_CTL_TRACE);
}

void vtss_ipt_disable(void)
{
	unsigned long long iptctl;

	rdmsrl(VTSS_IA32_RTIT_CTL, iptctl);
	wrmsrl(VTSS_IA32_RTIT_CTL, iptctl & ~VTSS_IPT_CTL_TRACE);
	/* clear control MSR */
	wrmsrl(VTSS_IA32_RTIT_CTL, 0);
}

static int vtss_ipt_write_overflow(struct vtss_transport *trn, int tidx)
{
	vtss_ipt_record_t rec;

	rec.flagword = VTSS_UEC_LEAF1    | VTSS_UECL1_VRESIDX | VTSS_UECL1_CPUIDX |
		       VTSS_UECL1_CPUTSC | VTSS_UECL1_SYSTRACE;
	rec.residx = tidx;
	rec.cpuidx = vtss_smp_processor_id();
	rec.cputsc = vtss_time_cpu();
	rec.type = VTSS_UECSYSTRACE_IPTOVF;
	rec.size = sizeof(rec.size) + sizeof(rec.type);
	return vtss_transport_write_record(trn, &rec, sizeof(rec), NULL, 0);
}

int vtss_ipt_write(struct vtss_transport *trn, int tidx, bool overflowed)
{
	int rc;
	unsigned short size;
	unsigned long long mask;
	vtss_ipt_record_t rec;

	if (overflowed) {
		rc = vtss_ipt_write_overflow(trn, tidx);
		if (rc) {
			vtss_ipt_ctl_init();
			return rc;
		}
	}

	/* form IPT record and save the contents of the output
	 * buffer (from base to current mask pointer) */
	rdmsrl(VTSS_IA32_RTIT_OUTPUT_MASK_PTRS, mask);
	size = mask >> 32; /* output offset */
	size += (mask & VTSS_IPT_TABLE_MASK) << (PAGE_SHIFT - 7);

	/* [flagword][residx][cpuidx][tsc][systrace(ipt)] */
	rec.flagword = VTSS_UEC_LEAF1    | VTSS_UECL1_VRESIDX | VTSS_UECL1_CPUIDX |
		       VTSS_UECL1_CPUTSC | VTSS_UECL1_SYSTRACE;
	rec.residx = tidx;
	rec.cpuidx = vtss_smp_processor_id();
	rec.cputsc = vtss_time_cpu();
	rec.type = VTSS_UECSYSTRACE_IPT;
	rec.size = sizeof(rec.size) + sizeof(rec.type) + size;

	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), vtss_pcb_cpu.iptbuf_virt, size);
	if (rc) vtss_stat_inc(&trn->lost.ipts);
	vtss_ipt_ctl_init();
	return rc;
}
