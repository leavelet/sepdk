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

#include "cpu.h"
#include "debug.h"
#include "kmem.h"
#include "kpti.h"
#include "modcfg.h"
#include "pcb.h"
#include "pebs.h"
#include "pmu.h"
#include "regs.h"

#define VTSS_PEBS_NR_RECORDS 2

#define VTSS_PEBS_RECORD_SIZE_MRM offsetof(struct vtss_pebs, applicable_counter)
#define VTSS_PEBS_RECORD_SIZE_NHM offsetof(struct vtss_pebs, eventing_ip)
#define VTSS_PEBS_RECORD_SIZE_HSW offsetof(struct vtss_pebs, tsc)
#define VTSS_PEBS_RECORD_SIZE_SKL sizeof(struct vtss_pebs)

#define vtss_pebs_core() (vtss_pebs_record_size == VTSS_PEBS_RECORD_SIZE_MRM)

#define vtss_pebs_has_eventing_ip() (vtss_pebs_record_size >= VTSS_PEBS_RECORD_SIZE_HSW)

#define vtss_dsa_buffer_size(cpu)\
	(sizeof(struct vtss_dsa) + \
	 vtss_pebs_nr_counters(vtss_pmu_id(cpu))*sizeof(unsigned long long))

#define vtss_pebs_buffer_size() (VTSS_PEBS_NR_RECORDS*vtss_pebs_record_size)

#ifdef VTSS_DISABLE_PEBS
atomic_t vtss_pebs_active = ATOMIC_INIT(-1);
#else
atomic_t vtss_pebs_active = ATOMIC_INIT(0);
#endif

#define vtss_pebs_disabled() (atomic_read(&vtss_pebs_active) == -1)
#define vtss_pebs_set_active() atomic_set(&vtss_pebs_active, 1)
#define vtss_pebs_set_inactive() (atomic_cmpxchg(&vtss_pebs_active, 1, 0) == 1)

static bool vtss_pebs_extended = false;
static size_t vtss_pebs_record_size = 0;

static int vtss_pebs_nr_counters(int pmu_id)
{
	int counters;

	if (vtss_pebs_core())
		return VTSS_PMU_V3_NR_GP_COUNTERS;

	counters = vtss_pmu_nr_gp_counters[pmu_id];
	if (vtss_pebs_extended)
		counters += vtss_pmu_nr_fx_counters[pmu_id];

	if (counters < VTSS_PMU_V3_NR_GP_COUNTERS)
		counters = VTSS_PMU_V3_NR_GP_COUNTERS;

	return counters;
}

static unsigned long long vtss_pebs_enable_mask(int pmu_id)
{
	if (vtss_pebs_core())
		return VTSS_PEBS_ENABLE_PMC0;
	return vtss_pmu_counters_mask(pmu_id, vtss_pebs_extended, true);
}

static int vtss_dsa_register(size_t size, int cpu)
{
	void *buffer;

	size = (PAGE_SIZE << get_order(size));

#ifdef VTSS_KPTI
	if (vtss_kpti_enabled && size > PAGE_SIZE) {
		vtss_pr_error("Failed to register more than CEA DSA allows: %ld", PAGE_SIZE);
		return -ENOMEM;
	}
	if (vtss_kpti_enabled) {
		/* CEA DSA should be already mapped to user and kernel space */
		void *cea = &get_cpu_entry_area(cpu)->cpu_debug_store;
		memset(cea, 0, size);
		vtss_pcb(cpu).dsa = cea;
		return 0;
	}
#endif
	buffer = vtss_alloc_pages(size, GFP_KERNEL | __GFP_ZERO, cpu);
	if (buffer == NULL) {
		vtss_pr_error("Not enough memory for DSA buffer on cpu%d", cpu);
		return -ENOMEM;
	}
	vtss_pcb(cpu).dsa_virt = buffer;
#ifdef VTSS_KAISER
	if (vtss_kpti_enabled) {
		int rc = vtss_kaiser_register(buffer, size);
		if (rc) {
			vtss_pr_error("Failed to register DSA buffer on cpu%d", cpu);
			return rc;
		}
	}
#endif
	vtss_pcb(cpu).dsa = buffer;
	return 0;
}

static void vtss_dsa_unregister(size_t size, int cpu)
{
	size = (PAGE_SIZE << get_order(size));

#ifdef VTSS_KAISER
	if (vtss_kpti_enabled)
		vtss_kaiser_unregister(vtss_pcb(cpu).dsa, size);
#endif
	vtss_pcb(cpu).dsa = NULL;

	vtss_free_pages(vtss_pcb(cpu).dsa_virt, size);
	vtss_pcb(cpu).dsa_virt = NULL;
}

static int vtss_pebs_register(size_t size, int cpu)
{
	void *buffer;

	size = (PAGE_SIZE << get_order(size));

#ifdef VTSS_KPTI
	if (vtss_kpti_enabled && size > PEBS_BUFFER_SIZE) {
		vtss_pr_error("Failed to register more than CEA PEBS allows: %ld",
			      PEBS_BUFFER_SIZE);
		return -ENOMEM;
	}
#endif

	buffer = vtss_alloc_pages(size, GFP_KERNEL | __GFP_ZERO, cpu);
	if (buffer == NULL) {
		vtss_pr_error("Not enough memory for PEBS buffer on cpu%d", cpu);
		return -ENOMEM;
	}
	vtss_pcb(cpu).pebs_virt = buffer;

#ifdef VTSS_KPTI
	if (vtss_kpti_enabled) {
		void *cea = &get_cpu_entry_area(cpu)->cpu_debug_buffers.pebs_buffer;
		int rc = vtss_cea_register(cea, buffer, size);
		if (rc) {
			vtss_pr_error("Failed to register PEBS buffer on cpu%d", cpu);
			return rc;
		}
		buffer = cea;
	}
#elif defined(VTSS_KAISER)
	if (vtss_kpti_enabled) {
		int rc = vtss_kaiser_register(buffer, size);
		if (rc) {
			vtss_pr_error("Failed to register PEBS buffer on cpu%d", cpu);
			return rc;
		}
	}
#endif
	vtss_pcb(cpu).pebs = buffer;
	return 0;
}

static void vtss_pebs_unregister(size_t size, int cpu)
{
	size = (PAGE_SIZE << get_order(size));

#ifdef VTSS_KPTI
	if (vtss_kpti_enabled)
		vtss_cea_unregister(vtss_pcb(cpu).pebs, size);
#elif defined(VTSS_KAISER)
	if (vtss_kpti_enabled)
		vtss_kaiser_unregister(vtss_pcb(cpu).pebs, size);
#endif
	vtss_pcb(cpu).pebs = NULL;

	vtss_free_pages(vtss_pcb(cpu).pebs_virt, size);
	vtss_pcb(cpu).pebs_virt = NULL;
}

static void vtss_dsa_save_cb(void *ctx)
{
	rdmsrl(VTSS_IA32_DS_AREA, vtss_pcb_cpu.msr_dsa);
	wrmsrl(VTSS_IA32_PEBS_ENABLE, 0);
}

static void vtss_dsa_restore_cb(void *ctx)
{
	wrmsrl(VTSS_IA32_PEBS_ENABLE, 0);
	wrmsrl(VTSS_IA32_DS_AREA, vtss_pcb_cpu.msr_dsa);
}

int vtss_pebs_init(void)
{
	int rc = 0, cpu;

	if (vtss_pebs_disabled()) {
		vtss_pr_warning("PEBS feature disabled");
		return 0;
	}

	if (vtss_pmu_version >= 5) {
		vtss_pebs_extended = true;
		vtss_pebs_record_size = VTSS_PEBS_RECORD_SIZE_SKL;
	} else if (vtss_pmu_version == 4) {
		vtss_pebs_record_size = VTSS_PEBS_RECORD_SIZE_SKL;
	} else if (vtss_pmu_version == 3) {
		switch (vtss_hardcfg.model) {
		case VTSS_CPU_HSW:
		case VTSS_CPU_HSW_X:
		case VTSS_CPU_HSW_M:
		case VTSS_CPU_HSW_G:
		case VTSS_CPU_BDW:
		case VTSS_CPU_BDW_G:
		case VTSS_CPU_BDW_X:
		case VTSS_CPU_BDW_XD:
			vtss_pebs_record_size = VTSS_PEBS_RECORD_SIZE_HSW;
			break;
		case VTSS_CPU_NHM:
		case VTSS_CPU_NHM_G:
		case VTSS_CPU_NHM_EP:
		case VTSS_CPU_NHM_EX:
		case VTSS_CPU_WMR:
		case VTSS_CPU_WMR_EP:
		case VTSS_CPU_WMR_EX:
		case VTSS_CPU_SNB:
		case VTSS_CPU_SNB_X:
		case VTSS_CPU_IVB:
		case VTSS_CPU_IVB_X:
			vtss_pebs_record_size = VTSS_PEBS_RECORD_SIZE_NHM;
			break;
		}
	}
	if (vtss_pebs_record_size == 0) {
		vtss_pr_warning("Fallback to core PEBS");
		vtss_pebs_record_size = VTSS_PEBS_RECORD_SIZE_MRM;
	}

	on_each_cpu(vtss_dsa_save_cb, NULL, 1);
	for (cpu = 0; cpu < vtss_nr_cpus(); cpu++) {
		rc = vtss_dsa_register(vtss_dsa_buffer_size(cpu), cpu);
		if (rc)	goto out_fail;
		rc = vtss_pebs_register(vtss_pebs_buffer_size(), cpu);
		if (rc)	goto out_fail;
	}
	vtss_pebs_set_active();

	vtss_pr_notice("PEBS: record size: 0x%02lx, mask: 0x%02llx, counters: %d",
		       vtss_pebs_record_size, vtss_pebs_enable_mask(VTSS_PMU_CORE),
		       vtss_pebs_nr_counters(VTSS_PMU_CORE));
	if (vtss_cpu_hybrid_mode)
		vtss_pr_notice("PEBS: record size: 0x%02lx, mask: 0x%02llx, counters: %d",
			       vtss_pebs_record_size, vtss_pebs_enable_mask(VTSS_PMU_ATOM),
			       vtss_pebs_nr_counters(VTSS_PMU_ATOM));

	return 0;

out_fail:
	vtss_pebs_cleanup();
	return rc;
}

void vtss_pebs_cleanup(void)
{
	int cpu;

	if (vtss_pebs_set_inactive())
		on_each_cpu(vtss_dsa_restore_cb, NULL, 1);
	for (cpu = 0; cpu < vtss_nr_cpus(); cpu++) {
		vtss_pebs_unregister(vtss_pebs_buffer_size(), cpu);
		vtss_dsa_unregister(vtss_dsa_buffer_size(cpu), cpu);
	}
}

void vtss_pebs_enable(int cpu)
{
	int i, pmu_id = vtss_pmu_id(cpu);
	struct vtss_dsa *dsa = vtss_pcb_cpu.dsa;
	struct vtss_pebs *pebs = vtss_pcb_cpu.pebs;

	if (dsa == NULL)
		return;
	if (pebs == NULL)
		return;

	/* setup PEBS in DSA */
	dsa->pebs_base   = pebs;
	dsa->pebs_index  = pebs;
	dsa->pebs_absmax = (char *)pebs + vtss_pebs_buffer_size();
	if (vtss_pebs_core())
		dsa->pebs_threshold = pebs;
	else
		dsa->pebs_threshold = (char *)pebs + vtss_pebs_record_size;
	/* reset PEBS counters */
	for (i = 0; i < vtss_pebs_nr_counters(pmu_id); i++)
		dsa->pebs_reset[i] = 0;
	/* invalidate the first PEBS record */
	pebs->ip = 0;

	/* enable DSA */
	wrmsrl(VTSS_IA32_DS_AREA, (unsigned long long)dsa);

	/* enable PEBS */
	wrmsrl(VTSS_IA32_PEBS_ENABLE, vtss_pebs_enable_mask(pmu_id));
}

void vtss_pebs_disable(void)
{
/**
 * Disabled as there are CPUs which reboot if a PEBS PMI is
 * encountered when PEBS is disabled.
 * PEBS is effectively disabled when disabling PMU counters.
 */
}

unsigned long vtss_pebs_get_ip(int cpu)
{
	struct vtss_dsa *dsa;
	struct vtss_pebs *pebs;

	dsa = vtss_pcb(cpu).dsa;
	if (dsa == NULL)
		return 0;

	if (dsa->pebs_index != dsa->pebs_base) {
		pebs = dsa->pebs_base;
		if (pebs == NULL)
			return 0;
		if (vtss_pebs_has_eventing_ip())
			return pebs->eventing_ip;
		else
			return pebs->ip;
	}
	return 0;
}
