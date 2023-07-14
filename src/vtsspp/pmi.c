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

#include "cmd.h"
#include "debug.h"
#include "ipt.h"
#include "lbr.h"
#include "mmap.h"
#include "pebs.h"
#include "pmi.h"
#include "pmu.h"
#include "task.h"
#include "task_map.h"
#include "transport.h"

static atomic_t vtss_resume_count = ATOMIC_INIT(0);

void vtss_profiling_pause(void)
{
	unsigned long flags;

	local_irq_save(flags);
	/* disable IPT (if requested) */
	if (vtss_reqcfg_ipt_mode())
		vtss_ipt_disable();
	/* disable LBR (if requested) */
	if (vtss_reqcfg_lbr_mode())
		vtss_lbr_disable();
	/* disable PEBS */
	vtss_pebs_disable();
	/* disable PMU events */
	vtss_pmu_disable();
	local_irq_restore(flags);
}

void vtss_profiling_resume(struct vtss_task *tsk, bool in_pmi)
{
	int cpu = vtss_smp_processor_id();

	vtss_task_events_disable(tsk);

	if (!vtss_collector_running()) {
		vtss_profiling_pause();
		return;
	}
	if (!vtss_cpu_active(cpu)) {
		vtss_profiling_pause();
		return;
	}
	if (!vtss_task_attached(tsk)) {
		vtss_profiling_pause();
		return;
	}

	atomic_inc(&vtss_resume_count);

	/* enable PEBS */
	vtss_pebs_enable(cpu);
	/* enable IPT (if requested) */
	if (vtss_reqcfg_ipt_mode()) {
		if (in_pmi || vtss_reqcfg_ipt_mode_full())
			vtss_ipt_enable(vtss_reqcfg.ipt_cfg.mode);
	}
	/* enable LBR (if requested) */
	if (vtss_reqcfg_lbr_mode())
		vtss_lbr_enable(tsk->lbr);
	/* enable PMU events */
	vtss_pmu_enable();
	/* restart PMU events */
	vtss_pmu_events_restart(tsk->events[vtss_pmu_id(cpu)]);
	/* events can be sampled */
	vtss_task_events_enable(tsk);

	atomic_dec(&vtss_resume_count);
}

void vtss_profiling_wait(void)
{
	while (atomic_read(&vtss_resume_count) != 0);
}

static void vtss_pmi_sample(struct pt_regs *regs, struct vtss_task *tsk)
{
	unsigned long ip;
	int cpu = vtss_smp_processor_id();

	if (!vtss_collector_started())
		return;
	if (!vtss_cpu_active(cpu))
		return;
	if (!vtss_task_attached(tsk))
		return;

	if (vtss_task_events_enabled(tsk)) {
		/* sample PMU events */
		vtss_pmu_events_sample(tsk->events[vtss_pmu_id(cpu)]);
		vtss_task_events_disable(tsk);
	}

	/* recover switch-to record */
	if (!vtss_task_in_context(tsk))
		vtss_task_write_switch_to(tsk, cpu, instruction_pointer(regs), false);

	if (vtss_task_in_context(tsk)) {
		/* store IPT dump (if requested) */
		if (vtss_reqcfg_ipt_mode())
			vtss_task_write_ipt(tsk);
		/* get IP for sample record */
		if (!tsk->sample_write_err) {
			/* get PEBS IP (if available) */
			ip = vtss_pebs_get_ip(cpu);
			if (ip == 0)
				ip = instruction_pointer(regs);
		} else {
			ip = VTSS_LOST_DATA_MODULE_ADDR;
		}
		/* store sample and its stack */
		vtss_task_write_sample(tsk, ip);
		if (!tsk->sample_write_err) {
			/* collect stack for sample record */
			vtss_task_unwind_stack(tsk, current, regs, 0);
			/* store stack for sample record */
			vtss_task_write_stack(tsk);
		}
	}
}

/**
 * PMU events overflow handler:
 * samples counter values, forms a trace record,
 * selects a new mux group (if applicable),
 * programs event counters.
 */
void vtss_pmi_handler(struct pt_regs *regs)
{
	struct vtss_task *tsk;

	vtss_profiling_pause();

	if (!vtss_is_task_valid(current))
		return;

	tsk = vtss_task_map_get(vtss_gettid(current));
	if (tsk) {
		vtss_pmi_sample(regs, tsk);
		vtss_profiling_resume(tsk, true);
	}
	vtss_task_map_put(tsk);
}
