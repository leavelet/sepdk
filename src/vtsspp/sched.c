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
#include "modcfg.h"
#include "pmi.h"
#include "regs.h"
#include "sched.h"
#include "task.h"
#include "task_map.h"

void vtss_sched_switch_from(struct vtss_task *tsk, struct task_struct *task,
			    unsigned long bp, unsigned long ip)
{
	unsigned long flags;
	int cpu = vtss_smp_processor_id();

	if (!vtss_cpu_active(cpu))
		return;
	if (!vtss_task_attached(tsk))
		return;
	if (vtss_is_task_in_execve(task))
		return;

	local_irq_save(flags);
	preempt_disable();

	/* save LBR (if requested) */
	if (vtss_reqcfg_lbr_mode())
		vtss_lbr_save(tsk->lbr);

	if (vtss_task_events_enabled(tsk)) {
		/* sample PMU events */
		vtss_pmu_events_sample(tsk->events[vtss_pmu_id(cpu)]);
		vtss_task_events_disable(tsk);
	}

	/* store IPT dump (if requested) */
	if (vtss_reqcfg_ipt_mode_full()) {
		if (vtss_task_in_context(tsk))
			vtss_task_write_ipt(tsk);
	}

	/* store switch-from IP */
	tsk->from_ip = ip;

	/* store sample and switch-from records and exit from the context */
	vtss_task_write_switch_from(tsk, vtss_is_task_preempt(task));

	/* collect stack on switch-from */
	if (vtss_reqcfg_ctx_mode())
		vtss_task_unwind_stack(tsk, task, NULL, bp);

	preempt_enable_no_resched();
	local_irq_restore(flags);
}

void vtss_sched_switch_to(struct vtss_task *tsk, struct task_struct *task,
			  unsigned long ip)
{
	unsigned long flags;
	int cpu = vtss_smp_processor_id();

	if (!vtss_cpu_active(cpu)) {
		vtss_profiling_pause();
		return;
	}
	if (!vtss_task_attached(tsk)) {
		vtss_profiling_pause();
		return;
	}
	if (vtss_is_task_in_execve(task)) {
		vtss_profiling_pause();
		return;
	}

	local_irq_save(flags);
	preempt_disable();

	/* use switch-from IP */
	if (ip == 0)
		ip = tsk->from_ip;
	/* use user IP if no stacks on context switches */
	if (ip == 0 || !vtss_reqcfg_ctx_mode())
		ip = vtss_get_task_ip(task);

	/* store switch-to record and enter the context */
	vtss_task_write_switch_to(tsk, cpu, ip, true);

	/* store switch-from stack (if requested) */
	if (vtss_reqcfg_ctx_mode()) {
		if (vtss_task_in_context(tsk)) {
			/* collect stack if switch-from stack is empty */
			if (!vtss_task_stack_unwound(tsk))
				vtss_task_unwind_stack(tsk, task, NULL, 0);
			/* store previously collected stack */
			vtss_task_write_stack(tsk);
		}
	}

	vtss_profiling_resume(tsk, false);

	preempt_enable_no_resched();
	local_irq_restore(flags);
}

#ifdef VTSS_PREEMPT_NOTIFIERS
static void vtss_sched_switch_from_notifier(struct preempt_notifier *notifier,
					    struct task_struct *next)
{
	struct vtss_task *tsk;

	vtss_profiling_pause();

	tsk = vtss_task_map_get(vtss_gettid(current));
	if (tsk)
		vtss_sched_switch_from(tsk, current, vtss_read_rbp(), 0);
	vtss_task_map_put(tsk);
}

static void vtss_sched_switch_to_notifier(struct preempt_notifier *notifier,
					  int cpu)
{
	struct vtss_task *tsk;

	tsk = vtss_task_map_get(vtss_gettid(current));
	if (tsk)
		vtss_sched_switch_to(tsk, current, _THIS_IP_);
	else
		vtss_profiling_pause();
	vtss_task_map_put(tsk);
}

bool vtss_sched_preempt_notifiers = false;

struct preempt_ops vtss_sched_preempt_ops = {
	.sched_out = vtss_sched_switch_from_notifier,
	.sched_in  = vtss_sched_switch_to_notifier
};
#endif

void vtss_sched_switch(struct task_struct *prev, struct task_struct *next,
		       unsigned long prev_bp, unsigned long prev_ip)
{
	struct vtss_task *tsk;

	vtss_profiling_pause();

	tsk = vtss_task_map_get(vtss_gettid(prev));
	if (tsk)
		vtss_sched_switch_from(tsk, prev, prev_bp, prev_ip);
	vtss_task_map_put(tsk);

	tsk = vtss_task_map_get(vtss_gettid(next));
	if (tsk)
		vtss_sched_switch_to(tsk, next, 0);
	vtss_task_map_put(tsk);
}
