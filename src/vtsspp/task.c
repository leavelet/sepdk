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
#include "kmem.h"
#include "modcfg.h"
#include "record.h"
#include "regs.h"
#include "sched.h"
#include "task.h"
#include "unwind.h"

int vtss_task_init(struct vtss_task *tsk, pid_t tid, pid_t pid, pid_t ppid, int order)
{
	tsk->tid = tid;
	tsk->pid = pid;
	tsk->ppid = ppid;
	tsk->order = order;
	tsk->cpu = vtss_smp_processor_id();
	atomic_set(&tsk->usage, 1);
	if (sizeof(struct vtss_task) > PAGE_SIZE)
		vtss_pr_warning("%d: Task structure requires too much memory", tid);
	return 0;
}

int vtss_task_init_buffers(struct vtss_task *tsk)
{
	int pmu_id;

	tsk->stk = vtss_zalloc(sizeof(struct vtss_stack), GFP_KERNEL);
	if (tsk->stk == NULL) {
		vtss_pr_error("%d: Not enough memory for stack structure", tsk->tid);
		return -ENOMEM;
	}
	tsk->lbr = vtss_zalloc(sizeof(struct vtss_lbr), GFP_KERNEL);
	if (tsk->lbr == NULL) {
		vtss_pr_error("%d: Not enough memory for LBR structure", tsk->tid);
		return -ENOMEM;
	}
	for (pmu_id = 0; pmu_id < VTSS_PMU_SIZE; pmu_id++) {
		tsk->events[pmu_id] = vtss_zalloc(sizeof(struct vtss_pmu_events) +
			vtss_reqcfg.nr_events[pmu_id]*sizeof(struct vtss_pmu_event), GFP_KERNEL);
		if (tsk->events[pmu_id] == NULL) {
			vtss_pr_error("%d: Not enough memory for events[%d] structure",
				      tsk->tid, pmu_id);
			return -ENOMEM;
		}
	}
	tsk->mmap_write_buf = vtss_zalloc(PAGE_SIZE, GFP_KERNEL);
	if (tsk->mmap_write_buf == NULL) {
		vtss_pr_error("%d: Not enough memory for mmap write buffer", tsk->tid);
		return -ENOMEM;
	}
	return 0;
}

void vtss_task_cleanup(struct vtss_task *tsk)
{
	int pmu_id;

	vtss_zfree(&tsk->stk, sizeof(struct vtss_stack));
	vtss_zfree(&tsk->lbr, sizeof(struct vtss_lbr));
	for (pmu_id = 0; pmu_id < VTSS_PMU_SIZE; pmu_id++) {
		vtss_zfree(&tsk->events[pmu_id], sizeof(struct vtss_pmu_events) +
			   vtss_reqcfg.nr_events[pmu_id]*sizeof(struct vtss_pmu_event));
	}
	vtss_zfree(&tsk->mmap_write_buf, PAGE_SIZE);
}

void vtss_task_set_name(struct vtss_task *tsk, struct task_struct *task)
{
	if (!task)
		return;

	get_task_comm(tsk->name, task);
	tsk->name[TASK_COMM_LEN - 1] = '\0';
}

void vtss_task_write_switch_from(struct vtss_task *tsk, bool preempt)
{
	if (vtss_task_in_context(tsk)) {
		/* store switch-from record, the loader will
		 * restore this record in case of an error */
		vtss_transport_write_switch_from(vtss_task_trn_sample(tsk), tsk->cpu, preempt);
		/* exit from the context */
		vtss_task_clear_context(tsk);
	}
}

void vtss_task_write_switch_to(struct vtss_task *tsk, int cpu, unsigned long ip, bool write_sample)
{
	int rc;

	/* store thread start record (if requested) */
	if (tsk->newtask_write_err) {
		tsk->newtask_write_err =
			vtss_transport_write_thread_start(tsk->trn, tsk->tid, tsk->pid, tsk->cpu);
		if (tsk->newtask_write_err)
			return;
	}

	/* store softcfg record (if requested) */
	if (tsk->softcfg_write_err) {
		tsk->softcfg_write_err =
			vtss_transport_write_softcfg(tsk->trn, tsk->tid);
		if (tsk->softcfg_write_err)
			return;
	}

	/* store pause record (if requested) */
	if (tsk->pause_write_err && vtss_collector_paused())
		tsk->pause_write_err =
			vtss_transport_write_probe(tsk->trn, tsk->cpu, VTSS_FID_ITT_PAUSE);

	/* don't enter the context if collector paused or not started */
	if (!vtss_collector_running())
		return;

	/* store sample on previous cpu */
	if (write_sample)
		vtss_task_write_sample(tsk, 0);

	/* store switch-to record */
	rc = vtss_transport_write_switch_to(vtss_task_trn_sample(tsk), tsk->tid, cpu, ip);
	if (!rc) {
		/* store cpu for sample records */
		tsk->cpu = cpu;
		/* enter the context */
		vtss_task_set_context(tsk);
	}
}

void vtss_task_unwind_stack(struct vtss_task *tsk, struct task_struct *task,
			    struct pt_regs *regs, unsigned long bp)
{
	int rc;
	unsigned long fp;

	if (!vtss_reqcfg_stk_mode())
		return;

	if (!vtss_stack_trylock(tsk->stk))
		return;

	/* get FP for unwinding */
	fp = regs ? regs->bp : bp;
	if (fp == 0)
		fp = vtss_read_rbp();

	/* clear kernel and user callchains */
	vtss_callchain_reset(&tsk->stk->kernel);
	vtss_callchain_reset(&tsk->stk->user);

	/* clear stack map history if stack was not stored */
	if (vtss_task_stack_unwound(tsk)) {
		vtss_stack_map_reset(tsk->stk);
		vtss_task_clear_stack_unwound(tsk);
	}
	/* collect user and kernel stacks */
	rc = vtss_stack_unwind(tsk->stk, task, regs, fp);
	if (!rc) {
		vtss_task_set_stack_unwound(tsk);
	} else {
		vtss_transport_write_debug(vtss_task_trn_sample(tsk),
			"Unwind error: %d: vresidx = 0x%08x, cpuidx = 0x%08x, ip = 0x%lx, stack = [0x%lx-0x%lx]",
			-rc, vtss_gettid(task), tsk->cpu, tsk->stk->ip, tsk->stk->sp, tsk->stk->bp);
		vtss_stack_map_reset(tsk->stk);
		tsk->stk->stat.eunwind++;
	}
	tsk->stk->stat.samples++;
	vtss_stack_unlock(tsk->stk);
}

void vtss_task_write_stack(struct vtss_task *tsk)
{
	int rc;

	if (!vtss_reqcfg_stk_mode())
		return;

	if (!vtss_stack_trylock(tsk->stk))
		return;

	/* store user and kernel stacks */
	rc = vtss_stack_write(vtss_task_trn_sample(tsk), tsk->stk, tsk->tid, tsk->cpu);
	if (!rc) vtss_task_clear_stack_unwound(tsk);

	vtss_stack_unlock(tsk->stk);
}

#ifdef VTSS_PREEMPT_NOTIFIERS
/* this prevents the registered state from being set if there were attempts to unregister */
#define vtss_task_set_notifier_registered(tsk) (atomic_inc_return(&(tsk)->notifier_registered) == 1)
#define vtss_task_set_notifier_unregistered(tsk) atomic_dec_and_test(&(tsk)->notifier_registered)

void vtss_task_init_notifier(struct vtss_task *tsk)
{
	if (vtss_sched_preempt_notifiers)
		preempt_notifier_init(&tsk->preempt_notifier, &vtss_sched_preempt_ops);
}

void vtss_task_register_notifier(struct vtss_task *tsk, struct task_struct *task)
{
	if (!task)
		return;
	if (vtss_sched_preempt_notifiers) {
		hlist_add_head(&tsk->preempt_notifier.link, &task->preempt_notifiers);
		if (vtss_task_set_notifier_registered(tsk))
			vtss_pr_debug_task("registered notifier for %d", tsk->tid);
		else
			preempt_notifier_unregister(&tsk->preempt_notifier);
	}
}

void vtss_task_unregister_notifier(struct vtss_task *tsk, struct task_struct *task)
{
	bool held = false;

	if (vtss_task_set_notifier_unregistered(tsk)) {
		if (!task) {
			task = vtss_get_task_struct(tsk->tid);
			held = true;
		}
		if (task) {
			preempt_notifier_unregister(&tsk->preempt_notifier);
			if (held) vtss_put_task_struct(task);
			vtss_pr_debug_task("unregistered notifier for %d", tsk->tid);
		}
	}
}
#endif
