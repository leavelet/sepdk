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
#include "kmem.h"
#include "mmap.h"
#include "modcfg.h"
#include "pmi.h"
#include "procfs.h"
#include "record.h"
#include "sched.h"
#include "stack.h"
#include "target.h"
#include "task.h"
#include "task_map.h"
#include "transport.h"

#include <linux/delay.h>	/* for msleep_interruptible */
#include <linux/hardirq.h>	/* for in_atomic */

#define vtss_target_workers_inc() atomic_inc(&vtss_target_workers)
#define vtss_target_workers_dec() atomic_dec(&vtss_target_workers)

static atomic_t vtss_target_workers = ATOMIC_INIT(0);

static int vtss_target_add_transport(struct vtss_task *tsk)
{
	int mode = 0;
	const char *name;

	/* enable IPT mode */
	if (vtss_reqcfg_ipt_mode())
		mode |= VTSS_TRANSPORT_IPT;

	/* create primary transport */
	tsk->trn = vtss_transport_add(tsk->ppid, tsk->pid, tsk->order, mode);
	if (tsk->trn == NULL) {
		vtss_pr_error("%d: Failed to add transport", tsk->tid);
		return -EFAULT;
	}

	/* enable ring-buffer mode for secondary transport */
	if (vtss_reqcfg_rb_mode())
		mode |= VTSS_TRANSPORT_RB;

	/* create secondary transport */
	mode |= VTSS_TRANSPORT_AUX;
	tsk->trn_aux = vtss_transport_add(tsk->ppid, tsk->pid, tsk->order, mode);
	if (tsk->trn_aux == NULL)
		vtss_pr_warning("%d: Failed to add secondary transport", tsk->tid);

	/* notify the user about transport creation */
	name = tsk->trn_aux ? tsk->trn_aux->name : tsk->trn->name;
	vtss_procfs_control_send(name, strlen(name) + 1);

	/* if no secondary transport is created, then the primary is used */
	if (tsk->trn_aux == NULL)
		tsk->trn_aux = tsk->trn;

	/* write initial records */
	vtss_transport_write_configs(vtss_task_trn_config(tsk), tsk->m32);
	vtss_transport_write_process_exec(tsk->trn, tsk->name, tsk->tid, tsk->pid, tsk->cpu);
	return 0;
}

static bool vtss_target_wait_attached(struct vtss_task *tsk)
{
	int wait_count = VTSS_TARGET_WAIT_TIMEOUT/VTSS_WAIT_INTERVAL;

	while (wait_count--) {
		if (vtss_task_attached(tsk))
			return true;
		if (vtss_task_invalid(tsk))
			return false;
		msleep_interruptible(VTSS_WAIT_INTERVAL);
	}
	vtss_pr_warning("%d: Wait timeout", tsk->tid);
	return false;
}

static int vtss_target_attach_transport(struct vtss_task *tsk)
{
	int rc = 0;
	struct vtss_task *ptsk;

	ptsk = vtss_task_map_get(tsk->pid);
	if (ptsk == NULL) {
		vtss_pr_error("%d: Lead task %d doesn't exist", tsk->tid, tsk->pid);
		return -ESRCH;
	}
	if (vtss_target_wait_attached(ptsk)) {
		/* use process leader transport */
		tsk->trn = ptsk->trn;
		tsk->trn_aux = ptsk->trn_aux;
		/* hold primary transport */
		if (tsk->trn)
			vtss_transport_get(tsk->trn);
		else
			rc = -EFAULT;
		/* hold secondary transport */
		if (tsk->trn_aux && tsk->trn_aux != tsk->trn)
			vtss_transport_get(tsk->trn_aux);
	} else {
		vtss_pr_error("%d: Lead task %d not attached", tsk->tid, tsk->pid);
		rc = -EFAULT;
	}
	vtss_task_map_put(ptsk);
	return rc;
}

static void vtss_target_detach_transport(struct vtss_task *tsk)
{
	if (tsk->trn == NULL)
		return;

	/* write thread final records */
	vtss_transport_write_thread_name(tsk->trn, tsk->name, tsk->tid);
	vtss_transport_write_thread_stop(tsk->trn, tsk->tid, tsk->pid, tsk->cpu);

	/* release secondary transport */
	if (tsk->trn_aux && tsk->trn_aux != tsk->trn) {
		if (vtss_transport_put(tsk->trn_aux))
			vtss_transport_complete(tsk->trn_aux);
	}
	tsk->trn_aux = NULL;

	/* release primary transport */
	if (vtss_transport_put(tsk->trn)) {
		/* write process final record before transport completion */
		vtss_transport_write_process_exit(tsk->trn, tsk->name, tsk->tid,
						  tsk->pid, tsk->cpu);
		vtss_transport_complete(tsk->trn);
	}
	tsk->trn = NULL;
}

static void vtss_target_mmap_write_worker(struct work_struct *work)
{
	struct task_struct *task;
	struct vtss_task *tsk = container_of(work, struct vtss_task, mmap_write_work);

	if (!vtss_collector_started())
		goto out;

	/* too late to add module map */
	if (!vtss_task_hashed(tsk))
		goto out;

	/* check if user task still exists */
	task = vtss_get_task_struct(tsk->tid);
	if (task == NULL)
		goto out;
	vtss_mmap_write_all(tsk, task);
	vtss_put_task_struct(task);
out:
	vtss_task_map_put(tsk);
	vtss_target_workers_dec();
}

static void vtss_target_write_mmap_async(pid_t tid, int order)
{
	struct vtss_task *tsk;

	tsk = vtss_task_map_get(tid);
	if (tsk && tsk->order == order) {
		vtss_target_workers_inc();
		INIT_WORK(&tsk->mmap_write_work, vtss_target_mmap_write_worker);
		vtss_queue_work(&tsk->mmap_write_work);
		vtss_pr_debug_task("scheduled mmap work for %d:%d", tsk->tid, tsk->order);
		/* tsk will be put by vtss_target_mmap_write_worker() */
		return;
	}
	vtss_task_map_put(tsk);
}

static int vtss_target_attach(struct vtss_task *tsk)
{
	int rc;
	struct task_struct *task;

	if (!vtss_collector_started())
		return -EFAULT;

	vtss_pr_debug_task("attaching to %d:%d", tsk->tid, tsk->order);

	/* initialize task buffers */
	rc = vtss_task_init_buffers(tsk);
	if (rc) return rc;

	/* initialize stack structure */
	rc = vtss_stack_init(tsk->stk, tsk->m32);
	if (rc) return rc;

	/* initialize transport */
	if (vtss_task_leader(tsk)) {
		rc = vtss_target_add_transport(tsk);
		if (rc) return rc;
	} else {
		rc = vtss_target_attach_transport(tsk);
		if (rc) return rc;
	}
	/* initialize pmu events */
	vtss_pmu_events_init(tsk->events[VTSS_PMU_CORE], VTSS_PMU_CORE);
	vtss_pmu_events_init(tsk->events[VTSS_PMU_ATOM], VTSS_PMU_ATOM);

	/* profiling starts after this call */
	vtss_task_set_attached(tsk);

	/* check if task is not removed */
	if (!vtss_task_hashed(tsk)) {
		vtss_pr_debug_task("task %d:%d completed", tsk->tid, tsk->order);
		return 0;
	}
	/* check if user task still exists */
	task = vtss_get_task_struct(tsk->tid);
	if (!task) {
		vtss_pr_warning("%d: Task doesn't exist", tsk->tid);
		return 0;
	}
	if (vtss_is_task_dead(task)) {
		vtss_pr_debug_task("task %d:%d terminated", tsk->tid, tsk->order);
		goto out;
	}
	if (vtss_is_task_in_execve(task) || vtss_is_task_exiting(task)) {
		vtss_pr_debug_task("task %d:%d is terminating", tsk->tid, tsk->order);
		goto out;
	}
	/* store user and kernel module map */
	if (vtss_task_leader(tsk)) {
		if (vtss_mmap_write_all(tsk, task))
			/* we should try to store module map again */
			vtss_target_write_mmap_async(tsk->tid, tsk->order);
	}
	/* register preempt notifier */
	vtss_task_register_notifier(tsk, task);

	if (vtss_task_leader(tsk))
		vtss_pr_notice("Attached to '%s' (pid: %d)", tsk->name, tsk->pid);
out:
	vtss_put_task_struct(task);
	return 0;
}

static void vtss_target_attach_worker(struct work_struct *work)
{
	int rc;
	struct vtss_task *tsk = container_of(work, struct vtss_task, attach_work);

	vtss_pr_debug_task("deffered attach to %d:%d", tsk->tid, tsk->order);

	rc = vtss_target_attach(tsk);
	if (rc) vtss_task_set_invalid(tsk);
	vtss_task_map_put(tsk);
	vtss_target_workers_dec();
	return;
}

static void vtss_target_switch_to_cb(void *ctx)
{
	struct vtss_task *tsk = ctx;

	if (tsk->tid == vtss_gettid(current)) {
		if (vtss_task_hashed(tsk)) {
			vtss_pr_debug_task("switching to %d:%d", tsk->tid, tsk->order);
			vtss_sched_switch_to(tsk, current, 0);
		}
	}
}

static void vtss_target_delete(struct vtss_task *tsk);

int vtss_target_add(struct task_struct *task, int order, bool attach)
{
	int rc = 0;
	struct vtss_task *tsk;
	pid_t tid = vtss_gettid(task);
	pid_t pid = vtss_getpid(task);
	pid_t ppid = vtss_getppid(task);

	vtss_pr_debug_task("tid=%d, pid=%d, ppid=%d, order=%d", tid, pid, ppid, order);

	if (!vtss_collector_started())
		return -EFAULT;

	/* allocate task structure */
	tsk = vtss_zalloc(sizeof(struct vtss_task), GFP_ATOMIC);
	if (tsk == NULL) {
		vtss_pr_error("%d: Not enough memory for task structure", tid);
		return -ENOMEM;
	}
	/* initialize task structure */
	vtss_task_init(tsk, tid, pid, ppid, order);

	/* request thread start record */
	tsk->newtask_write_err = -EAGAIN;
	/* request softcfg record */
	tsk->softcfg_write_err = -EAGAIN;
	/* request pause record (if applicable) */
	if (vtss_collector_paused())
		tsk->pause_write_err = -EAGAIN;

	/* setup correct arch of user task */
	tsk->m32 = !vtss_is_task_64bit_mode(task);

	/* initialize preempt notifier */
	vtss_task_init_notifier(tsk);

	/* initialize task name */
	vtss_task_set_name(tsk, task);

	/* skip runtool profiling */
	if (strcmp(tsk->name, VTSS_RUNSS_NAME) == 0)
		tsk->order = -1;

	/* register delete callback */
	tsk->delete_cb = vtss_target_delete;

	/* add to hash table as not attached
	 * and with incremented usage */
	vtss_task_map_add(tsk);

	if (tsk->order < 0) {
		/* skip runtool attaching */
		vtss_task_set_invalid(tsk);
		vtss_task_map_put(tsk);
	} else if (attach && !(in_atomic() || irqs_disabled())) {
		/* attach to the task immediately */
		vtss_target_workers_inc();
		rc = vtss_target_attach(tsk);
		if (rc) vtss_task_set_invalid(tsk);
		/* enter context immediately */
		if (vtss_task_attached(tsk))
			on_each_cpu(vtss_target_switch_to_cb, &tsk, 1);
		vtss_task_map_put(tsk);
		vtss_target_workers_dec();
	} else {
		/* schedule attach work */
		vtss_target_workers_inc();
		INIT_WORK(&tsk->attach_work, vtss_target_attach_worker);
		vtss_queue_work(&tsk->attach_work);
		/* tsk will be put by vtss_target_attach_worker() */
	}
	return rc;
}

static void vtss_target_delete(struct vtss_task *tsk)
{
	vtss_pr_debug_task("deleting %d:%d", tsk->tid, tsk->order);

	/* show transport statistics */
	if (vtss_task_leader(tsk)) {
		vtss_transport_stat(tsk->trn);
		if (tsk->trn != tsk->trn_aux)
			vtss_transport_stat(tsk->trn_aux);
	}
	/* stop using transport */
	vtss_target_detach_transport(tsk);
	/* show stack collection statistics */
	vtss_stack_stat(tsk->stk, tsk->tid);
	/* free stack buffers */
	vtss_stack_cleanup(tsk->stk);
	/* free task buffers */
	vtss_task_cleanup(tsk);
	vtss_zfree(&tsk, sizeof(struct vtss_task));
}

void vtss_target_fork(struct task_struct *parent, struct task_struct *child)
{
	struct vtss_task *ptsk;

	if (!vtss_collector_started())
		return;

	ptsk = vtss_task_map_get(vtss_gettid(parent));
	if (ptsk) {
		vtss_pr_debug_task("ptid=%d, ppid=%d", ptsk->tid, ptsk->pid);
		vtss_target_add(child, 0, false);
	}
	vtss_task_map_put(ptsk);
}

void vtss_target_exec(struct task_struct *task)
{
	struct vtss_task *tsk;

	if (!vtss_collector_started())
		return;

	vtss_profiling_pause();

	tsk = vtss_task_map_get(vtss_gettid(task));
	if (tsk) {
		vtss_pr_debug_task("replacing %d:%d", tsk->tid, tsk->order);
		vtss_task_unregister_notifier(tsk, task);
		vtss_task_map_remove(tsk);
		vtss_target_add(task, tsk->order + 1, false);
	}
	vtss_task_map_put(tsk);
}

static void vtss_target_flush_ipt(struct vtss_task *tsk)
{
	unsigned long flags;

	if (vtss_reqcfg_ipt_mode_full()) {
		if (vtss_task_in_context(tsk)) {
			local_irq_save(flags);
			preempt_disable();
			vtss_task_write_ipt(tsk);
			preempt_enable_no_resched();
			local_irq_restore(flags);
		}
	}
}

void vtss_target_exit(struct task_struct *task)
{
	struct vtss_task *tsk;

	if (!vtss_collector_started())
		return;

	vtss_profiling_pause();

	tsk = vtss_task_map_get(vtss_gettid(task));
	if (tsk) {
		vtss_pr_debug_task("detaching %d:%d", tsk->tid, tsk->order);
		vtss_target_flush_ipt(tsk);
		vtss_task_unregister_notifier(tsk, task);
		vtss_task_map_remove(tsk);
	}
	vtss_task_map_put(tsk);
}

static void vtss_target_detach_cb(struct vtss_task *tsk, void *arg)
{
	vtss_pr_debug_task("detaching %d:%d", tsk->tid, tsk->order);
	vtss_task_unregister_notifier(tsk, NULL);
	/* tsk will be removed by vtss_task_map_cleanup() */
}

void vtss_target_cleanup(void)
{
	if (atomic_read(&vtss_target_workers))
		vtss_pr_warning("%d target workers in progress", atomic_read(&vtss_target_workers));
	while (atomic_read(&vtss_target_workers) != 0);

	vtss_task_map_for_each(vtss_target_detach_cb, NULL);
}
