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

#ifndef _VTSS_TASK_H_
#define _VTSS_TASK_H_

#include "config.h"
#include "cmd.h"
#include "lbr.h"
#include "modcfg.h"
#include "pmu.h"
#include "record.h"
#include "stack.h"
#include "user.h"
#include "workqueue.h"

struct vtss_task {
	pid_t			tid;
	pid_t			pid;
	pid_t			ppid;
	int			order;
	bool			m32;

	int			cpu;
	unsigned long		from_ip;
	atomic_t		context;

	int			newtask_write_err;
	int			softcfg_write_err;
	int			pause_write_err;
	int			sample_write_err;
	int			ipt_write_err;

	atomic_t		attached;
	struct work_struct	attach_work;

	atomic_t		mmap_busy;
	struct work_struct	mmap_write_work;
	void			*mmap_write_buf;

	struct hlist_node	hlist;
	atomic_t		hashed;
	atomic_t		usage;
	struct rcu_head		rcu;
	void 			(*delete_cb)(struct vtss_task *tsk);

	atomic_t		stack_unwound;
	struct vtss_stack	*stk;
	struct vtss_lbr		*lbr;

	atomic_t		events_enabled;
	struct vtss_pmu_events	*events[VTSS_PMU_SIZE];

	struct vtss_transport	*trn;
	struct vtss_transport	*trn_aux;

	char			name[TASK_COMM_LEN];

#ifdef VTSS_PREEMPT_NOTIFIERS
	atomic_t		notifier_registered;
	struct preempt_notifier preempt_notifier;
#endif
};

/* task is main thread */
#define vtss_task_leader(tsk) ((tsk)->tid == (tsk)->pid)

/* task is fully initialized, ready to profile */
#define vtss_task_attached(tsk) (atomic_read(&(tsk)->attached) == 1)
#define vtss_task_set_attached(tsk) atomic_set(&(tsk)->attached, 1)

/* invalid state prevents childs to wait */
#define vtss_task_invalid(tsk) (atomic_read(&(tsk)->attached) == -1)
#define vtss_task_set_invalid(tsk) atomic_set(&(tsk)->attached, -1)

/* switch-to stored, cpu field is valid */
#define vtss_task_in_context(tsk) (atomic_read(&(tsk)->context) == 1)
#define vtss_task_set_context(tsk) atomic_set(&(tsk)->context, 1)
#define vtss_task_clear_context(tsk) atomic_set(&(tsk)->context, 0)

/* task writes user and kernel module maps */
#define vtss_task_mmap_busy(tsk) (atomic_read(&(tsk)->mmap_busy) == 1)
#define vtss_task_set_mmap_busy(tsk) (atomic_cmpxchg(&(tsk)->mmap_busy, 0, 1) == 0)
#define vtss_task_clear_mmap_busy(tsk) atomic_set(&(tsk)->mmap_busy, 0)

/* cpu events can be sampled */
#define vtss_task_events_enabled(tsk) (atomic_read(&(tsk)->events_enabled) == 1)
#define vtss_task_events_enable(tsk) atomic_set(&(tsk)->events_enabled, 1)
#define vtss_task_events_disable(tsk) atomic_set(&(tsk)->events_enabled, 0)

/* task in hash table */
#define vtss_task_hashed(tsk) (atomic_read(&(tsk)->hashed) == 1)
#define vtss_task_set_hashed(tsk) (atomic_cmpxchg(&(tsk)->hashed, 0, 1) == 0)
#define vtss_task_set_unhashed(tsk) (atomic_cmpxchg(&(tsk)->hashed, 1, -1) == 1)

/* transport entry for sample records */
#define vtss_task_trn_sample(tsk) (vtss_reqcfg_rb_mode() ? (tsk)->trn_aux : (tsk)->trn)
/* transport entry for config records */
#define vtss_task_trn_config(tsk) (vtss_reqcfg_rb_mode() ? (tsk)->trn : (tsk)->trn_aux)

#define vtss_task_write_sample(tsk, ip)\
	(tsk)->sample_write_err = \
		vtss_transport_write_sample(vtss_task_trn_sample(tsk), (tsk)->tid, \
					    (tsk)->cpu, tsk->events[vtss_pmu_id(cpu)], ip)

#define vtss_task_write_ipt(tsk)\
	(tsk)->ipt_write_err = \
		vtss_ipt_write(vtss_task_trn_sample(tsk), (tsk)->tid, (tsk)->ipt_write_err)

int vtss_task_init(struct vtss_task *tsk, pid_t tid, pid_t pid, pid_t ppid, int order);
int vtss_task_init_buffers(struct vtss_task *tsk);
void vtss_task_cleanup(struct vtss_task *tsk);

void vtss_task_set_name(struct vtss_task *tsk, struct task_struct *task);

void vtss_task_write_switch_from(struct vtss_task *tsk, bool preempt);
void vtss_task_write_switch_to(struct vtss_task *tsk, int cpu, unsigned long ip, bool write_sample);

#define vtss_task_stack_unwound(tsk) (atomic_read(&(tsk)->stack_unwound) == 1)
#define vtss_task_set_stack_unwound(tsk) atomic_set(&(tsk)->stack_unwound, 1)
#define vtss_task_clear_stack_unwound(tsk) atomic_set(&(tsk)->stack_unwound, 0)

void vtss_task_unwind_stack(struct vtss_task *tsk, struct task_struct *task,
			    struct pt_regs *regs, unsigned long bp);
void vtss_task_write_stack(struct vtss_task *tsk);

#ifdef VTSS_PREEMPT_NOTIFIERS
void vtss_task_init_notifier(struct vtss_task *tsk);
void vtss_task_register_notifier(struct vtss_task *tsk, struct task_struct *task);
void vtss_task_unregister_notifier(struct vtss_task *tsk, struct task_struct *task);
#else
#define vtss_task_init_notifier(tsk)
#define vtss_task_register_notifier(tsk, task)
#define vtss_task_unregister_notifier(tsk, task)
#endif

#endif
