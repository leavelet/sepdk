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

#ifndef _VTSS_USER_H_
#define _VTSS_USER_H_

#include "config.h"

#define vtss_gettid(task) ((task)->pid)
#define vtss_getpid(task) ((task)->tgid)
#define vtss_getppid(task) vtss_getpid((task)->real_parent)

#ifdef VTSS_AUTOCONF_TASK_STRUCT_HIDDEN_STATE
#define vtss_read_task_state(task) READ_ONCE((task)->__state)
#else
#define vtss_read_task_state(task) (task)->state
#endif

/* user tasks or kthreads with valid running/exit state and not in execve or exit */
#define vtss_is_task_valid(task)\
	(((task)->mm || ((task)->flags & PF_KTHREAD)) && \
	 vtss_read_task_state(task) < __TASK_STOPPED && (task)->exit_state == 0 && \
	 !vtss_is_task_in_execve(task) && !vtss_is_task_exiting(task))

#define vtss_is_task_dead(task) ((vtss_read_task_state(task) & TASK_DEAD) != 0)
#define vtss_is_task_preempt(task) (vtss_read_task_state(task) == TASK_RUNNING)

#define vtss_is_task_in_execve(task) ((task)->in_execve != 0)
#define vtss_is_task_exiting(task) (((task)->flags & PF_EXITING) != 0)

#define vtss_is_task_mm_valid(task) ((task)->mm && !((task)->flags & PF_KTHREAD))
#define vtss_is_task_64bit_mode(task) ((task)->mm ? user_64bit_mode(task_pt_regs(task)) : true)

#define vtss_get_task_regs(task) ((task)->mm ? task_pt_regs(task) : NULL)
#define vtss_get_task_sp(task) ((task)->mm ? task_pt_regs(task)->sp : 0)
#define vtss_get_task_ip(task) ((task)->mm ? task_pt_regs(task)->ip : 0)

static inline struct task_struct *vtss_get_task_struct(pid_t tid)
{
	struct pid *pid;
	struct task_struct *task = NULL;

	pid = find_get_pid(tid);
	if (pid) {
		rcu_read_lock();
		task = pid_task(pid, PIDTYPE_PID);
		if (task)
			get_task_struct(task);
		rcu_read_unlock();
		put_pid(pid);
	}
	return task;
}

static inline void vtss_put_task_struct(struct task_struct *task)
{
	put_task_struct(task);
}

#ifdef VTSS_AUTOCONF_MMAP_LOCK
#define vtss_mmap_read_lock(mm)    mmap_read_lock(mm)
#define vtss_mmap_read_trylock(mm) mmap_read_trylock(mm)
#define vtss_mmap_read_unlock(mm)  mmap_read_unlock(mm)
#else
#define vtss_mmap_read_lock(mm)    down_read(&(mm)->mmap_sem)
#define vtss_mmap_read_trylock(mm) (down_read_trylock(&(mm)->mmap_sem) != 0)
#define vtss_mmap_read_unlock(mm)  up_read(&(mm)->mmap_sem)
#endif

#define vtss_vma_exec(vma)\
	(((vma)->vm_flags & VM_EXEC) && \
	 (vma)->vm_file && (vma)->vm_file->f_path.dentry)

#define vtss_vma_hugepage_exec(vma)\
	(((vma)->vm_flags & VM_HUGEPAGE) && \
	 ((vma)->vm_flags & VM_EXEC) && \
	 !(vma)->vm_file)

#define vtss_vma_vdso(vma)\
	((vma)->vm_mm && \
	 (vma)->vm_start == (unsigned long)(vma)->vm_mm->context.vdso)

#ifndef preempt_enable_no_resched
#define preempt_enable_no_resched preempt_enable
#endif

static inline int vtss_smp_processor_id(void)
{
	int cpu;

	preempt_disable();
	cpu = smp_processor_id();
	preempt_enable_no_resched();
	return cpu;
}

#ifdef VTSS_AUTOCONF_INLINE_COPY_FROM_USER
#define vtss_copy_from_user(to, from, size) _copy_from_user(to, from, size)
#else
#define vtss_copy_from_user(to, from, size) copy_from_user(to, from, size)
#endif

static inline int vtss_copy_from_user_nmi(void *to, const void *from, size_t size)
{
	unsigned long rem;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
	rem = copy_from_user_nmi(to, from, size);
#else
	if (__range_not_ok(from, size, TASK_SIZE))
		return -EINVAL;

	pagefault_disable();
	rem = __copy_from_user_inatomic(to, from, size);
	pagefault_enable();
#endif
	return rem;
}

#endif
