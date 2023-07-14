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
#include "kprobes.h"
#include "mmap.h"
#include "probe.h"
#include "regs.h"
#include "sched.h"
#include "target.h"
#include "tracepoint.h"

#include <linux/module.h>
#include <trace/events/sched.h>
#ifdef VTSS_TRACEPOINT_VMA_STORE
#include <trace/events/mmap.h>
#endif

#ifdef VTSS_TRACEPOINT_SCHED_SWITCH
static void __maybe_unused
#ifdef VTSS_AUTOCONF_TRACEPOINT_SCHED_SWITCH_NO_ARG
vtss_tracepoint_sched_switch(void *data, struct task_struct *prev,
			     struct task_struct *next)
#elif defined(VTSS_AUTOCONF_TRACEPOINT_SCHED_SWITCH_RQ_ARG)
vtss_tracepoint_sched_switch(void *data, struct rq *rq, struct task_struct *prev,
			     struct task_struct *next)
#elif defined(VTSS_AUTOCONF_TRACEPOINT_SCHED_SWITCH_PREEMPT_ARG)
vtss_tracepoint_sched_switch(void *data, bool preempt, struct task_struct *prev,
			     struct task_struct *next)
#elif defined(VTSS_AUTOCONF_TRACEPOINT_SCHED_SWITCH_PREV_STATE_ARG)
vtss_tracepoint_sched_switch(void *data, bool preempt, struct task_struct *prev,
			     struct task_struct *next, unsigned int prev_state)
#endif
{
	unsigned long prev_bp = 0;
	unsigned long prev_ip = 0;

	if (prev == current) {
		prev_bp = vtss_read_rbp();
		prev_ip = _THIS_IP_;
	}
	vtss_sched_switch(prev, next, prev_bp, prev_ip);
}
VTSS_DEFINE_TRACEPOINT(sched_switch);
#endif

#ifdef VTSS_AUTOCONF_JPROBE
static void __maybe_unused
vtss_jprobe_sched_switch(struct task_struct *prev, struct task_struct *next)
{
	unsigned long prev_bp = 0;
	unsigned long prev_ip = 0;

	if (prev == current) {
		prev_bp = vtss_read_rbp();
		prev_ip = _THIS_IP_;
	}
	vtss_sched_switch(prev, next, prev_bp, prev_ip);
	jprobe_return();
}
VTSS_DEFINE_JPROBE(sched_switch);
#endif

static int vtss_probe_register_sched_switch(void)
{
	int rc = -ENOENT;

#ifdef VTSS_TRACEPOINT_SCHED_SWITCH
	rc = vtss_tracepoint_register_sched_switch();
#endif
#ifdef VTSS_AUTOCONF_JPROBE
	if (rc) rc = vtss_jprobe_register_sched_switch("context_switch");
	if (rc) rc = vtss_jprobe_register_sched_switch("__switch_to");
#endif
	if (rc) {
#ifdef VTSS_PREEMPT_NOTIFIERS
		vtss_pr_notice("Fallback to preempt notifiers");
		vtss_sched_preempt_notifiers = true;
		rc = 0;
#else
		vtss_pr_warning("Preempt notifiers disabled");
#endif
	}
	if (rc) vtss_pr_error("Failed to register 'sched_switch' probe");
	return rc;
}

static void vtss_probe_unregister_sched_switch(void)
{
#ifdef VTSS_TRACEPOINT_SCHED_SWITCH
	vtss_tracepoint_unregister_sched_switch();
#endif
#ifdef VTSS_AUTOCONF_JPROBE
	vtss_jprobe_unregister_sched_switch();
#endif
}

static void __maybe_unused
vtss_tracepoint_sched_process_fork(void *data, struct task_struct *parent,
				   struct task_struct *child)
{
	if (parent && child)
		vtss_target_fork(parent, child);
}
VTSS_DEFINE_TRACEPOINT(sched_process_fork);

static int __maybe_unused
vtss_kretprobe_fork_enter(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	/* skip kernel threads or if no memory */
	return (current->mm == NULL) ? 1 : 0;
}

static int __maybe_unused
vtss_kretprobe_fork_leave(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *child;
	pid_t tid = regs_return_value(regs);

	if (tid <= 0)
		return 0;

	child = vtss_get_task_struct(tid);
	if (child) {
		vtss_target_fork(current, child);
		/* releasing task_struct can be dangerous here */
		vtss_put_task_struct(child);
	} else {
		vtss_pr_warning("%d: Child task doesn't exist", tid);
	}
	return 0;
}
VTSS_DEFINE_KRETPROBE(fork, 0);

static int vtss_probe_register_fork(void)
{
	int rc;

	rc = vtss_tracepoint_register_sched_process_fork();
#ifdef VTSS_KPROBE_FORK_USER_MODE
	if (rc) rc = vtss_kretprobe_register_fork("sys_fork");
	if (rc) rc = vtss_kretprobe_register_fork("__x64_sys_fork");
#else
	if (rc) rc = vtss_kretprobe_register_fork("do_fork");
	if (rc) rc = vtss_kretprobe_register_fork("_do_fork");
	if (rc) rc = vtss_kretprobe_register_fork("kernel_clone");
#endif
	if (rc) vtss_pr_error("Failed to register 'fork' probe");
	return rc;
}

static void vtss_probe_unregister_fork(void)
{
	vtss_tracepoint_unregister_sched_process_fork();
	vtss_kretprobe_unregister_fork();
}

static void __maybe_unused
vtss_tracepoint_sched_process_exec(void *data, struct task_struct *task, pid_t ppid,
				   struct linux_binprm *bprm)
{
	vtss_target_exec(task);
}
VTSS_DEFINE_TRACEPOINT(sched_process_exec);

static int __maybe_unused
vtss_kretprobe_exec_enter(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	/* skip kernel threads or if no memory */
	return (current->mm == NULL) ? 1 : 0;
}

static int __maybe_unused
vtss_kretprobe_exec_leave(struct kretprobe_instance *ri, struct pt_regs *regs)
{
#ifdef VTSS_AUTOCONF_KRETPROBE_INSTANCE_TASK_ARG
	struct task_struct *task = ri->task;
#else
	struct task_struct *task = current;
#endif
	int rc = regs_return_value(regs);

	if (rc == 0)
		vtss_target_exec(task);
	return 0;
}
VTSS_DEFINE_KRETPROBE(exec, 0);

static int vtss_probe_register_exec(void)
{
	int rc;

	rc = vtss_tracepoint_register_sched_process_exec();
#ifdef VTSS_KPROBE_EXEC_USER_MODE
	if (rc) rc = vtss_kretprobe_register_exec("sys_execve");
	if (rc) rc = vtss_kretprobe_register_exec("__x64_sys_execve");
#else
	if (rc) rc = vtss_kretprobe_register_exec("do_execve");
#endif
	if (rc) vtss_pr_error("Failed to register 'exec' probe");
	return rc;
}

static void vtss_probe_unregister_exec(void)
{
	vtss_tracepoint_unregister_sched_process_exec();
	vtss_kretprobe_unregister_exec();
}

#ifdef CONFIG_COMPAT
#define vtss_kretprobe_compat_exec_enter vtss_kretprobe_exec_enter
#define vtss_kretprobe_compat_exec_leave vtss_kretprobe_exec_leave
VTSS_DEFINE_KRETPROBE(compat_exec, 0);

static int vtss_probe_register_compat_exec(void)
{
	int rc;

	rc = vtss_tracepoint_sched_process_exec_registered ? 0 : -ENOENT;
#ifdef VTSS_KPROBE_EXEC_USER_MODE
	if (rc) rc = vtss_kretprobe_register_compat_exec("compat_sys_execve");
	if (rc) rc = vtss_kretprobe_register_compat_exec("__x32_compat_sys_execve");
	if (rc) rc = vtss_kretprobe_register_compat_exec("__ia32_compat_sys_execve");
#else
	if (rc) rc = vtss_kretprobe_register_compat_exec("compat_do_execve");
#endif
	if (rc) vtss_pr_warning("Failed to register 'compat_exec' probe");
	return 0;
}

static void vtss_probe_unregister_compat_exec(void)
{
	vtss_kretprobe_unregister_compat_exec();
}
#endif

static void __maybe_unused
vtss_tracepoint_sched_process_exit(void *data, struct task_struct *task)
{
	vtss_target_exit(task);
}
VTSS_DEFINE_TRACEPOINT(sched_process_exit);

static int __maybe_unused
vtss_kprobe_exit(struct kprobe *kp, struct pt_regs *regs)
{
	vtss_target_exit(current);
	return 0;
}
VTSS_DEFINE_KPROBE(exit);

static int vtss_probe_register_exit(void)
{
	int rc;

	rc = vtss_tracepoint_register_sched_process_exit();
	if (rc) rc = vtss_kprobe_register_exit("do_exit");
	if (rc) vtss_pr_error("Failed to register 'exit' probe");
	return rc;
}

static void vtss_probe_unregister_exit(void)
{
	vtss_tracepoint_unregister_sched_process_exit();
	vtss_kprobe_unregister_exit();
}

#ifdef VTSS_TRACEPOINT_VMA_STORE
static void __maybe_unused
vtss_tracepoint_vma_store(void *data, struct maple_tree *mt, struct vm_area_struct *vma)
{
	if (vtss_vma_exec(vma))
		vtss_mmap_write_user(current, vma->vm_file, vma->vm_start, vma->vm_end,
				     vma->vm_pgoff);
}
VTSS_DEFINE_TRACEPOINT(vma_store);
#endif

struct vtss_kretprobe_mmap_data {
	struct file  *vm_file;
	unsigned long vm_start;
	unsigned long vm_end;
	unsigned long vm_flags;
	unsigned long vm_pgoff;
};

static int __maybe_unused
vtss_kretprobe_mmap_region_enter(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct vtss_kretprobe_mmap_data *data = (struct vtss_kretprobe_mmap_data *)ri->data;

	if (current->mm == NULL)
		return 1; /* skip kernel threads or if no memory */

	data->vm_file  = (struct file *)regs->di;
	data->vm_start = regs->si;
	data->vm_end   = data->vm_start + regs->dx;
#ifdef VTSS_KPROBE_MMAP_NO_FLAGS_ARG
	data->vm_flags = regs->cx;
	data->vm_pgoff = data->vm_file ? regs->r8 : 0;
#else
	/* regs->cx: unsigned long flags */
	data->vm_flags = regs->r8;
	data->vm_pgoff = data->vm_file ? regs->r9 : 0;
#endif
	return 0;
}

static int __maybe_unused
vtss_kretprobe_mmap_region_leave(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long rc = regs_return_value(regs);
	struct vtss_kretprobe_mmap_data *data = (struct vtss_kretprobe_mmap_data *)ri->data;

	if (rc != data->vm_start)
		return 0;

	if (vtss_vma_exec(data))
		vtss_mmap_write_user(current, data->vm_file, data->vm_start, data->vm_end,
				     data->vm_pgoff);

	return 0;
}
VTSS_DEFINE_KRETPROBE(mmap_region, sizeof(struct vtss_kretprobe_mmap_data));

static int vtss_probe_register_mmap_user(void)
{
	int rc = -ENOENT;

#ifdef VTSS_TRACEPOINT_VMA_STORE
	rc = vtss_tracepoint_register_vma_store();
#endif
	if (rc) rc = vtss_kretprobe_register_mmap_region("mmap_region");
	if (rc) vtss_pr_warning("Failed to register 'mmap_user' probe");
	return 0;
}

static void vtss_probe_unregister_mmap_user(void)
{
#ifdef VTSS_TRACEPOINT_VMA_STORE
	vtss_tracepoint_unregister_vma_store();
#endif
	vtss_kretprobe_unregister_mmap_region();
}

static int vtss_module_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
	struct module *mod = data;
#ifdef VTSS_AUTOCONF_MODULE_CORE_LAYOUT
	unsigned long start = (unsigned long)mod->core_layout.base;
	unsigned long end = start + mod->core_layout.size;
#else
	unsigned long start = (unsigned long)mod->module_core;
	unsigned long end = start + mod->core_size;
#endif

	if (action == MODULE_STATE_COMING)
		vtss_mmap_write_kernel(current, mod->name, start, end, 0);

	return NOTIFY_DONE;
}

static bool vtss_module_notifier_registered = false;
static struct notifier_block vtss_module_notifier_block = {
	.notifier_call = &vtss_module_notifier
};

static int vtss_probe_register_mmap_kernel(void)
{
	int rc;

	rc = register_module_notifier(&vtss_module_notifier_block);
	if (rc) vtss_pr_warning("Failed to register kernel module notifier");
	else vtss_module_notifier_registered = true;
	return 0;
}

static void vtss_probe_unregister_mmap_kernel(void)
{
	if (vtss_module_notifier_registered) {
		vtss_module_notifier_registered = false;
		unregister_module_notifier(&vtss_module_notifier_block);
	}
}

int vtss_probe_init(void)
{
	int rc;

	rc = vtss_probe_register_fork();
	if (rc) goto out_fail;

	rc = vtss_probe_register_exec();
	if (rc) goto out_fail;
#ifdef CONFIG_COMPAT
	rc = vtss_probe_register_compat_exec();
	if (rc) goto out_fail;
#endif
	rc = vtss_probe_register_exit();
	if (rc) goto out_fail;

	rc = vtss_probe_register_sched_switch();
	if (rc) goto out_fail;

	rc = vtss_probe_register_mmap_user();
	if (rc) goto out_fail;

	rc = vtss_probe_register_mmap_kernel();
	if (rc) goto out_fail;

#ifdef VTSS_PREEMPT_NOTIFIERS
#ifdef VTSS_AUTOCONF_PREEMPT_NOTIFIER_CONTROL
	if (vtss_sched_preempt_notifiers)
		preempt_notifier_inc();
#endif
#endif
	return 0;

out_fail:
	vtss_probe_cleanup();
	return rc;
}

void vtss_probe_cleanup(void)
{
	vtss_probe_unregister_mmap_kernel();
	vtss_probe_unregister_mmap_user();
	vtss_probe_unregister_sched_switch();
	vtss_probe_unregister_exit();
#ifdef CONFIG_COMPAT
	vtss_probe_unregister_compat_exec();
#endif
	vtss_probe_unregister_exec();
	vtss_probe_unregister_fork();
#ifdef VTSS_TRACEPOINTS
	tracepoint_synchronize_unregister();
#endif
#ifdef VTSS_PREEMPT_NOTIFIERS
#ifdef VTSS_AUTOCONF_PREEMPT_NOTIFIER_CONTROL
	if (vtss_sched_preempt_notifiers)
		preempt_notifier_dec();
#endif
#endif
}
