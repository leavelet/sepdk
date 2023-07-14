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

#ifndef _VTSS_CONFIG_H_
#define _VTSS_CONFIG_H_

#include "autoconf.h"

#include <linux/kernel.h>	/* for common defines     */
#include <linux/version.h>	/* for KERNEL_VERSION     */
#include <linux/list.h>		/* for struct list_head   */
#include <linux/rculist.h>	/* for struct rcu_head    */
#include <linux/fs.h>		/* for struct file        */
#include <linux/mm.h>		/* for struct mm_struct   */
#include <linux/sched.h>	/* for struct task_struct */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task.h>	    /* get_task_struct    */
#include <linux/sched/task_stack.h> /* task_stack_page    */
#include <linux/sched/mm.h>	    /* get_task_mm        */
#include <linux/sched/signal.h>	    /* do_each_pid_thread */
#endif
#include <linux/preempt.h>	/* for preempt_enable     */
#include <linux/smp.h>		/* for on_each_cpu        */
#include <linux/ptrace.h>	/* for struct pt_regs     */
#include <linux/uaccess.h>	/* for copy_from_user     */
#include <linux/nmi.h>		/* for touch_nmi_watchdog */

#include <asm/cpufeature.h>	/* for X86_FEATURE_*      */

#include "vtssrtcfg.h"
#include "vtsstrace.h"
#include "vtsstypes.h"

#ifndef VTSS_VERSION_MAJOR
#define VTSS_VERSION_MAJOR	1
#endif
#ifndef VTSS_VERSION_MINOR
#define VTSS_VERSION_MINOR	8
#endif
#ifndef VTSS_VERSION_REVISION
#define VTSS_VERSION_REVISION	0
#endif
#ifndef VTSS_VERSION_STRING
#define VTSS_VERSION_STRING	"1.8.0-custom"
#endif

#ifndef __x86_64__
#error "Only x86_64 architecture is supported"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
#error "Kernels prior to 3.2 are not supported"
#endif

#ifndef CONFIG_SMP
#error "The kernel should be compiled with CONFIG_SMP"
#endif

#ifndef CONFIG_MODULES
#error "The kernel should be compiled with CONFIG_MODULES"
#endif

#ifndef VTSS_AUTOCONF_KERNEL_HEADERS
#warning "Kernel headers are not compatible with current toolchain"
#endif

/* Tracepoints support */
#if defined (CONFIG_TRACEPOINTS) && \
   !defined(VTSS_DISABLE_TRACEPOINTS)
#define VTSS_TRACEPOINTS 1
/* Context switch tracepoint support */
#if defined(VTSS_AUTOCONF_TRACEPOINT_SCHED_SWITCH_NO_ARG) || \
    defined(VTSS_AUTOCONF_TRACEPOINT_SCHED_SWITCH_RQ_ARG) || \
    defined(VTSS_AUTOCONF_TRACEPOINT_SCHED_SWITCH_PREEMPT_ARG) || \
    defined(VTSS_AUTOCONF_TRACEPOINT_SCHED_SWITCH_PREV_STATE_ARG)
#define VTSS_TRACEPOINT_SCHED_SWITCH 1
#endif
#ifdef VTSS_AUTOCONF_TRACEPOINT_VMA_STORE
#define VTSS_TRACEPOINT_VMA_STORE 1
#endif
#endif

/* Preempt notifiers support */
#ifdef CONFIG_PREEMPT_NOTIFIERS
#define VTSS_PREEMPT_NOTIFIERS 1
#endif

/* Kprobes/kretprobes support */
#if defined(CONFIG_KPROBES) && \
    defined(CONFIG_KRETPROBES) &&\
   !defined(VTSS_DISABLE_KPROBES)
#define VTSS_KPROBES 1
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
/* Since 3.9 do_execve is inlined into sys_execve and
 * probe is broken because of this */
#define VTSS_KPROBE_EXEC_USER_MODE 1
/* Since 3.9 flags parameter was removed */
#define VTSS_KPROBE_MMAP_NO_FLAGS_ARG 1
#endif
#endif

/* Check for probes support */
#if !defined(VTSS_TRACEPOINTS) && \
    !defined(VTSS_KPROBES)
#error "The kernel should be compiled with CONFIG_TRACEPOINTS or CONFIG_KPROBES/CONFIG_KRETPROBES"
#endif

/* Check for context switch probe support */
#if !defined(VTSS_TRACEPOINT_SCHED_SWITCH) && \
    !defined(VTSS_AUTOCONF_JPROBE) && \
    !defined(VTSS_PREEMPT_NOTIFIERS)
#error "The kernel should be compiled with CONFIG_TRACEPOINTS or CONFIG_PREEMPT_NOTIFIERS"
#endif

/* Kallsyms support */
#if defined(CONFIG_KALLSYMS) && \
   !defined(VTSS_DISABLE_KALLSYMS)
#define VTSS_KALLSYMS 1
/* kallsysm_lookup_name is not exported since 5.7 kernel */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define VTSS_KALLSYMS_LOOKUP_NAME 1
#endif
#endif

/* Kernel/User page tables isolation support */
#if defined(X86_FEATURE_KAISER) || \
    defined(CONFIG_KAISER) || \
    defined(VTSS_AUTOCONF_KAISER)
#define VTSS_KAISER 1
#elif defined(X86_FEATURE_PTI)
#define VTSS_KPTI 1
#endif

/* Kernel address space layout randomization support */
#ifdef CONFIG_RANDOMIZE_BASE
#define VTSS_KASLR 1
#endif

/* Realtime patch support */
#if defined(CONFIG_PREEMPT_RT) || \
    defined(CONFIG_PREEMPT_RT_FULL)
#define VTSS_PREEMPT_RT 1
#define VTSS_WAIT_QUEUE_TIMEOUT 1000
#endif

/* User stack unwinding limit in pages */
#define VTSS_STACK_READ_LIMIT 256

/* User stack unwinding timeout in msec */
#define VTSS_STACK_READ_TIMEOUT 30

/* Internal wait interval in msec */
#define VTSS_WAIT_INTERVAL 5

/* NMI watchdog working thread timeout in msec */
#define VTSS_NMIWD_WAIT_TIMEOUT 100000

/* Target ready state timeout in msec */
#define VTSS_TARGET_WAIT_TIMEOUT 5000

/* Transprot timer interval in msec */
#define VTSS_TRANSPORT_TIMER_INTERVAL 10

/* Transport timeouts in msec */
#define VTSS_TRANSPORT_READ_TIMEOUT 5
#define VTSS_TRANSPORT_STOP_TIMEOUT 100000

/* Per-cpu transport buffer size in pages */
#define VTSS_TRANSPORT_SIZE 256
#define VTSS_TRANSPORT_IPT_SIZE 4096

/* Per-cpu transport buffer size per msec in ring-buffer mode */
#define VTSS_TRANSPORT_MSEC_SIZE 1
#define VTSS_TRANSPORT_IPT_MSEC_SIZE 128

/* Runtool name */
#define VTSS_RUNSS_NAME "amplxe-runss"

#endif
