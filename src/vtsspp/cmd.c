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
#include "kpti.h"
#include "ksyms.h"
#include "lbr.h"
#include "mmap.h"
#include "modcfg.h"
#include "nmiwd.h"
#include "pcb.h"
#include "pebs.h"
#include "pmi.h"
#include "probe.h"
#include "procfs.h"
#include "record.h"
#include "target.h"
#include "task.h"
#include "task_map.h"
#include "time.h"
#include "transport.h"
#include "workqueue.h"

#include <linux/cred.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <xen/xen.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Copyright (C) 2010-2023 Intel Corporation");
MODULE_DESCRIPTION("Virtualization, Threading and Stack Sampling++");

int uid = 0;
module_param(uid, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(uid, "An user id for profiling");

int gid = 0;
module_param(gid, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(gid, "A group id for profiling");

int mode = 0;
module_param(mode, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(mode, "A mode for files in procfs");

char *ksyms = NULL;
module_param(ksyms, charp, 0);
MODULE_PARM_DESC(ksyms, "kallsyms_lookup_name function address in hex");

uid_t vtss_session_uid = 0;
gid_t vtss_session_gid = 0;

static int vtss_session_init(void)
{
#ifdef VTSS_AUTOCONF_CURRENT_KUID_KGID
	kuid_t kuid;
	kgid_t kgid;

	current_uid_gid(&kuid, &kgid);
	vtss_session_uid = kuid.val;
	vtss_session_gid = kgid.val;
#else
	current_uid_gid(&vtss_session_uid, &vtss_session_gid);
#endif
	return 0;
}

static void vtss_session_cleanup(void)
{
	vtss_session_uid = 0;
	vtss_session_gid = 0;
}

atomic_t vtss_collector_state = ATOMIC_INIT(VTSS_COLLECTOR_STOPPED);
static atomic_t vtss_start_paused = ATOMIC_INIT(0);
static unsigned long long vtss_collection_start;

static int vtss_collector_init(void)
{
	int rc;

	vtss_nmiwd_disable();
	vtss_transport_wait();
	vtss_procfs_control_reset();
	vtss_kmem_stat_reset();

	rc = vtss_kpti_init();
	if (rc) vtss_pebs_set_disabled();

	rc = vtss_session_init();
	if (rc) return rc;

	rc = vtss_transport_start();
	if (rc) return rc;

	rc = vtss_task_map_init();
	if (rc) return rc;

	rc = vtss_pebs_init();
	if (rc) return rc;

	if (vtss_reqcfg_lbr_mode()) {
		rc = vtss_lbr_init();
		if (rc) return rc;
	}
	if (vtss_reqcfg_ipt_mode()) {
		rc = vtss_ipt_init();
		if (rc) return rc;
	}
	rc = vtss_nmi_init();
	if (rc) return rc;

	rc = vtss_probe_init();
	if (rc) return rc;

	vtss_pr_notice("Trace flags: 0x%x", vtss_reqcfg.trace_cfg.trace_flags);
#ifndef VTSS_AUTOCONF_CPULIST_SCNPRINTF
	vtss_pr_notice("Active CPU mask: %*pbl", cpumask_pr_args(&vtss_cpumask));
#else
	vtss_pr_notice("Number of active CPUs: %d", vtss_nr_active_cpus());
#endif
	vtss_pr_notice("Time source: %s", vtss_time_source ? "TSC" : "SYS");
	if (vtss_reqcfg.stk_sz[vtss_stk_user])
		vtss_pr_notice("User stack limit: %luKB",
			       vtss_reqcfg.stk_sz[vtss_stk_user] >> 10);

	return 0;
}

static void vtss_collector_cleanup(void)
{
	vtss_profiling_wait();
	vtss_target_cleanup();
	vtss_probe_cleanup();
	vtss_nmi_cleanup();
	if (vtss_reqcfg_ipt_mode())
		vtss_ipt_cleanup();
	if (vtss_reqcfg_lbr_mode())
		vtss_lbr_cleanup();
	vtss_pebs_cleanup();
	vtss_task_map_cleanup();
	vtss_transport_stop();
	vtss_session_cleanup();
	vtss_nmiwd_enable();
	vtss_kmem_stat_print();
}

int vtss_cmd_start(void)
{
	int rc;
	int st = atomic_cmpxchg(&vtss_collector_state,
				VTSS_COLLECTOR_STOPPED, VTSS_COLLECTOR_STARTING);

	if (st != VTSS_COLLECTOR_STOPPED) {
		vtss_pr_warning("Collection already started");
		return -EBUSY;
	}
	rc = vtss_collector_init();
	if (rc) {
		/* collection will be stopped by vtss_cmd_abort() */
		vtss_pr_error("Failed to start collection");
		return rc;
	}
	vtss_collection_start = vtss_time_cpu();
	atomic_set(&vtss_collector_state, VTSS_COLLECTOR_RUNNING);
	vtss_pr_notice("Collection started");
	if (atomic_read(&vtss_start_paused)) {
		atomic_set(&vtss_start_paused, 0);
		vtss_cmd_pause();
	}
	return 0;
}

int vtss_cmd_stop(void)
{
	int st = atomic_cmpxchg(&vtss_collector_state,
				VTSS_COLLECTOR_RUNNING, VTSS_COLLECTOR_STOPPING);

	if (st == VTSS_COLLECTOR_PAUSED) {
		atomic_set(&vtss_collector_state, VTSS_COLLECTOR_STOPPING);
	} else if (st != VTSS_COLLECTOR_RUNNING) {
		vtss_pr_notice("Collection already stopped");
		return 0;
	}
	vtss_pr_notice("Collection stopped");
	vtss_collector_cleanup();
	atomic_set(&vtss_start_paused, 0);
	atomic_set(&vtss_collector_state, VTSS_COLLECTOR_STOPPED);
	vtss_pr_notice("Collection duration: %lld sec",
		       (vtss_time_get_msec_from(vtss_collection_start) + 499)/1000);
	return 0;
}

static void vtss_cmd_abort_worker(struct work_struct *work)
{
	atomic_set(&vtss_collector_state, VTSS_COLLECTOR_ABORTING);
	vtss_collector_cleanup();
	atomic_set(&vtss_start_paused, 0);
	atomic_set(&vtss_collector_state, VTSS_COLLECTOR_STOPPED);
	vtss_pr_error("Collection stopped abnormally");
}

static DECLARE_WORK(vtss_cmd_abort_work, vtss_cmd_abort_worker);

int vtss_cmd_abort(void)
{
	if (!vtss_queue_work(&vtss_cmd_abort_work))
		return -EBUSY;
	return 0;
}

int vtss_cmd_pause(void)
{
	int rc;
	int st = atomic_cmpxchg(&vtss_collector_state,
				VTSS_COLLECTOR_RUNNING, VTSS_COLLECTOR_PAUSED);

	switch (st) {
	case VTSS_COLLECTOR_RUNNING:
		rc = vtss_transport_write_probe_all(vtss_smp_processor_id(), VTSS_FID_ITT_PAUSE);
		vtss_pr_notice("Collection paused");
		return rc;
	case VTSS_COLLECTOR_STOPPED:
		atomic_inc(&vtss_start_paused);
		vtss_pr_notice("Start paused: %s", atomic_read(&vtss_start_paused) ?
						   "Enabled" : "Disabled");
		break;
	case VTSS_COLLECTOR_PAUSED:
		vtss_pr_notice("Collection already paused");
		break;
	default:
		vtss_pr_warning("Pause in wrong state: %d", st);
		return -EINVAL;
	}
	return 0;
}

int vtss_cmd_resume(void)
{
	int rc;
	int st = atomic_cmpxchg(&vtss_collector_state,
				VTSS_COLLECTOR_PAUSED, VTSS_COLLECTOR_RUNNING);

	switch (st) {
	case VTSS_COLLECTOR_PAUSED:
		rc = vtss_transport_write_probe_all(vtss_smp_processor_id(), VTSS_FID_ITT_RESUME);
		vtss_pr_notice("Collection resumed");
		return rc;
	case VTSS_COLLECTOR_STOPPED:
		atomic_dec(&vtss_start_paused);
		vtss_pr_notice("Start paused: %s", atomic_read(&vtss_start_paused) ?
						   "Enabled" : "Disabled");
		break;
	case VTSS_COLLECTOR_RUNNING:
		vtss_pr_notice("Collection already resumed");
		break;
	default:
		vtss_pr_warning("Resume in wrong state: %d", st);
		return -EINVAL;
	}
	return 0;
}

int vtss_cmd_attach(pid_t pid)
{
	int rc;
	struct pid *group;
	struct task_struct *leader, *task;
	pid_t tid;

	if (!vtss_collector_started()) {
		vtss_pr_error("%d: Collection not started", pid);
		return -EFAULT;
	}

	vtss_pr_debug_cmd("attaching to pid %d", pid);

	leader = vtss_get_task_struct(pid);
	if (leader == NULL) {
		vtss_pr_error("Task %d doesn't exist", pid);
		return -ESRCH;
	}
	if (pid != vtss_getpid(leader)) {
		vtss_pr_error("Task %d is not a process", pid);
		rc = -EINVAL;
		goto out;
	}

	tid = vtss_gettid(leader);
	vtss_pr_debug_cmd("tid=%d, pid=%d", tid, pid);
	rc = vtss_target_add(leader, 0, true);
	if (rc) goto out;

	group = get_pid(task_pid(leader));
	if (group == NULL) {
		vtss_pr_error("Failed to get pid %d group", pid);
		rc = -ENOENT;
		goto out;
	}
	do_each_pid_thread(group, PIDTYPE_PID, task) {
		tid = vtss_gettid(task);
		if (tid == pid)
			continue;
		if (pid != vtss_getpid(task))
			continue;
		vtss_pr_debug_cmd("tid=%d, pid=%d", tid, pid);
		vtss_target_add(task, 0, true);
	} while_each_pid_thread(group, PIDTYPE_PID, task);
	put_pid(group);
out:
	vtss_put_task_struct(leader);
	return rc;
}

static int vtss_init(void)
{
	int rc;

	vtss_pr_notice("Driver version: %s", VTSS_VERSION_STRING);
	vtss_pr_notice("Driver options: uid: %d, gid: %d, mode: %o", uid, gid, mode);

	if (xen_initial_domain()) {
		vtss_pr_error("XEN initial domain not supported");
		return -EFAULT;
	}

	rc = vtss_pcb_init();
	if (rc) return rc;

	rc = vtss_modcfg_init();
	if (rc) return rc;

	rc = vtss_kallsyms_init();
	if (rc) return rc;

	rc = vtss_pmu_init();
	if (rc) return rc;

	rc = vtss_procfs_init();
	if (rc) return rc;

#ifdef VTSS_KPTI
	vtss_pr_notice("Kernel: KPTI detected");
#endif
#ifdef VTSS_KAISER
	vtss_pr_notice("Kernel: KAISER detected");
#endif
#ifdef VTSS_KASLR
	vtss_pr_notice("Kernel: KASLR detected");
#endif
#ifdef VTSS_PREEMPT_RT
	vtss_pr_notice("Kernel: RT patch detected");
#endif
#ifndef VTSS_TRACEPOINTS
	vtss_pr_warning("Kernel: Tracepoints disabled");
#endif
#ifndef VTSS_KPROBES
	vtss_pr_warning("Kernel: Kprobes disabled");
#endif
#ifndef VTSS_KALLSYMS
	vtss_pr_warning("Kernel: Kallsyms disabled");
#endif

	vtss_pr_notice("Driver has been loaded");
	return 0;
}

static void vtss_exit(void)
{
	if (vtss_collector_started())
		vtss_cmd_stop();

	vtss_transport_wait();
	vtss_procfs_cleanup();
	vtss_kmem_stat_check();

	vtss_pr_notice("Driver has been unloaded");
}

module_init(vtss_init);
module_exit(vtss_exit);
