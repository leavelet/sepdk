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
#include "nmiwd.h"

#include <linux/cred.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>
#include <linux/watchdog.h>
#include <linux/delay.h>

static bool vtss_nmiwd_disabled = false;
static atomic_t vtss_nmiwd_busy = ATOMIC_INIT(0);

#define vtss_nmiwd_lock()\
	while (atomic_cmpxchg(&vtss_nmiwd_busy, 0, 1) != 0) \
		msleep_interruptible(VTSS_WAIT_INTERVAL)

#define vtss_nmiwd_unlock()\
	atomic_set(&vtss_nmiwd_busy, 0)

static ssize_t vtss_kernel_read(struct file *file, void *buf, size_t count, loff_t pos)
{
#ifdef VTSS_AUTOCONF_KERNEL_READ_WRITE
	return kernel_read(file, buf, count, &pos);
#else
	unsigned long rc;

	mm_segment_t old_fs = get_fs();
	set_fs(get_ds());
	rc = vfs_read(file, (char __user *)buf, count, &pos);
	set_fs(old_fs);
	return rc;
#endif
}

static ssize_t vtss_kernel_write(struct file *file, void *buf, size_t count, loff_t pos)
{
#ifdef VTSS_AUTOCONF_KERNEL_READ_WRITE
	return kernel_write(file, buf, count, &pos);
#else
	unsigned long rc;

	mm_segment_t old_fs = get_fs();
	set_fs(get_ds());
	rc = vfs_write(file, (const char __user *)buf, count, &pos);
	set_fs(old_fs);
	return rc;
#endif
}

static struct file *vtss_nmiwd_open(void)
{
	struct cred *cred;

	cred = prepare_kernel_cred(&init_task);
	if (cred)
		commit_creds(cred);
	else
		vtss_pr_warning("Failed to prepare NMI watchdog credentials");

	return filp_open("/proc/sys/kernel/nmi_watchdog", O_RDWR, 0);
}

static void vtss_nmiwd_close(struct file *fd)
{
	filp_close(fd, 0);
}

static int vtss_nmiwd_thread_run(int (*threadfn)(void *data), int id)
{
	volatile int rc = -EBUSY;
	int wait_count = VTSS_NMIWD_WAIT_TIMEOUT/VTSS_WAIT_INTERVAL;
	struct task_struct *thread;

	thread = kthread_run(threadfn, (void *)&rc, "vtsspp_nmiwd_%d", id);
	if (IS_ERR(thread)) {
		vtss_pr_error("Failed to start NMI watchdog thread");
		return PTR_ERR(thread);
	}

	while ((rc == -EBUSY) && wait_count--)
		msleep_interruptible(VTSS_WAIT_INTERVAL);

	if (rc == -EBUSY)
		vtss_pr_error("NMI watchdog operation still in progress");

	return rc;
}

static int vtss_nmiwd_enable_thread(void *data)
{
	int rc = 0;
	struct file *fd;

	fd = vtss_nmiwd_open();
	if (IS_ERR(fd)) {
		vtss_pr_error("Failed to open NMI watchdog");
		rc = -ENOENT;
		goto out;
	}
	vtss_nmiwd_lock();
	vtss_pr_debug_nmiwd("enabling NMI watchdog");
	vtss_kernel_write(fd, "1", 1, 0);
	vtss_nmiwd_disabled = false;
	vtss_nmiwd_unlock();
	vtss_nmiwd_close(fd);
out:
	*(volatile int *)data = rc;
	return rc;
}

int vtss_nmiwd_enable(void)
{
	if (vtss_nmiwd_disabled)
		return vtss_nmiwd_thread_run(&vtss_nmiwd_enable_thread, 1);
	return -EAGAIN;
}

static int vtss_nmiwd_disable_thread(void *data)
{
	int rc = 0;
	struct file *fd;
	char chr = '0';

	fd = vtss_nmiwd_open();
	if (IS_ERR(fd)) {
		vtss_pr_error("Failed to open NMI watchdog");
		rc = -ENOENT;
		goto out;
	}
	vtss_nmiwd_lock();
	vtss_kernel_read(fd, &chr, 1, 0);
	if (chr != '0') {
		vtss_pr_debug_nmiwd("disabling NMI watchdog");
		vtss_kernel_write(fd, "0", 1, 0);
		vtss_nmiwd_disabled = true;
	} else {
		vtss_pr_debug_nmiwd("NMI watchdog already disabled");
		rc = -EAGAIN;
	}
	vtss_nmiwd_unlock();
	vtss_nmiwd_close(fd);
out:
	*(volatile int *)data = rc;
	return rc;
}

int vtss_nmiwd_disable(void)
{
	if (!vtss_nmiwd_disabled)
		return vtss_nmiwd_thread_run(&vtss_nmiwd_disable_thread, 0);
	return -EAGAIN;
}
