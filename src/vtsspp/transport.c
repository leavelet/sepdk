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
#include "kmem.h"
#include "modcfg.h"
#include "procfs.h"
#include "spinlock.h"
#include "time.h"
#include "transport.h"
#include "user.h"
#include "workqueue.h"

#include <linux/module.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/namei.h>

static atomic_t vtss_transport_started = ATOMIC_INIT(0);
static struct timer_list vtss_transport_timer = {0};
static VTSS_DEFINE_SPINLOCK(vtss_transport_list_lock);
static LIST_HEAD(vtss_transport_list);
static atomic_t vtss_transport_workers = ATOMIC_INIT(0);
atomic_t vtss_ring_buffer_stopped = ATOMIC_INIT(0);

#define vtss_transport_started() (atomic_read(&vtss_transport_started) == 1)
#define vtss_transport_stopping() (atomic_read(&vtss_transport_started) == -1)
#define vtss_transport_stopped() (atomic_read(&vtss_transport_started) == 0)

#define vtss_transport_set_started() (atomic_cmpxchg(&vtss_transport_started, 0, 1) == 0)
#define vtss_transport_set_stopping() (atomic_cmpxchg(&vtss_transport_started, 1, -1) == 1)
#define vtss_transport_set_stopped() (atomic_cmpxchg(&vtss_transport_started, -1, 0) == -1)

#define vtss_transport_opened(trn) (atomic_read(&(trn)->opened) == 1)
#define vtss_transport_closed(trn) (atomic_read(&(trn)->opened) == -1)
#define vtss_transport_set_opened(trn) (atomic_cmpxchg(&(trn)->opened, 0, 1) == 0)
#define vtss_transport_set_closed(trn) (atomic_cmpxchg(&(trn)->opened, 1, -1) == 1)

#define vtss_transport_completed(trn) (atomic_read(&(trn)->completed) == 1)
#define vtss_transport_set_completed(trn) (atomic_cmpxchg(&(trn)->completed, 0, 1) == 0)

#define vtss_transport_nr_records(trn) (1 + (long)atomic64_read(&(trn)->wr_seqno) - (long)atomic64_read(&(trn)->rd_seqno))
#define vtss_transport_has_data(trn) (vtss_transport_nr_records(trn) > 0 || !(trn)->magic)

#define VTSS_RB_ALIGN(x) ALIGN(x, sizeof(unsigned long))
#define vtss_ring_buffer_page(count) (((count) >> PAGE_SHIFT) % (rb->nr_pages))
#define vtss_ring_buffer_page_offset(count) ((count) & (PAGE_SIZE - 1))

#define vtss_ring_buffer_set_busy(rb) (atomic_cmpxchg(&(rb)->busy, 0, 1) == 0)
#define vtss_ring_buffer_clear_busy(rb) atomic_set(&(rb)->busy, 0)

static void vtss_ring_buffer_reset(struct vtss_ring_buffer *rb)
{
	if (rb == NULL)
		return;

	atomic64_set(&rb->rd_count, 0);
	atomic64_set(&rb->wr_count, 0);
	vtss_ring_buffer_clear_busy(rb);
}

static void vtss_ring_buffer_free(struct vtss_ring_buffer *rb)
{
	int index;

	if (rb == NULL)
		return;

	for (index = 0; index < rb->nr_pages; index++) {
		vtss_free_pages(rb->pages[index], PAGE_SIZE);
		rb->pages[index] = NULL;
	}
	vtss_zfree(&rb, sizeof(struct vtss_ring_buffer) + rb->nr_pages*sizeof(void *));
}

static struct vtss_ring_buffer *vtss_ring_buffer_alloc(int nr_pages, int cpu)
{
	int index;
	struct vtss_ring_buffer *rb;

	rb = vtss_zalloc(sizeof(struct vtss_ring_buffer) + nr_pages*sizeof(void *), GFP_KERNEL);
	if (rb == NULL) {
		vtss_pr_error("Not enough memory for ring-buffer page pool on cpu%d", cpu);
		return NULL;
	}

	rb->nr_pages = nr_pages;
	vtss_ring_buffer_reset(rb);

	for (index = 0; index < rb->nr_pages; index++) {
		rb->pages[index] = vtss_alloc_pages(PAGE_SIZE, GFP_KERNEL, cpu);
		if (rb->pages[index] == NULL) {
			vtss_pr_error("Not enough memory for ring-buffer page[%d] on cpu%d", index, cpu);
			vtss_ring_buffer_free(rb);
			return NULL;
		}
	}
	return rb;
}

static inline size_t vtss_ring_buffer_filled_size(struct vtss_ring_buffer *rb)
{
	return atomic64_read(&rb->wr_count) - atomic64_read(&rb->rd_count);
}

static inline size_t vtss_ring_buffer_free_size(struct vtss_ring_buffer *rb)
{
	return rb->nr_pages*PAGE_SIZE - vtss_ring_buffer_filled_size(rb);
}

static int vtss_ring_buffer_read(struct vtss_ring_buffer *rb, size_t rd_count, char *buf, size_t size, bool user_mode)
{
	/* assumes: size >= filled_size */
	while (size) {
		char *page = rb->pages[vtss_ring_buffer_page(rd_count)];
		int offset = vtss_ring_buffer_page_offset(rd_count);
		size_t nb = min(size, PAGE_SIZE - offset);
		if (user_mode) {
			if (copy_to_user((char __user *)buf, page + offset, nb))
				return -EFAULT;
		} else {
			memcpy(buf, page + offset, nb);
		}
		vtss_pr_debug_trn2("  page=%zu, offset=%d, nb=%zu", vtss_ring_buffer_page(rd_count), offset, nb);
		size -= nb; buf += nb;
		rd_count += nb;
	}
	return 0;
}

static int vtss_ring_buffer_write(struct vtss_ring_buffer *rb, size_t wr_count, const char *buf, size_t size)
{
	/* assumes: size >= free_size */
	while (size) {
		char *page = rb->pages[vtss_ring_buffer_page(wr_count)];
		int offset = vtss_ring_buffer_page_offset(wr_count);
		size_t nb = min(size, PAGE_SIZE - offset);
		memcpy(page + offset, buf, nb);
		vtss_pr_debug_trn2("  page=%zu, offset=%d, nb=%zu", vtss_ring_buffer_page(wr_count), offset, nb);
		size -= nb; buf += nb;
		wr_count += nb;
	}
	return 0;
}

struct vtss_transport_header {
	size_t seqno;
	size_t size;
};

static int vtss_transport_open(struct inode *inode, struct file *file)
{
	int rc;
	struct vtss_transport *trn;

	trn = vtss_procfs_pde_data(inode);
	if (trn == NULL) {
		vtss_pr_error("Invalid PDE data");
		return -ENOENT;
	}
	if (!vtss_transport_set_opened(trn)) {
		vtss_pr_error("%s: Already opened", trn->name);
		return -EBUSY;
	}
	rc = generic_file_open(inode, file);
	if (rc) {
		vtss_pr_error("%s: Failed to open file", trn->name);
		return rc;
	}
	trn->file = file;
	file->private_data = trn;
	/* increase the priority for trace reader to avoid lost events */
	set_user_nice(current, -19);
	vtss_pr_debug_trn("%s: opened by user", trn->name);
	return rc;
}

static int vtss_transport_close(struct inode *inode, struct file *file)
{
	struct vtss_transport *trn;

	trn = vtss_procfs_pde_data(inode);
	if (trn == NULL) {
		vtss_pr_error("Invalid PDE data");
		return -ENOENT;
	}
	trn->file = NULL;
	file->private_data = NULL;
	if (!vtss_transport_set_closed(trn)) {
		vtss_pr_error("%s: Already closed or not opened", trn->name);
		return -EFAULT;
	}
	/* restore default priority for trace reader */
	set_user_nice(current, 0);
	vtss_pr_debug_trn("%s: closed by user", trn->name);
	return 0;
}

static void vtss_transport_check(struct vtss_transport *trn, int verbose)
{
	int cpu;
	struct vtss_ring_buffer *rb;
	struct vtss_transport_header header;
	size_t filled_size, rd_count;

	if (verbose)
		vtss_pr_notice("%s: %ld records: wr_seqno: %ld, rd_seqno: %ld",
			       trn->name, vtss_transport_nr_records(trn),
			       (long)atomic64_read(&trn->wr_seqno),
			       (long)atomic64_read(&trn->rd_seqno));

	if (atomic64_read(&trn->wr_seqno) < 0 || atomic64_read(&trn->rd_seqno) < 1)
		vtss_pr_error("%s: Invalid sequence number", trn->name);

	if (vtss_transport_nr_records(trn) < 0)
		vtss_pr_error("%s: Sequence broken", trn->name);

	for (cpu = 0; cpu < vtss_nr_cpus(); cpu++) {

		rb = trn->ring_buffers[cpu];
		if (rb == NULL)
			continue;
		filled_size = vtss_ring_buffer_filled_size(rb);
		rd_count = atomic64_read(&rb->rd_count);

		if (verbose)
			vtss_pr_notice("%s: cpu%02d: %zu bytes: wr_count: %zu, rd_count: %zu",
				       trn->name, cpu, filled_size,
				       (size_t)atomic64_read(&rb->wr_count),
				       (size_t)atomic64_read(&rb->rd_count));

		while (filled_size >= sizeof(header)) {
			vtss_ring_buffer_read(rb, rd_count, (char *)&header, sizeof(header), false);
			if (verbose)
				vtss_pr_notice("%s: cpu%02d:    seqno: %zu, size: %zu",
					       trn->name, cpu, header.seqno, header.size);
			if (verbose < 2 || header.size <= 0 || header.size > 16*PAGE_SIZE)
				break;
			rd_count += VTSS_RB_ALIGN(sizeof(header) + header.size);
			filled_size -= VTSS_RB_ALIGN(sizeof(header) + header.size);
		}
	}
}

static ssize_t vtss_transport_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int rc, cpu;
	unsigned long long start;
	ssize_t nb, size = 0;
	unsigned int marker[2] = {VTSS_UEC_MAGIC, VTSS_UEC_MAGICVALUE};
	struct vtss_transport *trn;
	struct vtss_ring_buffer *rb;
	struct vtss_transport_header header;
	size_t filled_size;

	trn = file->private_data;
	if (trn == NULL) {
		vtss_pr_error("Invalid file private data");
		return -EINVAL;
	}
	if (trn->file == NULL) {
		vtss_pr_error("%s: Invalid transport file", trn->name);
		return -EINVAL;
	}
	if (buf == NULL || count == 0) {
		vtss_pr_error("%s: Invalid user buffer", trn->name);
		return -EINVAL;
	}

	while (!vtss_transport_completed(trn) && !vtss_transport_has_data(trn)) {

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
#ifdef VTSS_WAIT_QUEUE_TIMEOUT
		rc = wait_event_interruptible_timeout(trn->waitq,
						      (vtss_transport_completed(trn) ||
						       vtss_transport_has_data(trn)),
						      msecs_to_jiffies(VTSS_WAIT_QUEUE_TIMEOUT));
#else
		rc = wait_event_interruptible(trn->waitq,
					      (vtss_transport_completed(trn) ||
					       vtss_transport_has_data(trn)));
#endif
		if (rc < 0) {
			vtss_pr_error("%s: Failed to wait", trn->name);
			return -ERESTARTSYS;
		}
	}

	if (!trn->magic) {
		nb = sizeof(marker);
		if (copy_to_user(buf, marker, nb)) {
			vtss_pr_error("%s: Failed to copy magic marker", trn->name);
			return -EAGAIN;
		}
		count -= nb; buf += nb; size += nb;
		trn->magic = true;
	}

	start = vtss_time_cpu();
	while (count > 0 && vtss_transport_has_data(trn) &&
	       vtss_time_get_msec_from(start) < VTSS_TRANSPORT_READ_TIMEOUT) {
		for (cpu = 0; cpu < vtss_nr_cpus(); cpu++) {

			rb = trn->ring_buffers[cpu];
			if (rb == NULL)
				continue;

			filled_size = vtss_ring_buffer_filled_size(rb);

			if (filled_size >= sizeof(header)) {

				size_t rd_count = atomic64_read(&rb->rd_count);
				size_t rd_seqno = atomic64_read(&trn->rd_seqno);

				vtss_ring_buffer_read(rb, rd_count, (char *)&header, sizeof(header), false);
				rd_count += sizeof(header);

				if (header.seqno > rd_seqno)
					continue;
				if (header.seqno < rd_seqno) {
					/* skip unflushed */
					rd_count += header.size;
					atomic64_set(&rb->rd_count, VTSS_RB_ALIGN(rd_count));
					continue;
				}
				if (header.size > count) {
					vtss_pr_debug_trn2("%s: no room (%zu bytes) in user buffer", trn->name, count);
					goto out;
				}
				if (filled_size >= VTSS_RB_ALIGN(sizeof(header) + header.size)) {
					nb = header.size;
					rc = vtss_ring_buffer_read(rb, rd_count, (char *)buf, nb, true);
					if (rc) {
						vtss_pr_error("%s: Failed to copy to user buffer", trn->name);
						goto out;
					}
					rd_count += nb;
					count -= nb; buf += nb; size += nb;
				} else {
					vtss_pr_error("%s: Record truncted: %zu bytes of %zu",
						      trn->name, filled_size, header.size);
					goto out;
				}
				atomic64_set(&rb->rd_count, VTSS_RB_ALIGN(rd_count));
				atomic64_inc(&trn->rd_seqno);
				vtss_pr_debug_trn2("%s: read %zu bytes, cpu=%d, rd_seqno=%zu, rd_count=%zu",
						   trn->name, nb, cpu, rd_seqno, rd_count);
			}
		}
	}
	if (vtss_time_get_msec_from(start) >= VTSS_TRANSPORT_READ_TIMEOUT) {
		if (size == 0) {
			vtss_pr_error("%s: Read timeout", trn->name);
			vtss_transport_check(trn, 1);
			return -EFAULT;
		} else {
			vtss_pr_debug_trn("%s: timeout %lld msec, read %zu bytes",
					  trn->name, vtss_time_get_msec_from(start), size);
		}
	}
out:
	vtss_pr_debug_trn2("%s: total read %zu bytes", trn->name, size);
	return size;
}

static ssize_t vtss_transport_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	/* the transport entry is read only */
	return -EINVAL;
}

static unsigned int vtss_transport_poll(struct file *file, poll_table *poll_table)
{
	unsigned int rc = 0;
	struct vtss_transport *trn;

	trn = file->private_data;
	if (trn == NULL) {
		vtss_pr_error("Invalid file private data");
		return (POLLERR | POLLNVAL);
	}
	if (trn->file == NULL) {
		vtss_pr_error("%s: Invalid transport file", trn->name);
		return 0;
	}
	poll_wait(file, &trn->waitq, poll_table);
	if (vtss_transport_completed(trn) ||
	    (vtss_transport_has_data(trn) && !vtss_transport_rb(trn))) {
		/* data is ready to read */
		rc = (POLLIN | POLLRDNORM);
	}
	vtss_pr_debug_trn2("%s: %s", trn->name, rc ? "ready" : "-----");
	return rc;
}

static struct vtss_procfs_ops vtss_transport_fops = {
	.vtss_procfs_open    = vtss_transport_open,
	.vtss_procfs_release = vtss_transport_close,
	.vtss_procfs_read    = vtss_transport_read,
	.vtss_procfs_write   = vtss_transport_write,
	.vtss_procfs_poll    = vtss_transport_poll,
};

int vtss_transport_write_record(struct vtss_transport *trn, const void *part0, size_t size0,
							    const void *part1, size_t size1)
{
	int rc = 0;
	int cpu;
	struct vtss_ring_buffer *rb;
	size_t size = size0 + size1;
	struct vtss_transport_header header;

	if (!vtss_transport_started()) {
		vtss_pr_error("%s: Transport not started", trn->name);
		return -EFAULT;
	}

	if (vtss_transport_completed(trn)) {
		vtss_pr_error("%s: Transport completed", trn->name);
		return -EINVAL;
	}

	if (atomic_read(&vtss_ring_buffer_stopped) && vtss_transport_rb(trn)) {
		/* ring-buffer was stopped by user */
		return -EBUSY;
	}

	cpu = vtss_smp_processor_id();
	rb = trn->ring_buffers[cpu];
	if (rb == NULL) {
		vtss_pr_warning("%s: Buffer [cpu%d] disabled", trn->name, cpu);
		return -EINVAL;
	}

	if (!vtss_ring_buffer_set_busy(rb)) {
		vtss_stat_inc(&trn->lost.count);
		vtss_stat_add(size, &trn->lost.size);
		vtss_pr_warning("%s: Buffer [cpu%d] busy", trn->name, cpu);
		return -EBUSY;
	}

	/* flush ring-buffer */
	if (vtss_transport_rb(trn)) {
		while (vtss_ring_buffer_free_size(rb) < VTSS_RB_ALIGN(sizeof(header) + size)) {

			size_t rd_seqno;
			size_t rd_count = atomic64_read(&rb->rd_count);
			struct vtss_transport_header header;

			vtss_ring_buffer_read(rb, rd_count, (char *)&header, sizeof(header), false);
			while ((rd_seqno = atomic64_read(&trn->rd_seqno)) <= header.seqno)
				atomic64_cmpxchg(&trn->rd_seqno, rd_seqno, header.seqno + 1);

			rd_count += VTSS_RB_ALIGN(sizeof(header) + header.size);
			atomic64_set(&rb->rd_count, rd_count);
		}
	}

	if (vtss_ring_buffer_free_size(rb) >= VTSS_RB_ALIGN(sizeof(header) + size)) {

		size_t wr_seqno = atomic64_inc_return(&trn->wr_seqno);
		size_t wr_count = atomic64_read(&rb->wr_count);

		header = (struct vtss_transport_header){wr_seqno, size};
		vtss_ring_buffer_write(rb, wr_count, (char *)&header, sizeof(header));
		wr_count += sizeof(header);

		if (part0 && size0) {
			vtss_ring_buffer_write(rb, wr_count, part0, size0);
			wr_count += size0;
		}
		if (part1 && size1) {
			vtss_ring_buffer_write(rb, wr_count, part1, size1);
			wr_count += size1;
		}
		atomic64_set(&rb->wr_count, VTSS_RB_ALIGN(wr_count));
		vtss_pr_debug_trn2("%s: wrote %zu bytes, cpu=%d, wr_seqno=%zu, wr_count=%zu",
				  trn->name, size, cpu, wr_seqno, wr_count);
	} else {
		rc = -EAGAIN;
		vtss_pr_debug_trn("%s: cannot write %zu bytes", trn->name, size);
		vtss_stat_inc(&trn->lost.count);
		vtss_stat_add(size, &trn->lost.size);
	}
	vtss_ring_buffer_clear_busy(rb);

	return rc;
}

int vtss_transport_write_record_all(const void *part0, size_t size0,
				    const void *part1, size_t size1)
{
	int rc = 0;
	unsigned long flags;
	struct list_head *pos;
	struct vtss_transport *trn;

	vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
	list_for_each(pos, &vtss_transport_list) {
		trn = list_entry(pos, struct vtss_transport, list);
		/* use only primary transport */
		if (!(trn->mode & VTSS_TRANSPORT_AUX)) {
			/* if transport is used by collector and not closed */
			if (!vtss_transport_completed(trn) && !vtss_transport_closed(trn))
				rc |= vtss_transport_write_record(trn, part0, size0, part1, size1);
		}
	}
	vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
	return rc;
}

static int vtss_transport_nr_pages(int mode)
{
	int nr_pages = VTSS_TRANSPORT_SIZE;

	if (mode & VTSS_TRANSPORT_AUX) {
		if (mode & VTSS_TRANSPORT_RB) {
			if (mode & VTSS_TRANSPORT_IPT)
				nr_pages = vtss_reqcfg_rb_size()*VTSS_TRANSPORT_IPT_MSEC_SIZE;
			else
				nr_pages = vtss_reqcfg_rb_size()*VTSS_TRANSPORT_MSEC_SIZE;
		}
	} else {
		if (mode & VTSS_TRANSPORT_IPT)
			nr_pages = VTSS_TRANSPORT_IPT_SIZE;
	}
	return nr_pages;
}

static void vtss_transport_init(struct vtss_transport *trn, int mode)
{
	trn->mode = mode;
	INIT_LIST_HEAD(&trn->list);
	init_waitqueue_head(&trn->waitq);
	atomic_set(&trn->usage, 1);
	atomic64_set(&trn->wr_seqno, 0);
	atomic64_set(&trn->rd_seqno, 1);
}

static void vtss_transport_free(struct vtss_transport *trn)
{
	int cpu;

	if (trn == NULL)
		return;

	if (trn->ring_buffers) {
		for (cpu = 0; cpu < vtss_nr_cpus(); cpu++) {
			vtss_ring_buffer_free(trn->ring_buffers[cpu]);
			trn->ring_buffers[cpu] = NULL;
		}
		vtss_zfree(&trn->ring_buffers, vtss_nr_cpus()*sizeof(struct vtss_ring_buffer *));
	}
	vtss_zfree(&trn, sizeof(struct vtss_transport));
}

static struct vtss_transport *vtss_transport_alloc(int mode)
{
	int cpu;
	int nr_pages = vtss_transport_nr_pages(mode);
	struct vtss_transport *trn;

	trn = vtss_zalloc(sizeof(struct vtss_transport), GFP_KERNEL);
	if (trn == NULL) {
		vtss_pr_error("Not enough memory for transport structure");
		return NULL;
	}
	vtss_transport_init(trn, mode);

	trn->ring_buffers = vtss_zalloc(vtss_nr_cpus()*sizeof(struct vtss_ring_buffer *), GFP_KERNEL);
	if (trn->ring_buffers == NULL) {
		vtss_pr_error("Not enough memory for ring-buffer pool");
		goto out_fail;
	}
	for (cpu = 0; cpu < vtss_nr_cpus(); cpu++) {
		if (vtss_transport_rb(trn) && !vtss_cpu_active(cpu)) {
			/* skip ring-buffer allocation on inactive CPU */
			continue;
		}
		trn->ring_buffers[cpu] = vtss_ring_buffer_alloc(nr_pages, cpu);
		if (trn->ring_buffers[cpu] == NULL) {
			vtss_pr_error("Not enough memory for ring-buffer on cpu%d", cpu);
			goto out_fail;
		}
	}
	vtss_pr_debug_trn("allocated: nr_pages=%d, mode=0x%x", nr_pages, trn->mode);
	return trn;

out_fail:
	vtss_transport_free(trn);
	return NULL;
}

static void vtss_transport_list_init(void)
{
	unsigned long flags;

	vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
	INIT_LIST_HEAD(&vtss_transport_list);
	vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
}

static void vtss_transport_list_add(struct vtss_transport *trn)
{
	unsigned long flags;

	vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
	list_add_tail(&trn->list, &vtss_transport_list);
	vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
}

static void vtss_transport_force_close_all(void)
{
	unsigned long flags;
	struct list_head *pos;
	struct vtss_transport *trn;

	vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
	list_for_each(pos, &vtss_transport_list) {
		trn = list_entry(pos, struct vtss_transport, list);
		if (vtss_transport_set_completed(trn))
			vtss_pr_error("%s: Complete timeout", trn->name);
		if (vtss_transport_set_opened(trn))
			vtss_pr_error("%s: Open timeout", trn->name);
		if (vtss_transport_set_closed(trn)) {
			vtss_pr_error("%s: Close timeout", trn->name);
			if (trn->file) {
				trn->file->private_data = NULL;
				trn->file = NULL;
			}
		}
	}
	vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
}

static void vtss_transport_delete_worker(struct work_struct *work);

static int vtss_transport_wake_up_all(void)
{
	int rc = 0;
	unsigned long flags;
	struct list_head *pos, *next;
	struct vtss_transport *trn;

	if (!vtss_spin_trylock_irqsave(&vtss_transport_list_lock, flags))
		return -EAGAIN;

	list_for_each_safe(pos, next, &vtss_transport_list) {
		touch_nmi_watchdog();
		trn = list_entry(pos, struct vtss_transport, list);
		if (vtss_transport_opened(trn)) {
			if (vtss_transport_completed(trn) ||
			    (vtss_transport_has_data(trn) && !vtss_transport_rb(trn))) {
				/* data is ready to read */
				if (waitqueue_active(&trn->waitq))
					wake_up_interruptible(&trn->waitq);
			}
		}
		if (vtss_transport_closed(trn)) {
			if (vtss_transport_completed(trn)) {
				/* transport can be deleted */
				list_del(pos);
				atomic_inc(&vtss_transport_workers);
				INIT_WORK(&trn->delete_work, vtss_transport_delete_worker);
				vtss_queue_work(&trn->delete_work);
			}
		}
	}
	if (!list_empty(&vtss_transport_list))
		rc = -EAGAIN;
	vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
	return rc;
}

static unsigned long long vtss_transport_stopping_start = 0;
static bool vtss_transport_stop_sent = false;

#ifdef VTSS_AUTOCONF_TIMER_SETUP
static void vtss_transport_timer_tick(struct timer_list *unused)
#else
static void vtss_transport_timer_tick(unsigned long arg)
#endif
{
	int rc;
	bool again = false;
	bool timeout = false;

	if (vtss_transport_stopped()) {
		vtss_pr_warning("Transport tick when stopped");
		return;
	}

	if (vtss_transport_stopping()) {
		if (vtss_time_get_msec_from(vtss_transport_stopping_start) >= VTSS_TRANSPORT_STOP_TIMEOUT)
			timeout = true;
	}

	/* wake up user trace reader and
	 * remove closed transport endpoints */
	rc = vtss_transport_wake_up_all();
	if (rc) {
		/* has opened transport endpoints */
		again = true;
		if (timeout)
			vtss_transport_force_close_all();
	} else if (vtss_transport_stopping() &&
		   !vtss_collector_aborting() && /* not emergency stop */
		   !vtss_transport_stop_sent) {  /* do not spam user */
		/* notify user of collection stop */
		rc = vtss_procfs_control_send(NULL, 0);
		if (!rc) vtss_transport_stop_sent = true;
	}

	/* wake up user control endpoint */
	rc = vtss_procfs_control_wake_up();
	if (rc) {
		/* has unsent control messages */
		if (!again && timeout)
			vtss_pr_error("control: Close timeout");
		else
			again = true;
	}

	if (!again && vtss_transport_set_stopped()) {
		/* delete timer and stop */
		del_timer(&vtss_transport_timer);
		vtss_pr_notice("Transport shutdown: %lld msec",
			       vtss_time_get_msec_from(vtss_transport_stopping_start));
	} else {
		/* setup next timer tick */
		mod_timer(&vtss_transport_timer, jiffies + msecs_to_jiffies(VTSS_TRANSPORT_TIMER_INTERVAL));
	}
}

static int vtss_transport_check_mem(void)
{
	int mode = 0, nr_pages;
	int nr_cpus = vtss_nr_active_cpus();

	if (vtss_reqcfg_rb_mode())
		mode |= VTSS_TRANSPORT_RB;
	if (vtss_reqcfg_ipt_mode())
		mode |= VTSS_TRANSPORT_IPT;

	if (vtss_reqcfg_rb_mode())
		vtss_pr_notice("Ring-buffer %d msec enabled", vtss_reqcfg_rb_size());

	nr_pages = vtss_transport_nr_pages(mode) + vtss_transport_nr_pages(VTSS_TRANSPORT_AUX | mode);
	vtss_pr_notice("Transport per-process size: %d pages", nr_cpus*nr_pages);

#ifdef VTSS_AUTOCONF_SI_MEM_AVAILABLE
	if (mode) {
		vtss_pr_notice("Available kernel memory: %ld pages", si_mem_available());
		if (nr_cpus*nr_pages > si_mem_available()) {
			vtss_pr_error("Not enough memory for transport buffers");
			return -ENOMEM;
		}
	}
#endif
	return 0;
}

int vtss_transport_start(void)
{
	if (vtss_transport_check_mem())
		return -ENOMEM;

	if (!vtss_transport_set_started()) {
		vtss_pr_error("Transport already started");
		return -EBUSY;
	}

	vtss_transport_list_init();
	atomic_set(&vtss_ring_buffer_stopped, 0);

#ifdef VTSS_AUTOCONF_TIMER_SETUP
	timer_setup(&vtss_transport_timer, vtss_transport_timer_tick, 0);
	vtss_transport_timer.expires  = jiffies + msecs_to_jiffies(VTSS_TRANSPORT_TIMER_INTERVAL);
#else
	init_timer(&vtss_transport_timer);
	vtss_transport_timer.expires  = jiffies + msecs_to_jiffies(VTSS_TRANSPORT_TIMER_INTERVAL);
	vtss_transport_timer.function = vtss_transport_timer_tick;
	vtss_transport_timer.data     = 0;
#endif
	add_timer(&vtss_transport_timer);
	return 0;
}

void vtss_transport_stop(void)
{
	if (!vtss_transport_set_stopping()) {
		vtss_pr_warning("Transport already stopped");
		return;
	}
	vtss_transport_stopping_start = vtss_time_cpu();
	vtss_transport_stop_sent = false;
	return;
}

void vtss_transport_wait(void)
{
	if (!vtss_transport_stopped())
		vtss_pr_warning("Transport still not stopped");
	while (!vtss_transport_stopped());

	if (atomic_read(&vtss_transport_workers))
		vtss_pr_warning("%d transport workers in progress", atomic_read(&vtss_transport_workers));
	while (atomic_read(&vtss_transport_workers) != 0);
}

extern int uid, gid, mode;

static int vtss_transport_create_entry(struct vtss_transport *trn, uid_t cuid, gid_t cgid)
{
	struct proc_dir_entry *pde;

	if (vtss_procfs_root_entry == NULL) {
		vtss_pr_error("%s: Invalid procfs root", trn->name);
		return -EINVAL;
	}

#ifdef VTSS_PROCFS_OPS_OWNER
	vtss_transport_fops.owner = THIS_MODULE;
#endif
	pde = proc_create_data(trn->name, mode ? (mode & 0444) : 0440,
			       vtss_procfs_root_entry, &vtss_transport_fops, trn);
	if (pde == NULL) {
		vtss_pr_error("%s: Failed to create PDE", trn->name);
		return -EFAULT;
	}
#ifdef VTSS_AUTOCONF_PROCFS_PDE_OWNER
	pde->owner = THIS_MODULE;
#endif
	vtss_procfs_set_user(pde, cuid ? cuid : uid, cgid ? cgid : gid);
	return 0;
}

static void vtss_transport_remove_entry(struct vtss_transport *trn)
{
	if (vtss_transport_has_data(trn))
		vtss_pr_warning("%s: Dropped %ld records", trn->name, vtss_transport_nr_records(trn));

	if (vtss_procfs_root_entry)
		remove_proc_entry(trn->name, vtss_procfs_root_entry);

	vtss_pr_debug_trn("%s: removed", trn->name);
}

static void vtss_transport_delete_worker(struct work_struct *work)
{
	struct vtss_transport *trn = container_of(work, struct vtss_transport, delete_work);

	vtss_transport_remove_entry(trn);
	vtss_transport_free(trn);
	atomic_dec(&vtss_transport_workers);
}

struct vtss_transport *vtss_transport_add(pid_t ppid, pid_t pid, int order, int mode)
{
	int rc;
	struct vtss_transport *trn;
	char *ext = "";

	trn = vtss_transport_alloc(mode);
	if (trn == NULL)
		return NULL;

	if (mode & VTSS_TRANSPORT_AUX)
		ext = ".aux";
	snprintf(trn->name, sizeof(trn->name) - 1, "%d-%d.%d%s", ppid, pid, order, ext);
	rc = vtss_transport_create_entry(trn, vtss_session_uid, vtss_session_gid);
	if (rc) {
		vtss_transport_free(trn);
		return NULL;
	}
	vtss_transport_list_add(trn);
	vtss_pr_debug_trn("%s: added by collector", trn->name);
	return trn;
}

void vtss_transport_complete(struct vtss_transport *trn)
{
	if (trn == NULL)
		return;

	if (atomic_read(&trn->usage)) {
		vtss_pr_error("%s: Transport not completed, usage: %d",
			      trn->name, atomic_read(&trn->usage));
		return;
	}
	if (!vtss_transport_set_completed(trn)) {
		vtss_pr_warning("%s: Already completed", trn->name);
		return;
	}
	if (waitqueue_active(&trn->waitq))
		wake_up_interruptible(&trn->waitq);

	vtss_pr_debug_trn("%s: completed by collector", trn->name);
}

void vtss_transport_stat(struct vtss_transport *trn)
{
	if (trn == NULL)
		return;

	if (vtss_stat_read(&trn->lost.count))
		vtss_pr_warning("%s: Lost records: %zu/%ld (%zuKB)", trn->name,
				vtss_stat_read(&trn->lost.count),
				(long)atomic64_read(&trn->wr_seqno),
				vtss_stat_read(&trn->lost.size) >> 10);

	if (vtss_stat_read(&trn->lost.modules))
		vtss_pr_warning("%s: Lost module records: %zu", trn->name,
				vtss_stat_read(&trn->lost.modules));

	if (vtss_stat_read(&trn->lost.switches))
		vtss_pr_warning("%s: Lost switch records: %zu", trn->name,
				vtss_stat_read(&trn->lost.switches));

	if (vtss_stat_read(&trn->lost.samples))
		vtss_pr_warning("%s: Lost sample records: %zu", trn->name,
				vtss_stat_read(&trn->lost.samples));

	if (vtss_stat_read(&trn->lost.stacks))
		vtss_pr_warning("%s: Lost stack records: %zu", trn->name,
				vtss_stat_read(&trn->lost.stacks));

	if (vtss_stat_read(&trn->lost.ipts))
		vtss_pr_warning("%s: Lost IPT records: %zu", trn->name,
				vtss_stat_read(&trn->lost.ipts));
}
