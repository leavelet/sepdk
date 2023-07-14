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

#ifndef _VTSS_TRANSPORT_H_
#define _VTSS_TRANSPORT_H_

#include "config.h"
#include "stat.h"

extern atomic_t vtss_ring_buffer_stopped;

#define vtss_transport_stop_ring_bufer() atomic_set(&vtss_ring_buffer_stopped, 1)

struct vtss_ring_buffer {
	int nr_pages;
	atomic_t busy;
	atomic64_t wr_count ____cacheline_aligned;
	atomic64_t rd_count ____cacheline_aligned;
	void *pages[0];
};

struct vtss_transport_stat {
	struct vtss_stat size;
	struct vtss_stat count;
	struct vtss_stat modules;
	struct vtss_stat switches;
	struct vtss_stat samples;
	struct vtss_stat stacks;
	struct vtss_stat ipts;
};

/* enough for ppid-pid.order.aux */
#define VTSS_TRANSPORT_NAME_SIZE 64

/* transport operating modes */
#define VTSS_TRANSPORT_AUX  0x1
#define VTSS_TRANSPORT_IPT  0x2
#define VTSS_TRANSPORT_RB   0x4

#define vtss_transport_rb(trn)\
	(((trn)->mode & VTSS_TRANSPORT_AUX) &&\
	 ((trn)->mode & VTSS_TRANSPORT_RB))

struct vtss_transport {
	bool magic;
	unsigned int mode;
	char name[VTSS_TRANSPORT_NAME_SIZE];
	struct list_head list;
	struct file *file;
	wait_queue_head_t waitq;
	struct work_struct delete_work;
	/* usage status */
	atomic_t opened;
	atomic_t completed;
	atomic_t usage;
	/* statistics */
	struct vtss_transport_stat lost;
	/* per-cpu ring buffers */
	atomic64_t wr_seqno ____cacheline_aligned;
	atomic64_t rd_seqno ____cacheline_aligned;
	struct vtss_ring_buffer **ring_buffers;
};

int vtss_transport_start(void);
void vtss_transport_stop(void);
void vtss_transport_wait(void);

int vtss_transport_write_record(struct vtss_transport *trn, const void *part0, size_t size0,
							    const void *part1, size_t size1);
int vtss_transport_write_record_all(const void *part0, size_t size0,
				    const void *part1, size_t size1);

#define vtss_transport_get(trn) atomic_inc(&(trn)->usage)
#define vtss_transport_put(trn) atomic_dec_and_test(&(trn)->usage)

struct vtss_transport *vtss_transport_add(pid_t ppid, pid_t pid, int order, int mode);
void vtss_transport_complete(struct vtss_transport *trn);

void vtss_transport_stat(struct vtss_transport *trn);

#endif
