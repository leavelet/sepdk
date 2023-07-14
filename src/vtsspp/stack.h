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

#ifndef _VTSS_STACK_H_
#define _VTSS_STACK_H_

#include "config.h"
#include "spinlock.h"
#include "transport.h"

#define VTSS_STACK_MAP_SIZE (16*PAGE_SIZE)

/* stack map entry to map SP to either FP or IP,
 * never change the order or number of entries,
 * the compressor interprets them as an unsigned long array */
struct vtss_stack_map_entry {
	unsigned long ptr;
	unsigned long value;
};

/* compressed clear stack */
struct vtss_callchain {
	char *buf;
	size_t size;
	size_t pos;
	unsigned long prev_addr;
};

/* stack unwinding statistics */
struct vtss_stack_stat {
	unsigned long samples;
	unsigned long eacces;
	unsigned long enomem;
	unsigned long eunwind;
};

/* stack unwinding control structure */
struct vtss_stack {

	/* 32-bit task flag */
	bool m32;

	/* stack sample properties */
	unsigned long ip;
	unsigned long sp;
	unsigned long fp;
	unsigned long bp;

	/* stack map data buffers */
	void *buf[2];
	/* pointer to inactive data buffer */
	void *shadow;

	/* the beginning of the map (compression starts here) */
	struct vtss_stack_map_entry *start;
	/* common entry on the stack map */
	struct vtss_stack_map_entry *common;
	/* end of stack map (the unwinding starts from here) */
	struct vtss_stack_map_entry *end;

	/* kernel clear stack */
	struct vtss_callchain kernel;

	/* user clear stack */
	struct vtss_callchain user;

	/* statistics */
	struct vtss_stack_stat stat;

	/* stack access protection */
	vtss_spinlock_t lock;

	/* mmap access properties */
	struct mm_struct *mm;
	unsigned long long start_time;
	void *cache;
};

#define vtss_stack_lock(stk)    vtss_spin_lock(&(stk)->lock)
#define vtss_stack_trylock(stk) vtss_spin_trylock(&(stk)->lock)
#define vtss_stack_unlock(stk)  vtss_spin_unlock(&(stk)->lock)

static inline unsigned long vtss_stack_get_addr(const void *buf, int stride)
{
	return (stride == 4) ? *(u32 *)buf : *(u64 *)buf;
}

#define vtss_callchain_compressed_size(callchain) ((callchain)->pos)
void vtss_callchain_reset(struct vtss_callchain *callchain);
int vtss_callchain_compress_next(struct vtss_callchain *callchain, unsigned long addr);

int vtss_stack_init(struct vtss_stack *stk, bool m32);
void vtss_stack_cleanup(struct vtss_stack *stk);

bool vtss_stack_valid_fp(struct vtss_stack *stk, unsigned long sp, unsigned long fp);
bool vtss_stack_valid_ip(struct vtss_stack *stk, unsigned long ip);

int vtss_stack_copy_from_user(struct vtss_stack *stk, void *to, const void *from, size_t size);

int vtss_stack_unwind(struct vtss_stack *stk, struct task_struct *task,
		      struct pt_regs *regs, unsigned long fp);
int vtss_stack_write(struct vtss_transport *trn, struct vtss_stack *stk, pid_t tid, int cpu);
void vtss_stack_stat(struct vtss_stack *stk, pid_t tid);

#endif
