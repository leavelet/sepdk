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
#include "kmem.h"
#include "ksyms.h"
#include "lbr.h"
#include "mmap.h"
#include "modcfg.h"
#include "regs.h"
#include "stack.h"
#include "stat.h"
#include "time.h"
#include "unwind.h"

#include <asm/fixmap.h>		/* for VSYSCALL_START */

static int vtss_callchain_init(struct vtss_callchain *callchain, size_t size)
{
	callchain->buf = vtss_alloc_pages(size, GFP_KERNEL, -1);
	if (callchain->buf == NULL)
		return -ENOMEM;
	callchain->size = size;
	vtss_callchain_reset(callchain);
	return 0;
}

static void vtss_callchain_cleanup(struct vtss_callchain *callchain)
{
	vtss_free_pages(callchain->buf, callchain->size);
	callchain->buf = NULL;
}

void vtss_callchain_reset(struct vtss_callchain *callchain)
{
	callchain->pos = 0;
	callchain->prev_addr = 0;
}

int vtss_callchain_compress_next(struct vtss_callchain *callchain, unsigned long addr)
{
	int j;
	int sign;
	char prefix = 0;
	unsigned long addr_diff;

	addr_diff = addr - callchain->prev_addr;
	sign = (addr_diff & (1UL << ((sizeof(unsigned long) << 3) - 1))) ? 0xff : 0;
	for (j = sizeof(unsigned long) - 1; j >= 0; j--) {
		if (((addr_diff >> (j << 3)) & 0xff) != sign)
			break;
	}
	prefix |= sign ? 0x40 : 0;
	prefix |= j + 1;

	if (callchain->pos + 1 + j + 1 > callchain->size)
		return -ENOMEM;

	callchain->buf[callchain->pos] = prefix;
	callchain->pos++;

	memcpy(callchain->buf + callchain->pos, &addr_diff, j + 1);
	callchain->pos += j + 1;
	callchain->prev_addr = addr;
	return 0;
}

int vtss_stack_init(struct vtss_stack *stk, bool m32)
{
	stk->m32 = m32;

	stk->buf[0] = vtss_alloc_pages(VTSS_STACK_MAP_SIZE, GFP_KERNEL, -1);
	if (stk->buf[0] == NULL) {
		vtss_pr_error("Not enough memory for primary stack buffer");
		goto out_fail;
	}
	stk->buf[1] = vtss_alloc_pages(VTSS_STACK_MAP_SIZE, GFP_KERNEL, -1);
	if (stk->buf[1] == NULL) {
		vtss_pr_error("Not enough memory for secondary stack buffer");
		goto out_fail;
	}
	vtss_stack_map_reset(stk);

	if (vtss_callchain_init(&stk->kernel, PAGE_SIZE)) {
		vtss_pr_error("Failed to initialize kernel callchain");
		goto out_fail;
	}
	if (vtss_callchain_init(&stk->user, PAGE_SIZE)) {
		vtss_pr_error("Failed to initialize user callchain");
		goto out_fail;
	}

	vtss_spin_lock_init(&stk->lock);

	/* use user callchain buffer as unwinding cache */
	stk->cache = stk->user.buf;
	return 0;

out_fail:
	vtss_stack_cleanup(stk);
	return -ENOMEM;
}

void vtss_stack_cleanup(struct vtss_stack *stk)
{
	if (stk == NULL)
		return;

	vtss_free_pages(stk->buf[0], VTSS_STACK_MAP_SIZE);
	stk->buf[0] = NULL;
	vtss_free_pages(stk->buf[1], VTSS_STACK_MAP_SIZE);
	stk->buf[1] = NULL;
	vtss_callchain_cleanup(&stk->kernel);
	vtss_callchain_cleanup(&stk->user);
}

#ifdef VTSS_AUTOCONF_STACKTRACE_OPS
#include <asm/stacktrace.h>

struct vtss_kernel_stack {
	int rc;
	unsigned long bp;
	struct vtss_callchain *callchain;
};

#ifdef VTSS_AUTOCONF_STACKTRACE_OPS_WARNING
static void vtss_kernel_stack_warning(void *data, char *msg)
{
}

static void vtss_kernel_stack_warning_symbol(void *data, char *msg, unsigned long symbol)
{
}
#endif

static int vtss_kernel_stack_stack(void *data, char *name)
{
	struct vtss_kernel_stack *kstk = data;

	if (kstk == NULL)
		return -1;
	if (kstk->rc)
		return -1;
	return 0;
}

static void vtss_kernel_stack_address(void *data, unsigned long addr, int reliable)
{
	struct vtss_kernel_stack *kstk = data;

	if (!reliable)
		return;
	if (kstk == NULL || kstk->callchain == NULL)
		return;
	if (kstk->callchain->pos >= kstk->callchain->size)
		return;
#ifndef CONFIG_FRAME_POINTER
	if (addr < VTSS_KOFFSET)
		return;
#endif
	if (kstk->rc)
		return;

	kstk->rc = vtss_callchain_compress_next(kstk->callchain, addr);
	if (kstk->rc)
		vtss_pr_warning("No room to compress kernel stack");
}

#ifdef VTSS_AUTOCONF_STACKTRACE_OPS_ADDRESS_INT
static int vtss_kernel_stack_address_int(void *data, unsigned long addr, int reliable)
{
	vtss_kernel_stack_address(data, addr, reliable);
	return 0;
}
#endif

#ifdef VTSS_AUTOCONF_STACKTRACE_OPS_WALK_STACK
static unsigned long vtss_kernel_stack_walk_stack(
#ifdef VTSS_AUTOCONF_STACKTRACE_OPS_WALK_STACK_TASK_ARG
	struct task_struct *t,
#else
	struct thread_info *t,
#endif
	unsigned long *stack,
	unsigned long bp,
	const struct stacktrace_ops *ops,
	void *data,
	unsigned long *end,
	int *graph)
{
	struct vtss_kernel_stack *kstk = data;

	if (kstk == NULL) {
		vtss_pr_debug_stack("no kernel stack data");
		kstk->rc = -EINVAL;
		return bp;
	}
	if (stack == NULL) {
		vtss_pr_debug_stack("no kernel stack pointer");
		kstk->rc = -EINVAL;
		return bp;
	}
	if (stack <= (unsigned long *)VTSS_MAX_USER_SPACE) {
		vtss_pr_debug_stack("kernel sp=0x%p in user space", stack);
		kstk->rc = -EINVAL;
		return bp;
	}

	if (kstk->bp == 0)
		kstk->bp = bp;
	if (kstk->rc)
		return bp;

	bp = print_context_stack(t, stack, kstk->bp, ops, data, end, graph);
	if (bp < VTSS_KSTART)
		kstk->bp = bp;

	return bp;
}
#endif

static const struct stacktrace_ops vtss_kernel_stack_ops = {
#ifdef VTSS_AUTOCONF_STACKTRACE_OPS_WARNING
	.warning        = vtss_kernel_stack_warning,
	.warning_symbol = vtss_kernel_stack_warning_symbol,
#endif
	.stack          = vtss_kernel_stack_stack,
#ifdef VTSS_AUTOCONF_STACKTRACE_OPS_ADDRESS_INT
	.address        = vtss_kernel_stack_address_int,
#else
	.address        = vtss_kernel_stack_address,
#endif
#ifdef VTSS_AUTOCONF_STACKTRACE_OPS_WALK_STACK
	.walk_stack     = vtss_kernel_stack_walk_stack,
#endif
};

static int vtss_stack_unwind_kernel(struct vtss_stack *stk, struct task_struct *task,
				    struct pt_regs *regs, unsigned long *fp)
{
	struct vtss_kernel_stack kstk;

	kstk.rc = 0;
	kstk.bp = *fp;
	kstk.callchain = &stk->kernel;
#ifdef VTSS_AUTOCONF_DUMP_TRACE_HAVE_BP
	dump_trace(task, regs, NULL, 0, &vtss_kernel_stack_ops, &kstk);
#else
	dump_trace(task, regs, NULL, &vtss_kernel_stack_ops, &kstk);
#endif
	if (kstk.bp) *fp = kstk.bp;
	return kstk.rc;
}

#else /* VTSS_AUTOCONF_STACKTRACE_OPS */
#include <asm/unwind.h>

static int vtss_stack_unwind_kernel(struct vtss_stack *stk, struct task_struct *task,
				    struct pt_regs *regs, unsigned long *fp)
{
	int rc = 0;
	struct unwind_state state;
	unsigned long addr;

	for (unwind_start(&state, task, regs, NULL);
	     !unwind_done(&state); unwind_next_frame(&state)) {
		addr = unwind_get_return_address(&state);
		if (addr == 0)
			break;
		rc = vtss_callchain_compress_next(&stk->kernel, addr);
		if (rc) {
			vtss_pr_warning("No room to compress kernel stack");
			break;
		}
	}
	return rc;
}
#endif

bool vtss_stack_valid_fp(struct vtss_stack *stk, unsigned long sp, unsigned long fp)
{
	int stride = stk->m32 ? 4 : 8;

	if (fp < sp || fp >= stk->bp)
		return false;
	if (fp & (stride - 1))
		return false;
	return true;
}

static bool vtss_stack_valid_user_ip(struct vtss_stack *stk, unsigned long ip)
{
	struct vm_area_struct *vma;

	if (stk->mm == NULL)
		return false;
	vma = find_vma(stk->mm, ip);
	if (vma == NULL || ip < vma->vm_start)
		return false;
	if (!(vma->vm_flags & (VM_EXEC | VM_MAYEXEC)))
		return false;
	return true;
}

bool vtss_stack_valid_ip(struct vtss_stack *stk, unsigned long ip)
{
#ifdef VTSS_AUTOCONF_VSYSCALL_ADDR
	if ((ip & PAGE_MASK) == VSYSCALL_ADDR)
#else
	if ((ip >= VSYSCALL_START) && (ip < VSYSCALL_END))
#endif
		return true; /* [vsyscall] */

	else if (ip < VTSS_KSTART)
		return vtss_stack_valid_user_ip(stk, ip);

	else if (ip < PAGE_OFFSET)
		return true; /* in kernel */

	return false;
}

int vtss_stack_copy_from_user(struct vtss_stack *stk, void *to, const void *from, size_t size)
{
	unsigned long rem;

	if (vtss_time_get_msec_from(stk->start_time) >= VTSS_STACK_READ_TIMEOUT) {
		vtss_pr_debug_stack("0x%p: read timeout", from);
		return -EFAULT;
	}
	rem = vtss_copy_from_user_nmi(to, from, size);
	return rem ? -EFAULT : 0;
}

static int vtss_stack_read_user_frame(struct vtss_stack *stk, const void *from,
				      unsigned long *fp, unsigned long *ip)
{
	char buf[2*sizeof(unsigned long)]; /* fp + ip */
	int stride = stk->m32 ? 4 : 8;

	if (vtss_stack_copy_from_user(stk, buf, from, 2*stride))
		return -EFAULT;
	*fp = vtss_stack_get_addr(&buf[0*stride], stride);
	*ip = vtss_stack_get_addr(&buf[1*stride], stride);
	return 0;
}

static int vtss_stack_unwind_user(struct vtss_stack *stk)
{
	int rc = 0;
	unsigned long fp = stk->fp;
	unsigned long ip = stk->ip;
	unsigned long ptr = fp;

	vtss_pr_debug_stack("fp=0x%lx, ip=0x%lx", fp, ip);
	if (!vtss_stack_valid_fp(stk, stk->sp, fp))
		return -EFAULT; /* no frames */
	while (ptr) {
		rc = vtss_stack_read_user_frame(stk, (void *)ptr, &fp, &ip);
		if (rc)
			break;
		if (fp == ptr)
			break;
		if (!vtss_stack_valid_fp(stk, ptr, fp))
			break;
		if (!vtss_stack_valid_ip(stk, ip))
			break;

		rc = vtss_callchain_compress_next(&stk->user, ip);
		if (rc) {
			vtss_pr_warning("No room to compress user stack");
			break;
		}
		ptr = fp;
	}
	return rc;
}

static int vtss_stack_fixup_base(struct vtss_stack *stk, unsigned long sp, unsigned long *pbase)
{
	unsigned long base = *pbase;
	unsigned long stk_sz, limit;
	struct vm_area_struct *vma;

	if (stk->mm == NULL)
		return -EINVAL;

	vma = find_vma(stk->mm, sp);
	if (vma == NULL || sp < vma->vm_start) {
		vtss_pr_debug_stack("no vma for sp=0x%lx", sp);
		return -ENOENT;
	}

	if (!(vma->vm_flags & VM_READ) || !(vma->vm_flags & VM_WRITE)) {
		vtss_pr_debug_stack("sp=0x%lx: invalid vm_flags=%lx", sp, vma->vm_flags);
		return -ENOENT;
	}

	if (!(base >= vma->vm_start && base <= vma->vm_end) || (base <= sp)) {
		if (base)
			vtss_pr_debug_stack("fixup stack [0x%lx-0x%lx]->[0x%lx-0x%lx]",
					    sp, base, sp, vma->vm_end);
		base = vma->vm_end;
		vtss_stack_map_reset(stk);
	}

	stk_sz = ALIGN(vtss_reqcfg.stk_sz[vtss_stk_user], PAGE_SIZE);
	if (stk_sz == 0)
		stk_sz = VTSS_STACK_READ_LIMIT*PAGE_SIZE;
	if (stk_sz && (base - sp > stk_sz)) {
		limit = (sp + stk_sz) & ~(PAGE_SIZE - 1);
		vtss_pr_debug_stack("stack limited to %luKB, drop %luKB",
				    (limit - sp) >> 10, (base - limit) >> 10);
		base = limit;
	}

	*pbase = base;
	return 0;
}

/* returns success if user stack was unwound */
int vtss_stack_unwind(struct vtss_stack *stk, struct task_struct *task,
		      struct pt_regs *regs, unsigned long fp)
{
	int rc;
	bool kernel = false;

	/* check current task */
	if (task != current)
		return -EFAULT;
	if (!vtss_is_task_valid(task))
		return -EFAULT;

	/* collect LBR stack (if requested) */
	if (vtss_reqcfg_lbrstk_mode()) {
		vtss_lbr_sample(&stk->user);
		return 0;
	}

	/* check if we are in kernel mode */
	if (regs && !user_mode(regs))
		kernel = true;
	if (regs == NULL && fp > VTSS_MAX_USER_SPACE)
		kernel = true;
#ifdef VTSS_AUTOCONF_STACKTRACE_OPS
#ifndef CONFIG_FRAME_POINTER
	/* cannot unwind without framepointers and registers */
	if (regs == NULL)
		kernel = false;
#endif
#endif
	/* collect the kernel stack */
	if (kernel) {
		if (fp < PAGE_SIZE || fp == -1)
			fp = 0; /* error instead of FP */
		vtss_stack_unwind_kernel(stk, task, regs, &fp);
	}

	/* try to get a user mode registers */
	if (!(regs && user_mode(regs))) {
		regs = vtss_get_task_regs(task);
		if (!(regs && user_mode(regs))) {
			vtss_pr_debug_stack("%d: no user mode regs", vtss_gettid(task));
			return -EPERM;
		}
	}

	/* get user IP and SP registers */
	stk->ip = regs->ip;
	stk->sp = regs->sp;

	/* fixup user FP register */
	if (fp < PAGE_SIZE || fp > VTSS_MAX_USER_SPACE)
		stk->fp = regs->bp;
	else
		stk->fp = fp;

	/* skip kernel threads or if no memory */
	if (!vtss_is_task_mm_valid(task)) {
		vtss_pr_debug_stack("%d: in kernel thread", vtss_gettid(task));
		return -EINVAL;
	}
	/* mm is valid from this point */
	stk->mm = task->mm;

	/* lock task mmap to use find_vma() */
	if (!vtss_mmap_read_trylock(stk->mm)) {
		vtss_pr_debug_stack("%d: mmap busy", vtss_gettid(task));
		return -EBUSY;
	}

	/* check SP and fixup stack base */
	rc = vtss_stack_fixup_base(stk, stk->sp, &stk->bp);
	if (rc) goto out;

	/* setup initial time for read timeout */
	stk->start_time = vtss_time_cpu();

	/* collect user stack by framepointer unwinder (if requested) */
	if (vtss_reqcfg_fpstk_mode()) {
		vtss_stack_unwind_user(stk);
		rc = 0;
		goto out;
	}

	/* collect user stack by stack map unwinder */
	rc = vtss_stack_map_unwind(stk);
	if (rc) {
		/* error is returned only if incremental stack
		 * unwind fails, thus fallback to entire stack */
		vtss_stack_map_reset(stk);
		rc = vtss_stack_map_unwind(stk);
	}
	/* the stack is completely inaccessible */
	if (vtss_stack_map_nr_unwound(stk) == 0)
		rc = -EACCES;

	vtss_pr_debug_stack("stack=[0x%lx-0x%lx], ip=0x%lx, fp=0x%lx: unwound %zu entries",
			    stk->sp, stk->bp, stk->ip, stk->fp, vtss_stack_map_nr_unwound(stk));

out:
	vtss_mmap_read_unlock(stk->mm);
	return rc;
}

static int vtss_stack_write_kernel(struct vtss_transport *trn, struct vtss_stack *stk,
				   pid_t tid, int cpu)
{
	int rc;
	size_t size = vtss_callchain_compressed_size(&stk->kernel);
	vtss_kernel_stack_record_t rec;

	if (size == 0) {
		/* kernel stack is empty */
		return 0;
	}
	/* store kernel stack */
	rec.flagword = VTSS_UEC_LEAF1 | VTSS_UECL1_VRESIDX | VTSS_UECL1_SYSTRACE;
	rec.residx   = tid;
	rec.size     = sizeof(rec.size) + sizeof(rec.type) + sizeof(rec.idx) + size;
	rec.type     = VTSS_UECSYSTRACE_CLEAR_STACK64;
	rec.idx      = -1;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), stk->kernel.buf, size);
	if (rc) vtss_pr_debug_stack("%s: Failed to write kernel stack record", trn->name);
	return rc;
}

static int vtss_stack_write_user(struct vtss_transport *trn, struct vtss_stack *stk,
				 pid_t tid, int cpu)
{
	int rc;
	size_t size = vtss_callchain_compressed_size(&stk->user);
	vtss_clear_stack_record_t rec;

	if (size == 0) {
		/* user stack is empty */
		return 0;
	}
	/* store user stack */
	rec.flagword = VTSS_UEC_LEAF1    | VTSS_UECL1_VRESIDX  | VTSS_UECL1_CPUIDX |
		       VTSS_UECL1_CPUTSC | VTSS_UECL1_EXECADDR | VTSS_UECL1_SYSTRACE;
	rec.residx   = tid;
	rec.cpuidx   = cpu;
	rec.cputsc   = vtss_time_cpu();
	rec.execaddr = stk->ip;
	rec.size     = sizeof(rec.size) + sizeof(rec.type) + sizeof(rec.merge_node) + size;
	rec.type     = stk->m32 ? VTSS_UECSYSTRACE_CLEAR_STACK32 : VTSS_UECSYSTRACE_CLEAR_STACK64;
	rec.merge_node = 0xffffffff;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), stk->user.buf, size);
	if (rc) vtss_pr_debug_stack("%s: Failed to write user clear stack record", trn->name);
	return rc;
}

/* returns success if user stack was stored */
int vtss_stack_write(struct vtss_transport *trn, struct vtss_stack *stk, pid_t tid, int cpu)
{
	int rc;
	size_t size, pad32;
	unsigned short type;

	/* store kernel stack */
	vtss_stack_write_kernel(trn, stk, tid, cpu);

	/* store user clear stack (LBR or FP-based) */
	if (vtss_callchain_compressed_size(&stk->user)) {
		vtss_stack_write_user(trn, stk, tid, cpu);
		return 0;
	}

	/* check if stack map was unwound */
	if (vtss_stack_map_nr_unwound(stk) == 0)
		return 0;

	/* compress user stack map */
	size = vtss_stack_map_compress(stk);
	if (size == 0) {
		vtss_pr_debug_stack("%d: compression error", tid);
		return -EFAULT;
	}

	if (!vtss_stack_map_incremental(stk)) {
		/* entire stack */
		type = stk->m32 ? VTSS_UECSYSTRACE_STACK_CTX32_V0 :
				  VTSS_UECSYSTRACE_STACK_CTX64_V0;
	} else {
		/* incremental stack */
		type = stk->m32 ? VTSS_UECSYSTRACE_STACK_CTXINC32_V0 :
				  VTSS_UECSYSTRACE_STACK_CTXINC64_V0;
	}
	pad32 = stk->m32 ? 8 : 0 /* exclude padding after sp32/fp32 */;

	/* store user stack map */
	if (sizeof(vtss_stack_record_t) - pad32 + size <= VTSS_MAX_RECORD_SIZE) {
		vtss_stack_record_t rec;

		rec.flagword = VTSS_UEC_LEAF1    | VTSS_UECL1_VRESIDX  | VTSS_UECL1_CPUIDX |
			       VTSS_UECL1_CPUTSC | VTSS_UECL1_EXECADDR | VTSS_UECL1_SYSTRACE;
		rec.residx   = tid;
		rec.cpuidx   = cpu;
		rec.cputsc   = vtss_time_cpu();
		rec.execaddr = stk->ip;
		rec.type     = type;
		rec.size     = sizeof(rec.size) + sizeof(rec.type);
		if (stk->m32) {
			rec.sp32  = stk->sp;
			rec.fp32  = stk->fp;
			rec.size += sizeof(rec.sp32) + sizeof(rec.fp32);
		} else {
			rec.sp64  = stk->sp;
			rec.fp64  = stk->fp;
			rec.size += sizeof(rec.sp64) + sizeof(rec.fp64);
		}
		rec.size += size;
		rc = vtss_transport_write_record(trn, &rec, sizeof(rec) - pad32, stk->shadow, size);
		if (rc) vtss_pr_debug_stack("%s: Failed to write user stack record", trn->name);
	} else {
		vtss_large_stack_record_t rec;

		rec.flagword = VTSS_UEC_LEAF1    | VTSS_UECL1_VRESIDX  | VTSS_UECL1_CPUIDX |
			       VTSS_UECL1_CPUTSC | VTSS_UECL1_EXECADDR | VTSS_UECL1_LARGETRACE;
		rec.residx   = tid;
		rec.cpuidx   = cpu;
		rec.cputsc   = vtss_time_cpu();
		rec.execaddr = stk->ip;
		rec.type     = type;
		rec.size     = sizeof(rec.size) + sizeof(rec.type);
		if (stk->m32) {
			rec.sp32  = stk->sp;
			rec.fp32  = stk->fp;
			rec.size += sizeof(rec.sp32) + sizeof(rec.fp32);
		} else {
			rec.sp64  = stk->sp;
			rec.fp64  = stk->fp;
			rec.size += sizeof(rec.sp64) + sizeof(rec.fp64);
		}
		rec.size += size;
		rc = vtss_transport_write_record(trn, &rec, sizeof(rec) - pad32, stk->shadow, size);
		if (rc) vtss_pr_debug_stack("%s: Failed to write large user stack record",
					    trn->name);
	}
	if (rc) vtss_stat_inc(&trn->lost.stacks);
	return rc;
}

void vtss_stack_stat(struct vtss_stack *stk, pid_t tid)
{
	if (stk == NULL)
		return;

	if (stk->stat.eacces > 1)
		vtss_pr_warning("%d: Truncated stack samples: %ld/%ld: Read error",
				tid, stk->stat.eacces, stk->stat.samples);

	if (stk->stat.enomem)
		vtss_pr_warning("%d: Truncated stack samples: %ld/%ld: Out of memory",
				tid, stk->stat.enomem, stk->stat.samples);

	if (stk->stat.eunwind > stk->stat.samples/100 && stk->stat.samples > 100)
		vtss_pr_warning("%d: Lost stack samples: %ld/%ld: Unwind error",
				tid, stk->stat.eunwind, stk->stat.samples);
}
