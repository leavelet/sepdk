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
#include "ksyms.h"
#include "mmap.h"
#include "modcfg.h"
#include "record.h"
#include "task.h"
#include "task_map.h"
#include "time.h"

#include <linux/module.h>
#include <linux/path.h>
#include <asm/fixmap.h>		/* VSYSCALL_START */

#ifndef MODULES_VADDR
#define MODULES_VADDR VMALLOC_START
#endif

#ifdef VTSS_AUTOCONF_VMA_ITERATOR
#define VTSS_VMA_ITERATOR(vmi) struct vma_iterator vmi
#define vtss_vma_iter_init(vmi, mm) vma_iter_init(vmi, mm, 0)
#define vtss_for_each_vma(vmi, vma, mm) for_each_vma(vmi, vma)
#else
#define VTSS_VMA_ITERATOR(vmi)
#define vtss_vma_iter_init(vmi, mm)
#define vtss_for_each_vma(vmi, vma, mm) for ((vma) = (mm)->mmap; vma; (vma) = (vma)->vm_next)
#endif

static int vtss_mmap_write_user_all(struct vtss_task *tsk, struct task_struct *task)
{
	int rc = 0;
	char *name;
	bool vdso_found = false;
	unsigned long long cputsc, realtsc;
	unsigned long start, end;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	VTSS_VMA_ITERATOR(vmi);

	mm = get_task_mm(task);
	if (mm == NULL)
		return 0;
	vtss_mmap_read_lock(mm);

	vtss_time_get_sync(&cputsc, &realtsc);

	start = VTSS_LOST_DATA_MODULE_ADDR;
	end = start + 1;
	rc |= vtss_transport_write_module(vtss_task_trn_config(tsk),
		VTSS_LOST_DATA_MODULE_NAME, tsk->m32, start, end, 0,
		cputsc, realtsc);

#ifdef VTSS_AUTOCONF_VSYSCALL_ADDR
	start = VSYSCALL_ADDR;
	end = start + PAGE_SIZE;
#else
	start = VSYSCALL_START;
	end = start + VSYSCALL_MAPPED_PAGES*PAGE_SIZE;
#endif
	rc |= vtss_transport_write_module(vtss_task_trn_config(tsk),
		"[vsyscall]", false, start, end, 0, cputsc, realtsc);

	vtss_vma_iter_init(&vmi, mm);
	vtss_for_each_vma(vmi, vma, mm) {
		vtss_pr_debug_mmap("vma=[0x%lx-0x%lx], flags=0x%lx",
				   vma->vm_start, vma->vm_end, vma->vm_flags);
		if (vtss_vma_exec(vma)) {
			name = d_path(&vma->vm_file->f_path, tsk->mmap_write_buf, PAGE_SIZE);
			if (!IS_ERR(name))
				rc |= vtss_transport_write_module(vtss_task_trn_config(tsk),
					name, tsk->m32, vma->vm_start, vma->vm_end, vma->vm_pgoff,
					cputsc, realtsc);
#ifdef VM_HUGEPAGE
		} else if (vtss_vma_hugepage_exec(vma)) {
			/**
			 * Try to recover the mappings of some hugepages
			 * by looking at segments immediately precede and
			 * succeed them
			 */
			char *name_pred, *name_succ;
			unsigned long addr_pred = vma->vm_start - 1;
			unsigned long addr_succ = vma->vm_end;
			struct vm_area_struct *vma_pred = find_vma(mm, addr_pred);
			struct vm_area_struct *vma_succ = find_vma(mm, addr_succ);
			const size_t buf_sz = PAGE_SIZE/2;

			if (!vma_pred || addr_pred < vma_pred->vm_start || !vtss_vma_exec(vma_pred))
				continue;
			if (!vma_succ || addr_succ < vma_succ->vm_start || !vtss_vma_exec(vma_succ))
				continue;

			name_pred = d_path(&vma_pred->vm_file->f_path, tsk->mmap_write_buf, buf_sz);
			if (IS_ERR(name_pred))
				continue;

			name_succ = d_path(&vma_succ->vm_file->f_path, tsk->mmap_write_buf + buf_sz,
					   buf_sz);
			if (IS_ERR(name_succ))
				continue;

			if (strcmp(name_pred, name_succ) != 0)
				continue;

			vtss_pr_debug_mmap("recovered vma=[0x%lx-0x%lx], flags=0x%lx: %s",
					   vma->vm_start, vma->vm_end, vma->vm_flags,
					   name_pred);
			vtss_transport_write_module(vtss_task_trn_config(tsk),
				name_pred, tsk->m32, vma->vm_start, vma->vm_end,
				vma_pred->vm_pgoff +
				((vma_pred->vm_end - vma_pred->vm_start) >> PAGE_SHIFT),
				cputsc, realtsc);
#endif
		} else if (vtss_vma_vdso(vma)) {
			vdso_found = true;
			rc |= vtss_transport_write_module(vtss_task_trn_config(tsk),
				"[vdso]", tsk->m32, vma->vm_start, vma->vm_end, 0,
				cputsc, realtsc);
		}
	}
	if (!vdso_found && mm->context.vdso) {
		start = (unsigned long)mm->context.vdso;
		end = start + PAGE_SIZE;
		rc |= vtss_transport_write_module(vtss_task_trn_config(tsk),
			"[vdso]", tsk->m32, start, end, 0, cputsc, realtsc);
	}

	vtss_mmap_read_unlock(mm);
	mmput(mm);
	return rc;
}

static int vtss_mmap_write_kernel_all(struct vtss_task *tsk)
{
	int rc = 0;
	struct module *mod;
	struct list_head *modules;
	unsigned long long cputsc, realtsc;
	unsigned long start, end;

#ifdef VTSS_AUTOCONF_MODULE_MUTEX
	mutex_lock(&module_mutex);
#else
	rcu_read_lock_sched();
#endif
	vtss_time_get_sync(&cputsc, &realtsc);

	vtss_kallsyms_get_layout(&start, &end);
	rc |= vtss_transport_write_module(vtss_task_trn_config(tsk),
		"vmlinux", false, start, end, 0, cputsc, realtsc);

	/* locate the first module */
	for (modules = THIS_MODULE->list.prev;
	     (unsigned long)modules > MODULES_VADDR;
	     modules = modules->prev);

	list_for_each_entry(mod, modules, list) {
#ifdef VTSS_AUTOCONF_MODULE_CORE_LAYOUT
		start = (unsigned long)mod->core_layout.base;
		end = start + mod->core_layout.size;
#else
		start = (unsigned long)mod->module_core;
		end = start + mod->core_size;
#endif
		if (module_is_live(mod)) {
			rc |= vtss_transport_write_module(vtss_task_trn_config(tsk),
				mod->name, false, start, end, 0, cputsc, realtsc);
		}
	}
#ifdef VTSS_AUTOCONF_MODULE_MUTEX
	mutex_unlock(&module_mutex);
#else
	rcu_read_unlock_sched();
#endif
	return rc;
}

int vtss_mmap_write_all(struct vtss_task *tsk, struct task_struct *task)
{
	int rc;

	if (!vtss_collector_started()) {
		vtss_pr_warning("%d: Collection not started", tsk->tid);
		return -EFAULT;
	}
	if (!vtss_task_set_mmap_busy(tsk)) {
		vtss_pr_warning("%d: Busy to write module map", tsk->tid);
		return -EBUSY;
	}
	rc = vtss_mmap_write_user_all(tsk, task);
	vtss_mmap_write_kernel_all(tsk);
	vtss_task_clear_mmap_busy(tsk);

	return rc;
}

void vtss_mmap_write_user(struct task_struct *task, struct file *file,
			  unsigned long start, unsigned long end, unsigned long pgoff)
{
	struct vtss_task *tsk;
	char *name;
	unsigned long long cputsc, realtsc;

	if (!vtss_collector_started())
		return;

	if (vtss_is_task_in_execve(task))
		return;

	tsk = vtss_task_map_get(vtss_gettid(task));
	if (tsk && vtss_task_attached(tsk) && !vtss_task_mmap_busy(tsk)) {
		name = d_path(&file->f_path, tsk->mmap_write_buf, PAGE_SIZE);
		if (!IS_ERR(name)) {
			vtss_time_get_sync(&cputsc, &realtsc);
			vtss_transport_write_module(vtss_task_trn_config(tsk),
				name, tsk->m32, start, end, pgoff, cputsc, realtsc);
		}
	}
	vtss_task_map_put(tsk);
}

void vtss_mmap_write_kernel(struct task_struct *task, const char *name,
			    unsigned long start, unsigned long end, unsigned long pgoff)
{
	struct vtss_task *tsk;
	unsigned long long cputsc, realtsc;

	if (!vtss_collector_started())
		return;

	tsk = vtss_task_map_get(vtss_gettid(task));
	if (tsk && vtss_task_attached(tsk) && !vtss_task_mmap_busy(tsk)) {
		vtss_time_get_sync(&cputsc, &realtsc);
		vtss_transport_write_module(vtss_task_trn_config(tsk),
			name, false, start, end, pgoff, cputsc, realtsc);
	}
	vtss_task_map_put(tsk);
}
