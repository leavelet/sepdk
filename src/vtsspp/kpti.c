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
#include "kpti.h"
#include "ksyms.h"

bool vtss_kpti_enabled = false;

#ifdef VTSS_KPTI
#include <asm/io.h>		/* for virt_to_phys   */
#include <asm/tlbflush.h>	/* for flush_tlb_info */

#ifndef VTSS_AUTOCONF_FLUSH_TLB_INFO
struct flush_tlb_info {
	struct mm_struct	*mm;
	unsigned long		start;
	unsigned long		end;
	unsigned long		pad[5];
};
#endif

static int vtss_cea_init(void)
{
	if (static_cpu_has(X86_FEATURE_PTI)) {
		vtss_pr_notice("Kernel: KPTI enabled");
		vtss_kpti_enabled = true;
	} else {
		vtss_pr_notice("Kernel: KPTI disabled");
		vtss_kpti_enabled = false;
		return 0;
	}
	if (vtss_cea_set_pte == NULL) {
		vtss_pr_warning("Failed to find 'cea_set_pte' symbol");
		return -ENOENT;
	}
	if (vtss_do_kernel_range_flush == NULL) {
		vtss_pr_warning("Failed to find 'do_kernel_range_flush' symbol");
		return -ENOENT;
	}
	return 0;
}

/* This routine is a copy of the kernel's ds_update_cea */
int vtss_cea_register(void *cea, void *ptr, size_t size)
{
	unsigned long start = (unsigned long)cea;
	struct flush_tlb_info info = {0};
	phys_addr_t pa;
	size_t msz = 0;

	if (cea == NULL)
		return -EINVAL;

	pa = virt_to_phys(ptr);

	preempt_disable();
	for (; msz < size; msz += PAGE_SIZE, pa += PAGE_SIZE, cea += PAGE_SIZE)
		vtss_cea_set_pte(cea, pa, PAGE_KERNEL);

	info.start = start;
	info.end = start + size;
	vtss_do_kernel_range_flush(&info);
	preempt_enable();
	return 0;
}

/* This routine is a copy of the kernel's ds_clear_cea */
void vtss_cea_unregister(void *cea, size_t size)
{
	unsigned long start = (unsigned long)cea;
	struct flush_tlb_info info = {0};
	size_t msz = 0;

	if (cea == NULL)
		return;

	preempt_disable();
	for (; msz < size; msz += PAGE_SIZE, cea += PAGE_SIZE)
		vtss_cea_set_pte(cea, 0, PAGE_NONE);

	info.start = start;
	info.end = start + size;
	vtss_do_kernel_range_flush(&info);
	preempt_enable();
}

#elif defined(VTSS_KAISER)
#include <linux/kaiser.h>

static int vtss_kaiser_init(void)
{
	if (vtss_kaiser_enabled_ptr) {
		if (*vtss_kaiser_enabled_ptr) {
			vtss_pr_notice("Kernel: KAISER enabled");
			vtss_kpti_enabled = true;
		} else {
			vtss_pr_notice("Kernel: KAISER disabled");
			vtss_kpti_enabled = false;
			return 0;
		}
	} else {
		vtss_pr_notice("Kernel: KAISER auto mode enabled");
		vtss_kpti_enabled = true;
	}
	if (vtss_kaiser_add_mapping == NULL) {
		vtss_pr_warning("Failed to find 'kaiser_add_mapping' symbol");
		return -ENOENT;
	}
	if (vtss_kaiser_remove_mapping == NULL) {
		vtss_pr_warning("Failed to find 'kaiser_remove_mapping' symbol");
		return -ENOENT;
	}
	return 0;
}

int vtss_kaiser_register(void *ptr, size_t size)
{
	if (ptr == NULL)
		return -EINVAL;

	return vtss_kaiser_add_mapping((unsigned long)ptr, size, __PAGE_KERNEL | _PAGE_GLOBAL);
}

void vtss_kaiser_unregister(void *ptr, size_t size)
{
	if (ptr == NULL)
		return;

	vtss_kaiser_remove_mapping((unsigned long)ptr, size);
}
#endif

int vtss_kpti_init(void)
{
	int rc = 0;

#ifdef VTSS_KPTI
	rc = vtss_cea_init();
	if (rc) vtss_pr_warning("Failed to initialize KPTI");
#elif defined(VTSS_KAISER)
	rc = vtss_kaiser_init();
	if (rc) vtss_pr_warning("Failed to initialize KAISER");
#else
	vtss_pr_notice("Kernel: KPTI not detected");
#endif
	return rc;
}
