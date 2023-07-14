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

#include "cpu.h"
#include "debug.h"
#include "ksyms.h"
#include "regs.h"

#ifdef VTSS_KASLR
static unsigned long vtss_kaslr_text = 0;
static unsigned long vtss_kaslr_stext = 0;
#endif

#ifdef VTSS_KPTI
void (*vtss_cea_set_pte)(void *cea_vaddr, phys_addr_t pa, pgprot_t flags) = NULL;
void (*vtss_do_kernel_range_flush)(void *info) = NULL;
#endif

#ifdef VTSS_KAISER
int *vtss_kaiser_enabled_ptr = NULL;
int (*vtss_kaiser_add_mapping)(unsigned long addr, unsigned long size, pteval_t flags) = NULL;
void (*vtss_kaiser_remove_mapping)(unsigned long start, unsigned long size) = NULL;
#endif

#if defined (VTSS_AUTOCONF_TRACEPOINT_PROBE) &&\
   !defined (VTSS_AUTOCONF_FOR_EACH_KERNEL_TRACEPOINT)
struct tracepoint *vtss_ksyms_tracepoint_sched_switch = NULL;
struct tracepoint *vtss_ksyms_tracepoint_sched_process_fork = NULL;
struct tracepoint *vtss_ksyms_tracepoint_sched_process_exec = NULL;
struct tracepoint *vtss_ksyms_tracepoint_sched_process_exit = NULL;
#endif

extern char *ksyms;
#ifdef VTSS_KALLSYMS
static unsigned long (*vtss_kallsyms_lookup_name)(const char *) = NULL;
#endif

int vtss_kallsyms_init(void)
{
#ifdef VTSS_KALLSYMS
	bool ibt_enabled = false;
	unsigned long long cet;
	unsigned int eax, ebx, ecx, edx;

#ifdef VTSS_KALLSYMS_LOOKUP_NAME
	vtss_kallsyms_lookup_name = kallsyms_lookup_name;
#else
	int rc;
	unsigned long addr = 0;

	if (ksyms == NULL) {
		vtss_pr_warning("Empty 'ksyms' driver option");
		return 0;
	}
	vtss_pr_notice("Driver options: ksyms: %s", ksyms);
	rc = kstrtoul(ksyms, 16, &addr);
	if (rc) {
		vtss_pr_warning("Invalid 'ksyms' driver option");
		return 0;
	}
	if (addr == 0)
		vtss_pr_warning("Null address in 'ksyms' driver option");

	vtss_kallsyms_lookup_name = (void *)addr;

#endif
	cpuid(VTSS_CPUID_EXT_FEATURES, &eax, &ebx, &ecx, &edx);
	if (vtss_cpuid_cpu_has_ibt(edx)) {
		rdmsrl(VTSS_IA32_S_CET, cet);
		if (cet & VTSS_CET_ENDBR_EN) {
			vtss_pr_notice("CPU feature: IBT enabled");
			ibt_enabled = true;
		} else {
			vtss_pr_notice("CPU feature: IBT disabled");
		}
	}
	if (ibt_enabled)
		wrmsrl(VTSS_IA32_S_CET, cet & ~VTSS_CET_ENDBR_EN);

#ifdef VTSS_KASLR
	vtss_kaslr_text = vtss_kallsyms_lookup_name("_text") & ~(PAGE_SIZE - 1);
	vtss_kaslr_stext = vtss_kallsyms_lookup_name("_stext") & ~(PAGE_SIZE - 1);
#endif

#ifdef VTSS_KPTI
	vtss_cea_set_pte = (void *)vtss_kallsyms_lookup_name("cea_set_pte");
	vtss_do_kernel_range_flush = (void *)vtss_kallsyms_lookup_name("do_kernel_range_flush");
#endif

#ifdef VTSS_KAISER
	vtss_kaiser_enabled_ptr = (int *)vtss_kallsyms_lookup_name("kaiser_enabled");
	vtss_kaiser_add_mapping = (void *)vtss_kallsyms_lookup_name("kaiser_add_mapping");
	vtss_kaiser_remove_mapping = (void *)vtss_kallsyms_lookup_name("kaiser_remove_mapping");
#endif

#if defined (VTSS_AUTOCONF_TRACEPOINT_PROBE) &&\
   !defined (VTSS_AUTOCONF_FOR_EACH_KERNEL_TRACEPOINT)
	vtss_ksyms_tracepoint_sched_switch =
		(void *)vtss_kallsyms_lookup_name("__tracepoint_sched_switch");
	vtss_ksyms_tracepoint_sched_process_fork =
		(void *)vtss_kallsyms_lookup_name("__tracepoint_sched_process_fork");
	vtss_ksyms_tracepoint_sched_process_exec =
		(void *)vtss_kallsyms_lookup_name("__tracepoint_sched_process_exec");
	vtss_ksyms_tracepoint_sched_process_exit =
		(void *)vtss_kallsyms_lookup_name("__tracepoint_sched_process_exit");
#endif

	if (ibt_enabled)
		wrmsrl(VTSS_IA32_S_CET, cet);
#endif
	return 0;
}

void vtss_kallsyms_get_layout(unsigned long *start, unsigned long *end)
{
	*start = VTSS_KSTART;
	*end = *start + VTSS_KSIZE;
#ifdef VTSS_KASLR
	/* fixup start address of KASLR kernels */
	if (!vtss_kaslr_text && !vtss_kaslr_stext) {
		vtss_pr_warning("Failed to find KASLR symbols");
		return;
	}
	vtss_pr_debug_mmap("vmlinux: start=0x%lx, text=0x%lx, stext=0x%lx",
			   *start, vtss_kaslr_text, vtss_kaslr_stext);
	if (vtss_kaslr_text > *start)
		*start = vtss_kaslr_text;
	else if (!vtss_kaslr_text && vtss_kaslr_stext > *start)
		*start = vtss_kaslr_stext;
#endif
}
