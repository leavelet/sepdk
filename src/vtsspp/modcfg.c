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
#include "ipt.h"
#include "modcfg.h"
#include "procfs.h"
#include "regs.h"
#include "time.h"
#include "user.h"

#include <linux/utsname.h>
#include <linux/module.h>
#include <linux/cpufreq.h>
#include <linux/wait.h>

/* trace format information to enable forward compatibility */
vtss_fmtcfg_t vtss_fmtcfg[2];

/* system configuration */
vtss_syscfg_t vtss_syscfg;

/* hardware configuration */
vtss_hardcfg_t vtss_hardcfg;

/* cpuid data for all CPUs */
vtss_cpuinfo_t vtss_cpuinfo;

/* processor trace configuration */
vtss_iptcfg_t vtss_iptcfg;

/* profiling configuration */
struct vtss_reqcfg vtss_reqcfg;

/* time source for collection */
int vtss_time_source = VTSS_TIME_SOURCE_SYS;

/* CPUs to collect data on */
cpumask_t vtss_cpumask = CPU_MASK_NONE;

/* Big/small core support */
bool vtss_cpu_hybrid_mode = false;

static void vtss_fmtcfg_init(void)
{
	memset(&vtss_fmtcfg, 0, sizeof(vtss_fmtcfg_t)*2);

	/*
	 * Leaf 1: base
	 */
	vtss_fmtcfg[0].rank = 0;
	vtss_fmtcfg[0].and_mask = VTSS_UEC_LEAF0 | VTSS_UEC_LEAF1 | VTSS_UEC_LEAF2 | VTSS_UEC_LEAF3;
	vtss_fmtcfg[0].cmp_mask = VTSS_UEC_LEAF1;
	vtss_fmtcfg[0].defcount = 0x20;

	vtss_fmtcfg[0].defbit[0x00] = 4;  /* VTSS_UECL1_ACTIVITY      0x00000001 */
	vtss_fmtcfg[0].defbit[0x01] = 4;  /* VTSS_UECL1_VRESIDX       0x00000002 */
	vtss_fmtcfg[0].defbit[0x02] = 4;  /* VTSS_UECL1_CPUIDX        0x00000004 */
	vtss_fmtcfg[0].defbit[0x03] = 8;  /* VTSS_UECL1_USRLVLID      0x00000008 */
	vtss_fmtcfg[0].defbit[0x04] = 8;  /* VTSS_UECL1_CPUTSC        0x00000010 */
	vtss_fmtcfg[0].defbit[0x05] = 8;  /* VTSS_UECL1_REALTSC       0x00000020 */
	vtss_fmtcfg[0].defbit[0x06] = 1;  /* VTSS_UECL1_MUXGROUP      0x00000040 */
	vtss_fmtcfg[0].defbit[0x07] = 8;  /* VTSS_UECL1_CPUEVENT      0x00000080 */
	vtss_fmtcfg[0].defbit[0x08] = 8;  /* VTSS_UECL1_CHPSETEV      0x00000100 */
	vtss_fmtcfg[0].defbit[0x09] = 8;  /* VTSS_UECL1_OSEVENT       0x00000200 */
	vtss_fmtcfg[0].defbit[0x0a] = 8;  /* VTSS_UECL1_EXECADDR      0x00000400 */
	vtss_fmtcfg[0].defbit[0x0b] = 8;  /* VTSS_UECL1_REFADDR       0x00000800 */
	vtss_fmtcfg[0].defbit[0x0c] = 8;  /* VTSS_UECL1_EXEPHYSADDR   0x00001000 */
	vtss_fmtcfg[0].defbit[0x0d] = 8;  /* VTSS_UECL1_REFPHYSADDR   0x00002000 */
	vtss_fmtcfg[0].defbit[0x0e] = 4;  /* VTSS_UECL1_TPIDX         0x00004000 */
	vtss_fmtcfg[0].defbit[0x0f] = 8;  /* VTSS_UECL1_TPADDR        0x00008000 */
	vtss_fmtcfg[0].defbit[0x10] = 8;  /* VTSS_UECL1_PWREVENT      0x00010000 */
	vtss_fmtcfg[0].defbit[0x11] = 8;  /* VTSS_UECL1_CPURECTSC     0x00020000 */
	vtss_fmtcfg[0].defbit[0x12] = 8;  /* VTSS_UECL1_REALRECTSC    0x00040000 */
	vtss_fmtcfg[0].defbit[0x13] = 81; /* VTSS_UECL1_PADDING       0x00080000 */
	vtss_fmtcfg[0].defbit[0x14] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[0].defbit[0x15] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[0].defbit[0x16] = 82; /* VTSS_UECL1_SYSTRACE      0x00400000 */
	vtss_fmtcfg[0].defbit[0x17] = 84; /* VTSS_UECL1_LARGETRACE    0x00800000 */
	vtss_fmtcfg[0].defbit[0x18] = 82; /* VTSS_UECL1_USERTRACE     0x01000000 */
	vtss_fmtcfg[0].defbit[0x19] = 0;
	vtss_fmtcfg[0].defbit[0x1a] = 0;
	vtss_fmtcfg[0].defbit[0x1b] = 0;
	vtss_fmtcfg[0].defbit[0x1c] = 0;
	vtss_fmtcfg[0].defbit[0x1d] = 0;
	vtss_fmtcfg[0].defbit[0x1e] = 0;
	vtss_fmtcfg[0].defbit[0x1f] = 0;

	/*
	 * Leaf 1: extended
	 */
	vtss_fmtcfg[1].rank = 1;
	vtss_fmtcfg[1].and_mask = VTSS_UEC_LEAF0 | VTSS_UEC_LEAF1 | VTSS_UEC_LEAF2 | VTSS_UEC_LEAF3;
	vtss_fmtcfg[1].cmp_mask = VTSS_UEC_LEAF1;
	vtss_fmtcfg[1].defcount = 0x20;

	vtss_fmtcfg[1].defbit[0x00] = 8;  /* VTSS_UECL1_EXT_CPUFREQ   0x00000001 */
	vtss_fmtcfg[1].defbit[0x01] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x02] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x03] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x04] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x05] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x06] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x07] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x08] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x09] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x0a] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x0b] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x0c] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x0d] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x0e] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x0f] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x10] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x11] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x12] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x13] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x14] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x15] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x16] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x17] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x18] = VTSS_FMTCFG_RESERVED;
	vtss_fmtcfg[1].defbit[0x19] = 0;
	vtss_fmtcfg[1].defbit[0x1a] = 0;
	vtss_fmtcfg[1].defbit[0x1b] = 0;
	vtss_fmtcfg[1].defbit[0x1c] = 0;
	vtss_fmtcfg[1].defbit[0x1d] = 0;
	vtss_fmtcfg[1].defbit[0x1e] = 0;
	vtss_fmtcfg[1].defbit[0x1f] = 0;
}

static void vtss_syscfg_append_field(const char *name)
{
	short len = strlen(name) + 1;
	char *buf = (char *)&vtss_syscfg + vtss_syscfg.record_size;

	if (len > VTSS_MAX_SYSCFG_FIELD_LEN)
		len = VTSS_MAX_SYSCFG_FIELD_LEN;

	*(short *)buf = len;
	buf += sizeof(short);
	memcpy(buf, name, len);
	buf[len - 1] = '\0';
	vtss_syscfg.record_size += sizeof(short) + len;
}

static void vtss_syscfg_init(void)
{
	struct new_utsname *uts = init_utsname();

	memset(&vtss_syscfg, 0, sizeof(vtss_syscfg_t));

	/* sysinfo */
	vtss_syscfg.version = 1;
	vtss_syscfg.major = (LINUX_VERSION_CODE >> 16) & 0xff;
	vtss_syscfg.minor = (LINUX_VERSION_CODE >> 8) & 0xff;
	vtss_syscfg.spack = 0;
	vtss_syscfg.extra = LINUX_VERSION_CODE & 0xff;
	vtss_syscfg.type  = VTSS_LINUX_EM64T;
	vtss_syscfg.record_size = offsetof(vtss_syscfg_t, placeholder);

	/* host name */
	vtss_syscfg_append_field(uts->nodename);

	/* platform brand name */
	vtss_syscfg_append_field(uts->sysname);

	/* system ID string */
	vtss_syscfg_append_field(uts->release);

	/* root directory */
	vtss_syscfg_append_field("/");

	vtss_pr_notice("Kernel version: %s", uts->release);
}

static void vtss_hardcfg_init(void)
{
	int cpu;
	unsigned int eax, ebx, ecx, edx;
	int nr_threads = 0;
	int max_cpu_id = 0;

	memset(&vtss_hardcfg, 0, sizeof(vtss_hardcfg_t));
	/* global variable vtss_time_source affects result of vtss_time_real() */
	vtss_time_source = VTSS_TIME_SOURCE_SYS;
	if (vtss_ktime_equal(KTIME_MONOTONIC_RES, KTIME_LOW_RES)) {
		vtss_pr_warning("SYS timer not accurate");
		vtss_time_source = VTSS_TIME_SOURCE_TSC;
	}
	/* should be after vtss_time_source setup */
	vtss_hardcfg.timer_freq = vtss_freq_real();
	vtss_hardcfg.cpu_freq   = vtss_freq_cpu();
	vtss_hardcfg.version = 2;
	/* for 32 bits it is like 0xc0000000         */
	/* for 64 bits it is like 0xffff880000000000 */
	/* the actual value will be set in vtss_transport_write_hardcfg() */
	vtss_hardcfg.maxusr_address = PAGE_OFFSET;
	/* initialize execution mode and OS version */
	vtss_hardcfg.mode     = 64;
	vtss_hardcfg.os_type  = VTSS_LINUX_EM64T;
	vtss_hardcfg.os_major = 0;
	vtss_hardcfg.os_minor = 0;
	vtss_hardcfg.os_sp    = 0;

	/* initialize CPU family and model */
	cpuid(VTSS_CPUID_VERSION, &eax, &ebx, &ecx, &edx);
	vtss_hardcfg.family = vtss_cpuid_cpu_family(eax);
	vtss_hardcfg.model = vtss_cpuid_cpu_display_model(eax);
	vtss_hardcfg.stepping = vtss_cpuid_cpu_stepping(eax);

	/* find out the number of CPUs */
	for_each_possible_cpu(cpu) {
		if (cpu_present(cpu)) {
			if (cpu > max_cpu_id)
				max_cpu_id = cpu;
		}
	}
	if (max_cpu_id + 1 > num_present_cpus())
		vtss_hardcfg.cpu_no = max_cpu_id + 1;
	else
		vtss_hardcfg.cpu_no = num_present_cpus();

	/* find out the number of threads */
	cpuid(VTSS_CPUID_CACHE, &eax, &ebx, &ecx, &edx);
	if (vtss_hardcfg.cpu_no == 1) {
		nr_threads = 1;
	} else {
		if (vtss_hardcfg.family == VTSS_CPU_FAM_P6)
			nr_threads = vtss_cpuid_cpu_max_thread_id(eax) + 1;
		nr_threads = nr_threads ? nr_threads : 1;
	}

	vtss_pr_notice("Detected %d CPU(s) and %d thread(s) per core",
		       vtss_hardcfg.cpu_no, nr_threads);
	vtss_pr_notice("CPU family: 0x%02x, model: 0x%02x, stepping: %d",
		       vtss_hardcfg.family, vtss_hardcfg.model, vtss_hardcfg.stepping);
	vtss_pr_notice("CPU freq: %lldKHz, timer freq: %lldKHz",
		       vtss_hardcfg.cpu_freq/1000, vtss_hardcfg.timer_freq/1000);

	/**
	 * Build CPU map: distribute the current thread to all CPUs
	 * to compute CPU IDs for asymmetric system configurations
	 */
	for (cpu = 0; cpu < vtss_hardcfg.cpu_no; cpu++) {
		struct cpuinfo_x86 *cpu_data_ptr = &cpu_data(cpu);
		vtss_hardcfg.cpus[cpu].node   = cpu_to_node(cpu);
		vtss_hardcfg.cpus[cpu].pack   = cpu_data_ptr->phys_proc_id;
		vtss_hardcfg.cpus[cpu].core   = cpu_data_ptr->cpu_core_id;
		vtss_hardcfg.cpus[cpu].thread = cpu_data_ptr->initial_apicid & (nr_threads - 1);
	}
}

static void vtss_cpuinfo_init_cb(void *ctx)
{
	int cpu = vtss_smp_processor_id();

	vtss_cpuinfo.cpus[cpu].leaf_no = 1;
	/* hybrid information leaf */
	vtss_cpuinfo.cpus[cpu].leafs[0].in_eax = VTSS_CPUID_HYBRID;
	vtss_cpuinfo.cpus[cpu].leafs[0].in_ecx = 0;
	cpuid(vtss_cpuinfo.cpus[cpu].leafs[0].in_eax,
	      &vtss_cpuinfo.cpus[cpu].leafs[0].out_eax,
	      &vtss_cpuinfo.cpus[cpu].leafs[0].out_ebx,
	      &vtss_cpuinfo.cpus[cpu].leafs[0].out_ecx,
	      &vtss_cpuinfo.cpus[cpu].leafs[0].out_edx);
}

static void vtss_cpuinfo_init(void)
{
	int cpu, nr_atom_cpus = 0, nr_core_cpus = 0, nr_unknown_cpus = 0;

	memset(&vtss_cpuinfo, 0, sizeof(vtss_cpuinfo_t));
	vtss_cpuinfo.version = 1;
	vtss_cpuinfo.cpu_no = vtss_nr_cpus();
	on_each_cpu(vtss_cpuinfo_init_cb, NULL, 1);

	for (cpu = 0; cpu < vtss_nr_cpus(); cpu++) {
		vtss_pr_debug_reqcfg("cpu%d: type=0x%x, node=%d, pack=%d, core=%d, thread=%d",
				     cpu, vtss_cpu_type(cpu), vtss_hardcfg.cpus[cpu].node,
				     vtss_hardcfg.cpus[cpu].pack, vtss_hardcfg.cpus[cpu].core,
				     vtss_hardcfg.cpus[cpu].thread);

		if (vtss_cpu_type(cpu) == VTSS_CPU_TYPE_ATOM)
			nr_atom_cpus++;
		else if (vtss_cpu_type(cpu) == VTSS_CPU_TYPE_CORE)
			nr_core_cpus++;
		else
			nr_unknown_cpus++;
	}
	if (!nr_unknown_cpus && nr_atom_cpus && nr_core_cpus) {
		vtss_pr_notice("CPU hybrid mode detected");
		vtss_cpu_hybrid_mode = true;
	}
}

static void vtss_iptcfg_init(void)
{
	unsigned long long info;
	unsigned int eax, ebx, ecx, edx;

	memset(&vtss_iptcfg, 0, sizeof(vtss_iptcfg));
	if (vtss_ipt_supported()) {
		vtss_iptcfg.version = 0;
		rdmsrl(VTSS_MSR_PLATFORM_INFO, info);
		vtss_iptcfg.fratio = vtss_platform_info_fratio(info);
		cpuid(VTSS_CPUID_TSC, &eax, &ebx, &ecx, &edx);
		vtss_iptcfg.ctcnom = ebx;
		vtss_iptcfg.tscdenom = eax;
		vtss_iptcfg.mtcfreq = 0;
	}
}

int vtss_reqcfg_init(void)
{
	memset(&vtss_reqcfg, 0, sizeof(struct vtss_reqcfg));
	return 0;
}

void vtss_reqcfg_fixup_flags(void)
{
#ifdef VTSS_DISABLE_STACKS
	vtss_reqcfg.trace_cfg.trace_flags &= ~VTSS_CFGTRACE_STACKS;
	vtss_pr_warning("Stack unwinding disabled");
#endif
	/* enable IPT on modern architectures if BTS is requested */
	if (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_BRANCH) {
		if (vtss_ipt_supported())
			vtss_reqcfg.trace_cfg.trace_flags |= VTSS_CFGTRACE_IPT;
		else
			vtss_pr_warning("IPT not supported");
	}
	if (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) {
		/* disable LBR and BTS if IPT is requested */
		vtss_reqcfg.trace_cfg.trace_flags &=
			~(VTSS_CFGTRACE_BRANCH | VTSS_CFGTRACE_LASTBR | VTSS_CFGTRACE_LBRSTK);
		if (vtss_reqcfg.ipt_cfg.mode & vtss_iptmode_full) {
			/* disable stacks if full IPT is requested */
			vtss_reqcfg.trace_cfg.trace_flags &= ~VTSS_CFGTRACE_STACKS;
		}
	}
	/* enable LASTBR if LBR stacks are requested */
	if (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_LBRSTK)
		vtss_reqcfg.trace_cfg.trace_flags |= VTSS_CFGTRACE_LASTBR;
}

static bool vtss_reqcfg_valid_event(cpuevent_cfg_v1_t *evcfg)
{
	char *name = (char *)evcfg + evcfg->name_off;

	if (evcfg->selmsr.idx != VTSS_IA32_FIXED_CTR_CTRL &&
	    (evcfg->selmsr.idx < VTSS_IA32_PERFEVTSEL0 ||
	     evcfg->selmsr.idx >= VTSS_IA32_PERFEVTSEL0 +
				  vtss_pmu_nr_gp_counters[evcfg->pmu_id])) {
		vtss_pr_warning("%s: Invalid CTRL MSR: 0x%x", name, evcfg->selmsr.idx);
		return false;
	}
	if (evcfg->selmsr.idx == VTSS_IA32_FIXED_CTR_CTRL) {
		if (evcfg->cntmsr.idx < VTSS_IA32_FIXED_CTR0 ||
		    evcfg->cntmsr.idx >= VTSS_IA32_FIXED_CTR0 +
					 vtss_pmu_nr_fx_counters[evcfg->pmu_id]) {
			vtss_pr_warning("%s: Invalid DATA MSR: 0x%x for fixed counter",
					name, evcfg->cntmsr.idx);
			return false;
		}
	} else {
		if (evcfg->cntmsr.idx < VTSS_IA32_PMC0 ||
		    evcfg->cntmsr.idx >= VTSS_IA32_PMC0 +
					 vtss_pmu_nr_gp_counters[evcfg->pmu_id]) {
			vtss_pr_warning("%s: Invalid DATA MSR: 0x%x for GP counter",
					name, evcfg->cntmsr.idx);
			return false;
		}
	}
	if (evcfg->extmsr.idx &&
	    (evcfg->extmsr.idx != VTSS_MSR_OFFCORE_RSP_0 &&
	     evcfg->extmsr.idx != VTSS_MSR_OFFCORE_RSP_1 &&
	     evcfg->extmsr.idx != VTSS_MSR_PEBS_LD_LAT   &&
	     evcfg->extmsr.idx != VTSS_MSR_PEBS_FRONTEND)) {
		vtss_pr_warning("%s: Invalid ESCR MSR: 0x%x", name, evcfg->extmsr.idx);
		return false;
	}
	return true;
}

#define vtss_reqcfg_pr_event(evcfg)\
	vtss_pr_debug_reqcfg("[%02d/%d] %s:%d:%x/%llx:%x/%llx:%x/%llx", \
			     (evcfg)->mux_grp, evcfg->pmu_id, \
			     (char *)(evcfg) + (evcfg)->name_off, (evcfg)->interval, \
			     (evcfg)->selmsr.idx, (evcfg)->selmsr.val, \
			     (evcfg)->cntmsr.idx, (evcfg)->cntmsr.val, \
			     (evcfg)->extmsr.idx, (evcfg)->extmsr.val);

static void vtss_reqcfg_fixup_hybrid_events(void)
{
	int core_max_group = -1;
	cpuevent_cfg_v1_t *evcfg;

	vtss_reqcfg_for_each_event(evcfg) {
		if (evcfg->pmu_id >= VTSS_PMU_SIZE) {
			vtss_pr_warning("%s: Invalid PMU index: %d",
					(char *)evcfg + evcfg->name_off, evcfg->pmu_id);
			continue;
		}
		if (evcfg->pmu_id == VTSS_PMU_CORE) {
			/* determine the max count of core groups */
			if (core_max_group < evcfg->mux_grp)
				core_max_group = evcfg->mux_grp;
		}
		/* determine the number of events */
		vtss_reqcfg.nr_events[evcfg->pmu_id]++;
	}
	/* setup offset for atom groups */
	vtss_reqcfg.group_offset[VTSS_PMU_ATOM] = core_max_group + 1;

	vtss_reqcfg_for_each_event(evcfg) {
		/* fixup group index */
		evcfg->mux_grp += vtss_reqcfg.group_offset[evcfg->pmu_id];
	}
	vtss_pr_debug_reqcfg("core: nr_events=%d, group_offset=%d",
			     vtss_reqcfg.nr_events[VTSS_PMU_CORE],
			     vtss_reqcfg.group_offset[VTSS_PMU_CORE]);
	vtss_pr_debug_reqcfg("atom: nr_events=%d, group_offset=%d",
			     vtss_reqcfg.nr_events[VTSS_PMU_ATOM],
			     vtss_reqcfg.group_offset[VTSS_PMU_ATOM]);
}

void vtss_reqcfg_print_events(void)
{
	cpuevent_cfg_v1_t *evcfg;

	vtss_reqcfg_for_each_event(evcfg)
		vtss_reqcfg_pr_event(evcfg);
}

void vtss_reqcfg_fixup_events(void)
{
	int counter;
	cpuevent_cfg_v1_t *evcfg;

	/* fixup hybrid configuration */
	vtss_reqcfg_fixup_hybrid_events();

	vtss_reqcfg_for_each_event(evcfg) {
		/* check for invalid values */
		if (!vtss_reqcfg_valid_event(evcfg)) {
			evcfg->interval = 0;
			evcfg->selmsr.idx = VTSS_IA32_PERFEVTSEL0;
			evcfg->selmsr.val = 0;
			evcfg->cntmsr.idx = VTSS_IA32_PMC0;
			evcfg->cntmsr.val = 0;
			evcfg->extmsr.idx = 0;
			evcfg->extmsr.val = 0;
		}
		/* fixup APEBS configuration */
		if (evcfg->selmsr.idx == VTSS_IA32_FIXED_CTR_CTRL) {
			for (counter = 0; counter < vtss_pmu_nr_fx_counters[evcfg->pmu_id]; counter++)
				if (((evcfg->selmsr.val >> (4*counter)) & VTSS_PMU_FIXED_CTRL_MASK) != 0)
					evcfg->selmsr.val |= VTSS_PMU_FIXED_CTRL_PMI << (4*counter); /* set PMI flag */
		} else {
			evcfg->selmsr.val &= VTSS_PMU_PERFEVTSEL_MASK; /* clear APEBS flags */
		}
		/* disable sampling in case of full PT tracing */
		if (vtss_reqcfg_ipt_mode_full()) {
			evcfg->interval = 0;
			evcfg->cntmsr.val = 0;
			if (evcfg->selmsr.idx == VTSS_IA32_FIXED_CTR_CTRL) {
				for (counter = 0; counter < vtss_pmu_nr_fx_counters[evcfg->pmu_id]; counter++)
					evcfg->selmsr.val &= ~(VTSS_PMU_FIXED_CTRL_PMI << (4*counter)); /* clear PMI flag */
			} else {
				evcfg->selmsr.val &= ~VTSS_PMU_PERFEVTSEL_INT; /* clear INT flag */
			}
		}
		/* correct sampling interval if not setup explicitly */
		if (evcfg->interval == 0 && evcfg->cntmsr.val != 0) {
			evcfg->interval = -(int)(evcfg->cntmsr.val | 0xffffffff00000000ULL);
			if (evcfg->interval < VTSS_PMU_CLK_THRESHOLD)
				evcfg->interval = VTSS_PMU_CLK_THRESHOLD*400;
		}
		vtss_reqcfg_pr_event(evcfg);
	}
}

static int vtss_reqcfg_append_event(int id, int selmsr, int cntmsr, char *name)
{
	int mux_grp, max_group = 0;
	cpuevent_cfg_v1_t *evcfg;

	/* find out the max count of MUX groups */
	vtss_reqcfg_for_each_event(evcfg) {
		if (max_group < evcfg->mux_grp)
			max_group = evcfg->mux_grp;
	}
	for (mux_grp = 0; mux_grp <= max_group; mux_grp++) {
		/* copy uncore event configuration */
		if (vtss_reqcfg.events_size + sizeof(cpuevent_cfg_v1_t) > VTSS_CFG_CHAIN_SPACE_SIZE) {
			vtss_pr_error("No room to copy uncore event configuration");
			return -ENOMEM;
		}
		evcfg = (cpuevent_cfg_v1_t *)(vtss_reqcfg.events_space + vtss_reqcfg.events_size);

		evcfg->event_id   = id + VTSS_CFG_CHAIN_SIZE;
		evcfg->mux_grp    = mux_grp;
		evcfg->selmsr.idx = selmsr;
		evcfg->cntmsr.idx = cntmsr;
		evcfg->name_off   = sizeof(cpuevent_cfg_v1_t);
		evcfg->name_len   = strlen(name) + 1;
		evcfg->desc_off   = sizeof(cpuevent_cfg_v1_t) + evcfg->name_len;
		evcfg->desc_len   = 0;
		evcfg->reqtype    = VTSS_CFGREQ_CPUEVENT_V1;
		evcfg->reqsize    = sizeof(cpuevent_cfg_v1_t) + evcfg->name_len + evcfg->desc_len;
		if (mux_grp < vtss_reqcfg.group_offset[VTSS_PMU_ATOM])
			evcfg->pmu_id = VTSS_PMU_CORE;
		else
			evcfg->pmu_id = VTSS_PMU_ATOM;
		vtss_reqcfg.events_size += sizeof(cpuevent_cfg_v1_t);
		/* copy uncore event name */
		if (vtss_reqcfg.events_size + evcfg->name_len > VTSS_CFG_CHAIN_SPACE_SIZE) {
			vtss_pr_error("No room to copy uncore event name");
			return -ENOMEM;
		}
		strcpy(vtss_reqcfg.events_space + vtss_reqcfg.events_size, name);
		vtss_reqcfg.events_size += evcfg->name_len;
		vtss_reqcfg.nr_events[evcfg->pmu_id]++;
		vtss_reqcfg_pr_event(evcfg);
	}
	return 0;
}

int vtss_reqcfg_append_events(void)
{
	int rc;

	if (vtss_reqcfg_pwridle_mode())
		vtss_pr_warning("Power idle events not supported");

	if (vtss_reqcfg_pwract_mode()) {
		rc = vtss_reqcfg_append_event(10, VTSS_UNC_ENERGY, VTSS_MSR_PP0_ENERGY_STATUS, "UNC_PP0_ENERGY_STATUS");
		if (rc) return rc;
		rc = vtss_reqcfg_append_event(11, VTSS_UNC_ENERGY, VTSS_MSR_PP1_ENERGY_STATUS, "UNC_PP1_ENERGY_STATUS");
		if (rc) return rc;
		rc = vtss_reqcfg_append_event(12, VTSS_UNC_ENERGY, VTSS_MSR_PKG_ENERGY_STATUS, "UNC_PKG_ENERGY_STATUS");
		if (rc) return rc;
		rc = vtss_reqcfg_append_event(13, VTSS_UNC_ENERGY, VTSS_MSR_DRAM_ENERGY_STATUS, "UNC_DRAM_ENERGY_STATUS");
		if (rc) return rc;
		vtss_pr_notice("Added power active events");
	}
	if (vtss_reqcfg_ehfi_mode()) {
		rc = vtss_reqcfg_append_event(15, VTSS_UNC_EHFI, VTSS_IA32_HW_FEEDBACK_CHAR, "UNC_IA32_HW_FEEDBACK_CHAR");
		if (rc) return rc;
		vtss_pr_notice("Added HW feedback char event");
	}
	return 0;
}

int vtss_reqcfg_verify(void)
{
	if (vtss_reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_BRANCH)
		return -EINVAL;
	return 0;
}

int vtss_modcfg_init(void)
{
	vtss_fmtcfg_init();
	vtss_syscfg_init();
	vtss_hardcfg_init();
	vtss_cpuinfo_init();
	vtss_iptcfg_init();
	vtss_reqcfg_init();
	return 0;
}
