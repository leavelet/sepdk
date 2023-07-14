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
#include "modcfg.h"
#include "pmu.h"
#include "record.h"
#include "stat.h"
#include "time.h"

int vtss_transport_write_debug(struct vtss_transport *trn, const char *fmt, ...)
{
	int rc;
	size_t len;
	char message[256];
	vtss_record_t rec;
	va_list args;

	va_start(args, fmt);
	rc = vsnprintf(message, 256, fmt, args);
	va_end(args);

	if (rc > 0) {
		len = strlen(message) + 1;
		rec.flagword = VTSS_UEC_LEAF1 | VTSS_UECL1_USERTRACE;
		rec.size     = sizeof(rec.size) + sizeof(rec.type) + len;
		rec.type     = VTSS_UECSYSTRACE_DEBUG;
		rc = vtss_transport_write_record(trn, &rec, sizeof(rec), message, len);
	}
	return rc;
}

int vtss_transport_write_process_exec(struct vtss_transport *trn, const char *name,
				      pid_t tid, pid_t pid, int cpu)
{
	int rc;
	size_t len = name ? strlen(name) + 1 : 0;
	vtss_process_record_t rec;

	vtss_pr_debug_record("%s: %s", trn->name, name);
	rec.flagword = VTSS_UEC_LEAF1      | VTSS_UECL1_ACTIVITY | VTSS_UECL1_CPUIDX  |
		       VTSS_UECL1_USRLVLID | VTSS_UECL1_CPUTSC   | VTSS_UECL1_REALTSC |
		       VTSS_UECL1_SYSTRACE;
	rec.activity = VTSS_UECACT_NEWTASK;
	rec.cpuidx   = cpu;
	rec.pid      = pid;
	rec.tid      = tid;
	vtss_time_get_sync(&rec.cputsc, &rec.realtsc);
	rec.size     = sizeof(rec.size) + sizeof(rec.type) + len;
	rec.type     = VTSS_UECSYSTRACE_PROCESS_NAME;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), name, len);
	if (rc) vtss_pr_warning("%s: Failed to write process exec record: %s", trn->name, name);
	return rc;
}

int vtss_transport_write_process_exit(struct vtss_transport *trn, const char *name,
				      pid_t tid, pid_t pid, int cpu)
{
	int rc;
	size_t len = name ? strlen(name) + 1 : 0;
	vtss_process_record_t rec;

	vtss_pr_debug_record("%s: %s", trn->name, name);
	rec.flagword = VTSS_UEC_LEAF1      | VTSS_UECL1_ACTIVITY | VTSS_UECL1_CPUIDX  |
		       VTSS_UECL1_USRLVLID | VTSS_UECL1_CPUTSC   | VTSS_UECL1_REALTSC |
		       VTSS_UECL1_SYSTRACE;
	rec.activity = VTSS_UECACT_OLDTASK;
	rec.cpuidx   = cpu;
	rec.pid      = pid;
	rec.tid      = tid;
	vtss_time_get_sync(&rec.cputsc, &rec.realtsc);
	rec.size     = sizeof(rec.size) + sizeof(rec.type) + len;
	rec.type     = VTSS_UECSYSTRACE_PROCESS_NAME;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), name, len);
	if (rc) vtss_pr_warning("%s: Failed to write process exit record: %s", trn->name, name);
	return rc;
}

int vtss_transport_write_thread_start(struct vtss_transport *trn, pid_t tid, pid_t pid, int cpu)
{
	int rc;
	vtss_thread_record_t rec;

	rec.flagword = VTSS_UEC_LEAF1    | VTSS_UECL1_ACTIVITY | VTSS_UECL1_VRESIDX |
		       VTSS_UECL1_CPUIDX | VTSS_UECL1_USRLVLID | VTSS_UECL1_CPUTSC  |
		       VTSS_UECL1_REALTSC;
	rec.activity = VTSS_UECACT_NEWTASK;
	rec.residx   = tid;
	rec.cpuidx   = cpu;
	rec.pid      = pid;
	rec.tid      = tid;
	vtss_time_get_sync(&rec.cputsc, &rec.realtsc);
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), NULL, 0);
	if (rc) vtss_pr_warning("%s: Failed to write thread start record", trn->name);
	return rc;
}

int vtss_transport_write_thread_stop(struct vtss_transport *trn, pid_t tid, pid_t pid, int cpu)
{
	int rc;
	vtss_thread_record_t rec;

	rec.flagword = VTSS_UEC_LEAF1    | VTSS_UECL1_ACTIVITY | VTSS_UECL1_VRESIDX |
		       VTSS_UECL1_CPUIDX | VTSS_UECL1_USRLVLID | VTSS_UECL1_CPUTSC  |
		       VTSS_UECL1_REALTSC;
	rec.activity = VTSS_UECACT_OLDTASK;
	rec.residx   = tid;
	rec.cpuidx   = cpu;
	rec.pid      = pid;
	rec.tid      = tid;
	vtss_time_get_sync(&rec.cputsc, &rec.realtsc);
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), NULL, 0);
	if (rc) vtss_pr_warning("%s: Failed to write thread stop record", trn->name);
	return rc;
}

int vtss_transport_write_thread_name(struct vtss_transport *trn, const char *name, pid_t tid)
{
	int rc;
	size_t len = name ? strlen(name) + 1 : 0;
	vtss_thread_name_record_t rec;

	vtss_pr_debug_record("%s: %s", trn->name, name);
	rec.probe.flagword  = VTSS_UEC_LEAF1    | VTSS_UECL1_ACTIVITY | VTSS_UECL1_VRESIDX |
		              VTSS_UECL1_CPUIDX | VTSS_UECL1_CPUTSC   | VTSS_UECL1_USERTRACE;
	rec.probe.activity  = VTSS_UECACT_PROBED;
	rec.probe.residx    = tid;
	rec.probe.cpuidx    = 0;
	rec.probe.cputsc    = vtss_time_real();
	rec.probe.size      = sizeof(rec) - offsetof(typeof(rec.probe), size) + len;
	rec.probe.type      = VTSS_URT_APIWRAP64_V1;
	rec.probe.entry_tsc = rec.probe.cputsc;
	rec.probe.entry_cpu = rec.probe.cpuidx;
	rec.probe.fid       = VTSS_FID_THREAD_NAME;
	rec.version         = 1;
	rec.length          = len;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), name, len);
	if (rc) vtss_pr_warning("%s: Failed to write thread name: %s", trn->name, name);
	return rc;
}

int vtss_transport_write_switch_from(struct vtss_transport *trn, int cpu, bool preempt)
{
	int rc;
	vtss_switch_from_record_t rec;

	rec.flagword = VTSS_UEC_LEAF1    | VTSS_UECL1_ACTIVITY | VTSS_UECL1_CPUIDX |
		       VTSS_UECL1_CPUTSC | VTSS_UECL1_REALTSC;
	rec.activity = (preempt ? 0 : VTSS_UECACT_SYNCHRO) | VTSS_UECACT_SWITCHFROM;
	rec.cpuidx   = cpu;
	vtss_time_get_sync(&rec.cputsc, &rec.realtsc);
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), NULL, 0);
	if (rc) vtss_stat_inc(&trn->lost.switches);
	return rc;
}

int vtss_transport_write_switch_to(struct vtss_transport *trn, pid_t tid, int cpu,
				   unsigned long ip)
{
	int rc;
	vtss_switch_to_record_t rec;

	rec.flagword = VTSS_UEC_LEAF1    | VTSS_UECL1_ACTIVITY | VTSS_UECL1_VRESIDX |
		       VTSS_UECL1_CPUIDX | VTSS_UECL1_CPUTSC   | VTSS_UECL1_REALTSC |
		       VTSS_UECL1_EXECADDR;
	rec.activity = VTSS_UECACT_SWITCHTO;
	rec.residx   = tid;
	rec.cpuidx   = cpu;
	vtss_time_get_sync(&rec.cputsc, &rec.realtsc);
	rec.execaddr = ip;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), NULL, 0);
	if (rc) vtss_stat_inc(&trn->lost.switches);
	return rc;
}

int vtss_transport_write_sample(struct vtss_transport *trn, pid_t tid, int cpu,
				struct vtss_pmu_events *events, unsigned long ip)
{
	int i, rc;
	unsigned long flags;
	struct vtss_pmu_event *event;
	unsigned long long samples[VTSS_MAX_SAMPLES + 1];
	int group = events->group_id + vtss_reqcfg.group_offset[events->pmu_id];

	if (!(events->nr_events > 0))
		return 0;

	i = 0;
	local_irq_save(flags);
	vtss_pmu_for_each_active_event(events, event) {
		samples[i++] = event->count;
		if (i >= VTSS_MAX_SAMPLES) {
			vtss_pr_warning("%s: Maximum number of active CPU events reached",
					trn->name);
			break;
		}
	}
	samples[i] = ip;
	if (ip) {
		vtss_sample_record_t rec;

		rec.flagword = VTSS_UEC_VECTORED   | VTSS_UEC_LEAF1      | VTSS_UECL1_ACTIVITY |
			       VTSS_UECL1_VRESIDX  | VTSS_UECL1_CPUIDX   | VTSS_UECL1_CPUTSC   |
			       VTSS_UECL1_MUXGROUP | VTSS_UECL1_CPUEVENT | VTSS_UECL1_EXECADDR;
		rec.vectored = VTSS_UECL1_CPUEVENT;
		rec.activity = VTSS_UECACT_SAMPLED;
		rec.residx   = tid;
		rec.cpuidx   = cpu;
		rec.cputsc   = vtss_time_cpu();
		rec.muxgroup = group;
		rec.event_no = i;
		rc = vtss_transport_write_record(trn, &rec, sizeof(rec), samples,
						 (i + 1)*sizeof(unsigned long long));
	} else {
		vtss_cpuevent_record_t rec;

		rec.flagword = VTSS_UEC_VECTORED | VTSS_UEC_LEAF1    | VTSS_UECL1_VRESIDX  |
			       VTSS_UECL1_CPUIDX | VTSS_UECL1_CPUTSC | VTSS_UECL1_MUXGROUP |
			       VTSS_UECL1_CPUEVENT;
		rec.vectored = VTSS_UECL1_CPUEVENT;
		rec.residx   = tid;
		rec.cpuidx   = cpu;
		rec.cputsc   = vtss_time_cpu();
		rec.muxgroup = group;
		rec.event_no = i;
		rc = vtss_transport_write_record(trn, &rec, sizeof(rec), samples,
						 i*sizeof(unsigned long long));
	}
	local_irq_restore(flags);
	if (rc) vtss_stat_inc(&trn->lost.samples);
	return rc;
}

int vtss_transport_write_module(struct vtss_transport *trn, const char *name, bool m32,
				unsigned long start, unsigned long end, unsigned long pgoff,
				unsigned long long cputsc, unsigned long long realtsc)
{
	int rc;

	vtss_pr_debug_mmap("%s: mmap%s: [0x%lx-0x%lx] %s", trn->name,
			   m32 ? "32" : "64", start, end, name);

	if (m32) {
		vtss_module32_record_t rec;

		rec.flagword = VTSS_UEC_LEAF1     | VTSS_UECL1_USRLVLID | VTSS_UECL1_CPUTSC |
			       VTSS_UECL1_REALTSC | VTSS_UECL1_SYSTRACE;
		rec.type     = VTSS_UECSYSTRACE_MODULE_MAP32;
		rec.pid      = 0;
		rec.tid      = 0;
		rec.cputsc   = cputsc;
		rec.realtsc  = realtsc;
		rec.start    = start;
		rec.end      = end;
		rec.offset   = pgoff << PAGE_SHIFT;
		rec.bin      = VTSS_MODTYPE_ELF;
		rec.len      = strlen(name) + 1;
		rec.size     = sizeof(rec) - offsetof(typeof(rec), size) + rec.len;
		rc = vtss_transport_write_record(trn, &rec, sizeof(rec), name, rec.len);
	} else {
		vtss_module64_record_t rec;

		rec.flagword = VTSS_UEC_LEAF1     | VTSS_UECL1_USRLVLID | VTSS_UECL1_CPUTSC |
			       VTSS_UECL1_REALTSC | VTSS_UECL1_SYSTRACE;
		rec.type     = VTSS_UECSYSTRACE_MODULE_MAP64;
		rec.pid      = 0;
		rec.tid      = 0;
		rec.cputsc   = cputsc;
		rec.realtsc  = realtsc;
		rec.start    = start;
		rec.end      = end;
		rec.offset   = pgoff << PAGE_SHIFT;
		rec.bin      = VTSS_MODTYPE_ELF;
		rec.len      = strlen(name) + 1;
		rec.size     = sizeof(rec) - offsetof(typeof(rec), size) + rec.len;
		rc = vtss_transport_write_record(trn, &rec, sizeof(rec), name, rec.len);
	}
	if (rc) {
		vtss_pr_warning("%s: Failed to write mmap%s: [0x%lx-0x%lx]: %s",
				trn->name, m32 ? "32" : "64", start, end, name);
		vtss_stat_inc(&trn->lost.modules);
	}
	return rc;
}

static int vtss_transport_write_fmtcfg(struct vtss_transport *trn)
{
	int rc;
	vtss_record_t rec;

	/* generate forward compatibility format record */
	/* [flagword][systrace(fmtcfg)] */
	rec.flagword = VTSS_UEC_LEAF1 | VTSS_UECL1_SYSTRACE;
	rec.size     = sizeof(rec.size) + sizeof(rec.type) + sizeof(vtss_fmtcfg);
	rec.type     = VTSS_UECSYSTRACE_FMTCFG;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), vtss_fmtcfg, sizeof(vtss_fmtcfg));
	if (rc) vtss_pr_warning("%s: Failed to write forward compatibility format", trn->name);
	return rc;
}

static int vtss_transport_write_colcfg(struct vtss_transport *trn)
{
	int rc;
	static const char name[] = "vtsspp-"VTSS_VERSION_STRING;
	vtss_colcfg_record_t rec;

	/* generate collector configuration record */
	/* [flagword][systrace(colcfg)] */
	rec.flagword = VTSS_UEC_LEAF1 | VTSS_UECL1_SYSTRACE;
	rec.size     = sizeof(rec) - offsetof(typeof(rec), size) + sizeof(name);
	rec.type     = VTSS_UECSYSTRACE_COLCFG;

	rec.version  = 1;
	rec.major    = VTSS_VERSION_MAJOR;
	rec.minor    = VTSS_VERSION_MINOR;
	rec.revision = VTSS_VERSION_REVISION;
	rec.features = VTSS_CFGTRACE_CPUEV   | VTSS_CFGTRACE_SWCFG   | VTSS_CFGTRACE_HWCFG  |
		       VTSS_CFGTRACE_SAMPLE  | VTSS_CFGTRACE_TP      | VTSS_CFGTRACE_MODULE |
		       VTSS_CFGTRACE_PROCTHR | VTSS_CFGTRACE_BRANCH  | VTSS_CFGTRACE_EXECTX |
		       VTSS_CFGTRACE_TBS     | VTSS_CFGTRACE_LASTBR  | VTSS_CFGTRACE_TREE   |
		       VTSS_CFGTRACE_SYNCARG;
	rec.features |= vtss_reqcfg.trace_cfg.trace_flags;
	rec.len = sizeof(name);
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), name, sizeof(name));
	if (rc) vtss_pr_warning("%s: Failed to write collector configuration", trn->name);
	return rc;
}

static int vtss_transport_write_syscfg(struct vtss_transport *trn)
{
	int rc;
	unsigned short size;
	vtss_record_t rec;

	size = vtss_syscfg.record_size;
	/* generate system configuration record */
	/* [flagword][systrace(sysinfo)] */
	rec.flagword = VTSS_UEC_LEAF1 | VTSS_UECL1_SYSTRACE;
	rec.size     = sizeof(rec.size) + sizeof(rec.type) + size;
	rec.type     = VTSS_UECSYSTRACE_SYSINFO;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), &vtss_syscfg, size);
	if (rc) vtss_pr_warning("%s: Failed to write system configuration", trn->name);
	return rc;
}

static int vtss_transport_write_hardcfg(struct vtss_transport *trn, int m32)
{
	int rc;
	unsigned short size;
	vtss_record_t rec;

	size = sizeof(vtss_hardcfg) - (NR_CPUS - vtss_hardcfg.cpu_no)*sizeof(vtss_hardcfg.cpus[0]);
	/* generate hardware configuration record */
	/* [flagword][systrace(hwcfg)] */
	rec.flagword = VTSS_UEC_LEAF1 | VTSS_UECL1_SYSTRACE;
	rec.size     = sizeof(rec.size) + sizeof(rec.type) + size;
	rec.type     = VTSS_UECSYSTRACE_HWCFG;
	/* fixup max user address */
	vtss_hardcfg.maxusr_address = m32 ? IA32_PAGE_OFFSET : PAGE_OFFSET;
	/* update real timer freq */
	vtss_hardcfg.timer_freq = vtss_freq_real();
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), &vtss_hardcfg, size);
	if (rc) vtss_pr_warning("%s: Failed to write hardware configuration", trn->name);
	return rc;
}

static int vtss_transport_write_cpuinfo(struct vtss_transport *trn)
{
	int rc;
	unsigned int size;
	vtss_record_t rec;

	size = sizeof(vtss_cpuinfo) - (NR_CPUS - vtss_cpuinfo.cpu_no)*sizeof(vtss_cpuinfo.cpus[0]);
	/* generate cpuinfo record */
	/* [flagword][systrace(cpuinfo)] */
	rec.flagword = VTSS_UEC_LEAF1 | VTSS_UECL1_SYSTRACE;
	rec.size     = sizeof(rec.size) + sizeof(rec.type) + size;
	rec.type     = VTSS_UECSYSTRACE_CPUINFO;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), &vtss_cpuinfo, size);
	if (rc) vtss_pr_warning("%s: Failed to write cpuinfo record", trn->name);
	return rc;
}

static int vtss_transport_write_iptcfg(struct vtss_transport *trn)
{
	int rc;
	vtss_record_t rec;

	/* generate IPT configuration record */
	/* [flagword][systrace(iptcfg)] */
	rec.flagword = VTSS_UEC_LEAF1 | VTSS_UECL1_USERTRACE;
	rec.size     = sizeof(rec.size) + sizeof(rec.type) + sizeof(vtss_iptcfg);
	rec.type     = VTSS_UECSYSTRACE_IPTCFG;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), &vtss_iptcfg, sizeof(vtss_iptcfg));
	if (rc) vtss_pr_warning("%s: Failed to write IPT configuration", trn->name);
	return rc;
}

static int vtss_transport_write_time_marker(struct vtss_transport *trn)
{
	int rc;
	struct vtss_timespec now;
	vtss_time_marker_record_t rec;

	/* generate time marker record */
	rec.flagword = VTSS_UEC_LEAF1 | VTSS_UEC_VECTORED | VTSS_UECL1_REALTSC;
	rec.vectored = VTSS_UECL1_REALTSC;
	rec.vec_no   = 2;
	rec.tsc      = vtss_time_real();
	vtss_time_get_real_ts(&now);
	/* convert global time to 100ns units */
	rec.utc      = vtss_time_ts_to_ns(&now)/100ULL;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), NULL, 0);
	if (rc) vtss_pr_warning("%s: Failed to write time marker", trn->name);
	return rc;
}

int vtss_transport_write_configs(struct vtss_transport *trn, int m32)
{
	int rc = 0;

	rc |= vtss_transport_write_fmtcfg(trn);
	rc |= vtss_transport_write_colcfg(trn);
	rc |= vtss_transport_write_syscfg(trn);
	rc |= vtss_transport_write_cpuinfo(trn);
	rc |= vtss_transport_write_hardcfg(trn, m32);
	rc |= vtss_transport_write_iptcfg(trn);
	rc |= vtss_transport_write_time_marker(trn);
	return rc;
}

int vtss_transport_write_softcfg(struct vtss_transport *trn, pid_t tid)
{
	int rc;
	vtss_softcfg_record_t rec;

	/* generate software configuration record */
	/* [flagword][systrace(swcfg)] */
	rec.flagword = VTSS_UEC_LEAF1 | VTSS_UECL1_VRESIDX | VTSS_UECL1_SYSTRACE;
	rec.vresidx  = tid;
	rec.size     = sizeof(rec) - offsetof(typeof(rec), size) + vtss_reqcfg.events_size;
	rec.type     = VTSS_UECSYSTRACE_SWCFG;
	rec.version  = 2;
	rec.cpu_chain_len = vtss_reqcfg.nr_events[VTSS_PMU_CORE] +
			    vtss_reqcfg.nr_events[VTSS_PMU_ATOM];
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), vtss_reqcfg.events_space,
					 vtss_reqcfg.events_size);
	if (rc) vtss_pr_warning("%s: Failed to write software configuration", trn->name);
	return rc;
}

int vtss_transport_write_probe(struct vtss_transport *trn, int cpu, int fid)
{
	int rc;
	vtss_probe_record_t rec;

	vtss_pr_debug_record("%s: fid=0x%x", trn->name, fid);
	rec.flagword  = VTSS_UEC_LEAF1    | VTSS_UECL1_ACTIVITY | VTSS_UECL1_VRESIDX |
		        VTSS_UECL1_CPUIDX | VTSS_UECL1_CPUTSC   | VTSS_UECL1_USERTRACE;
	rec.activity  = VTSS_UECACT_PROBED;
	/* it's a global probe and TID isn't important here */
	rec.residx    = 0;
	rec.cpuidx    = cpu;
	/* it's real TSC to be consistent with TPSS */
	rec.cputsc    = vtss_time_real();
	rec.size      = sizeof(rec) - offsetof(typeof(rec), size);
	/* arch isn't important here but make it as native arch */
	rec.type      = VTSS_URT_APIWRAP64_V1;
	rec.entry_tsc = rec.cputsc;
	rec.entry_cpu = rec.cpuidx;
	rec.fid       = fid;
	rc = vtss_transport_write_record(trn, &rec, sizeof(rec), NULL, 0);
	if (rc) vtss_pr_warning("%s: Failed to write probe record: 0x%x", trn->name, fid);
	return rc;
}

int vtss_transport_write_probe_all(int cpu, int fid)
{
	int rc;
	vtss_probe_record_t rec;

	vtss_pr_debug_record("fid=0x%x", fid);
	rec.flagword  = VTSS_UEC_LEAF1    | VTSS_UECL1_ACTIVITY | VTSS_UECL1_VRESIDX |
		        VTSS_UECL1_CPUIDX | VTSS_UECL1_CPUTSC   | VTSS_UECL1_USERTRACE;
	rec.activity  = VTSS_UECACT_PROBED;
	/* it's a global probe and TID isn't important here */
	rec.residx    = 0;
	rec.cpuidx    = cpu;
	/* it's real TSC to be consistent with TPSS */
	rec.cputsc    = vtss_time_real();
	rec.size      = sizeof(rec) - offsetof(typeof(rec), size);
	/* arch isn't important here but make it as native arch */
	rec.type      = VTSS_URT_APIWRAP64_V1;
	rec.entry_tsc = rec.cputsc;
	rec.entry_cpu = rec.cpuidx;
	rec.fid       = fid;
	rc = vtss_transport_write_record_all(&rec, sizeof(rec), NULL, 0);
	if (rc) vtss_pr_warning("Failed to write probe all record: 0x%x", fid);
	return rc;
}
