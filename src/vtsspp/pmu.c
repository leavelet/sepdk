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
#include "modcfg.h"
#include "pcb.h"
#include "pmi.h"
#include "pmu.h"
#include "regs.h"
#include "time.h"

#include <asm/nmi.h>	/* for register_nmi_handler */
#include <asm/apic.h>	/* for apic_write           */

#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

int vtss_pmu_version = 0;
int vtss_pmu_nr_fx_counters[VTSS_PMU_SIZE] = {0, 0};
int vtss_pmu_nr_gp_counters[VTSS_PMU_SIZE] = {0, 0};
static int vtss_pmu_fx_counter_width = 0;
static int vtss_pmu_gp_counter_width = 0;
#define vtss_pmu_fx_counter_mask ((1ULL << vtss_pmu_fx_counter_width) - 1)
#define vtss_pmu_gp_counter_mask ((1ULL << vtss_pmu_gp_counter_width) - 1)

static atomic_t vtss_pmu_active = ATOMIC_INIT(0);
#define vtss_pmu_active() (atomic_read(&vtss_pmu_active) == 1)
#define vtss_pmu_set_active() atomic_set(&vtss_pmu_active, 1)
#define vtss_pmu_set_inactive() (atomic_cmpxchg(&vtss_pmu_active, 1, 0) == 1)

static void vtss_pmu_save_cb(void *ctx)
{
	unsigned long flags;

	local_irq_save(flags);
	rdmsrl(VTSS_IA32_PERF_GLOBAL_OVF_CTRL, vtss_pcb_cpu.msr_ovf);
	rdmsrl(VTSS_IA32_PERF_GLOBAL_CTRL,     vtss_pcb_cpu.msr_ctrl);
	rdmsrl(VTSS_IA32_DEBUGCTL,             vtss_pcb_cpu.msr_debug);
	vtss_pcb_cpu.apic_lvtpc = apic_read(APIC_LVTPC);
	local_irq_restore(flags);
}

static void vtss_pmu_restore_cb(void *ctx)
{
	unsigned long flags;

	local_irq_save(flags);
	wrmsrl(VTSS_IA32_PERF_GLOBAL_OVF_CTRL, vtss_pcb_cpu.msr_ovf);
	wrmsrl(VTSS_IA32_PERF_GLOBAL_CTRL,     vtss_pcb_cpu.msr_ctrl);
	wrmsrl(VTSS_IA32_DEBUGCTL,             vtss_pcb_cpu.msr_debug);
	apic_write(APIC_LVTPC, vtss_pcb_cpu.apic_lvtpc);
	local_irq_restore(flags);
}

static void vtss_pmu_start_cb(void *ctx)
{
	unsigned long flags;

	local_irq_save(flags);
	wrmsrl(VTSS_IA32_PERF_GLOBAL_OVF_CTRL, 0);
	wrmsrl(VTSS_IA32_PERF_GLOBAL_CTRL,     0);
	wrmsrl(VTSS_IA32_DEBUGCTL,             0);
	apic_write(APIC_LVTPC, APIC_DM_NMI);
	local_irq_restore(flags);
}

static void vtss_pmu_stop_cb(void *ctx)
{
	int i;
	int cpu = vtss_smp_processor_id();
	int pmu_id = vtss_pmu_id(cpu);
	unsigned long flags;

	local_irq_save(flags);
	for (i = 0; i < vtss_pmu_nr_gp_counters[pmu_id]; i++) {
		wrmsrl(VTSS_IA32_PERFEVTSEL0 + i, 0);
		wrmsrl(VTSS_IA32_PMC0        + i, 0);
	}
	wrmsrl(VTSS_IA32_FIXED_CTR_CTRL,       0);
	wrmsrl(VTSS_IA32_PERF_GLOBAL_OVF_CTRL, 0);
	wrmsrl(VTSS_IA32_PERF_GLOBAL_CTRL,     0);
	wrmsrl(VTSS_IA32_DEBUGCTL,             0);
	local_irq_restore(flags);
}

static int vtss_nmi_handler(unsigned int cmd, struct pt_regs *regs)
{
	if (vtss_collector_stopped()) {
		vtss_pr_warning("Unexpected NMI");
		return NMI_DONE;
	}
	/* handle PMI */
	vtss_pmi_handler(regs);
	/* unmask NMI (late ack) */
	apic_write(APIC_LVTPC, APIC_DM_NMI);
	return NMI_HANDLED;
}

int vtss_nmi_init(void)
{
	if (!(vtss_pmu_nr_fx_counters[VTSS_PMU_CORE] > 0 &&
	      vtss_pmu_nr_gp_counters[VTSS_PMU_CORE] > 0)) {
		vtss_pr_error("PMU counters not detected");
		return -EINVAL;
	}
	if (vtss_reqcfg.nr_events[VTSS_PMU_CORE] > 0)
		vtss_pr_notice("PMU: uploading %d core events",
			       vtss_reqcfg.nr_events[VTSS_PMU_CORE]);
	if (vtss_reqcfg.nr_events[VTSS_PMU_ATOM] > 0)
		vtss_pr_notice("PMU: uploading %d atom events",
			       vtss_reqcfg.nr_events[VTSS_PMU_ATOM]);

	if (!(vtss_reqcfg.nr_events[VTSS_PMU_CORE] > 0 ||
	      vtss_reqcfg.nr_events[VTSS_PMU_ATOM] > 0)) {
		vtss_pr_error("Invalid CPU events configuration");
		return -EINVAL;
	}
	on_each_cpu(vtss_pmu_save_cb, NULL, 1);
	on_each_cpu(vtss_pmu_start_cb, NULL, 1);
	register_nmi_handler(NMI_LOCAL, vtss_nmi_handler, 0, "vtsspp_pmi");
	vtss_pr_notice("Registered NMI handler");
	vtss_pmu_set_active();
	return 0;
}

void vtss_nmi_cleanup(void)
{
	if (!vtss_pmu_set_inactive())
		return;
	on_each_cpu(vtss_pmu_stop_cb, NULL, 1);
	on_each_cpu(vtss_pmu_restore_cb, NULL, 1);
	unregister_nmi_handler(NMI_LOCAL, "vtsspp_pmi");
}

int vtss_pmu_init(void)
{
	unsigned int eax, ebx, ecx, edx;
	int nr_fx_counters, nr_gp_counters;

	if (vtss_hardcfg.family == VTSS_CPU_FAM_P6) {

		cpuid(VTSS_CPUID_PMU, &eax, &ebx, &ecx, &edx);

		vtss_pmu_version = vtss_cpuid_pmu_version(eax);
		nr_fx_counters = vtss_cpuid_pmu_nr_fx_counters(edx);
		nr_gp_counters = vtss_cpuid_pmu_nr_gp_counters(eax);

		if (vtss_cpu_hybrid_mode) {
			/* in hybrid mode cpuid reports atom config */
			if (nr_fx_counters)
				vtss_pmu_nr_fx_counters[VTSS_PMU_CORE] = VTSS_PMU_V5_NR_FX_COUNTERS;
			if (nr_gp_counters)
				vtss_pmu_nr_gp_counters[VTSS_PMU_CORE] = VTSS_PMU_V5_NR_GP_COUNTERS;
			vtss_pmu_nr_fx_counters[VTSS_PMU_ATOM] = nr_fx_counters;
			vtss_pmu_nr_gp_counters[VTSS_PMU_ATOM] = nr_gp_counters;
		} else {
			vtss_pmu_nr_fx_counters[VTSS_PMU_CORE] = nr_fx_counters;
			vtss_pmu_nr_gp_counters[VTSS_PMU_CORE] = nr_gp_counters;
		}
		vtss_pmu_fx_counter_width = vtss_cpuid_pmu_fx_counter_width(edx);
		vtss_pmu_gp_counter_width = vtss_cpuid_pmu_gp_counter_width(eax);
	}

	vtss_pr_notice("PERFMONv%d: fixed events: %d, generic counters: %d",
		       vtss_pmu_version,
		       vtss_pmu_nr_fx_counters[VTSS_PMU_CORE],
		       vtss_pmu_nr_gp_counters[VTSS_PMU_CORE]);

	if (vtss_cpu_hybrid_mode)
		vtss_pr_notice("PERFMONv%d: fixed events: %d, generic counters: %d",
			       vtss_pmu_version,
			       vtss_pmu_nr_fx_counters[VTSS_PMU_ATOM],
			       vtss_pmu_nr_gp_counters[VTSS_PMU_ATOM]);

	vtss_pr_debug_pmu("fixed counter width: %d", vtss_pmu_fx_counter_width);
	vtss_pr_debug_pmu("generic counter width: %d", vtss_pmu_gp_counter_width);

	return 0;
}

void vtss_pmu_enable(void)
{
	unsigned long long mask;
	int cpu = vtss_smp_processor_id();
	int pmu_id = vtss_pmu_id(cpu);

	if (!vtss_pmu_active())
		return;

	/* enable counters globally */
	mask = vtss_pmu_counters_mask(pmu_id, true, true);
	wrmsrl(VTSS_IA32_PERF_GLOBAL_CTRL, mask);
	/* clear global overflow status */
	mask |= (VTSS_PMU_GLOBAL_OVF_DSA | VTSS_PMU_GLOBAL_COND_CHGD);
	wrmsrl(VTSS_IA32_PERF_GLOBAL_OVF_CTRL, mask);
}

void vtss_pmu_disable(void)
{
	int i;
	int cpu = vtss_smp_processor_id();
	int pmu_id = vtss_pmu_id(cpu);

	/* freeze counters */
	for (i = 0; i < vtss_pmu_nr_gp_counters[pmu_id]; i++)
		wrmsrl(VTSS_IA32_PERFEVTSEL0 + i, 0);
	wrmsrl(VTSS_IA32_FIXED_CTR_CTRL, 0);
}

static void vtss_pmu_event_core_restart(struct vtss_pmu_event *event)
{
	int counter;
	long long interval = event->frozen_count;
	unsigned long long ctrl, mask;

	if (event->interval == 0 && event->aux_interval == 0) { /* no sampling */
		/* wrap the counters around */
		event->frozen_count &= VTSS_PMU_CNT_THRESHOLD - 1;
		interval = -event->frozen_count;
	} else {
		if (interval >= event->aux_interval) { /* overflowed */
			/* use the programmed interval */
			event->frozen_count = interval = event->interval;
		} else { /* underflowed */
			/* use the residual count */
			event->frozen_count = interval = -interval;
			if (event->aux_interval)
				event->frozen_count = -interval;
		}
	}
	/* ensure we do not count backwards */
	if (interval > event->interval)
		interval = event->interval;
	/* set up counters */
	if (vtss_pmu_event_fixed(event)) {
		/* set up the counter */
		wrmsrl(event->cntmsr, -interval & vtss_pmu_fx_counter_mask);
		/* set up the control register */
		rdmsrl(event->selmsr, ctrl);
		counter = event->cntmsr - VTSS_IA32_FIXED_CTR0;
		mask = event->selmsk & (VTSS_PMU_FIXED_CTRL_MASK << (4*counter));
		wrmsrl(event->selmsr, ctrl | mask);
	} else {
		/* set up the counter */
		wrmsrl(event->cntmsr, -interval & vtss_pmu_gp_counter_mask);
		/* set up the control register */
		wrmsrl(event->selmsr, event->selmsk);
	}
	if (event->extmsr)
		wrmsrl(event->extmsr, event->extmsk);
}

static void vtss_pmu_event_core_sample(struct vtss_pmu_event *event)
{
	long long interval = (event->frozen_count > 0) ? event->frozen_count : event->interval;
	int fx_counter_shift = 64 - vtss_pmu_fx_counter_width;
	int gp_counter_shift = 64 - vtss_pmu_gp_counter_width;
	/* check only fixed counters overflow */
	unsigned long long mask = vtss_pmu_counters_mask(event->pmu_id, true, false);
	unsigned long long ovf;

	rdmsrl(VTSS_IA32_PERF_GLOBAL_STATUS, ovf);
	ovf &= mask;

	wrmsrl(event->selmsr, 0);
	rdmsrl(event->cntmsr, event->frozen_count);

	/* convert the count to 64 bits */
	if (vtss_pmu_event_fixed(event))
		event->frozen_count = (event->frozen_count << fx_counter_shift) >> fx_counter_shift;
	else
		event->frozen_count = (event->frozen_count << gp_counter_shift) >> gp_counter_shift;

	/* ensure we do not count backwards */
	if (event->frozen_count < -interval) {
		event->frozen_count = -event->interval;
		interval = event->interval;
	}
	if (event->interval == 0) {  /* no sampling */
		if (event->frozen_count < interval) {  /* HW and VM sanity check */
			interval = event->frozen_count;
		}
		event->sampled_count += event->frozen_count - interval;
	} else {
		/* update the accrued count by adding the signed
		 * values of current count and sampling interval */
		event->sampled_count += interval + event->frozen_count;
	}
	/* separately preserve counts of overflowed counters, and always save fixed
	 * counters (to show performance impact of synchronization on call tree) */
	if ((event->frozen_count >= 0 && event->frozen_count >= event->aux_interval) ||
	    (vtss_pmu_event_fixed(event) && ovf))
		event->count = event->sampled_count;
}

static bool vtss_pmu_event_core_overflowed(struct vtss_pmu_event *event)
{
	if (event->frozen_count >= 0) {
		/* always signal overflow for no sampling
		 * mode and in case of real overflow */
		return true;
	}
	return false;
}

static void vtss_pmu_event_energy_restart(struct vtss_pmu_event *event)
{
	rdmsrl(event->cntmsr, event->frozen_count);
	event->frozen_count &= 0xffffffffLL;
}

static void vtss_pmu_event_energy_sample(struct vtss_pmu_event *event)
{
	long long count;

	rdmsrl(event->cntmsr, count);
	count &= 0xffffffffLL;
	if (count < event->frozen_count)
		count += 0x100000000LL;
	event->count += (count - event->frozen_count) << 4;
}

static bool vtss_pmu_event_energy_overflowed(struct vtss_pmu_event *event)
{
	return false;
}

static void vtss_pmu_event_ehfi_restart(struct vtss_pmu_event *event)
{
	return;
}

static void vtss_pmu_event_ehfi_sample(struct vtss_pmu_event *event)
{
	rdmsrl(event->cntmsr, event->count);
}

static bool vtss_pmu_event_ehfi_overflowed(struct vtss_pmu_event *event)
{
	return false;
}

/* called from vtss_target_attach() to form a common
 * event chain from the configuration records */
void vtss_pmu_events_init(struct vtss_pmu_events *events, int pmu_id)
{
	int max_group = -1;
	cpuevent_cfg_v1_t *evcfg;
	struct vtss_pmu_event *event;

	events->pmu_id = pmu_id;
	if (!(vtss_reqcfg.nr_events[pmu_id] > 0))
		return;

	vtss_reqcfg_for_each_event(evcfg) {
		if (evcfg->pmu_id != pmu_id)
			continue;
		event = events->evbuf + events->nr_events;
		event->name = (char *)evcfg + evcfg->name_off;
		if (evcfg->event_id >= VTSS_CFG_CHAIN_SIZE) {
			/* copy uncore events parameters */
			event->selmsr = evcfg->selmsr.idx;
			event->cntmsr = evcfg->cntmsr.idx;
			if (event->selmsr == VTSS_UNC_ENERGY) {
				/* setup energy events interface */
				event->restart = vtss_pmu_event_energy_restart;
				event->sample = vtss_pmu_event_energy_sample;
				event->overflowed = vtss_pmu_event_energy_overflowed;
			} else if (event->selmsr == VTSS_UNC_EHFI) {
				/* setup EHFI events interface */
				event->restart = vtss_pmu_event_ehfi_restart;
				event->sample = vtss_pmu_event_ehfi_sample;
				event->overflowed = vtss_pmu_event_ehfi_overflowed;
			}
		} else {
			/* copy core events parameters */
			event->interval = evcfg->interval;
			event->selmsr = evcfg->selmsr.idx;
			event->selmsk = evcfg->selmsr.val;
			event->cntmsr = evcfg->cntmsr.idx;
			event->cntmsk = evcfg->cntmsr.val;
			event->extmsr = evcfg->extmsr.idx;
			event->extmsk = evcfg->extmsr.val;
			/* setup core events interface */
			event->restart = vtss_pmu_event_core_restart;
			event->sample = vtss_pmu_event_core_sample;
			event->overflowed = vtss_pmu_event_core_overflowed;
			/* setup fixed events as followers of the leading event */
			if (vtss_pmu_event_fixed(event)) {
				if (event->cntmsr != VTSS_IA32_FIXED_CTR0 + 2 &&
				    vtss_pmu_nr_fx_counters[pmu_id] > 2) {
					event->aux_interval = event->interval;
					event->interval = 0;
				}
			}
		}
		/* copy MUX parameters */
		event->group_id = evcfg->mux_grp - vtss_reqcfg.group_offset[pmu_id];
		event->mux_alg = evcfg->mux_alg;
		event->mux_arg = evcfg->mux_arg;
		event->pmu_id = pmu_id;

		/* find out the max count of MUX groups */
		if (max_group < event->group_id)
			max_group = event->group_id;

		vtss_pr_debug_pmu("[%02d/%d] %s: si=%lld, sel=%x/%llx, cnt=%x/%llx",
				  event->group_id, event->pmu_id, event->name, event->interval,
				  event->selmsr, event->selmsk, event->cntmsr, event->cntmsk);

		events->nr_events++;
	}
	if (events->nr_events != vtss_reqcfg.nr_events[pmu_id])
		vtss_pr_warning("PMU%d: uploaded %d events instead of %d", pmu_id,
				events->nr_events, vtss_reqcfg.nr_events[pmu_id]);
	/* setup PMU events parameters */
	events->nr_groups = max_group + 1;
	if (events->nr_events > 0) {
		events->mux_alg = events->evbuf[0].mux_alg;
		events->mux_arg = events->evbuf[0].mux_arg;
	}
	vtss_pr_debug_pmu("uploaded %d events in %d mux groups",
			  events->nr_events, events->nr_groups);
}

/* called from vtss_sched_switch_to() and vtss_pmi_handler()
 * to re-select multiplexion groups and restart counting */
void vtss_pmu_events_restart(struct vtss_pmu_events *events)
{
	bool overflowed;
	struct vtss_pmu_event *event;

	if (!vtss_pmu_active())
		return;

	/* update current MUX index */
	switch (events->mux_alg) {
	case VTSS_CFGMUX_NONE:
		/* no update to MUX index */
		break;
	case VTSS_CFGMUX_TIME:
		if (events->mux_time == 0) {
			/* setup new time interval */
			events->mux_time = vtss_time_cpu() +
					   (events->mux_arg*vtss_hardcfg.cpu_freq);
		} else if (vtss_time_cpu() >= events->mux_time) {
			/* setup new MUX index */
			events->group_id = (events->group_id + 1) % events->nr_groups;
			events->mux_time = 0;
		}
		break;
	case VTSS_CFGMUX_MST:
	case VTSS_CFGMUX_SLV:
		overflowed = false;
		vtss_pmu_for_each_active_event(events, event) {
			if (event->mux_alg == VTSS_CFGMUX_MST) {
				if (event->overflowed(event)) {
					overflowed = true;
					break;
				}
			}
		}
		if (!overflowed)
			break;
		/* fall through */
	case VTSS_CFGMUX_SEQ:
		if (events->mux_count >= events->mux_arg) {
			/* setup new MUX index */
			events->group_id = (events->group_id + 1) % events->nr_groups;
			events->mux_count = 0;
		}
		/* update MUX counter */
		events->mux_count++;
		break;
	}

	/* restart counting */
	vtss_pmu_for_each_active_event(events, event)
		event->restart(event);
}

/* called from vtss_sched_switch_from() and vtss_pmi_handler()
 * to read event values and form a sample record */
void vtss_pmu_events_sample(struct vtss_pmu_events *events)
{
	struct vtss_pmu_event *event;

	vtss_pmu_for_each_active_event(events, event)
		event->sample(event);
}
