/****
    Copyright (C) 2011 Intel Corporation.  All Rights Reserved.

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
****/





#include "lwpmudrv_defines.h"
#include "lwpmudrv_types.h"
#include "lwpmudrv_ecb.h"
#include "lwpmudrv_struct.h"

#include "inc/ecb_iterators.h"
#include "inc/control.h"
#include "inc/haswellunc_sa.h"
#include "inc/pci.h"
#include "inc/utility.h"

extern U64       *read_counter_info;
extern DRV_CONFIG drv_cfg;

#if !defined(DISABLE_BUILD_SOCPERF)
extern VOID
SOCPERF_Read_Data3(PVOID data_buffer);
#endif

/*!
 * @fn         static VOID hswunc_sa_Initialize(PVOID)
 *
 * @brief      Initialize any registers or addresses
 *
 * @param      param
 *
 * @return     None
 *
 * <I>Special Notes:</I>
 */
static VOID
hswunc_sa_Initialize(VOID *param)
{
	SEP_DRV_LOG_TRACE_IN("Param: %p.", param);
	SEP_DRV_LOG_TRACE_OUT("Empty function.");
	return;
}

/* ------------------------------------------------------------------------- */
/*!
 * @fn hswunc_sa_Read_Counts(param, id, read_from_intr)
 *
 * @param    param          Pointer to populate read data
 * @param    id             Device index
 * @param    read_from_intr Read data from interrupt or timer
 *
 * @return   None     No return needed
 *
 * @brief    Read the Uncore count data and store into the buffer param;
 *
 */
static VOID
hswunc_sa_Trigger_Read(PVOID param, U32 id, U32 read_from_intr)
{
	U64 *data = (U64 *)param;
	U32  cur_grp;
	ECB  pecb;
	U32  this_cpu;
	U32  package_num;

	SEP_DRV_LOG_TRACE_IN("Param: %p, id: %u.", param, id);

	this_cpu    = CONTROL_THIS_CPU();
	package_num = core_to_package_map[this_cpu];
	cur_grp     = LWPMU_DEVICE_cur_group(&devices[id])[package_num];
	pecb        = LWPMU_DEVICE_PMU_register_data(&devices[id])[cur_grp];

	// group id
	data = (U64 *)((S8 *)data + ECB_group_offset(pecb));
#if !defined(DISABLE_BUILD_SOCPERF)
	SOCPERF_Read_Data3((void *)data);
#endif

	SEP_DRV_LOG_TRACE_OUT("");
	return;
}

/* ------------------------------------------------------------------------- */
/*!
 * @fn hswunc_sa_Read_PMU_Data(param)
 *
 * @param    param    the device index
 *
 * @return   None     No return needed
 *
 * @brief    Read the Uncore count data and store into the buffer param;
 *
 */
static VOID
hswunc_sa_Read_PMU_Data(PVOID param, U32 dev_idx)
{
	U32       j;
	U64      *buffer = (U64 *)param;
	U32       this_cpu;
	CPU_STATE pcpu;
	U32       event_index = 0;
	U64       counter_buffer[HSWUNC_SA_MAX_COUNTERS + 1];

	SEP_DRV_LOG_TRACE_IN("Param: %p.", param);

	this_cpu = CONTROL_THIS_CPU();
	pcpu     = &pcb[this_cpu];

	// NOTE THAT the read_pmu function on for EMON collection.
	if (!DRV_CONFIG_emon_mode(drv_cfg)) {
		SEP_DRV_LOG_TRACE_OUT("Early exit (!emon_mode).");
		return;
	}
	if (!CPU_STATE_system_master(pcpu)) {
		SEP_DRV_LOG_TRACE_OUT("Early exit (!system_master).");
		return;
	}

#if !defined(DISABLE_BUILD_SOCPERF)
	SOCPERF_Read_Data3((void *)counter_buffer);
#endif

	FOR_EACH_PCI_DATA_REG_RAW (pecb, i, dev_idx) {
		j         = ECB_entries_uncore_buffer_offset_in_system(pecb, i);
		buffer[j] = counter_buffer[event_index + 1];
		event_index++;
		SEP_DRV_LOG_TRACE("j=%u, value=%llu, cpu=%u", j, buffer[j],
				  this_cpu);
	}
	END_FOR_EACH_PCI_DATA_REG_RAW;

	SEP_DRV_LOG_TRACE_OUT("");
	return;
}

/*
 * Initialize the dispatch table
 */
DISPATCH_NODE hswunc_sa_dispatch = {
	hswunc_sa_Initialize,    // initialize
	NULL,                    // destroy
	NULL,                    // write
	NULL,                    // freeze
	NULL,                    // restart
	hswunc_sa_Read_PMU_Data, // read
	NULL,                    // check for overflow
	NULL,                    // swap group
	NULL,                    // read lbrs
	NULL,                    // cleanup
	NULL,                    // hw errata
	NULL,                    // read power
	NULL,                    // check overflow errata
	NULL,                    // read counts
	NULL,                    // check overflow gp errata
	NULL,                    // read_ro
	NULL,                    // platform info
	hswunc_sa_Trigger_Read,  // trigger read
	NULL,                    // scan for uncore
	NULL                     // read metrics
};

