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

#ifndef _VTSS_REGS_H_
#define _VTSS_REGS_H_

#include "config.h"

#include <asm/msr.h>	/* for rdmsrl/wrmsrl */

/* Uncore internal select registers */
#define VTSS_UNC_ENERGY 0x1
#define VTSS_UNC_EHFI   0x2

/* Debug control register */
#define VTSS_IA32_DEBUGCTL 0x1d9

/* Offcore response event select registers */
#define VTSS_MSR_OFFCORE_RSP_0 0x1a6
#define VTSS_MSR_OFFCORE_RSP_1 0x1a7

/* Load latency threshold register */
#define VTSS_MSR_PEBS_LD_LAT   0x3f6
/* Frontend precise event condition select */
#define VTSS_MSR_PEBS_FRONTEND 0x3f7

/* Energy status registers */
#define VTSS_MSR_PP0_ENERGY_STATUS  0x639
#define VTSS_MSR_PP1_ENERGY_STATUS  0x641
#define VTSS_MSR_PKG_ENERGY_STATUS  0x611
#define VTSS_MSR_DRAM_ENERGY_STATUS 0x619

/* Thread level scope register */
#define VTSS_IA32_HW_FEEDBACK_CHAR 0x17d2

/* Platform information register */
#define VTSS_MSR_PLATFORM_INFO 0xce
/* Maximum non-turbo ratio */
#define vtss_platform_info_fratio(info) ((info >> 8) & 0xff)

/* Control-flow Enforcement Technology
 * supervisor mode configuration */
#define VTSS_IA32_S_CET 0x6a2
/* Enables Indirect Branch Tracking */
#define VTSS_CET_ENDBR_EN 0x04ULL

static inline unsigned long vtss_read_rbp(void)
{
	unsigned long val;
	asm volatile("movq %%rbp, %0" : "=r"(val));
	return val;
}

/* Performance-Monitoring Counter Enable:
 * enables execution of the RDPMC instruction
 * at any protection level */
#define VTSS_CR4_PCE 0x100

static inline unsigned long vtss_read_cr4(void)
{
	unsigned long val;
	asm volatile("movq %%cr4, %0" : "=r" (val));
	return val;
}

static inline void vtss_write_cr4(unsigned long val)
{
	asm volatile("movq %0, %%cr4" :: "r" (val) : "memory");
}

#endif
