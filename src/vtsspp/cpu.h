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

#ifndef _VTSS_CPU_H_
#define _VTSS_CPU_H_

/* Version information: type, family, model, etc */
#define VTSS_CPUID_VERSION 0x01

#define vtss_cpuid_cpu_stepping(eax) ((eax) & 0xf)

#define VTSS_CPU_FAM_P6 0x06

#define vtss_cpuid_cpu_family(eax) (((eax) >> 8) & 0xf)

#define VTSS_CPU_NHM    0x1e
#define VTSS_CPU_NHM_G  0x1f
#define VTSS_CPU_NHM_EP 0x1a
#define VTSS_CPU_NHM_EX 0x2e

#define VTSS_CPU_WMR    0x25
#define VTSS_CPU_WMR_EP 0x2c
#define VTSS_CPU_WMR_EX 0x2f

#define VTSS_CPU_SNB    0x2a
#define VTSS_CPU_SNB_X  0x2d
#define VTSS_CPU_IVB    0x3a
#define VTSS_CPU_IVB_X  0x3e

#define VTSS_CPU_HSW    0x3c
#define VTSS_CPU_HSW_X  0x3f
#define VTSS_CPU_HSW_M  0x45
#define VTSS_CPU_HSW_G  0x46

#define VTSS_CPU_BDW    0x3d
#define VTSS_CPU_BDW_G  0x47
#define VTSS_CPU_BDW_X  0x4f
#define VTSS_CPU_BDW_XD 0x56

#define vtss_cpuid_cpu_model(eax) (((eax) >> 4) & 0xf)
#define vtss_cpuid_cpu_ext_model(eax) (((eax) >> 16) & 0xf)

#define vtss_cpuid_cpu_display_model(eax)\
	((vtss_cpuid_cpu_family(eax) == VTSS_CPU_FAM_P6) ?\
		(vtss_cpuid_cpu_ext_model(eax) << 4) + vtss_cpuid_cpu_model(eax) :\
		(vtss_cpuid_cpu_model(eax)))

/* Deterministic cache parameters */
#define VTSS_CPUID_CACHE 0x04

/* Maximum id of logical processor  */
#define vtss_cpuid_cpu_max_thread_id(eax) (((eax) >> 14) & 0xfff)

/* Extended feature flags */
#define VTSS_CPUID_EXT_FEATURES 0x07

/* CPU supports Indirect Branch Tracking feature */
#define vtss_cpuid_cpu_has_ibt(edx) (((edx) >> 20) & 0x1)

/* Architectural Performance Monitoring */
#define VTSS_CPUID_PMU 0x0a

#define vtss_cpuid_pmu_version(eax) ((eax) & 0xff)

#define vtss_cpuid_pmu_nr_gp_counters(eax) (((eax) >> 8) & 0xff)
#define vtss_cpuid_pmu_gp_counter_width(eax) (((eax) >> 16) & 0xff)

#define vtss_cpuid_pmu_nr_fx_counters(edx) ((edx) & 0x1f)
#define vtss_cpuid_pmu_fx_counter_width(edx) (((edx) >> 5) & 0xff)

/* Time stamp counter and nominal core clock */
#define VTSS_CPUID_TSC 0x15

/* Hybrid information */
#define VTSS_CPUID_HYBRID 0x1a

#define VTSS_CPU_TYPE_ATOM 0x20
#define VTSS_CPU_TYPE_CORE 0x40

#define vtss_cpuid_cpu_type(eax) (((eax) >> 24) & 0xff)

#endif
