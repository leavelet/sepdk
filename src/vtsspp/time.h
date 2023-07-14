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

#ifndef _VTSS_TIME_H_
#define _VTSS_TIME_H_

#include "config.h"

#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>

#define VTSS_TIME_SOURCE_SYS 0
#define VTSS_TIME_SOURCE_TSC 1

#ifdef VTSS_AUTOCONF_KTIME_EQUAL
#define vtss_ktime_equal(cmp1, cmp2) ktime_equal(cmp1, cmp2)
#else
#define vtss_ktime_equal(cmp1, cmp2) ((cmp1) == (cmp2))
#endif

#ifdef VTSS_AUTOCONF_KTIME_GET_TS64
#define vtss_timespec timespec64
#define vtss_time_get_raw_ts(ts) ktime_get_raw_ts64(ts)
#define vtss_time_get_real_ts(ts) ktime_get_real_ts64(ts)
#define vtss_time_ts_to_ns(ts) ((unsigned long long)timespec64_to_ns(ts))
#else
#define vtss_timespec timespec
#define vtss_time_get_raw_ts(ts) getrawmonotonic(ts)
#define vtss_time_get_real_ts(ts) getnstimeofday(ts)
#define vtss_time_ts_to_ns(ts) ((unsigned long long)timespec_to_ns(ts))
#endif

extern int vtss_time_source; /* 0 - raw clock monotonic (default), 1 - rdtsc */

static __always_inline unsigned long long vtss_freq_cpu(void)
{
	return tsc_khz*1000ULL;
}

static __always_inline unsigned long long vtss_freq_real(void)
{
	return (vtss_time_source == VTSS_TIME_SOURCE_TSC) ?
		tsc_khz*1000ULL : 1000000000ULL /* 1ns */;
}

static __always_inline unsigned long long vtss_time_cpu(void)
{
	return get_cycles();
}

static __always_inline unsigned long long vtss_time_real(void)
{
	if (vtss_time_source == VTSS_TIME_SOURCE_TSC) {
		return vtss_time_cpu();
	} else {
		struct vtss_timespec now;
		vtss_time_get_raw_ts(&now);
		return vtss_time_ts_to_ns(&now);
	}
}

static __always_inline void vtss_rdtsc_barrier(void)
{
	asm volatile("mfence" ::: "memory");
	asm volatile("lfence" ::: "memory");
}

static __always_inline void vtss_time_get_sync(unsigned long long *ptsc, unsigned long long *preal)
{
	unsigned long long tsc = vtss_time_cpu();

	if (vtss_time_source == VTSS_TIME_SOURCE_TSC) {
		*ptsc = *preal = tsc;
	} else {
		struct vtss_timespec now1, now2;
		vtss_time_get_raw_ts(&now1);
		vtss_rdtsc_barrier();
		vtss_time_get_raw_ts(&now2);
		*ptsc = (tsc + vtss_time_cpu())/2;
		*preal = (vtss_time_ts_to_ns(&now1) + vtss_time_ts_to_ns(&now2))/2;
	}
}

static __always_inline unsigned long long vtss_time_get_msec_from(unsigned long long cputsc)
{
	return (vtss_time_cpu() - cputsc)/tsc_khz;
}

#endif
