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

#ifndef _VTSS_STAT_H_
#define _VTSS_STAT_H_

#include "config.h"

#define VTSS_STAT_INIT(i) {ATOMIC64_INIT(i)}

struct vtss_stat {
	atomic64_t cnt;
};

#define VTSS_STAT_MAX_INIT(i) {ATOMIC64_INIT(i), ATOMIC64_INIT(i)}

struct vtss_stat_max {
	atomic64_t cnt;
	atomic64_t max;
};

#define vtss_stat_inc(v) atomic64_inc(&(v)->cnt)
#define vtss_stat_dec(v) atomic64_dec(&(v)->cnt)

#define vtss_stat_add(i, v) atomic64_add(i, &(v)->cnt)
#define vtss_stat_sub(i, v) atomic64_sub(i, &(v)->cnt)

#define vtss_stat_read(v)     (size_t)atomic64_read(&(v)->cnt)
#define vtss_stat_read_max(v) (size_t)atomic64_read(&(v)->max)

#define vtss_stat_reset(v)     atomic64_set(&(v)->cnt, 0)
#define vtss_stat_reset_max(v) atomic64_set(&(v)->max, 0)

static inline void vtss_stat_max_add(size_t i, struct vtss_stat_max *v)
{
	size_t cnt, max;

	atomic64_add(i, &v->cnt);
	cnt = atomic64_read(&v->cnt);
	max = atomic64_read(&v->max);
	if (cnt > max) atomic64_cmpxchg(&v->max, max, cnt);
}

#endif
