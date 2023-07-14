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

#ifndef _VTSS_IPT_H_
#define _VTSS_IPT_H_

#include "config.h"
#include "pmu.h"
#include "transport.h"

/* Trace control register */
#define VTSS_IA32_RTIT_CTL 0x570

/* Tracing status register */
#define VTSS_IA32_RTIT_STATUS 0x571

/* Trace output base register */
#define VTSS_IA32_RTIT_OUTPUT_BASE 0x560

/* Trace output mask pointers register */
#define VTSS_IA32_RTIT_OUTPUT_MASK_PTRS 0x561

/* Layout of trace control register */
#define VTSS_IPT_CTL_TRACE  0x0001ULL
#define VTSS_IPT_CTL_CYCLE  0x0002ULL
#define VTSS_IPT_CTL_KERNEL 0x0004ULL
#define VTSS_IPT_CTL_USER   0x0008ULL
#define VTSS_IPT_CTL_TOPA   0x0100ULL
#define VTSS_IPT_CTL_TSC    0x0400ULL
#define VTSS_IPT_CTL_NORETC 0x0800ULL
#define VTSS_IPT_CTL_BRANCH 0x2000ULL

/* Layout of ToPA table entry */
#define VTSS_IPT_TOPA_END   0x01ULL
#define VTSS_IPT_TOPA_INT   0x04ULL
#define VTSS_IPT_TOPA_STOP  0x10ULL

/* Trace output masks */
#define VTSS_IPT_LOWER_MASK 0x0000007fULL
#define VTSS_IPT_TABLE_MASK 0xffffff80ULL

#define VTSS_IPT_NR_BUFFERS 16

#define vtss_ipt_supported() (vtss_pmu_version >= 4)

int vtss_ipt_init(void);
void vtss_ipt_cleanup(void);
void vtss_ipt_enable(unsigned int mode);
void vtss_ipt_disable(void);
int vtss_ipt_write(struct vtss_transport *trn, int tidx, bool overflowed);

#endif
