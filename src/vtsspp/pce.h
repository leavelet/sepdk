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

#ifndef _VTSS_PCE_H_
#define _VTSS_PCE_H_

#include "config.h"
#include "pcb.h"
#include "regs.h"

static void vtss_pce_set_cb(void *ctx)
{
	unsigned long cr4 = vtss_read_cr4();

	if (ctx) {
		/* save PCE bit */
		vtss_pcb_cpu.pce_state = cr4 & VTSS_CR4_PCE;
		/* set PCE bit */
		cr4 |= VTSS_CR4_PCE;
	} else if (!vtss_pcb_cpu.pce_state) {
		/* if there was no PCE bit before saving, reset it */
		cr4 &= ~VTSS_CR4_PCE;
	}
	vtss_write_cr4(cr4);
}

static inline void vtss_pce_enable(void)
{
	on_each_cpu(vtss_pce_set_cb, (void *)1, 1);
}

static inline void vtss_pce_disable(void)
{
	on_each_cpu(vtss_pce_set_cb, (void *)0, 1);
}

#endif
