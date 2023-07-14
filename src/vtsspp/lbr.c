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
#include "lbr.h"
#include "pmu.h"
#include "regs.h"
#include "time.h"

static int vtss_lbr_size = 0;

/* initialize the architectural LBR parameters */
int vtss_lbr_init(void)
{
	if (vtss_pmu_version >= 4) {
		vtss_lbr_size = 32;
	} else if (vtss_pmu_version == 3) {
		vtss_lbr_size = 16;
	} else {
		vtss_pr_error("LBR not supported");
		return -EINVAL;
	}
	vtss_pr_notice("LBR: stack size: %d", vtss_lbr_size);
	return 0;
}

static void vtss_lbr_disable_cb(void *ctx)
{
	vtss_lbr_disable();
}

/* disable LBR collection on each processor */
void vtss_lbr_cleanup(void)
{
	if (!vtss_lbr_size)
		return;
	on_each_cpu(vtss_lbr_disable_cb, NULL, 1);
	vtss_lbr_size = 0;
}

/* start LBR collection on the processor */
void vtss_lbr_enable(struct vtss_lbr *lbr)
{
	int i;
	unsigned long long dbgctl;

	if (!vtss_lbr_size)
		return;

	wrmsrl(VTSS_MSR_LBR_SELECT, 0);
	rdmsrl(VTSS_IA32_DEBUGCTL, dbgctl);
	dbgctl |= VTSS_LBR_ENABLE_MASK;
	wrmsrl(VTSS_IA32_DEBUGCTL, 0);

	/* restore LBR stack (if saved) */
	if (lbr->saved) {
		for (i = 0; i < vtss_lbr_size; i++) {
			wrmsrl(VTSS_MSR_LASTBRANCH_0_FROM_IP + i, lbr->stk[i].from);
			wrmsrl(VTSS_MSR_LASTBRANCH_0_TO_IP   + i, lbr->stk[i].to);
		}
		wrmsrl(VTSS_MSR_LASTBRANCH_TOS, lbr->tos);
		lbr->saved = false;
	}
	/* enable LBR call stack */
	wrmsrl(VTSS_MSR_LBR_SELECT, VTSS_LBR_SELECT_MASK);
	wrmsrl(VTSS_IA32_DEBUGCTL, dbgctl);
}

/* stop LBR collection on the processor */
void vtss_lbr_disable(void)
{
	unsigned long long dbgctl;

	if (!vtss_lbr_size)
		return;

	rdmsrl(VTSS_IA32_DEBUGCTL, dbgctl);
	dbgctl &= ~VTSS_LBR_ENABLE_MASK;
	wrmsrl(VTSS_IA32_DEBUGCTL, dbgctl);
}

/* save LBR stack, LBR should be disabled */
void vtss_lbr_save(struct vtss_lbr *lbr)
{
	int i;

	/* save LBR stack only on modern architectures */
	if (vtss_lbr_size == 32) {
		for (i = 0; i < vtss_lbr_size; i++) {
			rdmsrl(VTSS_MSR_LASTBRANCH_0_FROM_IP + i, lbr->stk[i].from);
			rdmsrl(VTSS_MSR_LASTBRANCH_0_TO_IP   + i, lbr->stk[i].to);
		}
		rdmsrl(VTSS_MSR_LASTBRANCH_TOS, lbr->tos);
		lbr->saved = true;
	}
}

/* collect an LBR clear stack record */
int vtss_lbr_sample(struct vtss_callchain *callchain)
{
	int rc;
	int i, lbridx;
	unsigned long long tos, from;
	unsigned long addr;

	if (!vtss_lbr_size)
		return -EINVAL;
	if (callchain->buf == NULL)
		return -ENOMEM;

	/* loop through all LBRs and form a clear stack record */
	rdmsrl(VTSS_MSR_LASTBRANCH_TOS, tos);
	lbridx = tos & (vtss_lbr_size - 1);
	for (i = 0; i < vtss_lbr_size; i++) {
		rdmsrl(VTSS_MSR_LASTBRANCH_0_FROM_IP + lbridx, from);
		addr = (from << 16) >> 16;
		if (addr == 0)
			break;
		rc = vtss_callchain_compress_next(callchain, addr);
		if (rc) {
			vtss_pr_warning("No room to compress LBR stack");
			return 0;
		}
		lbridx = lbridx ? lbridx - 1 : vtss_lbr_size - 1;
	}
	return 0;
}
