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

#ifndef _VTSS_LBR_H_
#define _VTSS_LBR_H_

#include "config.h"
#include "stack.h"

/* LBR filtering select register */
#define VTSS_MSR_LBR_SELECT 0x1c8

/* LBR stack TOS register */
#define VTSS_MSR_LASTBRANCH_TOS 0x1c9

/* LBR 0 from IP register */
#define VTSS_MSR_LASTBRANCH_0_FROM_IP 0x680

/* LBR 0 to IP register */
#define VTSS_MSR_LASTBRANCH_0_TO_IP   0x6c0

/* Debug control enable mask */
#define VTSS_LBR_ENABLE_MASK 0x201ULL

/* LBR filtering select mask */
#define VTSS_LBR_SELECT_MASK 0x3c5ULL

/* maximum supported LBR size */
#define VTSS_LBR_MAX_SIZE 32

struct vtss_lbr_record {
	unsigned long long from;
	unsigned long long to;
};

struct vtss_lbr {
	bool saved;
	unsigned long long tos;
	struct vtss_lbr_record stk[VTSS_LBR_MAX_SIZE];
};

int vtss_lbr_init(void);
void vtss_lbr_cleanup(void);
void vtss_lbr_enable(struct vtss_lbr *lbr);
void vtss_lbr_disable(void);
void vtss_lbr_save(struct vtss_lbr *lbr);
int vtss_lbr_sample(struct vtss_callchain *callchain);

#endif
