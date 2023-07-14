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
#include "unwind.h"

/* empty the stack map */
void vtss_stack_map_reset(struct vtss_stack *stk)
{
	stk->end = stk->start = stk->common = stk->buf[0];
	stk->shadow = stk->buf[1];
}

#define VTSS_IP_SEARCH_RANGE 0x08UL

/* walk from SP up to stack base and
 * build an incremental map of stack,
 * frame and instruction pointers */
int vtss_stack_map_unwind(struct vtss_stack *stk)
{
	/* user registers */
	unsigned long sp = stk->sp;
	unsigned long bp = stk->bp;

	/* pointer to user stack */
	unsigned long ptr;
	/* value read from the user stack */
	unsigned long value;
	/* user stack border */
	unsigned long border;

	/* stack walk stride in bytes */
	int stride = stk->m32 ? 4 : 8;

	/* whether to detect the changed region */
	bool find_changed_region = true;

	/* position in the stack map */
	struct vtss_stack_map_entry *pos;

	/* read stack map parameters */
	struct vtss_stack_map_entry *start  = stk->start;
	struct vtss_stack_map_entry *common = stk->common;
	struct vtss_stack_map_entry *end    = stk->end;

	/* number of free entries in the stack map */
	int nr_free = VTSS_STACK_MAP_SIZE/sizeof(struct vtss_stack_map_entry);
	/* number of common entries in the stack map */
	int nr_common = 0;

	/* reset cache read index */
	size_t idx = PAGE_SIZE;
	/* reset cache read length */
	size_t len = 0;
	/* cache pointer */
	char *cache = stk->cache;

	/* align sp to machine word size */
	sp = ALIGN(sp, stride);

	/* clear the border between changed/unchanged stack map regions */
	common = NULL;

	/* check if the stack and stack map intersect */
	border = 0;
	if (start != end) { /* the map is not empty */
		if ((end - 1)->ptr >= bp || (end - 1)->ptr < sp) {
			/* the stack map is beyond the actual stack, clear it */
			common = end = start;
			/* nothing to find */
			find_changed_region = false;
			/* search the entire stack, the map is emptied */
			border = bp - stride;
		}
	} else { /* empty stack */
		/* clear the stack map */
		common = end = start;
		/* nothing to find */
		find_changed_region = false;
		/* search the entire stack, the map is emptied */
		border = bp - stride;
	}
	if (!find_changed_region)
		goto end_of_search;

	/* search the stack and the stack map to detect the changed/unchanged regions */
	for (pos = start; pos < end; pos++) {
		touch_nmi_watchdog();
		/* check if within the actual stack */
		if (pos->ptr < sp) {
			/* remember the changed border */
			common = pos;
			continue;
		}
		/* read in the actual stack contents */
		if (vtss_stack_copy_from_user(stk, &cache[0], (void *)pos->ptr, stride)) {
			vtss_pr_debug_stack("Failed to copy %d bytes from 0x%lx: [0x%lx-0x%lx]",
					    stride, pos->ptr, sp, bp);
			/* clear the stack map */
			common = end = start;
			/* search the entire stack, the map is emptied */
			border = bp - stride;
			goto end_of_search;
		}
		value = vtss_stack_get_addr(&cache[0], stride);
		/* check if the current entry has changed */
		if (pos->value != value) {
			/* remember the changed border */
			common = pos;
		} else if (pos + 1 == end) {
			/* check the stack above the last map entry */
			/* not required for Linux */
		} else if (value < sp || value >= bp) {
			/* do extra IP search above the current IP entry */
			if (pos + 1 < end)
				border = min((pos + 1)->ptr, pos->ptr + VTSS_IP_SEARCH_RANGE*stride);
			else
				border = min(bp, pos->ptr + VTSS_IP_SEARCH_RANGE*stride);
			/* search for IPs from the same module */
			len = 0;
			for (ptr = pos->ptr + stride; ptr < border; ptr += stride, idx += stride) {
				touch_nmi_watchdog();
				if (idx >= len) {
					idx = 0;
					len = min(PAGE_SIZE - (ptr & ~PAGE_MASK), border - ptr + stride);
					len = min(VTSS_IP_SEARCH_RANGE*stride, len);
					if (vtss_stack_copy_from_user(stk, &cache[idx], (void *)ptr, len)) {
						vtss_pr_debug_stack("Failed to copy %ld bytes from 0x%lx: [0x%lx-0x%lx]",
								    len, ptr, sp, bp);
						/* clear the stack map */
						common = end = start;
						/* search the entire stack, the map is emptied */
						border = bp - stride;
						goto end_of_search;
					}
				}
				value = vtss_stack_get_addr(&cache[idx], stride);
				/* this is a relaxed IP search condition (to increase the performance) */
				if (vtss_stack_valid_ip(stk, value)) {
					/* remember the changed border */
					common = pos;
					break;
				}
			}
		}
	}
	if (common) { /* found the chanaged/unchanged border */
		/* use the map entry following the changed one */
		common++;
	} else { /* unchanged stack */
		common = start;
	}
	/* search below the unchanged region */
	border = (common == end) ? bp - stride : common->ptr - stride;
	/* switch to another stack map, the common part is kept
	 * in the current map and will be copied to the new one */
	pos = start;
	start = stk->shadow;
	stk->shadow = pos;
end_of_search:

	/* compute the number of entries in the unchanged stack map region */
	nr_common = end - common;
	/* correct the number of free entries in the stack map */
	nr_free -= nr_common;

	/* search the stack for IPs and FPs and update the stack map */
	idx = PAGE_SIZE;
	len = 0;
	for (ptr = sp, pos = start; ptr <= border; ptr += stride, idx += stride) {
		touch_nmi_watchdog();
		if (pos - start >= nr_free) {
			/* the map is full */
			vtss_pr_debug_stack("No room to copy from 0x%lx: [0x%lx-0x%lx]", ptr, sp, bp);
			if (common == end) {
				/* failed to search the entire stack, return at least something */
				stk->stat.enomem++;
				break;
			} else {
				/* failed to search in incremental part, fallback to entire stack */
				return -ENOMEM;
			}
		}
		if (idx >= len) {
			/* read a value from the stack */
			idx = 0;
			len = min(PAGE_SIZE - (ptr & ~PAGE_MASK), border - ptr + stride);
			if (vtss_stack_copy_from_user(stk, &cache[idx], (void *)ptr, len)) {
				vtss_pr_debug_stack("Failed to copy %ld bytes from 0x%lx: [0x%lx-0x%lx]",
						    len, ptr, sp, bp);
				if (common == end) {
					/* failed to search the entire stack, return at least something */
					stk->stat.eacces++;
					break;
				} else {
					/* failed to search in incremental part, fallback to entire stack */
					return -EACCES;
				}
			}
		}
		value = vtss_stack_get_addr(&cache[idx], stride);
		/* check for FP first as there are no find_vma() calls */
		if (!vtss_stack_valid_fp(stk, ptr, value))
			/* it's not FP, check for IP */
			if (!vtss_stack_valid_ip(stk, value))
				continue;
		/* it's either FP or IP, store it */
		pos->ptr = ptr;
		pos->value = value;
		pos++;
	}
	if (common != end) {
		/* merge in the unchanged stack map region */
		memcpy(pos, common, nr_common*sizeof(struct vtss_stack_map_entry));
		/* include one common entry into the current stack increment */
		pos++; nr_common--;
	}
	/* store stack map parameters */
	stk->start  = start;
	stk->end    = pos + nr_common;
	stk->common = pos;
	return 0;
}

/* compress the collected stack map */
size_t vtss_stack_map_compress(struct vtss_stack *stk)
{
	int i, j;
	int prefix;
	unsigned long value;
	unsigned long offset;
	unsigned long tmp;
	int sign;

	int nr = vtss_stack_map_nr_unwound(stk)*2 /* SP + FP/IP */;
	unsigned long *map = (unsigned long *)stk->start;
	unsigned long ip = stk->ip;
	unsigned long sp = stk->sp;
	unsigned long fp = stk->fp;
	unsigned long base = stk->bp;
	unsigned char *buf = stk->shadow;
	size_t reserve = sizeof(unsigned long)*2 + 2;
	int stride = stk->m32 ? 4 : 8;

	/* correct sp */
	sp = ALIGN(sp, stride);

	for (i = 0; i < nr; i++) {
		touch_nmi_watchdog();
		/* check the border */
		if (buf - (unsigned char *)stk->shadow >= VTSS_STACK_MAP_SIZE - reserve) {
			vtss_pr_warning("No room to compress stack map");
			return 0;
		}

		/* [[prefix][stack pointer][prefix][value]]...
		 *  [prefix bits: |7: frame(1)/code(0)|6: sign|5:|4:|3-0: bytes per value]
		 *  [prefix bits for sp: |7: (1) - idicates value is encoded in prefix|6-0: scaled sp value]
		 *                           (0) - |6:|5:|4:|3-0: bytes per value]
		 *  [prefix bits for fp: |7: frame(1)/code(0)|6: sign|5: in-prefix (0) - |4:|3-0: bytes per value]
		 *                                                                 (1) - |4-0: scaled fp value]
		 *  [value: difference from previous value of the same type] */

		/* compress a stack pointer */
		value = map[i] - sp;	/* assert(value >= 0); */
		value >>= 2;		/* scale the stack pointer down by 4 */

		if (value < 0x80) {
			prefix = 0x80 | (int)value;
			*buf++ = prefix;
		} else {
			for (j = sizeof(unsigned long) - 1; j >= 0; j--) {
				if (value & (0xffUL << (j << 3)))
					break;
			}
			prefix = j + 1;
			*buf++ = prefix;

			for (; j >= 0; j--) {
				*buf++ = value & 0xff;
				value >>= 8;
			}
		}
		sp = map[i++];

		/* test and compress a value */
		value = map[i];

		if (value >= sp && value < base) {
			offset = fp;
			fp = value;
			value -= offset;
			tmp = value & (1UL << ((sizeof(unsigned long) << 3) - 1));
			value = (value >> 2) | tmp | (tmp >> 1);

			if (value < 0x20) {
				prefix = 0xa0 | (int)value;
				*buf++ = prefix;
				continue;
			} else if (value > (unsigned long)-32) {
				prefix = 0xe0 | (int)(value & 0xff);
				*buf++ = prefix;
				continue;
			}
			prefix = 0x80;
		} else {
			offset = ip;
			ip = value;
			prefix = 0;
			value -= offset;
		}
		sign = (value & (1UL << ((sizeof(unsigned long) << 3) - 1))) ? 0xff : 0;

		for (j = sizeof(unsigned long) - 1; j >= 0; j--) {
			if (((value >> (j << 3)) & 0xff) != sign)
				break;
		}
		prefix |= sign ? 0x40 : 0;
		prefix |= j + 1;
		*buf++ = prefix;

		for (; j >= 0; j--) {
			*buf++ = value & 0xff;
			value >>= 8;
		}
	}
	return buf - (unsigned char *)stk->shadow;
}
