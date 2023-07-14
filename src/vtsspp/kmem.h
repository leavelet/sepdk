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

#ifndef _VTSS_KMEM_H_
#define _VTSS_KMEM_H_

#include "config.h"
#include "debug.h"
#include "stat.h"

#include <linux/gfp.h>		/* for alloc_pages */
#include <linux/slab.h>		/* for kmalloc */

extern struct vtss_stat_max vtss_kmem_pages;

/**
 * Pages allocation routines:
 * used for working buffers allocations,
 * can be bound to a specified NUMA node.
 */

#define vtss_alloc_pages(size, flags, cpu)\
({\
	unsigned int order = get_order(size);\
	struct page *page = ((cpu) < 0) ? alloc_pages(flags, order) :\
					  alloc_pages_node(cpu_to_node(cpu), flags, order);\
	void *ptr = page ? page_address(page) : NULL;\
	if (ptr) vtss_stat_max_add(1 << order, &vtss_kmem_pages);\
	if (order) vtss_pr_debug_kmem("alloc_pages: 0x%p, flags=0x%x, order=%d, cpu=%d",\
				      ptr, flags, order, cpu);\
	ptr;\
})

#define vtss_free_pages(ptr, size)\
({\
	unsigned int order = get_order(size);\
	if (ptr) {\
		vtss_stat_sub(1 << order, &vtss_kmem_pages);\
		if (order) vtss_pr_debug_kmem("free_pages: 0x%p, order=%d", ptr, order);\
		free_pages((unsigned long)(ptr), order);\
	}\
})

extern struct vtss_stat_max vtss_kmem_chunks;
extern struct vtss_stat_max vtss_kmem_chunks_size;

/**
 * Data allocation routines:
 * used for data structures allocations,
 * always zeroed out.
 */

#define vtss_zalloc(size, flags)\
({\
	void *ptr = kmalloc(size, flags);\
	if (ptr) {\
		memset(ptr, 0, size);\
		vtss_stat_max_add(1, &vtss_kmem_chunks);\
		vtss_stat_max_add(size, &vtss_kmem_chunks_size);\
	}\
	vtss_pr_debug_kmem("alloc: 0x%p, flags=0x%x, size=%zu", ptr, flags, (size_t)(size));\
	ptr;\
})

#define vtss_zfree(pptr, size)\
({\
	if (*(pptr)) {\
		vtss_stat_sub(1, &vtss_kmem_chunks);\
		vtss_stat_sub(size, &vtss_kmem_chunks_size);\
		vtss_pr_debug_kmem("free: 0x%p, size=%zu", *(pptr), size);\
		kfree(*(pptr));\
		*(pptr) = NULL;\
	}\
})

void vtss_kmem_stat_print(void);
void vtss_kmem_stat_check(void);
void vtss_kmem_stat_reset(void);

#endif
