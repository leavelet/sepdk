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
#include "kmem.h"

struct vtss_stat_max vtss_kmem_pages = VTSS_STAT_MAX_INIT(0);
struct vtss_stat_max vtss_kmem_chunks = VTSS_STAT_MAX_INIT(0);
struct vtss_stat_max vtss_kmem_chunks_size = VTSS_STAT_MAX_INIT(0);

void vtss_kmem_stat_print(void)
{
	size_t pages = vtss_stat_read_max(&vtss_kmem_pages);
	size_t size = vtss_stat_read_max(&vtss_kmem_chunks_size) +
		      pages*PAGE_SIZE;

	vtss_pr_notice("Memory used: %zuMB", size >> 20);

	vtss_pr_debug_kmem("max pages allocated: %zu (%zuMB)",
			   pages, pages*PAGE_SIZE >> 20);
	vtss_pr_debug_kmem("max chunks allocated: %zu (%zuKB)",
			   vtss_stat_read_max(&vtss_kmem_chunks),
			   vtss_stat_read_max(&vtss_kmem_chunks_size) >> 10);
}

void vtss_kmem_stat_check(void)
{
	size_t pages = vtss_stat_read(&vtss_kmem_pages);
	size_t chunks = vtss_stat_read(&vtss_kmem_chunks);

	if (pages || chunks)
		vtss_pr_error("Possible memory leak detected");

	if (pages)
		vtss_pr_warning("Memory pages still allocated: %zu (%zuMB)",
				pages, pages*PAGE_SIZE >> 20);
	if (chunks)
		vtss_pr_warning("Memory chunks still allocated: %zu (%zuKB)",
				chunks, vtss_stat_read(&vtss_kmem_chunks_size) >> 10);
}

void vtss_kmem_stat_reset(void)
{
	vtss_kmem_stat_check();
	vtss_stat_reset_max(&vtss_kmem_pages);
	vtss_stat_reset_max(&vtss_kmem_chunks);
	vtss_stat_reset_max(&vtss_kmem_chunks_size);
}
