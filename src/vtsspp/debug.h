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

#ifndef _VTSS_DEBUG_H_
#define _VTSS_DEBUG_H_

#include <linux/printk.h>	/* for printk  */
#include <linux/sched.h>	/* for current */
#include <linux/smp.h>		/* for raw_smp_processor_id */

/*
 * Use VTSS_DEBUG environment variable before
 * building the driver to enable debug output,
 * for example:
 *
 * export VTSS_DEBUG=cmd:stack:task
 * build-driver -ni
 */
#ifndef vtss_pr_debug_cmd
#define vtss_pr_debug_cmd vtss_pr_none
#endif
#ifndef vtss_pr_debug_kmem
#define vtss_pr_debug_kmem vtss_pr_none
#endif
#ifndef vtss_pr_debug_pmu
#define vtss_pr_debug_pmu vtss_pr_none
#endif
#ifndef vtss_pr_debug_mmap
#define vtss_pr_debug_mmap vtss_pr_none
#endif
#ifndef vtss_pr_debug_nmiwd
#define vtss_pr_debug_nmiwd vtss_pr_none
#endif
#ifndef vtss_pr_debug_probe
#define vtss_pr_debug_probe vtss_pr_none
#endif
#ifndef vtss_pr_debug_procfs
#define vtss_pr_debug_procfs vtss_pr_none
#endif
#ifndef vtss_pr_debug_record
#define vtss_pr_debug_record vtss_pr_none
#endif
#ifndef vtss_pr_debug_reqcfg
#define vtss_pr_debug_reqcfg vtss_pr_none
#endif
#ifndef vtss_pr_debug_stack
#define vtss_pr_debug_stack vtss_pr_none
#endif
#ifndef vtss_pr_debug_task
#define vtss_pr_debug_task vtss_pr_none
#endif
#ifndef vtss_pr_debug_trn
#define vtss_pr_debug_trn vtss_pr_none
#endif
#ifndef vtss_pr_debug_trn2
#define vtss_pr_debug_trn2 vtss_pr_none
#endif

#define vtss_pr_none(fmt, ...)    do { } while (0)
#define vtss_pr_error(fmt, ...)   printk(KERN_ERR     "vtsspp: " fmt "\n", ##__VA_ARGS__)
#define vtss_pr_warning(fmt, ...) printk(KERN_WARNING "vtsspp: " fmt "\n", ##__VA_ARGS__)
#define vtss_pr_notice(fmt, ...)  printk(KERN_NOTICE  "vtsspp: " fmt "\n", ##__VA_ARGS__)
#define vtss_pr_info(fmt, ...)    printk(KERN_INFO    "[cpu%d:%d] %s(%d): " fmt "\n",\
					 raw_smp_processor_id(), current->pid,\
					 __func__, __LINE__, ##__VA_ARGS__)

#endif
