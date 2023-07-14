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

#ifndef _VTSS_PROCFS_H_
#define _VTSS_PROCFS_H_

#include "config.h"

#include <linux/proc_fs.h>

#ifdef VTSS_AUTOCONF_PROCFS_OPS
#define vtss_procfs_ops proc_ops
#define vtss_procfs_open proc_open
#define vtss_procfs_read proc_read
#define vtss_procfs_write proc_write
#define vtss_procfs_lseek proc_lseek
#define vtss_procfs_release proc_release
#define vtss_procfs_poll proc_poll
#else
#define VTSS_PROCFS_OPS_OWNER 1
#define vtss_procfs_ops file_operations
#define vtss_procfs_open open
#define vtss_procfs_read read
#define vtss_procfs_write write
#define vtss_procfs_lseek llseek
#define vtss_procfs_release release
#define vtss_procfs_poll poll
#endif

#ifdef VTSS_AUTOCONF_PROCFS_PDE_DATA
#define vtss_procfs_pde_data(inode) pde_data(inode)
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define vtss_procfs_pde_data(inode) PDE_DATA(inode)
#else
#define vtss_procfs_pde_data(inode) PDE(inode)->data
#endif
#endif

extern struct proc_dir_entry *vtss_procfs_root_entry;

int vtss_procfs_init(void);
void vtss_procfs_cleanup(void);

const char *vtss_procfs_root_path(void);
void vtss_procfs_set_user(struct proc_dir_entry *pde, int uid, int gid);

int vtss_procfs_control_send(const char *msg, size_t size);
int vtss_procfs_control_wake_up(void);
void vtss_procfs_control_reset(void);

#endif
