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

#ifndef _VTSS_CMD_H_
#define _VTSS_CMD_H_

#include "config.h"

extern uid_t vtss_session_uid;
extern gid_t vtss_session_gid;

#define VTSS_COLLECTOR_ABORTING -2
#define VTSS_COLLECTOR_STOPPING -1
#define VTSS_COLLECTOR_STOPPED   0
#define VTSS_COLLECTOR_STARTING  1
#define VTSS_COLLECTOR_RUNNING   2
#define VTSS_COLLECTOR_PAUSED    3

extern atomic_t vtss_collector_state;

#define vtss_collector_aborting() (atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_ABORTING)
#define vtss_collector_stopping() (atomic_read(&vtss_collector_state) <= VTSS_COLLECTOR_STOPPING)
#define vtss_collector_stopped()  (atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_STOPPED)
#define vtss_collector_started()  (atomic_read(&vtss_collector_state) >= VTSS_COLLECTOR_RUNNING)
#define vtss_collector_running()  (atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_RUNNING)
#define vtss_collector_paused()   (atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_PAUSED)

int vtss_cmd_start(void);
int vtss_cmd_stop(void);
int vtss_cmd_abort(void);
int vtss_cmd_pause(void);
int vtss_cmd_resume(void);
int vtss_cmd_attach(pid_t pid);

#endif
