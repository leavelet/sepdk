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

#ifndef _VTSS_RECORD_H_
#define _VTSS_RECORD_H_

#include "config.h"
#include "pmu.h"
#include "transport.h"

int vtss_transport_write_debug(struct vtss_transport *trn, const char *fmt, ...);
int vtss_transport_write_process_exec(struct vtss_transport *trn, const char *name,
				      pid_t tid, pid_t pid, int cpu);
int vtss_transport_write_process_exit(struct vtss_transport *trn, const char *name,
				      pid_t tid, pid_t pid, int cpu);
int vtss_transport_write_thread_start(struct vtss_transport *trn, pid_t tid, pid_t pid, int cpu);
int vtss_transport_write_thread_stop(struct vtss_transport *trn, pid_t tid, pid_t pid, int cpu);
int vtss_transport_write_thread_name(struct vtss_transport *trn, const char *name, pid_t tid);
int vtss_transport_write_switch_from(struct vtss_transport *trn, int cpu, bool preempt);
int vtss_transport_write_switch_to(struct vtss_transport *trn, pid_t tid, int cpu,
				   unsigned long ip);
int vtss_transport_write_sample(struct vtss_transport *trn, pid_t tid, int cpu,
				struct vtss_pmu_events *events, unsigned long ip);
int vtss_transport_write_module(struct vtss_transport *trn, const char *name, bool m32,
				unsigned long start, unsigned long end, unsigned long pgoff,
				unsigned long long cputsc, unsigned long long realtsc);
int vtss_transport_write_configs(struct vtss_transport *trn, int m32);
int vtss_transport_write_softcfg(struct vtss_transport *trn, pid_t tid);
int vtss_transport_write_probe(struct vtss_transport *trn, int cpu, int fid);
int vtss_transport_write_probe_all(int cpu, int fid);

#endif
