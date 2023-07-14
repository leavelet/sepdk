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

#ifndef _VTSS_TRACEPOINT_H_
#define _VTSS_TRACEPOINT_H_

#include "config.h"
#include "debug.h"
#include "ksyms.h"

#include <linux/tracepoint.h>

#ifdef VTSS_TRACEPOINTS
#ifdef VTSS_AUTOCONF_TRACEPOINT_PROBE
#ifdef VTSS_AUTOCONF_FOR_EACH_KERNEL_TRACEPOINT
#define vtss_tracepoint_name(tp) (tp)->name
#define VTSS_DEFINE_TRACEPOINT(name)\
static int vtss_tracepoint_##name##_registered = false;\
static void vtss_tracepoint_register_##name##_cb(struct tracepoint *tp, void *priv)\
{\
	if (strcmp(vtss_tracepoint_name(tp), #name) == 0) {\
		int rc = tracepoint_probe_register(tp, vtss_tracepoint_##name, NULL);\
		if (rc) vtss_pr_warning("Failed to register '"#name"' tracepoint");\
		else vtss_pr_notice("Registered '"#name"' tracepoint");\
		*(int *)priv = rc;\
	}\
}\
static int vtss_tracepoint_register_##name(void)\
{\
	int rc = -ENOENT;\
	for_each_kernel_tracepoint(vtss_tracepoint_register_##name##_cb, &rc);\
	if (rc == -ENOENT) vtss_pr_warning("Failed to find '"#name"' tracepoint");\
	vtss_tracepoint_##name##_registered = !rc;\
	return rc;\
}\
static void vtss_tracepoint_unregister_##name##_cb(struct tracepoint *tp, void *priv)\
{\
	if (strcmp(vtss_tracepoint_name(tp), #name) == 0) {\
		int rc = tracepoint_probe_unregister(tp, vtss_tracepoint_##name, NULL);\
		if (rc) vtss_pr_warning("Failed to unregister '"#name"' tracepoint");\
	}\
}\
static void vtss_tracepoint_unregister_##name(void)\
{\
	if (vtss_tracepoint_##name##_registered) {\
		for_each_kernel_tracepoint(vtss_tracepoint_unregister_##name##_cb, NULL);\
	}\
}
#elif defined (VTSS_KALLSYMS)
#define VTSS_DEFINE_TRACEPOINT(name)\
static int vtss_tracepoint_##name##_registered = false;\
static int vtss_tracepoint_register_##name(void)\
{\
	int rc;\
	if (vtss_ksyms_tracepoint_##name) {\
		rc = tracepoint_probe_register(vtss_ksyms_tracepoint_##name,\
					       vtss_tracepoint_##name, NULL);\
		if (rc) vtss_pr_warning("Failed to register '"#name"' tracepoint");\
		else vtss_pr_notice("Registered '"#name"' tracepoint");\
	} else {\
		vtss_pr_warning("Failed to find '"#name"' tracepoint");\
		rc = -ENOENT;\
	}\
	vtss_tracepoint_##name##_registered = !rc;\
	return rc;\
}\
static void vtss_tracepoint_unregister_##name(void)\
{\
	if (vtss_tracepoint_##name##_registered) {\
		int rc = tracepoint_probe_unregister(vtss_ksyms_tracepoint_##name,\
						     vtss_tracepoint_##name, NULL);\
		if (rc) vtss_pr_warning("Failed to unregister '"#name"' tracepoint");\
	}\
}
#else
#define VTSS_DEFINE_TRACEPOINT(name)\
static int vtss_tracepoint_register_##name(void)\
{\
	return -ENOENT;\
}\
static void vtss_tracepoint_unregister_##name(void)\
{\
}
#endif
#else
#define VTSS_DEFINE_TRACEPOINT(name)\
static int vtss_tracepoint_##name##_registered = false;\
static int vtss_tracepoint_register_##name(void)\
{\
	int rc = register_trace_##name(vtss_tracepoint_##name, NULL);\
	if (rc) vtss_pr_warning("Failed to register '"#name"' tracepoint");\
	else vtss_pr_notice("Registered '"#name"' tracepoint");\
	vtss_tracepoint_##name##_registered = !rc;\
	return rc;\
}\
static void vtss_tracepoint_unregister_##name(void)\
{\
	if (vtss_tracepoint_##name##_registered) {\
		int rc = unregister_trace_##name(vtss_tracepoint_##name, NULL);\
		if (rc) vtss_pr_warning("Failed to unregister '"#name"' tracepoint");\
	}\
}
#endif
#else
#define VTSS_DEFINE_TRACEPOINT(name)\
static int __maybe_unused vtss_tracepoint_##name##_registered = false;\
static int vtss_tracepoint_register_##name(void)\
{\
	return -ENOENT;\
}\
static void vtss_tracepoint_unregister_##name(void)\
{\
}
#endif

#endif
