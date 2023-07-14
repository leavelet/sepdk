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

#ifndef _VTSS_KPROBES_H_
#define _VTSS_KPROBES_H_

#include "config.h"
#include "debug.h"

#include <linux/kprobes.h>

#ifdef VTSS_KPROBES
#define VTSS_DEFINE_KPROBE(name)\
static struct kprobe vtss_kp_##name;\
static int vtss_kprobe_register_##name(const char *symbol)\
{\
	int rc;\
	memset(&vtss_kp_##name, 0, sizeof(struct kprobe));\
	vtss_kp_##name.symbol_name = symbol;\
	vtss_kp_##name.pre_handler = vtss_kprobe_##name;\
	rc = register_kprobe(&vtss_kp_##name);\
	if (rc) {\
		vtss_pr_debug_probe("Failed to register '%s' kprobe", symbol);\
		vtss_kp_##name.addr = NULL;\
	}\
	else vtss_pr_notice("Registered '%s' kprobe", symbol);\
	return rc;\
}\
static void vtss_kprobe_unregister_##name(void)\
{\
	if (vtss_kp_##name.addr) {\
		unregister_kprobe(&vtss_kp_##name);\
		vtss_kp_##name.addr = NULL;\
	}\
}
#else
#define VTSS_DEFINE_KPROBE(name)\
static int vtss_kprobe_register_##name(const char *symbol)\
{\
	return -ENOENT;\
}\
static void vtss_kprobe_unregister_##name(void)\
{\
}
#endif

#ifdef VTSS_KPROBES
#define VTSS_DEFINE_KRETPROBE(name, size)\
static struct kretprobe vtss_rp_##name;\
static int vtss_kretprobe_register_##name(const char *symbol)\
{\
	int rc;\
	memset(&vtss_rp_##name, 0, sizeof(struct kretprobe));\
	vtss_rp_##name.kp.symbol_name = symbol;\
	vtss_rp_##name.entry_handler = vtss_kretprobe_##name##_enter;\
	vtss_rp_##name.handler = vtss_kretprobe_##name##_leave;\
	vtss_rp_##name.data_size = size;\
	vtss_rp_##name.maxactive = 32; /* probe up to 32 instances concurrently */\
	rc = register_kretprobe(&vtss_rp_##name);\
	if (rc) {\
		vtss_pr_debug_probe("Failed to register '%s' kretprobe", symbol);\
		vtss_rp_##name.kp.addr = NULL;\
	}\
	else vtss_pr_notice("Registered '%s' kretprobe", symbol);\
	return rc;\
}\
static void vtss_kretprobe_unregister_##name(void)\
{\
	if (vtss_rp_##name.kp.addr) {\
		unregister_kretprobe(&vtss_rp_##name);\
		vtss_rp_##name.kp.addr = NULL;\
		if (vtss_rp_##name.nmissed) {\
			vtss_pr_warning("Missed probing of '"#name"' %d times",\
					vtss_rp_##name.nmissed);\
		}\
	}\
}
#else
#define VTSS_DEFINE_KRETPROBE(name, size)\
static int vtss_kretprobe_register_##name(const char *symbol)\
{\
	return -ENOENT;\
}\
static void vtss_kretprobe_unregister_##name(void)\
{\
}
#endif

#ifdef VTSS_AUTOCONF_JPROBE
#define VTSS_DEFINE_JPROBE(name)\
static struct jprobe vtss_jp_##name;\
static int vtss_jprobe_register_##name(const char *symbol)\
{\
	int rc;\
	memset(&vtss_jp_##name, 0, sizeof(struct jprobe));\
	vtss_jp_##name.kp.symbol_name = symbol;\
	vtss_jp_##name.entry = vtss_jprobe_##name;\
	rc = register_jprobe(&vtss_jp_##name);\
	if (rc) {\
		vtss_pr_debug_probe("Failed to register '%s' jprobe", symbol);\
		vtss_jp_##name.kp.addr = NULL;\
	}\
	else vtss_pr_notice("Registered '%s' jprobe", symbol);\
	return rc;\
}\
static void vtss_jprobe_unregister_##name(void)\
{\
	if (vtss_jp_##name.kp.addr) {\
		unregister_jprobe(&vtss_jp_##name);\
		vtss_jp_##name.kp.addr = NULL;\
	}\
}
#endif

#endif
