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

#ifndef _VTSSTYPES_H_
#define _VTSSTYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
//
// VTSS Trace File Data Types
//
*/

#define VTSS_WINDOWS_IA32   0
#define VTSS_WINDOWS_IA64   1
#define VTSS_WINDOWS_EM64T  2

#define VTSS_LINUX_IA32     3
#define VTSS_LINUX_IA64     4
#define VTSS_LINUX_EM64T    5
#define VTSS_LINUX_KNC      6

#define VTSS_UNKNOWN_ARCH   0xff

#define VTSS_CFG_SPACE_SIZE 0x2000
#define VTSS_CFG_CHAIN_SIZE 0x0200
#define VTSS_CFG_CHAIN_SPACE_SIZE (16*VTSS_CFG_SPACE_SIZE)

#define VTSS_MAX_RECORD_SIZE 0xffff

#define VTSS_FMTCFG_RESERVED 0xf0   /// specified for bits unused in the trace being generated
                                    /// for format indicator bits specify the size of 0
#define VTSS_MAX_SAMPLES 32

#define VTSS_MAX_SYSCFG_FIELD_LEN (VTSS_CFG_SPACE_SIZE/4 - sizeof(short))

#pragma pack(push, 1)

/// defbit[i] specifies the size code for a corresponding syntax element as follows:
/// [76543210]
///  ||
///  |+------- reserved
///  +-------- 0: fixed-length element, bits 0-5 provide the size of a syntax element in bytes
///  +-------- 1: variable-length element, bits 0-2 specify the number of bytes at the
///               beginning of the element which, in their turn, provide the element's size
typedef struct
{
    unsigned char rank;
    unsigned int  and_mask;
    unsigned int  cmp_mask;
    unsigned char defcount;
    unsigned char defbit[0x20]; /// sizeof(flagword)

} vtss_fmtcfg_t;

typedef struct
{
    int version;

    short type;
    short major;
    short minor;
    short extra;
    short spack;

    union
    {
        short len;
        char host_name[0];
        char brand_name[0];
        char sysid_string[0];
        char system_root_dir[0];
        char placeholder[VTSS_CFG_SPACE_SIZE];
    };
    int record_size;

} vtss_syscfg_t;

typedef struct
{
    int version;

    unsigned long long cpu_freq;            /// Hz
    unsigned long long timer_freq;          /// realtsc, Hz
    unsigned long long maxusr_address;
    unsigned char os_sp;
    unsigned char os_minor;
    unsigned char os_major;
    unsigned char os_type;

    unsigned char mode;                     /// 32 or 64 bit
    unsigned char family;
    unsigned char model;
    unsigned char stepping;

    int cpu_no;
    struct
    {
        unsigned char node;
        unsigned char pack;
        unsigned char core;
        unsigned char thread;

    } cpus[NR_CPUS];   /// stored truncated to cpu_no elements

} vtss_hardcfg_t;

typedef struct
{
    int version;

    int cpu_no;
    struct
    {
        unsigned short leaf_no;
        struct
        {
            unsigned int in_eax;
            unsigned int in_ecx;
            unsigned int out_eax;
            unsigned int out_ebx;
            unsigned int out_ecx;
            unsigned int out_edx;

        } leafs[1];

    } cpus[NR_CPUS];   /// stored truncated to cpu_no elements

} vtss_cpuinfo_t;

typedef struct
{
    int version;

    unsigned int fratio;    /// MSR_PLATFORM_INFO[15:8]; max non-turbo ratio
    unsigned int ctcnom;    /// RATIO_P = CPUID[21].EBX / CPUID[21].EAX; ratio of ART/CTC to TSC
    unsigned int tscdenom;
    unsigned int mtcfreq;   /// IA32_RTIT_CTL.MTCFreq

} vtss_iptcfg_t;

/// common record
typedef struct
{
    unsigned int flagword;
    unsigned short size;
    unsigned short type;

} vtss_record_t;

/// collector configuration record
typedef struct
{
    unsigned int flagword;
    unsigned short size;
    unsigned short type;

    int version;

    short major;
    short minor;
    int   revision;
    unsigned long long features;

    unsigned char len;
    char name[0];

} vtss_colcfg_record_t;

/// software configuration record
typedef struct
{
    unsigned int flagword;
    unsigned int vresidx;
    unsigned short size;
    unsigned short type;

    int version;
    short int cpu_chain_len;

} vtss_softcfg_record_t;

/// time marker record
typedef struct
{
    unsigned int flagword;
    unsigned int vectored;
    unsigned char vec_no;
    unsigned long long tsc;
    unsigned long long utc;

} vtss_time_marker_record_t;

/// 64 bit module record
typedef struct
{
    unsigned int flagword;
    unsigned int pid;
    unsigned int tid;
    unsigned long long cputsc;
    unsigned long long realtsc;
    unsigned short size;
    unsigned short type;

    unsigned long long start;
    unsigned long long end;
    unsigned long long offset;
    unsigned char bin;
    unsigned short len;

} vtss_module64_record_t;

/// 32 bit module record
typedef struct
{
    unsigned int flagword;
    unsigned int pid;
    unsigned int tid;
    unsigned long long cputsc;
    unsigned long long realtsc;
    unsigned short size;
    unsigned short type;

    unsigned int start;
    unsigned int end;
    unsigned int offset;
    unsigned char bin;
    unsigned short len;

} vtss_module32_record_t;

// thread start/stop record
typedef struct
{
    unsigned int flagword;
    unsigned int activity;
    unsigned int residx;
    unsigned int cpuidx;
    unsigned int pid;
    unsigned int tid;
    unsigned long long cputsc;
    unsigned long long realtsc;

} vtss_thread_record_t;

// context switch-to record
typedef struct
{
    unsigned int flagword;
    unsigned int activity;
    unsigned int residx;
    unsigned int cpuidx;
    unsigned long long cputsc;
    unsigned long long realtsc;
    unsigned long long execaddr;

} vtss_switch_to_record_t;

// context switch-from record
typedef struct
{
    unsigned int flagword;
    unsigned int activity;
    unsigned int cpuidx;
    unsigned long long cputsc;
    unsigned long long realtsc;

} vtss_switch_from_record_t;

// process exec/exit record
typedef struct
{
    unsigned int flagword;
    unsigned int activity;
    unsigned int cpuidx;
    unsigned int pid;
    unsigned int tid;
    unsigned long long cputsc;
    unsigned long long realtsc;
    unsigned short size;
    unsigned short type;

} vtss_process_record_t;

/// kernel stack record
typedef struct
{
    unsigned int flagword;
    unsigned int residx;
    unsigned short size;
    unsigned short type;

    unsigned int idx;

} vtss_kernel_stack_record_t;

/// clear stack record
typedef struct
{
    unsigned int flagword;
    unsigned int residx;
    unsigned int cpuidx;
    unsigned long long cputsc;
    unsigned long long execaddr;
    unsigned short size;
    unsigned short type;
    unsigned int merge_node;

} vtss_clear_stack_record_t;

/// stack record
typedef struct
{
    unsigned int flagword;
    unsigned int residx;
    unsigned int cpuidx;
    unsigned long long cputsc;
    unsigned long long execaddr;
    unsigned short size;
    unsigned short type;

    union
    {
        struct
        {
            unsigned long long sp64;
            unsigned long long fp64;
        };
        struct
        {
            unsigned int sp32;
            unsigned int fp32;
        };
    };

} vtss_stack_record_t;

/// large stack record
typedef struct
{
    unsigned int flagword;
    unsigned int residx;
    unsigned int cpuidx;
    unsigned long long cputsc;
    unsigned long long execaddr;
    unsigned int size;
    unsigned short type;

    union
    {
        struct
        {
            unsigned long long sp64;
            unsigned long long fp64;
        };
        struct
        {
            unsigned int sp32;
            unsigned int fp32;
        };
    };

} vtss_large_stack_record_t;

/// sample record
typedef struct
{
    unsigned int flagword;
    unsigned int vectored;
    unsigned int activity;
    unsigned int residx;
    unsigned int cpuidx;
    unsigned long long cputsc;
    unsigned char muxgroup;
    unsigned char event_no;

} vtss_sample_record_t;

/// CPU event record
typedef struct
{
    unsigned int flagword;
    unsigned int vectored;
    unsigned int residx;
    unsigned int cpuidx;
    unsigned long long cputsc;
    unsigned char muxgroup;
    unsigned char event_no;

} vtss_cpuevent_record_t;

/// probe record
typedef struct
{
    unsigned int flagword;
    unsigned int activity;
    unsigned int residx;
    unsigned int cpuidx;
    unsigned long long cputsc;
    unsigned short size;
    unsigned short type;
    unsigned long long entry_tsc;
    unsigned int entry_cpu;
    unsigned int fid;

} vtss_probe_record_t;

/// thread name record
typedef struct
{
    vtss_probe_record_t probe;
    unsigned char version;
    unsigned short length;

} vtss_thread_name_record_t;

/// IPT dump/overflow record
typedef struct
{
    unsigned int flagword;
    unsigned int residx;
    unsigned int cpuidx;
    unsigned long long cputsc;
    unsigned short size;
    unsigned short type;

} vtss_ipt_record_t;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
