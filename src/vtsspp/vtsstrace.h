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

#ifndef _VTSSTRACE_H_
#define _VTSSTRACE_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
//
// VTune Trace File Format
//
*/

/// Flags to initialize the mandatory flagword member of each trace record
#define VTSS_UEC_LEAF0           0x00000000
#define VTSS_UEC_LEAF1           0x02000000
#define VTSS_UEC_LEAF2           0x04000000
#define VTSS_UEC_LEAF3           0x06000000
#define VTSS_UEC_MAGIC           0x08000000
#define VTSS_UEC_SEQMARK         0x10000000
#define VTSS_UEC_VECTORED        0x20000000
#define VTSS_UEC_EXTENDED        0x40000000
#define VTSS_UEC_OVERFLOW        0x80000000

/// Leaf 1 flags
#define VTSS_UECL1_ACTIVITY      0x00000001
#define VTSS_UECL1_VRESIDX       0x00000002
#define VTSS_UECL1_CPUIDX        0x00000004
#define VTSS_UECL1_USRLVLID      0x00000008
#define VTSS_UECL1_CPUTSC        0x00000010
#define VTSS_UECL1_REALTSC       0x00000020
#define VTSS_UECL1_MUXGROUP      0x00000040
#define VTSS_UECL1_CPUEVENT      0x00000080
#define VTSS_UECL1_CHPSETEV      0x00000100
#define VTSS_UECL1_OSEVENT       0x00000200
#define VTSS_UECL1_EXECADDR      0x00000400
#define VTSS_UECL1_REFADDR       0x00000800
#define VTSS_UECL1_EXEPHYSADDR   0x00001000
#define VTSS_UECL1_REFPHYSADDR   0x00002000
#define VTSS_UECL1_TPIDX         0x00004000
#define VTSS_UECL1_TPADDR        0x00008000
#define VTSS_UECL1_PWREVENT      0x00010000
#define VTSS_UECL1_CPURECTSC     0x00020000
#define VTSS_UECL1_REALRECTSC    0x00040000
#define VTSS_UECL1_PADDING       0x00080000
#define VTSS_UECL1_UNKNOWN0      0x00100000
#define VTSS_UECL1_UNKNOWN1      0x00200000
#define VTSS_UECL1_SYSTRACE      0x00400000
#define VTSS_UECL1_LARGETRACE    0x00800000
#define VTSS_UECL1_USERTRACE     0x01000000

/// Leaf 1 extended flags
#define VTSS_UECL1_EXT_CPUFREQ   0x00000001

/// VTSS_UEC magic value
#define VTSS_UEC_MAGICVALUE      0xaddedefa

/// Activity flags
#define VTSS_UECACT_USERDEFINED  0x80000000
#define VTSS_UECACT_SWITCHFROM   0x00000000
#define VTSS_UECACT_SWITCHTO     0x00000001
#define VTSS_UECACT_SWITCHREALTO 0x00000002
#define VTSS_UECACT_SAMPLED      0x00000004
#define VTSS_UECACT_APC          0x00000008
#define VTSS_UECACT_EXCEPTION    0x00000010
#define VTSS_UECACT_INTERRUPT    0x00000020
#define VTSS_UECACT_PROBED       0x00000040
#define VTSS_UECACT_CODETRACE    0x00000080
#define VTSS_UECACT_FREQUENCY    0x00000100
#define VTSS_UECACT_MODULELOAD   0x00000200
#define VTSS_UECACT_MODULEUNLOAD 0x00000400
#define VTSS_UECACT_TRIGGERED    0x00000800
#define VTSS_UECACT_NEWTASK      0x00001000
#define VTSS_UECACT_OLDTASK      0x00002000
#define VTSS_UECACT_SYNCHRO      0x00004000
#define VTSS_UECACT_BTSOVFLW     0x00008000
#define VTSS_UECACT_NESTED       0x00010000  /// ORed with context switch activities
#define VTSS_UECACT_CALLBACK     0x00020000

/// Systrace types
#define VTSS_UECSYSTRACE_PROCESS_NAME        0
#define VTSS_UECSYSTRACE_STACK_SAMPLE32      1
#define VTSS_UECSYSTRACE_STACK_SAMPLE64      2
#define VTSS_UECSYSTRACE_MODULE_MAP32        3
#define VTSS_UECSYSTRACE_MODULE_MAP64        4
#define VTSS_UECSYSTRACE_INST_SAMPLE32       5
#define VTSS_UECSYSTRACE_INST_SAMPLE64       6
#define VTSS_UECSYSTRACE_STACK_INC32         7
#define VTSS_UECSYSTRACE_STACK_INC64         8
#define VTSS_UECSYSTRACE_STACK_EXT32         9
#define VTSS_UECSYSTRACE_STACK_EXT64        10
#define VTSS_UECSYSTRACE_STACK_INCEXT32     11
#define VTSS_UECSYSTRACE_STACK_INCEXT64     12
#define VTSS_UECSYSTRACE_STACK_CTX32_V0     13  /// full stack preceded with real esp:ebp
#define VTSS_UECSYSTRACE_STACK_CTX64_V0     14  /// full stack preceded with real rsp:rbp
#define VTSS_UECSYSTRACE_STACK_CTXINC32_V0  15  /// incremental stack preceded with real esp:ebp
#define VTSS_UECSYSTRACE_STACK_CTXINC64_V0  16  /// incremental stack preceded with real rsp:rbp
#define VTSS_UECSYSTRACE_SWCFG              17  /// software configuration record
#define VTSS_UECSYSTRACE_HWCFG              18  /// hardware configuration record
#define VTSS_UECSYSTRACE_FMTCFG             19  /// forward compatibility format record
#define VTSS_UECSYSTRACE_BRANCH_V0          20  /// branch trace record
#define VTSS_UECSYSTRACE_REGCTX32           21  /// register context for IA32 (PEBS)
#define VTSS_UECSYSTRACE_REGCTX32E          22  /// register context for EM64T (PEBS)
#define VTSS_UECSYSTRACE_REGCTX32_VEC       23  /// a vector of register contexts for IA32 (PEBS)
#define VTSS_UECSYSTRACE_REGCTX32E_VEC      24  /// a vector of register contexts for EM64T (PEBS)
#define VTSS_UECSYSTRACE_INDEX_LOCATOR      25  /// a record to locate trace indices
#define VTSS_UECSYSTRACE_INDEX_STREAM       26  /// a stream of trace index records
#define VTSS_UECSYSTRACE_CLEAR_STACK32      27  /// 32-bit call stack sequence
#define VTSS_UECSYSTRACE_CLEAR_STACK64      28  /// 64-bit call stack sequence
#define VTSS_UECSYSTRACE_EXECTX_V0          29  /// execution context for IA32/EM64T (register and memory contents)
#define VTSS_UECSYSTRACE_LOAD_JIT32         30  /// load JITted method
#define VTSS_UECSYSTRACE_UNLOAD_JIT32       31  /// unload JITted method
#define VTSS_UECSYSTRACE_LOAD_JIT64         32  /// load JITted method
#define VTSS_UECSYSTRACE_UNLOAD_JIT64       33  /// unload JITted method
#define VTSS_UECSYSTRACE_RESERVED_V0        34  /// to be further specified
#define VTSS_UECSYSTRACE_IPT                35  /// a record with a raw IPT data stream
#define VTSS_UECSYSTRACE_IPTCFG             36  /// a record with IPT configuration
#define VTSS_UECSYSTRACE_IPTIPS             37  /// a record with decoded IPT IPs from TIP/FUP packets
#define VTSS_UECSYSTRACE_IPTMNT             38  /// a record with decoded MNT packet payloads
#define VTSS_UECSYSTRACE_IPTOVF             39  /// a record to signal IPT data loss
#define VTSS_UECSYSTRACE_STACK_CTX32_V1     40  /// full stack preceded with esp:bottom (instead of fp)
#define VTSS_UECSYSTRACE_STACK_CTX64_V1     41  /// full stack preceded with  rsp:bottom (instead of fp)
#define VTSS_UECSYSTRACE_STACK_CTXINC32_V1  42  /// incremental stack preceded with  esp:bottom (instead of fp)
#define VTSS_UECSYSTRACE_STACK_CTXINC64_V1  43  /// incremental stack preceded with  rsp:bottom (instead of fp)
#define VTSS_UECSYSTRACE_COLCFG             44  /// collector configuration record
#define VTSS_UECSYSTRACE_SYSINFO            45  /// system information record
#define VTSS_UECSYSTRACE_STACK_CTX32_V2     46  /// full stack without sp and fp values (both equal exectx.sp)
#define VTSS_UECSYSTRACE_STACK_CTX64_V2     47  /// full stack without sp and fp values (both equal exectx.sp)
#define VTSS_UECSYSTRACE_STACK_CTXINC32_V2  48  /// incremental stack without sp and fp values (both equal exectx.sp)
#define VTSS_UECSYSTRACE_STACK_CTXINC64_V2  49  /// incremental stack without sp and fp values (both equal exectx.sp)
#define VTSS_UECSYSTRACE_STREAM_ZLIB        50  /// a record containing a stream compressed with ZLIB
#define VTSS_UECSYSTRACE_DEBUG              60  /// a record with debugging info in a human-readable format
#define VTSS_UECSYSTRACE_CPUINFO            61  /// a record with raw cpuid data collected for all CPUs

/// Module types for systrace (module map)
#define VTSS_MODTYPE_ELF        0x00    /// default Linux module type
#define VTSS_MODTYPE_COFF       0x01    /// default Windows module type
#define VTSS_MODTYPE_BIN        0x02    /// any non-structured executable region
#define VTSS_MODTYPE_JIT_FLAG   0x80    /// should be ORed with the actial JITted module type

// Pre-defined user record types
#define VTSS_URT_PARTIAL_RECORD 0x8000  /// indicates the next subsequent record
                                        /// should be appended to the current one
#define VTSS_URT_CALLSTACK_DATA 0x0000  /// a sequence of function IDs / addresses
#define VTSS_URT_FUNCMODID_MAP  0x0001  /// a map of IDs to functions and modules
#define VTSS_URT_ALTSTREAM      0x0002  /// wraps an alternative stream of user-level data
#define VTSS_URT_IMPORTS32      0x0003  /// recorded info on instrumented import functions
#define VTSS_URT_IMPORTS64      0x0004  /// recorded info on instrumented import functions
#define VTSS_URT_APIWRAP32_V0   0x0005  /// recorded info on instrumented API functions
#define VTSS_URT_APIWRAP64_V0   0x0006  /// recorded info on instrumented API functions
#define VTSS_URT_APIWRAP32_V1   0x0007  /// recorded info on instrumented API functions
#define VTSS_URT_APIWRAP64_V1   0x0008  /// recorded info on instrumented API functions
#define VTSS_URT_APIWRAP32_V2   0x0009  /// recorded info on instrumented API functions
#define VTSS_URT_APIWRAP64_V2   0x000a  /// recorded info on instrumented API functions

// Pre-defined system function IDs
#define VTSS_FID_ITT_PAUSE      0x0066  /// tpss_pi___itt_pause
#define VTSS_FID_ITT_RESUME     0x0067  /// tpss_pi___itt_resume
#define VTSS_FID_THREAD_NAME    0x011e  /// thread name

#ifdef __cplusplus
}
#endif

#endif
