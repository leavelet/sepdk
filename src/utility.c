/****
    Copyright (C) 2005 Intel Corporation.  All Rights Reserved.

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
****/





#include "lwpmudrv_defines.h"
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <asm/msr.h>
#include <linux/ptrace.h>
#include <linux/time.h>
#include <linux/vmalloc.h>

#include "lwpmudrv_defines.h"
#include "lwpmudrv_types.h"
#include "rise_errors.h"
#include "lwpmudrv_ecb.h"
#include "lwpmudrv.h"
#include "core2.h"
#include "silvermont.h"
#include "perfver4.h"
#include "valleyview_sochap.h"
#include "unc_gt.h"
#include "haswellunc_sa.h"
#include "utility.h"

#include "control.h"

volatile int         config_done;
extern DISPATCH_NODE unc_msr_dispatch;
extern DISPATCH_NODE unc_pci_dispatch;
extern DISPATCH_NODE unc_mmio_single_bar_dispatch;
extern DISPATCH_NODE unc_mmio_multiple_bar_dispatch;
extern DISPATCH_NODE unc_mmio_fpga_dispatch;
extern DISPATCH_NODE unc_mmio_pmm_dispatch;
extern DISPATCH_NODE unc_power_dispatch;
extern DISPATCH_NODE unc_rdt_dispatch;
extern DISPATCH_NODE hswunc_sa_dispatch;

#if defined(DRV_PMT_ENABLE)
extern DISPATCH_NODE unc_pmt_dispatch;
#endif
extern U32 drv_type;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
extern char sym_lookup_func_addr[17];
#else
extern char *sym_lookup_func_addr;
#endif
typedef unsigned long (*sym_lookup_func)(char const *);
static unsigned long (*kallsyms_lookup_name_local)(char const *);
#endif

extern VOID
UTILITY_down_read_mm(struct mm_struct *mm)
{
	SEP_DRV_LOG_TRACE_IN("Mm: %p.", mm);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
	down_read((struct rw_semaphore *)&mm->mmap_sem);
#else
	down_read((struct rw_semaphore *)&mm->mmap_lock);
#endif

	SEP_DRV_LOG_TRACE_OUT("");
	return;
}

extern VOID
UTILITY_up_read_mm(struct mm_struct *mm)
{
	SEP_DRV_LOG_TRACE_IN("Mm: %p.", mm);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
	up_read((struct rw_semaphore *)&mm->mmap_sem);
#else
	up_read((struct rw_semaphore *)&mm->mmap_lock);
#endif

	SEP_DRV_LOG_TRACE_OUT("");
	return;
}

// NOT to be instrumented, used inside DRV_LOG!
extern VOID
UTILITY_Read_TSC(U64 *pTsc)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	*pTsc = rdtsc_ordered();
#else
	rdtscll(*(pTsc));
#endif

	return;
}

/* ------------------------------------------------------------------------- */
/*!
 * @fn       VOID UTILITY_Read_Cpuid
 *
 * @brief    executes the cpuid_function of cpuid and returns values
 *
 * @param  IN   cpuid_function
 *         OUT  rax  - results of the cpuid instruction in the
 *         OUT  rbx  - corresponding registers
 *         OUT  rcx
 *         OUT  rdx
 *
 * @return   none
 *
 * <I>Special Notes:</I>
 *              <NONE>
 *
 */
extern VOID
UTILITY_Read_Cpuid(U64  cpuid_function,
		   U64 *rax_value,
		   U64 *rbx_value,
		   U64 *rcx_value,
		   U64 *rdx_value)
{
	U32  function = (U32)cpuid_function;
	U32 *eax      = (U32 *)rax_value;
	U32 *ebx      = (U32 *)rbx_value;
	U32 *ecx      = (U32 *)rcx_value;
	U32 *edx      = (U32 *)rdx_value;

	SEP_DRV_LOG_TRACE_IN(
		"Fn: %llu, rax_p: %p, rbx_p: %p, rcx_p: %p, rdx_p: %p.",
		cpuid_function, rax_value, rbx_value, rcx_value, rdx_value);

	*eax = function;

	__asm__("cpuid"
		: "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
		: "a"(function), "b"(*ebx), "c"(*ecx), "d"(*edx));

	SEP_DRV_LOG_TRACE_OUT("");
	return;
}

/* ------------------------------------------------------------------------- */
/*!
 * @fn       VOID UTILITY_Configure_CPU
 *
 * @brief    Reads the CPU information from the hardware
 *
 * @param    param   dispatch_id -  The id of the dispatch table.
 *
 * @return   Pointer to the correct dispatch table for the CPU architecture
 *
 * <I>Special Notes:</I>
 *              <NONE>
 */
extern DISPATCH
UTILITY_Configure_CPU(U32 dispatch_id)
{
	DISPATCH dispatch = NULL;

	SEP_DRV_LOG_TRACE_IN("Dispatch_id: %u.", dispatch_id);

	switch (dispatch_id) {
	case 6:
		SEP_DRV_LOG_INIT("Set up the Silvermont dispatch table.");
		dispatch = &silvermont_dispatch;
		break;
	case 7:
		SEP_DRV_LOG_INIT(
			"Set up the perfver4 HTON dispatch table such as Skylake.");
		dispatch = &perfver4_dispatch;
		break;
	case 8:
		SEP_DRV_LOG_INIT(
			"Set up the perfver4 HTOFF dispatch table such as Skylake.");
		dispatch = &perfver4_dispatch_htoff_mode;
		break;
	case 11:
		SEP_DRV_LOG_INIT(
			"Set up the perfver4 NONHT dispatch table such as Icelake.");
		dispatch = &perfver4_dispatch_nonht_mode;
		break;
	case 700:
	case 701:
	case 1100:
		SEP_DRV_LOG_INIT("Set up the Valleyview SA dispatch table.");
		dispatch = &valleyview_visa_dispatch;
		break;
	case 2:
		SEP_DRV_LOG_INIT(
			"Set up the Core i7(TM) processor dispatch table.");
		dispatch = &corei7_dispatch;
		break;
	case 3:
		SEP_DRV_LOG_INIT("Set up the Core i7(TM) dispatch table.");
		dispatch = &corei7_dispatch_htoff_mode;
		break;
	case 10:
		SEP_DRV_LOG_INIT("Set up the Knights family dispatch table.");
		dispatch = &knights_dispatch;
		break;
	case 100:
		SEP_DRV_LOG_INIT("Set up the MSR based uncore dispatch table.");
		dispatch = &unc_msr_dispatch;
		break;
	case 110:
		SEP_DRV_LOG_INIT("Set up the PCI Based Uncore dispatch table.");
		dispatch = &unc_pci_dispatch;
		break;
	case 120:
		SEP_DRV_LOG_INIT(
			"Set up the MMIO based single bar uncore dispatch table.");
		dispatch = &unc_mmio_single_bar_dispatch;
		break;
	case 121:
		SEP_DRV_LOG_INIT(
			"Set up the MMIO based uncore dispatch table for FPGA.");
		dispatch = &unc_mmio_fpga_dispatch;
		break;
	case 122:
		SEP_DRV_LOG_INIT(
			"Set up the MMIO based multiple bar uncore dispatch table.");
		dispatch = &unc_mmio_multiple_bar_dispatch;
		break;
	case 123:
		SEP_DRV_LOG_INIT(
			"Set up the MMIO based uncore dispatch table for PMM.");
		dispatch = &unc_mmio_pmm_dispatch;
		break;
	case 130:
		SEP_DRV_LOG_INIT("Set up the Uncore Power dispatch table.");
		dispatch = &unc_power_dispatch;
		break;
	case 131:
		SEP_DRV_LOG_INIT("Set up the Uncore RDT dispatch table.");
		dispatch = &unc_rdt_dispatch;
		break;
	case 230:
		SEP_DRV_LOG_INIT("Set up the Haswell SA dispatch table.");
		dispatch = &hswunc_sa_dispatch;
		break;
	case 400:
		SEP_DRV_LOG_INIT("Set up the GT dispatch table.");
		dispatch = &unc_gt_dispatch;
		break;

#if defined(DRV_PMT_ENABLE)
	case 500:
		SEP_DRV_LOG_INIT("Set up the PMT UNC dispatch table.");
		dispatch = &unc_pmt_dispatch;
		break;
#endif
	default:
		dispatch = NULL;
		SEP_DRV_LOG_ERROR(
			"Architecture not supported (dispatch_id: %d).",
			dispatch_id);
		break;
	}

	SEP_DRV_LOG_TRACE_OUT("Res: %p.", dispatch);
	return dispatch;
}

#if defined(DRV_USE_RDPMC)
/* ------------------------------------------------------------------------- */
/*!
 * @fn          U64 SYS_Read_PMC (IN int ctr_addr, IN U32 is_fixed_reg)
 * @brief       Wrapper function of read perfmon counters
 *
 * @param       ctr_addr - counter address
 *              is_fixed_reg - flag to indicate if counter is fixed or GP
 *
 * @return      Counter value
 *
 * <I>Special Notes:</I>
 *      Counter relative index from base is specified in bits [29:0]
 *      If fixed register is requested, bit 30 of input operand must be additionally set
 *
 */
extern U64
SYS_Read_PMC_opt(U32 ctr_addr, U32 is_fixed_ctr)
{
#if !defined(rdpmcl)
	U32 low  = 0;
	U32 high = 0;
#endif
	U64 val     = 0;
	int counter = 0;

	if (is_fixed_ctr) {
		counter = (1ULL << RDPMC_COUNTER_TYPE_BIT_SHIFT);
		counter |= ctr_addr - IA32_FIXED_CTR0;
	} else {
		counter |= ctr_addr - IA32_PMC0;
	}
	SEP_DRV_LOG_REGISTER_IN("Will read counter 0x%x, rdpmc ctr_index %d.",
				ctr_addr, counter);
#if defined(rdpmcl)
	rdpmcl(counter, val);
#else
	rdpmc(counter, low, high);
	val = ((U64)high << 32) | low;
#endif
	SEP_DRV_LOG_REGISTER_OUT("Has read counter 0x%x: %llu.", ctr_addr, val);

	return val;
}
#endif

extern U64
SYS_Read_MSR_With_Status(U32 msr, S32 *status)
{
	U64 val = 0;
	int error;

	if (status) {
		*status = 0;
	}

#if defined(DRV_SAFE_MSR)
	SEP_DRV_LOG_REGISTER_IN("Will safely read MSR 0x%x.", msr);
#else
	SEP_DRV_LOG_REGISTER_IN("Will read MSR 0x%x.", msr);
#endif

	if (!msr) {
		SEP_DRV_LOG_WARNING("Ignoring MSR address is 0.");
		return 0ULL;
	}

#if defined(DRV_SAFE_MSR)
	error = rdmsrl_safe(msr, &val);
	if (error) {
		if (status) {
			*status = error;
		}
		SEP_DRV_LOG_ERROR("Failed to read MSR 0x%x.", msr);
	}
	SEP_DRV_LOG_REGISTER_OUT("Has read MSR 0x%x: 0x%llx (error: %d).", msr,
				 val, error);
#else
	rdmsrl(msr, val);
	SEP_DRV_LOG_REGISTER_OUT("Has read MSR 0x%x: 0x%llx.", msr, val);
#endif

	return val;
}

extern void
SYS_Write_MSR_With_Status(U32 msr, U64 val, S32 *status)
{
	int error;

	if (status) {
		*status = 0;
	}

#if defined(DRV_SAFE_MSR)
	SEP_DRV_LOG_REGISTER_IN("Will safely write MSR 0x%x: 0x%llx.", msr,
				val);
#else
	SEP_DRV_LOG_REGISTER_IN("Will write MSR 0x%x: 0x%llx.", msr, val);
#endif

	if (!msr) {
		SEP_DRV_LOG_WARNING("Ignoring MSR address is 0.");
		return;
	}

#if defined(DRV_SAFE_MSR)
	error = wrmsr_safe(msr, (U32)val, (U32)(val >> 32));
	if (error) {
		if (status) {
			*status = error;
		}
		SEP_DRV_LOG_ERROR("Failed to write MSR 0x%x: 0x%llx.", msr,
				  val);
	}
	SEP_DRV_LOG_REGISTER_OUT("Wrote MSR 0x%x: 0x%llx (error: %d).", msr,
				 val, error);

#else // !DRV_SAFE_MSR
#if defined(DRV_IA32)
	wrmsr(msr, (U32)val, (U32)(val >> 32));
#endif
#if defined(DRV_EM64T)
	wrmsrl(msr, val);
#endif
	SEP_DRV_LOG_REGISTER_OUT("Wrote MSR 0x%x: 0x%llx.", msr, val);

#endif // !DRV_SAFE_MSR
}

#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
static unsigned long utility_Compare_Symbol_Names_Return_Value = 0;
/* ------------------------------------------------------------------------- */
/*!
 * @fn       static int utility_Compare_Symbol_Names (void* ref_name const char* symbol_name, struct module* dummy, unsigned long symbol_address)
 *
 * @brief    Comparator for kallsyms_on_each_symbol.
 *
 * @param    void         * ref_name        : Symbol we are looking for
 *           const char   * symbol_name     : Name of the current symbol being evaluated
 *           struct module* dummy           : Pointer to the module structure. Not needed.
 *           unsigned long  symbol_address  : Address of the current symbol being evaluated
 *
 * @return   1 if ref_name matches symbol_name, 0 otherwise. Fills utility_Compare_Symbol_Names_Return_Value with the symbol's address on success.
 *
 * <I>Special Notes:</I>
 *           Only used as a callback comparator for kallsyms_on_each_symbol.
 */
static int
utility_Compare_Symbol_Names(void          *ref_name,
			     char const    *symbol_name,
			     struct module *dummy,
			     unsigned long  symbol_address)
{
	int res = 0;

	SEP_DRV_LOG_TRACE_IN(
		"Ref_name: %p, symbol_name: %p, dummy: %p, symbol_address: %u.",
		ref_name, symbol_name, dummy, symbol_address);

	if (strcmp((char *)ref_name, symbol_name) == 0) {
		utility_Compare_Symbol_Names_Return_Value = symbol_address;
		res                                       = 1;
	}

	SEP_DRV_LOG_TRACE_OUT("Res: %u.", res);
	return res;
}
#endif

/*
 * @fn       extern void UTILITY_Init_Symbol (void)
 *
 * @brief    Finds the address of the kernel symbols the driver depends on.
 *
 * @param    void
 *
 * @return   void
 */
extern void
UTILITY_Init_Symbol(void)
{
        U64 rbx, rcx, rdx, num_basic_functions;
	U64 cet_val = 0ULL;
        S32 msr_status;
	U64 kallsyms_lookup_ptr = 0;

	SEP_DRV_LOG_TRACE_IN("");

	num_basic_functions = 0;
	rbx = 0;
	rcx = 0;
	rdx = 0;

	ibt_status = DRV_SETUP_INFO_IBT_UNAVAILABLE;
	UTILITY_Read_Cpuid(0x7, &num_basic_functions, &rbx, &rcx, &rdx);
	if ((rdx >> 20) & 0x1) {
		cet_val = SYS_Read_MSR_With_Status(IA32_S_CET, &msr_status);
		if (!msr_status) {
			if ((cet_val >> 2) & 0x1) {
				ibt_status = DRV_SETUP_INFO_IBT_ENABLED;
			} else {
				ibt_status = DRV_SETUP_INFO_IBT_AVAILABLE;
			}
		}
	}
	if (ibt_status == DRV_SETUP_INFO_IBT_ENABLED) {
		SYS_Write_MSR(IA32_S_CET, cet_val & (~CET_IBT_EN));
	}
	kallsyms_lookup_ptr = UTILITY_Find_Symbol("kallsyms_lookup_name");

	SEP_DRV_LOG_TRACE("kallsyms_lookup_name address: 0x%lx",
		kallsyms_lookup_ptr);

	if (!kallsyms_lookup_ptr) {
		kallsyms_lookup_available = FALSE;
	} else {
		kallsyms_lookup_available = TRUE;
		kaiser_enabled_ptr_addr = UTILITY_Find_Symbol("kaiser_enabled");
		kaiser_pti_option_addr = UTILITY_Find_Symbol("pti_option");

		dyn_addr = UTILITY_Find_Symbol("_text");
		if (!dyn_addr) {
			dyn_addr = UTILITY_Find_Symbol("_stext");
		}

		kaiser_add_mapping_addr = UTILITY_Find_Symbol("kaiser_add_mapping");
		kaiser_remove_mapping_addr = UTILITY_Find_Symbol("kaiser_remove_mapping");
		cea_set_pte_addr = UTILITY_Find_Symbol("cea_set_pte");
		do_kernel_range_flush_addr = UTILITY_Find_Symbol("do_kernel_range_flush");
	}

	if (ibt_status == DRV_SETUP_INFO_IBT_ENABLED) {
		SYS_Write_MSR(IA32_S_CET, cet_val);
	}

	SEP_DRV_LOG_TRACE_OUT("");
}


/* ------------------------------------------------------------------------- */
/*!
 * @fn       extern unsigned long UTILITY_Find_Symbol (const char* name)
 *
 * @brief    Finds the address of the specified kernel symbol.
 *
 * @param    const char* name - name of the symbol to look for
 *
 * @return   Symbol address (0 if could not find)
 *
 * <I>Special Notes:</I>
 *           This wrapper is needed due to kallsyms_lookup_name not being exported
 *           in kernel version 2.6.32.*.
 *           Careful! This code is *NOT* multithread-safe or reentrant! Should only
 *           be called from 1 context at a time!
 */
extern unsigned long
UTILITY_Find_Symbol(char const *name)
{
	unsigned long res = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	int           ret;
	unsigned long addr = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	char buf[MAXNAMELEN];
#endif
#endif

	SEP_DRV_LOG_TRACE_IN(
		"Name: %p.",
		name); // Not printing the name to follow the log convention: *must not* dereference any pointer in an 'IN' message

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	if (!kallsyms_lookup_name_local) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		if (!sym_lookup_func_addr) {
			SEP_DRV_LOG_TRACE_OUT("sym_lookup_func_addr is NULL");
			return res;
		}
#endif
		ret = kstrtoul(sym_lookup_func_addr, 16, &addr);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#if defined(CONFIG_KALLSYMS)
		sprint_symbol(buf, addr);

		if (strstr(buf, "kallsyms_lookup_name")) {
			SEP_DRV_LOG_TRACE(
				"Found the address of kallsyms_lookup_name: 0x%lx",
				addr);
		} else {
			SEP_DRV_LOG_WARNING(
				"Failed to verify the param address 0x%lx is for kallsyms_lookup_name function",
				addr);
		}
#else
		SEP_DRV_LOG_WARNING(
			"Could not verify the param address 0x%lx because KALLSYSMS kernel config is not enabled",
			addr);
#endif
#endif

		if (!ret) {
			kallsyms_lookup_name_local = ((sym_lookup_func)addr);
		}
	}
#endif

#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
	if (kallsyms_on_each_symbol(utility_Compare_Symbol_Names,
				    (void *)name)) {
		res = utility_Compare_Symbol_Names_Return_Value;
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	if (kallsyms_lookup_name_local) {
		SEP_DRV_LOG_TRACE("kallsyms_lookup_name 0x%lx",
				  (unsigned long)kallsyms_lookup_name_local);
		res = kallsyms_lookup_name_local(name);
	} else {
		SEP_DRV_LOG_WARNING(
			"Failed to locate kallsyms_lookup_name address");
	}
#else
	res = kallsyms_lookup_name(name);
#endif

	SEP_DRV_LOG_INIT(
		"Name: '%s': 0x%llx.", name ? name : "NULL",
		(unsigned long long)
			res); // Printing here instead. (Paranoia in case of corrupt pointer.)

	SEP_DRV_LOG_TRACE_OUT("Res: 0x%llx.", (unsigned long long)res);
	return res;
}

/*
 ************************************
 *  DRIVER LOG BUFFER DECLARATIONS  *
 ************************************
 */

volatile U8 active_ioctl;

DRV_LOG_BUFFER driver_log_buffer;

static char const *drv_log_categories[DRV_NB_LOG_CATEGORIES] = {
	"load",  "init",     "detection",    "error",  "state change",
	"mark",  "debug",    "flow",         "alloc",  "interrupt",
	"trace", "register", "notification", "warning"
};

#define DRV_LOG_NB_DRIVER_STATES 9
static char const *drv_log_states[DRV_LOG_NB_DRIVER_STATES] = {
	"Uninitialized", "Reserved", "Idle",         "Paused",     "Stopped",
	"Running",       "Pausing",  "Prepare_Stop", "Terminating"
};

/* ------------------------------------------------------------------------- */
/*!
 * @fn       static VOID utility_Driver_Log_Kprint_Helper (U8 category, char**  category_string,
 *                                                  U8 secondary, char** secondary_string_1,
 *                                                  char**  secondary_string_2, char**  secondary_string_3,
 *                                                  char**  secondary_string_4)
 *
 * @brief    Helper function for printing log messages to the system log.
 *
 * @param    IN     category            -  message category
 *           IN/OUT category_string     -  location where to place a pointer to the category's name
 *           IN     secondary           -  secondary field value for the message
 *           IN/OUT secondary_string_1  -  location where to place a pointer to the 1st part of the secondary info's decoded information
 *           IN/OUT secondary_string_2  -  location where to place a pointer to the 2nd part of the secondary info's decoded information
 *           IN/OUT secondary_string_3  -  location where to place a pointer to the 3rd part of the secondary info's decoded information
 *           IN/OUT secondary_string_4  -  location where to place a pointer to the 4th part of the secondary info's decoded information
 *
 * @return   none
 *
 * <I>Special Notes:</I>
 *           Allows a single format string to be used for all categories (instead of category-specific format
 *           strings) when calling printk, simplifying the print routine and reducing potential errors.
 *           There is a performance cost to this approach (forcing printk to process empty strings), but it
 *           should be dwarved by the cost of calling printk in the first place.
 *           NB: none of the input string pointers may be NULL!
 */
static VOID
utility_Driver_Log_Kprint_Helper(U8     category,
				 char **category_string,
				 U8     secondary,
				 char **secondary_string_1,
				 char **secondary_string_2,
				 char **secondary_string_3,
				 char **secondary_string_4)
{
	if (category >= DRV_NB_LOG_CATEGORIES) {
		*category_string = "Unknown category";
	} else {
		*category_string = (char *)drv_log_categories[category];
	}

	*secondary_string_1 = "";
	*secondary_string_2 = "";
	*secondary_string_3 = "";
	*secondary_string_4 = "";

	switch (category) {
	case DRV_LOG_CATEGORY_FLOW:
	case DRV_LOG_CATEGORY_TRACE:
	case DRV_LOG_CATEGORY_INTERRUPT: // we should *never* be kprinting from an interrupt context...
		if (secondary != DRV_LOG_NOTHING) {
			*secondary_string_1 = ", ";
			if (secondary == DRV_LOG_FLOW_IN) {
				*secondary_string_2 = "Entering";
			} else if (secondary == DRV_LOG_FLOW_OUT) {
				*secondary_string_2 = "Leaving";
			}
		}
		break;
	case DRV_LOG_CATEGORY_STATE_CHANGE: {
		U8 orig_state, dest_state;

		orig_state = (secondary & 0xF0) >> 4;
		dest_state = secondary & 0x0F;

		*secondary_string_1 = ", ";

		if (orig_state < DRV_LOG_NB_DRIVER_STATES) {
			*secondary_string_2 =
				(char *)drv_log_states[orig_state];
		} else {
			*secondary_string_2 = "Unknown_state";
		}

		*secondary_string_3 = " -> ";

		if (dest_state < DRV_LOG_NB_DRIVER_STATES) {
			*secondary_string_4 =
				(char *)drv_log_states[dest_state];
		} else {
			*secondary_string_4 = "Unknown_state";
		}
	} break;

	default:
		break;
	}

	return;
}

/* ------------------------------------------------------------------------- */
/*!
 * @fn       static inline VOID utility_Log_Write (
 *                                    U8 destination, U8 category, U8 secondary,
 *                                    const char* function_name, U32 func_name_len,
 *                                    U32 line_number, U64 tsc, U8 ioctl, U16 processor_id,
 *                                    U8 driver_state, U16 nb_active_interrupts,
 *                                    U16 nb_active_notifications,
 *                                    const char* format_string, ...)
 *
 * @brief    Checks whether and where the message should be logged, and logs it as appropriate.
 *
 * @param    U8          destination             - whether to write to the primary (0) or the auxiliary log buffer (1)
 *           U8          category                - message category
 *           U8          secondary               - secondary information field for the message
 *           const char* function_name           - name of the calling function
 *           U32         func_name_len           - length of the name of the calling function (more efficient
 *                                                 to pass it as parameter than finding it back at runtime)
 *           U32         line_number             - line number of the call site
 *           U64         tsc                     - time stamp value to use
 *           U8          ioctl                   - current active ioctl
 *           U16         processor_id            - id of the active core/thread
 *           U8          driver_state            - current driver state
 *           U16         nb_active_interrupts    - number of interrupts currently being processed
 *           U16         nb_active_notifications - number of notifications currently being processed
 *           const char* format_string           - classical format string for printf-like functions
 *           ...                                 - elements to print
 *
 * @return   none
 *
 * <I>Special Notes:</I>
 *           Writes the specified message to the specified log buffer.
 *           The order of writes (integrity tag at the beginning, overflow tag at the very end) matters
 *           to ensure the logged information can be detected to be only partially written if applicable).
 *           Much of the needed information (active core, driver state, tsc..) is passed through the
 *           stack (instead of obtained inside utility_Log_Write) to guarantee entries representing the
 *           same message (or log call) in different channels use consistent information, letting the
 *           decoder reliably identify duplicates.
 */
static inline VOID
utility_Log_Write(U8          destination,
		  U8          category,
		  U8          secondary,
		  char const *function_name,
		  U32         function_name_length,
		  U32         line_number,
		  U64         tsc,
		  U8          ioctl,
		  U16         processor_id,
		  U8          driver_state,
		  U16         nb_active_interrupts,
		  U16         nb_active_notifications,
		  char const *format_string,
		  va_list     args)
{
	U32           entry_id;
	U16           overflow_tag;
	DRV_LOG_ENTRY entry;
	char         *target_func_buffer;
	U32           local_func_name_length;
	U32           i;

	if (destination == 0) { // primary buffer
		entry_id = __sync_add_and_fetch(
			&DRV_LOG_BUFFER_pri_entry_index(DRV_LOG()), 1);
		overflow_tag = (U16)(entry_id / DRV_LOG_MAX_NB_PRI_ENTRIES);
		entry        = DRV_LOG_BUFFER_entries(DRV_LOG()) +
			entry_id % DRV_LOG_MAX_NB_PRI_ENTRIES;
	} else {
		entry_id = __sync_add_and_fetch(
			&DRV_LOG_BUFFER_aux_entry_index(DRV_LOG()), 1);
		overflow_tag = (U16)(entry_id / DRV_LOG_MAX_NB_AUX_ENTRIES);
		entry        = DRV_LOG_BUFFER_entries(DRV_LOG()) +
			DRV_LOG_MAX_NB_PRI_ENTRIES +
			entry_id % DRV_LOG_MAX_NB_AUX_ENTRIES;
	}

	DRV_LOG_COMPILER_MEM_BARRIER();
	DRV_LOG_ENTRY_integrity_tag(entry) = overflow_tag;
	DRV_LOG_COMPILER_MEM_BARRIER();

	if (format_string &&
	    *format_string) { // setting this one first to try to increase MLP
		vsnprintf(DRV_LOG_ENTRY_message(entry), DRV_LOG_MESSAGE_LENGTH,
			  format_string, args);
	} else {
		DRV_LOG_ENTRY_message(entry)[0] = 0;
	}

	target_func_buffer = DRV_LOG_ENTRY_function_name(entry);
	local_func_name_length =
		function_name_length < DRV_LOG_FUNCTION_NAME_LENGTH ?
			function_name_length :
			DRV_LOG_FUNCTION_NAME_LENGTH;
	for (i = 0; i < local_func_name_length - 1; i++) {
		target_func_buffer[i] = function_name[i];
	}
	target_func_buffer[i] = 0;

	DRV_LOG_ENTRY_category(entry)                = category;
	DRV_LOG_ENTRY_secondary_info(entry)          = secondary;
	DRV_LOG_ENTRY_line_number(entry)             = line_number;
	DRV_LOG_ENTRY_active_drv_operation(entry)    = ioctl;
	DRV_LOG_ENTRY_processor_id(entry)            = processor_id;
	DRV_LOG_ENTRY_driver_state(entry)            = driver_state;
	DRV_LOG_ENTRY_nb_active_interrupts(entry)    = nb_active_interrupts;
	DRV_LOG_ENTRY_nb_active_notifications(entry) = nb_active_notifications;
	DRV_LOG_ENTRY_tsc(entry)                     = tsc;

	DRV_LOG_COMPILER_MEM_BARRIER();
	DRV_LOG_ENTRY_temporal_tag(entry) = overflow_tag;
	DRV_LOG_COMPILER_MEM_BARRIER();

	return;
}

/* ------------------------------------------------------------------------- */
/*!
 * @fn       extern void UTILITY_Log (U8 category, U8 in_notification, U8 secondary,
 *                                    const char* function_name, U32 func_name_len,
 *                                    U32 line_number, const char* format_string, ...)
 *
 * @brief    Checks whether and where the message should be logged, and logs it as appropriate.
 *
 * @param    U8          category        - message category
 *           U8          in_notification - whether or not we are in a notification/OS callback context
 *                                         (this information cannot be reliably obtained without passing
 *                                         it through the stack)
 *           U8          secondary       - secondary information field for the message
 *           const char* function_name   - name of the calling function
 *           U32         func_name_len   - length of the name of the calling function (more efficient
 *                                         to pass it as parameter than finding it back at runtime)
 *           U32         line_number     - line number of the call site
 *           const char* format_string   - classical format string for printf-like functions
 *           ...                         - elements to print
 *
 * @return   none
 *
 * <I>Special Notes:</I>
 *           Takes a snapshot of various elements (TSC, driver state, etc.) to ensure a single log call
 *           writes consistent information to all applicable channels (i.e. favoring consistency over
 *           instantaneous accuracy). See utility_Log_Write for details.
 */
extern VOID
UTILITY_Log(U8          category,
	    U8          in_notification,
	    U8          secondary,
	    char const *function_name,
	    U32         func_name_len,
	    U32         line_number,
	    char const *format_string,
	    ...)
{
	U64 tsc_snapshot;
	U8  ioctl_snapshot;
	U8  driver_state_snapshot;
	U16 processor_id_snapshot;
	U16 nb_active_interrupts_snapshot;
	U16 nb_active_notifications_snapshot;
	U8  category_verbosity;
	U8  in_interrupt;
	U8  is_enabled;
	U8  is_logging;

	category_verbosity    = DRV_LOG_VERBOSITY(category);
	processor_id_snapshot = raw_smp_processor_id();
	in_interrupt          = ((pcb && atomic_read(&CPU_STATE_in_interrupt(
						 &pcb[processor_id_snapshot]))) +
			 (category == DRV_LOG_CATEGORY_INTERRUPT));
	is_enabled =
		in_interrupt * !!(category_verbosity & LOG_CONTEXT_INTERRUPT) +
		in_notification *
			!!(category_verbosity & LOG_CONTEXT_NOTIFICATION) +
		(!in_interrupt * !in_notification) *
			!!(category_verbosity & LOG_CONTEXT_REGULAR);

	if (is_enabled) {
		va_list args;
		U32     i;

		ioctl_snapshot        = active_ioctl;
		driver_state_snapshot = GET_DRIVER_STATE();
		nb_active_interrupts_snapshot =
			DRV_LOG_BUFFER_nb_active_interrupts(DRV_LOG());
		nb_active_notifications_snapshot =
			DRV_LOG_BUFFER_nb_active_notifications(DRV_LOG());
		UTILITY_Read_TSC(&tsc_snapshot);

		va_start(args, format_string);

		for (i = 0; i < 2; i++) {
			if (category_verbosity & (1 << i)) {
				va_list args_copy;
				va_copy(args_copy, args);
				utility_Log_Write(
					i, // 0 for primary log, 1 for auxiliary log
					category, secondary, function_name,
					func_name_len, line_number,
					tsc_snapshot, ioctl_snapshot,
					processor_id_snapshot,
					driver_state_snapshot,
					nb_active_interrupts_snapshot,
					nb_active_notifications_snapshot,
					format_string, args_copy);
				va_end(args_copy);
			}
		}
		if (category_verbosity & LOG_CHANNEL_PRINTK ||
		    category_verbosity & LOG_CHANNEL_TRACEK) {
#define DRV_LOG_DEBUG_ARRAY_SIZE 512
			char    tmp_array[DRV_LOG_DEBUG_ARRAY_SIZE];
			U32     nb_written_characters;
			char   *category_s, *sec1_s, *sec2_s, *sec3_s, *sec4_s;
			va_list args_copy;
			utility_Driver_Log_Kprint_Helper(category, &category_s,
							 secondary, &sec1_s,
							 &sec2_s, &sec3_s,
							 &sec4_s);

			nb_written_characters = snprintf(
				tmp_array, DRV_LOG_DEBUG_ARRAY_SIZE - 1,
				SEP_MSG_PREFIX " [%s%s%s%s%s] [%s@%d]: ",
				category_s, sec1_s, sec2_s, sec3_s, sec4_s,
				function_name, line_number);

			if (nb_written_characters > 0) {
				va_copy(args_copy, args);
				nb_written_characters += vsnprintf(
					tmp_array + nb_written_characters,
					DRV_LOG_DEBUG_ARRAY_SIZE -
						nb_written_characters - 1,
					format_string, args_copy);
				va_end(args_copy);
#undef DRV_LOG_DEBUG_ARRAY_SIZE

				tmp_array[nb_written_characters++] = '\n';
				tmp_array[nb_written_characters++] = 0;

				is_logging = (category_verbosity &
					      LOG_CHANNEL_PRINTK) *
					     !in_interrupt * !in_notification;
				if (is_logging) {
					if (!in_atomic()) {
						switch (category) {
						case DRV_LOG_CATEGORY_ERROR:
							printk(KERN_ERR "%s",
							       tmp_array);
							break;
						case DRV_LOG_CATEGORY_WARNING:
							printk(KERN_WARNING
							       "%s",
							       tmp_array);
							break;
						default:
							printk(KERN_INFO "%s",
							       tmp_array);
							break;
						}
					}
				}

				/*
				//trace_printk is allowed only in debug kernel
#if defined(CONFIG_DYNAMIC_FTRACE)
				if (category_verbosity & LOG_CHANNEL_TRACEK) {
					trace_printk("%s", tmp_array);
				}
#endif
				*/
			}
		}

		va_end(args);
	}

	return;
}

/* ------------------------------------------------------------------------- */
/*!
 * @fn       extern DRV_STATUS UTILITY_Driver_Log_Init (void)
 *
 * @brief    Allocates and initializes the driver log buffer.
 *
 * @param    none
 *
 * @return   OS_SUCCESS on success, OS_NO_MEM on error.
 *
 * <I>Special Notes:</I>
 *           Should be (successfully) run before any non-LOAD log calls.
 *           Allocates memory without going through CONTROL_Allocate (to avoid
 *           complicating the instrumentation of CONTROL_* functions): calling
 *           UTILITY_Driver_Log_Free is necessary to free the log structure.
 *           Falls back to vmalloc when contiguous physical memory cannot be
 *           allocated. This does not impact runtime behavior, but may impact
 *           the easiness of retrieving the log from a core dump if the system
 *           crashes.
 */
extern DRV_STATUS
UTILITY_Driver_Log_Init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	struct timespec64 cur_time;
#else
	struct timespec cur_time;
#endif
	U32 size = sizeof(*driver_log_buffer);
	U8  using_contiguous_physical_memory;
	U32 bitness;

	if (size <
	    MAX_KMALLOC_SIZE) { // allocating outside the regular function to restrict the area of the driver
		driver_log_buffer = (PVOID)kmalloc(
			size,
			GFP_KERNEL); // where the log might not be initialized
	} else {
		driver_log_buffer =
			(PVOID)__get_free_pages(GFP_KERNEL, get_order(size));
	}

	if (driver_log_buffer) {
		using_contiguous_physical_memory = 1;
	} else {
		driver_log_buffer = vmalloc(size);

		if (!driver_log_buffer) {
			return OS_NO_MEM;
		}

		using_contiguous_physical_memory = 0;
	}

	memset(driver_log_buffer, DRV_LOG_FILLER_BYTE,
	       sizeof(*driver_log_buffer)); // we don't want zero-filled pages (so that the buffer's pages don't get ommitted in some crash dumps)

	DRV_LOG_COMPILER_MEM_BARRIER();
	DRV_LOG_BUFFER_header_signature(driver_log_buffer)[0] =
		DRV_LOG_SIGNATURE_0;
	DRV_LOG_BUFFER_footer_signature(driver_log_buffer)[0] =
		DRV_LOG_SIGNATURE_6;
	DRV_LOG_BUFFER_header_signature(driver_log_buffer)[3] =
		DRV_LOG_SIGNATURE_3;
	DRV_LOG_BUFFER_footer_signature(driver_log_buffer)[3] =
		DRV_LOG_SIGNATURE_3;

	DRV_LOG_COMPILER_MEM_BARRIER();
	DRV_LOG_BUFFER_header_signature(driver_log_buffer)[2] =
		DRV_LOG_SIGNATURE_2;
	DRV_LOG_BUFFER_footer_signature(driver_log_buffer)[2] =
		DRV_LOG_SIGNATURE_4;
	DRV_LOG_BUFFER_header_signature(driver_log_buffer)[1] =
		DRV_LOG_SIGNATURE_1;
	DRV_LOG_BUFFER_footer_signature(driver_log_buffer)[1] =
		DRV_LOG_SIGNATURE_5;

	DRV_LOG_COMPILER_MEM_BARRIER();
	DRV_LOG_BUFFER_header_signature(driver_log_buffer)[7] =
		DRV_LOG_SIGNATURE_7;
	DRV_LOG_BUFFER_footer_signature(driver_log_buffer)[7] =
		DRV_LOG_SIGNATURE_7;
	DRV_LOG_BUFFER_header_signature(driver_log_buffer)[5] =
		DRV_LOG_SIGNATURE_5;
	DRV_LOG_BUFFER_footer_signature(driver_log_buffer)[5] =
		DRV_LOG_SIGNATURE_1;

	DRV_LOG_COMPILER_MEM_BARRIER();
	DRV_LOG_BUFFER_header_signature(driver_log_buffer)[6] =
		DRV_LOG_SIGNATURE_6;
	DRV_LOG_BUFFER_footer_signature(driver_log_buffer)[6] =
		DRV_LOG_SIGNATURE_0;
	DRV_LOG_BUFFER_header_signature(driver_log_buffer)[4] =
		DRV_LOG_SIGNATURE_4;
	DRV_LOG_BUFFER_footer_signature(driver_log_buffer)[4] =
		DRV_LOG_SIGNATURE_2;

	DRV_LOG_BUFFER_log_size(driver_log_buffer) = sizeof(*driver_log_buffer);
	DRV_LOG_BUFFER_max_nb_pri_entries(driver_log_buffer) =
		DRV_LOG_MAX_NB_PRI_ENTRIES;
	DRV_LOG_BUFFER_max_nb_aux_entries(driver_log_buffer) =
		DRV_LOG_MAX_NB_AUX_ENTRIES;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	ktime_get_real_ts64(&cur_time);
	timespec64_to_ns(&cur_time);
#else
	getnstimeofday(&cur_time);
#endif

	DRV_LOG_BUFFER_init_time(driver_log_buffer)       = cur_time.tv_sec;
	DRV_LOG_BUFFER_disambiguator(driver_log_buffer)   = 0;
	DRV_LOG_BUFFER_log_version(driver_log_buffer)     = DRV_LOG_VERSION;
	DRV_LOG_BUFFER_pri_entry_index(driver_log_buffer) = (U32)((S32)-1);
	DRV_LOG_BUFFER_aux_entry_index(driver_log_buffer) = (U32)((S32)-1);

#if defined(DRV_EM64T)
	bitness = 64;
#else
	bitness = 32;
#endif

	snprintf(DRV_LOG_BUFFER_driver_version(driver_log_buffer),
		 DRV_LOG_DRIVER_VERSION_SIZE,
		 "[%u-bit Linux] SEP v%d.%d . API %d. type %u.", bitness,
		 SEP_MAJOR_VERSION, SEP_MINOR_VERSION, SEP_API_VERSION,
		 drv_type);

	DRV_LOG_BUFFER_driver_state(driver_log_buffer) = GET_DRIVER_STATE();
	DRV_LOG_BUFFER_active_drv_operation(driver_log_buffer) = active_ioctl;
	DRV_LOG_BUFFER_nb_drv_operations(driver_log_buffer)    = 0;
	DRV_LOG_BUFFER_nb_interrupts(driver_log_buffer)        = 0;
	DRV_LOG_BUFFER_nb_active_interrupts(driver_log_buffer) = 0;
	DRV_LOG_BUFFER_nb_notifications(driver_log_buffer)     = 0;
	DRV_LOG_BUFFER_nb_active_notifications(driver_log_buffer)     = 0;
	DRV_LOG_BUFFER_nb_driver_state_transitions(driver_log_buffer) = 0;

	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_LOAD) =
		DRV_LOG_DEFAULT_LOAD_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_INIT) =
		DRV_LOG_DEFAULT_INIT_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_DETECTION) =
		DRV_LOG_DEFAULT_DETECTION_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_ERROR) =
		DRV_LOG_DEFAULT_ERROR_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_STATE_CHANGE) =
		DRV_LOG_DEFAULT_STATE_CHANGE_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_MARK) =
		DRV_LOG_DEFAULT_MARK_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_DEBUG) =
		DRV_LOG_DEFAULT_DEBUG_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_FLOW) =
		DRV_LOG_DEFAULT_FLOW_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_ALLOC) =
		DRV_LOG_DEFAULT_ALLOC_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_INTERRUPT) =
		DRV_LOG_DEFAULT_INTERRUPT_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_TRACE) =
		DRV_LOG_DEFAULT_TRACE_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_REGISTER) =
		DRV_LOG_DEFAULT_REGISTER_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_NOTIFICATION) =
		DRV_LOG_DEFAULT_NOTIFICATION_VERBOSITY;
	DRV_LOG_VERBOSITY(DRV_LOG_CATEGORY_WARNING) =
		DRV_LOG_DEFAULT_WARNING_VERBOSITY;

	DRV_LOG_BUFFER_contiguous_physical_memory(driver_log_buffer) =
		using_contiguous_physical_memory;

	SEP_DRV_LOG_LOAD(
		"Initialized driver log using %scontiguous physical memory.",
		DRV_LOG_BUFFER_contiguous_physical_memory(driver_log_buffer) ?
			"" :
			"non-");

	return OS_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/*!
 * @fn       extern DRV_STATUS UTILITY_Driver_Log_Free (void)
 *
 * @brief    Frees the driver log buffer.
 *
 * @param    none
 *
 * @return   OS_SUCCESS on success, OS_NO_MEM on error.
 *
 * <I>Special Notes:</I>
 *           Should be done before unloading the driver.
 *           See UTILITY_Driver_Log_Init for details.
 */
extern void
UTILITY_Driver_Log_Free(VOID)
{
	U32 size = sizeof(*driver_log_buffer);

	if (driver_log_buffer) {
		if (DRV_LOG_BUFFER_contiguous_physical_memory(
			    driver_log_buffer)) {
			if (size < MAX_KMALLOC_SIZE) {
				kfree(driver_log_buffer);
			} else {
				free_pages((unsigned long)driver_log_buffer,
					   get_order(size));
			}
		} else {
			vfree(driver_log_buffer);
		}

		driver_log_buffer = NULL;
	}
}

/* ------------------------------------------------------------------------- */
/*!
 * @fn       extern void UTILITY_Driver_Set_Active_Ioctl (U32 ioctl)
 *
 * @brief    Sets the 'active_ioctl' global to the specified value.
 *
 * @param    U32 ioctl - ioctl/drvop code to use
 *
 * @return   none
 *
 * <I>Special Notes:</I>
 *           Used to keep track of the IOCTL operation currently being processed.
 *           This information is saved in the log buffer (globally), as well as
 *           in every log entry.
 *           NB: only IOCTLs for which grabbing the ioctl mutex is necessary
 *           should be kept track of this way.
 */
extern void
UTILITY_Driver_Set_Active_Ioctl(U32 ioctl)
{
	active_ioctl = ioctl;
	if (ioctl) {
		DRV_LOG_BUFFER_nb_drv_operations(driver_log_buffer)++;
	}
}

/* ------------------------------------------------------------------------- */
/*!
 * @fn       extern const char** UTILITY_Log_Category_Strings (void)
 *
 * @brief    Accessor function for the log category string array
 *
 * @param    none
 *
 * @return   none
 *
 * <I>Special Notes:</I>
 *           Only needed for cosmetic purposes when adjusting category verbosities.
 */
extern char const **
UTILITY_Log_Category_Strings(void)
{
	return drv_log_categories;
}

/* ------------------------------------------------------------------------- */
/*!
 * @fn       extern U32 UTILITY_Change_Driver_State (U32 allowed_prior_states, U32 state, const char* func, U32 line_number)
 *
 * @brief    Updates the driver state (if the transition is legal).
 *
 * @param    U32 allowed_prior_states   - the bitmask representing the states from which the transition is allowed to occur
 *           U32 state                  - the destination state
 *           const char* func           - the callsite's function's name
 *           U32 line_number            - the callsite's line number
 *
 * @return   1 in case of success, 0 otherwise
 *
 * <I>Special Notes:</I>
 *
 */
extern U32
UTILITY_Change_Driver_State(U32         allowed_prior_states,
			    U32         state,
			    char const *func,
			    U32         line_number)
{
	U32 res = 1;
	U32 previous_state;
	U32 current_state = GET_DRIVER_STATE();
	U32 nb_attempts   = 0;

	SEP_DRV_LOG_TRACE_IN(
		"Prior states: 0x%x, state: %u, func: %p, line: %u.",
		allowed_prior_states, state, func, line_number);

	if (state >= DRV_LOG_NB_DRIVER_STATES) {
		SEP_DRV_LOG_ERROR("Illegal destination state %d (%s@%u)!",
				  state, func, line_number);
		res = 0;
		goto clean_return;
	}

	do {
		previous_state = current_state;
		nb_attempts++;
		SEP_DRV_LOG_TRACE("Attempt #%d to transition to state %s.",
				  nb_attempts, drv_log_states[state]);

		if (DRIVER_STATE_IN(current_state, allowed_prior_states)) {
			current_state = cmpxchg(&GET_DRIVER_STATE(),
						previous_state, state);
		} else {
			SEP_DRV_LOG_ERROR(
				"Invalid transition [%s -> %s] (%s@%u)!",
				drv_log_states[previous_state],
				drv_log_states[state], func, line_number);
			res = 0;
			goto clean_return;
		}

	} while (previous_state != current_state);

	SEP_DRV_LOG_STATE_TRANSITION(previous_state, state, "From %s@%u.", func,
				     line_number);

clean_return:
	SEP_DRV_LOG_TRACE_OUT("Res: %u.", res);
	return res;
}

