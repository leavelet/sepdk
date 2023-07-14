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

#ifndef _VTSS_SPINLOCK_H_
#define _VTSS_SPINLOCK_H_

#include "config.h"

#include <linux/spinlock.h>

#ifdef VTSS_PREEMPT_RT
#define VTSS_DEFINE_SPINLOCK			 DEFINE_RAW_SPINLOCK
#define vtss_spinlock_t				 raw_spinlock_t
#define vtss_spin_lock_init(lock)		 raw_spin_lock_init(lock)
#define vtss_spin_lock(lock)			 raw_spin_lock(lock)
#define vtss_spin_trylock(lock)			 raw_spin_trylock(lock)
#define vtss_spin_unlock(lock)			 raw_spin_unlock(lock)
#define vtss_spin_lock_irqsave(lock, flags)	 raw_spin_lock_irqsave(lock, flags)
#define vtss_spin_trylock_irqsave(lock, flags)	 raw_spin_trylock_irqsave(lock, flags)
#define vtss_spin_unlock_irqrestore(lock, flags) raw_spin_unlock_irqrestore(lock, flags)
#else
#define VTSS_DEFINE_SPINLOCK			 DEFINE_SPINLOCK
#define vtss_spinlock_t				 spinlock_t
#define vtss_spin_lock_init(lock)		 spin_lock_init(lock)
#define vtss_spin_lock(lock)			 spin_lock(lock)
#define vtss_spin_trylock(lock)			 spin_trylock(lock)
#define vtss_spin_unlock(lock)			 spin_unlock(lock)
#define vtss_spin_lock_irqsave(lock, flags)	 spin_lock_irqsave(lock, flags)
#define vtss_spin_trylock_irqsave(lock, flags)	 spin_trylock_irqsave(lock, flags)
#define vtss_spin_unlock_irqrestore(lock, flags) spin_unlock_irqrestore(lock, flags)
#endif

#endif
