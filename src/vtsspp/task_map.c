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

#include "debug.h"
#include "spinlock.h"
#include "task.h"
#include "task_map.h"

#include <linux/jhash.h>

#ifdef VTSS_AUTOCONF_HLIST_NODE_ITERATOR
#define VTSS_HLIST_NODE_ITERATOR(pos) struct hlist_node *pos
#define vtss_hlist_for_each_entry_safe(tsk, pos, next, head)\
	hlist_for_each_entry_safe(tsk, pos, next, head, hlist)
#define vtss_hlist_for_each_entry_rcu(tsk, pos, head)\
	hlist_for_each_entry_rcu(tsk, pos, head, hlist)
#else
#define VTSS_HLIST_NODE_ITERATOR(pos)
#define vtss_hlist_for_each_entry_rcu(tsk, pos, head)\
	hlist_for_each_entry_rcu(tsk, head, hlist)
#define vtss_hlist_for_each_entry_safe(tsk, pos, next, head)\
	hlist_for_each_entry_safe(tsk, next, head, hlist)
#endif

#define VTSS_HASH_TABLE_SIZE (1 << 10)

static VTSS_DEFINE_SPINLOCK(vtss_task_map_lock);
static struct hlist_head vtss_task_map_hash_table[VTSS_HASH_TABLE_SIZE] = {{NULL}};

static atomic_t vtss_task_map_active = ATOMIC_INIT(0);
#define vtss_task_map_active() (atomic_read(&vtss_task_map_active) == 1)
#define vtss_task_map_set_active() atomic_set(&vtss_task_map_active, 1)
#define vtss_task_map_set_inactive() (atomic_cmpxchg(&vtss_task_map_active, 1, 0) == 1)

/**
 * Compute hash value.
 */
static __always_inline u32 vtss_task_map_hash(pid_t tid)
{
	return (jhash_1word(tid, 0) & (VTSS_HASH_TABLE_SIZE - 1));
}

/**
 * Reclaim an entry after grace period is expired.
 */
static void vtss_task_map_reclaim(struct rcu_head *rcu)
{
	struct vtss_task *tsk = container_of(rcu, struct vtss_task, rcu);

	if (atomic_read(&tsk->usage) == 0) {
		if (tsk->delete_cb)
			tsk->delete_cb(tsk);
	} else {
		vtss_pr_error("%d: Task not deleted, usage: %d",
			      tsk->tid, atomic_read(&tsk->usage));
	}
}

/**
 * Initialize hash table.
 * Returns non-zero if an error occurred.
 */
int vtss_task_map_init(void)
{
	int i;
	unsigned long flags;
	struct hlist_head *head;

	vtss_spin_lock_irqsave(&vtss_task_map_lock, flags);
	for (i = 0; i < VTSS_HASH_TABLE_SIZE; i++) {
		head = &vtss_task_map_hash_table[i];
		INIT_HLIST_HEAD(head);
	}
	vtss_spin_unlock_irqrestore(&vtss_task_map_lock, flags);
	synchronize_rcu();
	vtss_task_map_set_active();
	return 0;
}

/**
 * Cleanup hash table.
 * Remove all entries from the hash table and delete them if no usage.
 */
void vtss_task_map_cleanup(void)
{
	int i;
	unsigned long flags;
	struct vtss_task *tsk;
	struct hlist_head *head;
	struct hlist_node *next;
	VTSS_HLIST_NODE_ITERATOR(pos);

	if (!vtss_task_map_set_inactive())
		return;

	vtss_spin_lock_irqsave(&vtss_task_map_lock, flags);
	for (i = 0; i < VTSS_HASH_TABLE_SIZE; i++) {
		head = &vtss_task_map_hash_table[i];
		vtss_hlist_for_each_entry_safe(tsk, pos, next, head) {
			if (vtss_task_set_unhashed(tsk)) {
				vtss_pr_debug_task("removing %d:%d", tsk->tid, tsk->order);
				hlist_del_init_rcu(&tsk->hlist);
			} else {
				vtss_pr_error("%d: Task not removed, usage: %d",
					      tsk->tid, atomic_read(&tsk->usage));
			}
			if (atomic_read(&tsk->usage) && atomic_dec_and_test(&tsk->usage)) {
				vtss_pr_debug_task("reclaiming %d:%d", tsk->tid, tsk->order);
				call_rcu(&tsk->rcu, vtss_task_map_reclaim);
			} else {
				vtss_pr_error("%d: Task not reclaimed, usage: %d",
					      tsk->tid, atomic_read(&tsk->usage));
			}
		}
	}
	vtss_spin_unlock_irqrestore(&vtss_task_map_lock, flags);
	synchronize_rcu();
}

/**
 * Add the entry into the hash table with incremented usage.
 * Returns 'true' if the entry was added, 'false' otherwise.
 */
bool vtss_task_map_add(struct vtss_task *tsk)
{
	unsigned long flags;
	struct hlist_head *head;

	if (tsk == NULL)
		return false;

	if (vtss_task_set_hashed(tsk)) {
		vtss_pr_debug_task("adding %d:%d", tsk->tid, tsk->order);
		head = &vtss_task_map_hash_table[vtss_task_map_hash(tsk->tid)];
		atomic_inc(&tsk->usage);
		vtss_spin_lock_irqsave(&vtss_task_map_lock, flags);
		hlist_add_head_rcu(&tsk->hlist, head);
		vtss_spin_unlock_irqrestore(&vtss_task_map_lock, flags);
		return true;
	}
	return false;
}

/**
 * Remove the entry from the hash table, decrement usage and delete if no usage.
 * Returns 'true' if the entry is about to be deleted, 'false' otherwise.
 */
bool vtss_task_map_remove(struct vtss_task *tsk)
{
	unsigned long flags;

	if (tsk == NULL)
		return false;

	if (vtss_task_set_unhashed(tsk)) {
		vtss_pr_debug_task("removing %d:%d", tsk->tid, tsk->order);
		vtss_spin_lock_irqsave(&vtss_task_map_lock, flags);
		hlist_del_init_rcu(&tsk->hlist);
		vtss_spin_unlock_irqrestore(&vtss_task_map_lock, flags);
	}
	if (atomic_dec_and_test(&tsk->usage)) {
		vtss_pr_debug_task("reclaiming %d:%d", tsk->tid, tsk->order);
		call_rcu(&tsk->rcu, vtss_task_map_reclaim);
		return true;
	}
	return false;
}

/**
 * Get an entry if it is present in the hash table and increment its usage.
 * Returns 'NULL' if not present.
 */
struct vtss_task *vtss_task_map_get(pid_t tid)
{
	struct vtss_task *tsk = NULL;
	struct hlist_head *head;
	VTSS_HLIST_NODE_ITERATOR(pos);

	if (!vtss_task_map_active())
		return NULL;

	rcu_read_lock();
	head = &vtss_task_map_hash_table[vtss_task_map_hash(tid)];
	vtss_hlist_for_each_entry_rcu(tsk, pos, head) {
		if (tsk->tid == tid) {
			if (vtss_task_hashed(tsk))
				atomic_inc(&tsk->usage);
			else
				tsk = NULL;
			break;
		}
	}
	rcu_read_unlock();
	return tsk;
}

/**
 * Decrement usage, remove from the hash table and delete if no usage.
 * Returns 'true' if the entry is about to be deleted, 'false' otherwise.
 */
bool vtss_task_map_put(struct vtss_task *tsk)
{
	unsigned long flags;

	if (tsk == NULL)
		return false;

	if (atomic_dec_and_test(&tsk->usage)) {
		/* here somebody can increment usage */
		if (vtss_task_set_unhashed(tsk)) {
			vtss_pr_debug_task("removing %d:%d", tsk->tid, tsk->order);
			vtss_spin_lock_irqsave(&vtss_task_map_lock, flags);
			hlist_del_init_rcu(&tsk->hlist);
			vtss_spin_unlock_irqrestore(&vtss_task_map_lock, flags);
		}
		if (atomic_read(&tsk->usage) == 0) { /* do not remove this check */
			vtss_pr_debug_task("reclaiming %d:%d", tsk->tid, tsk->order);
			call_rcu(&tsk->rcu, vtss_task_map_reclaim);
			return true;
		}
	}
	return false;
}

/**
 * Apply a function to each entry of the hash table.
 * Returns non-zero if an error occurred.
 */
int vtss_task_map_for_each(vtss_task_map_cb_t *cb, void *arg)
{
	int i;
	struct vtss_task *tsk;
	struct hlist_head *head;
	VTSS_HLIST_NODE_ITERATOR(pos);

	if (cb == NULL) {
		vtss_pr_error("Invalid task map callback");
		return -EINVAL;
	}
	if (!vtss_task_map_active())
		return -EFAULT;

	rcu_read_lock();
	for (i = 0; i < VTSS_HASH_TABLE_SIZE; i++) {
		head = &vtss_task_map_hash_table[i];
		vtss_hlist_for_each_entry_rcu(tsk, pos, head)
			cb(tsk, arg);
	}
	rcu_read_unlock();
	return 0;
}
