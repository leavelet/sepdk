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

#include "cmd.h"
#include "debug.h"
#include "ipt.h"
#include "kmem.h"
#include "modcfg.h"
#include "nmiwd.h"
#include "pce.h"
#include "pmu.h"
#include "procfs.h"
#include "spinlock.h"
#include "target.h"
#include "task.h"
#include "task_map.h"
#include "time.h"

#include <linux/module.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define VTSS_PROCFS_CONTROL_NAME ".control"
#define VTSS_PROCFS_CPUMASK_NAME ".cpumask"
#define VTSS_PROCFS_TARGETS_NAME ".targets"
#define VTSS_PROCFS_TIMESRC_NAME ".timesrc"

struct vtss_procfs_entry {
	char *name;
	struct proc_dir_entry *pde;
	struct vtss_procfs_ops *ops;
};

struct vtss_procfs_control {
	struct list_head list;
	size_t size;
	char buf[0];
};

extern int uid, gid, mode;

struct proc_dir_entry *vtss_procfs_root_entry = NULL;

static atomic_t vtss_procfs_control_opened = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(vtss_procfs_control_waitq);
static VTSS_DEFINE_SPINLOCK(vtss_procfs_control_list_lock);
static LIST_HEAD(vtss_procfs_control_list);

#define vtss_procfs_control_opened(trn) (atomic_read(&vtss_procfs_control_opened) == 1)
#define vtss_procfs_control_set_opened(trn) (atomic_cmpxchg(&vtss_procfs_control_opened, 0, 1) == 0)
#define vtss_procfs_control_set_closed(trn) (atomic_cmpxchg(&vtss_procfs_control_opened, 1, 0) == 1)

static int vtss_procfs_control_open(struct inode *inode, struct file *file)
{
	if (!vtss_procfs_control_set_opened()) {
		vtss_pr_warning("Control entry is already opened");
		return -EBUSY;
	}
	vtss_pr_debug_procfs("opened");
	/* increase the priority for trace reader to avoid lost events */
	set_user_nice(current, -19);
	return 0;
}

static int vtss_procfs_control_close(struct inode *inode, struct file *file)
{
	if (!vtss_procfs_control_set_closed()) {
		vtss_pr_warning("Control entry is already closed");
		return -EFAULT;
	}
	vtss_pr_debug_procfs("closed");
	if (!vtss_collector_stopped())
		vtss_cmd_abort();
	/* set defaults for next session */
	cpumask_copy(&vtss_cpumask, cpu_present_mask);
	/* restore default priority for trace reader */
	set_user_nice(current, 0);
	return 0;
}

static ssize_t vtss_procfs_control_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int rc;
	ssize_t size;
	unsigned long flags;
	struct vtss_procfs_control *ctl;

	/* wait for non-empty ready queue */
	vtss_spin_lock_irqsave(&vtss_procfs_control_list_lock, flags);
	while (list_empty(&vtss_procfs_control_list)) {
		vtss_spin_unlock_irqrestore(&vtss_procfs_control_list_lock, flags);
		vtss_pr_debug_procfs("waiting");
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
#ifdef VTSS_WAIT_QUEUE_TIMEOUT
		rc = wait_event_interruptible_timeout(vtss_procfs_control_waitq,
						      !list_empty(&vtss_procfs_control_list),
						      msecs_to_jiffies(VTSS_WAIT_QUEUE_TIMEOUT));
#else
		rc = wait_event_interruptible(vtss_procfs_control_waitq,
					      !list_empty(&vtss_procfs_control_list));
#endif
		if (rc < 0)
			return -ERESTARTSYS;
		vtss_spin_lock_irqsave(&vtss_procfs_control_list_lock, flags);
	}
	/* get the first message from the list */
	ctl = list_first_entry(&vtss_procfs_control_list, struct vtss_procfs_control, list);
	list_del_init(&ctl->list);
	vtss_spin_unlock_irqrestore(&vtss_procfs_control_list_lock, flags);

	/* write it out */
	size = ctl->size;
	if (size > 0) {
		vtss_pr_debug_procfs("msg=%s, size=%zu", ctl->buf, ctl->size);
		if (size <= count) {
			if (copy_to_user(buf, ctl->buf, size)) {
				vtss_pr_error("Failed to copy control message");
				size = -EFAULT;
			}
		} else {
			vtss_pr_error("No room for control message");
			size = -EINVAL;
		}
		if (size > 0)
			*ppos += size;
	} else {
		vtss_pr_debug_procfs("[EOF]");
	}
	vtss_zfree(&ctl, sizeof(struct vtss_procfs_control) + ctl->size);
	return size;
}

static ssize_t vtss_procfs_control_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	int rc;
	char chr;
	bool major;
	int major_ver, minor_ver;
	ssize_t buf_size = count;
	unsigned long flags;
	unsigned long pid;
	ssize_t cfg_size;

	while (buf_size > 0) {
		if (get_user(chr, buf))
			return -EFAULT;
		buf += sizeof(char);
		buf_size -= sizeof(char);
		vtss_pr_debug_procfs("cmd: %c", chr);
		switch (chr) {
		case 'V': /* V<major.minor> - client version */
			major = true;
			major_ver = 0;
			minor_ver = 0;
			while (buf_size > 0) {
				if (get_user(chr, buf))
					return -EFAULT;
				if (chr >= '0' && chr <= '9') {
					buf += sizeof(char);
					buf_size -= sizeof(char);
					if (major)
						major_ver = major_ver*10 + (chr - '0');
					else
						minor_ver = minor_ver*10 + (chr - '0');
				} else {
					if (major && chr == '.') {
						major = false;
						buf += sizeof(char);
						buf_size -= sizeof(char);
					} else {
						break;
					}
				}
			}
			vtss_pr_debug_procfs("version: %u.%u", major_ver, minor_ver);
			break;
		case 'T': /* T<pid> - set target PID */
			pid = 0;
			while (buf_size > 0) {
				if (get_user(chr, buf))
					return -EFAULT;
				if (chr >= '0' && chr <= '9') {
					buf += sizeof(char);
					buf_size -= sizeof(char);
					pid = pid*10 + (chr - '0');
				} else {
					break;
				}
			}
			vtss_pr_debug_procfs("attach: pid=%lu", pid);
			if (pid) {
				rc = vtss_cmd_attach(pid);
				if (rc) return rc;
			} else {
				vtss_pr_error("Invalid target PID");
				return -EINVAL;
			}
			break;
		case 'I': /* I<flags> - initialize */
			flags = 0;
			while (buf_size > 0) {
				if (get_user(chr, buf))
					return -EFAULT;
				if (chr >= '0' && chr <= '9') {
					buf += sizeof(char);
					buf_size -= sizeof(char);
					flags = flags*10 + (chr - '0');
				} else {
					break;
				}
			}
			vtss_pr_debug_procfs("init: flags=0x%lx", flags);
			rc = vtss_reqcfg_verify();
			if (rc) {
				vtss_pr_error("Invalid collection configuration");
				return rc;
			}
			rc = vtss_cmd_start();
			if (rc) return rc;
			break;
		case 'E': /* E<size>=... - configuration request */
			cfg_size = 0;
			while (buf_size > 0) {
				if (get_user(chr, buf))
					return -EFAULT;
				buf += sizeof(char);
				buf_size -= sizeof(char);
				if (chr >= '0' && chr <= '9')
					cfg_size = cfg_size*10 + (chr - '0');
				else
					break;
			}
			vtss_reqcfg_init();
			vtss_pr_debug_procfs("events: size=%zd", cfg_size);
			if (chr != '=' || cfg_size > buf_size) {
				vtss_pr_error("Invalid configuration command: E%lu", cfg_size);
				return -EINVAL;
			}
			while (cfg_size > 0) {
				int cfgreq;
				trace_cfg_t trace_cfg;
				stk_cfg_t stk_cfg;
				cpuevent_cfg_v1_t *evcfg;

				if (get_user(cfgreq, (const int __user *)buf)) {
					vtss_pr_error("Failed to get user events config");
					return -EFAULT;
				}
				switch (cfgreq) {
				case VTSS_CFGREQ_VOID:
					cfg_size = 0;
					break;
				case VTSS_CFGREQ_CPUEVENT_V1:
					/* copy CPU event configuration */
					if (vtss_reqcfg.events_size + sizeof(cpuevent_cfg_v1_t) > VTSS_CFG_CHAIN_SPACE_SIZE) {
						vtss_pr_error("No room to copy CPU event configuration");
						return -ENOMEM;
					}
					if (vtss_copy_from_user(vtss_reqcfg.events_space + vtss_reqcfg.events_size,
								buf, sizeof(cpuevent_cfg_v1_t))) {
						vtss_pr_error("Failed to copy CPU event configuration");
						return -EFAULT;
					}
					evcfg = (cpuevent_cfg_v1_t *)(vtss_reqcfg.events_space + vtss_reqcfg.events_size);
					vtss_reqcfg.events_size += sizeof(cpuevent_cfg_v1_t);
					/* copy CPU event name */
					if (vtss_reqcfg.events_size + evcfg->name_len > VTSS_CFG_CHAIN_SPACE_SIZE) {
						vtss_pr_error("No room to copy CPU event name");
						return -ENOMEM;
					}
					if (vtss_copy_from_user(vtss_reqcfg.events_space + vtss_reqcfg.events_size,
								&buf[evcfg->name_off], evcfg->name_len)) {
						vtss_pr_error("Failed to copy CPU event name");
						return -EFAULT;
					}
					vtss_reqcfg.events_size += evcfg->name_len;
					/* ignore CPU event description */
					evcfg->desc_off = sizeof(cpuevent_cfg_v1_t) + evcfg->name_len;
					evcfg->desc_len = 0;
					/* adjust record size (as it may differ from initial request size) */
					evcfg->reqsize = sizeof(cpuevent_cfg_v1_t) + evcfg->name_len + evcfg->desc_len;
					vtss_pr_debug_procfs("cpuevent[%d]: %s", evcfg->event_id,
							     (char *)evcfg + evcfg->name_off);
					buf += evcfg->reqsize;
					buf_size -= evcfg->reqsize;
					cfg_size -= evcfg->reqsize;
					break;
				case VTSS_CFGREQ_BTS:
					/* ignore BTS configuration */
					buf += sizeof(bts_cfg_t);
					buf_size -= sizeof(bts_cfg_t);
					cfg_size -= sizeof(bts_cfg_t);
					break;
				case VTSS_CFGREQ_LBR:
					if (vtss_copy_from_user(&vtss_reqcfg.lbr_cfg, buf, sizeof(lbr_cfg_t))) {
						vtss_pr_error("Failed to copy LBR configuration");
						return -EFAULT;
					}
					vtss_pr_debug_procfs("lbr: brcount=%d, modifier=0x%x",
							     vtss_reqcfg.lbr_cfg.brcount,
							     vtss_reqcfg.lbr_cfg.modifier);
					buf += sizeof(lbr_cfg_t);
					buf_size -= sizeof(lbr_cfg_t);
					cfg_size -= sizeof(lbr_cfg_t);
					break;
				case VTSS_CFGREQ_TRACE:
					if (vtss_copy_from_user(&trace_cfg, buf, sizeof(trace_cfg_t))) {
						vtss_pr_error("Failed to copy tracing configuration");
						return -EFAULT;
					}
					if (trace_cfg.namelen < VTSS_CFG_SPACE_SIZE) {
						if (vtss_copy_from_user(&vtss_reqcfg.trace_cfg, buf,
									sizeof(trace_cfg_t) + trace_cfg.namelen)) {
							vtss_pr_error("Failed to copy tracing configuration name");
							return -EFAULT;
						}
					}
					vtss_pr_debug_procfs("trace: trace_flags=0x%x, namelen=%d",
							     vtss_reqcfg.trace_cfg.trace_flags,
							     trace_cfg.namelen);
					buf += sizeof(trace_cfg_t) + (trace_cfg.namelen - 1);
					buf_size -= sizeof(trace_cfg_t) + (trace_cfg.namelen - 1);
					cfg_size -= sizeof(trace_cfg_t) + (trace_cfg.namelen - 1);
					break;
				case VTSS_CFGREQ_STK:
					if (vtss_copy_from_user(&stk_cfg, buf, sizeof(stk_cfg_t))) {
						vtss_pr_error("Failed to copy stack configuration");
						return -EFAULT;
					}
					if (stk_cfg.stktype >= vtss_stk_last) {
						vtss_pr_warning("Invalid stack type: %d", stk_cfg.stktype);
						break;
					}
					vtss_reqcfg.stk_sz[stk_cfg.stktype] = stk_cfg.stk_sz;
					vtss_reqcfg.stk_pg_sz[stk_cfg.stktype] = stk_cfg.stk_pg_sz;
					vtss_pr_debug_procfs("stack: stk_sz=0x%lx, stk_pg_sz=0x%lx",
							     vtss_reqcfg.stk_sz[stk_cfg.stktype],
							     vtss_reqcfg.stk_pg_sz[stk_cfg.stktype]);
					buf += sizeof(stk_cfg_t);
					buf_size -= sizeof(stk_cfg_t);
					cfg_size -= sizeof(stk_cfg_t);
					break;
				case VTSS_CFGREQ_IPT:
					if (vtss_copy_from_user(&vtss_reqcfg.ipt_cfg, buf, sizeof(ipt_cfg_t))) {
						vtss_pr_error("Failed to copy IPT configuration");
						return -EFAULT;
					}
					buf += sizeof(ipt_cfg_t);
					buf_size -= sizeof(ipt_cfg_t);
					cfg_size -= sizeof(ipt_cfg_t);
					/* calculate ring buffer size in milliseconds */
					vtss_reqcfg.ipt_cfg.size = vtss_reqcfg.ipt_cfg.size*1000 +
						(vtss_reqcfg.ipt_cfg.mode >> 22);
					vtss_pr_debug_procfs("ipt: mode=0x%x, size=%d",
							     vtss_reqcfg.ipt_cfg.mode, vtss_reqcfg.ipt_cfg.size);
					break;
				default:
					vtss_pr_error("Invalid configuration request: 0x%x", cfgreq);
					return -EINVAL;
				}
				vtss_pr_debug_procfs("events: size=%zd", cfg_size);
			} /* while (cfg_size > 0) */
			vtss_reqcfg_fixup_flags();
			vtss_reqcfg_print_events();
			vtss_reqcfg_fixup_events();
			rc = vtss_reqcfg_append_events();
			if (rc) return rc;
			break;
		case 'F': /* F - finish or stop */
			vtss_pr_debug_procfs("stop command");
			vtss_cmd_stop();
			break;
		case 'P': /* P - pause */
			vtss_pr_debug_procfs("pause command");
			vtss_cmd_pause();
			break;
		case 'R': /* R - resume */
			vtss_pr_debug_procfs("resume command");
			vtss_cmd_resume();
			break;
		case 'B': /* B - stop ring buffer */
			vtss_pr_debug_procfs("stop rb command");
			vtss_transport_stop_ring_bufer();
			break;
		case 'W': /* W<cmd> - watchdog */
			if (get_user(chr, buf))
				return -EFAULT;
			buf += sizeof(char);
			buf_size -= sizeof(char);
			vtss_pr_debug_procfs("watchdog: cmd=%c", chr);
			if (chr == '0') {
				rc = vtss_nmiwd_disable();
			} else if (chr == '1') {
				rc = vtss_nmiwd_enable();
			} else {
				vtss_pr_error("Invalid NMI watchdog command: %c", chr);
				return -EINVAL;
			}
			if (rc) return rc;
			break;
		case 'C': /* C<cmd> - set PCE */
			if (get_user(chr, buf))
				return -EFAULT;
			buf += sizeof(char);
			buf_size -= sizeof(char);
			vtss_pr_debug_procfs("setpce: cmd=%c", chr);
			if (chr == '0') {
				vtss_pce_disable();
			} else if (chr == '1') {
				vtss_pce_enable();
			} else {
				vtss_pr_error("Invalid PCE command: %c", chr);
				return -EINVAL;
			}
			break;
		case ' ':
		case '\n':
			break;
		default:
			vtss_pr_error("Invalid control command: %c", chr);
			return -EINVAL;
		}
	}
	return count;
}

static unsigned int vtss_procfs_control_poll(struct file *file, poll_table *poll_table)
{
	unsigned int rc = 0;
	unsigned long flags;

	if (!vtss_procfs_control_opened())
		return (POLLERR | POLLNVAL);

	poll_wait(file, &vtss_procfs_control_waitq, poll_table);

	vtss_spin_lock_irqsave(&vtss_procfs_control_list_lock, flags);
	if (!list_empty(&vtss_procfs_control_list))
		rc = (POLLIN | POLLRDNORM);
	vtss_spin_unlock_irqrestore(&vtss_procfs_control_list_lock, flags);

	vtss_pr_debug_procfs("%s", rc ? "ready" : "-----");
	return rc;
}

static struct vtss_procfs_ops vtss_procfs_control_fops = {
	.vtss_procfs_open    = vtss_procfs_control_open,
	.vtss_procfs_release = vtss_procfs_control_close,
	.vtss_procfs_read    = vtss_procfs_control_read,
	.vtss_procfs_write   = vtss_procfs_control_write,
	.vtss_procfs_poll    = vtss_procfs_control_poll,
};

static struct vtss_procfs_entry vtss_procfs_control_entry = {
	.name = VTSS_PROCFS_CONTROL_NAME,
	.ops = &vtss_procfs_control_fops,
};

int vtss_procfs_control_send(const char *msg, size_t size)
{
	unsigned long flags;
	struct vtss_procfs_control *ctl;

	ctl = vtss_zalloc(sizeof(struct vtss_procfs_control) + size, GFP_ATOMIC);
	if (ctl == NULL) {
		vtss_pr_error("Not enough memory for message");
		return -ENOMEM;
	}
	if (size > 0) {
		memcpy(ctl->buf, msg, size);
		vtss_pr_debug_procfs("msg=%s, size=%zu", msg, size);
	} else {
		vtss_pr_debug_procfs("[EOF]");
	}
	ctl->size = size;
	vtss_spin_lock_irqsave(&vtss_procfs_control_list_lock, flags);
	list_add_tail(&ctl->list, &vtss_procfs_control_list);
	vtss_spin_unlock_irqrestore(&vtss_procfs_control_list_lock, flags);
	vtss_procfs_control_wake_up();
	return 0;
}

int vtss_procfs_control_wake_up(void)
{
	int rc;
	unsigned long flags;

	if (!vtss_procfs_control_opened())
		return 0;

	vtss_spin_lock_irqsave(&vtss_procfs_control_list_lock, flags);
	rc = list_empty(&vtss_procfs_control_list) ? 0 : -EAGAIN;
	vtss_spin_unlock_irqrestore(&vtss_procfs_control_list_lock, flags);
	if (rc) {
		if (waitqueue_active(&vtss_procfs_control_waitq))
			wake_up_interruptible(&vtss_procfs_control_waitq);
	}
	return rc;
}

void vtss_procfs_control_reset(void)
{
	unsigned long flags;
	struct list_head *pos, *next;
	struct vtss_procfs_control *ctl;

	vtss_spin_lock_irqsave(&vtss_procfs_control_list_lock, flags);
	list_for_each_safe(pos, next, &vtss_procfs_control_list) {
		ctl = list_entry(pos, struct vtss_procfs_control, list);
		list_del_init(pos);
		vtss_pr_warning("Unsent message: %s", ctl->size ? ctl->buf : "[EOF]");
		vtss_zfree(&ctl, sizeof(struct vtss_procfs_control) + ctl->size);
	}
	vtss_spin_unlock_irqrestore(&vtss_procfs_control_list_lock, flags);
}

static int vtss_procfs_cpumask_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int vtss_procfs_cpumask_close(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t vtss_procfs_cpumask_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	ssize_t size = 0;
	size_t len = vtss_nr_cpus()*5 /* 4 digits + comma */ + 2;
	char *str;

	if (*ppos == 0) {
		str = vtss_zalloc(len, GFP_KERNEL);
		if (str == NULL) {
			vtss_pr_error("Not enough memory for cpumask");
			return -ENOMEM;
		}
#ifdef VTSS_AUTOCONF_CPULIST_SCNPRINTF
		size = cpulist_scnprintf(str, len - 2, &vtss_cpumask);
#else
		size = scnprintf(str, len - 2, "%*pbl", cpumask_pr_args(&vtss_cpumask));
#endif
		str[size] = '\n';
		size++;
		str[size] = '\0';

		if (size <= count) {
			if (copy_to_user(buf, str, size))
				size = -EFAULT;
		} else {
			size = -EINVAL;
		}
		if (size > 0)
			*ppos += size;
		vtss_zfree(&str, len);
	}
	return size;
}

static ssize_t vtss_procfs_cpumask_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	int rc;
	ssize_t size = -EINVAL;
	cpumask_var_t cpumask;

	if (!alloc_cpumask_var(&cpumask, GFP_KERNEL | __GFP_NOWARN))
		return -ENOMEM;
	rc = cpumask_parselist_user(buf, count, cpumask);
	if (!rc) {
		cpumask_and(&vtss_cpumask, cpumask, cpu_present_mask);
		size = count;
	}
	free_cpumask_var(cpumask);
	return size;
}

static struct vtss_procfs_ops vtss_procfs_cpumask_fops = {
	.vtss_procfs_open    = vtss_procfs_cpumask_open,
	.vtss_procfs_release = vtss_procfs_cpumask_close,
	.vtss_procfs_read    = vtss_procfs_cpumask_read,
	.vtss_procfs_write   = vtss_procfs_cpumask_write,
};

static struct vtss_procfs_entry vtss_procfs_cpumask_entry = {
	.name = VTSS_PROCFS_CPUMASK_NAME,
	.ops = &vtss_procfs_cpumask_fops,
};

static void *vtss_procfs_targets_info_ptr = NULL;

static void *vtss_procfs_targets_start(struct seq_file *s, loff_t *pos)
{
	return (*pos) ? NULL : &vtss_procfs_targets_info_ptr;
}

static void vtss_procfs_targets_stop(struct seq_file *s, void *v)
{
}

static void *vtss_procfs_targets_next(struct seq_file *s, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void vtss_procfs_targets_show_pid(struct vtss_task *tsk, void *arg)
{
	struct seq_file *s = arg;

	if (!vtss_task_attached(tsk))
		return;
	if (vtss_task_leader(tsk))
		seq_printf(s, "%d\n", tsk->pid);
}

static int vtss_procfs_targets_show(struct seq_file *s, void *v)
{
	return vtss_task_map_for_each(vtss_procfs_targets_show_pid, s);
}

static struct seq_operations vtss_procfs_targets_sops = {
	.start = vtss_procfs_targets_start,
	.stop  = vtss_procfs_targets_stop,
	.next  = vtss_procfs_targets_next,
	.show  = vtss_procfs_targets_show,
};

static int vtss_procfs_targets_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &vtss_procfs_targets_sops);
}

static struct vtss_procfs_ops vtss_procfs_targets_fops = {
	.vtss_procfs_open    = vtss_procfs_targets_open,
	.vtss_procfs_read    = seq_read,
	.vtss_procfs_lseek   = seq_lseek,
	.vtss_procfs_release = seq_release,
};

static struct vtss_procfs_entry vtss_procfs_targets_entry = {
	.name = VTSS_PROCFS_TARGETS_NAME,
	.ops = &vtss_procfs_targets_fops,
};

static int vtss_procfs_timesrc_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int vtss_procfs_timesrc_close(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t vtss_procfs_timesrc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	ssize_t size = 0;
	char str[8]; /* enough for "tsc" or "sys" */

	if (*ppos == 0) {
		size = snprintf(str, sizeof(str) - 2, "%s", vtss_time_source ? "tsc" : "sys");
		if (size < 0)
			size = 0;
		str[size] = '\n';
		size++;
		str[size] = '\0';

		if (size <= count) {
			if (copy_to_user(buf, str, size))
				size = -EFAULT;
		} else {
			size = -EINVAL;
		}
		if (size > 0)
			*ppos += size;
	}
	return size;
}

static ssize_t vtss_procfs_timesrc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char str[8]; /* enough for "tsc" or "sys" */

	if (count < 3 || vtss_copy_from_user(str, buf, 3)) {
		vtss_pr_error("Failed to copy time source configuration");
		return -EFAULT;
	}
	str[3] = '\0';
	if (strcmp(str, "tsc") == 0) {
		if (check_tsc_unstable())
			vtss_pr_warning("TSC timer is unstable");
		vtss_time_source = VTSS_TIME_SOURCE_TSC;
	}
	if (strcmp(str, "sys") == 0)
		vtss_time_source = VTSS_TIME_SOURCE_SYS;
	return count;
}

static struct vtss_procfs_ops vtss_procfs_timesrc_fops = {
	.vtss_procfs_open    = vtss_procfs_timesrc_open,
	.vtss_procfs_release = vtss_procfs_timesrc_close,
	.vtss_procfs_read    = vtss_procfs_timesrc_read,
	.vtss_procfs_write   = vtss_procfs_timesrc_write,
};

static struct vtss_procfs_entry vtss_procfs_timesrc_entry = {
	.name = VTSS_PROCFS_TIMESRC_NAME,
	.ops = &vtss_procfs_timesrc_fops,
};

static int vtss_procfs_create_root_entry(void)
{
	int rc;
	struct path path;

	rc = kern_path(vtss_procfs_root_path(), 0, &path);
	if (!rc) {
#ifdef VTSS_AUTOCONF_PROCFS_SUBTREE
		/* if exist, remove it */
		path_put(&path);
		remove_proc_subtree(THIS_MODULE->name, NULL);
		rc = -ENOENT;
#else
		/* if exist, attach to it */
		vtss_procfs_root_entry = PDE(path.dentry->d_inode);
		path_put(&path);
#endif
	}
	if (rc) {
		/* doesn't exist, so create it */
		vtss_procfs_root_entry = proc_mkdir(THIS_MODULE->name, NULL);
	}
	if (vtss_procfs_root_entry == NULL) {
		vtss_pr_error("Failed to create '%s'", vtss_procfs_root_path());
		return -EFAULT;
	}
	vtss_procfs_set_user(vtss_procfs_root_entry, uid, gid);
	return 0;
}

static void vtss_procfs_remove_root_entry(void)
{
	if (vtss_procfs_root_entry == NULL)
		return;

#ifdef VTSS_AUTOCONF_PROCFS_SUBTREE
	remove_proc_subtree(THIS_MODULE->name, NULL);
#else
	if (atomic_read(&vtss_procfs_root_entry->count) != 1) {
		vtss_pr_warning("Failed to remove '%s'", vtss_procfs_root_path());
		return;
	}
	remove_proc_entry(THIS_MODULE->name, NULL);
#endif
	vtss_procfs_root_entry = NULL;
}

static int vtss_procfs_create_entry(struct vtss_procfs_entry *entry)
{
#ifdef VTSS_PROCFS_OPS_OWNER
	entry->ops->owner = THIS_MODULE;
#endif
	vtss_pr_debug_procfs("creating '%s'", entry->name);
	entry->pde = proc_create(entry->name, (mode_t)(mode ? (mode & 0666) : 0660),
				 vtss_procfs_root_entry, entry->ops);
	if (entry->pde == NULL) {
		vtss_pr_error("Failed to create '%s/%s'", vtss_procfs_root_path(), entry->name);
		return -EFAULT;
	}
	vtss_procfs_set_user(entry->pde, uid, gid);
	return 0;
}

static void vtss_procfs_remove_entry(struct vtss_procfs_entry *entry)
{
	if (entry->pde == NULL)
		return;

	vtss_pr_debug_procfs("removing '%s'", entry->name);
	remove_proc_entry(entry->name, vtss_procfs_root_entry);
	entry->pde = NULL;
}

int vtss_procfs_init(void)
{
	int rc;
	unsigned long flags;

	vtss_spin_lock_irqsave(&vtss_procfs_control_list_lock, flags);
	INIT_LIST_HEAD(&vtss_procfs_control_list);
	vtss_spin_unlock_irqrestore(&vtss_procfs_control_list_lock, flags);

	cpumask_copy(&vtss_cpumask, cpu_present_mask);

	rc = vtss_procfs_create_root_entry();
	if (rc) goto out_fail;

	rc = vtss_procfs_create_entry(&vtss_procfs_control_entry);
	if (rc) goto out_fail;

	rc = vtss_procfs_create_entry(&vtss_procfs_cpumask_entry);
	if (rc) goto out_fail;

	rc = vtss_procfs_create_entry(&vtss_procfs_targets_entry);
	if (rc) goto out_fail;

	rc = vtss_procfs_create_entry(&vtss_procfs_timesrc_entry);
	if (rc) goto out_fail;

	return 0;

out_fail:
	vtss_procfs_cleanup();
	return rc;
}

void vtss_procfs_cleanup(void)
{
	if (vtss_procfs_control_opened())
		vtss_pr_warning("Control entry is still opened");

	vtss_procfs_control_reset();
	vtss_procfs_remove_entry(&vtss_procfs_control_entry);
	vtss_procfs_remove_entry(&vtss_procfs_cpumask_entry);
	vtss_procfs_remove_entry(&vtss_procfs_targets_entry);
	vtss_procfs_remove_entry(&vtss_procfs_timesrc_entry);
	vtss_procfs_remove_root_entry();
}

const char *vtss_procfs_root_path(void)
{
	static char buf[MODULE_NAME_LEN + 7 /* strlen("/proc/") */];

	snprintf(buf, sizeof(buf) - 1, "/proc/%s", THIS_MODULE->name);
	return buf;
}

void vtss_procfs_set_user(struct proc_dir_entry *pde, int uid, int gid)
{
#ifdef VTSS_AUTOCONF_PROCFS_SET_USER
	kuid_t kuid = KUIDT_INIT(uid);
	kgid_t kgid = KGIDT_INIT(gid);
	proc_set_user(pde, kuid, kgid);
#else
	pde->uid = uid;
	pde->gid = gid;
#endif
}
