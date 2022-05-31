// SPDX-License-Identifier: GPL-2.0+

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include "tracer.h"

/*
 * tracer.c - Kprobe based tracer
 *
 * Author: Mihai Cherechesu <mihai.cherechesu@gmail.com>
 */

struct kmalloc_node {
	int size;
	void *address;
	struct hlist_node hlist;
};

struct tracer_node {
	pid_t pid;
	int calls_kmalloc;
	int calls_kfree;
	int calls_schedule;
	int calls_up;
	int calls_down;
	int calls_lock;
	int calls_unlock;
	int mem_kmalloc;
	int mem_kfree;
	struct hlist_node hlist;
};

struct proc_dir_entry *tracer_proc_read;

DEFINE_SPINLOCK(lock);
DEFINE_HASHTABLE(kmalloc_ht, ALLOCATIONS_HT_BITS);
DEFINE_HASHTABLE(tracer_ht, ALLOCATIONS_HT_BITS);

static void tracer_alloc_add(int size, void *address)
{
	struct kmalloc_node *node = kmalloc(sizeof(*node), GFP_KERNEL);

	if (!node)
		return;

	node->address	= address;
	node->size	= size;

	spin_lock(&lock);
	hash_add(kmalloc_ht, &node->hlist, (u32) node->address);
	spin_unlock(&lock);
}

static void tracer_add(pid_t pid)
{
	struct tracer_node *node = kmalloc(sizeof(*node), GFP_KERNEL);

	if (!node)
		return;

	node->pid		= pid;
	node->calls_kmalloc	= 0;
	node->calls_kfree	= 0;
	node->calls_schedule	= 0;
	node->calls_up		= 0;
	node->calls_down	= 0;
	node->calls_lock	= 0;
	node->calls_unlock	= 0;
	node->mem_kmalloc	= 0;
	node->mem_kfree		= 0;

	spin_lock(&lock);
	hash_add(tracer_ht, &node->hlist, (u32) pid);
	spin_unlock(&lock);
}

static struct kmalloc_node *alloc_find(void *address)
{
	struct kmalloc_node *node;

	hash_for_each_possible(kmalloc_ht, node, hlist, (u32) address) {
		if (node->address == address)
			return node;
	}

	return NULL;
}

static struct tracer_node *tracer_find(pid_t pid)
{
	struct tracer_node *node;

	hash_for_each_possible(tracer_ht, node, hlist, (u32) pid) {
		if (node->pid == pid)
			return node;
	}

	return NULL;
}

static void tracer_remove(pid_t pid)
{
	struct tracer_node *node = tracer_find(pid);

	if (!node)
		return;

	spin_lock(&lock);
	hash_del(&node->hlist);
	kfree(node);
	spin_unlock(&lock);
}

static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case TRACER_ADD_PROCESS:
		tracer_add((pid_t) arg);
		break;
	case TRACER_REMOVE_PROCESS:
		tracer_remove((pid_t) arg);
		break;
	default:
		break;
	}

	return 0;
}

static const struct file_operations tracer_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = tracer_ioctl
};

static struct miscdevice tracer_dev = {
	.minor	= TRACER_DEV_MINOR,
	.name	= TRACER_DEV_NAME,
	.fops	= &tracer_fops
};

static int kmalloc_probe_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int size = *((int *)(ri->data));
	struct tracer_node *node = tracer_find(current->pid);

	if (!node)
		return -ENOENT;

	tracer_alloc_add(size, (void *) regs_return_value(regs));
	spin_lock(&lock);
	node->mem_kmalloc += size;
	spin_unlock(&lock);

	return 0;
}

static int kmalloc_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_node *node;

	*(int *)ri->data = regs->ax;
	node = tracer_find(current->pid);
	if (!node)
		return -ENOENT;

	spin_lock(&lock);
	node->calls_kmalloc++;
	spin_unlock(&lock);

	return 0;
}

static int kfree_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	void *address = (void *) regs->ax;
	struct kmalloc_node *mem_node;
	struct tracer_node *node;

	mem_node = alloc_find(address);
	if (!mem_node)
		return -ENOENT;

	node = tracer_find(current->pid);
	if (!node)
		return -ENOENT;

	spin_lock(&lock);
	node->calls_kfree++;
	node->mem_kfree += mem_node->size;
	spin_unlock(&lock);

	return 0;
}

static int schedule_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_node *node = tracer_find(current->pid);

	if (!node)
		return -ENOENT;

	spin_lock(&lock);
	node->calls_schedule++;
	spin_unlock(&lock);

	return 0;
}

static int up_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_node *node = tracer_find(current->pid);

	if (!node)
		return -ENOENT;

	spin_lock(&lock);
	node->calls_up++;
	spin_unlock(&lock);
	return 0;
}

static int down_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_node *node = tracer_find(current->pid);

	if (!node)
		return -ENOENT;

	spin_lock(&lock);
	node->calls_down++;
	spin_unlock(&lock);

	return 0;
}

static int lock_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_node *node = tracer_find(current->pid);

	if (!node)
		return -ENOENT;

	spin_lock(&lock);
	node->calls_lock++;
	spin_unlock(&lock);

	return 0;
}

static int unlock_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_node *node = tracer_find(current->pid);

	if (!node)
		return -ENOENT;

	spin_lock(&lock);
	node->calls_unlock++;
	spin_unlock(&lock);

	return 0;
}

static struct kretprobe kmalloc_probe = {
	.entry_handler	= kmalloc_probe_entry_handler,
	.handler	= kmalloc_probe_ret_handler,
	.maxactive	= 32,
	.data_size	= sizeof(int),
	.kp		= { .symbol_name = "__kmalloc" },
};

static struct kretprobe kfree_probe = {
	.entry_handler	= kfree_probe_entry_handler,
	.maxactive	= 32,
	.kp		= { .symbol_name = "kfree" },
};

static struct kretprobe schedule_probe = {
	.entry_handler	= schedule_probe_entry_handler,
	.maxactive	= 32,
	.kp		= { .symbol_name = "schedule" },
};

static struct kretprobe up_probe = {
	.entry_handler	= up_probe_entry_handler,
	.maxactive	= 32,
	.kp		= { .symbol_name = "up" },
};

static struct kretprobe down_probe = {
	.entry_handler	= down_probe_entry_handler,
	.maxactive	= 32,
	.kp		= { .symbol_name = "down_interruptible" },
};

static struct kretprobe lock_probe = {
	.entry_handler	= lock_probe_entry_handler,
	.maxactive	= 32,
	.kp		= { .symbol_name = "mutex_lock_nested" },
};

static struct kretprobe unlock_probe = {
	.entry_handler	= unlock_probe_entry_handler,
	.maxactive	= 32,
	.kp		= { .symbol_name = "mutex_unlock" },
};

static int tracer_proc_show(struct seq_file *m, void *v)
{
	u32 bkt;
	struct tracer_node *node;

	seq_puts(m, "PID kmalloc kfree kmalloc_mem kfree_mem sched up down lock unlock\n");

	hash_for_each(tracer_ht, bkt, node, hlist) {
		seq_printf(m, "%d %d %d %d %d %d %d %d %d %d\n",
			node->pid,
			node->calls_kmalloc,
			node->calls_kfree,
			node->mem_kmalloc,
			node->mem_kfree,
			node->calls_schedule,
			node->calls_up,
			node->calls_down,
			node->calls_lock,
			node->calls_unlock);
	}

	return 0;
}

static int tracer_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, tracer_proc_show, NULL);
}

static const struct proc_ops procfs_fops = {
	.proc_open	= tracer_proc_open,
	.proc_release	= single_release,
	.proc_read	= seq_read
};

static int tracer_init(void)
{
	int ret;

	hash_init(kmalloc_ht);
	hash_init(tracer_ht);

	tracer_proc_read = proc_create(TRACER_DEV_NAME, 0000, NULL, &procfs_fops);
	if (!tracer_proc_read)
		return -ENOMEM;

	ret = misc_register(&tracer_dev);
	if (ret)
		return ret;

	register_kretprobe(&kmalloc_probe);
	register_kretprobe(&kfree_probe);
	register_kretprobe(&schedule_probe);
	register_kretprobe(&up_probe);
	register_kretprobe(&down_probe);
	register_kretprobe(&lock_probe);
	register_kretprobe(&unlock_probe);

	return 0;
}

static void tracer_exit(void)
{
	proc_remove(tracer_proc_read);
	misc_deregister(&tracer_dev);
	unregister_kretprobe(&kmalloc_probe);
	unregister_kretprobe(&kfree_probe);
	unregister_kretprobe(&schedule_probe);
	unregister_kretprobe(&up_probe);
	unregister_kretprobe(&down_probe);
	unregister_kretprobe(&lock_probe);
	unregister_kretprobe(&unlock_probe);
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Mihai Cherechesu <mihai.cherechesu@gmail.com>");
MODULE_LICENSE("GPL v2");
