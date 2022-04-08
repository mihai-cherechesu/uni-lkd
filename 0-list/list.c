// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * TODO 1/0: Fill in name / email
 * Author: Mihai Cherechesu <mihai.cherechesu@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/ctype.h>

#define PROCFS_MAX_SIZE		512
#define PROCFS_CMD_SIZE		2

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"
#define procfs_add_front	"addf"
#define procfs_add_end		"adde"
#define procfs_del_first	"delf"
#define procfs_del_all		"dela"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

/* TODO 2: define your list! */
struct procfs_string {
	char *string;
	struct list_head list;
};

LIST_HEAD(head);

static struct procfs_string *procfs_string_alloc(char *string)
{
	struct procfs_string *ps;

	ps = kmalloc(sizeof(*ps), GFP_KERNEL);
	if (ps == NULL)
		return NULL;

	ps->string = kmalloc(strlen(string) + 1, GFP_KERNEL);
	if (ps->string == NULL)
		goto err_alloc;
	strcpy(ps->string, string);

	return ps;

err_alloc:
	kfree(ps);
	return NULL;
}

static void procfs_string_add(char *string, bool on_top)
{
	struct procfs_string *ps;

	ps = procfs_string_alloc(string);
	if (ps == NULL)
		return;

	if (on_top)
		list_add(&ps->list, &head);
	else
		list_add_tail(&ps->list, &head);
}

static void procfs_string_delete(char *string, bool delete_all)
{
	struct procfs_string *ps;
	struct list_head *p, *q;

	list_for_each_safe(p, q, &head) {
		ps = list_entry(p, struct procfs_string, list);

		if (!strcmp(ps->string, string)) {
			list_del(p);
			kfree(ps->string);
			kfree(ps);

			if (!delete_all)
				return;
		}
	}
}

static int list_proc_show(struct seq_file *m, void *v)
{
	struct procfs_string *ps;
	struct list_head *p;

	/* TODO 3: print your list. One element / line. */
	list_for_each(p, &head) {
		ps = list_entry(p, struct procfs_string, list);
		seq_puts(m, ps->string);
		seq_putc(m, '\n');
	}

	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static const char *skip_arg(const char *cp)
{
    while (*cp && !isspace(*cp))
        cp++;

    return cp;
}

static int count_argc(const char *str)
{
    int count = 0;

    while (*str) {
        str = skip_spaces(str);
        if (*str) {
            count++;
            str = skip_arg(str);
        }
    }

    return count;
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char **argv;
	char local_buffer[PROCFS_MAX_SIZE];
	int argv_count;
	unsigned long local_buffer_size = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	/* local_buffer contains your command written in /proc/list/management
	 * TODO 4/0: parse the command and add/delete elements.
	 */
	argv_count = count_argc(local_buffer);
	argv = argv_split(GFP_KERNEL, local_buffer, NULL);
	if (argv == NULL)
		return -ENOMEM;
	
	if (argv_count != PROCFS_CMD_SIZE)
		return -E2BIG;

	if (!strcmp(argv[0], procfs_add_end))
		procfs_string_add(argv[1], false);
	else if (!strcmp(argv[0], procfs_add_front))
		procfs_string_add(argv[1], true);
	else if (!strcmp(argv[0], procfs_del_first))
		procfs_string_delete(argv[1], false);
	else if (!strcmp(argv[0], procfs_del_all))
		procfs_string_delete(argv[1], true);
	else
		goto err_argv;

	argv_free(argv);
	return local_buffer_size;

err_argv:
	argv_free(argv);
	return -EINVAL;
}

static const struct proc_ops r_pops = {
	.proc_open		= list_read_open,
	.proc_read		= seq_read,
	.proc_release		= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open		= list_write_open,
	.proc_write		= list_write,
	.proc_release		= single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
/* TODO 5: Fill in your name / email address */
MODULE_AUTHOR("Mihai Cherechesu <mihai.cherechesu@gmail.com>");
MODULE_LICENSE("GPL v2");
