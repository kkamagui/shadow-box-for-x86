/*
 *                          Shadow-Box
 *                         ------------
 *      Lightweight Hypervisor-Based Kernel Protector 
 * 
 *               Copyright (C) 2017 Seunghun Han
 *     at National Security Research Institute of South Korea
 */

/*
 * This software has GPL v2 license. See the GPL_LICENSE file.
 */
#ifndef __WORKAROUND_H__
#define __WORKAROUND_H__

/*
 * Macros.
 */
/*
 * Kernel patch workaround is experimental feature. If you want to use code
 * patch workaround, turn on this feature.
 */
#define SHADOWBOX_USE_WORKAROUND		0

/* Define for kernel workaround. */
#ifndef __GFP_COLD
#define __GFP_COLD 0
#endif 

#define SOCK_TYPE_TCP	0
#define SOCK_TYPE_UDP	1

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	typedef struct ldttss_desc64 LDTTSS_DESC;
#else
	typedef struct ldttss_desc LDTTSS_DESC;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#define INIT_LEVEL4_PGT		"init_level4_pgt"
#else
#define INIT_LEVEL4_PGT		"init_top_pgt"
#endif


/*
 * Structures.
 */
/* Workaround information structure. */
struct sb_workaround
{
	u64 addr_array[WORK_AROUND_MAX_COUNT];
	int count_array[WORK_AROUND_MAX_COUNT];
};

/* Read-only information entry structure. */
struct ro_addr_struct
{
	u64 start;
	u64 end;
	u64 type;
};

/* Predefined symbol entry structure. */
struct sb_symbol_addr_struct
{
	char* name;
	u64 addr;
};

/* Predefined symbol structure. */
struct sb_symbol_table_struct
{
	struct sb_symbol_addr_struct symbol[SYMBOL_MAX_COUNT];
};

/* Structure for kernel workaround. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
union proc_op {
	int (*proc_get_link)(struct dentry *, struct path *);
	int (*proc_show)(struct seq_file *m,
		struct pid_namespace *ns, struct pid *pid,
		struct task_struct *task);
};

struct proc_inode {
	struct pid *pid;
	unsigned int fd;
	union proc_op op;
	struct proc_dir_entry *pde;
	struct ctl_table_header *sysctl;
	struct ctl_table *sysctl_entry;
	struct hlist_node sysctl_inodes;
	const struct proc_ns_operations *ns_ops;
	struct inode vfs_inode;
};

struct proc_dir_entry {
	/*
	 * number of callers into module in progress;l
	 * negative -> it's going away RSN
	 */
	atomic_t in_use;
	refcount_t refcnt;
	struct list_head pde_openers;	/* who did ->open, but not ->release */
	/* protects ->pde_openers and all struct pde_opener instances */
	spinlock_t pde_unload_lock;
	struct completion *pde_unload_completion;
	const struct inode_operations *proc_iops;
	const struct file_operations *proc_fops;
	union {
		const struct seq_operations *seq_ops;
		int (*single_show)(struct seq_file *, void *);
	};
	/* ..omitted... */
};
#endif


/*
 * Functions.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
/* General functions for kernel workaround. */
static inline struct proc_inode *PROC_I(const struct inode *inode)
{
	return container_of(inode, struct proc_inode, vfs_inode);
}

static inline struct proc_dir_entry *PDE(const struct inode *inode)
{
	return PROC_I(inode)->pde;
}
#endif

#endif
