/*
 *                          Shadow-Box
 *                         ------------
 *      Lightweight Hypervisor-Based Kernel Protector
 *
 *               Copyright (C) 2017 Seunghun Han
 *     at National Security Research Institute of South Korea
 */

/*
 * This software has dual license (MIT and GPL v2). See the GPL_LICENSE and
 * MIT_LICENSE file.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <asm/spinlock.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include "shadow_box.h"
#include "shadow_watcher.h"
#include "mmu.h"
#include "asm.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#endif

/*
 * Variables.
 */
volatile int g_module_count = 0;
volatile int g_task_count = 0;
volatile u64 g_last_task_check_jiffies = 0;
volatile u64 g_last_module_check_jiffies = 0;
volatile u64 g_last_dkom_check_jiffies = 0;

static struct sb_task_manager g_task_manager;
static struct sb_module_manager g_module_manager;
static spinlock_t g_time_lock;
static volatile u64 g_tasklock_fail_count = 0;
static volatile u64 g_modulelock_fail_count = 0;
static int g_vfs_object_attack_detected = 0;
static int g_net_object_attack_detected = 0;

/*
 * Functions.
 */
static int sb_add_task_to_sw_task_manager(struct task_struct* task);
static int sb_add_module_to_sw_module_manager(struct module* mod, int protect);
static int sb_del_task_from_sw_task_manager(pid_t pid, pid_t tgid);
static int sw_del_module_from_sw_module_manager(struct module* mod);
static void sb_check_sw_task_periodic(int cpu_id);
static void sb_check_sw_module_periodic(int cpu_id);
static int sb_check_sw_module_list(int cpu_id);
static int sb_get_module_count(void);
static int sb_check_sw_vfs_object(int cpu_id);
static int sb_check_sw_net_object(int cpu_id);
static int sb_check_sw_inode_op_fields(int cpu_id, const struct inode_operations* op,
	const char* obj_name);
static int sb_check_sw_file_op_fields(int cpu_id, const struct file_operations* op,
	const char* obj_name);
static int sb_check_sw_tcp_seq_afinfo_fields(int cpu_id, const struct tcp_seq_afinfo* op,
	const char* obj_name);
static int sb_check_sw_proto_op_fields(int cpu_id, const struct proto_ops* op,
	const char* obj_name);
static int sb_check_sw_task_list(int cpu_id);
static int sw_is_in_task_list(struct task_struct* task);
static int sb_is_in_module_list(struct module* target);
static int sb_get_task_count(void);
static int sb_is_valid_vm_status(int cpu_id);

#if SHADOWBOX_USE_WATCHER_DEBUG
static int sb_get_list_count(struct list_head* head);
static void sb_validate_sw_task_list(int count_of_task_list);
static void sb_validate_sw_module_list(int count_of_module_list);
#endif /* SHADOWBOX_USE_WATCHER_DEBUG */

static void sb_copy_task_list_to_sw_task_manager(void);
static void sb_copy_module_list_to_sw_module_manager(void);

/*
 * Prepare Shadow-watcher.
 */
int sb_prepare_shadow_watcher(void)
{
	int i;
	int size;

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Framework Preinitialize\n");
	memset(&g_task_manager, 0, sizeof(g_task_manager));
	memset(&g_module_manager, 0, sizeof(g_module_manager));

	INIT_LIST_HEAD(&(g_task_manager.free_node_head));
	INIT_LIST_HEAD(&(g_task_manager.existing_node_head));
	size = sizeof(struct sb_task_node) * TASK_NODE_MAX;
	g_task_manager.pool = vmalloc(size);
	if (g_task_manager.pool == NULL)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] Task pool allcation fail\n");
		return -1;
	}
	memset(g_task_manager.pool, 0, size);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Task pool %016lX, size %d\n",
		g_task_manager.pool, size);

	for (i = 0 ; i < TASK_NODE_MAX ; i++)
	{
		list_add(&(g_task_manager.pool[i].list), &(g_task_manager.free_node_head));
	}

	INIT_LIST_HEAD(&(g_module_manager.free_node_head));
	INIT_LIST_HEAD(&(g_module_manager.existing_node_head));
	size = sizeof(struct sb_module_node) * MODULE_NODE_MAX;
	g_module_manager.pool = vmalloc(size);
	if (g_module_manager.pool == NULL)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] Module pool allcation fail\n");
		return -1;
	}
	memset(g_module_manager.pool, 0, size);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Module pool %016lX, size %d\n",
		g_module_manager.pool, size);

	for (i = 0 ; i < MODULE_NODE_MAX ; i++)
	{
		list_add(&(g_module_manager.pool[i].list), &(g_module_manager.free_node_head));
	}
	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Complete\n");

	return 0;
}

/*
 * Hiding Shadow-wacher data from the guest.
 */
void sb_protect_shadow_watcher_data(void)
{
	u64 size;

	size = sizeof(struct sb_task_node) * TASK_NODE_MAX;
	sb_hide_range((u64)g_task_manager.pool, (u64)g_task_manager.pool + size,
		ALLOC_VMALLOC);

	size = sizeof(struct sb_module_node) * MODULE_NODE_MAX;
	sb_hide_range((u64)g_module_manager.pool, (u64)g_module_manager.pool + size,
		ALLOC_VMALLOC);
}

/*
 * Initialize Shadow-watcher.
 */
void sb_init_shadow_watcher(void)
{
	spin_lock_init(&g_time_lock);

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Framework Initailize\n");

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Check task list\n");
	sb_copy_task_list_to_sw_task_manager();

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Check module list\n");
	sb_copy_module_list_to_sw_module_manager();

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Task count %d\n", g_task_count);
	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Module count %d\n", g_module_count);
	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Complete\n", g_module_count);
}

/*
 * Check a timer expired.
 *
 * If another core has already time lock, skip this time.
 */
static int sb_check_sw_timer_expired_and_update(volatile u64* last_jiffies)
{
	int expired = 0;
	u64 value;

	/* For syncronization. */
	if (spin_trylock(&g_time_lock))
	{
		value = jiffies - *last_jiffies;

		if (jiffies_to_usecs(value) >= TIMER_INTERVAL)
		{
			*last_jiffies = jiffies;
			expired = 1;
		}

		spin_unlock(&g_time_lock);
	}
	else
	{
		// Do nothing
	}

#if SHADOWBOX_HARD_TEST
	expired = 1;
#endif /* SHADOWBOX_HARD_TEST */

	return expired;
}

/*
 * Check task list periodically in VM timer.
 */
static void sb_check_sw_task_periodic(int cpu_id)
{
	if (!sb_check_sw_timer_expired_and_update(&g_last_task_check_jiffies))
	{
		return ;
	}

	if (write_trylock(g_tasklist_lock))
	{
		sb_check_sw_task_list(cpu_id);
		write_unlock(g_tasklist_lock);
	}
	else
	{
		/* If lock operation is failed, try next immediately. */
		g_last_task_check_jiffies = 0;
	}

}

/*
 * Check module list periodically in VM timer.
 */
static void sb_check_sw_module_periodic(int cpu_id)
{
	if (!sb_check_sw_timer_expired_and_update(&g_last_module_check_jiffies))
	{
		return ;
	}

	if(mutex_trylock(&module_mutex))
	{
		sb_check_sw_module_list(cpu_id);
		mutex_unlock(&module_mutex);
	}
	else
	{
		/* If lock operation is failed, try next immediately. */
		g_last_module_check_jiffies = 0;
	}
}

/*
 * Check function pointers periodically in VM timer.
 */
static void sb_check_function_pointers_periodic(int cpu_id)
{
	if (!sb_check_sw_timer_expired_and_update(&g_last_dkom_check_jiffies))
	{
		return ;
	}

	/* If detected, no more check again. */
	if (g_vfs_object_attack_detected == 0)
	{
		if (sb_check_sw_vfs_object(cpu_id) < 0)
		{
			g_vfs_object_attack_detected = 1;
		}
	}

	if (g_net_object_attack_detected == 0)
	{
		if (sb_check_sw_net_object(cpu_id) < 0)
		{
			g_net_object_attack_detected = 1;
		}
	}
}

/*
 * Check if VM status is valid.
 *
 * Check VM status after Shadow-box is completely loaded.
 */
static int sb_is_valid_vm_status(int cpu_id)
{
	if (atomic_read(&g_need_init_in_secure) == 0)
	{
		return 1;
	}

	return 0;
}

/*
 * Process callback of VM timer.
 */
void sb_sw_callback_vm_timer(int cpu_id)
{
	if (sb_is_valid_vm_status(cpu_id) == 1)
	{
		sb_check_sw_task_periodic(cpu_id);
		sb_check_sw_module_periodic(cpu_id);
		sb_check_function_pointers_periodic(cpu_id);
	}
}

/*
 * Syncronize page table of the host with page table of the guest.
 *
 * This is an internal function of sb_sync_sw_page().
 */
void sb_sync_sw_page_internal(u64 addr)
{
	u64 ret_value;

	ret_value = sb_sync_page_table(addr);
	if (ret_value != 0)
	{
#if SHADOWBOX_USE_PAGE_DEBUG
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "===================INFO======================");
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "sb_sync_page_table ret is not null "
			"ret:" "%016lX addr:%016lX\n", ret_value, addr);
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "===================INFO======================");
#endif /* SHADOWBOX_USE_PAGE_DEBUG */
	}

	return ;
}

/*
 * Syncronize page table of the host with page table of the guest.
 */
void sb_sync_sw_page(u64 addr, u64 size)
{
	u64 page_count;
	u64 i;

	// 올림
	page_count = ((addr % VAL_4KB) + size + VAL_4KB - 1) / VAL_4KB;

	for (i = 0 ; i < page_count ; i++)
	{
		sb_sync_sw_page_internal(addr + VAL_4KB * i);
	}
}

/*
 * Process add task callback.
 */
void sb_sw_callback_add_task(int cpu_id, struct sb_vm_exit_guest_register* context)
{
	struct task_struct* task;

	task = (struct task_struct*)context->rdi;

	while (!write_trylock(g_tasklist_lock))
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] ==== Task Add Lock Fail ===\n",
			cpu_id);
		sb_pause_loop();
		g_tasklock_fail_count++;
	}

	if (g_task_count == 0)
	{
		goto EXIT;
	}

	/* Syncronize before introspection. */
	sb_sync_sw_page((u64)task, sizeof(struct task_struct));

	if (task->pid != task->tgid)
	{
		goto EXIT;
	}

	if (sw_is_in_task_list(task))
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Task Create addr:%016lX "
			"phy:%016lX pid %d tgid %d [%s]\n", cpu_id, task, virt_to_phys(task),
			task->pid, task->tgid, task->comm);

		sb_add_task_to_sw_task_manager(task);
		sb_check_sw_task_list(cpu_id);
	}

EXIT:
	write_unlock(g_tasklist_lock);
}

/*
 * Process delete task callback.
 *
 * Task is still alive when this function is called.
 */
void sb_sw_callback_del_task(int cpu_id, struct sb_vm_exit_guest_register* context)
{
	struct task_struct* task;

	while (!write_trylock(g_tasklist_lock))
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] ==== Task Remove Lock Fail ===\n",
			cpu_id);
		sb_pause_loop();
		g_tasklock_fail_count++;
	}

	if (g_task_count == 0)
	{
		goto EXIT;
	}

	task = (struct task_struct*)context->rdi;

	if (task->pid != task->tgid)
	{
		goto EXIT;
	}

	if (sw_is_in_task_list(task))
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Task Delete %d %d [%s]\n",
			cpu_id, task->pid, task->tgid, task->comm);

		sb_check_sw_task_list(cpu_id);
		sb_del_task_from_sw_task_manager(task->pid, task->tgid);
	}

EXIT:
	write_unlock(g_tasklist_lock);
}


#if SHADOWBOX_USE_WATCHER_DEBUG
/*
 * Check task list for debugging.
 */
static void sb_validate_sw_task_list(int count_of_task_list)
{
	int free_count;
	int exist_count;

	free_count = sb_get_list_count(g_task_manager.free_node_head.next);
	exist_count = sb_get_list_count(g_task_manager.existing_node_head.next);

	if ((free_count + exist_count) != TASK_NODE_MAX)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================================================\n");
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "Task count is not match, free count [%d], "
			"exist count [%d], max count [%d]\n", free_count, exist_count,
			TASK_NODE_MAX);
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================================================\n");
	}

	if (count_of_task_list < exist_count)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================================================\n");
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "Task count is not match, count of task "
			"list[%d], exist count of task_manager [%d]\n", count_of_task_list,
			exist_count);
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================================================\n");
	}
}

/*
 * Check module list for debugging.
 */
static void sb_validate_sw_module_list(int count_of_module_list)
{
	int free_count;
	int exist_count;

	free_count = sb_get_list_count(g_module_manager.free_node_head.next);
	exist_count = sb_get_list_count(g_module_manager.existing_node_head.next);

	if ((free_count + exist_count) != MODULE_NODE_MAX)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================================================");
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "Module count is not match, free count [%d], "
			"exist count [%d], max count [%d]", free_count, exist_count,
			MODULE_NODE_MAX);
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================================================");
	}

	if (count_of_module_list < exist_count)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================================================");
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "Module count is not match, count of "
			"module list [%d], exist count of module_manager [%d]",
			count_of_module_list, exist_count);
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "===============================================================");
	}
}
#endif

/*
 * Check task list.
 */
static int sb_check_sw_task_list(int cpu_id)
{
	struct list_head *node;
	struct list_head *next;
	struct sb_task_node *target;
	int cur_count;

	cur_count = sb_get_task_count();

#if SHADOWBOX_USE_WATCHER_DEBUG
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] sb_check_sw_task_list, "
		"cur_task_count[%d], task_manager_task_count[%d]", cpu_id, cur_count,
		g_task_count);

	sb_validate_sw_task_list(cur_count);
#endif /* SHADOWBOX_USE_WATCHER_DEBUG */

	if (g_task_count > cur_count)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Task count is different, "
			"expect=%d real=%d\n", cpu_id, g_task_count, cur_count);

		list_for_each_safe(node, next, &(g_task_manager.existing_node_head))
		{
			target = container_of(node, struct sb_task_node, list);

			if (sw_is_in_task_list(target->task))
			{
				continue;
			}

			sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Hidden task, PID=%d "
				"TGID=%d fork name=\"%s\" process name=\"%s\"\n", cpu_id,
				target->pid, target->tgid, target->comm, target->task->comm);

			sb_del_task_from_sw_task_manager(target->pid, target->tgid);
		}

		sb_error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}

	return 0;
}


/*
 * Process task switch callback.
 */
void sb_sw_callback_task_switch(int cpu_id)
{
	sb_check_sw_task_list(cpu_id);
}

/*
 * Process insmod callback.
 *
 * The module is in module list already when this function is called.
 */
void sb_sw_callback_insmod(int cpu_id)
{
	struct module *mod;
	struct list_head* mod_head_node;

	mod_head_node = g_modules_ptr;
	while (!mutex_trylock(&module_mutex))
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] ==== Module Insmod Lock Fail ===\n",
			cpu_id);
		sb_pause_loop();
		g_modulelock_fail_count++;
	}

	if (g_module_count == 0)
	{
		goto EXIT;
	}

	/* Get last module information and synchronize before introspection. */
	mod = list_entry((mod_head_node->next), struct module, list);
	sb_sync_sw_page((u64)mod, sizeof(struct module));

	sb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Kernel module is loaded, "
		"current PID=%d PPID=%d process name=%s module=%s\n", cpu_id,
		current->pid, current->parent->pid, current->comm, mod->name);

	/* Add module without protect option. */
	sb_add_module_to_sw_module_manager(mod, 0);
	sb_check_sw_module_list(cpu_id);

EXIT:
	mutex_unlock(&module_mutex);
}

/*
 * Process rmmod callback.
 *
 * The module is still in module list when this function is called.
 */
void sb_sw_callback_rmmod(int cpu_id, struct sb_vm_exit_guest_register* context)
{
	struct module* mod;
	u64 mod_base;
	u64 mod_ro_size;

	while (!mutex_trylock(&module_mutex))
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] ==== Module Rmmod Lock Fail ===\n",
			cpu_id);
		sb_pause_loop();
		g_modulelock_fail_count++;
	}

	if (g_module_count == 0)
	{
		goto EXIT;
	}

	/* Synchronize before introspection. */
	mod = (struct module*)context->rdi;
	sb_sync_sw_page((u64)mod, sizeof(struct module));
	sb_sync_sw_page((u64)current, sizeof(struct task_struct));

	if (!sb_is_in_module_list(mod))
	{
		goto EXIT;
	}

	if (mod != THIS_MODULE)
	{
		/* Relase all memory and give all permission to physical pages. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		mod_base = (u64)mod->module_core;
		mod_ro_size = (u64)mod->core_ro_size;
#else
		mod_base = (u64)(mod->core_layout.base);
		mod_ro_size = (u64)(mod->core_layout.ro_size);
#endif /* LINUX_VERSION_CODE */
		sb_set_all_access_range(mod_base, mod_base + mod_ro_size, ALLOC_VMALLOC);
		sb_delete_ro_area(mod_base, mod_base + mod_ro_size);

		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Kernel module is unloaded, "
			"current PID=%d PPID=%d process name=%s module=%s\n", cpu_id,
			current->pid, current->parent->pid, current->comm, mod->name);

		sb_check_sw_module_list(cpu_id);
		sw_del_module_from_sw_module_manager(mod);
	}
	else
	{
		if (mod == THIS_MODULE)
		{
			/* Shadow-box should not be unloaded. */
			sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Process try to unload, "
				"Shadow-box. current PID=%d PPID=%d process name=%s\n", cpu_id,
				current->pid, current->parent->pid, current->comm);
		}
		else
		{
			/* Shadow-box-helper should not be unloaded. */
			sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Process try to unload, "
				"Shado-box-helper. current PID=%d PPID=%d process name=%s\n", 
				cpu_id, current->pid, current->parent->pid, current->comm);
		}

		sb_insert_exception_to_vm();
	}

EXIT:
	mutex_unlock(&module_mutex);
}

#if SHADOWBOX_USE_WATCHER_DEBUG
/*
 * Get count of list.
 */
static int sb_get_list_count(struct list_head* head)
{
	struct list_head *node;
	int cur_count = 0;

	list_for_each(node, head)
	{
		cur_count++;
	}

	return cur_count;
}
#endif /* SHADOWBOX_USE_WATCHER_DEBUG */

/*
 * Check module list.
 */
static int sb_check_sw_module_list(int cpu_id)
{
	struct list_head *node;
	struct list_head *next;
	struct sb_module_node *target;
	int count;

	count = sb_get_module_count();

#if SHADOWBOX_USE_WATCHER_DEBUG
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] sb_check_sw_module_list, "
		"cur_module_count [%d], module_manager_module_count [%d]", cpu_id, count,
		sb_get_list_count(g_module_manager.existing_node_head.next));

	sb_validate_sw_module_list(count);
#endif /* SHADOWBOX_USE_WATCHER_DEBUG */

	if (g_module_count > count)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Module count is different, "
			"expect=%d real=%d\n", cpu_id, g_module_count, count);

		list_for_each_safe(node, next, &(g_module_manager.existing_node_head))
		{
			target = container_of(node, struct sb_module_node, list);
			if (sb_is_in_module_list(target->module))
			{
				continue;
			}

			sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Hidden module, module "
				"name=\"%s\" ptr=%016lX\n", cpu_id, target->name, target->module);

			sw_del_module_from_sw_module_manager(target->module);
		}

		sb_error_log(ERROR_KERNEL_MODIFICATION);
	}

	return g_module_count;
}

/*
 * Get module count.
 */
static int sb_get_module_count(void)
{
	struct list_head *pos, *node;
	int count = 0;
	struct module* cur;

	node = g_modules_ptr;

	list_for_each(pos, node)
	{
		cur = container_of(pos, struct module, list);
		if (cur != NULL)
		{
			sb_sync_sw_page((u64)cur, sizeof(cur));

			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "kernel module %s, list ptr %016lX, "
				"phy %016lX module ptr %016lX, phy %016lX\n", cur->name, pos,
				virt_to_phys(pos), cur, virt_to_phys(pos));
		}
		count++;
	}

	return count;
}

/*
 * Check if the module is in module list.
 */
static int sb_is_in_module_list(struct module* target)
{
	struct list_head *pos, *node;
	struct module* cur;
	int find = 0;

	node = g_modules_ptr;

	/* Synchronize before introspection. */
	sb_sync_sw_page((u64)(node->next), sizeof(struct list_head));

	list_for_each(pos, node)
	{
		cur = container_of(pos, struct module, list);
		sb_sync_sw_page((u64)cur, sizeof(cur));
		if (cur == target)
		{
			find = 1;
			break;
		}

		sb_sync_sw_page((u64)(pos->next), sizeof(struct list_head));
	}

	return find;
}

/*
 * Get task count.
 */
static int sb_get_task_count(void)
{
	struct task_struct *iter;
	int count = 0;

	sb_sync_sw_page((u64)(init_task.tasks.next), sizeof(struct task_struct));
	for_each_process(iter)
	{
		count++;

		if (count >= TASK_NODE_MAX - 1)
		{
			sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "Task count overflows\n");
			break;
		}
		sb_sync_sw_page((u64)(iter->tasks.next), sizeof(struct task_struct));
	}

	return count;
}

/*
 * Add new task to task manager.
 */
static int sb_add_task_to_sw_task_manager(struct task_struct *task)
{
	struct list_head *temp;
	struct sb_task_node *node;

	g_task_count++;

	if (list_empty(&(g_task_manager.free_node_head)))
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "Task count overflows\n");
		sb_error_log(ERROR_TASK_OVERFLOW);
		return -1;
	}

	temp = g_task_manager.free_node_head.next;
	node = container_of(temp, struct sb_task_node, list);
	list_del(&(node->list));

	node->pid = task->pid;
	node->tgid = task->tgid;
	node->task = task;
	memcpy(node->comm, task->comm, sizeof(node->comm));

	list_add(&(node->list), &(g_task_manager.existing_node_head));

	return 0;
}

/*
 * Copy task list to task manager.
 */
static void sb_copy_task_list_to_sw_task_manager(void)
{
	struct task_struct *iter;

	for_each_process(iter)
	{
		if (sb_add_task_to_sw_task_manager(iter) != 0)
		{
			return ;
		}
	}
}

/*
 * Add new module to module manager.
 */
static int sb_add_module_to_sw_module_manager(struct module *mod, int protect)
{
	struct list_head *temp;
	struct sb_module_node* node;

	g_module_count++;

	if (list_empty(&(g_module_manager.free_node_head)))
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "Module count overflows\n");
		sb_error_log(ERROR_MODULE_OVERFLOW);
		return -1;
	}

	temp = g_module_manager.free_node_head.next;
	node = container_of(temp, struct sb_module_node, list);
	list_del(&(node->list));

	node->module = mod;
	node->protect = protect;
	memcpy(node->name, mod->name, sizeof(mod->name));

	list_add(&(node->list), &(g_module_manager.existing_node_head));

	return 0;
}

/*
 * Copy module list to module manager.
 */
static void sb_copy_module_list_to_sw_module_manager(void)
{
	struct module *mod;
	struct list_head *pos, *node;

	node = g_modules_ptr;
	list_for_each(pos, node)
	{
		mod = container_of(pos, struct module, list);

		if (mod == THIS_MODULE)
		{
			continue;
		}

		/* Add module with protect option. */
		sb_add_module_to_sw_module_manager(mod, 1);
	}
}

/*
 * Delete the task from task manager.
 */
static int sb_del_task_from_sw_task_manager(pid_t pid, pid_t tgid)
{
	struct list_head *node;
	struct sb_task_node *target;

	g_task_count--;

	list_for_each(node, &(g_task_manager.existing_node_head))
	{
		target = container_of(node, struct sb_task_node, list);
		if ((pid == target->pid) && (tgid == target->tgid))
		{
			list_del(&(target->list));
			list_add(&(target->list), &(g_task_manager.free_node_head));
			return 0;
		}
	}

	return -1;
}

/*
 * Delete the module from module manager.
 */
static int sw_del_module_from_sw_module_manager(struct module *mod)
{
	struct list_head *node;
	struct sb_module_node *target;

	g_module_count--;

	list_for_each(node, &(g_module_manager.existing_node_head))
	{
		target = container_of(node, struct sb_module_node, list);
		if (target->module == mod)
		{
			list_del(&(target->list));
			list_add(&(target->list), &(g_module_manager.free_node_head));
			return 0;
		}
	}

	return -1;
}

/*
 * Check if the task is in task list.
 */
static int sw_is_in_task_list(struct task_struct* task)
{
	struct task_struct *iter;
	int is_in = 0;

	sb_sync_sw_page((u64)(init_task.tasks.next), sizeof(struct task_struct));

	for_each_process(iter)
	{
		if ((iter == task) && (task->pid == iter->pid) &&
			(task->tgid == iter->tgid))
		{
			is_in = 1;
			break;
		}

		sb_sync_sw_page((u64)(iter->tasks.next), sizeof(struct task_struct));
	}

	return is_in;
}

/*
 * Check integrity of inode function pointers.
 */
static int sb_check_sw_inode_op_fields(int cpu_id, const struct inode_operations* op,
	const char* obj_name)
{
	int error = 0;

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s inode operation fields\n",
		obj_name);

	error |= !sb_is_addr_in_ro_area(op->lookup);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
	error |= !sb_is_addr_in_ro_area(op->follow_link);
#else
	error |= !sb_is_addr_in_ro_area(op->get_link);
#endif /* LINUX_VERSION_CODE */
	error |= !sb_is_addr_in_ro_area(op->permission);
	error |= !sb_is_addr_in_ro_area(op->get_acl);
	error |= !sb_is_addr_in_ro_area(op->readlink);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
	error |= !sb_is_addr_in_ro_area(op->put_link);
#endif /* LINUX_VERSION_CODE */
	error |= !sb_is_addr_in_ro_area(op->create);
	error |= !sb_is_addr_in_ro_area(op->link);
	error |= !sb_is_addr_in_ro_area(op->unlink);
	error |= !sb_is_addr_in_ro_area(op->symlink);
	error |= !sb_is_addr_in_ro_area(op->mkdir);
	error |= !sb_is_addr_in_ro_area(op->rmdir);
	error |= !sb_is_addr_in_ro_area(op->mknod);
	error |= !sb_is_addr_in_ro_area(op->rename);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !sb_is_addr_in_ro_area(op->rename2);
#endif /* LINUX_VERSION_CODE */
	error |= !sb_is_addr_in_ro_area(op->setattr);
	error |= !sb_is_addr_in_ro_area(op->getattr);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !sb_is_addr_in_ro_area(op->setxattr);
	error |= !sb_is_addr_in_ro_area(op->getxattr);
#endif /* LINUX_VERSION_CODE */
	error |= !sb_is_addr_in_ro_area(op->listxattr);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !sb_is_addr_in_ro_area(op->removexattr);
#endif /* LINUX_VERSION_CODE */
	error |= !sb_is_addr_in_ro_area(op->fiemap);
	error |= !sb_is_addr_in_ro_area(op->update_time);
	error |= !sb_is_addr_in_ro_area(op->atomic_open);
	error |= !sb_is_addr_in_ro_area(op->tmpfile);
	error |= !sb_is_addr_in_ro_area(op->set_acl);

	if (error != 0)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Function pointer attack is "
			"detected, function pointer=\"%s inode_op\"\n", cpu_id, obj_name);

		sb_error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}

/*
 * Check integrity of file function pointers.
 */
static int sb_check_sw_file_op_fields(int cpu_id, const struct file_operations* op,
	const char* obj_name)
{
	int error = 0;

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s file operation fields\n",
		obj_name);

	error |= !sb_is_addr_in_ro_area(op->llseek);
	error |= !sb_is_addr_in_ro_area(op->read);
	error |= !sb_is_addr_in_ro_area(op->write);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	error |= !sb_is_addr_in_ro_area(op->aio_read);
	error |= !sb_is_addr_in_ro_area(op->aio_write);
#endif /* LINUX_VERSION_CODE */
	error |= !sb_is_addr_in_ro_area(op->read_iter);
	error |= !sb_is_addr_in_ro_area(op->write_iter);
	error |= !sb_is_addr_in_ro_area(op->iterate);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	error |= !sb_is_addr_in_ro_area(op->iterate_shared);
#endif /* LINUX_VERSION_CODE */
	error |= !sb_is_addr_in_ro_area(op->poll);
	error |= !sb_is_addr_in_ro_area(op->unlocked_ioctl);
	error |= !sb_is_addr_in_ro_area(op->compat_ioctl);
	error |= !sb_is_addr_in_ro_area(op->mmap);
	error |= !sb_is_addr_in_ro_area(op->open);
	error |= !sb_is_addr_in_ro_area(op->flush);
	error |= !sb_is_addr_in_ro_area(op->release);
	error |= !sb_is_addr_in_ro_area(op->fsync);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !sb_is_addr_in_ro_area(op->aio_fsync);
#endif /* LINUX_VERSION_CODE */
	error |= !sb_is_addr_in_ro_area(op->fasync);
	error |= !sb_is_addr_in_ro_area(op->lock);
	error |= !sb_is_addr_in_ro_area(op->sendpage);
	error |= !sb_is_addr_in_ro_area(op->get_unmapped_area);
	error |= !sb_is_addr_in_ro_area(op->check_flags);
	error |= !sb_is_addr_in_ro_area(op->flock);
	error |= !sb_is_addr_in_ro_area(op->splice_write);
	error |= !sb_is_addr_in_ro_area(op->splice_read);
	error |= !sb_is_addr_in_ro_area(op->setlease);
	error |= !sb_is_addr_in_ro_area(op->fallocate);
	error |= !sb_is_addr_in_ro_area(op->show_fdinfo);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	error |= !sb_is_addr_in_ro_area(op->copy_file_range);
	error |= !sb_is_addr_in_ro_area(op->clone_file_range);
	error |= !sb_is_addr_in_ro_area(op->dedupe_file_range);
#endif /* LINUX_VERSION_CODE */

	if (error != 0)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Function pointer attack is "
			"detected, function pointer=\"%s file_op\"\n", cpu_id, obj_name);
		sb_error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}

/*
 * Check integrity of VFS function pointers.
 */
static int sb_check_sw_vfs_object(int cpu_id)
{
	struct inode_operations* inode_op;
	struct file_operations* file_op;
	int ret = 0;

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Check /proc vfs field\n", cpu_id);
	if (g_proc_file_ptr == NULL)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d]     [*] Check /proc vfs field "
			"fail\n", cpu_id);
	}
	else
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		inode_op = (struct inode_operations*)
			g_proc_file_ptr->f_dentry->d_inode->i_op;
#else
		inode_op = (struct inode_operations*)
			g_proc_file_ptr->f_path.dentry->d_inode->i_op;
#endif /* LINUX_VERSION_CODE */
		file_op = (struct file_operations*)g_proc_file_ptr->f_op;

		/* Check integrity of inode and file operation function pointers. */
		ret |= sb_check_sw_inode_op_fields(cpu_id, inode_op, "Proc FS");
		ret |= sb_check_sw_file_op_fields(cpu_id, file_op, "Proc FS");
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Check / vfs field\n", cpu_id);
	if (g_root_file_ptr == NULL)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d]     [*] Check / vfs field fail\n",
			cpu_id);
	}
	else
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		inode_op = (struct inode_operations*)
			g_root_file_ptr->f_dentry->d_inode->i_op;
#else
		inode_op = (struct inode_operations*)
			g_root_file_ptr->f_path.dentry->d_inode->i_op;
#endif /* LINUX_VERSION_CODE */
		file_op = (struct file_operations*)
			g_root_file_ptr->f_op;

		/* Check integrity of inode and file operation function pointers. */
		ret |= sb_check_sw_inode_op_fields(cpu_id, inode_op, "Root FS");
		ret |= sb_check_sw_file_op_fields(cpu_id, file_op, "Root FS");
	}

	return ret;
}

/*
 * Check integrity of TCP function pointers.
 */
static int sb_check_sw_tcp_seq_afinfo_fields(int cpu_id, const struct tcp_seq_afinfo* op,
	const char* obj_name)
{
	int error = 0;

	if (sb_check_sw_file_op_fields(cpu_id, op->seq_fops, obj_name) < 0)
	{
		return -1;
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s seq_operations function "
		"pointer\n", obj_name);

	error |= !sb_is_addr_in_ro_area(op->seq_ops.start);
	error |= !sb_is_addr_in_ro_area(op->seq_ops.stop);
	error |= !sb_is_addr_in_ro_area(op->seq_ops.next);
	error |= !sb_is_addr_in_ro_area(op->seq_ops.show);

	if (error != 0)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Function pointer attack is "
			"detected, function pointer=\"%s tcp_seq_afinfo\"\n", cpu_id, obj_name);

		sb_error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}

/*
 * Check integrity of UDP function pointers.
 */
static int sb_check_sw_udp_seq_afinfo_fields(int cpu_id, const struct udp_seq_afinfo* op,
	const char* obj_name)
{
	int error = 0;

	if (sb_check_sw_file_op_fields(cpu_id, op->seq_fops, obj_name) < 0)
	{
		return -1;
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s seq_operations function "
		"pointer\n", obj_name);

	error |= !sb_is_addr_in_ro_area(op->seq_ops.start);
	error |= !sb_is_addr_in_ro_area(op->seq_ops.stop);
	error |= !sb_is_addr_in_ro_area(op->seq_ops.next);
	error |= !sb_is_addr_in_ro_area(op->seq_ops.show);

	if (error != 0)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Function pointer attack is "
			"detected, function pointer=\"%s udp_seq_afinfo\"\n", cpu_id, obj_name);

		sb_error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}


/*
 * Check integrity of protocol function pointers.
 */
static int sb_check_sw_proto_op_fields(int cpu_id, const struct proto_ops* op, const char*
	obj_name)
{
	int error = 0;

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s proto_ops operation fields\n",
		obj_name);

	error |= !sb_is_addr_in_ro_area(op->release);
	error |= !sb_is_addr_in_ro_area(op->bind);
	error |= !sb_is_addr_in_ro_area(op->connect);
	error |= !sb_is_addr_in_ro_area(op->socketpair);
	error |= !sb_is_addr_in_ro_area(op->accept);
	error |= !sb_is_addr_in_ro_area(op->getname);
	error |= !sb_is_addr_in_ro_area(op->poll);
	error |= !sb_is_addr_in_ro_area(op->ioctl);
	error |= !sb_is_addr_in_ro_area(op->compat_ioctl);
	error |= !sb_is_addr_in_ro_area(op->listen);
	error |= !sb_is_addr_in_ro_area(op->shutdown);
	error |= !sb_is_addr_in_ro_area(op->setsockopt);
	error |= !sb_is_addr_in_ro_area(op->getsockopt);
	error |= !sb_is_addr_in_ro_area(op->compat_setsockopt);
	error |= !sb_is_addr_in_ro_area(op->compat_getsockopt);
	error |= !sb_is_addr_in_ro_area(op->sendmsg);
	error |= !sb_is_addr_in_ro_area(op->recvmsg);
	error |= !sb_is_addr_in_ro_area(op->mmap);
	error |= !sb_is_addr_in_ro_area(op->sendpage);
	error |= !sb_is_addr_in_ro_area(op->splice_read);
	error |= !sb_is_addr_in_ro_area(op->set_peek_off);
	if (error != 0)
	{
		sb_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Function pointer attack is "
			"detected, function pointer=\"%s proto_seq_afinfo\"\n", cpu_id, obj_name);

		sb_error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}

/*
 * Check integrity of net function pointers.
 */
static int sb_check_sw_net_object(int cpu_id)
{
	struct tcp_seq_afinfo* tcp_afinfo;
	struct udp_seq_afinfo* udp_afinfo;
	int ret = 0;

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Check Net Object\n");

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check TCP Net Object\n");
	if (g_tcp_file_ptr != NULL)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		tcp_afinfo = (struct tcp_seq_afinfo*)
			PDE_DATA(g_tcp_file_ptr->f_dentry->d_inode);
#else
		tcp_afinfo = (struct tcp_seq_afinfo*)
			PDE_DATA(g_tcp_file_ptr->f_path.dentry->d_inode);
#endif /* LINUX_VERSION_CODE */
		ret |= sb_check_sw_tcp_seq_afinfo_fields(cpu_id, tcp_afinfo, "TCP Net");
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check UDP Net Object\n");
	if (g_udp_file_ptr != NULL)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		udp_afinfo = (struct udp_seq_afinfo*)
			PDE_DATA(g_udp_file_ptr->f_dentry->d_inode);
#else
		udp_afinfo = (struct udp_seq_afinfo*)
			PDE_DATA(g_udp_file_ptr->f_path.dentry->d_inode);
#endif /* LINUX_VERSION_CODE */
		ret |= sb_check_sw_udp_seq_afinfo_fields(cpu_id, udp_afinfo, "UDP Net");
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check TCP6 Net Object\n");
	if (g_tcp6_file_ptr != NULL)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		tcp_afinfo = (struct tcp_seq_afinfo*)
			PDE_DATA(g_tcp6_file_ptr->f_dentry->d_inode);
#else
		tcp_afinfo = (struct tcp_seq_afinfo*)
			PDE_DATA(g_tcp6_file_ptr->f_path.dentry->d_inode);
#endif /* LINUX_VERSION_CODE */
		ret |= sb_check_sw_tcp_seq_afinfo_fields(cpu_id, tcp_afinfo, "TCP6 Net");
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check UDP6 Net Object\n");
	if (g_udp6_file_ptr != NULL)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		udp_afinfo = (struct udp_seq_afinfo*)
			PDE_DATA(g_udp6_file_ptr->f_dentry->d_inode);
#else
		udp_afinfo = (struct udp_seq_afinfo*)
			PDE_DATA(g_udp6_file_ptr->f_path.dentry->d_inode);
#endif /* LINUX_VERSION_CODE */
		ret |= sb_check_sw_udp_seq_afinfo_fields(cpu_id, udp_afinfo, "UDP6 Net");
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check TCP Socket Object\n");
	if (g_tcp_sock != NULL)
	{
		ret |= sb_check_sw_proto_op_fields(cpu_id, g_tcp_sock->ops, "TCP Socket");
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check UDP Socket Object\n");
	if (g_udp_sock != NULL)
	{
		ret |= sb_check_sw_proto_op_fields(cpu_id, g_udp_sock->ops, "UDP Socket");
	}

	return ret;
}
