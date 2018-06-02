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
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/getcpu.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <asm/desc.h>
#include <linux/kallsyms.h>
#include <asm/reboot.h>
#include <linux/reboot.h>
#include <asm/cacheflush.h>
#include <linux/hardirq.h>
#include <asm/processor.h>
#include <asm/pgtable_64.h>
#include <asm/hw_breakpoint.h>
#include <asm/debugreg.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/utsname.h>
#include <linux/mmzone.h>
#include <linux/jiffies.h>
#include <linux/tboot.h>
#include <linux/log2.h>
#include <linux/version.h>
#include <linux/kfifo.h>
#include <asm/uaccess.h>
#include "asm.h"
#include "shadow_box.h"
#include "shadow_watcher.h"
#include "mmu.h"
#include "iommu.h"
#include "asm.h"
#include "symbol.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/vmalloc.h>
#endif

/*
 * Variables.
 */
/* Variables for supporting multi-core environment. */
struct task_struct *g_vm_start_thread_id[MAX_PROCESSOR_COUNT]= {NULL, };
int g_thread_result = 0;
struct task_struct *g_vm_shutdown_thread_id[MAX_PROCESSOR_COUNT]= {NULL, };
struct desc_ptr g_gdtr_array[MAX_PROCESSOR_COUNT];
void* g_vmx_on_vmcs_log_addr[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_guest_vmcs_log_addr[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_vm_exit_stack_addr[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_io_bitmap_addrA[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_io_bitmap_addrB[MAX_PROCESSOR_COUNT] = {NULL, };
void* g_msr_bitmap_addr[MAX_PROCESSOR_COUNT] = {NULL, };
int g_trap_count[MAX_PROCESSOR_COUNT] = {0, };
void* g_virt_apic_page_addr[MAX_PROCESSOR_COUNT] = {NULL, };
int g_vmx_root_mode[MAX_PROCESSOR_COUNT] = {0, };
u64 g_stack_size = MAX_STACK_SIZE;
u64 g_vm_host_phy_pml4 = 0;
u64 g_vm_init_phy_pml4 = 0;
struct module* g_shadow_box_module = NULL;
static int g_support_smx = 0;
static int g_support_xsave = 0;

atomic_t g_need_init_in_secure = {1};
volatile int g_allow_shadow_box_hide = 0;
volatile u64 g_init_in_secure_jiffies = 0;
atomic_t g_thread_run_flags;
atomic_t g_thread_entry_count;
atomic_t g_sync_flags;
atomic_t g_complete_flags;
atomic_t g_framework_init_start_flags;
atomic_t g_enter_flags;
atomic_t g_enter_count;
atomic_t g_first;
atomic_t g_framework_init_flags;
atomic_t g_iommu_complete_flags;
atomic_t g_mutex_lock_flags;
u64 g_vm_pri_proc_based_ctrl_default = 0;
static spinlock_t g_mem_pool_lock;

/* Variables for checking dynamic kernel objects. */
struct list_head* g_modules_ptr = NULL;
struct file* g_root_file_ptr = NULL;
struct file* g_proc_file_ptr = NULL;
struct file* g_tcp_file_ptr = NULL;
struct file* g_tcp6_file_ptr = NULL;
struct file* g_udp_file_ptr = NULL;
struct file* g_udp6_file_ptr = NULL;
struct socket* g_tcp_sock = NULL;
struct socket* g_udp_sock = NULL;
rwlock_t* g_tasklist_lock;

/* Variables for operating. */
u64 g_max_ram_size = 0;
struct sb_memory_pool_struct g_memory_pool = {0, };
int g_ro_array_count = 0;
struct ro_addr_struct g_ro_array[MAX_RO_ARRAY_COUNT];
struct sb_workaround g_workaround = {{0, }, {0, }};
struct sb_share_context* g_share_context = NULL;
atomic_t g_is_shutdown_trigger_set = {0, };
volatile u64 g_shutdown_jiffies = 0;
static volatile u64 g_first_flag[MAX_PROCESSOR_COUNT] = {0, };

volatile u64 g_dump_jiffies = 0;
u64 g_dump_count[MAX_VM_EXIT_DUMP_COUNT] = {0, };

/*
 * Static functions.
 */
static int sb_get_kernel_version_index(void);
static int sb_is_kaslr_working(void);
static int sb_relocate_symbol(void);
static void sb_alloc_vmcs_memory(void);
static void sb_setup_workaround(void);
static int sb_setup_memory_pool(void);
void * sb_get_memory(void);
static int sb_is_workaround_addr(u64 addr);
static int sb_check_gdtr(int cpu_id);
static int sb_init_vmx(int cpu_id);
static void sb_vm_set_msr_write_bitmap(struct sb_vm_control_register*
	sb_vm_control_register, u64 msr_number);
static void sb_setup_vm_host_register(struct sb_vm_host_register* pstVMHost);
static void sb_setup_vm_guest_register(struct sb_vm_guest_register* pstVMGuest,
	const struct sb_vm_host_register* pstVMHost);
static void sb_setup_vm_control_register(struct sb_vm_control_register*
	pstVMControl, int iCPUID);
static void sb_setup_vmcs(const struct sb_vm_host_register* pstVMHost, const
	struct sb_vm_guest_register* pstVMGuest, const struct sb_vm_control_register*
	pstVMControl);
static void sb_dump_vm_host_register(struct sb_vm_host_register* pstVMHost);
static void sb_dump_vm_guest_register(struct sb_vm_guest_register* pstVMHost);
static void sb_dump_vm_control_register(struct sb_vm_control_register*
	pstVMControl);
static u64 sb_get_desc_base(u64 qwOffset);
static u64 sb_get_desc_access(u64 qwOffset);
static void sb_remove_int_exception_from_vm(int vector);
static void sb_print_vm_result(const char* pcData, int iResult);
static void sb_disable_and_change_machine_check_timer(void);
static int sb_vm_thread(void* pvArgument);
static void sb_dup_page_table_for_host(void);
static void sb_protect_kernel_ro_area(void);
static void sb_protect_module_list_ro_area(void);
static void sb_protect_vmcs(void);
static void sb_protect_gdt(int cpu_id);
static void sb_protect_shadow_box_module(void);
static void sb_advance_vm_guest_rip(void);
static u64 sb_calc_vm_pre_timer_value(void);
static unsigned long sb_encode_dr7(int dr_num, unsigned int len, unsigned int type);
static void sb_print_shadow_box_logo(void);
#if SHADOWBOX_USE_SHUTDOWN
static int sb_vm_thread_shutdown(void* argument);
static void sb_shutdown_vm_this_core(int cpu_id, struct sb_vm_exit_guest_register*
	guest_context);
static void sb_fill_context_from_vm_guest(struct sb_vm_exit_guest_register*
	guest_context, struct sb_vm_full_context* full_context);
static void sb_restore_context_from_vm_guest(int cpu_id, struct sb_vm_full_context*
	full_context, u64 guest_rsp);
#endif /* SHADOWBOX_USE_SHUTDOWN */
static void sb_lock_range(u64 start_addr, u64 end_addr, int alloc_type);
static void sb_get_function_pointers(void);
static int sb_is_system_shutdowning(void);
static void sb_disable_desc_monitor(void);
static void sb_trigger_shutdown_timer(void);
static int sb_is_shutdown_timer_expired(void);
static void sb_sync_page_table_flag(struct sb_pagetable* vm, struct sb_pagetable*
	init, int index, u64 addr);
static void sb_set_reg_value_from_index(struct sb_vm_exit_guest_register*
	guest_context, int index, u64 reg_value);
static u64 sb_get_reg_value_from_index(struct sb_vm_exit_guest_register*
	guest_context, int index);

/* Functions for vm exit. */
static void sb_vm_exit_callback_int(int cpu_id, unsigned long dr6, struct
	sb_vm_exit_guest_register* guest_context);
static void sb_vm_exit_callback_init_signal(int cpu_id);
static void sb_vm_exit_callback_start_up_signal(int cpu_id);
static void sb_vm_exit_callback_access_cr(int cpu_id, struct
	sb_vm_exit_guest_register* guest_context, u64 exit_reason, u64 exit_qual);
static void sb_vm_exit_callback_vmcall(int cpu_id, struct sb_vm_exit_guest_register*
	guest_context);
static void sb_vm_exit_callback_wrmsr(int cpu_id);
static void sb_vm_exit_callback_gdtr_idtr(int cpu_id, struct
	sb_vm_exit_guest_register* guest_context);
static void sb_vm_exit_callback_ldtr_tr(int cpu_id, struct sb_vm_exit_guest_register*
	guest_context);
static void sb_vm_exit_callback_ept_violation(int cpu_id, struct
	sb_vm_exit_guest_register* guest_context, u64 exit_reason, u64 exit_qual,
	u64 guest_linear, u64 guest_physical);
static void sb_vm_exit_callback_cpuid(struct sb_vm_exit_guest_register*
	guest_context);
static void sb_vm_exit_callback_invd(void);
static void sb_vm_exit_callback_pre_timer_expired(int cpu_id);

#if SHADOWBOX_USE_SHUTDOWN
static int sb_system_reboot_notify(struct notifier_block *nb, unsigned long code,
	void *unused);

static struct notifier_block* g_vm_reboot_nb_ptr = NULL;
static struct notifier_block g_vm_reboot_nb = {
	.notifier_call = sb_system_reboot_notify,
};
#endif /* SHADOWBOX_USE_SHUTDOWN*/

/*
 * Start function of Shadow-box module
 */
static int __init shadow_box_init(void)
{
	int cpu_count;
	int cpu_id;
	int i;
	struct new_utsname* name;
	u32 eax, ebx, ecx, edx;

	sb_print_shadow_box_logo();

	/* Check kernel version and kernel ASLR. */
	if (sb_get_kernel_version_index() == -1)
	{
		name = utsname();
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "Kernel version is not supported, [%s]",
			name->version);
		sb_error_log(ERROR_KERNEL_VERSION_MISMATCH);
		return -1;
	}

	/* Check kASLR. */
	if (sb_is_kaslr_working() == 1)
	{
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Kernel ASLR is enabled\n");
		sb_relocate_symbol();
	}

	/* Check VMX support. */
	cpuid_count(1, 0, &eax, &ebx, &ecx, &edx);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Initialize VMX\n");
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check virtualization, %08X, "
		"%08X, %08X, %08X\n", eax, ebx, ecx, edx);
	if (ecx & CPUID_1_ECX_VMX)
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] VMX support\n");
	}
	else
	{
		sb_printf(LOG_LEVEL_NONE, LOG_ERROR "    [*] VMX not support\n");
		sb_error_log(ERROR_HW_NOT_SUPPORT);
		return -1;
	}

	if (ecx & CPUID_1_ECX_SMX)
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] SMX support\n");
		g_support_smx = 1;
	}
	else
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_ERROR "    [*] SMX not support\n");
	}

	/* Check XSAVES, XRSTORS support. */
	cpuid_count(0x0D, 1, &eax, &ebx, &ecx, &edx);

	if (eax & CPUID_D_EAX_XSAVES)
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] XSAVES/XRSTORES support\n");
		g_support_xsave = 1;
	}
	else
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] XSAVES/XRSTORES not support\n");
	}

#if SHADOWBOX_USE_SHUTDOWN
	/* Add callback function for checking system shutdown. */
	g_vm_reboot_nb_ptr = kmalloc(sizeof(struct notifier_block), GFP_KERNEL);
	memcpy(g_vm_reboot_nb_ptr, &g_vm_reboot_nb, sizeof(struct notifier_block));
	register_reboot_notifier(g_vm_reboot_nb_ptr);

	/* Create shared context for system shutdown. */
	g_share_context = (struct sb_share_context*) kmalloc(sizeof(struct
		sb_share_context), GFP_KERNEL);
	atomic_set(&(g_share_context->shutdown_complete_count), 0);
	atomic_set(&(g_share_context->shutdown_flag), 0);
#endif /* SHADOWBOX_USE_SHUTDOWN */

	/*
	 * Check total RAM size.
	 * To cover system reserved area (3GB ~ 4GB), if system has under 4GB RAM,
	 * Shadow-box sets 4GB RAM to the variable. If system RAM has upper 4GB RAM,
	 * Shadow-box sets 1GB more than original size to the variable.
	 */
	g_max_ram_size = sb_get_max_ram_size();
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "totalram_pages %ld, size %ld, "
		"g_max_ram_size %ld\n", totalram_pages, totalram_pages * VAL_4KB,
		g_max_ram_size);
	if (g_max_ram_size < VAL_4GB)
	{
		g_max_ram_size = VAL_4GB;
	}
	else
	{
		g_max_ram_size = g_max_ram_size + VAL_1GB;
	}
	cpu_id = smp_processor_id();
	cpu_count = num_online_cpus();

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "CPU Count %d\n", cpu_count);
	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Booting CPU ID %d\n", cpu_id);

#if SHADOWBOX_USE_TBOOT
	if (tboot != NULL)
	{
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Checking tboot\n", tboot->log_addr);
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] log_addr = %016lX\n",
			tboot->log_addr);
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] shutdown_entry = %016lX\n",
			tboot->shutdown_entry);
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] shutdown_type = %016lX\n",
			tboot->shutdown_type);
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] num_in_wfs = %d\n",
			tboot->num_in_wfs);
	}
#endif /* SHADOWBOX_USE_TBOOT */

	sb_get_function_pointers();
	sb_alloc_vmcs_memory();

#if SHADOWBOX_USE_EPT
	if (sb_alloc_ept_pages() != 0)
	{
		sb_error_log(ERROR_MEMORY_ALLOC_FAIL);
		goto ERROR_HANDLE;
	}
	sb_setup_ept_pagetable_4KB();
#endif /* SHADOWBOX_USE_EPT */

#if SHADOWBOX_USE_IOMMU
	if (sb_alloc_iommu_pages() != 0)
	{
		sb_error_log(ERROR_MEMORY_ALLOC_FAIL);
		goto ERROR_HANDLE;
	}
	sb_setup_iommu_pagetable_4KB();
#endif /* SHADOWBOX_USE_IOMMU */

	sb_protect_kernel_ro_area();

#if SHADOWBOX_USE_EPT
	sb_protect_ept_pages();
	sb_protect_vmcs();
#endif /* SHADOWBOX_USE_EPT */

#if SHADOWBOX_USE_IOMMU
	sb_protect_iommu_pages();
#endif /* SHADOWBOX_USE_IOMMU */

	/* Prepare Shadow-watcher */
	if (sb_prepare_shadow_watcher() != 0)
	{
		sb_error_log(ERROR_MEMORY_ALLOC_FAIL);
		return -1;
	}

	sb_setup_workaround();

	if (sb_setup_memory_pool() != 0)
	{
		sb_error_log(ERROR_MEMORY_ALLOC_FAIL);
		return -1;
	}

	g_tasklist_lock = (rwlock_t*) sb_get_symbol_address("tasklist_lock");

	atomic_set(&g_thread_run_flags, cpu_count);
	atomic_set(&g_thread_entry_count, cpu_count);
	atomic_set(&g_sync_flags, cpu_count);
	atomic_set(&g_complete_flags, cpu_count);
	atomic_set(&g_framework_init_start_flags, cpu_count);
	atomic_set(&g_first, 1);
	atomic_set(&g_enter_flags, 0);
	atomic_set(&g_enter_count, 0);
	atomic_set(&g_framework_init_flags, cpu_count);
	atomic_set(&g_iommu_complete_flags, 0);
	atomic_set(&(g_mutex_lock_flags), 0);

	/* Create thread for each core. */
	for (i = 0 ; i < cpu_count ; i++)
	{
		g_vm_start_thread_id[i] = (struct task_struct *)kthread_create_on_node(
			sb_vm_thread, NULL, cpu_to_node(i), "vm_thread");
		if (g_vm_start_thread_id[i] != NULL)
		{
			kthread_bind(g_vm_start_thread_id[i], i);
		}
		else
		{
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] Thread run fail\n", i);
		}

#if SHADOWBOX_USE_SHUTDOWN
		g_vm_shutdown_thread_id[i] = (struct task_struct *)kthread_create_on_node(
			sb_vm_thread_shutdown, NULL, cpu_to_node(i), "vm_shutdown_thread");
		if (g_vm_shutdown_thread_id[i] != NULL)
		{
			kthread_bind(g_vm_shutdown_thread_id[i], i);
		}
		else
		{
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] Thread run fail\n", i);
		}
#endif /* SHADOWBOX_USE_SHUTDOWN */
	}

	/*
	 * Execute thread for each core except this core.
	 * If sb_vm_thread() is executed, task scheduling is prohibited. So,
	 * If task switching is occured when this core run loop below, some core could
	 * not run sb_vm_thread().
	 */
	for (i = 0 ; i < cpu_count ; i++)
	{
		if (i != cpu_id) {
			wake_up_process(g_vm_start_thread_id[i]);
			sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Thread Run Success\n", i);
		}

#if SHADOWBOX_USE_SHUTDOWN
		wake_up_process(g_vm_shutdown_thread_id[i]);
#endif /* SHADOWBOX_USE_SHUTDOWN */
	}

	/* Execute thread for this core */
	wake_up_process(g_vm_start_thread_id[cpu_id]);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Thread Run Success\n", cpu_id);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Waiting for complete\n", i);

	/* Check complete flags */
	while(atomic_read(&g_complete_flags) > 0)
	{
		msleep(100);
	}

	if (g_thread_result != 0)
	{
		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Execution Fail\n");
		return -1;
	}

	/* Hiding Shadow-box module. */
	mutex_lock(&module_mutex);
	list_del(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	mutex_unlock(&module_mutex);

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Execution Complete\n");
	sb_error_log(ERROR_SUCCESS);

	/* Set hide flag and time. */
	g_init_in_secure_jiffies = jiffies;
	g_allow_shadow_box_hide = 1;

	return 0;

ERROR_HANDLE:
	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Execution Fail\n");

	sb_free_ept_pages();
	sb_free_iommu_pages();
	return -1;
}

/*
 * End function of Shadow-box module.
 *
 * Shadow-box should not be terminated.
 */
static void __exit shadow_box_exit(void)
{
	int cpu_id;

	cpu_id = smp_processor_id();
	sb_print_shadow_box_logo();
	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "VMX [%d] Stop Shadow-Box\n", cpu_id);
}

/*
 * Print Shadow-box logo.
 */
static void sb_print_shadow_box_logo(void)
{
	sb_printf(LOG_LEVEL_NONE, "     \n");
	sb_printf(LOG_LEVEL_NONE, "███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗      ██████╗  ██████╗ ██╗  ██╗\n");
	sb_printf(LOG_LEVEL_NONE, "██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║      ██╔══██╗██╔═══██╗╚██╗██╔╝\n");
	sb_printf(LOG_LEVEL_NONE, "███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║█████╗██████╔╝██║   ██║ ╚███╔╝ \n");
	sb_printf(LOG_LEVEL_NONE, "╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════╝██╔══██╗██║   ██║ ██╔██╗ \n");
	sb_printf(LOG_LEVEL_NONE, "███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝      ██████╔╝╚██████╔╝██╔╝ ██╗\n");
	sb_printf(LOG_LEVEL_NONE, "╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝       ╚═════╝  ╚═════╝ ╚═╝  ╚═╝\n");
	sb_printf(LOG_LEVEL_NONE, "     \n");
	sb_printf(LOG_LEVEL_NONE, "              Lightweight Hypervisor-Based Kernel Protector v2.0.0\n");
	sb_printf(LOG_LEVEL_NONE, "     \n");
}

/*
 * Check and return shutdown status.
 */
static int sb_is_system_shutdowning(void)
{
	int cpu_id;

	cpu_id = smp_processor_id();
	if ((system_state == SYSTEM_RUNNING) || (system_state == SYSTEM_BOOTING))
	{
		return 0;
	}

	return 1;
}

/*
 * Disable descriptor (GDT, LDT, IDT) monitoring function.
 */
static void sb_disable_desc_monitor(void)
{
	u64 reg_value;

	sb_read_vmcs(VM_CTRL_SEC_PROC_BASED_EXE_CTRL, &reg_value);
	reg_value &= ~((u64)(VM_BIT_VM_SEC_PROC_CTRL_DESC_TABLE));
	reg_value &= 0xFFFFFFFF;
	sb_write_vmcs(VM_CTRL_SEC_PROC_BASED_EXE_CTRL, reg_value);
}

/*
 * Trigger shutdown timer if the system is shutdowning.
 */
static void sb_trigger_shutdown_timer(void)
{
	if (sb_is_system_shutdowning() == 0)
	{
		return ;
	}

	if (atomic_cmpxchg(&g_is_shutdown_trigger_set, 0, 1) == 0)
	{
#if SHADOWBOX_USE_IOMMU
		//sb_unlock_iommu();
#endif /* SHADOWBOX_USE_IOMMU */

		g_shutdown_jiffies = jiffies;
	}

	return ;
}

/*
 * Check time is over after the shutdown timer is triggered.
 */
static int sb_is_shutdown_timer_expired(void)
{
	u64 value;

	if (g_is_shutdown_trigger_set.counter == 0)
	{
		return 0;
	}

	value = jiffies - g_shutdown_jiffies;

	if (jiffies_to_msecs(value) >= SHUTDOWN_TIME_LIMIT_MS)
	{
		sb_printf(LOG_LEVEL_NONE, LOG_ERROR "VM[%d] Shutdown timer is expired\n",
			smp_processor_id());
		sb_error_log(ERROR_SHUTDOWN_TIME_OUT);
		g_shutdown_jiffies = jiffies;
		return 1;
	}

	return 0;
}


/*
 * Process VM resume fail.
 */
void sb_vm_resume_fail_callback(u64 error)
{
	u64 value;
	u64 value2;
	u64 value3;

	sb_read_vmcs(VM_GUEST_EFER, &value);
	sb_read_vmcs(VM_CTRL_VM_ENTRY_CTRLS, &value2);
	sb_read_vmcs(VM_GUEST_CR0, &value3);

	if (value & EFER_BIT_LME)
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM is in 64bit mode, %016lX, %016lX,"
			" %016lX\n", value, value2, value3);
	}
	else
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM is not in 64bit mode, %016lX, "
			"%016lX, %016lX\n", value, value2, value3);
	}


	sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM_RESUME fail %d\n", error);
	sb_print_shadow_box_logo();

	sb_error_log(ERROR_LAUNCH_FAIL);
}

/*
 * Find matched index of current kernel version.
 */
static int sb_get_kernel_version_index(void)
{
	int i;
	int match_index = -1;
	struct new_utsname* name;

	name = utsname();

	/* Search kernel version table */
	for (i = 0 ; i < (sizeof(g_kernel_version) / sizeof(char*)) ; i++)
	{
		if (strcmp(name->version, g_kernel_version[i]) == 0)
		{
			match_index = i;
			break;
		}
	}

	return match_index;
}

/*
 * Check kernel ASLR
 */
static int sb_is_kaslr_working(void)
{
	u64 stored_text_addr;
	u64 real_text_addr;

	stored_text_addr = sb_get_symbol_address("_etext");
	real_text_addr = kallsyms_lookup_name("_etext");

	if (stored_text_addr != real_text_addr)
	{
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "_etext System.map=%lX Kallsyms=%lX\n",
			stored_text_addr, real_text_addr);
		return 1;
	}

	return 0;
}

/*
 * Relocate symbol depending on KASLR
 */
static int sb_relocate_symbol(void)
{
	u64 stored_text_addr;
	u64 real_text_addr;
	u64 delta;
	int index;
	int i;

	stored_text_addr = sb_get_symbol_address("_etext");
	real_text_addr = kallsyms_lookup_name("_etext");

	delta = real_text_addr - stored_text_addr;
	if (delta == 0)
	{
		return 0;
	}

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Reloace symbol System.map=%lX Kallsyms="
		"%lX\n", stored_text_addr, real_text_addr);

	index = sb_get_kernel_version_index();
	if (index == -1)
	{
		return -1;
	}

	for (i = 0 ; i < SYMBOL_MAX_COUNT ; i++)
	{
		g_symbol_table_array[index].symbol[i].addr += delta;
	}

	return 0;
}


/*
 * Get address of kernel symbol.
 * kallsyms_lookup_name() does not have all symbol address which are in System.map.
 * So, if the symbol is not found in kallsyms_lookup_name(), this function finds
 * symbol address in predefined symbal table address.
 */
u64 sb_get_symbol_address(char* symbol)
{
	u64 log_addr = 0;
#if SHADOWBOX_USE_PRE_SYMBOL
	int i;
	int match_index;
#endif /* SHADOWBOX_USE_PRE_SYMBOL */

	log_addr = kallsyms_lookup_name(symbol);
#if SHADOWBOX_USE_PRE_SYMBOL
	if (log_addr == 0)
	{
		match_index = sb_get_kernel_version_index();

		if (match_index == -1)
		{
			return 0;
		}

		for (i = 0 ; i < SYMBOL_MAX_COUNT; i++)
		{
			if (strcmp(g_symbol_table_array[match_index].symbol[i].name, symbol) == 0)
			{
				log_addr = g_symbol_table_array[match_index].symbol[i].addr;
				break;
			}
		}
	}
#endif /* SHADOWBOX_USE_PRE_SYMBOL */

	return log_addr;
}


/*
 * Convert DR7 data from debug register index, length, type.
 */
static unsigned long sb_encode_dr7(int index, unsigned int len, unsigned int type)
{
	unsigned long value;

	value = (len | type) & 0xf;
	value <<= (DR_CONTROL_SHIFT + index * DR_CONTROL_SIZE);
	value |= (DR_GLOBAL_ENABLE << (index * DR_ENABLE_SIZE));

	return value;
}


/*
 * Dump memory in hex format.
 */
void vm_dump_memory(u8* addr, int size)
{
	char buffer[200];
	char temp[20];
	int i;
	int j;

	for (j = 0 ; j < size / 16 ; j++)
	{
		memset(buffer, 0, sizeof(buffer));
		sprintf(buffer, "[%04X] ", j * 16);
		for (i = 0 ; i < 16 ; i++)
		{
			sprintf(temp, "%02X ", addr[j * 16 + i]);
			strcat(buffer, temp);
		}

		sb_printf(LOG_LEVEL_NONE, LOG_INFO "%s\n", buffer);
	}
}

/*
 * Allocate memory for VMCS.
 */
static void sb_alloc_vmcs_memory(void)
{
 	int cpu_count;
 	int i;

	cpu_count = num_online_cpus();

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Alloc VMCS Memory\n");

	for (i = 0 ; i < cpu_count ; i++)
	{
		g_vmx_on_vmcs_log_addr[i] = kmalloc(VMCS_SIZE, GFP_KERNEL | __GFP_COLD);
		g_guest_vmcs_log_addr[i] = kmalloc(VMCS_SIZE, GFP_KERNEL | __GFP_COLD);
		g_vm_exit_stack_addr[i] = (void*)vmalloc(g_stack_size);

		g_io_bitmap_addrA[i] = kmalloc(IO_BITMAP_SIZE, GFP_KERNEL | __GFP_COLD);
		g_io_bitmap_addrB[i] = kmalloc(IO_BITMAP_SIZE, GFP_KERNEL | __GFP_COLD);
		g_msr_bitmap_addr[i] = kmalloc(IO_BITMAP_SIZE, GFP_KERNEL | __GFP_COLD);
		g_virt_apic_page_addr[i] = kmalloc(VIRT_APIC_PAGE_SIZE, GFP_KERNEL | __GFP_COLD);

		if ((g_vmx_on_vmcs_log_addr[i] == NULL) || (g_guest_vmcs_log_addr[i] == NULL) ||
			(g_vm_exit_stack_addr[i] == NULL) || (g_io_bitmap_addrA[i] == NULL) ||
			(g_io_bitmap_addrB[i] == NULL) || (g_msr_bitmap_addr[i] == NULL) ||
			(g_virt_apic_page_addr[i] == NULL))
		{
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "sb_alloc_vmcs_memory alloc fail\n");
			return ;
		}
		else
		{
			sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] Alloc Host VMCS"
				" %016lX\n", i, g_vmx_on_vmcs_log_addr[i]);
			sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] Alloc Guest VMCS"
				" %016lX\n", i, g_guest_vmcs_log_addr[i]);
			sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] Stack Addr %016lX\n",
				i, g_vm_exit_stack_addr[i]);
			sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] IO bitmapA Addr"
				" %016lX\n", i, g_io_bitmap_addrA[i]);
			sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] IO bitmapB Addr"
				" %016lX\n", i, g_io_bitmap_addrB[i]);
			sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] MSR Bitmap Addr"
				" %016lX\n", i, g_msr_bitmap_addr[i]);
			sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM[%d] Virt APIC Page "
				"Addr %016lX\n", i, g_virt_apic_page_addr[i]);
		}
	}
}

/*
 * Setup data for kernel patch workaround.
 * If you use CONIG_JUMP_LABEL,kernel patches itself during runtime.
 * This function adds exceptional case to allow runtime patch.
 */
static void sb_setup_workaround(void)
{
#if SHADOWBOX_USE_WORKAROUND
	char* function_list[WORK_AROUND_MAX_COUNT] = {
		"__netif_hash_nolisten", "__ip_select_ident",
		"secure_dccpv6_sequence_number", "secure_ipv4_port_ephemeral",
		"netif_receive_skb_internal", "__netif_receive_skb_core",
		"netif_rx_internal", "inet6_ehashfn.isra.6", "inet_ehashfn", };
	u64 log_addr;
	u64 phy_addr;
	int i;
	int index = 0;

	memset(&g_workaround, 0, sizeof(g_workaround));
	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Setup Workaround Address\n");

	for (i = 0 ; i < WORK_AROUND_MAX_COUNT ; i++)
	{
		if (function_list[i] == 0)
		{
			break;
		}

		log_addr = sb_get_symbol_address(function_list[i]);
		if (log_addr <= 0)
		{
			sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] %s log %016lX is not"
				" found\n", function_list[i], log_addr);
			continue;
		}
		phy_addr = virt_to_phys((void*)(log_addr & MASK_PAGEADDR));

		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] %s log %016lX %016lX\n",
			function_list[i], log_addr, phy_addr);
		g_workaround.addr_array[index] = phy_addr;
		g_workaround.count_array[index] = 0;

		index++;
	}
#endif /* SHADOWBOX_USE_WORKAROUND */
}

/*
 * Check if the address is in workaround address.
 */
static int sb_is_workaround_addr(u64 addr)
{
#if SHADOWBOX_USE_WORKAROUND
	int i;

	for (i = 0 ; i < WORK_AROUND_MAX_COUNT ; i++)
	{
		if (g_workaround.addr_array[i] == (addr & MASK_PAGEADDR))
		{
			return 1;
		}
	}
#endif /* SHADOWBOX_USE_WORKAROUND */

	return 0;
}

/*
 * Allocate memory for Shadow-box.
 * After Shadow-box is loaded and two world are separated, Shadow-box uses own
 * memory pool to prevent interference of the guest.
 */
static int sb_setup_memory_pool(void)
{
	u64 i;
	u64 size;

	spin_lock_init(&g_mem_pool_lock);

	/* Allocate 1 page per 2MB */
	g_memory_pool.max_count = g_max_ram_size / VAL_2MB;
	size = g_memory_pool.max_count * VAL_4KB;
	g_memory_pool.pool = NULL;

	g_memory_pool.pool = (u64 *) vmalloc(size);
	if (g_memory_pool.pool == NULL)
	{
		goto ERROR;
	}

	memset(g_memory_pool.pool, 0, sizeof(g_memory_pool.max_count));
	for (i = 0 ; i < g_memory_pool.max_count ; i++)
	{
		g_memory_pool.pool[i] = (u64)kmalloc(VAL_4KB, GFP_KERNEL | __GFP_COLD);
		if (g_memory_pool.pool[i] == 0)
		{
			goto ERROR;
		}
	}

	g_memory_pool.pop_index = 0;

	return 0;

ERROR:
	if (g_memory_pool.pool != NULL)
	{
		for (i = 0 ; i < g_memory_pool.max_count ; i++)
		{
			if (g_memory_pool.pool[i] != 0)
			{
				kfree((void*)g_memory_pool.pool[i]);
			}
		}

		kfree(g_memory_pool.pool);
	}

	return -1;
}

/*
 * Allocate memory from memory pool of Shadow-box.
 */
void * sb_get_memory(void)
{
	void *memory;

	spin_lock(&g_mem_pool_lock);

	if (g_memory_pool.pop_index >= g_memory_pool.max_count)
	{
		spin_unlock(&g_mem_pool_lock);
		return NULL;
	}

	memory = (void *)g_memory_pool.pool[g_memory_pool.pop_index];

	g_memory_pool.pop_index++;
	spin_unlock(&g_mem_pool_lock);

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Get Memory Index %d Addr %016lX\n",
		g_memory_pool.pop_index, memory);

	return memory;
}

/*
 * Check malicious descriptors in GDT.
 */
static int sb_check_gdtr(int cpu_id)
{
	struct desc_ptr gdtr;
	struct desc_struct* gdt;
	int result = 0;
	int i;
	u64 address;
	u64 size;

	sb_read_vmcs(VM_GUEST_GDTR_BASE, &address);
	sb_read_vmcs(VM_GUEST_GDTR_LIMIT, &size);
	gdtr.address = address;
	gdtr.size = (u16)size;

	if ((sb_is_system_shutdowning() == 1))
	{
		return 0;
	}

	if (gdtr.address != g_gdtr_array[cpu_id].address)
	{
		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] Structure not same, Org "
			"Addr %016lX, Size %d, New Addr %016lX, Size %d\n",
			cpu_id, g_gdtr_array[cpu_id].address, g_gdtr_array[cpu_id].size,
			gdtr.address, gdtr.size);

		return -1;
	}

	if (gdtr.size >= 0x1000)
	{
		sb_printf(LOG_LEVEL_NONE, LOG_ERROR "VM [%d] GDT size is over, Org Addr"
			" %016lX, Size %d, New Addr %016lX, Size %d\n",
			cpu_id, g_gdtr_array[cpu_id].address, g_gdtr_array[cpu_id].size,
			gdtr.address, gdtr.size);
	}

	/* Check descriptors in GDT */
	for (i = 0 ; i < gdtr.size ; i += 8)
	{
		gdt = (struct desc_struct*)(gdtr.address + i);
		/* Is the descriptor system? Can user level access the descriptor? */
		if((gdt->s == 0) && (gdt->p == 1) && (gdt->dpl == 3))
		{
			if ((gdt->type == GDT_TYPE_64BIT_CALL_GATE) ||
				(gdt->type == GDT_TYPE_64BIT_INTERRUPT_GATE) ||
				(gdt->type == GDT_TYPE_64BIT_TRAP_GATE))
			{
				sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] index %d low %08X"
					" high %08X\n", cpu_id, i, gdt->a, gdt->b);

				result = -1;
				break;
			}
			else if ((gdt->type == GDT_TYPE_64BIT_LDT) ||
					 (gdt->type == GDT_TYPE_64BIT_TSS) ||
					 (gdt->type == GDT_TYPE_64BIT_TSS_BUSY))
			{
				/* For 16byte Descriptor. */
				i += 8;
			}
		}
	}

	return result;
}

/*
 * Lock memory range from the guest.
 */
static void sb_lock_range(u64 start_addr, u64 end_addr, int alloc_type)
{
	u64 i;
	u64 phy_addr;
	u64 align_end_addr;

	align_end_addr = (end_addr + PAGE_SIZE - 1) & MASK_PAGEADDR;

	for (i = (start_addr & MASK_PAGEADDR) ; i < align_end_addr ; i += 0x1000)
	{
		if (alloc_type == ALLOC_KMALLOC)
		{
			phy_addr = virt_to_phys((void*)i);
		}
		else
		{
			phy_addr = PFN_PHYS(vmalloc_to_pfn((void*)i));
		}

		sb_set_ept_lock_page(phy_addr);

#if SHADOWBOX_USE_IOMMU
		sb_set_iommu_hide_page(phy_addr);
#endif /* SHADOWBOX_USE_IOMMU */

	}
}

/*
 * Set permissions to memory range.
 */
void sb_set_all_access_range(u64 start_addr, u64 end_addr, int alloc_type)
{
	u64 i;
	u64 phy_addr;
	u64 align_end_addr;

	align_end_addr = (end_addr + PAGE_SIZE - 1) & MASK_PAGEADDR;

	for (i = (start_addr & MASK_PAGEADDR) ; i < align_end_addr ; i += 0x1000)
	{
		if (alloc_type == ALLOC_KMALLOC)
		{
			phy_addr = virt_to_phys((void*)i);
		}
		else
		{
			phy_addr = PFN_PHYS(vmalloc_to_pfn((void*)i));
		}

		sb_set_ept_all_access_page(phy_addr);

#if SHADOWBOX_USE_IOMMU
		sb_set_iommu_all_access_page(phy_addr);
#endif /* SHADOWBOX_USE_IOMMU */
	}
}

/*
 * Hiding memory range from the guest.
 */
void sb_hide_range(u64 start_addr, u64 end_addr, int alloc_type)
{
	u64 i;
	u64 phy_addr;
	u64 align_end_addr;

	/* Round up the end address */
	align_end_addr = (end_addr + PAGE_SIZE - 1) & MASK_PAGEADDR;

	for (i = (start_addr & MASK_PAGEADDR) ; i < align_end_addr ; i += 0x1000)
	{
		if (alloc_type == ALLOC_KMALLOC)
		{
			phy_addr = virt_to_phys((void*)i);
		}
		else
		{
			phy_addr = PFN_PHYS(vmalloc_to_pfn((void*)i));
		}

#if SHADOWBOX_USE_EPT
		sb_set_ept_hide_page(phy_addr);
#endif

#if SHADOWBOX_USE_IOMMU
		sb_set_iommu_hide_page(phy_addr);
#endif
	}
}

/*
 * Protect static kernel object of Linux kernel using locking and hiding.
 */
static void sb_protect_kernel_ro_area(void)
{
	char* sym_list[] = {
		"_text", "_etext",
		"__start___ex_table", "__stop___ex_table",
		"__start_rodata", "__end_rodata",
	};
	u64 start_log_addr;
	u64 end_log_addr;
	u64 start_phy_addr;
	u64 end_phy_addr;
	u64 i;

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Protect Kernel Code Area\n");
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Setup RO Area\n");
	for (i = 0 ; i < sizeof(sym_list)/ sizeof(char*) ; i+=2)
	{
		start_log_addr = sb_get_symbol_address(sym_list[i]);
		end_log_addr = sb_get_symbol_address(sym_list[i + 1]);

		start_phy_addr = virt_to_phys((void*)start_log_addr);
		end_phy_addr = virt_to_phys((void*)end_log_addr);

		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] %s Log %016lX, Phy %016lX\n",
			sym_list[i], start_log_addr, start_phy_addr);
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] %s Log %016lX, Phy %016lX\n",
			sym_list[i + 1], end_log_addr, end_phy_addr);

#if SHADOWBOX_USE_EPT
		sb_lock_range(start_log_addr, end_log_addr, ALLOC_KMALLOC);
#endif
		sb_add_ro_area(start_log_addr, end_log_addr, RO_KERNEL);

		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] %d Pages\n",
			(end_log_addr - start_log_addr) / EPT_PAGE_SIZE);
	}

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Complete\n");
}

/*
 * Protect static kernel object of the module using locking and hiding.
 */
static void sb_add_and_protect_module_ro(struct module* mod)
{
	u64 mod_init_base;
	u64 mod_init_size;
	u64 mod_init_text_size;
	u64 mod_init_ro_size;
	u64 mod_core_base;
	u64 mod_core_size;
	u64 mod_core_text_size;
	u64 mod_core_ro_size;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	mod_init_base = (u64)mod->module_init;
	mod_init_size = (u64)mod->init_size;
	mod_init_text_size = (u64)mod->init_text_size;
	mod_init_ro_size = (u64)mod->init_ro_size;
	mod_core_base = (u64)mod->module_core;
	mod_core_size = (u64)mod->core_size;
	mod_core_text_size = (u64)mod->core_text_size;
	mod_core_ro_size = (u64)mod->core_ro_size;
#else
	mod_init_base = (u64)(mod->init_layout.base);
	mod_init_size = (u64)(mod->init_layout.size);
	mod_init_text_size = (u64)(mod->init_layout.text_size);
	mod_init_ro_size = (u64)(mod->init_layout.ro_size);
	mod_core_base = (u64)(mod->core_layout.base);
	mod_core_size = (u64)(mod->core_layout.size);
	mod_core_text_size = (u64)(mod->core_layout.text_size);
	mod_core_ro_size = (u64)(mod->core_layout.ro_size);
#endif

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] mod:%p [%s]", mod, mod->name);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] init:0x%p module_init:0x%08lX"
		" module_core:0x%08lX\n", mod->init, mod_init_base, mod_core_base);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] init_size:0x%ld core_size:%ld",
		mod_init_size, mod_core_size);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] init_text_size:%ld "
		"core_text_size:%ld\n", mod_init_text_size, mod_core_text_size);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] init_ro_size:%ld core_ro_size:"
		"%ld", mod_init_ro_size, mod_core_ro_size);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "\n");

#if SHADOWBOX_USE_EPT
	sb_lock_range(mod_core_base, mod_core_base + mod_core_ro_size, ALLOC_VMALLOC);
#endif
	sb_add_ro_area(mod_core_base, mod_core_base + mod_core_ro_size, RO_MODULE);
}

/*
 * Protect static kernel object of modules using sb_add_and_protect_module_ro.
 */
static void sb_protect_module_list_ro_area(void)
{
	struct module *mod;
	struct list_head *pos, *node;
	unsigned long mod_head_node;
	u64 mod_core_size;

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Protect Module Code Area\n");
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Setup RO Area\n");

	g_shadow_box_module = THIS_MODULE;
	mod = THIS_MODULE;
	pos = &THIS_MODULE->list;

	sb_add_and_protect_module_ro(mod);

	node = &THIS_MODULE->list;
	mod_head_node = sb_get_symbol_address("modules");
	/* For later use */
	g_modules_ptr = (struct list_head*)mod_head_node;

	list_for_each(pos, node)
	{
		if(mod_head_node == (unsigned long)pos)
			break;

		mod = container_of(pos, struct module, list);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		mod_core_size = mod->core_size;
#else
		mod_core_size = mod->core_layout.size;
#endif
		if (mod_core_size == 0)
		{
			continue;
		}

		sb_add_and_protect_module_ro(mod);
	}

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Complete\n");
}

/*
 * Protect Shadow-box module
 */
static void sb_protect_shadow_box_module(void)
{
	struct module *mod;
	u64 mod_init_base;
	u64 mod_init_size;
	u64 mod_init_text_size;
	u64 mod_init_ro_size;
	u64 mod_core_base;
	u64 mod_core_size;
	u64 mod_core_text_size;
	u64 mod_core_ro_size;

	mod = g_shadow_box_module;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	mod_init_base = (u64)mod->module_init;
	mod_init_size = (u64)mod->init_size;
	mod_init_text_size = (u64)mod->init_text_size;
	mod_init_ro_size = (u64)mod->init_ro_size;
	mod_core_base = (u64)mod->module_core;
	mod_core_size = (u64)mod->core_size;
	mod_core_text_size = (u64)mod->core_text_size;
	mod_core_ro_size = (u64)mod->core_ro_size;
#else
	mod_init_base = (u64)(mod->init_layout.base);
	mod_init_size = (u64)(mod->init_layout.size);
	mod_init_text_size = (u64)(mod->init_layout.text_size);
	mod_init_ro_size = (u64)(mod->init_layout.ro_size);
	mod_core_base = (u64)(mod->core_layout.base);
	mod_core_size = (u64)(mod->core_layout.size);
	mod_core_text_size = (u64)(mod->core_layout.text_size);
	mod_core_ro_size = (u64)(mod->core_layout.ro_size);
#endif

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Protect Shadow-Box Area\n");
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] mod:%p [%s], size of module"
		" struct %d", mod, mod->name, sizeof(struct module));
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init:0x%p module_init:0x%08lX "
		"module_core:0x%08lX\n", mod->init, mod_init_base, mod_core_base);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init_size:0x%ld core_size:%ld",
		mod_init_size, mod_core_size);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init_text_size:%ld "
		"core_text_size:%ld\n", mod_init_text_size, mod_core_text_size);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init_ro_size:%ld core_ro_size:%ld",
		mod_init_ro_size, mod_core_ro_size);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "\n");

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] protection start:%016lX end:%016lX",
		mod_core_base, mod_core_base + mod_core_size);

#if SHADOWBOX_USE_SHUTDOWN
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] sb_system_reboot_notify:%016lX,"
		" g_vm_reboot_nb:%016lX", (u64)sb_system_reboot_notify,
		(u64)g_vm_reboot_nb_ptr);
#endif
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Complete\n");

	sb_hide_range(mod_core_base, mod_core_base + mod_core_size, ALLOC_VMALLOC);

	/*
	 * Module structure is included in module core range, so give full access
	 * to module structure.
	 */
	sb_set_all_access_range((u64)g_shadow_box_module, (u64)g_shadow_box_module +
		sizeof(struct module), ALLOC_VMALLOC);
}

/*
 * Protect GDT and IDT.
 */
static void sb_protect_gdt(int cpu_id)
{
	struct desc_ptr idtr;

	native_store_gdt(&(g_gdtr_array[cpu_id]));
	native_store_idt(&idtr);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM[%d] Protect GDT IDT\n", cpu_id);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM[%d]    [*] GDTR Base %16lX, Size %d\n",
		cpu_id, g_gdtr_array[cpu_id].address, g_gdtr_array[cpu_id].size);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM[%d]    [*] IDTR Base %16lX, Size %d\n", cpu_id, idtr.address, idtr.size);

#if SHADOWBOX_USE_EPT
	sb_lock_range(idtr.address, (idtr.address + 0xFFF) & MASK_PAGEADDR, ALLOC_VMALLOC);
#endif
}

/*
 * Print Shadow-box log.
 */
void sb_printf(int level, char* format, ...)
{
	va_list arg_list;

	if (level <= LOG_LEVEL)
	{
		va_start(arg_list, format);
		vprintk(format, arg_list);
		va_end(arg_list);
	}
}

/*
 * Print Shadow-box error.
 */
void sb_error_log(int error_code)
{
	sb_printf(LOG_LEVEL_NONE, LOG_ERROR "errorcode=%d\n", error_code);
}

/*
 * Expand page table entry.
 */
void vm_expand_page_table_entry(u64 phy_table_addr, u64 start_entry_and_flags,
	u64 entry_size, u64 dummy)
{
	u64 i;
	struct sb_pagetable* log_addr;

	log_addr = (struct sb_pagetable*)phys_to_virt((u64)phy_table_addr & ~(MASK_PAGEFLAG));

	sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Expand page table entry. Start entry "
		"%016lX, size %016lX, phy table %016lX\n", start_entry_and_flags,
		entry_size, phy_table_addr);

	for (i = 0 ; i < 512 ; i++)
	{
		if (entry_size == VAL_4KB)
		{
			log_addr->entry[i] = (start_entry_and_flags & ~(MASK_PAGE_SIZE_FLAG)) +
				(i * entry_size);
		}
		else
		{
			log_addr->entry[i] = (start_entry_and_flags | MASK_PAGE_SIZE_FLAG) +
				(i * entry_size);
		}
	}
}

/*
 * Check and allocate page table.
 */
u64 vm_check_alloc_page_table(struct sb_pagetable* pagetable, int index)
{
	u64 value;

	if ((pagetable->entry[index] == 0) ||
		(pagetable->entry[index] & MASK_PAGE_SIZE_FLAG))
	{
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "PageTable %016lX Index %d is null\n",
			pagetable, index);

		value = (u64)sb_get_memory();
		if (value == 0)
		{
			sb_printf(LOG_LEVEL_NONE, LOG_ERROR "vm_check_alloc_page fail \n");
			sb_error_log(ERROR_MEMORY_ALLOC_FAIL);
		}

		memset((void*)value, 0, 0x1000);

		sb_printf(LOG_LEVEL_NONE, LOG_INFO "vm_check_alloc_page log %lX, phy %lX \n",
			value, virt_to_phys((void*)value));
		value = virt_to_phys((void*)value);
	}
	else
	{
		value = pagetable->entry[index];
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "PageTable %016lX Index %d is not null"
			" %016lX\n", pagetable, index, value);
	}

	return value;
}

/*
 * Syncronize page table flags.
 */
static void sb_sync_page_table_flag(struct sb_pagetable* vm, struct sb_pagetable* init,
	int index, u64 addr)
{
	u64 value;

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "SyncPage %016lX %016lX Index %d %016lX\n",
		vm->entry[index], init->entry[index], index, addr);

	value = addr & ~(MASK_PAGEFLAG);
	value |= init->entry[index] & MASK_PAGEFLAG;

	vm->entry[index] = value;
}

/*
 * Check if page table flags are same or page size is set.
 */
int vm_is_same_page_table_flag_or_size_flag_set(struct sb_pagetable* vm,
	struct sb_pagetable* init, int index)
{
	u64 vm_value;
	u64 init_value;

	if (init->entry[index] & MASK_PAGE_SIZE_FLAG)
	{
		return 1;
	}

	vm_value = vm->entry[index] & MASK_PAGEFLAG_WO_DA;
	init_value = init->entry[index] & MASK_PAGEFLAG_WO_DA;

	if (vm_value == init_value)
	{
		return 1;
	}

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Index not same %d\n", index);
	return 0;
}

/*
 * Check if new page table is needed.
 * If page table entry is in page table or page size flag is set, new page table
 * is needed.
 */
int vm_is_new_page_table_needed(struct sb_pagetable* vm, struct sb_pagetable* init,
	int index)
{
	if ((vm->entry[index] != 0) && ((vm->entry[index] & MASK_PAGE_SIZE_FLAG) == 0))
	{
		return 0;
	}

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Index not present %d\n", index);
	return 1;
}

/*
 * Get physical address from logical address.
 */
void sb_get_phy_from_log(u64 pml4_phy_addr, u64 addr, struct vm_page_entry_struct*
	out_data)
{
	struct sb_pagetable* pml4;
	struct sb_pagetable* pdpte_pd;
	struct sb_pagetable* pdept;
	struct sb_pagetable* pte;
	u64 pml4_index;
	u64 pdpte_pd_index;
	u64 pdept_index;
	u64 pte_index;
	u64 value;
	u64 addr_value;

	pml4_index = (addr / VAL_512GB) % 512;
	pdpte_pd_index = (addr / VAL_1GB) %  512;
	pdept_index = (addr / VAL_2MB) %  512;
	pte_index = (addr / VAL_4KB) %  512;

	memset(out_data, 0, sizeof(struct vm_page_entry_struct));

	/* PML4 */
	pml4 = phys_to_virt((u64)pml4_phy_addr);
	value = pml4->entry[pml4_index];
	addr_value = GET_ADDR(value);
	out_data->phy_addr[0] = value;

	if (!IS_PRESENT(value))
	{
		return ;
	}

	if (IS_SIZE_FLAG_SET(value))
	{
		addr_value += pdpte_pd_index * VAL_1GB + pdept_index * VAL_2MB +
			pte_index * VAL_4KB;
		out_data->phy_addr[3] = addr_value | (value & MASK_PAGEFLAG_WO_SIZE);
		return ;
	}

	/* PDPTE_PD */
	pdpte_pd = phys_to_virt((u64)addr_value);
	value = pdpte_pd->entry[pdpte_pd_index];
	addr_value = GET_ADDR(value);
	out_data->phy_addr[1] = value;

	if (!IS_PRESENT(value))
	{
		return ;
	}

	if (IS_SIZE_FLAG_SET(value))
	{
		addr_value += pdept_index * VAL_2MB + pte_index * VAL_4KB;
		out_data->phy_addr[3] = addr_value | (value & MASK_PAGEFLAG_WO_SIZE);
		return ;
	}

	/* PDEPT */
	pdept = phys_to_virt((u64)addr_value);
	value = pdept->entry[pdept_index];
	addr_value = GET_ADDR(value);
	out_data->phy_addr[2] = value;

	if (!IS_PRESENT(value))
	{
		return ;
	}

	if (IS_SIZE_FLAG_SET(value))
	{
		addr_value += pte_index * VAL_4KB;
		out_data->phy_addr[3] = addr_value | (value & MASK_PAGEFLAG_WO_SIZE);
		return ;
	}

	/* PTE */
	pte = phys_to_virt((u64)addr_value);
	value = pte->entry[pte_index];
	out_data->phy_addr[3] = value;
}

/*
 * Syncronize page table with the guest to introspect it. V2
 * PML4 -> PDPTE_PD -> PDEPT -> PTE -> 4KB
 */
u64 sb_sync_page_table2(u64 addr)
{
	struct sb_pagetable* pml4;
	struct sb_pagetable* pdpte_pd;
	struct sb_pagetable* pdept;
	struct sb_pagetable* pte;
	struct vm_page_entry_struct phy_entry;

	u64 pml4_index;
	u64 pdpte_pd_index;
	u64 pdept_index;
	u64 pte_index;
	u64 value;
	u64 expand_value = 0;

	/* Skip direct mapping area */
	if (((u64)page_offset_base <= addr) && (addr < (u64)page_offset_base + (64 * VAL_1TB)))
	{
		return 0;
	}

	/* Skip static kernel object area */
	if (sb_is_addr_in_kernel_ro_area((void*)addr))
	{
		return 0;
	}

	pml4_index = (addr / VAL_512GB) % 512;
	pdpte_pd_index = (addr / VAL_1GB) %  512;
	pdept_index = (addr / VAL_2MB) %  512;
	pte_index = (addr / VAL_4KB) %  512;

	/* Get physical page by traversing page table of the guest. */
	sb_get_phy_from_log(g_vm_init_phy_pml4, addr, &phy_entry);
	if (!IS_PRESENT(phy_entry.phy_addr[3]))
	{
		return 0;
	}

	pml4 = phys_to_virt(g_vm_host_phy_pml4);

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "addr = %016lX PML4 index %ld %016lX "
		"%016lX\n", addr, pml4_index, pml4, pml4->entry[pml4_index]);

	/* Get PDPTE_PD from PML4 */
	if (vm_is_new_page_table_needed(pml4, NULL, pml4_index) == 1)
	{
		value = vm_check_alloc_page_table(pml4, pml4_index);
		vm_expand_page_table_entry(value, pml4->entry[pml4_index], VAL_1GB, 0);
		pml4->entry[pml4_index] = GET_ADDR(value) | (phy_entry.phy_addr[0] &
			MASK_PAGEFLAG);

		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Expand Log %016lX Phy %016lX",
			addr, (u64)virt_to_phys((void*)addr));

		if (expand_value == 0)
		{
			expand_value = VAL_1GB;
		}
	}

	pdpte_pd = phys_to_virt(GET_ADDR(pml4->entry[pml4_index]));

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "PDPTE_PD index %d %016lX %016lX\n",
		pdpte_pd_index, pdpte_pd, pdpte_pd->entry[pdpte_pd_index]);

	/* If PDEPT exist, syncronize the flag */
	if (vm_is_new_page_table_needed(pdpte_pd, NULL, pdpte_pd_index) == 1)
	{
		value = vm_check_alloc_page_table(pdpte_pd, pdpte_pd_index);
		vm_expand_page_table_entry(value, pdpte_pd->entry[pdpte_pd_index],
			VAL_2MB, 0);
		pdpte_pd->entry[pdpte_pd_index] = GET_ADDR(value) |
			(phy_entry.phy_addr[1] & MASK_PAGEFLAG);

		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Expand Log %016lX Phy %016lX",
			addr, (u64)virt_to_phys((void*)addr));

		if (expand_value == 0)
		{
			expand_value = VAL_2MB;
		}
	}

	pdept = phys_to_virt(GET_ADDR(pdpte_pd->entry[pdpte_pd_index]));

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "PDEPT index %d %016lX %016lX\n",
		pdept_index, pdept, pdept->entry[pdept_index]);

	/* If PTE exist, syncronize the flag */
	if (vm_is_new_page_table_needed(pdept, NULL, pdept_index) == 1)
	{
		value = vm_check_alloc_page_table(pdept, pdept_index);
		vm_expand_page_table_entry(value, pdept->entry[pdept_index], VAL_4KB, 0);
		pdept->entry[pdept_index] = GET_ADDR(value) |
			(phy_entry.phy_addr[2] & MASK_PAGEFLAG);

		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "Expand Log %016lX Phy %016lX",
			addr, (u64)virt_to_phys((void*)addr));

		if (expand_value == 0)
		{
			expand_value = VAL_4KB;
		}
	}

	pte = phys_to_virt(GET_ADDR(pdept->entry[pdept_index]));
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "PTE index %d %016lX %016lX\n",
		pte_index, pte, pte->entry[pte_index]);

	/* Copy PTE from the guest */
	pte->entry[pte_index] = phy_entry.phy_addr[3];

	/* Update page table to CPU */
	sb_set_cr3(g_vm_host_phy_pml4);
	return expand_value;
}

/*
 * Syncronize page table with the guest to introspect it. V1
 * PML4 -> PDPTE_PD -> PDEPT -> PTE -> 4KB
 */
u64 sb_sync_page_table(u64 addr)
{
	struct sb_pagetable* init_pml4;
	struct sb_pagetable* init_pdpte_pd;
	struct sb_pagetable* init_pdept;
	struct sb_pagetable* init_pte;
	struct sb_pagetable* vm_pml4;
	struct sb_pagetable* vm_pdpte_pd;
	struct sb_pagetable* vm_pdept;
	struct sb_pagetable* vm_pte;
	struct vm_page_entry_struct phy_entry;

	u64 pml4_index;
	u64 pdpte_pd_index;
	u64 pdept_index;
	u64 pte_index;
	u64 value;
	u64 expand_value = 0;

	/* Skip direct mapping area */
	if (((u64)page_offset_base <= addr) && (addr < (u64)page_offset_base + (64 * VAL_1TB)))
	{
		return 0;
	}

	/* Skip static kernel object area */
	if (sb_is_addr_in_kernel_ro_area((void*)addr))
	{
		return 0;
	}

	/* Get physical page by traversing page table of the guest. */
	sb_get_phy_from_log(g_vm_init_phy_pml4, addr, &phy_entry);
	if (!IS_PRESENT(phy_entry.phy_addr[3]))
	{
		return 0;
	}

	init_pml4 = (struct sb_pagetable*)g_vm_init_phy_pml4;
	init_pml4 = phys_to_virt((u64)init_pml4);
	vm_pml4 = phys_to_virt(g_vm_host_phy_pml4);

	pml4_index = (addr / VAL_512GB) % 512;
	pdpte_pd_index = (addr / VAL_1GB) %  512;
	pdept_index = (addr / VAL_2MB) %  512;
	pte_index = (addr / VAL_4KB) %  512;

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "addr = %016lX PML4 index %ld %016lX "
		"%016lX %016X\n", addr, pml4_index, vm_pml4, init_pml4,
		init_pml4->entry[pml4_index]);

	/*
	 * Get PDPTE_PD from PML4
	 */
	init_pdpte_pd = (struct sb_pagetable*)(init_pml4->entry[pml4_index]);
	if ((init_pdpte_pd == 0) || ((u64)init_pdpte_pd & MASK_PAGE_SIZE_FLAG))
	{
		vm_pml4->entry[pml4_index] = (u64)init_pdpte_pd;

		sb_printf(LOG_LEVEL_NONE, LOG_INFO "===================INFO======================");
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "PML4 addr = %016lX sync\n", addr);
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "===================INFO======================");

		sb_printf(LOG_LEVEL_NONE, LOG_INFO "PDPTE_PD has size flags or 0\n");

#if SHADOWBOX_USE_PAGE_DEBUG
		while(1)
		{
			sb_pause_loop();
		}
#endif
		goto EXIT;
	}

	if (vm_is_new_page_table_needed(vm_pml4, init_pml4, pml4_index) == 1)
	{
		value = vm_check_alloc_page_table(vm_pml4, pml4_index);
		vm_expand_page_table_entry(value, vm_pml4->entry[pml4_index], VAL_1GB,
			init_pml4->entry[pml4_index]);
		sb_sync_page_table_flag(vm_pml4, init_pml4, pml4_index, value);

		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "New table is needed. Expand Log "
			"%016lX Phy %016lX", addr, (u64)virt_to_phys((void*)addr));
		if (expand_value == 0)
		{
			expand_value = VAL_1GB;
		}

#if SHADOWBOX_USE_PAGE_DEBUG
		while(1)
		{
			sb_pause_loop();
		}
#endif
	}

	init_pdpte_pd = phys_to_virt((u64)init_pdpte_pd & ~(MASK_PAGEFLAG));
	vm_pdpte_pd = (struct sb_pagetable*)(vm_pml4->entry[pml4_index]);
	vm_pdpte_pd = phys_to_virt((u64)vm_pdpte_pd & ~(MASK_PAGEFLAG));

	/*
	 * Get PDEPT from PDPTE_PD
	 */
	init_pdept = (struct sb_pagetable*)(init_pdpte_pd->entry[pdpte_pd_index]);

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "PDPTE_PD index %d %016lX %016lX %016lX\n",
		pdpte_pd_index, vm_pdpte_pd, init_pdpte_pd,
		init_pdpte_pd->entry[pdpte_pd_index]);

	if ((init_pdept == 0) || ((u64)init_pdept & MASK_PAGE_SIZE_FLAG))
	{
		if (vm_pdpte_pd->entry[pdpte_pd_index] != (u64)init_pdept)
		{
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "===================INFO======================");
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "PDEPT addr = %016lX sync\n", addr);
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "===================INFO======================");
		}
		else
		{
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "PDEPT is same");
		}

		vm_pdpte_pd->entry[pdpte_pd_index] = (u64)init_pdept;

		sb_printf(LOG_LEVEL_NONE, LOG_INFO "PDEPT has size flags or 0\n");

#if SHADOWBOX_USE_PAGE_DEBUG
		while(1)
		{
			sb_pause_loop();
		}
#endif

		goto EXIT;
	}

	/* If PDEPT exist, syncronize the flag */
	if (vm_is_new_page_table_needed(vm_pdpte_pd, init_pdpte_pd, pdpte_pd_index) == 1)
	{
		value = vm_check_alloc_page_table(vm_pdpte_pd, pdpte_pd_index);
		vm_expand_page_table_entry(value, vm_pdpte_pd->entry[pdpte_pd_index],
			VAL_2MB, init_pdpte_pd->entry[pdpte_pd_index]);
		sb_sync_page_table_flag(vm_pdpte_pd, init_pdpte_pd, pdpte_pd_index, value);

		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "New PDEPT is needed. Expand Log "
			"%016lX Phy %016lX", addr, (u64)virt_to_phys((void*)addr));

		if (expand_value == 0)
		{
			expand_value = VAL_2MB;
		}

#if SHADOWBOX_USE_PAGE_DEBUG
		while(1)
		{
			sb_pause_loop();
		}
#endif
	}

	init_pdept = phys_to_virt((u64)init_pdept & ~(MASK_PAGEFLAG));
	vm_pdept = (struct sb_pagetable*)(vm_pdpte_pd->entry[pdpte_pd_index]);
	vm_pdept = phys_to_virt((u64)vm_pdept & ~(MASK_PAGEFLAG));

	/*
	 * Get PTE from PDPTE_PD
	 */
	init_pte = (struct sb_pagetable*)(init_pdept->entry[pdept_index]);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "PDEPT index %d %016lX %016lX %016lX\n", pdept_index, vm_pdept, init_pdept, init_pdept->entry[pdept_index]);

	if ((init_pte == 0) || ((u64)init_pte & MASK_PAGE_SIZE_FLAG))
	{
		if (vm_pdept->entry[pdept_index] != (u64)init_pte)
		{
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "===================INFO======================");
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "PDEPT addr = %016lX sync\n", addr);
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "===================INFO======================");
		}
		else
		{
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "PDEPT is same");
		}

		vm_pdept->entry[pdept_index] = (u64)init_pte;

		sb_printf(LOG_LEVEL_NONE, LOG_INFO "PTE has size flags or 0\n");

#if SHADOWBOX_USE_PAGE_DEBUG
		while(1)
		{
			sb_pause_loop();
		}
#endif

		goto EXIT;
	}

	/* If PTE exist, syncronize the flag */
	if (vm_is_new_page_table_needed(vm_pdept, init_pdept, pdept_index) == 1)
	{
		value = vm_check_alloc_page_table(vm_pdept, pdept_index);
		vm_expand_page_table_entry(value, vm_pdept->entry[pdept_index], VAL_4KB,
			init_pdept->entry[pdept_index]);
		sb_sync_page_table_flag(vm_pdept, init_pdept, pdept_index, value);

		sb_printf(LOG_LEVEL_NORMAL, LOG_INFO "New PTE is needed. Expand Log "
			"%016lX Phy %016lX", addr, (u64)virt_to_phys((void*)addr));

		if (expand_value == 0)
		{
			expand_value = VAL_4KB;
		}

#if SHADOWBOX_USE_PAGE_DEBUG
		while(1)
		{
			sb_pause_loop();
		}
#endif

	}
	init_pte = phys_to_virt((u64)init_pte & ~(MASK_PAGEFLAG));
	vm_pte = (struct sb_pagetable*)(vm_pdept->entry[pdept_index]);

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "PTE index %d Physical %016lX %016lX\n",
		pte_index, vm_pte, init_pte);
	vm_pte = phys_to_virt((u64)vm_pte & ~(MASK_PAGEFLAG));
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "PTE index %d %016lX %016lX %016lX\n",
		pte_index, vm_pte, init_pte, init_pte->entry[pte_index]);

	/* Copy PTE from the guest */
	if (vm_pte->entry[pte_index] != init_pte->entry[pte_index])
	{
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "===================INFO======================");
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "PTE addr = %016lX sync\n", addr);
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "PTE index %d %016lX %016lX %016lX\n",
			pte_index, vm_pte, init_pte, init_pte->entry[pte_index]);
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "===================INFO======================");
	}
	else
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "PTE is same");
	}

#if SHADOWBOX_USE_PAGE_DEBUG
	if (init_pte->entry[pte_index] != phy_entry.phy_addr[3])
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "===================INFO======================");
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "PTE index %d is not same. Addr %016lX "
			"Physical %016lX %016lX\n", addr, pte_index, init_pte->entry[pte_index],
			phy_entry.phy_addr[3]);
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "===================INFO======================");

		while(1)
		{
			sb_pause_loop();
		}
	}
#endif

	vm_pte->entry[pte_index] = init_pte->entry[pte_index];

EXIT:

	/* Update page table to CPU */
	sb_set_cr3(g_vm_host_phy_pml4);
	return expand_value;
}

/*
 * Duplicate page tabel for the host.
 *
 * Memory space of Linux kernel is as follows.
 * 0000000000000000 - 00007fffffffffff (=47 bits) user space, different per mm
 * ffff800000000000 - ffff80ffffffffff (=40 bits) guard hole
 * ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all phys. memory
 * ffffc80000000000 - ffffc8ffffffffff (=40 bits) hole
 * ffffc90000000000 - ffffe8ffffffffff (=45 bits) vmalloc/ioremap space
 * ffffe90000000000 - ffffe9ffffffffff (=40 bits) hole
 * ffffea0000000000 - ffffeaffffffffff (=40 bits) virtual memory map (1TB)
 * ffffffff80000000 - ffffffffa0000000 (=512 MB)  kernel text mapping, from phys 0
 * ffffffffa0000000 - fffffffffff00000 (=1536 MB) module mapping space
 */
static void sb_dup_page_table_for_host(void)
{
	struct sb_pagetable* org_pml4;
	struct sb_pagetable* org_pdpte_pd;
	struct sb_pagetable* org_pdept;
	struct sb_pagetable* org_pte;
	struct sb_pagetable* vm_pml4;
	struct sb_pagetable* vm_pdpte_pd;
	struct sb_pagetable* vm_pdept;
	struct sb_pagetable* vm_pte;
	int i;
	int j;
	int k;
	struct mm_struct* swapper_mm;
	u64 cur_addr;

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Duplicate page tables\n");

	org_pml4 = (struct sb_pagetable*)sb_get_symbol_address("init_level4_pgt");
	g_vm_init_phy_pml4 = virt_to_phys(org_pml4);
	swapper_mm = (struct mm_struct*)sb_get_symbol_address("init_mm");
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "init_mm %016lX\n", swapper_mm);
	vm_pml4 =  (struct sb_pagetable*)__get_free_pages(GFP_KERNEL_ACCOUNT |
		__GFP_ZERO, PGD_ALLOCATION_ORDER);
#if SHADOWBOX_USE_EPT
	sb_hide_range((u64)vm_pml4, (u64)vm_pml4 + PAGE_SIZE * (0x1 << PGD_ALLOCATION_ORDER),
		ALLOC_KMALLOC);
#endif

	g_vm_host_phy_pml4 = virt_to_phys(vm_pml4);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "PML4 Logical %016lX, Physical %016lX, "
		"page_offset_base %016lX\n", vm_pml4, g_vm_host_phy_pml4, page_offset_base);

	/* Create page tables */
	for (i = 0 ; i < 512 ; i++)
	{
		cur_addr = i * VAL_512GB;

		if ((org_pml4->entry[i] == 0) ||
			((org_pml4->entry[i] & MASK_PAGE_SIZE_FLAG)))
		{
			vm_pml4->entry[i] = org_pml4->entry[i];
			continue;
		}

		vm_pml4->entry[i] = (u64)kmalloc(0x1000, GFP_KERNEL | GFP_ATOMIC |
			__GFP_COLD | __GFP_ZERO);
#if SHADOWBOX_USE_EPT
		sb_hide_range((u64)vm_pml4->entry[i], (u64)(vm_pml4->entry[i]) + PAGE_SIZE,
			ALLOC_KMALLOC);
#endif
		vm_pml4->entry[i] = virt_to_phys((void*)(vm_pml4->entry[i]));
		vm_pml4->entry[i] |= org_pml4->entry[i] & MASK_PAGEFLAG;

		/* Run loop to copy PDEPT */
		org_pdpte_pd = (struct sb_pagetable*)(org_pml4->entry[i] & ~(MASK_PAGEFLAG));
		vm_pdpte_pd = (struct sb_pagetable*)(vm_pml4->entry[i] & ~(MASK_PAGEFLAG));
		org_pdpte_pd = phys_to_virt((u64)org_pdpte_pd);
		vm_pdpte_pd = phys_to_virt((u64)vm_pdpte_pd);

		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] PML4[%d] %16lX %16lp %16lp\n",
			i, org_pml4->entry[i], org_pdpte_pd, vm_pdpte_pd);
		for (j = 0 ; j < 512 ; j++)
		{
			if ((org_pdpte_pd->entry[j] == 0) ||
				((org_pdpte_pd->entry[j] & MASK_PAGE_SIZE_FLAG)))
			{
				vm_pdpte_pd->entry[j] = org_pdpte_pd->entry[j];
				continue;
			}

			/* Allocate PDEPT and copy */
			vm_pdpte_pd->entry[j] = (u64)kmalloc(0x1000, GFP_KERNEL | GFP_ATOMIC |
				__GFP_COLD | __GFP_ZERO);
#if SHADOWBOX_USE_EPT
			sb_hide_range((u64)vm_pdpte_pd->entry[j], (u64)(vm_pdpte_pd->entry[j]) +
				PAGE_SIZE, ALLOC_KMALLOC);
#endif
			vm_pdpte_pd->entry[j] = virt_to_phys((void*)(vm_pdpte_pd->entry[j]));
			vm_pdpte_pd->entry[j] |= org_pdpte_pd->entry[j] & MASK_PAGEFLAG;

			/* Run loop to copy PDEPT */
			org_pdept = (struct sb_pagetable*)(org_pdpte_pd->entry[j] & ~(MASK_PAGEFLAG));
			vm_pdept = (struct sb_pagetable*)(vm_pdpte_pd->entry[j] & ~(MASK_PAGEFLAG));
			org_pdept = phys_to_virt((u64)org_pdept);
			vm_pdept = phys_to_virt((u64)vm_pdept);

			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] PDPTE_PD[%d] %016lX"
				" %016lp %016lp\n", j, org_pdpte_pd->entry[j], org_pdept, vm_pdept);
			for (k = 0 ; k < 512 ; k++)
			{
				if ((org_pdept->entry[k] == 0) ||
					((org_pdept->entry[k] & MASK_PAGE_SIZE_FLAG)))
				{
					vm_pdept->entry[k] = org_pdept->entry[k];
					continue;
				}

				/* Allocate PTE and copy */
				vm_pdept->entry[k] = (u64)kmalloc(0x1000, GFP_KERNEL | GFP_ATOMIC |
					__GFP_COLD | __GFP_ZERO);
#if SHADOWBOX_USE_EPT
				sb_hide_range((u64)vm_pdept->entry[k], (u64)(vm_pdept->entry[k]) + PAGE_SIZE,
					ALLOC_KMALLOC);
#endif
				vm_pdept->entry[k] = virt_to_phys((void*)(vm_pdept->entry[k]));
				vm_pdept->entry[k] |= org_pdept->entry[k] & MASK_PAGEFLAG;

				/* Run loop to copy PTE */
				org_pte = (struct sb_pagetable*)(org_pdept->entry[k] & ~(MASK_PAGEFLAG));
				vm_pte = (struct sb_pagetable*)(vm_pdept->entry[k] & ~(MASK_PAGEFLAG));
				org_pte = phys_to_virt((u64)org_pte);
				vm_pte = phys_to_virt((u64)vm_pte);

				sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "            [*] PDEPT[%d]"
					" %016lX %016lp %016lp\n", k, org_pdept->entry[k], org_pte,
					vm_pte);
				memcpy(vm_pte, org_pte, 0x1000);
			}
		}
	}
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] complete\n");
}


/*
 * Protect VMCS structure.
 */
static void sb_protect_vmcs(void)
{
	int i;
	int cpu_count;

	cpu_count = num_online_cpus();
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Protect VMCS\n");

	for (i = 0 ; i < cpu_count ; i++)
	{
		sb_hide_range((u64)g_vmx_on_vmcs_log_addr[i],
			(u64)g_vmx_on_vmcs_log_addr[i] + VMCS_SIZE, ALLOC_KMALLOC);
		sb_hide_range((u64)g_guest_vmcs_log_addr[i],
			(u64)g_guest_vmcs_log_addr[i] + VMCS_SIZE, ALLOC_KMALLOC);
		sb_hide_range((u64)g_vm_exit_stack_addr[i],
			(u64)g_vm_exit_stack_addr[i] + g_stack_size, ALLOC_VMALLOC);
		sb_hide_range((u64)g_io_bitmap_addrA[i],
			(u64)g_io_bitmap_addrA[i] + IO_BITMAP_SIZE, ALLOC_KMALLOC);
		sb_hide_range((u64)g_io_bitmap_addrB[i],
			(u64)g_io_bitmap_addrB[i] + IO_BITMAP_SIZE, ALLOC_KMALLOC);
		sb_hide_range((u64)g_msr_bitmap_addr[i],
			(u64)g_msr_bitmap_addr[i] + IO_BITMAP_SIZE, ALLOC_KMALLOC);
		sb_hide_range((u64)g_virt_apic_page_addr[i],
			(u64)g_virt_apic_page_addr[i] + VIRT_APIC_PAGE_SIZE, ALLOC_KMALLOC);
	}
}

/*
 * Hang system.
 * This function should be called in emergency situation.
 */
void sb_hang(char* string)
{
	do
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "===============================\n");
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "===============================\n");
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "HANG %s\n", string);
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "===============================\n");
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "===============================\n");

		msleep(5000);
	} while(sb_is_system_shutdowning() == 0);
}

/*
 * Disable machine check exception and change the check interval.
 */
static void sb_disable_and_change_machine_check_timer(void)
{
	typedef void (*mce_timer_delete_all) (void);
	typedef void (*mce_cpu_restart) (void *data);
	u64 cr4;

	unsigned long *check_interval;
	mce_timer_delete_all delete_timer_fp;
	mce_cpu_restart restart_cpu_fp;

	/* Disable MCE event. */
	cr4 = sb_get_cr4();
	cr4 &= ~(CR4_BIT_MCE);
	sb_set_cr4(cr4);
	disable_irq(VM_INT_MACHINE_CHECK);

	/* Change MCE polling timer. */
	if (smp_processor_id() == 0)
	{
		check_interval = (unsigned long *)sb_get_symbol_address("check_interval");
		delete_timer_fp = (mce_timer_delete_all)sb_get_symbol_address("mce_timer_delete_all");
		restart_cpu_fp = (mce_cpu_restart)sb_get_symbol_address("mce_cpu_restart");

		/* Set seconds for timer interval and restart timer. */
		*check_interval = VM_MCE_TIMER_VALUE;

		delete_timer_fp();
		on_each_cpu(restart_cpu_fp, NULL, 1);
	}
}

/*
 * Enable VT-x and run Shadow-box.
 * This thread function runs on each core.
 */
static int sb_vm_thread(void* argument)
{
	struct sb_vm_host_register* host_register;
	struct sb_vm_guest_register* guest_register;
	struct sb_vm_control_register* control_register;
	u64 vm_err_number;
	unsigned long irqs;
	int result;
	int cpu_id;

	cpu_id = smp_processor_id();

	/* Disable MCE exception. */
	sb_disable_and_change_machine_check_timer();

	/* Synchronize processors. */
	atomic_dec(&g_thread_entry_count);
	while(atomic_read(&g_thread_entry_count) > 0)
	{
		schedule();
	}

	host_register = kmalloc(sizeof(struct sb_vm_host_register), GFP_KERNEL | __GFP_COLD);
	guest_register = kmalloc(sizeof(struct sb_vm_guest_register), GFP_KERNEL | __GFP_COLD);
	control_register = kmalloc(sizeof(struct sb_vm_control_register), GFP_KERNEL | __GFP_COLD);

	if ((host_register == NULL) || (guest_register == NULL) ||
			(control_register == NULL))
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Host or Guest or Control "
			"Register alloc fail\n", cpu_id);
		g_thread_result |= -1;
		return -1;
	}

	memset(host_register, 0, sizeof(struct sb_vm_host_register));
	memset(guest_register, 0, sizeof(struct sb_vm_guest_register));
	memset(control_register, 0, sizeof(struct sb_vm_control_register));

	/* Lock module_mutex, and protect module RO area, and syncronize all core. */
	if (cpu_id == 0)
	{
		mutex_lock(&module_mutex);
		sb_protect_module_list_ro_area();

		atomic_set(&g_mutex_lock_flags, 1);
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] module mutex lock complete\n",
			cpu_id);
	}
	else
	{
		while (atomic_read(&g_mutex_lock_flags) == 0)
		{
			schedule();
		}
	}

	/* Disable preemption and hold processors. */
	preempt_disable();

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Wait until thread executed\n",
		cpu_id);

	/* Synchronize processors. */
	atomic_dec(&g_thread_run_flags);
	while(atomic_read(&g_thread_run_flags) > 0)
	{
		mdelay(1);
	}
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Complete to wait until thread "
		"executed\n", cpu_id);

	/* Lock tasklist_lock and initialize Shadow-watcher. */
	if (cpu_id == 0)
	{
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Dup talbe Initialize \n",
			cpu_id);

		/* Duplicate page table for the host and Shadow-box. */
		sb_dup_page_table_for_host();

		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Dup talbe Initialize Complete\n",
			cpu_id);

		/* Lock tasklist. */
		read_lock(g_tasklist_lock);

		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Framework Initialize \n",
			cpu_id);

		/* Initialize Shadow-watcher. */
		sb_init_shadow_watcher();

		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Framework Initialize Complete \n",
			cpu_id);

		/* Unlock tasklist. */
		read_unlock(g_tasklist_lock);
	}

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Framework Initialize Waiting\n",
		cpu_id);

	/* Synchronize processors. */
	atomic_dec(&g_framework_init_flags);
	while(atomic_read(&g_framework_init_flags) > 0)
	{
		mdelay(1);
	}
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM [%d] Complete\n", cpu_id);

	/* Disable interrupt before VM launch */
	local_irq_save(irqs);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] IRQ Lock complete\n", cpu_id);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Wait until stable status\n",
		cpu_id);
	mdelay(10);

	/* Synchronize processors. */
	atomic_dec(&g_sync_flags);
	while(atomic_read(&g_sync_flags) > 0)
	{
		mdelay(1);
	}
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Ready to go!!\n", cpu_id);

#if SHADOWBOX_USE_IOMMU
	/* Lock iommu and synchronize processors. */
	if (cpu_id == 0)
	{
		sb_lock_iommu();
		atomic_set(&g_iommu_complete_flags, 1);
	}
	else
	{
		while(atomic_read(&g_iommu_complete_flags) == 0)
		{
			mdelay(1);
		}
	}
#endif /* SHADOWBOX_USE_IOMMU */

	/* Synchronize processors. */
	while (atomic_read(&g_enter_count) != cpu_id)
	{
		mdelay(1);
	}

	/* Initialize VMX */
	if (sb_init_vmx(cpu_id) < 0)
	{
		atomic_set(&g_enter_flags, 0);
		atomic_inc(&g_enter_count);
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] sb_init_vmx fail\n", cpu_id);
		goto ERROR;
	}

	sb_protect_gdt(cpu_id);
	sb_setup_vm_host_register(host_register);
	sb_setup_vm_guest_register(guest_register, host_register);
	sb_setup_vm_control_register(control_register, cpu_id);
	sb_setup_vmcs(host_register, guest_register, control_register);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Launch Start\n", cpu_id);
	result = sb_vm_launch();

	atomic_set(&g_enter_flags, 0);
	atomic_inc(&g_enter_count);

	if (result == -2)
	{
		sb_printf(LOG_LEVEL_NONE, LOG_ERROR "    [*] VM [%d] Launch Valid Fail\n",
			cpu_id);
		sb_read_vmcs(VM_DATA_INST_ERROR, &vm_err_number);
		sb_printf(LOG_LEVEL_NONE, LOG_ERROR "    [*] VM [%d] Error Number [%d]\n",
			cpu_id, (int)vm_err_number);
		sb_error_log(ERROR_LAUNCH_FAIL);

		goto ERROR;
	}
	else if (result == -1)
	{
		sb_printf(LOG_LEVEL_NONE, LOG_ERROR "    [*] VM [%d] Launch Invalid Fail\n",
			cpu_id);
		sb_error_log(ERROR_LAUNCH_FAIL);

		goto ERROR;
	}
	else
	{
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM [%d] Launch Success\n",
			cpu_id);
	}

	/* Synchronize processors. */
	atomic_dec(&g_framework_init_start_flags);
	while(atomic_read(&g_framework_init_start_flags) > 0)
	{
		mdelay(1);
	}

	/* Enable interrupt */
	local_irq_restore(irqs);
	preempt_enable();

	if (cpu_id == 0)
	{
		mutex_unlock(&module_mutex);
	}
	atomic_dec(&g_complete_flags);

	return 0;

/* Handle errors. */
ERROR:
	g_thread_result |= -1;

	/* Enable interrupt */
	local_irq_restore(irqs);
	preempt_enable();

	if (cpu_id == 0)
	{
		mutex_unlock(&module_mutex);
	}
	atomic_dec(&g_complete_flags);

	return -1;
}

/*
 * Initialize VMX context (VMCS)
 */
static int sb_init_vmx(int cpu_id)
{
	u64 vmx_msr;
	u64 msr;
	u64 cr4;
	u64 cr0;
	u32* vmx_VMCS_log_addr;
	u32* vmx_VMCS_phy_addr;
	u32* guest_VMCS_log_addr;
	u32* guest_VMCS_phy_addr;
	u64 value;
	int result;

	// To handle the SMXE exception.
	if (g_support_smx)
	{
		cr4 = sb_get_cr4();
		cr4 |= CR4_BIT_SMXE;
		sb_set_cr4(cr4);
	}

	vmx_msr = sb_rdmsr(MSR_IA32_VM_BASIC);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_VMX_BASIC MSR Value %016lX\n",
		vmx_msr);

	value = sb_rdmsr(MSR_IA32_VMX_ENTRY_CTRLS);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_VMX_ENTRY_CTRLS MSR Value "
		"%016lX\n", value);

	value = sb_rdmsr(MSR_IA32_VMX_EXIT_CTRLS);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_VMX_EXIT_CTRLS MSR Value "
		"%016lX\n", value);

	msr = sb_rdmsr(MSR_IA32_FEATURE_CONTROL);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_FEATURE_CONTROL MSR Value "
		"%016lX\n", msr);

	msr = sb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_IA32_VMX_PROCBASED_CTRLS "
		"MSR Value %016lX\n", msr);

	msr = sb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_IA32_VMX_PROCBASED_CTRLS2 "
		"MSR Value %016lX\n", msr);

	msr = sb_rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_IA32_VMX_EPT_VPID MSR Value "
		"%016lX\n", msr);


	msr = sb_rdmsr(MSR_IA32_EFER);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_EFER MSR Value %016lX\n",
		msr);

	cr0 = sb_get_cr0();
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] CR0 %016lX\n", cr0);

	cr4 = sb_get_cr4();
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Before Enable VMX CR4 %016lX\n",
		cr4);

	sb_enable_vmx();
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Enable VMX CR4\n");

	cr4 = sb_get_cr4();
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] After Enable VMX CR4 %016lX\n",
		cr4);

	vmx_VMCS_log_addr = (u32*)(g_vmx_on_vmcs_log_addr[cpu_id]);
	vmx_VMCS_phy_addr = (u32*)virt_to_phys(vmx_VMCS_log_addr);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Alloc Physical VMCS %016lX\n",
		vmx_VMCS_phy_addr);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Start VMX\n");

	/* First data of VMCS should be VMX revision number */
	vmx_VMCS_log_addr[0] = (u32)vmx_msr;
	result = sb_start_vmx(&vmx_VMCS_phy_addr);
	if (result == 0)
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] VMXON Success\n");
	}
	else
	{
		sb_printf(LOG_LEVEL_NONE, LOG_ERROR "    [*] VMXON Fail\n");
		sb_error_log(ERROR_LAUNCH_FAIL);
		return -1;
	}

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Preparing Geust\n");

	/* Allocate kernel memory for Guest VCMS */
	guest_VMCS_log_addr = (u32*)(g_guest_vmcs_log_addr[cpu_id]);
	guest_VMCS_phy_addr = (u32*)virt_to_phys(guest_VMCS_log_addr);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Alloc Physical Guest VMCS %016lX\n",
		guest_VMCS_phy_addr);

	/* First data of VMCS should be VMX revision number */
	guest_VMCS_log_addr[0] = (u32) vmx_msr;
	result = sb_clear_vmcs(&guest_VMCS_phy_addr);
	if (result == 0)
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Guest VCMS Clear Success\n");
	}
	else
	{
		sb_printf(LOG_LEVEL_NONE, LOG_ERROR "    [*] Guest VCMS Clear Fail\n");
		sb_error_log(ERROR_LAUNCH_FAIL);
		return -1;
	}

	result = sb_load_vmcs((void**)&guest_VMCS_phy_addr);
	if (result == 0)
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Guest VCMS Load Success\n");
	}
	else
	{
		sb_printf(LOG_LEVEL_NONE, LOG_ERROR "    [*] Guest VCMS Load Fail\n");
		sb_error_log(ERROR_LAUNCH_FAIL);
		return -1;
	}

	return 0;
}

/*
 * Skip guest instruction
 */
static void sb_advance_vm_guest_rip(void)
{
	u64 inst_delta;
	u64 rip;

	sb_read_vmcs(VM_DATA_VM_EXIT_INST_LENGTH, &inst_delta);
	sb_read_vmcs(VM_GUEST_RIP, &rip);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM_DATA_VM_EXIT_INST_LENGTH: %016lX, "
		"VM_GUEST_RIP: %016lX\n", inst_delta, rip);
	sb_write_vmcs(VM_GUEST_RIP, rip + inst_delta);
}

/*
 * Calculate preemption timer value
 */
static u64 sb_calc_vm_pre_timer_value(void)
{
	u64 scale;

	scale = sb_rdmsr(MSR_IA32_VMX_MISC);
	scale &= 0x1F;

	return (VM_PRE_TIMER_VALUE >> scale);
}

/*
 * Dump vm_exit event data
 */
void sb_dump_vm_exit_data(void)
{
	u64 value;
	int i;
	u64 total = 0;

	value = jiffies - g_dump_jiffies;
	if (jiffies_to_msecs(value) >= 1000)
	{
		for (i = 0 ; i < MAX_VM_EXIT_DUMP_COUNT ; i++)
		{
			total += g_dump_count[i];
		}

		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] ====== %ld =======\n", total);
		for (i = 0 ; i < MAX_VM_EXIT_DUMP_COUNT / 16 ; i++)
		{
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] %ld %ld %ld %ld %ld %ld "
				"%ld % ld %ld %ld %ld %ld %ld %ld %ld %ld\n", i * 16,
				g_dump_count[i * 16], g_dump_count[i * 16 + 1],
				g_dump_count[i * 16 + 2], g_dump_count[i * 16 + 3],
				g_dump_count[i * 16 + 4], g_dump_count[i * 16 + 5],
				g_dump_count[i * 16 + 6], g_dump_count[i * 16 + 7],
				g_dump_count[i * 16 + 8], g_dump_count[i * 16 + 9],
				g_dump_count[i * 16 + 10], g_dump_count[i * 16 + 11],
				g_dump_count[i * 16 + 12], g_dump_count[i * 16 + 13],
				g_dump_count[i * 16 + 14], g_dump_count[i * 16 + 15]);
		}

		memset(g_dump_count, 0, sizeof(g_dump_count));

		g_dump_jiffies = jiffies;
	}
}

/*
 * Process vm_exit event.
 */
void sb_vm_exit_callback(struct sb_vm_exit_guest_register* guest_context)
{
	u64 exit_reason;
	u64 exit_qual;
	u64 guest_linear;
	u64 guest_physical;
	int cpu_id;
	u64 info_field;

	cpu_id = smp_processor_id();

	/* Update currnt cpu mode. */
	g_vmx_root_mode[cpu_id] = 1;

	sb_read_vmcs(VM_DATA_EXIT_REASON, &exit_reason);
	sb_read_vmcs(VM_DATA_EXIT_QUALIFICATION, &exit_qual);
	sb_read_vmcs(VM_DATA_GUEST_LINEAR_ADDR, &guest_linear);
	sb_read_vmcs(VM_DATA_GUEST_PHY_ADDR, &guest_physical);

	sb_read_vmcs(VM_DATA_VM_EXIT_INT_INFO, &info_field);

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] EXIT Reason field: %016lX\n",
		cpu_id, exit_reason);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] EXIT Interrupt Info field: %016lX\n",
		cpu_id, info_field);

	/* Check system is shutdowning and shutdown timer is expired */
	sb_trigger_shutdown_timer();
	sb_is_shutdown_timer_expired();

	sb_write_vmcs(VM_CTRL_VM_ENTRY_INST_LENGTH, 0);

	if ((g_allow_shadow_box_hide == 1) &&
		((jiffies_to_msecs(jiffies - g_init_in_secure_jiffies) >= SHADOW_BOX_HIDE_TIME_BUFFER_MS)))
	{
		if (atomic_cmpxchg(&g_need_init_in_secure, 1, 0))
		{
#if SHADOWBOX_USE_EPT
			/* Hide Shadow-box module here after all vm thread are terminated */
			sb_protect_shadow_box_module();
			sb_protect_shadow_watcher_data();
#endif /* SHADOWBOX_USE_EPT */

			g_allow_shadow_box_hide = 0;
		}
	}

 #if SHADOWBOX_USE_VMEXIT_DEBUG
	g_dump_count[exit_reason & 0xFFFF] += 1;
	sb_dump_vm_exit_data();
#endif /* SHADOWBOX_USE_VMEXIT_DEBUG */

	switch((exit_reason & 0xFFFF))
	{
		case VM_EXIT_REASON_EXCEPT_OR_NMI:
			sb_vm_exit_callback_int(cpu_id, exit_qual, guest_context);
			break;

		case VM_EXIT_REASON_EXT_INTTERUPT:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] External Interrupt \n",
				cpu_id);
			break;

		case VM_EXIT_REASON_TRIPLE_FAULT:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Triple fault \n", cpu_id);
			sb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_INIT_SIGNAL:
			sb_vm_exit_callback_init_signal(cpu_id);
			break;

		case VM_EXIT_REASON_START_UP_IPI:
			sb_vm_exit_callback_start_up_signal(cpu_id);
			break;

		case VM_EXIT_REASON_IO_SMI:
		case VM_EXIT_REASON_OTHER_SMI:
		case VM_EXIT_REASON_INT_WINDOW:
		case VM_EXIT_REASON_NMI_WINDOW:
		case VM_EXIT_REASON_TASK_SWITCH:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] VM_EXIT_REASON_IO_SMI, "
				"INT, NMI\n", cpu_id);
			sb_advance_vm_guest_rip();
			break;

		/* Unconditional VM exit event */
		case VM_EXIT_REASON_CPUID:
			sb_vm_exit_callback_cpuid(guest_context);
			break;

		/* For tboot interoperation*/
		case VM_EXIT_REASON_GETSEC:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] GETSEC call \n", cpu_id);
			sb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_HLT:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] VM_EXIT_REASON_GETSEC, HLT\n",
				cpu_id);
			sb_advance_vm_guest_rip();
			break;

		/* Unconditional VM exit event */
		case VM_EXIT_REASON_INVD:
			sb_vm_exit_callback_invd();
			break;

		case VM_EXIT_REASON_INVLPG:
		case VM_EXIT_REASON_RDPMC:
		case VM_EXIT_REASON_RDTSC:
		case VM_EXIT_REASON_RSM:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] VM_EXIT_REASON_INVLPG, "
				"RDPMC, RDTSC, RSM\n", cpu_id);
			sb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_VMCLEAR:
		case VM_EXIT_REASON_VMLAUNCH:
		case VM_EXIT_REASON_VMPTRLD:
		case VM_EXIT_REASON_VMPTRST:
		case VM_EXIT_REASON_VMREAD:
		case VM_EXIT_REASON_VMRESUME:
		case VM_EXIT_REASON_VMWRITE:
		case VM_EXIT_REASON_VMXON:
		case VM_EXIT_REASON_VMXOFF:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Virtualization Instruction "
				"Detected\n", cpu_id);
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Skip VT instruction\n",
				cpu_id);
			sb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_VMCALL:
			sb_vm_exit_callback_vmcall(cpu_id, guest_context);
			break;

		/* Unconditional VM exit event (move fron reg_value) */
		case VM_EXIT_REASON_CTRL_REG_ACCESS:
			sb_vm_exit_callback_access_cr(cpu_id, guest_context, exit_reason, exit_qual);
			break;

		case VM_EXIT_REASON_MOV_DR:
			sb_printf(LOG_LEVEL_DETAIL, LOG_ERROR "VM [%d] MOVE DR is executed",
				cpu_id);
			sb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_IO_INST:
		case VM_EXIT_REASON_RDMSR:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] VM_EXIT_REASON_IO_INST, "
				"RDMSR\n", cpu_id);
			sb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_WRMSR:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] VM_EXIT_REASON_WRMSR\n",
				cpu_id);
			sb_vm_exit_callback_wrmsr(cpu_id);
			break;

		case VM_EXIT_REASON_VM_ENTRY_FAILURE_INV_GUEST:
		case VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOAD:
		case VM_EXIT_REASON_MWAIT:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] VM_EXIT_REASON_VM_ENTRY_"
				"FAILURE_INV_GUEST, MSR_LOAD\n", cpu_id);
			sb_advance_vm_guest_rip();
			break;

		/* For hardware breakpoint interoperation */
		case VM_EXIT_REASON_MONITOR_TRAP_FLAG:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] VM_EXIT_REASON_TRAP_FLAG\n",
				cpu_id);
			sb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_MONITOR:
		case VM_EXIT_REASON_PAUSE:
		case VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK:
		case VM_EXIT_REASON_TRP_BELOW_THRESHOLD:
		case VM_EXIT_REASON_APIC_ACCESS:
		case VM_EXIT_REASON_VIRTUALIZED_EOI:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] VM_EXIT_REASON_MONITOR, "
				"PAUSE, VM_ENTRY_FAILURE_MACHINE_CHECK,...\n", cpu_id);
			sb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_ACCESS_GDTR_OR_IDTR:
			sb_vm_exit_callback_gdtr_idtr(cpu_id, guest_context);
			break;

		case VM_EXIT_REASON_ACCESS_LDTR_OR_TR:
			sb_vm_exit_callback_ldtr_tr(cpu_id, guest_context);
			break;

		case VM_EXIT_REASON_EPT_VIOLATION:
			sb_vm_exit_callback_ept_violation(cpu_id, guest_context, exit_reason,
				exit_qual, guest_linear, guest_physical);
			break;

		case VM_EXIT_REASON_EPT_MISCONFIGURATION:
		case VM_EXIT_REASON_INVEPT:
		case VM_EXIT_REASON_RDTSCP:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] VM_EXIT_REASON_EPT_MISCONFIG\n",
				cpu_id);
			sb_advance_vm_guest_rip();
			break;

		case VM_EXIT_REASON_VMX_PREEMP_TIMER_EXPIRED:
			sb_vm_exit_callback_pre_timer_expired(cpu_id);
			break;

		case VM_EXIT_REASON_INVVPID:
		case VM_EXIT_REASON_WBINVD:
		case VM_EXIT_REASON_XSETBV:
		case VM_EXIT_REASON_APIC_WRITE:
		case VM_EXIT_REASON_RDRAND:
		case VM_EXIT_REASON_INVPCID:
		case VM_EXIT_REASON_VMFUNC:
		case VM_EXIT_REASON_RDSEED:
		case VM_EXIT_REASON_XSAVES:
		case VM_EXIT_REASON_XRSTORS:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] VM_EXIT_REASON_INVVPID\n",
				cpu_id);
			sb_advance_vm_guest_rip();
			break;

		default:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] VM_EXIT_REASON_DEFAULT\n",
				cpu_id);
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Exit Reason: %d, %016lX\n",
				cpu_id, (u32)exit_reason, exit_reason);
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Exit Qualification: %d, %016lX\n",
				cpu_id, (u32)exit_qual, exit_qual);
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Guest Linear: %d, %016lX\n",
				cpu_id, (u32)guest_linear, guest_linear);
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Guest Physical: %d, %016lX\n",
				cpu_id, (u32)guest_physical, guest_physical);
			sb_advance_vm_guest_rip();
			break;
	}

	/* Update currnt cpu mode. */
	g_vmx_root_mode[cpu_id] = 0;
}

/*
 * Process interrupt callback.
 */
static void sb_vm_exit_callback_int(int cpu_id, unsigned long dr6, struct
	sb_vm_exit_guest_register* guest_context)
{
	unsigned long dr7;
	u64 info_field;
	int vector;
	int type;
 
	// 8:10 bit is NMI
	sb_read_vmcs(VM_DATA_VM_EXIT_INT_INFO, &info_field);
	vector = VM_EXIT_INT_INFO_VECTOR(info_field);
	type = VM_EXIT_INT_INFO_INT_TYPE(info_field);

	if (type == VM_EXIT_INT_TYPE_NMI)
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] ===================WARNING======================\n",
			cpu_id);
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] NMI Interrupt Occured\n", cpu_id);
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] ===================WARNING======================\n",
			cpu_id);
	}
	else if (vector != VM_INT_DEBUG_EXCEPTION)
	{
		sb_remove_int_exception_from_vm(vector);
		return ;
	}

	/* For stable shutdown, skip processing if system is shutdowning. */
	if (sb_is_system_shutdowning() == 0)
	{
		/* Create process case. */
		if (dr6 & DR_BIT_ADD_TASK)
		{
			sb_sw_callback_add_task(cpu_id, guest_context);
		}

		/* Terminate process case. */
		if (dr6 & DR_BIT_DEL_TASK)
		{
			sb_sw_callback_del_task(cpu_id, guest_context);
		}

		/* Load module case. */
		if (dr6 & DR_BIT_INSMOD)
		{
			sb_sw_callback_insmod(cpu_id);
		}

		/* Unload module case. */
		if (dr6 & DR_BIT_RMMOD)
		{
			sb_sw_callback_rmmod(cpu_id, guest_context);
		}
	}

	dr6 &= 0xfffffffffffffff0;
	set_debugreg(dr6, 6);

	/* When the guest is resumed, Let the guest skip hardware breakpoint. */
	sb_read_vmcs(VM_GUEST_RFLAGS, (u64*)&dr7);
	dr7 |= RFLAGS_BIT_RF;
	sb_write_vmcs(VM_GUEST_RFLAGS, dr7);

	sb_remove_int_exception_from_vm(vector);
}

/*
 * Process INIT IPI.
 */
static void sb_vm_exit_callback_init_signal(int cpu_id)
{
	u64 status;

	sb_read_vmcs(VM_GUEST_ACTIVITY_STATE, &status);
	sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] ===================WARNING======================\n",
		cpu_id);
	sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Activity Status %016lX\n", cpu_id,
		status);
	sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] ===================WARNING======================\n",
		cpu_id);
}

/*
 * Process Startup IPI.
 */
static void sb_vm_exit_callback_start_up_signal(int cpu_id)
{
	u64 status;

	sb_read_vmcs(VM_GUEST_ACTIVITY_STATE, &status);
	sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] ===================WARNING======================\n",
		cpu_id);
	sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Change Activity Status to Active, %016lX\n",
		cpu_id, status);
	sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] ===================WARNING======================\n",
		cpu_id);
}

/*
 * Process  read and write event of control register.
 */
static void sb_vm_exit_callback_access_cr(int cpu_id, struct sb_vm_exit_guest_register*
	guest_context, u64 exit_reason, u64 exit_qual)
{
	u64 reg_value = 0;
	u64 prev_cr3 = 0;

	if (VM_EXIT_QUAL_CTRL_REG_ACC_GET_ACC_TYPE(exit_qual) ==
		VM_EXIT_QUAL_CTRL_REG_ACC_MOVE_FROM_CR)
	{
		switch(VM_EXIT_QUAL_CTRL_REG_ACC_GET_CTRL_REG_NUMBER(exit_qual))
		{
			case REG_NUM_CR0:
				reg_value = sb_get_cr0();
				break;

			case REG_NUM_CR2:
				reg_value = sb_get_cr2();
				break;

			case REG_NUM_CR3:
				reg_value = sb_get_cr3();
				break;

			case REG_NUM_CR4:
				reg_value = sb_get_cr4();
				break;

			case REG_NUM_CR8:
				reg_value = sb_get_cr8();
				break;
		}

		sb_set_reg_value_from_index(guest_context,
			VM_EXIT_QUAL_CTRL_REG_ACC_GET_GP_REG_NUMBER(exit_qual), reg_value);
	}
	else if (VM_EXIT_QUAL_CTRL_REG_ACC_GET_ACC_TYPE(exit_qual) ==
			 VM_EXIT_QUAL_CTRL_REG_ACC_MOVE_TO_CR)
	{
		reg_value = sb_get_reg_value_from_index(guest_context,
			VM_EXIT_QUAL_CTRL_REG_ACC_GET_GP_REG_NUMBER(exit_qual));

		switch(VM_EXIT_QUAL_CTRL_REG_ACC_GET_CTRL_REG_NUMBER(exit_qual))
		{
			case REG_NUM_CR0:
				sb_write_vmcs(VM_GUEST_CR0, reg_value);
				break;

			case REG_NUM_CR2:
				/* sb_write_vmcs(VM_GUEST_CR2, reg_value); */
				break;

			case REG_NUM_CR3:
				sb_read_vmcs(VM_GUEST_CR3, &prev_cr3);
				sb_write_vmcs(VM_GUEST_CR3, reg_value);
				break;

			case REG_NUM_CR4:
				/* VMXE bit should be set! for unrestricted guest. */
				reg_value |= ((u64) CR4_BIT_VMXE);
				sb_write_vmcs(VM_GUEST_CR4, reg_value);
				break;

			case REG_NUM_CR8:
				/* sb_write_vmcs(VM_GUEST_CR8, reg_value); */
				break;
		}
	}
	else
	{
		sb_printf(LOG_LEVEL_NONE, LOG_ERROR "VM [%d] VM_EXIT_QUAL_CTRL_REG is "
			"not move from reg_value: %d\n", cpu_id,
			(int)VM_EXIT_QUAL_CTRL_REG_ACC_GET_ACC_TYPE(exit_qual));
		sb_printf(LOG_LEVEL_NONE, LOG_ERROR "VM [%d] VM_EXIT_QUAL_CTRL_REG is "
			"not move from reg_value\n", cpu_id);
	}

	sb_advance_vm_guest_rip();
}

/*
 * Get register value of index in guest context.
 */
static u64 sb_get_reg_value_from_index(struct sb_vm_exit_guest_register* guest_context, int index)
{
	u64 reg_value = 0;

	switch(index)
	{
		case REG_NUM_RAX:
			reg_value = guest_context->rax;
			break;

		case REG_NUM_RCX:
			reg_value = guest_context->rcx;
			break;

		case REG_NUM_RDX:
			reg_value = guest_context->rdx;
			break;

		case REG_NUM_RBX:
			reg_value = guest_context->rbx;
			break;

		case REG_NUM_RSP:
			/* reg_value = guest_context->rsp; */
			break;

		case REG_NUM_RBP:
			reg_value = guest_context->rbp;
			break;

		case REG_NUM_RSI:
			reg_value = guest_context->rsi;
			break;

		case REG_NUM_RDI:
			reg_value = guest_context->rdi;
			break;

		case REG_NUM_R8:
			reg_value = guest_context->r8;
			break;

		case REG_NUM_R9:
			reg_value = guest_context->r9;
			break;

		case REG_NUM_R10:
			reg_value = guest_context->r10;
			break;

		case REG_NUM_R11:
			reg_value = guest_context->r11;
			break;

		case REG_NUM_R12:
			reg_value = guest_context->r12;
			break;

		case REG_NUM_R13:
			reg_value = guest_context->r13;
			break;

		case REG_NUM_R14:
			reg_value = guest_context->r14;
			break;

		case REG_NUM_R15:
			reg_value = guest_context->r15;
			break;
	}

	return reg_value;
}

/*
 * Set value to register of index in guest context.
 */
static void sb_set_reg_value_from_index(struct sb_vm_exit_guest_register*
	guest_context, int index, u64 reg_value)
{
	switch(index)
	{
		case REG_NUM_RAX:
			guest_context->rax = reg_value;
			break;

		case REG_NUM_RCX:
			guest_context->rcx = reg_value;
			break;

		case REG_NUM_RDX:
			guest_context->rdx = reg_value;
			break;

		case REG_NUM_RBX:
			guest_context->rbx = reg_value;
			break;

		case REG_NUM_RSP:
			/* guest_context->rsp = reg_value; */
			break;

		case REG_NUM_RBP:
			guest_context->rbp = reg_value;
			break;

		case REG_NUM_RSI:
			guest_context->rsi = reg_value;
			break;

		case REG_NUM_RDI:
			guest_context->rdi = reg_value;
			break;

		case REG_NUM_R8:
			guest_context->r8 = reg_value;
			break;

		case REG_NUM_R9:
			guest_context->r9 = reg_value;
			break;

		case REG_NUM_R10:
			guest_context->r10 = reg_value;
			break;

		case REG_NUM_R11:
			guest_context->r11 = reg_value;
			break;

		case REG_NUM_R12:
			guest_context->r12 = reg_value;
			break;

		case REG_NUM_R13:
			guest_context->r13 = reg_value;
			break;

		case REG_NUM_R14:
			guest_context->r14 = reg_value;
			break;

		case REG_NUM_R15:
			guest_context->r15 = reg_value;
			break;
	}
}

/*
 * Calculate destination memory address from instruction information in guest
 * context.
 */
static u64 sb_calc_dest_mem_addr(struct sb_vm_exit_guest_register* guest_context,
	u64 inst_info)
{
	u64 dest_addr = 0;

	if (!(inst_info & VM_INST_INFO_IDX_REG_INVALID))
	{
		dest_addr += sb_get_reg_value_from_index(guest_context,
			VM_INST_INFO_IDX_REG(inst_info));
		dest_addr = dest_addr << VM_INST_INFO_SCALE(inst_info);
	}

	if (!(inst_info & VM_INST_INFO_BASE_REG_INVALID))
	{
		dest_addr += sb_get_reg_value_from_index(guest_context,
			VM_INST_INFO_BASE_REG(inst_info));
	}

	return dest_addr;
}

/*
 * Set value to memory.
 */
static void sb_set_value_to_memory(u64 inst_info, u64 addr, u64 value)
{
	switch(VM_INST_INFO_ADDR_SIZE(inst_info))
	{
		case VM_INST_INFO_ADDR_SIZE_16BIT:
			*(u16*)addr = (u16)value;
			break;

		case VM_INST_INFO_ADDR_SIZE_32BIT:
			*(u32*)addr = (u64)value;
			break;

		case VM_INST_INFO_ADDR_SIZE_64BIT:
			*(u64*)addr = (u64)value;
			break;
	}
}

/**
 * Get value from memory.
 */
static u64 sb_get_value_from_memory(u64 inst_info, u64 addr)
{
	u64 value = 0;

	switch(VM_INST_INFO_ADDR_SIZE(inst_info))
	{
		case VM_INST_INFO_ADDR_SIZE_16BIT:
			value = *(u16*)addr;
			break;

		case VM_INST_INFO_ADDR_SIZE_32BIT:
			value = *(u32*)addr;
			break;

		case VM_INST_INFO_ADDR_SIZE_64BIT:
			value = *(u64*)addr;
			break;
	}

	return value;
}

/*
 * Process VM call.
 */
static void sb_vm_exit_callback_vmcall(int cpu_id, struct sb_vm_exit_guest_register*
	guest_context)
{
	u64 svr_num;
	void* arg;

	svr_num = guest_context->rax;
	arg = (void*)guest_context->rbx;

	/* Set return value. */
	guest_context->rax = 0;

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] VMCALL index[%ld], arg_in[%016lX]\n",
		cpu_id, svr_num, arg);

	/* Move RIP to next instruction. */
	sb_advance_vm_guest_rip();

	switch(svr_num)
	{
		/* Return log info structure. */
		case VM_SERVICE_GET_LOGINFO:
			guest_context->rax = 0;
			break;

#if SHADOWBOX_USE_SHUTDOWN
		case VM_SERVICE_SHUTDOWN:
			atomic_set(&(g_share_context->shutdown_flag), 1);
			break;

		case VM_SERVICE_SHUTDOWN_THIS_CORE:
			sb_shutdown_vm_this_core(cpu_id, guest_context);
			break;
#endif /* SHADOWBOX_USE_SHUTDOWN */

		default:
			sb_advance_vm_guest_rip();
			break;
	}
}

#if SHADOWBOX_USE_SHUTDOWN
/**
 *	Shutdown Shadow-box
 */
static void sb_shutdown_vm_this_core(int cpu_id, struct sb_vm_exit_guest_register*
	guest_context)
{
	struct sb_vm_full_context full_context;
	u64 guest_VMCS_log_addr;
	u64 guest_VMCS_phy_addr;
	u64 guest_rsp;

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] sb_shutdown_vm_this_core is called\n",
		cpu_id);

	sb_read_vmcs(VM_GUEST_RSP, &guest_rsp);
	sb_fill_context_from_vm_guest(guest_context, &full_context);

	guest_VMCS_log_addr = (u64)(g_guest_vmcs_log_addr[cpu_id]);
	guest_VMCS_phy_addr = (u64)virt_to_phys((void*)guest_VMCS_log_addr);
	sb_clear_vmcs(&guest_VMCS_phy_addr);
	sb_stop_vmx();

#if SHADOWBOX_USE_TBOOT
	/* For tboot interoperation, VMX is disabled by tboot. */
	if (tboot == NULL)
	{
		sb_disable_vmx();
	}
#else
	sb_disable_vmx();
#endif /* SHADOWBOX_USE_TBOOT */

	sb_restore_context_from_vm_guest(cpu_id, &full_context, guest_rsp);
}

/*
 * Fill guest context from the guest VMCS.
 */
static void sb_fill_context_from_vm_guest(struct sb_vm_exit_guest_register*
	guest_context, struct sb_vm_full_context* full_context)
{
	memcpy(&(full_context->gp_register), guest_context,
		sizeof(struct sb_vm_exit_guest_register));

	sb_read_vmcs(VM_GUEST_CS_SELECTOR, &(full_context->cs_selector));
	sb_read_vmcs(VM_GUEST_DS_SELECTOR, &(full_context->ds_selector));
	sb_read_vmcs(VM_GUEST_ES_SELECTOR, &(full_context->es_selector));
	sb_read_vmcs(VM_GUEST_FS_SELECTOR, &(full_context->fs_selector));
	sb_read_vmcs(VM_GUEST_GS_SELECTOR, &(full_context->gs_selector));

	sb_read_vmcs(VM_GUEST_LDTR_SELECTOR, &(full_context->ldtr_selector));
	sb_read_vmcs(VM_GUEST_TR_SELECTOR, &(full_context->tr_selector));

	sb_read_vmcs(VM_GUEST_CR0, &(full_context->cr0));
	sb_read_vmcs(VM_GUEST_CR3, &(full_context->cr3));
	sb_read_vmcs(VM_GUEST_CR4, &(full_context->cr4));
	sb_read_vmcs(VM_GUEST_RIP, &(full_context->rip));
	sb_read_vmcs(VM_GUEST_RFLAGS, &(full_context->rflags));
}

/*
 * Restore the guest VMCS from the full context.
 * When Shadow-box is shutdown, return to sb_vm_call() function in the guest.
 */
static void sb_restore_context_from_vm_guest(int cpu_id, struct sb_vm_full_context*
	full_context, u64 guest_rsp)
{
	u64 target_addr;

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] guest_rsp %016lX\n", cpu_id,
		guest_rsp);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] cr4 %016lX, %016lX\n", cpu_id,
		full_context->cr4, sb_get_cr4());
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] cr3 %016lX, %016lX\n", cpu_id,
		full_context->cr3, sb_get_cr3());
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] cr0 %016lX, %016lX\n", cpu_id,
		full_context->cr0, sb_get_cr0());

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] tr %016lX\n", cpu_id,
		full_context->tr_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] ldtr %016lX\n", cpu_id,
		full_context->ldtr_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] gs %016lX\n", cpu_id,
		full_context->gs_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] fs %016lX\n", cpu_id,
		full_context->fs_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] es %016lX\n", cpu_id,
		full_context->es_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] ds %016lX\n", cpu_id,
		full_context->ds_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] cs %016lX\n", cpu_id,
		full_context->cs_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] r15 %016lX\n", cpu_id,
		full_context->gp_register.r15);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] rbp %016lX\n", cpu_id,
		full_context->gp_register.rbp);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] rflags %016lX, %016lX\n", cpu_id,
		full_context->rflags, sb_get_rflags());
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] rip %016lX, %016lX\n", cpu_id,
		full_context->rip, sb_vm_thread_shutdown);

	/* Copy context to stack and restore */
	target_addr = guest_rsp - sizeof(struct sb_vm_full_context);
	memcpy((void*)target_addr, full_context, sizeof(struct sb_vm_full_context));

	sb_restore_context_from_stack(target_addr);
}

/*
 * Process system reboot notify event.
 */
static int sb_system_reboot_notify(struct notifier_block *nb, unsigned long code,
	void *unused)
{
	int cpu_count;

	/* Call Shadow-box shutdown function */
	sb_vm_call(VM_SERVICE_SHUTDOWN, NULL);

	cpu_count = num_online_cpus();
	sb_printf(LOG_LEVEL_NONE, LOG_INFO "Shutdown start, cpu count %d\n", cpu_count);

	while(1)
	{
		if (atomic_read(&(g_share_context->shutdown_complete_count)) == cpu_count)
		{
			break;
		}

		ssleep(1);
	}

	return NOTIFY_DONE;
}

/*
 * Disable VT-x and terminate Shadow-box.
 * This thread function runs on each core.
 */
static int sb_vm_thread_shutdown(void* argument)
{
	int cpu_id;

	cpu_id = smp_processor_id();

	while(atomic_read(&(g_share_context->shutdown_flag)) == 0)
	{
		ssleep(1);
	}

	sb_vm_call(VM_SERVICE_SHUTDOWN_THIS_CORE, NULL);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Shutdown complete\n", cpu_id);

	atomic_inc(&(g_share_context->shutdown_complete_count));
	return 0;
}

#endif /* SHADOWBOX_USE_SHUTDOWN */

/*
 * Insert exception to the guest.
 */
void sb_insert_exception_to_vm(void)
{
	u64 info_field;
	sb_read_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, &info_field);

	//info_field = VM_BIT_VM_ENTRY_INT_INFO_GP;
	info_field = VM_BIT_VM_ENTRY_INT_INFO_UD;

	sb_write_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, info_field);
	sb_write_vmcs(VM_CTRL_VM_ENTRY_EXCEPT_ERR_CODE, 0);
}

/*
 * Remove INT1 exception from the guest.
 */
static void sb_remove_int_exception_from_vm(int vector)
{
	u64 info_field;

	sb_read_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, &info_field);
	info_field &= ~((u64) 0x01 << vector);
	sb_write_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, info_field);
}

/*
 * Process write MSR callback.
 */
static void sb_vm_exit_callback_wrmsr(int cpu_id)
{
	sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] sb_vm_exit_callback_wrmsr\n", cpu_id);
	sb_insert_exception_to_vm();
}

/*
 * Process GDTR, IDTR modification callback.
 */
static void sb_vm_exit_callback_gdtr_idtr(int cpu_id, struct sb_vm_exit_guest_register*
	guest_context)
{
	if (sb_is_system_shutdowning() == 0)
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] ===================WARNING======================\n",
			cpu_id);
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] sb_vm_exit_callback_gdtr_idtr\n",
			cpu_id);
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] ===================WARNING======================\n",
			cpu_id);

		sb_advance_vm_guest_rip();
	}
	else
	{
		sb_disable_desc_monitor();
	}
}

/*
 * Process LDTR, TR modification callback.
 * Linux set 0 to LLDT, so this function allows only 0 value setting.
 */
static void sb_vm_exit_callback_ldtr_tr(int cpu_id, struct sb_vm_exit_guest_register*
	guest_context)
{
	u64 inst_info;
	u64 dest_addr = 0;
	u64 value;
	int memory = 0;

	sb_read_vmcs(VM_DATA_VM_EXIT_INST_INFO, &inst_info);

	/* Check destination type. */
	if (!VM_INST_INFO_MEM_REG(inst_info))
	{
		dest_addr = sb_calc_dest_mem_addr(guest_context, inst_info);
		memory = 1;
	}
	else
	{
		dest_addr = sb_get_reg_value_from_index(guest_context,
			VM_INST_INFO_REG1(inst_info));
	}

	switch(VM_INST_INFO_INST_IDENTITY(inst_info))
	{
		// SLDT
		case VM_INST_INFO_SLDT:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] SLDT is not allowed\n",
				cpu_id);
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] sb_vm_exit_callback_ldtr_tr"
				" SLDT\n", cpu_id);
			value = sb_get_ldtr();
			if (memory == 1)
			{
				sb_set_value_to_memory(inst_info, dest_addr, value);
			}
			else
			{
				sb_set_reg_value_from_index(guest_context, (inst_info >> 3) & 0xF,
					value);
			}
			break;

		// STR
		case VM_INST_INFO_STR:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] STR is not allowed\n",
				cpu_id);
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] sb_vm_exit_callback_ldtr_tr "
				"STR\n", cpu_id);
			sb_insert_exception_to_vm();
			break;

		// LLDT
		case VM_INST_INFO_LLDT:
			if (memory == 1)
			{
				sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Memory, value[%016lX]\n",
					cpu_id, dest_addr);
				sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] sb_vm_exit_callback_ldtr_tr "
					"LLDT 1\n", cpu_id);
				sb_insert_exception_to_vm();

				value = sb_get_value_from_memory(inst_info, dest_addr);
				sb_write_vmcs(VM_GUEST_LDTR_SELECTOR, value);
			}
			else
			{
				if (dest_addr == 0)
				{
					sb_write_vmcs(VM_GUEST_LDTR_SELECTOR, dest_addr);
				}
				else
				{
					sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] LLDT Value is not 0, "
						"%016lX\n", cpu_id, dest_addr);
					sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] sb_vm_exit_callback_"
						"ldtr_tr LLDT 2\n", cpu_id);
					sb_insert_exception_to_vm();
				}
			}
			break;

		// LTR
		case VM_INST_INFO_LTR:
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] LTR is not allowed\n",
				cpu_id);
			sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] sb_vm_exit_callback_ldtr_tr "
				"LTR\n", cpu_id);
			sb_insert_exception_to_vm();
			break;
	}

	sb_advance_vm_guest_rip();
}

/*
 * Process EPT violation.
 */
static void sb_vm_exit_callback_ept_violation(int cpu_id, struct sb_vm_exit_guest_register*
	guest_context, u64 exit_reason, u64 exit_qual, u64 guest_linear, u64 guest_physical)
{
	u64 log_addr;
	u64 cr0;

	sb_printf(LOG_LEVEL_NONE, LOG_ERROR "VM [%d] Memory attack is detected, "
		"guest linear=%016lX guest physical=%016X virt_to_phys=%016lX\n",
		cpu_id, guest_linear, guest_physical, virt_to_phys((void*)guest_linear));

	if (sb_is_system_shutdowning() == 0)
	{
		/* If the address is in workaround area, set all permission to the page */
		if (sb_is_workaround_addr(guest_physical) == 1)
		{
			sb_set_ept_all_access_page(guest_physical);
			sb_printf(LOG_LEVEL_NONE,
				LOG_ERROR "VM [%d] === %016lX is Workaround Address ===\n\n",
				cpu_id, guest_physical);
		}
		else
		{
			/* Insert exception to the guest */
			sb_insert_exception_to_vm();
			sb_read_vmcs(VM_GUEST_CR0, &cr0);

			/* If malware turns WP bit off, recover it again */
			if ((cr0 & CR0_BIT_PG) && !(cr0 & CR0_BIT_WP))
			{
				sb_write_vmcs(VM_GUEST_CR0, cr0 | CR0_BIT_WP);
			}

			sb_error_log(ERROR_KERNEL_MODIFICATION);
		}
	}
	else
	{
		log_addr = (u64)phys_to_virt(guest_physical);
		if (sb_is_addr_in_kernel_ro_area((void*)log_addr) == 0)
		{
			sb_set_ept_all_access_page(guest_physical);
		}
	}
}

/*
 * Process CPUID callback.
 */
static void sb_vm_exit_callback_cpuid(struct sb_vm_exit_guest_register* guest_context)
{
	cpuid_count(guest_context->rax, guest_context->rcx, (u32*)&guest_context->rax, (u32*)&guest_context->rbx,
		(u32*)&guest_context->rcx, (u32*)&guest_context->rdx);

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM_EXIT_REASON_CPUID Result: %08X, %08X, %08X, %08X\n",
		(u32)guest_context->rax, (u32) guest_context->rbx, (u32)guest_context->rcx, (u32)guest_context->rdx);

	sb_advance_vm_guest_rip();
}

/*
 * Process INVD callback.
 */
static void sb_vm_exit_callback_invd(void)
{
	sb_invd();
	sb_advance_vm_guest_rip();
}

/*
 * Process VT-timer expire callback.
 */
static void sb_vm_exit_callback_pre_timer_expired(int cpu_id)
{
	u64 value;

	if (sb_is_system_shutdowning() == 0)
	{
#if SHADOWBOX_USE_DESC_TABLE
		/* Check gdtr. */
		if (sb_check_gdtr(cpu_id) == -1)
		{
			sb_printf(LOG_LEVEL_NONE, LOG_ERROR "VM [%d] GDTR or IDTR attack is detected\n", cpu_id);
			sb_error_log(ERROR_KERNEL_MODIFICATION);
		}

		/* Call the function of Shadow-watcher. */
		sb_sw_callback_vm_timer(cpu_id);
#endif
	}

	/* Reset VM timer. */
	value = sb_calc_vm_pre_timer_value();
	sb_write_vmcs(VM_GUEST_VMX_PRE_TIMER_VALUE, value);
}

/*
 * Setup the host registers.
 */
static void sb_setup_vm_host_register(struct sb_vm_host_register* sb_vm_host_register)
{
	struct desc_ptr gdtr;
	struct desc_ptr idtr;
	struct desc_struct* gdt;
	struct ldttss_desc64* tss;
	u64 base0 = 0;
	u64 base1 = 0;
	u64 base2 = 0;
	u64 base3 = 0;
	int i;
	char* vm_exit_stack;
	u64 stack_size = g_stack_size;
	int cpu_id;

	cpu_id = smp_processor_id();

	/* Allocate kernel stack for VM exit */
	vm_exit_stack = (char*)(g_vm_exit_stack_addr[cpu_id]);
	memset(vm_exit_stack, 0, stack_size);

	native_store_gdt(&gdtr);
	native_store_idt(&idtr);

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup Host Register\n", cpu_id);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDTR Address %016lX\n",
		gdtr.address);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDTR Size %d\n", gdtr.size);

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IDTR Address %016lX\n",
		idtr.address);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IDTR Size %d\n", idtr.size);

	for (i = 0 ; i < (gdtr.size + 7) / 8 ; i++)
	{
		gdt = (struct desc_struct*)(gdtr.address + i * 8);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDT Index %d\n", i);
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDT High %08X, Low %08X\n",
			gdt->b, gdt->a);
	}

	sb_vm_host_register->cr0 = sb_get_cr0();

	/* Using Shadow CR3 for world separation in host. */
	sb_vm_host_register->cr3 = g_vm_host_phy_pml4;
	sb_vm_host_register->cr4 = sb_get_cr4();

	sb_vm_host_register->rsp = (u64)vm_exit_stack + stack_size - 0x1000;
	sb_vm_host_register->rip = (u64)sb_vm_exit_callback_stub;

	sb_vm_host_register->cs_selector = __KERNEL_CS;
	sb_vm_host_register->ss_selector = __KERNEL_DS;
	sb_vm_host_register->ds_selector = __KERNEL_DS;
	sb_vm_host_register->es_selector = __KERNEL_DS;
	sb_vm_host_register->fs_selector = __KERNEL_DS;
	sb_vm_host_register->gs_selector = __KERNEL_DS;
	sb_vm_host_register->tr_selector = sb_get_tr();

	sb_vm_host_register->fs_base_addr = sb_rdmsr(MSR_FS_BASE_ADDR);
	sb_vm_host_register->gs_base_addr = sb_rdmsr(MSR_GS_BASE_ADDR);

	tss = (struct ldttss_desc64*)(gdtr.address +
		(sb_vm_host_register->tr_selector & ~MASK_GDT_ACCESS));
	base0 = tss->base0;
	base1 = tss->base1;
	base2 = tss->base2;
	base3 = tss->base3;
	sb_vm_host_register->tr_base_addr = base0 | (base1 << 16) | (base2 << 24) |
		(base3 << 32);

	sb_vm_host_register->gdtr_base_addr = gdtr.address;
	sb_vm_host_register->idtr_base_addr = idtr.address;

	sb_vm_host_register->ia32_sys_enter_cs = sb_rdmsr(MSR_IA32_SYSENTER_CS);
	sb_vm_host_register->ia32_sys_enter_esp = sb_rdmsr(MSR_IA32_SYSENTER_ESP);
	sb_vm_host_register->ia32_sys_enter_eip = sb_rdmsr(MSR_IA32_SYSENTER_EIP);

	sb_vm_host_register->ia32_perf_global_ctrl = sb_rdmsr(MSR_IA32_PERF_GLOBAL_CTRL);
	sb_vm_host_register->ia32_pat = sb_rdmsr(MSR_IA32_PAT);
	sb_vm_host_register->ia32_efer = sb_rdmsr(MSR_IA32_EFER);

	sb_dump_vm_host_register(sb_vm_host_register);
}

/*
 * Setup the guest register.
 */
static void sb_setup_vm_guest_register(struct sb_vm_guest_register*
	sb_vm_guest_register, const struct sb_vm_host_register* sb_vm_host_register)
{
	struct desc_ptr gdtr;
	struct desc_ptr idtr;
	struct desc_struct* gdt;
	struct ldttss_desc64* ldt;
	struct ldttss_desc64* tss;
	u64 base0 = 0;
	u64 base1 = 0;
	u64 base2 = 0;
	u64 base3 = 0;
	u64 access = 0;
	u64 qwLimit0 = 0;
	u64 qwLimit1 = 0;
	int cpu_id;
#if SHADOWBOX_USE_HW_BREAKPOINT
	unsigned long dr6;
#endif
	unsigned long dr7 = 0;
	cpu_id = smp_processor_id();

	native_store_gdt(&gdtr);
	native_store_idt(&idtr);

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup Guest Register\n", cpu_id);

	sb_vm_guest_register->cr0 = sb_vm_host_register->cr0;
	sb_vm_guest_register->cr3 = sb_get_cr3();
	sb_vm_guest_register->cr4 = sb_vm_host_register->cr4;

#if SHADOWBOX_USE_HW_BREAKPOINT
	set_debugreg(sb_get_symbol_address("wake_up_new_task"), 0);
	set_debugreg(sb_get_symbol_address("proc_flush_task"), 1);
	set_debugreg(sb_get_symbol_address("ftrace_module_init"), 2);
	set_debugreg(sb_get_symbol_address("free_module"), 3);

	dr7 = sb_encode_dr7(0, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= sb_encode_dr7(1, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= sb_encode_dr7(2, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= sb_encode_dr7(3, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= (0x01 << 10);

	sb_vm_guest_register->dr7 = dr7;
	get_debugreg(dr6, 6);
	dr6 &= 0xfffffffffffffff0;
	set_debugreg(dr6, 6);
#else
	sb_vm_guest_register->dr7 = sb_get_dr7();
#endif
	get_debugreg(dr7, 6);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "ORG DB6 = %lx", dr7);
	get_debugreg(dr7, 7);
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "ORG DB7 = %lx", sb_vm_guest_register->dr7);

	sb_vm_guest_register->rflags = sb_get_rflags();
	/* Under two registers are set when VM launch. */
	sb_vm_guest_register->rsp = 0xFFFFFFFFFFFFFFFF;
	sb_vm_guest_register->rip = 0xFFFFFFFFFFFFFFFF;

	sb_vm_guest_register->cs_selector = sb_get_cs();
	sb_vm_guest_register->ss_selector = sb_get_ss();
	sb_vm_guest_register->ds_selector = sb_get_ds();
	sb_vm_guest_register->es_selector = sb_get_es();
	sb_vm_guest_register->fs_selector = sb_get_fs();
	sb_vm_guest_register->gs_selector = sb_get_gs();
	sb_vm_guest_register->ldtr_selector = sb_get_ldtr();
	sb_vm_guest_register->tr_selector = sb_get_tr();

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "LDTR Selector %08X\n",
		(u32)sb_vm_guest_register->ldtr_selector);

	sb_vm_guest_register->cs_base_addr =
		sb_get_desc_base(sb_vm_guest_register->cs_selector);
	sb_vm_guest_register->ss_base_addr =
		sb_get_desc_base(sb_vm_guest_register->ss_selector);
	sb_vm_guest_register->ds_base_addr =
		sb_get_desc_base(sb_vm_guest_register->ds_selector);
	sb_vm_guest_register->es_base_addr =
		sb_get_desc_base(sb_vm_guest_register->es_selector);
	sb_vm_guest_register->fs_base_addr = sb_rdmsr(MSR_FS_BASE_ADDR);
	sb_vm_guest_register->gs_base_addr = sb_rdmsr(MSR_GS_BASE_ADDR);

	if (sb_vm_guest_register->ldtr_selector == 0)
	{
		sb_vm_guest_register->ldtr_base_addr = 0;
	}
	else
	{
		ldt = (struct ldttss_desc64*)(gdtr.address +
			(sb_vm_guest_register->ldtr_selector & ~MASK_GDT_ACCESS));
		base0 = ldt->base0;
		base1 = ldt->base1;
		base2 = ldt->base2;
		base3 = ldt->base3;
		sb_vm_guest_register->ldtr_base_addr = base0 | (base1 << 16) |
			(base2 << 24) | (base3 << 32);
	}

	if (sb_vm_guest_register->tr_selector == 0)
	{
		sb_vm_guest_register->tr_base_addr = 0x00;
	}
	else
	{
		tss = (struct ldttss_desc64*)(gdtr.address +
			(sb_vm_guest_register->tr_selector & ~MASK_GDT_ACCESS));
		base0 = tss->base0;
		base1 = tss->base1;
		base2 = tss->base2;
		base3 = tss->base3;
		sb_vm_guest_register->tr_base_addr = base0 | (base1 << 16) |
			(base2 << 24) | (base3 << 32);
	}

	sb_vm_guest_register->cs_limit = 0xFFFFFFFF;
	sb_vm_guest_register->ss_limit = 0xFFFFFFFF;
	sb_vm_guest_register->ds_limit = 0xFFFFFFFF;
	sb_vm_guest_register->es_limit = 0xFFFFFFFF;
	sb_vm_guest_register->fs_limit = 0xFFFFFFFF;
	sb_vm_guest_register->gs_limit = 0xFFFFFFFF;

	if (sb_vm_guest_register->ldtr_selector == 0)
	{
		sb_vm_guest_register->ldtr_limit = 0;
	}
	else
	{
		ldt = (struct ldttss_desc64*)(gdtr.address +
			(sb_vm_guest_register->ldtr_selector & ~MASK_GDT_ACCESS));
		qwLimit0 = ldt->limit0;
		qwLimit1 = ldt->limit1;
		sb_vm_guest_register->ldtr_limit = qwLimit0 | (qwLimit1 << 16);
	}

	if (sb_vm_guest_register->tr_selector == 0)
	{
		sb_vm_guest_register->tr_limit = 0;
	}
	else
	{
		tss = (struct ldttss_desc64*)(gdtr.address +
			(sb_vm_guest_register->tr_selector & ~MASK_GDT_ACCESS));
		qwLimit0 = tss->limit0;
		qwLimit1 = tss->limit1;
		sb_vm_guest_register->tr_limit = qwLimit0 | (qwLimit1 << 16);
	}

	sb_vm_guest_register->cs_access =
		sb_get_desc_access(sb_vm_guest_register->cs_selector);
	sb_vm_guest_register->ss_access =
		sb_get_desc_access(sb_vm_guest_register->ss_selector);
	sb_vm_guest_register->ds_access =
		sb_get_desc_access(sb_vm_guest_register->ds_selector);
	sb_vm_guest_register->es_access =
		sb_get_desc_access(sb_vm_guest_register->es_selector);
	sb_vm_guest_register->fs_access =
		sb_get_desc_access(sb_vm_guest_register->fs_selector);
	sb_vm_guest_register->gs_access =
		sb_get_desc_access(sb_vm_guest_register->gs_selector);

	if (sb_vm_guest_register->ldtr_selector == 0)
	{
		sb_vm_guest_register->ldtr_access = 0x10000;
	}
	else
	{
		ldt = (struct ldttss_desc64*)(gdtr.address +
			(sb_vm_guest_register->ldtr_selector & ~MASK_GDT_ACCESS));
		gdt = (struct desc_struct*)ldt;
		access = gdt->b >> 8;

		/* type: 4, s: 1, dpl: 2, p: 1; limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8 */
		sb_vm_guest_register->ldtr_access = access & 0xF0FF;
	}

	if (sb_vm_guest_register->tr_selector == 0)
	{
		sb_vm_guest_register->tr_access = 0;
	}
	else
	{
		tss = (struct ldttss_desc64*)(gdtr.address +
			(sb_vm_guest_register->tr_selector & ~MASK_GDT_ACCESS));
		gdt = (struct desc_struct*)tss;
		access = gdt->b >> 8;

		/* type: 4, s: 1, dpl: 2, p: 1; limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8 */
		sb_vm_guest_register->tr_access = access & 0xF0FF;
	}

	sb_vm_guest_register->gdtr_base_addr = sb_vm_host_register->gdtr_base_addr;
	sb_vm_guest_register->idtr_base_addr = sb_vm_host_register->idtr_base_addr;
	sb_vm_guest_register->gdtr_limit = gdtr.size;
	sb_vm_guest_register->idtr_limit = idtr.size;

	sb_vm_guest_register->ia32_debug_ctrl = 0;
	sb_vm_guest_register->ia32_sys_enter_cs = sb_vm_host_register->ia32_sys_enter_cs;
	sb_vm_guest_register->ia32_sys_enter_esp = sb_vm_host_register->ia32_sys_enter_esp;
	sb_vm_guest_register->ia32_sys_enter_eip = sb_vm_host_register->ia32_sys_enter_eip;
	sb_vm_guest_register->vmcs_link_ptr = 0xFFFFFFFFFFFFFFFF;

	sb_vm_guest_register->ia32_perf_global_ctrl =
		sb_vm_host_register->ia32_perf_global_ctrl;
	sb_vm_guest_register->ia32_pat = sb_vm_host_register->ia32_pat;
	sb_vm_guest_register->ia32_efer = sb_vm_host_register->ia32_efer;

	sb_dump_vm_guest_register(sb_vm_guest_register);
}

/*
 * Set MSR write bitmap to get a VM exit event of modification.
 */
static void sb_vm_set_msr_write_bitmap(struct sb_vm_control_register*
	sb_vm_control_register, u64 msr_number)
{
	u64 byte_offset;
	u64 bit_offset;
	u64 bitmap_add = 2048;

	byte_offset = (msr_number & 0xFFFFFFF) / 8;
	bit_offset = (msr_number & 0xFFFFFFF) % 8;

	if (msr_number >= 0xC0000000)
	{
		bitmap_add += 1024;
	}

	((u8*)sb_vm_control_register->msr_bitmap_addr)[bitmap_add + byte_offset] =
		((u8*)sb_vm_control_register->msr_bitmap_addr)[bitmap_add + byte_offset] |
		(0x01 << bit_offset);
}


/*
 * Set VM control register.
 */
static void sb_setup_vm_control_register(struct sb_vm_control_register*
	sb_vm_control_register, int cpu_id)
{
	u64 sec_flags = 0;
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup VM Control Register\n", cpu_id);

#if SHADOWBOX_USE_DESC_TABLE
	sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_DESC_TABLE;
#endif

#if SHADOWBOX_USE_EPT
#if SHADOWBOX_USE_UNRESTRICTED
	sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_UNREST_GUEST;
#endif

	sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_USE_EPT;
#endif

	if ((sb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) &
		VM_BIT_VM_SEC_PROC_CTRL_ENABLE_INVPCID)
	{
		sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Support Enable INVPCID\n",
			cpu_id);
		sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_ENABLE_INVPCID;
	}

	if (g_support_xsave == 1)
	{
		if ((sb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) &
			VM_BIT_VM_SEC_PROC_CTRL_ENABLE_XSAVE)
		{
			sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Support Enable XSAVE\n",
				cpu_id);
			sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_ENABLE_XSAVE;
		}
	}

#if SHADOWBOX_USE_VPID
	if ((sb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) &
		VM_BIT_VM_SEC_PROC_CTRL_ENABLE_VPID)
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "VM [%d] Support Enable VPID\n",
			cpu_id);
		sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_ENABLE_VPID;
	}
#endif

#if SHADOWBOX_USE_PRE_TIMER
	sb_vm_control_register->pin_based_ctrl =
		(sb_rdmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS) | VM_BIT_VM_PIN_BASED_USE_PRE_TIMER) &
		0xFFFFFFFF;
#else
	sb_vm_control_register->pin_based_ctrl = (sb_rdmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS)) &
		0xFFFFFFFF;
#endif

	sb_vm_control_register->pri_proc_based_ctrl =
		(sb_rdmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS) | VM_BIT_VM_PRI_PROC_CTRL_USE_IO_BITMAP |
		VM_BIT_VM_PRI_PROC_CTRL_USE_MSR_BITMAP | VM_BIT_VM_PRI_PROC_CTRL_USE_SEC_CTRL |
		VM_BIT_VM_PRI_PROC_CTRL_USE_MOVE_DR) & 0xFFFFFFFF;

	g_vm_pri_proc_based_ctrl_default = sb_vm_control_register->pri_proc_based_ctrl;
	sb_vm_control_register->sec_proc_based_ctrl =
		(sb_rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) | sec_flags) & 0xFFFFFFFF;

	sb_vm_control_register->vm_entry_ctrl_field =
		(sb_rdmsr(MSR_IA32_VMX_TRUE_ENTRY_CTRLS) | VM_BIT_VM_ENTRY_CTRL_IA32E_MODE_GUEST |
		VM_BIT_VM_ENTRY_LOAD_DEBUG_CTRL) & 0xFFFFFFFF;

#if SHADOWBOX_USE_PRE_TIMER
	sb_vm_control_register->vm_exti_ctrl_field = (sb_rdmsr(MSR_IA32_VMX_TRUE_EXIT_CTRLS) |
		VM_BIT_VM_EXIT_CTRL_HOST_ADDR_SIZE | VM_BIT_VM_EXIT_SAVE_DEBUG_CTRL |
		VM_BIT_VM_EXIT_CTRL_SAVE_PRE_TIMER | VM_BIT_VM_EXIT_CTRL_SAVE_IA32_EFER) &
		0xFFFFFFFF;
#else
	sb_vm_control_register->vm_exti_ctrl_field = (sb_rdmsr(MSR_IA32_VMX_TRUE_EXIT_CTRLS) |
		VM_BIT_VM_EXIT_CTRL_HOST_ADDR_SIZE | VM_BIT_VM_EXIT_SAVE_DEBUG_CTRL |
		VM_BIT_VM_EXIT_CTRL_SAVE_IA32_EFER) & 0xFFFFFFFF;
#endif

#if SHADOWBOX_USE_HW_BREAKPOINT
	sb_vm_control_register->except_bitmap = ((u64)0x01 << VM_INT_DEBUG_EXCEPTION);
#else
	sb_vm_control_register->except_bitmap = 0x00;
#endif

	sb_vm_control_register->io_bitmap_addrA = (u64)(g_io_bitmap_addrA[cpu_id]);
	sb_vm_control_register->io_bitmap_addrB = (u64)(g_io_bitmap_addrB[cpu_id]);
	sb_vm_control_register->msr_bitmap_addr = (u64)(g_msr_bitmap_addr[cpu_id]);
	sb_vm_control_register->virt_apic_page_addr = (u64)(g_virt_apic_page_addr[cpu_id]);

	memset((char*)sb_vm_control_register->io_bitmap_addrA, 0, 0x1000);
	memset((char*)sb_vm_control_register->io_bitmap_addrB, 0, 0x1000);
	memset((char*)sb_vm_control_register->msr_bitmap_addr, 0, 0x1000);
	memset((char*)sb_vm_control_register->virt_apic_page_addr, 0, 0x1000);

	/* Registers related SYSENTER, SYSCALL MSR are write-protected. */
	sb_vm_set_msr_write_bitmap(sb_vm_control_register, MSR_IA32_SYSENTER_CS);
	sb_vm_set_msr_write_bitmap(sb_vm_control_register, MSR_IA32_SYSENTER_ESP);
	sb_vm_set_msr_write_bitmap(sb_vm_control_register, MSR_IA32_SYSENTER_EIP);
	sb_vm_set_msr_write_bitmap(sb_vm_control_register, MSR_IA32_STAR);
	sb_vm_set_msr_write_bitmap(sb_vm_control_register, MSR_IA32_LSTAR);
	sb_vm_set_msr_write_bitmap(sb_vm_control_register, MSR_IA32_FMASK);

	sb_vm_control_register->io_bitmap_addrA =
		(u64)virt_to_phys((void*)sb_vm_control_register->io_bitmap_addrA);
	sb_vm_control_register->io_bitmap_addrB =
		(u64)virt_to_phys((void*)sb_vm_control_register->io_bitmap_addrB);
	sb_vm_control_register->msr_bitmap_addr =
		(u64)virt_to_phys((void*)sb_vm_control_register->msr_bitmap_addr);
	sb_vm_control_register->virt_apic_page_addr =
		(u64)virt_to_phys((void*)sb_vm_control_register->virt_apic_page_addr);

#if SHADOWBOX_USE_EPT
	sb_vm_control_register->ept_ptr =
		(u64)virt_to_phys((void*)g_ept_info.pml4_page_addr_array[0]) |
		VM_BIT_EPT_PAGE_WALK_LENGTH_BITMAP | VM_BIT_EPT_MEM_TYPE_WB;
#endif

	sb_vm_control_register->cr4_guest_host_mask = CR4_BIT_VMXE;
	sb_vm_control_register->cr4_read_shadow = CR4_BIT_VMXE;

	sb_dump_vm_control_register(sb_vm_control_register);
}

/*
 * Setup VMCS.
 */
static void sb_setup_vmcs(const struct sb_vm_host_register* sb_vm_host_register,
	const struct sb_vm_guest_register* sb_vm_guest_register,
	const struct sb_vm_control_register* sb_vm_control_register)
{
	int result;
	int cpu_id;
	u64 value;

	cpu_id = smp_processor_id();

	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup VMCS\n", cpu_id);

	/* Setup host information. */
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Set Host Register\n");
	result = sb_write_vmcs(VM_HOST_CR0, sb_vm_host_register->cr0);
	sb_print_vm_result("    [*] CR0", result);
	result = sb_write_vmcs(VM_HOST_CR3, sb_vm_host_register->cr3);
	sb_print_vm_result("    [*] CR3", result);
	result = sb_write_vmcs(VM_HOST_CR4, sb_vm_host_register->cr4);
	sb_print_vm_result("    [*] CR4", result);
	result = sb_write_vmcs(VM_HOST_RSP, sb_vm_host_register->rsp);
	sb_print_vm_result("    [*] RSP", result);
	result = sb_write_vmcs(VM_HOST_RIP, sb_vm_host_register->rip);
	sb_print_vm_result("    [*] RIP", result);
	result = sb_write_vmcs(VM_HOST_CS_SELECTOR, sb_vm_host_register->cs_selector);
	sb_print_vm_result("    [*] CS Selector", result);
	result = sb_write_vmcs(VM_HOST_SS_SELECTOR, sb_vm_host_register->ss_selector);
	sb_print_vm_result("    [*] SS Selector", result);
	result = sb_write_vmcs(VM_HOST_DS_SELECTOR, sb_vm_host_register->ds_selector);
	sb_print_vm_result("    [*] DS Selector", result);
	result = sb_write_vmcs(VM_HOST_ES_SELECTOR, sb_vm_host_register->es_selector);
	sb_print_vm_result("    [*] ES Selector", result);
	result = sb_write_vmcs(VM_HOST_FS_SELECTOR, sb_vm_host_register->fs_selector);
	sb_print_vm_result("    [*] FS Selector", result);
	result = sb_write_vmcs(VM_HOST_GS_SELECTOR, sb_vm_host_register->gs_selector);
	sb_print_vm_result("    [*] GS Selector", result);
	result = sb_write_vmcs(VM_HOST_TR_SELECTOR, sb_vm_host_register->tr_selector);
	sb_print_vm_result("    [*] TR Selector", result);

	result = sb_write_vmcs(VM_HOST_FS_BASE, sb_vm_host_register->fs_base_addr);
	sb_print_vm_result("    [*] FS Base", result);
	result = sb_write_vmcs(VM_HOST_GS_BASE, sb_vm_host_register->gs_base_addr);
	sb_print_vm_result("    [*] GS Base", result);
	result = sb_write_vmcs(VM_HOST_TR_BASE, sb_vm_host_register->tr_base_addr);
	sb_print_vm_result("    [*] TR Base", result);
	result = sb_write_vmcs(VM_HOST_GDTR_BASE, sb_vm_host_register->gdtr_base_addr);
	sb_print_vm_result("    [*] GDTR Base", result);
	result = sb_write_vmcs(VM_HOST_IDTR_BASE, sb_vm_host_register->idtr_base_addr);
	sb_print_vm_result("    [*] IDTR Base", result);

	result = sb_write_vmcs(VM_HOST_IA32_SYSENTER_CS,
		sb_vm_host_register->ia32_sys_enter_cs);
	sb_print_vm_result("    [*] SYSENTER_CS Base", result);
	result = sb_write_vmcs(VM_HOST_IA32_SYSENTER_ESP,
		sb_vm_host_register->ia32_sys_enter_esp);
	sb_print_vm_result("    [*] SYSENTER_ESP", result);
	result = sb_write_vmcs(VM_HOST_IA32_SYSENTER_EIP,
		sb_vm_host_register->ia32_sys_enter_eip);
	sb_print_vm_result("    [*] SYSENTER_EIP", result);
	result = sb_write_vmcs(VM_HOST_PERF_GLOBAL_CTRL,
		sb_vm_host_register->ia32_perf_global_ctrl);
	sb_print_vm_result("    [*] Perf Global Ctrl", result);
	result = sb_write_vmcs(VM_HOST_PAT, sb_vm_host_register->ia32_pat);
	sb_print_vm_result("    [*] PAT", result);
	result = sb_write_vmcs(VM_HOST_EFER, sb_vm_host_register->ia32_efer);
	sb_print_vm_result("    [*] EFER", result);

	/* Setup guest information. */
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Set Guest Register\n");
	result = sb_write_vmcs(VM_GUEST_CR0, sb_vm_guest_register->cr0);
	sb_print_vm_result("    [*] CR0", result);
	result = sb_write_vmcs(VM_GUEST_CR3, sb_vm_guest_register->cr3);
	sb_print_vm_result("    [*] CR3", result);
	result = sb_write_vmcs(VM_GUEST_CR4, sb_vm_guest_register->cr4);
	sb_print_vm_result("    [*] CR4", result);
	result = sb_write_vmcs(VM_GUEST_DR7, sb_vm_guest_register->dr7);
	sb_print_vm_result("    [*] DR7", result);
	result = sb_write_vmcs(VM_GUEST_RSP, sb_vm_guest_register->rsp);
	sb_print_vm_result("    [*] RSP", result);
	result = sb_write_vmcs(VM_GUEST_RIP, sb_vm_guest_register->rip);
	sb_print_vm_result("    [*] RIP", result);
	result = sb_write_vmcs(VM_GUEST_RFLAGS, sb_vm_guest_register->rflags);
	sb_print_vm_result("    [*] RFLAGS", result);
	result = sb_write_vmcs(VM_GUEST_CS_SELECTOR, sb_vm_guest_register->cs_selector);
	sb_print_vm_result("    [*] CS Selector", result);
	result = sb_write_vmcs(VM_GUEST_SS_SELECTOR, sb_vm_guest_register->ss_selector);
	sb_print_vm_result("    [*] SS Selector", result);
	result = sb_write_vmcs(VM_GUEST_DS_SELECTOR, sb_vm_guest_register->ds_selector);
	sb_print_vm_result("    [*] DS Selector", result);
	result = sb_write_vmcs(VM_GUEST_ES_SELECTOR, sb_vm_guest_register->es_selector);
	sb_print_vm_result("    [*] ES Selector", result);
	result = sb_write_vmcs(VM_GUEST_FS_SELECTOR, sb_vm_guest_register->fs_selector);
	sb_print_vm_result("    [*] FS Selector", result);
	result = sb_write_vmcs(VM_GUEST_GS_SELECTOR, sb_vm_guest_register->gs_selector);
	sb_print_vm_result("    [*] GS Selector", result);
	result = sb_write_vmcs(VM_GUEST_LDTR_SELECTOR, sb_vm_guest_register->ldtr_selector);
	sb_print_vm_result("    [*] LDTR Selector", result);
	result = sb_write_vmcs(VM_GUEST_TR_SELECTOR, sb_vm_guest_register->tr_selector);
	sb_print_vm_result("    [*] TR Selector", result);

	result = sb_write_vmcs(VM_GUEST_CS_BASE, sb_vm_guest_register->cs_base_addr);
	sb_print_vm_result("    [*] CS Base", result);
	result = sb_write_vmcs(VM_GUEST_SS_BASE, sb_vm_guest_register->ss_base_addr);
	sb_print_vm_result("    [*] SS Base", result);
	result = sb_write_vmcs(VM_GUEST_DS_BASE, sb_vm_guest_register->ds_base_addr);
	sb_print_vm_result("    [*] DS Base", result);
	result = sb_write_vmcs(VM_GUEST_ES_BASE, sb_vm_guest_register->es_base_addr);
	sb_print_vm_result("    [*] ES Base", result);
	result = sb_write_vmcs(VM_GUEST_FS_BASE, sb_vm_guest_register->fs_base_addr);
	sb_print_vm_result("    [*] FS Base", result);
	result = sb_write_vmcs(VM_GUEST_GS_BASE, sb_vm_guest_register->gs_base_addr);
	sb_print_vm_result("    [*] GS Base", result);
	result = sb_write_vmcs(VM_GUEST_LDTR_BASE, sb_vm_guest_register->ldtr_base_addr);
	sb_print_vm_result("    [*] LDTR Base", result);
	result = sb_write_vmcs(VM_GUEST_TR_BASE, sb_vm_guest_register->tr_base_addr);
	sb_print_vm_result("    [*] TR Base", result);

	result = sb_write_vmcs(VM_GUEST_CS_LIMIT, sb_vm_guest_register->cs_limit);
	sb_print_vm_result("    [*] CS Limit", result);
	result = sb_write_vmcs(VM_GUEST_SS_LIMIT, sb_vm_guest_register->ss_limit);
	sb_print_vm_result("    [*] SS Limit", result);
	result = sb_write_vmcs(VM_GUEST_DS_LIMIT, sb_vm_guest_register->ds_limit);
	sb_print_vm_result("    [*] DS Limit", result);
	result = sb_write_vmcs(VM_GUEST_ES_LIMIT, sb_vm_guest_register->es_limit);
	sb_print_vm_result("    [*] ES Limit", result);
	result = sb_write_vmcs(VM_GUEST_FS_LIMIT, sb_vm_guest_register->fs_limit);
	sb_print_vm_result("    [*] FS Limit", result);
	result = sb_write_vmcs(VM_GUEST_GS_LIMIT, sb_vm_guest_register->gs_limit);
	sb_print_vm_result("    [*] GS Limit", result);
	result = sb_write_vmcs(VM_GUEST_LDTR_LIMIT, sb_vm_guest_register->ldtr_limit);
	sb_print_vm_result("    [*] LDTR Limit", result);
	result = sb_write_vmcs(VM_GUEST_TR_LIMIT, sb_vm_guest_register->tr_limit);
	sb_print_vm_result("    [*] TR Limit", result);

	result = sb_write_vmcs(VM_GUEST_CS_ACC_RIGHT, sb_vm_guest_register->cs_access);
	sb_print_vm_result("    [*] CS Access", result);
	result = sb_write_vmcs(VM_GUEST_SS_ACC_RIGHT, sb_vm_guest_register->ss_access);
	sb_print_vm_result("    [*] SS Access", result);
	result = sb_write_vmcs(VM_GUEST_DS_ACC_RIGHT, sb_vm_guest_register->ds_access);
	sb_print_vm_result("    [*] DS Access", result);
	result = sb_write_vmcs(VM_GUEST_ES_ACC_RIGHT, sb_vm_guest_register->es_access);
	sb_print_vm_result("    [*] ES Access", result);
	result = sb_write_vmcs(VM_GUEST_FS_ACC_RIGHT, sb_vm_guest_register->fs_access);
	sb_print_vm_result("    [*] FS Access", result);
	result = sb_write_vmcs(VM_GUEST_GS_ACC_RIGHT, sb_vm_guest_register->gs_access);
	sb_print_vm_result("    [*] GS Access", result);
	result = sb_write_vmcs(VM_GUEST_LDTR_ACC_RIGHT, sb_vm_guest_register->ldtr_access);
	sb_print_vm_result("    [*] LDTR Access", result);
	result = sb_write_vmcs(VM_GUEST_TR_ACC_RIGHT, sb_vm_guest_register->tr_access);
	sb_print_vm_result("    [*] TR Access", result);

	result = sb_write_vmcs(VM_GUEST_GDTR_BASE, sb_vm_guest_register->gdtr_base_addr);
	sb_print_vm_result("    [*] GDTR Base", result);
	result = sb_write_vmcs(VM_GUEST_IDTR_BASE, sb_vm_guest_register->idtr_base_addr);
	sb_print_vm_result("    [*] IDTR Base", result);
	result = sb_write_vmcs(VM_GUEST_GDTR_LIMIT, sb_vm_guest_register->gdtr_limit);
	sb_print_vm_result("    [*] GDTR Base", result);
	result = sb_write_vmcs(VM_GUEST_IDTR_LIMIT, sb_vm_guest_register->idtr_limit);
	sb_print_vm_result("    [*] IDTR Base", result);

	result = sb_write_vmcs(VM_GUEST_DEBUGCTL, sb_vm_guest_register->ia32_debug_ctrl);
	sb_print_vm_result("    [*] DEBUG CONTROL", result);
	result = sb_write_vmcs(VM_GUEST_IA32_SYSENTER_CS,
		sb_vm_guest_register->ia32_sys_enter_cs);
	sb_print_vm_result("    [*] SYSENTER_CS Base", result);
	result = sb_write_vmcs(VM_GUEST_IA32_SYSENTER_ESP,
		sb_vm_guest_register->ia32_sys_enter_esp);
	sb_print_vm_result("    [*] SYSENTER_ESP", result);
	result = sb_write_vmcs(VM_GUEST_IA32_SYSENTER_EIP,
		sb_vm_guest_register->ia32_sys_enter_eip);
	sb_print_vm_result("    [*] SYSENTER_EIP", result);
	result = sb_write_vmcs(VM_GUEST_PERF_GLOBAL_CTRL,
		sb_vm_guest_register->ia32_perf_global_ctrl);
	sb_print_vm_result("    [*] Perf Global Ctrl", result);
	result = sb_write_vmcs(VM_GUEST_PAT, sb_vm_guest_register->ia32_pat);
	sb_print_vm_result("    [*] PAT", result);
	result = sb_write_vmcs(VM_GUEST_EFER, sb_vm_guest_register->ia32_efer);
	sb_print_vm_result("    [*] EFER", result);

	result = sb_write_vmcs(VM_VMCS_LINK_PTR, sb_vm_guest_register->vmcs_link_ptr);
	sb_print_vm_result("    [*] VMCS Link ptr", result);

	result = sb_write_vmcs(VM_GUEST_INT_STATE, 0);
	sb_print_vm_result("    [*] Guest Int State", result);

	result = sb_write_vmcs(VM_GUEST_ACTIVITY_STATE, 0);
	sb_print_vm_result("    [*] Guest Activity State", result);

	result = sb_write_vmcs(VM_GUEST_SMBASE, 0);
	sb_print_vm_result("    [*] Guest SMBase", result);

	result = sb_write_vmcs(VM_GUEST_PENDING_DBG_EXCEPTS, 0);
	sb_print_vm_result("    [*] Pending DBG Excepts", result);

	value = sb_calc_vm_pre_timer_value();
	result = sb_write_vmcs(VM_GUEST_VMX_PRE_TIMER_VALUE, value);
	sb_print_vm_result("    [*] VM Preemption Timer", result);

	/* Setup VM control information. */
	sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Set VM Control Register\n");
#if SHADOWBOX_USE_VPID
	result = sb_write_vmcs(VM_CTRL_VIRTUAL_PROCESS_ID, 1);
	sb_print_vm_result("    [*] VIRTUAL_PROCESS_ID", result);
#endif
	result = sb_write_vmcs(VM_CTRL_PIN_BASED_VM_EXE_CTRL,
		sb_vm_control_register->pin_based_ctrl);
	sb_print_vm_result("    [*] PIN Based Ctrl", result);
	result = sb_write_vmcs(VM_CTRL_PRI_PROC_BASED_EXE_CTRL,
		sb_vm_control_register->pri_proc_based_ctrl);
	sb_print_vm_result("    [*] Primary Process Based Ctrl", result);
	result = sb_write_vmcs(VM_CTRL_SEC_PROC_BASED_EXE_CTRL,
		sb_vm_control_register->sec_proc_based_ctrl);
	sb_print_vm_result("    [*] Secondary Process Based Ctrl", result);
	result = sb_write_vmcs(VM_CTRL_EXCEPTION_BITMAP,
		sb_vm_control_register->except_bitmap);
	sb_print_vm_result("    [*] Exception Bitmap", result);
	result = sb_write_vmcs(VM_CTRL_IO_BITMAP_A_ADDR,
		sb_vm_control_register->io_bitmap_addrA);
	sb_print_vm_result("    [*] IO Bitmap A", result);
	result = sb_write_vmcs(VM_CTRL_IO_BITMAP_B_ADDR,
		sb_vm_control_register->io_bitmap_addrB);
	sb_print_vm_result("    [*] IO Bitmap B", result);
	result = sb_write_vmcs(VM_CTRL_EPT_PTR, sb_vm_control_register->ept_ptr);
	sb_print_vm_result("    [*] EPT Ptr", result);
	result = sb_write_vmcs(VM_CTRL_MSR_BITMAPS,
		sb_vm_control_register->msr_bitmap_addr);
	sb_print_vm_result("    [*] MSR Bitmap", result);
	result = sb_write_vmcs(VM_CTRL_VM_ENTRY_CTRLS,
		sb_vm_control_register->vm_entry_ctrl_field);
	sb_print_vm_result("    [*] VM Entry Control", result);
	result = sb_write_vmcs(VM_CTRL_VM_EXIT_CTRLS,
		sb_vm_control_register->vm_exti_ctrl_field);
	sb_print_vm_result("    [*] VM Exit Control", result);
	result = sb_write_vmcs(VM_CTRL_VIRTUAL_APIC_ADDR,
		sb_vm_control_register->virt_apic_page_addr);
	sb_print_vm_result("    [*] Virtual APIC Page", result);
	result = sb_write_vmcs(VM_CTRL_CR0_GUEST_HOST_MASK, 0);
	sb_print_vm_result("    [*] CR0 Guest Host Mask", result);
	result = sb_write_vmcs(VM_CTRL_CR4_GUEST_HOST_MASK,
		sb_vm_control_register->cr4_guest_host_mask);
	sb_print_vm_result("    [*] CR4 Guest Host Mask", result);
	result = sb_write_vmcs(VM_CTRL_CR0_READ_SHADOW, 0);
	sb_print_vm_result("    [*] CR0 Read Shadow", result);
	result = sb_write_vmcs(VM_CTRL_CR4_READ_SHADOW,
		sb_vm_control_register->cr4_read_shadow);
	sb_print_vm_result("    [*] CR4 Read Shadow", result);
	result = sb_write_vmcs(VM_CTRL_CR3_TARGET_VALUE_0, 0);
	sb_print_vm_result("    [*] CR3 Target Value 0", result);
	result = sb_write_vmcs(VM_CTRL_CR3_TARGET_VALUE_1, 0);
	sb_print_vm_result("    [*] CR3 Target Value 1", result);
	result = sb_write_vmcs(VM_CTRL_CR3_TARGET_VALUE_2, 0);
	sb_print_vm_result("    [*] CR3 Target Value 2", result);
	result = sb_write_vmcs(VM_CTRL_CR3_TARGET_VALUE_3, 0);
	sb_print_vm_result("    [*] CR3 Target Value 3", result);

	result = sb_write_vmcs(VM_CTRL_PAGE_FAULT_ERR_CODE_MASK, 0);
	sb_print_vm_result("    [*] Page Fault Error Code Mask", result);
	result = sb_write_vmcs(VM_CTRL_PAGE_FAULT_ERR_CODE_MATCH, 0);
	sb_print_vm_result("    [*] Page Fault Error Code Match", result);
	result = sb_write_vmcs(VM_CTRL_CR3_TARGET_COUNT, 0);
	sb_print_vm_result("    [*] CR3 Target Count", result);
	result = sb_write_vmcs(VM_CTRL_VM_EXIT_MSR_STORE_COUNT, 0);
	sb_print_vm_result("    [*] MSR Store Count", result);
	result = sb_write_vmcs(VM_CTRL_VM_EXIT_MSR_LOAD_COUNT, 0);
	sb_print_vm_result("    [*] MSR Load Count", result);
	result = sb_write_vmcs(VM_CTRL_VM_EXIT_MSR_LOAD_ADDR, 0);
	sb_print_vm_result("    [*] MSR Load Addr", result);
	result = sb_write_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, 0);
	sb_print_vm_result("    [*] VM Entry Int Info Field", result);
	result = sb_write_vmcs(VM_CTRL_VM_ENTRY_EXCEPT_ERR_CODE, 0);
	sb_print_vm_result("    [*] VM Entry Except Err Code", result);
	result = sb_write_vmcs(VM_CTRL_VM_ENTRY_INST_LENGTH, 0);
	sb_print_vm_result("    [*] VM Entry Inst Length", result);
	result = sb_write_vmcs(VM_CTRL_VM_ENTRY_MSR_LOAD_COUNT, 0);
	sb_print_vm_result("    [*] VM Entry MSR Load Count", result);
	result = sb_write_vmcs(VM_CTRL_VM_ENTRY_MSR_LOAD_ADDR, 0);
	sb_print_vm_result("    [*] VM Entry MSR Load Addr", result);

	result = sb_write_vmcs(VM_CTRL_TPR_THRESHOLD, 0);
	sb_print_vm_result("    [*] TPR Threashold", result);
	result = sb_write_vmcs(VM_CTRL_EXECUTIVE_VMCS_PTR, 0);
	sb_print_vm_result("    [*] Executive VMCS Ptr", result);
	result = sb_write_vmcs(VM_CTRL_TSC_OFFSET, 0);
	sb_print_vm_result("    [*] TSC Offset", result);
}

/*
 * Print message with result.
 */
static void sb_print_vm_result(const char* string, int result)
{
	return ;
	if (result == 1)
	{
		sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "%s Success\n", string);
	}
	else
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "%s Fail\n", string);
	}
}

/*
 * Dump the host register information.
 */
static void sb_dump_vm_host_register(struct sb_vm_host_register* host_register)
{
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Dump Host Register\n");
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR0 %016lX\n", host_register->cr0);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR3 %016lX\n", host_register->cr3);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR4 %016lX\n", host_register->cr4);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RSP %016lX\n", host_register->rsp);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RIP %016lX\n", host_register->rip);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Selector %08X\n",
		host_register->cs_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Selector %08X\n",
		host_register->ss_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Selector %08X\n",
		host_register->ds_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Selector %08X\n",
		host_register->es_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Selector %08X\n",
		host_register->fs_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Selector %08X\n",
		host_register->gs_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Selector %08X\n",
		host_register->tr_selector);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Base     %016lX\n",
		host_register->fs_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Base     %016lX\n",
		host_register->gs_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Base     %016lX\n",
		host_register->tr_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GDTR Base   %016lX\n",
		host_register->gdtr_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IDTR Base   %016lX\n",
		host_register->idtr_base_addr);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER CS  %016lX\n",
		host_register->ia32_sys_enter_cs);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER ESP %016lX\n",
		host_register->ia32_sys_enter_esp);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER EIP %016lX\n",
		host_register->ia32_sys_enter_eip);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 Perf Global Ctrl %016lX\n",
		host_register->ia32_perf_global_ctrl);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 PAT              %016lX\n",
		host_register->ia32_pat);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 IA32 EFER        %016lX\n",
		host_register->ia32_efer);
}

/*
 * Dump the guest register information.
 */
static void sb_dump_vm_guest_register(struct sb_vm_guest_register* guest_register)
{
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Dump Guest Register\n");
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR0 %016lX\n", guest_register->cr0);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR3 %016lX\n", guest_register->cr3);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR4 %016lX\n", guest_register->cr4);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DR7 %016lX\n", guest_register->dr7);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RSP %016lX\n", guest_register->rsp);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RIP %016lX\n", guest_register->rip);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RFLAGS %016lX\n", guest_register->rflags);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Selector %08X\n",
		(u32)guest_register->cs_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Selector %08X\n",
		(u32)guest_register->ss_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Selector %08X\n",
		(u32)guest_register->ds_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Selector %08X\n",
		(u32)guest_register->es_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Selector %08X\n",
		(u32)guest_register->fs_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Selector %08X\n",
		(u32)guest_register->gs_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Selector %08X\n",
		(u32)guest_register->ldtr_selector);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Selector %08X\n",
		(u32)guest_register->tr_selector);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Base     %016lX\n",
		guest_register->cs_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Base     %016lX\n",
		guest_register->ss_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Base     %016lX\n",
		guest_register->ds_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Base     %016lX\n",
		guest_register->es_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Base     %016lX\n",
		guest_register->fs_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Base     %016lX\n",
		guest_register->gs_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Base   %016lX\n",
		guest_register->ldtr_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Base     %016lX\n",
		guest_register->tr_base_addr);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Limit    %08X\n",
		(u32)guest_register->cs_limit);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Limit    %08X\n",
		(u32)guest_register->ss_limit);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Limit    %08X\n",
		(u32)guest_register->ds_limit);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Limit    %08X\n",
		(u32)guest_register->es_limit);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Limit    %08X\n",
		(u32)guest_register->fs_limit);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Limit    %08X\n",
		(u32)guest_register->gs_limit);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Limit  %08X\n",
		(u32)guest_register->ldtr_limit);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Limit    %08X\n",
		(u32)guest_register->tr_limit);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Access   %08X\n",
		(u32)guest_register->cs_access);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Access   %08X\n",
		(u32)guest_register->ss_access);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Access   %08X\n",
		(u32)guest_register->ds_access);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Access   %08X\n",
		(u32)guest_register->es_access);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Access   %08X\n",
		(u32)guest_register->fs_access);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Access   %08X\n",
		(u32)guest_register->gs_access);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Access %08X\n",
		(u32)guest_register->ldtr_access);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Access   %08X\n",
		(u32)guest_register->tr_access);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GDTR Base   %016lX\n",
		guest_register->gdtr_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IDTR Base   %016lX\n",
		guest_register->idtr_base_addr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GDTR Limit  %08X\n",
		(u32)guest_register->gdtr_limit);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IDTR Limit  %08X\n",
		(u32)guest_register->idtr_limit);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 DEBUG CTRL   %016lX\n",
		guest_register->ia32_debug_ctrl);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER CS  %016lX\n",
		guest_register->ia32_sys_enter_cs);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER ESP %016lX\n",
		guest_register->ia32_sys_enter_esp);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER EIP %016lX\n",
		guest_register->ia32_sys_enter_eip);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VCMS Link Ptr     %016lX\n",
		guest_register->vmcs_link_ptr);

	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 Perf Global Ctrl %016lX\n",
		guest_register->ia32_perf_global_ctrl);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 PAT              %016lX\n",
		guest_register->ia32_pat);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 IA32 EFER        %016lX\n",
		guest_register->ia32_efer);
}

/*
 * Dump VM control register information.
 */
static void sb_dump_vm_control_register(struct sb_vm_control_register* control_register)
{
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Dump Control Register\n");
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Pin Based Ctrl %016lX\n", control_register->pin_based_ctrl);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Primary Process Based Ctrl %016lX\n", control_register->pri_proc_based_ctrl);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Secondary Process Based Ctrl %016lX\n", control_register->sec_proc_based_ctrl);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM Entry Ctrl %016lX\n", control_register->vm_entry_ctrl_field);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM Exit Ctrl %016lX\n", control_register->vm_exti_ctrl_field);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Exception Bitmap %016lX\n", control_register->except_bitmap);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IO Bitmap AddrA %016lX\n", control_register->io_bitmap_addrA);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IO Bitmap AddrB %016lX\n", control_register->io_bitmap_addrB);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] EPT Pointer %016lX\n", control_register->ept_ptr);
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] MSRBitmap %016lX\n", control_register->msr_bitmap_addr);
}


/*
 * Get base address of the descriptor.
 */
static u64 sb_get_desc_base(u64 offset)
{
	struct desc_ptr gdtr;
	struct desc_struct* gdt;
	u64 qwTotalBase = 0;
	u64 base0 = 0;
	u64 base1 = 0;
	u64 base2 = 0;

	if (offset == 0)
	{
		return 0;
	}

	native_store_gdt(&gdtr);
	gdt = (struct desc_struct*)(gdtr.address + (offset & ~MASK_GDT_ACCESS));

	base0 = gdt->base0;
	base1 = gdt->base1;
	base2 = gdt->base2;

	qwTotalBase = base0 | (base1 << 16) | (base2 << 24);
	return qwTotalBase;
}

/*
 * Get access type of the descriptor.
 */
static u64 sb_get_desc_access(u64 offset)
{
	struct desc_ptr gdtr;
	struct desc_struct* gdt;
	u64 total_access = 0;
	u64 access = 0;

	if (offset == 0)
	{
		/* Return unused value. */
		return 0x10000;
	}

	native_store_gdt(&gdtr);
	gdt = (struct desc_struct*)(gdtr.address + (offset & ~MASK_GDT_ACCESS));
	access = gdt->b >> 8;

	/* type: 4, s: 1, dpl: 2, p: 1; limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8 */
	total_access = access & 0xF0FF;
	return total_access;
}

/*
 * Add read-only area (static kernel objects) information with the type.
 */
void sb_add_ro_area(u64 start, u64 end, u64 ro_type)
{
	g_ro_array[g_ro_array_count].start = start;
	g_ro_array[g_ro_array_count].end = end;
	g_ro_array[g_ro_array_count].type = ro_type;
	g_ro_array_count++;
}

/*
 * Delete read-only area (static kernel objects) information with the type.
 */
void sb_delete_ro_area(u64 start, u64 end)
{
	int i;

	for (i = 0 ; i < g_ro_array_count ; i++)
	{
		if ((g_ro_array[g_ro_array_count].start == start) &&
		    (g_ro_array[g_ro_array_count].end == end))
		{
			g_ro_array[g_ro_array_count].start = 0;
			g_ro_array[g_ro_array_count].end = 0;
			break;
		}
	}
}

/*
 * Check if the address is in read-only area.
 */
int sb_is_addr_in_ro_area(void* addr)
{
	int i;

	/* Allow NULL pointer. */
	if (addr == NULL)
	{
		return 1;
	}

	for (i = 0 ; i < g_ro_array_count ; i++)
	{
		if ((g_ro_array[i].start <= (u64)addr) &&
			((u64)addr < (g_ro_array[i].end)))
		{
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "%p is in core area\n", addr);
			return 1;
		}
	}

	//sb_printf(LOG_LEVEL_NONE, LOG_ERROR "%p is not in code area\n", addr);

	return 0;
}

/*
 * Check if the address is in kernel read-only area.
 */
int sb_is_addr_in_kernel_ro_area(void* addr)
{
	int i;

	/* Allow NULL pointer. */
	if (addr == NULL)
	{
		return 1;
	}

	for (i = 0 ; i < g_ro_array_count ; i++)
	{
		if ((g_ro_array[i].start <= (u64)addr) &&
			((u64)addr < (g_ro_array[i].end)) &&
			(g_ro_array[i].type == RO_KERNEL))
		{
			sb_printf(LOG_LEVEL_DETAIL, LOG_INFO "%p is in core area\n", addr);
			return 1;
		}

		if (g_ro_array[i].type == RO_MODULE)
		{
			break;
		}
	}

	return 0;
}


/*
 * Get function pointers for periodic check.
 */
static void sb_get_function_pointers(void)
{
	sb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Get function pointers\n");

	g_modules_ptr = (struct list_head*)sb_get_symbol_address("modules");

	g_root_file_ptr = filp_open("/", O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(g_root_file_ptr))
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "/ Open VFS Object Fail\n");
	}

	g_proc_file_ptr = filp_open("/proc", O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(g_proc_file_ptr))
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "/proc Open VFS Object Fail\n");
	}

	g_tcp_file_ptr = filp_open("/proc/net/tcp", O_RDONLY, 0);
	if (IS_ERR(g_tcp_file_ptr))
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "/proc/net/tcp Open VFS Object Fail\n");
	}

	g_udp_file_ptr = filp_open("/proc/net/udp", O_RDONLY, 0);
	if (IS_ERR(g_udp_file_ptr))
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "/proc/net/udp Open VFS Object Fail\n");
	}

	g_tcp6_file_ptr = filp_open("/proc/net/tcp6", O_RDONLY, 0);
	if (IS_ERR(g_tcp6_file_ptr))
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "/proc/net/tcp6 Open VFS Object Fail\n");
	}

	g_udp6_file_ptr = filp_open("/proc/net/udp6", O_RDONLY, 0);
	if (IS_ERR(g_udp6_file_ptr))
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "/proc/net/udp6 Open VFS Object Fail\n");
	}

	if (sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &g_udp_sock) < 0)
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "UDP Socket Object Open Fail\n");
	}

	if (sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &g_tcp_sock) < 0)
	{
		sb_printf(LOG_LEVEL_NONE, LOG_INFO "TCP Socket Object Open Fail\n");
	}
}

module_init(shadow_box_init);
module_exit(shadow_box_exit);

MODULE_AUTHOR("Seunghun Han");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("Shadow-box: Lightweight Hypervisor-based Kernel Protector.");
