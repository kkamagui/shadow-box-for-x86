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
#ifndef __ASM_H__
#define __ASM_H__

/*
 * Functions.
 */
extern void sb_enable_vmx(void);
extern void sb_disable_vmx(void);
extern u64 sb_get_cpuid(void);
extern u64 sb_get_cr0(void);
extern void sb_set_cr0(u64 cr0);
extern u64 sb_get_cr2(void);
extern u64 sb_get_cr3(void);
extern void sb_set_cr3(u64);
extern u64 sb_get_cr4(void);
extern u64 sb_get_cr8(void);
extern u64 sb_get_cs(void);
extern u64 sb_get_ss(void);
extern u64 sb_get_ds(void);
extern u64 sb_get_es(void);
extern u64 sb_get_fs(void);
extern u64 sb_get_gs(void);
extern u64 sb_get_tr(void);
extern u64 sb_get_dr7(void);
extern u64 sb_get_rflags(void);
extern u64 sb_get_ldtr(void);
extern void sb_set_cr4(u64 cr4);
extern int sb_start_vmx(void* vmcs);
extern int sb_clear_vmcs(void* guest_vmcs);
extern int sb_load_vmcs(void** guest_vmcs);
extern int sb_write_vmcs(u64 reg_index, u64 value);
extern int sb_read_vmcs(u64 reg_index, u64* value);
extern void sb_stop_vmx(void);
extern u64 sb_rdmsr(u64 msr_index);
extern void sb_wrmsr(u64 msr_index, u64 value);
extern int sb_vm_launch(void);
extern int sb_vm_resume(void);
extern u64 sb_get_rip(void);
extern u64 sb_calc_vm_exit_callback_addr(u64 error);
extern void sb_vm_exit_callback_stub(void);
extern void sb_invd(void);
extern void sb_flush_gdtr(void);
extern void sb_gen_int(u64 number);
extern void sb_pause_loop(void);
extern void* sb_vm_call(u64 svr_num, void* arg);
extern void sb_restore_context_from_stack(u64 stack_addr);

#endif
