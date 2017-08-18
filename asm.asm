;
;                          Shadow-Box
;                         ------------
;      Lightweight Hypervisor-Based Kernel Protector
;
;               Copyright (C) 2017 Seunghun Han
;     at National Security Research Institute of South Korea
;

; This software has dual license (MIT and GPL v2). See the GPL_LICENSE and
; MIT_LICENSE file.

[bits 64]
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Exported functions.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
global sb_enable_vmx
global sb_disable_vmx
global sb_start_vmx
global sb_clear_vmcs
global sb_load_vmcs
global sb_read_vmcs
global sb_write_vmcs
global sb_stop_vmx
global sb_get_cr0
global sb_set_cr0
global sb_get_cr2
global sb_get_cr3
global sb_set_cr3
global sb_get_cr4
global sb_set_cr4
global sb_get_cr8
global sb_get_cs
global sb_get_ss
global sb_get_ds
global sb_get_es
global sb_get_fs
global sb_get_gs
global sb_get_tr
global sb_get_dr7
global sb_get_rflags
global sb_get_ldtr
global sb_rdmsr
global sb_wrmsr
global sb_vm_launch
global sb_resume
global sb_calc_vm_exit_callback_addr
global sb_vm_exit_callback_stub
global sb_invd
global sb_flush_gdtr
global sb_gen_int
global sb_pause_loop
global sb_vm_call
global sb_restore_context_from_stack

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Imported functions.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
extern sb_vm_exit_callback
extern sb_vm_resume_fail_callback

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%macro PUSHAQ 0
	push rbp
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
%endmacro

%macro POPAQ 0
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	pop rbp
%endmacro

; Enable VMX.
sb_enable_vmx:
	mov rax, cr4
	bts rax, 13
	mov cr4, rax
	ret

; Disable VMX.
sb_disable_vmx:
	mov rax, cr4
	btc rax, 13
	mov cr4, rax
	ret

; Start VMX.
sb_start_vmx:
	;call disable_A20
	vmxon [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	;call enable_A20
	ret

; Clear VMCS.
sb_clear_vmcs:
	vmclear [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Load VMCS.
sb_load_vmcs:
	vmptrld [rdi]
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Write data to VMCS.
sb_write_vmcs:
	vmwrite rdi, rsi
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Read data from VMCS.
sb_read_vmcs:
	vmread [rsi], rdi
	jc .error
	jz .error

	mov rax, 0
	jmp .end

.error:
	mov rax, -1
.end:
	ret

; Stop VMX.
sb_stop_vmx:
	vmxoff
	ret

; Get CR0.
sb_get_cr0:
	mov rax, cr0
	ret

; Set CR0.
sb_set_cr0:
	mov cr0, rdi
	ret

; Get CR2.
sb_get_cr2:
	mov rax, cr2
	ret

; Get CR3.
sb_get_cr3:
	mov rax, cr3
	ret

; Set CR3.
sb_set_cr3:
	mov cr3, rdi
	ret

; Get CR4.
sb_get_cr4:
	mov rax, cr4
	ret

; Set CR4.
sb_set_cr4:
	mov cr4, rdi
	ret

; Get CR8.
sb_get_cr8:
	mov rax, cr8
	ret

; Get CS.
sb_get_cs:
	mov rax, cs
	ret

; Get SS.
sb_get_ss:
	mov rax, ss
	ret

; Get DS.
sb_get_ds:
	mov rax, ds
	ret

; Get ES.
sb_get_es:
	mov rax, es
	ret

; Get FS.
sb_get_fs:
	mov rax, fs
	ret

; Get GS.
sb_get_gs:
	mov rax, gs
	ret

; Get TR.
sb_get_tr:
	str rax
	ret

; Get DR7.
sb_get_dr7:
	mov rax, dr7
	ret

; Get RFLAGS.
sb_get_rflags:
	pushfq
	pop rax
	ret

; Get LDTR.
sb_get_ldtr:
	sldt rax
	ret

; Read MSR.
sb_rdmsr:
	push rdx
	push rcx

	xor rdx, rdx
	xor rax, rax

	mov ecx, edi
	rdmsr

	shl rdx, 32
	or rax, rdx

	pop rcx
	pop rdx
	ret

; Write MSR.
sb_wrmsr:
	push rdx
	push rcx

	mov rdx, rsi
	shr rdx, 32
	mov eax, esi

	mov ecx, edi
	wrmsr

	pop rcx
	pop rdx
	ret

; Launch VM.
sb_vm_launch:
	push rbx

	; For seamless interoperation, set RSP of the guest to the host.
	mov rbx, 0x681C		; RSP
	mov rax, rsp
	vmwrite rbx, rax
	
	; Get current RIP.
	call .get_rip
.get_rip:
	pop rax
	
	mov rbx, 0x681E		; RIP
	add rax, (.success - .get_rip)
	vmwrite rbx, rax

	vmlaunch

	; Process fail.
	pop rbx

	jc .errorInvalid
	jz .errorValid

	mov rax, 0
	jmp .end

.errorInvalid:
	mov rax, -1
	jmp .end

.errorValid:
	mov rax, -2

.end:
	ret

.success:
	; Start line of the guest.
	; Now the core is in the guest.
	pop rbx
	mov rax, 0
	ret

; Stub of VM exit callback.
;
; When VM exit occur, RFLAGS is cleared except bit 1.
sb_vm_exit_callback_stub:
	; Start line of the host.
	; Now the core is in the host.
	PUSHAQ
	
	; RDI has the pointer of the guest context structure.
	mov rdi, rsp

	call sb_vm_exit_callback
	
	; Resume the guest.
	POPAQ
	vmresume

	; Error occur.
	mov rdi, rax
	call sb_vm_resume_fail_callback

.hang:
	jmp .hang
	ret

; Resume VM.
sb_vm_resume:
	vmresume

	jc .errorInvalid
	jz .errorValid

	mov rax, 0
	jmp .end

.errorInvalid:
	mov rax, -1
	jmp .end

.errorValid:
	mov rax, -2

.end:
	ret

.success:
	; Start line of the guest.
	; Now the core is in the guest.
	mov rax, 0
	ret

; Get current RIP.
sb_get_rip:
	pop rax
	push rax
	ret

; Process INVD.
sb_invd:
	invd
	ret

; Flush GDTR.
sb_flush_gdtr:
	push rax

	mov ax, ss
	mov ss, ax

	pop rax
	ret

; Generate interrupt 0xF8.
sb_gen_int:
	push rax
	mov rax, rdi
	sti
	int 0xf8
	pop rax
	ret

; Pause CPU.
sb_pause_loop:
	pause
	ret

; Call vmcall.
;	VMcall argument:
;		rax: service number
;		rbx: argument
;	Result:
;		rax: return value
sb_vm_call:
	push rbx

	mov rax, rdi
	mov rbx, rsi

	vmcall

	pop rbx
	ret

; Restore context from stack(vm_full_context).
sb_restore_context_from_stack:
	mov rsp, rdi
	
	pop rax			; cr4
	;mov cr4, rax

	pop rax			; cr3
	mov cr3, rax

	pop rax			; cr0
	;mov cr0, rax

	pop rax			; tr
	;ltr ax

	pop rax			; lldt
	;lldt ax

	pop rax			; gs
	;mov gs, ax

	pop rax			; fs
	mov fs, ax

	pop rax			; es
	mov es, ax

	pop rax			; ds
	mov ds, ax

	pop rax			; cs
	;ignore cs

	POPAQ			; Restore GP register.
	popfq			; Restore RFLAGS.

	ret				; Return to RIP.
