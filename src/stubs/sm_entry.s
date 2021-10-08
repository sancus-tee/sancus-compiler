    .section ".sm.text"
    .align 2
    .global __sm_entry
    .type __sm_entry,@function

    ; r6: ID of entry point to be called, 0xffff if returning
    ; r7: return address
__sm_entry:
    ; On entry, disable interrupts. This will not work (NOP) with Aion but will work with default Sancus.
    dint
    ; First remove ssa base addr to notify violation handler to not use this SMs violation pointer
    mov #0, &__sm_ssa_base_addr
    ; Back up r15 to use it for clix
    mov r15, &__sm_tmp
    ; In Aion mode, the dint above did nothing. In that case, set up clix length and call clix (word 0x1389)
    mov #100, r15 
    .word 0x1389
    ; ========================= Aion CLIX length STARTS here =========================
    ; Restore r15
    mov &__sm_tmp, r15

    ; If we are here because of an IRQ, we will need the current SP later. We do
    ; do not store it in its final destination yet (__sm_irq_sp) because we may
    ; not actually be called by an IRQ in which case we might overwrite a stored
    ; stack pointer.
    mov r1, &__sm_tmp

    ; Initialize SSA frame address for IRQ logic
    ; Technically, this could be set to any SSA but we have just one for now
    mov #__sm_ssa_base, &__sm_ssa_base_addr

    ; check if this is an IRQ
    push r15
    ; sancus_get_caller_id()
    .word 0x1387
    cmp #0xfff0, r15
    jlo 1f
    ; SEMI-HACK: If we are not protected, and no other SM has ever been
    ; executed, the caller ID will be that of the last IRQ because entering this
    ; SM was no protection domain switch. This basically means that once an IRQ
    ; has occurred, we cannot call normal entry points anymore. Since it is nice
    ; to be able to use unprotected SMs during testing, and it is quiet common
    ; to have interrupts disabled then, the caller ID will always be that of the
    ; reset IRQ (0xffff). Since there is no valid use case of actually handling
    ; a reset inside an SM (since the reset will disable all SMs), we simply
    ; ignore it here so that normal entry points can still be used.
    cmp #0xffff, r15
    jeq 1f
    ; If we just do je __sm_isr we get a PCREL relocation which our runtime
    ; linker doesn't understand yet.
    br #__sm_isr

1:
    ; We are not called by an IRQ.
    ; check if this is a return from a interrupt
    bit #0x1, &__sm_ssa_sp
    jz 1f
    ; restore execution state if the sm was resumed
    br #__reti_entry ; defined in exit.s

1:
    ; if waiting for an ORET, only the callee is allowed to  return and we do
    ; not support nested ecalls (hence we sanitize the caller-provided r6
    ; and force it to 0xffff so the ret_entry path below will be taken)
    or #0x7FFF, r6
    tst &__sm_ssa_ocall_id
    jz .Laccept_call
    ; Is ocall_id equal to caller_id?
    cmp &__sm_ssa_ocall_id, r15
    jne .Lreject_call
    mov #0xffff, r6
    clr &__sm_ssa_ocall_id
    jmp .Laccept_call

.Lreject_call:
    ; note: at this point we just want to leave the enclave while leaving its
    ; internal state unmodified; registers do not contain secrets at this
    ; point (except possibly the stored stack pointer), so no need to clear others
    clr r1
    br #error

.Laccept_call:
    ; Overwrite caller_id field in SSA frame (caller_id still in r15)
    mov r15, &__sm_ssa_caller_id
    ; Pop r15 again from the stack (we don't need the caller_id anymore)
    pop r15
    ; === safe to handle IRQs now ===
    eint
    ; ========================= Aion CLIX length ENDS here =========================

    mov &__sm_sp, r1
    ; initialize sp on first entry
    cmp #0x0, r1
    jne 1f
    mov #__sm_stack_init, r1

1:
    ; check if this is a return
    cmp #0xffff, r6
    jne 1f
    br #__ret_entry ; defined in exit.s

1:
    ; check if the given index (r6) is within bounds
    cmp #__sm_nentries, r6
    jhs .Lerror

    ; check if the given return point of the ECALL also belongs to the caller
    push r15
    ; Get the ID of the module at the return address
    mov r7, r15
    .word 0x1386
    ; Get the ID of our caller and compare them
    cmp &__sm_ssa_caller_id, r15
    pop r15
    ; If IDs do not match, the caller asks us to return to another entity than itself. Abort.
    jne .Lerror

    ; store callee-save registers
    push r4
    push r5
    push r8
    push r9
    push r10
    push r11

    ; calculate offset of the function to be called (r6 x 6)
    rla r6
    mov r6, r11
    rla r6
    add r11, r6

    ; function address
    mov __sm_table(r6), r11

    ; call the sm
    call r11

    ; restore callee-save registers
    pop r11
    pop r10
    pop r9
    pop r8
    pop r5
    pop r4

    ; clear the arithmetic status bits (0, 1, 2 and 8) of the status register
    and #0x7ef8, r2

    ; clear the return registers which are not used
    mov 4+__sm_table(r6), r6
    rra r6
    jc 1f
    clr r12
    clr r13
    rra r6
    jc 1f
    clr r14
    rra r6
    jc 1f
    clr r15

1:
    mov #0xffff, r6
    mov #0, &__sm_ssa_caller_id
    mov #0, &__sm_sp
    br r7

.Lerror:
    ; something really went wrong
    ; infinite loop as jumping outside might leave inconsistent internal state
    ; and/or leak secrets in registers
1:
    jmp 1b
