    .section ".sm.text"
    .align 2
    .global __sm_entry
    .type __sm_entry,@function

    ; r6: ID of entry point to be called, 0xffff if returning
    ; r7: return address
__sm_entry:
    ; If we are here because of an IRQ, we will need the current SP later. We do
    ; do not store it in its final destination yet (__sm_irq_sp) because we may
    ; not actually be called by an IRQ in which case we might overwrite a stored
    ; stack pointer.
    mov r1, &__sm_tmp
    # Switch stack.
    mov &__sm_sp, r1
    cmp #0x0, r1
    jne 1f
    mov #__sm_stack_init, r1

1:
    ; check of this is an IRQ
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
    jne __sm_isr
1:
    pop r15

    ; check if this is a return
    cmp #0xffff, r6
    jne 1f
    br #__ret_entry ; defined in exit.s

1:
    ; check if the given index (r6) is within bounds
    cmp #__sm_nentries, r6
    jhs .Lerror

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
    mov r1, &__sm_sp
    mov #0xffff, r6
    br r7

.Lerror:
    br #exit
