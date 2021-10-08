    .section ".sm.text"
    .align 2
    .global __sm_isr
    .type __sm_isr,@function

; The default isr stub performs the CPU state storing and resuming. In between, it calls
; the ISR function that can deal with the interrupt but does not have to deal with 
; carefully storing and resuming the CPU state.
__sm_isr:
    ; Now that we are sure we are called by an IRQ, commit the SP.
    mov &__sm_tmp, &__sm_irq_sp

    ; Store all registers.
    push r4
    push r5
    push r6
    push r7
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    ; r15 is already pushed in sm_entry.s

    ; r15 contains the caller ID of the IRQ. Mask out the actual IRQ number to
    ; pass it to the handler.
    and #0x000f, r15
    call #__sm_isr_func

    ; Restore all registers. Note that we do not restore or clear R2 since that
    ; will be done by reti.
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop r7
    pop r6
    pop r5
    pop r4
    pop r15

    ; Switch the stack.
    mov r1, &__sm_sp
    mov &__sm_irq_sp, r1
    reti
    ; ========================= Aion CLIX length ENDS here =========================
