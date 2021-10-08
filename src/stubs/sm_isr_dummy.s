    .section ".sm.text"
    .align 2
    .global __sm_isr
    .type __sm_isr,@function

; The dummy ISR does nothing and just immediately returns from the interrupt.
__sm_isr:
    ; r15 is pushed in sm_entry.s
    pop r15
    mov &__sm_tmp, r1
    reti
    ; ========================= Aion CLIX length ENDS here =========================
