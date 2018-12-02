    .section ".sm.text"
    .align 2
    .global __sm_exit
    .type __sm_exit,@function

    ; r6: ID of entry point or function address to be called
    ; r7: register usage
    ; r8: entry point to call
__sm_exit:
    ; store and clear callee-save registers
    push r4
    clr  r4
    push r5
    clr  r5
    push r9
    clr  r9
    push r10
    clr  r10
    push r11
    clr  r11

    ; clear unused argument registers
    rra r7
    jc 1f
    clr r12
    rra r7
    jc 1f
    clr r13
    rra r7
    jc 1f
    clr r14
    rra r7
    jc 1f
    clr r15
1:
    ; atomic leaving of sm
    dint
    ; store sp
    mov r1, &__sm_sp

    ; pass the entry point as return address
    mov #__sm_entry, r7
    br r8

    .align 2
    .global __reti_entry
    .type __reti_entry,@function
__reti_entry:
    pop r4
    pop r5
    pop r6
    pop r7
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    
    ; clear bit 0 
    ; maybe we also should store stackpointer
    ; or we assume: reti never jumps out of sm
    bic #0x1, &__sm_sp
    
    reti
        
    .align 2
    .global __ret_entry
    .type __ret_entry,@function
__ret_entry:
    ; restore callee-save registers
    pop r11
    pop r10
    pop r9
    pop r5
    pop r4

    pop r8
    pop r7
    pop r6

    ret
