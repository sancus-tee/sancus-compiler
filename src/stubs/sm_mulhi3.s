    .section ".sm.text"
    .align 2
    .global __sm_mulhi3
    .type __sm_mulhi3,@function

    ; \arg r14: a
    ; \arg r15: b
    ; \ret r15: a*b
    ; \note: clobbers r13
__sm_mulhi3:
    mov     r15, r13
    clr     r15
1:  tst     r14
    jz      3f
    clrc
    rrc     r13
    jnc     2f
    add     r14, r15
2:  rla     r14
    tst     r13
    jnz     1b
3:  ret
