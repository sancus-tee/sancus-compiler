    .section ".sm.text"
    .align 2
    .global __sm_umodhi3
    .type __sm_umodhi3,@function

__sm_umodhi3:
    call    #__sm_udivhi3
    mov     r14,    r15
    ret
