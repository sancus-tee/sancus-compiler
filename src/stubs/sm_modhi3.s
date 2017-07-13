    .section ".sm.text"
    .align 2
    .global __sm_modhi3
    .type __sm_modhi3,@function

__sm_modhi3:
    call    #__sm_divhi3
    mov     r14,    r15
    ret
