    .section ".sm.text"
    .align 2
    .global __sm_divhi3
    .type __sm_divhi3,@function

__sm_divhi3:
    clr     r13
    tst     r15
    jge     1f
    mov     #3, r13
    inv     r15
    inc     r15
1:  tst     r14
    jge     2f
    xor.b   #1, r13
    inv     r14
    inc     r14
2:  push    r13
    call    #__sm_udivhi3
    pop     r13
    bit.b   #2, r13
    jz      3f
    inv     r14
    inc     r14
3:  bit.b   #1, r13
    jz      4f
    inv     r15
    inc     r15
4:  ret
