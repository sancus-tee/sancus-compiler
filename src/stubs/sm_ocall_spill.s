    .section ".sm.text"
    .align 2
    .global __sm_ocall_spill
    .type __sm_ocall_spill,@function

    ; \arg r6  : narg
    ; \note    : clobber r6, r7, r8
    ; \note    : stack ret, r6, r7, r8, ocall_frame
__sm_ocall_spill:
    ; __unprotected_sp: check untrusted memory range to be written
    ; NOTE: hardware enforces read-only text section
    mov &__unprotected_sp, r8
    mov r8, r7
    sub r6, r7
    cmp #__sm_secret_end, r7
    jge 2f
    cmp #__sm_secret_start, r8
    jl 2f

    ; TODO allocate space for return value

1:  mov r7, &__unprotected_sp
    ret

    ; NOTE: copy stack frame low to high; don't change r1 for interruptability
2:  mov r1, r6
    add #4, r6

3:  cmp r7, r8
    jeq 1b
    mov.b @r6+, 0(r7)
    inc r7
    jmp 3b
