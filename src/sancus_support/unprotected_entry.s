    .data
    .align 2
    .global __unprotected_sp
__unprotected_sp:
    .word 0x0000

    .text
    .align 2
    .global __unprotected_entry
    .type __unprotected_entry,@function

    ; r6: address of function to call
    ; r7: return address
__unprotected_entry:
    ; restore the unprotected stack
    mov &__unprotected_sp, r1
    call r6
    ; if an unprotected function was called somewhere during the above call, the
    ; stored stack pointer has changed so we need to store the correct one again
    mov r1, &__unprotected_sp
    mov #0xffff, r6
    br r7
