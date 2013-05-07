    .section ".spm.text"
    .align 2
    .global __spm_entry
    .type __spm_entry,@function

    ; r6: ID of entry point to be called, 0xffff if returning
    ; r7: return address
__spm_entry:
    #switch stack
    mov &__spm_sp, r1
    cmp #0x0, r1
    jne 1f
    mov #__spm_stack_init, r1

1:
    ; check if this is a return
    cmp #0xffff, r6
    jne 1f
    br #__ret_entry ; defined in exit.s
1:
    ; check if the given index (r6) is within bounds
    cmp #__spm_nentries, r6
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
    mov __spm_table(r6), r11

    ; call the spm
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
    mov 4+__spm_table(r6), r6
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
    mov r1, &__spm_sp
    mov #0xffff, r6
    br r7

.Lerror:
    br #exit
