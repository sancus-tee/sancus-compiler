;******************************************************************************
; stub that will be executed when entering an asm (__naked__) SM
;******************************************************************************
    .section ".sm.text"
    .align 2
    .global __sm_entry
    .type __sm_entry,@function

    ; \arg      r6: logical entry idx
    ;           r7: return address to caller
    ; \note     function arguments in r15-r12 
    ; \note     after successful callerID verification, caller is completely
    ;           trusted (no argument checking, register clearing, etc)
__sm_entry:
    ; enforce exclusive access for caller SM
    ; sancus_get_caller_id
    mov r15, r11
    .word 0x1387
    cmp #__sm_caller_id, r15
    jne .Lerror

    ; restore C compiler ABI
    mov r11, r15
    
    ; calculate offset of the entry function to be called (r6 x 6)
    ; note: sm_table is securely stored in text section
    rla r6
    mov r6, r11
    rla r6
    add r11, r6
    mov __sm_table(r6), r6

    ; call the entry function
    ; NOTE: function should not touch r7 used by sm_exit stub
    br r6

.Lerror:
    clr &__sm_entry             ; raise memory violation
    jmp .Lerror
