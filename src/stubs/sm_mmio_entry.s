;******************************************************************************
; stub executed when entering an MMIO SM without general purpose data section
;******************************************************************************
    .section ".sm.text"
    .align 2
    .global __sm_entry
    .type __sm_entry,@function

    ; \arg      r6: logical entry idx
    ;           r7: return address to caller
    ; \note     function arguments in r15-r12 
    ; \note     no argument checking when using trusted callerID verification
__sm_entry:

.ifdef mmio_exclusive
    ; enforce exclusive access for caller SM
    ; sancus_get_caller_id
    mov r15, r11
    .word 0x1387
    cmp #__sm_caller_id, r15
    jne .Lerror

    ; restore C compiler ABI
    mov r11, r15
.else
    ; check if the given index (r6) is within bounds
    cmp #__sm_nentries, r6
    jhs .Lerror
.endif

    ; calculate offset of the entry function to be called (r6 x 6)
    ; note: sm_table is securely stored in text section
    rla r6
    mov r6, r11
    rla r6
    add r11, r6
    mov __sm_table(r6), r6

    ; call the entry function
    ; NOTE: function should not touch r7, holding the return address
    br r6

    .align 2
    .global __sm_exit
    .type __sm_exit,@function

    ; \arg      r7: return address to caller
    ; \ret      r6: return entry point (0xffff)
    ; \note     no register clearing
    ; \note     no support for outcalls; asm SMs can only return to caller
__sm_exit:
    mov #0xffff, r6
    br r7

.Lerror:
    clr &__sm_entry             ; raise memory violation
    jmp .Lerror
