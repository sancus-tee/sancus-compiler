;******************************************************************************
; stub that will be executed to return from an asm (__naked__) SM
;******************************************************************************
    .section ".sm.text"
    .align 2
    .global __sm_exit
    .type __sm_exit,@function

    ; \arg      r7: return address to caller
    ; \return   r6: return entry point (0xffff)
    ; \note     caller has been successfully verified by sm_entry and is 
    ;           now completely trusted (no register clearing, etc)
    ; \note     no support for outcalls; asm SMs can only return to caller
__sm_exit:
    mov #0xffff, r6
    br r7
