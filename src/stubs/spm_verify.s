    .section ".spm.text"
    .align 2
    .global __spm_verify
    .type __spm_verify,@function

    ; r13: address of stored ID
    ; r14: address of an SPM
    ; r15: address of expected HMAC
__spm_verify:
    mov 0(r13), r12
    cmp #0x0000, r12
    jeq .Lhmac

    ; we have a stored ID, check if it  matches with the SPM
    mov r14, r15
    .word 0x1385
    cmp r12, r15
    jne .Lexit
    ret

.Lhmac:
    ; we don't have an ID yet, calculate HMAC
    .word 0x1382
    cmp #0x0000, r15
    jeq .Lexit
    mov r15, 0(r13)
    ret

.Lexit:
    call exit
