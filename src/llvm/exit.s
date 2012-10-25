	.align 2
	.type __spm_exit,@function

__spm_exit:
	; store and clear callee-save registers
	push r4
	clr  r4
	push r5
	clr  r5
	push r6
	clr  r6
	push r11
	clr  r11

	; clear unused argument registers
	rra r9
	jc 1f
	clr r12
	rra r9
	jc 1f
	clr r13
	rra r9
	jc 1f
	clr r14
	rra r9
	jc 1f
	clr r15
1:

	; save r15 on the protected stack
	push r15

	; switch stack, save old sp in r11
	mov r1, r11
	mov r11, &__spm_sp
	mov &__unprotected_sp, r1

	; check if extra space needs to be reserved on the stack for the return
	; value
	cmp #0, r10
	jeq 1f
	sub r10, r1
	mov r1, r15
1:

	; stack frame will be copied from high to low addresses (number of bytes
	; passed in r7) first calculate high address
	mov r7, r9
	add r11, r9

	; check if we're done copying
1:
	cmp r9, r11
	jeq 1f

	; move from old stack to new stack. since the sp has been switched, we can
	; just push.
	push 18(r9)

	; we pushed 2 bytes so adjust r9
	sub #2, r9
	jmp 1b

1:
	; call the unprotected function
	mov #0xffff, r6
	push #__spm_entry
	br r8

__unprotected_ret:
	; remove the parameters from the stack
	add r7, r1

	; copy return value to protected memory. the address to copy to is at the
	; top of the spm stack
	mov @r11+, r9
1:
	cmp #0, r10
	jeq 1f
	mov @r1+, r8
	mov r8, @r9
	incd r9
	decd r10
	jmp 1b
1:

	; switch the stack back
	mov r1, &__unprotected_sp
	mov r11, r1

	; restore callee-save registers
	pop r11
	pop r6
	pop r5
	pop r4

	pop r10
	pop r9
	pop r8
	pop r7
	ret
