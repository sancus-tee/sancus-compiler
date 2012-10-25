	.align 2
	.type __spm_entry,@function

__spm_entry:
	; check if this is a return from unprotected
	cmp #0xffff, r6
	jne 1f
	nop
	br #__unprotected_ret ; defined in exit.S
1:

	; store callee-save registers
	push r4
	push r5
	push r7
	push r8
	push r9
	push r10
	push r11

	; check if the given index (r6) is within bounds
	mov &__spm_table, r11
	cmp r11, r6
	jhs .Lerror

	; calculate offset of the function to be called (r6 x 6)
	rla r6
	mov r6, r11
	rla r6
	add r11, r6

	; function address
	mov 2+__spm_table(r6), r11

	; number of bytes to be copied to the spm stack
	mov 4+__spm_table(r6), r10

	; switch stack, save old sp in r9
	mov r1, r9
	mov r9, &__unprotected_sp
	mov &__spm_sp, r1

	; stack frame will be copied from high to low addresses
	; first calculate high address
	mov r10, r8
	add r9, r10

	; check if we're done copying
1:
	cmp r10, r9
	jeq 1f

	; move from old stack to new stack. since the sp has been switched, we can
	; just push.
	push 16(r10)

	; we pushed 2 bytes so adjust r10
	sub #2, r10
	jmp 1b

1:
	; call the spm
	call r11

	; remove the parameters from the stack and save the stack pointer
	add r8, r1
	mov r1, &__spm_sp

	; switch the stack back
	mov r9, r1

	; restore callee-save registers
	pop r11
	pop r10
	pop r9
	pop r8
	pop r7
	pop r5
	pop r4

	; clear status register
	clr r2

	; clear the return registers which are not used
	mov 6+__spm_table(r6), r6
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
	pop r6
	ret

.Lerror:
	br #exit
