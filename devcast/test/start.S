! Bare-metal entry for the sh4trace test program. reios loads the ELF and
! jumps to 0x8c010000 with SR.BL set; give the program a stack, its own
! vectors and an SR that lets trapa raise a normal exception.

	.section .text.start,"ax",@progbits
	.global start
start:
	mov.l	stack_top, r15
	mov.l	vectors_addr, r0
	ldc	r0, vbr
	mov.l	sr_value, r0
	ldc	r0, sr
	mov.l	main_addr, r0
	jmp	@r0
	nop
	.balign 4
stack_top:	.long 0x8cfffff0
vectors_addr:	.long vectors
sr_value:	.long 0x400000f0	! MD=1, BL=0, all interrupts masked
main_addr:	.long _main_loop

	.section .text.vectors,"ax",@progbits
	.balign 256
vectors:
	.space 0x100
	! VBR+0x100: general exceptions (trapa) return straight to the caller
	rte
	nop
	.space 0x600 - 0x104
	! VBR+0x600: interrupts (masked, but harmless)
	rte
	nop
