! Bare-metal entry for the Sh4Fit layout demo, standing in for KOS's
! startup.o: a plain .text section linked first, so it stays at 0x8c010000.

	.text
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
stack_top:	.long 0x8d000000
vectors_addr:	.long vectors
sr_value:	.long 0x400000f0	! MD=1, BL=0, all interrupts masked
main_addr:	.long _main

	.balign 256
vectors:
	.space 0x100
	rte			! VBR+0x100: general exceptions
	nop
	.space 0x600 - 0x104
	rte			! VBR+0x600: interrupts (masked)
	nop
