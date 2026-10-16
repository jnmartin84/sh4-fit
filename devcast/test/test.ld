/* hot_b lands exactly one instruction-cache size (8 KiB) after hot_a. */
OUTPUT_FORMAT("elf32-shl")
OUTPUT_ARCH(sh)
ENTRY(start)
SECTIONS
{
	. = 0x8c010000;
	.text : {
		*(.text.start)
		. = ALIGN(32);
		__hot_a = .;
		*(.text.hot_a)
		*(.text.main_loop)
		. = __hot_a + 8192;
		*(.text.hot_b)
		*(.text.vectors)
		*(.text .text.*)
	}
	.rodata : { *(.rodata .rodata.*) }
	.data : { *(.data .data.*) }
	.bss : { *(.bss .bss.*) *(COMMON) }
}
