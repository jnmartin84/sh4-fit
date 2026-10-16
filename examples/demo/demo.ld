/* Shaped like KallistiOS's shlelf.xc where it matters to Sh4Fit: start.o's
 * plain .text comes first at 0x8c010000 under one combined .text selector,
 * and data follows in .rodata/.data/.bss. */
OUTPUT_FORMAT("elf32-shl", "elf32-shl", "elf32-shl")
OUTPUT_ARCH(sh)
ENTRY(start)
SECTIONS
{
  . = 0x8c010000;
  .init           : { KEEP (*(SORT_NONE(.init))) } =0x0009
  .text           :
  {
    *(.text .stub .text.* .gnu.linkonce.t.*)
    /* .gnu.warning sections are handled specially by elf32.em.  */
    *(.gnu.warning)
  } =0x0009
  .fini           : { KEEP (*(SORT_NONE(.fini))) } =0x0009
  PROVIDE (__etext = .);
  .rodata         : { *(.rodata .rodata.* .gnu.linkonce.r.*) }
  . = ALIGN(32);
  .data           :
  {
    *(.data .data.* .gnu.linkonce.d.*)
    SORT(CONSTRUCTORS)
  }
  _edata = .; PROVIDE (edata = .);
  __bss_start = .;
  .bss            :
  {
    *(.dynbss)
    *(.bss .bss.* .gnu.linkonce.b.*)
    *(COMMON)
    . = ALIGN(. != 0 ? 32 / 8 : 1);
  }
  . = ALIGN(32 / 8);
  _end = .; PROVIDE (end = .);
}
