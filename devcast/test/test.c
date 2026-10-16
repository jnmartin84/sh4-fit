/* sh4trace test program: hot_a and hot_b sit exactly 8 KiB apart (test.ld),
 * so they share every instruction-cache slot. main_loop alternates them,
 * touches data, issues each cache op once per iteration, takes a trapa, and
 * prints a start marker on the serial port. */

#define SCIF_SCFTDR2 (*(volatile unsigned char *)0xffe8000c)
#define CCN_CCR (*(volatile unsigned int *)0xff00001c)

int table[2048];        /* 8 KiB, the size of the instruction cache */
volatile int sink;
int line_buffer[8] __attribute__((aligned(32)));

__attribute__((noinline, section(".text.hot_a"))) int hot_a(int x)
{
    for (int i = 0; i < 64; i++)
        x += table[i * 8] ^ i;
    return x;
}

__attribute__((noinline, section(".text.hot_b"))) int hot_b(int x)
{
    for (int i = 0; i < 64; i++)
        table[i * 8 + 1] = x + i;
    return x * 3;
}

static void serial_puts(const char *s)
{
    while (*s)
        SCIF_SCFTDR2 = *s++;
}

static void cache_ops(void *p)
{
    __asm__ volatile("pref @%0" : : "r"(p) : "memory");
    __asm__ volatile("ocbwb @%0" : : "r"(p) : "memory");
    __asm__ volatile("mov %1,r0\n\tmovca.l r0,@%0" : : "r"(p), "r"(sink) : "r0", "memory");
    __asm__ volatile("ocbp @%0" : : "r"(p) : "memory");
    __asm__ volatile("ocbi @%0" : : "r"(p) : "memory");
}

void main_loop(void)
{
    CCN_CCR = 0x0000090d;   /* ICE|ICI|OCE|OCI|CB: caches on and invalidated */
    serial_puts("SH4FIT-TEST start\n");
    for (;;) {
        sink += hot_a(sink);
        sink += hot_b(sink);
        cache_ops(line_buffer);
        __asm__ volatile("trapa #0x20" : : : "memory");
    }
}
