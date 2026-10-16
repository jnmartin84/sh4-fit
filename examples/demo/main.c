#include "demo.h"

#define SCIF_SCFTDR2 (*(volatile unsigned char *)0xffe8000c)
#define CCN_CCR (*(volatile unsigned int *)0xff00001c)

volatile int demo_never;   /* keeps the cold code linked under --gc-sections */
int frame_count;

static void serial_puts(const char *s)
{
    while (*s)
        SCIF_SCFTDR2 = *s++;
}

/* What KOS's icache_flush_range() does per line: an associative store to the
 * instruction-cache address array, which invalidates the line if it is cached.
 * The SH-4 only allows that from P2, so it is called through its P2 alias. */
static void __attribute__((noinline)) icache_flush_line(unsigned address)
{
    *(volatile unsigned *)(0xf0000008 | (address & 0x1fe0)) = address & 0x1ffffc00;
}

int main(void)
{
    CCN_CCR = 0x0000090d;   /* ICE|ICI|OCE|OCI|CB, as KOS sets it */
    world_init();
    serial_puts("SH4FIT-DEMO start\n");
    for (;;) {
        if (demo_never)
            cold_paths(demo_never);
        physics_step();
        ai_update(frame_count);
        render_build();
        audio_mix(frame_count);
        if ((++frame_count & 255) == 0) {
            void (*flush)(unsigned) = (void (*)(unsigned))((unsigned)icache_flush_line | 0x20000000);
            flush((unsigned)physics_step);
        }
    }
}
