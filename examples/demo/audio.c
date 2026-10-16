#include "demo.h"

short mix_buffer[SAMPLES];
const short wave[256] = {
#define W(n) (short)((n) * 97 % 2048 - 1024)
    W(0), W(1), W(2), W(3), W(4), W(5), W(6), W(7), W(8), W(9), W(10), W(11), W(12), W(13), W(14), W(15),
    W(16), W(17), W(18), W(19), W(20), W(21), W(22), W(23), W(24), W(25), W(26), W(27), W(28), W(29), W(30), W(31),
    W(32), W(33), W(34), W(35), W(36), W(37), W(38), W(39), W(40), W(41), W(42), W(43), W(44), W(45), W(46), W(47),
    W(48), W(49), W(50), W(51), W(52), W(53), W(54), W(55), W(56), W(57), W(58), W(59), W(60), W(61), W(62), W(63),
};

void audio_mix(int frame)
{
    for (int i = 0; i < SAMPLES; i++)
        mix_buffer[i] = (short)((mix_buffer[i] >> 1) + wave[(i + frame) & 63] / tuning.gain);
}

void cold_paths(int which)
{
    extern void physics_debug_draw(void), menu_draw(void), menu_input(void), menu_options(void),
        ai_debug_dump(void), loader_open(void), loader_parse(void), render_screenshot(void);
    extern char save_buffer[], loader_scratch[];
    save_buffer[which] = loader_scratch[which];
    physics_debug_draw(); menu_draw(); menu_input(); menu_options();
    ai_debug_dump(); loader_open(); loader_parse(); render_screenshot();
}
