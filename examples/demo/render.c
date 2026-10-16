#include "demo.h"

int cmd_buffer[COMMANDS];

void render_build(void)
{
    int *p = cmd_buffer;
    for (int i = 0; i < ENTITIES; i++) {
        int x = (int)pos_x[i], y = (int)pos_y[i];
        *p++ = x | y << 16;
        *p++ = (ai_state[i] & 0xff) * tuning.gain + tuning.bias;
    }
}

COLD_CODE(render_screenshot, 8492)
