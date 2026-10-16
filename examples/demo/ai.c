#include "demo.h"

float vel_x[ENTITIES], vel_y[ENTITIES];
int ai_state[ENTITIES];
struct tuning tuning = { 7, 3, 1 };
const short ai_weights[64] = {
    3, -1, 4, -1, 5, -9, 2, -6, 5, -3, 5, -8, 9, -7, 9, -3,
    2, -3, 8, -4, 6, -2, 6, -4, 3, -3, 8, -3, 2, -7, 9, -5,
    0, -2, 8, -8, 4, -1, 9, -7, 1, -6, 9, -3, 9, -9, 3, -7,
    5, -1, 0, -5, 8, -2, 0, -9, 7, -4, 9, -4, 4, -5, 9, -2,
};

void ai_update(int frame)
{
    for (int i = 0; i < ENTITIES; i++) {
        int s = ai_state[i] * 1103515245 + 12345 + frame;
        ai_state[i] = s;
        if (((unsigned)s >> 16) / tuning.divisor % 3 == 0) {
            vel_x[i] += ai_weights[s & 63] * 0.01f;
            vel_y[i] -= ai_weights[(s >> 6) & 63] * 0.01f;
        }
    }
}

COLD_CODE(ai_debug_dump, 1200)
