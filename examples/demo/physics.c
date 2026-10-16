#include "demo.h"

float pos_x[ENTITIES], pos_y[ENTITIES];

void world_init(void)
{
    for (int i = 0; i < ENTITIES; i++) {
        pos_x[i] = (float)(i * 37 % 640);
        pos_y[i] = (float)(i * 91 % 480);
        vel_x[i] = (float)(i % 7) - 3.0f;
        vel_y[i] = (float)(i % 5) - 2.0f;
        ai_state[i] = i * 2654435761u;
    }
}

void physics_step(void)
{
    for (int i = 0; i < ENTITIES; i++) {
        pos_x[i] += vel_x[i] * 0.5f;
        pos_y[i] += vel_y[i] * 0.5f;
        if (pos_x[i] < 0.0f || pos_x[i] > 640.0f)
            vel_x[i] = -vel_x[i];
        if (pos_y[i] < 0.0f || pos_y[i] > 480.0f)
            vel_y[i] = -vel_y[i];
    }
}

COLD_CODE(physics_debug_draw, 2260)
