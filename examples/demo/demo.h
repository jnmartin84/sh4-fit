/* Sh4Fit layout demo: a toy "game frame" whose default link order makes hot
 * functions share instruction-cache slots and hot arrays share operand-cache
 * slots. Cold menu/loader code and a save buffer sit between them, the way
 * rarely used code and buffers end up between systems in a real game. */
#ifndef DEMO_H
#define DEMO_H

#define ENTITIES 256
#define COMMANDS 512
#define SAMPLES 1024

/* A function of `bytes` bytes of straight-line code that never runs. */
#define COLD_CODE(name, bytes) \
    __attribute__((noinline)) void name(void) { __asm__ volatile(".rept " #bytes " / 2\n\tnop\n\t.endr"); }

extern float pos_x[ENTITIES], pos_y[ENTITIES];
extern float vel_x[ENTITIES], vel_y[ENTITIES];
extern int ai_state[ENTITIES];
extern int cmd_buffer[COMMANDS];
extern short mix_buffer[SAMPLES];
extern struct tuning { int divisor, gain, bias; } tuning;

void world_init(void);
void physics_step(void);
void ai_update(int frame);
void render_build(void);
void audio_mix(int frame);
void cold_paths(int which);

#endif
