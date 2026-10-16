/* sh4fit_perf.h: measure what Sh4Fit predicts, on real hardware.
 *
 * Counts instruction- or operand-cache misses per 1,000 issued instructions
 * with the SH-4 performance counters (KallistiOS <dc/perfctr.h>), so a build
 * relinked with a generated script can be compared with the original on a
 * Dreamcast, in the same units as Sh4Fit's report. A third mode measures the
 * pipeline stalls caused by cache misses, from which the cycles per miss for
 * --ic-miss-cycles / --oc-miss-cycles follow.
 *
 * Both counters are used, so KallistiOS's nanosecond timer on PRFC0 is turned
 * off while measuring (perf_cntr_timer_ns() falls back to the 80 ns timer) and
 * back on by sh4fit_perf_stop().
 *
 *     #include "sh4fit_perf.h"
 *     sh4fit_perf_start(SH4FIT_PERF_IC);    // or SH4FIT_PERF_OC, SH4FIT_PERF_STALLS
 *     for (;;) {
 *         game_frame();
 *         if (++frames % 600 == 0)
 *             sh4fit_perf_report("gameplay");  // prints and restarts the counts
 *     }
 *
 * Output goes through printf, i.e. to dcload's console or the serial port:
 *     sh4fit gameplay: 600 frames, 812345678 instructions, 51234 IC misses = 0.0631 per 1k instructions
 *
 * Header only; include it in one file.
 */
#ifndef SH4FIT_PERF_H
#define SH4FIT_PERF_H

#include <stdint.h>
#include <stdio.h>
#include <dc/perfctr.h>

typedef enum {
    SH4FIT_PERF_IC,      /* instruction-cache misses and issued instructions */
    SH4FIT_PERF_OC,      /* operand-cache misses and issued instructions */
    SH4FIT_PERF_STALLS,  /* cycles frozen by instruction- and by operand-cache misses */
} sh4fit_perf_mode_t;

static sh4fit_perf_mode_t sh4fit_perf_mode;
static uint32_t sh4fit_perf_frames;

static inline void sh4fit_perf_restart(void)
{
    static const perf_cntr_event_t first[] = {
        PMCR_INSTRUCTION_CACHE_MISS_MODE, PMCR_OPERAND_CACHE_MISS_MODE,
        PMCR_PIPELINE_FREEZE_BY_ICACHE_MISS_MODE,
    };
    static const perf_cntr_event_t second[] = {
        PMCR_INSTRUCTION_ISSUED_MODE, PMCR_INSTRUCTION_ISSUED_MODE,
        PMCR_PIPELINE_FREEZE_BY_DCACHE_MISS_MODE,
    };
    perf_cntr_stop(PRFC0);
    perf_cntr_stop(PRFC1);
    perf_cntr_clear(PRFC0);
    perf_cntr_clear(PRFC1);
    perf_cntr_start(PRFC0, first[sh4fit_perf_mode], PMCR_COUNT_CPU_CYCLES);
    perf_cntr_start(PRFC1, second[sh4fit_perf_mode], PMCR_COUNT_CPU_CYCLES);
    sh4fit_perf_frames = 0;
}

/* Start counting in `mode`. */
static inline void sh4fit_perf_start(sh4fit_perf_mode_t mode)
{
    perf_cntr_timer_disable();
    sh4fit_perf_mode = mode;
    sh4fit_perf_restart();
}

/* Call once per game frame if the report should say how many frames it covers. */
static inline void sh4fit_perf_frame(void)
{
    sh4fit_perf_frames++;
}

/* Print the counts since the last start or report, then start over. */
static inline void sh4fit_perf_report(const char *label)
{
    uint64_t a, b;
    perf_cntr_stop(PRFC0);
    perf_cntr_stop(PRFC1);
    a = perf_cntr_count(PRFC0);
    b = perf_cntr_count(PRFC1);
    if (sh4fit_perf_mode == SH4FIT_PERF_STALLS) {
        printf("sh4fit %s: %lu frames, %llu cycles stalled on IC misses, %llu on OC misses\n",
               label, (unsigned long)sh4fit_perf_frames, (unsigned long long)a, (unsigned long long)b);
    } else {
        /* misses per 1k instructions, with four decimals, without floating point */
        uint64_t rate = b ? a * 10000000ull / b : 0;
        printf("sh4fit %s: %lu frames, %llu instructions, %llu %s misses = %llu.%04llu per 1k instructions\n",
               label, (unsigned long)sh4fit_perf_frames, (unsigned long long)b, (unsigned long long)a,
               sh4fit_perf_mode == SH4FIT_PERF_IC ? "IC" : "OC",
               (unsigned long long)(rate / 10000), (unsigned long long)(rate % 10000));
    }
    sh4fit_perf_restart();
}

/* Stop counting and give PRFC0 back to KallistiOS's nanosecond timer. */
static inline void sh4fit_perf_stop(void)
{
    perf_cntr_stop(PRFC0);
    perf_cntr_stop(PRFC1);
    perf_cntr_timer_enable();
}

#endif
