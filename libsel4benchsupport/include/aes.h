/*
 * Copyright 2016, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(D61_BSD)
 */
#pragma once

#include <sel4bench/sel4bench.h>

#define N_IGNORED 10
#define N_RUNS (100 + N_IGNORED)
#define N_THROUGHPUT 11
#define PERIOD (10 * US_IN_MS)
#define BUDGET 1000

typedef struct {
    ccnt_t A[N_THROUGHPUT][N_RUNS];
    ccnt_t B[N_THROUGHPUT][N_RUNS];
    ccnt_t baseline[N_THROUGHPUT][N_RUNS];
    seL4_Word total[N_THROUGHPUT][N_RUNS];
    seL4_Word idle[N_THROUGHPUT][N_RUNS];
} tput_results_t;

typedef struct aes_results {
    ccnt_t rollback_cost[N_RUNS];
    ccnt_t rollback_cost_cold[N_RUNS];
    ccnt_t emergency_cost[N_RUNS];
    ccnt_t emergency_cost_cold[N_RUNS];
    ccnt_t extend_cost[N_RUNS];
    ccnt_t extend_cost_cold[N_RUNS];
    ccnt_t kill_cost[N_RUNS];
    ccnt_t kill_cost_cold[N_RUNS];
    ccnt_t overhead[N_RUNS];
    tput_results_t ten_ms;
    tput_results_t hundred_ms;
    tput_results_t thousand_ms;
} aes_results_t;



static inline int get_budget_for_index(int i, uint64_t step)
{
    return i * step;
}
