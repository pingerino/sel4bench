/*
 * Copyright 2016, NICTA
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(NICTA_GPL)
 */
#include "benchmark.h"
#include "processing.h"
#include "json.h"

#include <aes.h>
#include <stdio.h>

static void process_tput_result(tput_results_t *res, int ms, json_t *array,
                           uint64_t step, uint64_t period)
{
    char name[80];
    sprintf(name, "A-%d", ms);

    json_int_t budget[N_THROUGHPUT];
    column_t extra = {
        .header = "budget",
        .type = JSON_INTEGER,
        .integer_array = &budget[0]
    };

    result_t throughput_results[N_THROUGHPUT];
    result_set_t set = {
        .name = name,
        .n_results = N_THROUGHPUT,
        .n_extra_cols = 1,
        .extra_cols = &extra,
        .results = throughput_results
    };

    result_desc_t desc = {
        .stable = true,
        .name = name,
        .ignored = N_IGNORED
    };

    /* process A's results */
    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, res->A[i], desc);
    }

    json_array_append_new(array, result_set_to_json(set));
    /* process B's results */
    sprintf(name, "B-%d", ms);
    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = period - get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, res->B[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));

    /* process baseline results */
    sprintf(name, "baseline-%d", ms);

    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, res->baseline[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));

    sprintf(name, "util-%d", ms);
    set.n_extra_cols = 0;

    for (int i = 0; i < N_THROUGHPUT; i++) {
        throughput_results[i] = process_result(N_RUNS, res->util[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));
}


static json_t *
aes_process(void *results)
{
    aes_results_t *raw_results = results;

    result_desc_t desc = {
        .stable = true,
        .name = "aes overhead",
        .ignored = N_IGNORED
    };

    result_t result = process_result(N_RUNS, raw_results->overhead, desc);

    result_set_t set = {
        .name = "aes overhead",
        .n_results = 1,
        .n_extra_cols = 0,
        .results = &result
    };

    json_t *array = json_array();
    json_array_append_new(array, result_set_to_json(set));

    set.name = "aes rollback";
    desc.stable = false;
    desc.overhead = result.min;

    result = process_result(N_RUNS, raw_results->rollback_cost, desc);
    json_array_append_new(array, result_set_to_json(set));

    set.name = "aes rollback cold";
    result = process_result(N_RUNS, raw_results->rollback_cost_cold, desc);
    json_array_append_new(array, result_set_to_json(set));

    set.name = "aes emergency";
    result = process_result(N_RUNS, raw_results->emergency_cost, desc);
    json_array_append_new(array, result_set_to_json(set));

    set.name = "aes emergency cold";
    result = process_result(N_RUNS, raw_results->emergency_cost_cold, desc);
    json_array_append_new(array, result_set_to_json(set));

    set.name = "aes extend";
    result = process_result(N_RUNS, raw_results->extend_cost, desc);
    json_array_append_new(array, result_set_to_json(set));

    set.name = "aes extend cold";
    result = process_result(N_RUNS, raw_results->extend_cost_cold, desc);
    json_array_append_new(array, result_set_to_json(set));

    set.name = "aes kill";
    result = process_result(N_RUNS, raw_results->kill_cost, desc);
    json_array_append_new(array, result_set_to_json(set));

    set.name = "aes kill cold";
    result = process_result(N_RUNS, raw_results->kill_cost_cold, desc);
    json_array_append_new(array, result_set_to_json(set));

    process_tput_result(&raw_results->ten_ms, 10, array, BUDGET, PERIOD);
    process_tput_result(&raw_results->hundred_ms, 100, array, BUDGET*10, PERIOD*10);
    process_tput_result(&raw_results->ten_ms, 1000, array, BUDGET*100, PERIOD*100);

    return array;
}

static benchmark_t aes_benchmark = {
    .name = "aes",
    .enabled = config_set(CONFIG_APP_AES),
    .results_pages = BYTES_TO_SIZE_BITS_PAGES(sizeof(aes_results_t), seL4_PageBits),
    .process = aes_process,
    .init = blank_init
};

benchmark_t *
aes_benchmark_new(void)
{
    return &aes_benchmark;
}

