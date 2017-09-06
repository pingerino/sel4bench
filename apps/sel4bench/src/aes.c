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

    set.name = "A-10";
    desc.name = set.name;
    json_int_t budget[N_THROUGHPUT];
    column_t extra = {
        .header = "budget",
        .type = JSON_INTEGER,
        .integer_array = &budget[0]
    };
    set.n_extra_cols = 1;
    set.extra_cols = &extra;
    set.n_results = N_THROUGHPUT;
    result_t throughput_results[N_THROUGHPUT];
    set.results = throughput_results;
    uint64_t step = BUDGET;
    uint64_t period = PERIOD;

    /* process A's results */
    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, raw_results->ten_ms.A[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));
    /* process B's results */
    set.name = "B-10";
    desc.name = set.name;

    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = period - get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, raw_results->ten_ms.B[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));

    /* process baseline results */
    set.name = "baseline-10";
    desc.name = set.name;

    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, raw_results->ten_ms.baseline[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));

    step *= 10;
    period *= 10;
    /* process A's results */
    set.name = "A-100";
    desc.name = set.name;
    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, raw_results->hundred_ms.A[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));
    /* process B's results */
    set.name = "B-100";
    desc.name = set.name;

    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = period - get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, raw_results->hundred_ms.B[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));

    /* process baseline results */
    set.name = "baseline-100";
    desc.name = set.name;

    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, raw_results->hundred_ms.baseline[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));

    step *= 10;
    period *= 10;
    /* process A's results */
    set.name = "A-1000";
    desc.name = set.name;
    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, raw_results->thousand_ms.A[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));
    /* process B's results */
    set.name = "B-1000";
    desc.name = set.name;

    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = period - get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, raw_results->thousand_ms.B[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));

    /* process baseline results */
    set.name = "baseline-1000";
    desc.name = set.name;

    for (int i = 0; i < N_THROUGHPUT; i++) {
        budget[i] = get_budget_for_index(i, step);
        throughput_results[i] = process_result(N_RUNS, raw_results->thousand_ms.baseline[i], desc);
    }
    json_array_append_new(array, result_set_to_json(set));



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

