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

#include <stdio.h>
#include <ulscheduler.h>


static json_t *task_result(ccnt_t results[N_RUNS*2]) {
    json_t *result_array = json_array();
    for (int i = 0; i < N_RUNS * 2 ; i++) {
        ccnt_t value = results[i];
        if (value == 0) {
            break;
        }
        json_array_append_new(result_array, json_integer(value));
    }
    return result_array;
}

static json_t *task_set_result(ccnt_t results[NUM_TASKS+1][N_RUNS*2], int n_tasks) {
    json_t *task_set_array = json_array();
    for (int i = 0; i < n_tasks; i++) {
        json_array_append_new(task_set_array, task_result(results[i]));
    }

    /* now get results from the scheduler idle */
    json_array_append_new(task_set_array, task_result(results[NUM_TASKS]));
    return task_set_array;
}

static json_t *ulsched_result(ccnt_t results[NUM_TASKS][CONFIG_NUM_TASK_SETS][NUM_TASKS+1][N_RUNS*2])
{
    json_t *result_array = json_array();
    assert(result_array != NULL);

    for (int n_tasks = CONFIG_MIN_TASKS; n_tasks <= CONFIG_MAX_TASKS; n_tasks++) {
        json_t *n_tasks_object = json_object();
        json_t *n_tasks_results = json_array();
        json_object_set_new(n_tasks_object, "n tasks", json_integer(n_tasks));
        json_object_set_new(n_tasks_object, "results", n_tasks_results);
        for (int task_set = 0; task_set < CONFIG_NUM_TASK_SETS; task_set++) {
            json_array_append_new(n_tasks_results,
                task_set_result(results[n_tasks-CONFIG_MIN_TASKS][task_set], n_tasks));
        }
        json_array_append_new(result_array, n_tasks_object);
    }

    return result_array;
}

static json_t *
ulscheduler_process(void *results) {
    ulscheduler_results_t *raw_results = results;

    json_t *array = json_array();

    json_t *coop_results = json_object();
    json_array_append_new(array, coop_results);
    assert(coop_results != NULL);

    int error = 0;
    error = json_object_set_new(coop_results, "Benchmark", json_string("EDF-coop"));
    assert(error == 0);

    error = json_object_set_new(coop_results, "Results", ulsched_result(raw_results->edf_coop));

    json_t *preempt_results = json_object();
    json_array_append_new(array, preempt_results);

    error = json_object_set_new(preempt_results, "Benchmark", json_string("EDF-preempt"));
    assert(error == 0);

    error = json_object_set_new(preempt_results, "Results", ulsched_result(raw_results->edf_preempt));
    assert(error == 0);

    return array;
}

static benchmark_t ulsched_benchmark = {
    .name = "ulscheduler",
    .enabled = config_set(CONFIG_APP_ULSCHEDULERBENCH),
    .results_pages = BYTES_TO_SIZE_BITS_PAGES(sizeof(ulscheduler_results_t), seL4_PageBits),
    .process = ulscheduler_process,
    .init = blank_init
};

benchmark_t *
ulscheduler_benchmark_new(void)
{
    return &ulsched_benchmark;
}

