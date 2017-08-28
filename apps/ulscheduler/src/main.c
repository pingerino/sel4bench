/*
 * Copyright 2016, NICTA
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(NICTA_BSD)
 */
#include <autoconf.h>
#include <stdio.h>

#include <sel4/sel4.h>
#include <sel4bench/arch/sel4bench.h>
#include <sel4bench/flog.h>
#include <sel4bench/sel4bench.h>
#include <sel4platsupport/timer.h>
#include <sel4utils/sched.h>
#include <sel4utils/sel4_zf_logif.h>
#include <vka/capops.h>
#include <benchmark.h>
#include <ulscheduler.h>
#ifdef CONFIG_ARCH_X86
#include <platsupport/arch/tsc.h>
#endif

#define NOPS ""
#define __SWINUM(x) ((x) & 0x00ffffff)

#define NUM_ARGS 7

#include "params.h"

void
abort(void)
{
    benchmark_finished(EXIT_FAILURE);
}

void
__arch_putchar(int c)
{
    benchmark_putchar(c);
}

typedef struct task {
    sel4utils_thread_t thread;
    cspacepath_t endpoint_path;
    vka_object_t reply;
    uint32_t id;
    char args[NUM_ARGS][WORD_STRING_SIZE];
    char *argv[NUM_ARGS];
} task_t;

typedef void (*create_fn_t)(sched_t *, env_t *, task_t *, uint64_t, uint64_t, void *, int);

static task_t tasks[NUM_TASKS + CONFIG_MIN_TASKS];

bool
sched_finished(void *cookie)
{
    size_t *count = (size_t *) cookie;
    (*count)++;
    return (*count > N_RUNS + 1);
}

static inline uint64_t
get_budget(char **argv)
{
    uint64_t budget = 0;
    if (CONFIG_WORD_SIZE == 64) {
        budget = atol(argv[3]);
    } else if (CONFIG_WORD_SIZE == 32) {
        budget = atol(argv[3]) + (((uint64_t) atol(argv[4])) << 32llu);
    } else {
        ZF_LOGF("Invalid word size");
    }

    return budget;
}

static inline uint32_t
timestamp(void)
{
#ifdef CONFIG_ARCH_X86
    return (uint32_t) rdtsc_pure();
#else
    uint32_t ts;
    SEL4BENCH_READ_CCNT(ts);
    return ts;
#endif
}

static inline void
spin(uint64_t budget)
{
    uint64_t sum = 0;
    assert(budget > 0);

    while (sum <= budget) {
        COMPILER_MEMORY_FENCE();
        uint32_t start = timestamp();
        COMPILER_MEMORY_FENCE();
        uint32_t end = timestamp();
        uint32_t diff = end - start;
        assert(diff > 0);
        if (diff < 150) {
            sum += (diff * 2);
        }
    }
}

void
edf_coop_fn(int argc, char **argv)
{
    assert(argc == NUM_ARGS);
    UNUSED int id = (int) atol(argv[0]);
    seL4_CPtr ep = (seL4_CPtr) atol(argv[1]);
    uint64_t budget = get_budget(argv);

    seL4_Call(ep, seL4_MessageInfo_new(0, 0, 0, 0));

    while (1) {
        spin(budget);
        seL4_Call(ep, seL4_MessageInfo_new(0, 0, 0, 0));
    }
}

void
cfs_coop_fn(int argc, char **argv)
{
    assert(argc == NUM_ARGS);
    UNUSED int id = (int) atol(argv[0]);
    seL4_CPtr ep = (seL4_CPtr) atol(argv[1]);
    seL4_CPtr reply = (seL4_CPtr) atol(argv[2]);
    uint64_t budget = get_budget(argv);

    seL4_NBSendRecv(ep, seL4_MessageInfo_new(0, 0, 0, 0), ep, NULL, reply);

    while (1) {
        spin(budget);
        seL4_ReplyRecv(ep, seL4_MessageInfo_new(0, 0, 0, 0), NULL, reply);
    }
}

void
edf_preempt_fn(UNUSED int argc, UNUSED char **argv)
{
    UNUSED int id = (int) atol(argv[0]);
    seL4_CPtr ep = (seL4_CPtr) atol(argv[1]);
    /* call once to wait for first release */

    seL4_Call(ep, seL4_MessageInfo_new(0, 0, 0, 0));
    while (true);
}

void
cfs_preempt_fn(UNUSED int argc, UNUSED char **argv)
{
    while (true);
}


static void
create_edf_thread(sched_t *sched, env_t *env, task_t *task, uint64_t budget, uint64_t period, void *fn, int prio)
{
    UNUSED seL4_Word error = seL4_TCB_SetPriority(task->thread.tcb.cptr, prio);
    assert(error == seL4_NoError);

    /* add the thread to the scheduler */
    struct edf_sched_add_tcb_args edf_args = {
        .tcb = task->thread.tcb.cptr,
        .period = period,
        .budget = budget,
        .reply = task->reply.cptr,
        .slot = task->endpoint_path
    };

    /* reset sched params - give thread time to start*/
    error = seL4_SchedControl_Configure(simple_get_sched_ctrl(&env->simple, 0),
                                        task->thread.sched_context.cptr,
                                        CONFIG_BOOT_THREAD_TIME_SLICE * US_IN_MS,
                                        CONFIG_BOOT_THREAD_TIME_SLICE * US_IN_MS,
                                        0, 0);
    ZF_LOGF_IFERR(error, "Failed to configure sched context");



   /* create args */
    sel4utils_create_word_args(task->args, task->argv, NUM_ARGS, task->id, task->endpoint_path.capPtr, 0, (seL4_Word) budget, (seL4_Word) (budget >> 32llu));
    /* spawn thread */
    error = sel4utils_start_thread(&task->thread, fn, (void *) NUM_ARGS, (void *) task->argv, true);
    ZF_LOGF_IFERR(error, "Failed to start thread");

    error = (seL4_Word) sched_add_tcb(sched, task->thread.sched_context.cptr, (void *) &edf_args);
    ZF_LOGF_IF(error == 0, "Failed to add tcb to scheduler");

    /* set timeout fault handler */
    seL4_CapData_t guard = seL4_CapData_Guard_new(0, seL4_WordBits -
                                                  CONFIG_SEL4UTILS_CSPACE_SIZE_BITS);
    error = seL4_TCB_SetSpace(task->thread.tcb.cptr, seL4_CapNull,
                              task->endpoint_path.capPtr, simple_get_cnode(&env->simple),
                              guard, simple_get_pd(&env->simple), seL4_NilData);
    ZF_LOGF_IFERR(error, "Failed to set space for tcb");

    /* set sched params */
    error = seL4_SchedControl_Configure(simple_get_sched_ctrl(&env->simple, 0),
                                        task->thread.sched_context.cptr,
                                        MAX(edf_args.budget / NS_IN_US, 100 * NS_IN_US),
                                        MAX(edf_args.budget / NS_IN_US, 100 * NS_IN_US),
                                        0, 0);
    ZF_LOGF_IFERR(error, "Failed to configure sched context");


}

static void
create_cfs_thread(sched_t *sched, env_t *env, task_t *task, uint64_t budget, uint64_t period, void *fn, int prio)
{
    UNUSED seL4_Word error = seL4_TCB_SetPriority(task->thread.tcb.cptr, prio);
    assert(error == seL4_NoError);

    /* set sched params */
    error = seL4_SchedControl_Configure(simple_get_sched_ctrl(&env->simple, 0),
                                        task->thread.sched_context.cptr,
                                        MAX(budget / NS_IN_US, 100 * NS_IN_US),
                                        MAX(budget / NS_IN_US, 100 * NS_IN_US),
                                        0, 0);
    ZF_LOGF_IFERR(error, "Failed to configure sched context");

    /* add the thread to the scheduler */
    struct cfs_sched_add_tcb_args cfs_args = {
        .slot = task->endpoint_path,
        .tcb = task->thread.tcb.cptr
    };

    /* create args */
    sel4utils_create_word_args(task->args, task->argv, NUM_ARGS, task->id, task->endpoint_path.capPtr,
                               task->reply.cptr, (seL4_Word) budget, (seL4_Word) (budget >> 32llu));

      /* clear timeout fault handler */
    seL4_CapData_t guard = seL4_CapData_Guard_new(0, seL4_WordBits -
                                                  CONFIG_SEL4UTILS_CSPACE_SIZE_BITS);
    error = seL4_TCB_SetSpace(task->thread.tcb.cptr, seL4_CapNull,
                              seL4_CapNull, simple_get_cnode(&env->simple),
                              guard, simple_get_pd(&env->simple), seL4_NilData);
    ZF_LOGF_IFERR(error, "Failed to set space for tcb");


    /* spawn thread */
    error = sel4utils_start_thread(&task->thread, fn, (void *) NUM_ARGS, (void *) task->argv, true);
    ZF_LOGF_IFERR(error, "Failed to start thread");

    error = (seL4_Word) sched_add_tcb(sched, task->thread.sched_context.cptr, (void *) &cfs_args);
    ZF_LOGF_IF(error == 0, "Failed to add tcb to scheduler");
}


static void
teardown_thread(vka_t *vka, vspace_t *vspace, task_t *task)
{
    vka_cnode_delete(&task->endpoint_path);
    seL4_TCB_Suspend(task->thread.tcb.cptr);
}

static void
run_benchmark(env_t *env, sched_t *sched, int num_tasks, void *client_fn, create_fn_t create_fn,
              ltimer_t *timer, ccnt_t *results, int prio)
{

    for (int run = 0; run < CONFIG_NUM_TASK_SETS; run++) {
        ZF_LOGD("Run %d/%d, %d tasks\n", run, CONFIG_NUM_TASK_SETS, num_tasks);
        for (int t = 0; t < num_tasks; t++) {
            tasks[t].id = t;
            create_fn(sched, env, &tasks[t],
                      edf_params[num_tasks - CONFIG_MIN_TASKS][run * num_tasks + t][BUDGET],
                      edf_params[num_tasks - CONFIG_MIN_TASKS][run * num_tasks + t][PERIOD],
                      client_fn, prio);
        }

        ltimer_reset(timer);
        flog_t *flog = flog_init(&results[run * N_RUNS], N_RUNS);
        assert(flog != NULL);

        size_t count = 0;
        sched_run(sched, sched_finished, &count, (void *) flog);

        for (int t = 0; t < num_tasks; t++) {
            teardown_thread(&env->slab_vka, &env->vspace, &tasks[t]);
        }

        flog_free(flog);
        sched_reset(sched);
    }
}

static void
measure_overhead(ccnt_t *results)
{
    ccnt_t start, end;
    for (int i = 0; i < N_RUNS; i++) {
        SEL4BENCH_READ_CCNT(start);
        SEL4BENCH_READ_CCNT(end);
        results[i] = (end - start);
    }
}


int
main(int argc, char **argv)
{
    env_t *env;
    UNUSED int error;
    ulscheduler_results_t *results;
    sched_t *sched;

    static size_t object_freq[seL4_ObjectTypeCount] = {
        [seL4_TCBObject] = NUM_TASKS,
        [seL4_SchedContextObject] = NUM_TASKS,
        [seL4_ReplyObject] = NUM_TASKS,
        [seL4_EndpointObject] = 2
    };

    env = benchmark_get_env(argc, argv, sizeof(ulscheduler_results_t), object_freq);
    results = (ulscheduler_results_t *) env->results;

    sel4bench_init();

    measure_overhead(results->overhead);

    /* create the tasks */
    for (int i = 0; i < NUM_TASKS; i++) {
         /* allocate a cslot for the minted ep for this process */
        if (vka_cspace_alloc_path(&env->slab_vka, &tasks[i].endpoint_path) != 0) {
            ZF_LOGF("Failed to allocate cspace path");
        }
        if (vka_alloc_reply(&env->slab_vka, &tasks[i].reply) != 0) {
            ZF_LOGF("Failed to allocate reply object");
        }

        benchmark_configure_thread(env, seL4_CapNull, seL4_MaxPrio - 1, "ulscheduled thread", &tasks[i].thread);
    }

    /* edf, threads yield immediately */
    sched = sched_new_edf(&env->timer, &env->slab_vka, SEL4UTILS_TCB_SLOT, env->ntfn.cptr);
    for (int i = 0; i < NUM_TASKS; i++) {
        ZF_LOGD("EDF coop benchmark %d/%d", i + CONFIG_MIN_TASKS, NUM_TASKS);
        run_benchmark(env, sched, i + CONFIG_MIN_TASKS, edf_coop_fn, create_edf_thread, &env->timer.ltimer,
                      results->edf_coop[i], seL4_MaxPrio - 2);
    }
    sched_destroy_scheduler(sched);
    /* edf, threads rate limited, do not yield */
    sched = sched_new_edf(&env->timer, &env->slab_vka, SEL4UTILS_TCB_SLOT, env->ntfn.cptr);
    for (int i = 0; i < NUM_TASKS; i++) {
        ZF_LOGD("EDF preempt benchmark %d/%d", i + CONFIG_MIN_TASKS, NUM_TASKS);
        run_benchmark(env, sched, i + CONFIG_MIN_TASKS, edf_preempt_fn, create_edf_thread, &env->timer.ltimer,
                      results->edf_preempt[i], seL4_MaxPrio - 2);
    }
    sched_destroy_scheduler(sched);

#if 0
    /* cfs shared sc coop benchmark */
    sched = sched_new_cooperative_cfs(&env->slab_vka, SEL4UTILS_SCHED_CONTEXT_SLOT);
    for (int i = 0; i < NUM_TASKS; i++) {
        ZF_LOGD("CFS coop benchmark %d/%d", i + CONFIG_MIN_TASKS, NUM_TASKS);
        run_benchmark(env, sched, i + CONFIG_MIN_TASKS, cfs_coop_fn, create_cfs_thread,
                      env->clock_timer->timer, results->cfs_coop[i], seL4_MaxPrio - 2);
    }
    sched_destroy_scheduler(sched);

    /* cfs preemptive non-shared sc */
    sched = sched_new_preemptive_cfs();
    for (int i = 0; i < NUM_TASKS; i++) {
        ZF_LOGD("CFS preempt benchmark %d/%d", i + CONFIG_MIN_TASKS, NUM_TASKS);
        run_benchmark(env, sched, i + CONFIG_MIN_TASKS, cfs_preempt_fn, create_cfs_thread,
                      env->clock_timer->timer, results->cfs_preempt[i], seL4_MaxPrio);
    }
    sched_destroy_scheduler(sched);

#endif
    /* done -> results are stored in shared memory so we can now return */
    benchmark_finished(EXIT_SUCCESS);
    return 0;
}

