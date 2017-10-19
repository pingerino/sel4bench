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
#include <autoconf.h>
#include <stdio.h>

#include <sel4/sel4.h>
#include <sel4bench/arch/sel4bench.h>

#include <benchmark.h>
#include <vka/capops.h>
#include <vka/vka.h>

#include <aes/crypto.h>
#include <aes/rijndael-alg-fst.h>

#include <aes.h>
#include <sel4/benchmark_utilisation_types.h>

typedef struct {
    uint8_t *vector;
    uint8_t *pt;
    uint8_t *ct;
    size_t len;
} state_t;

#define N_TIMEOUT_ARGS 3
#define N_CLIENTS 10

static aes_results_t *results = NULL;

/* server state */
static volatile state_t *st = NULL;
static uint8_t dummy_pt[4096 * 1000];
static uint8_t dummy_ct[sizeof(dummy_pt)];
static uint8_t dummy_iv[] = {0};
static uint32_t rk[4 * (AES256_KEY_ROUNDS + 1)];

static sel4utils_checkpoint_t cp;
static sel4utils_thread_t tfep_thread;
static sel4utils_thread_t server_thread;
static sel4utils_thread_t clients[N_CLIENTS];

/* EP for client <-> server communication */
static vka_object_t ep;
/* EP clients use to signal they are finished */
static vka_object_t done_ep;
/* EP server uses to initialise */
static vka_object_t init_ep;
/* EP clients block on when they are done */
static vka_object_t stop_ep;
/* Timeout fault EP */
static vka_object_t timeout_ep;

static seL4_CPtr sched_ctrl;
#define THROUGHPUT_SIZE (sizeof(dummy_pt))

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

void server_fn(void *arg0, void *arg1, void *arg2)
{
    state_t s2, s;
    st = NULL;

    /* init */
    uint8_t key[AES256_KEY_BITS / 8];
    for (unsigned i = 0; i < sizeof key; i++)
             key[i] = i;



    ZF_LOGV("Server started\n");
    seL4_NBSendRecv(init_ep.cptr, seL4_MessageInfo_new(0, 0, 0, 0), ep.cptr, NULL, server_thread.reply.cptr);

    for (int req = 0; true; req++) {
        assert(st == NULL);

        // XXX: Unpack state into `s`
        s.vector = (uint8_t *) seL4_GetMR(0);
        if (s.vector == NULL) {
            /* new request */
            s.pt = dummy_pt;
            s.ct = dummy_ct;
            s.len = seL4_GetMR(3);
            s.vector = dummy_iv;
        } else {
            /* continued request */
            s.pt = (uint8_t *) seL4_GetMR(1);
            s.ct = (uint8_t *) seL4_GetMR(2);
            s.len = (size_t) seL4_GetMR(3);
        }

        st = &s;

        while (st->len > 0) {
            assert(st->len <= sizeof(dummy_pt));
            uint8_t pt_block[AES_BLOCK_SIZE];
            for (unsigned i = 0; i < AES_BLOCK_SIZE; i++) {
                pt_block[i] = st->pt[i] ^ st->vector[i];
            }

            rijndaelEncrypt(rk, AES256_KEY_ROUNDS, pt_block, st->ct);

            if (st == &s) {
            /* swap to s2 */
                s2.vector = st->ct;
                s2.pt = st->pt + AES_BLOCK_SIZE;
                s2.ct = st->ct + AES_BLOCK_SIZE;
                s2.len = st->len - AES_BLOCK_SIZE;
                COMPILER_MEMORY_FENCE();
                st = &s2;
            } else {
                /* swap to s */
                s.vector = st->ct;
                s.pt = st->pt + AES_BLOCK_SIZE;
                s.ct = st->ct + AES_BLOCK_SIZE;
                s.len = st->len - AES_BLOCK_SIZE;
                COMPILER_MEMORY_FENCE();
                st = &s;
            }
        }
        ZF_LOGV("Done ");
        seL4_SetMR(3, 0);
        seL4_ReplyRecv(ep.cptr, seL4_MessageInfo_new(0, 0, 0, 4), NULL, server_thread.reply.cptr);
        st = NULL;
    }

    /* server never exits */
}

void
client_fn(void *arg0, void *arg1, void *arg2)
{
    seL4_Word mr0 = 0;
    seL4_Word mr1 = 0;
    seL4_Word mr2 = 0;
    seL4_Word mr3 = 0;
    while (true) {
		if (mr3 == 0) {
            mr0 = 0;
            mr3 = sizeof(dummy_pt);
        }
        seL4_CallWithMRs(ep.cptr, seL4_MessageInfo_new(0, 0, 0, 4), &mr0, &mr1, &mr2, &mr3);
    }
}

void
counting_client_fn(void *arg0, void *arg1, void *arg2)
{
    uint64_t *res = arg1;
    seL4_MessageInfo_t info = seL4_MessageInfo_new(0, 0, 0, 4);
    /* set MR0 to 0 for the first request */
    seL4_Word mr0 = 0;
    seL4_Word mr1 = 0;
    seL4_Word mr2 = 0;
    seL4_Word mr3 = THROUGHPUT_SIZE;

    ccnt_t start, end;
    SEL4BENCH_READ_CCNT(start);
    while (mr3 > 0) {
        info = seL4_CallWithMRs(ep.cptr, info, &mr0, &mr1, &mr2, &mr3);
    }
    SEL4BENCH_READ_CCNT(end);
    *res = end - start;

    seL4_Send(done_ep.cptr, info);
    seL4_Wait(stop_ep.cptr, NULL);
}

static inline void
kill_child(seL4_CPtr ep)
{
    /* invoke the reply cap  - this will return the client sc along the call chain */
    seL4_Send(server_thread.reply.cptr, seL4_MessageInfo_new(0, 0, 0, 0));

    //give server time to get back on ep (or could extend client budget)
    int error = seL4_SchedContext_Bind(server_thread.sched_context.cptr, server_thread.tcb.cptr);
    ZF_LOGF_IF(error != 0, "Failed to bind sc to server");

    ZF_LOGV("Killed client\n");
    /* restore server */
    st = NULL;
    sel4utils_checkpoint_restore(&cp, false, true);

    ZF_LOGV("Waiting for server to reply\n");
    // wait for server to init and take context back
    seL4_Wait(init_ep.cptr, NULL);

    /* convert server back to passive */
    error = seL4_SchedContext_Unbind(server_thread.sched_context.cptr);
    ZF_LOGF_IF(error != 0, "Failed to unbind sc from server");
}

void restart_clients(void)
{
    /* restart clients for more murder */
    for (int i = 0; i < N_CLIENTS; i++) {
        int error = seL4_TCB_Resume(clients[i].tcb.cptr);
        ZF_LOGF_IF(error != seL4_NoError, "Failed to restart client");
    }
}

/* timeout fault handler for killing clients */
void
tfep_fn_kill(int argc, char **argv)
{
    ccnt_t start, end;
    seL4_Word badge, data;

    ZF_LOGV("TFE started\n");

    /* hot cache */
    for (int j = 0; j < (N_RUNS / N_CLIENTS); j++) {
        for (int i = 0; i < N_CLIENTS; i++) {
            seL4_Wait(timeout_ep.cptr, &badge);
            data = seL4_GetMR(seL4_Timeout_Data);
            ZF_LOGV("Fault from %"PRIuPTR"\n", data);
            assert(data < N_CLIENTS);
            SEL4BENCH_READ_CCNT(start);
            kill_child(ep.cptr);
            SEL4BENCH_READ_CCNT(end);
            results->kill_cost[j * (N_CLIENTS) + i] = end - start;
        }
        restart_clients();
    }

    /* cold cache */
    for (int j = 0; j < N_RUNS / N_CLIENTS; j++) {
        for (int i = 0; i < N_CLIENTS; i++) {
            seL4_Wait(timeout_ep.cptr, &badge);
            data = seL4_GetMR(seL4_Timeout_Data);
            ZF_LOGV("Fault from %"PRIuPTR"\n", data);
            assert(data < N_CLIENTS);
            seL4_BenchmarkFlushCaches();
            SEL4BENCH_READ_CCNT(start);
            kill_child(ep.cptr);
            SEL4BENCH_READ_CCNT(end);
            results->kill_cost_cold[j * (N_CLIENTS) + i] = end - start;
        }
        restart_clients();
    }

    seL4_Send(done_ep.cptr, seL4_MessageInfo_new(0, 0, 0, 0));
    seL4_Wait(stop_ep.cptr, NULL);
}

static inline void
handle_timeout_extend(seL4_CPtr sched_ctrl, seL4_Word data, uint64_t more, uint64_t period)
{
    /* give the client more budget */
    int error = seL4_SchedControl_Configure(sched_ctrl, clients[data].sched_context.cptr, more, period, 0, data);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to extend budget");
}

static inline void
handle_timeout_emergency_budget(seL4_Word data, seL4_CPtr reply)
{
    /* for this timeout fault handler, we give the server some extra budget,
     * we run at higher prio to the server to we call into its queue and take the budget
     * away once it responds
     */

    /* take away clients sc from the server */
    int error = seL4_SchedContext_UnbindObject(clients[data].sched_context.cptr, server_thread.tcb.cptr);
    ZF_LOGF_IF(error != seL4_NoError, "failed to unbind client sc from server");

    /* bind server with emergency budget */
    error = seL4_SchedContext_Bind(server_thread.sched_context.cptr, server_thread.tcb.cptr);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to bind server emergency budget");

    /* reply to the timeout fault */
    seL4_Send(reply, seL4_MessageInfo_new(0, 0, 0, 0));
}

static inline void
handle_timeout_rollback(seL4_CPtr ep, seL4_Word badge)
{
    /* restore client */
    if (st != NULL) {
        ZF_LOGV("Restored client %"PRIuPTR", %"PRIuPTR" left\n", badge, st->len);
        seL4_SetMR(0, (seL4_Word) st->vector);
        seL4_SetMR(1, (seL4_Word) st->pt);
        seL4_SetMR(2, (seL4_Word) st->ct);
        seL4_SetMR(3, (seL4_Word) st->len);
    } else {
        ZF_LOGV("Failed\n");
        seL4_SetMR(3, THROUGHPUT_SIZE);
    }
    /* reply to client */
    seL4_Send(server_thread.reply.cptr, seL4_MessageInfo_new(0, 0, 0, 4));

    st = NULL;
    sel4utils_checkpoint_restore(&cp, false, true);
    //give server time to get back on ep (or could extend client budget)
    UNUSED int error = seL4_SchedContext_Bind(server_thread.sched_context.cptr, server_thread.tcb.cptr);
    assert(error == 0);

     // wait for server to init and take context back
    seL4_Wait(init_ep.cptr, NULL);

    /* convert server back to passive */
    error = seL4_SchedContext_Unbind(server_thread.sched_context.cptr);
    assert(error == 0);
}

void
tfep_fn_emergency_budget(int argc, char **argv)
{
    seL4_Word badge;
    ccnt_t start, end;
     for (int i = 0; i < N_RUNS; i++) {
        seL4_Recv(timeout_ep.cptr, &badge, tfep_thread.reply.cptr);
        ZF_LOGV("%d/%d Fault from %"PRIuPTR"\n", i, N_RUNS, seL4_GetMR(0));
        SEL4BENCH_READ_CCNT(start);
        handle_timeout_emergency_budget(seL4_GetMR(seL4_Timeout_Data), tfep_thread.reply.cptr);
        /* call the server with a fake finished request */
        seL4_SetMR(0, 0xdeadbeef);
        seL4_SetMR(3, 0);
        SEL4BENCH_READ_CCNT(end);
        results->emergency_cost[i] = end - start;
        seL4_Call(ep.cptr, seL4_MessageInfo_new(0, 0, 0, 4));
        /* server is done! remove emergency budget */
        seL4_SchedContext_Unbind(server_thread.sched_context.cptr);
     }

    /* cold cache */
    for (int i = 0; i < N_RUNS; i++) {
        seL4_Recv(timeout_ep.cptr, &badge, tfep_thread.reply.cptr);
        ZF_LOGV("%d/%d cold Fault from %"PRIuPTR"\n", i, N_RUNS, seL4_GetMR(0));
        seL4_BenchmarkFlushCaches();
        SEL4BENCH_READ_CCNT(start);
        handle_timeout_emergency_budget(seL4_GetMR(seL4_Timeout_Data), tfep_thread.reply.cptr);
        seL4_SetMR(0, 0xdeadbeef);
        seL4_SetMR(3, 0);
        SEL4BENCH_READ_CCNT(end);
        results->emergency_cost_cold[i] = end - start;
        seL4_Call(ep.cptr, seL4_MessageInfo_new(0, 0, 0, 4));
        /* server is done! remove emergency budget */
        seL4_SchedContext_Unbind(server_thread.sched_context.cptr);
    }

    /* finished */
	seL4_Send(done_ep.cptr, seL4_MessageInfo_new(0, 0, 0, 0));
    seL4_Wait(stop_ep.cptr, NULL);
}

/* timeout fault handler for doing rollbacks */
void
tfep_fn_rollback(int argc, char **argv)
{
    ZF_LOGV("TFE started\n");
    ccnt_t start, end;
    seL4_Word badge;

    /* hot cache */
    for (int i = 0; i < N_RUNS; i++) {
        seL4_Recv(timeout_ep.cptr, &badge, tfep_thread.reply.cptr);
        ZF_LOGV("Fault from %"PRIuPTR"\n", seL4_GetMR(0));
        SEL4BENCH_READ_CCNT(start);
        handle_timeout_rollback(0, badge);
        SEL4BENCH_READ_CCNT(end);
        results->rollback_cost[i] = end - start;
    }

    /* cold cache */
    for (int i = 0; i < N_RUNS; i++) {
        seL4_Recv(timeout_ep.cptr, &badge, tfep_thread.reply.cptr);
        ZF_LOGV("Fault from %"PRIuPTR"\n", seL4_GetMR(0));
        seL4_BenchmarkFlushCaches();
        SEL4BENCH_READ_CCNT(start);
        handle_timeout_rollback(0, badge);
        SEL4BENCH_READ_CCNT(end);
        results->rollback_cost_cold[i] = end - start;
        ZF_LOGV("Recorded cost "CCNT_FORMAT, results->rollback_cost_cold[i]);
    }

    /* finished */
	seL4_Send(done_ep.cptr, seL4_MessageInfo_new(0, 0, 0, 0));
    seL4_Wait(stop_ep.cptr, NULL);
}

void tfep_fn_rollback_infinite(int arc, char **argv) {

    while (1) {
        seL4_Word badge;
        seL4_Recv(timeout_ep.cptr, &badge, tfep_thread.reply.cptr);
        badge = seL4_GetMR(seL4_Timeout_Data);
        handle_timeout_rollback(0, badge);
    }
}

void
reset_budgets(seL4_CPtr sched_ctrl, uint64_t budgets[N_CLIENTS])
{
    for (int i = 0; i < N_CLIENTS; i++) {
        budgets[i] = 1 * US_IN_MS;
        int error = seL4_SchedControl_Configure(sched_ctrl, clients[i].sched_context.cptr, budgets[i],
                100 * US_IN_MS, 0, i);
        ZF_LOGF_IF(error != seL4_NoError, "Failed to configure sc");
    }
}

/* timeout fault handler for doing rollbacks */
void
tfep_fn_extend(int argc, char **argv)
{
    ZF_LOGV("TFE started\n");
    ccnt_t start, end;
    seL4_Word badge;
    uint64_t budgets[N_CLIENTS] = {0};

    seL4_Recv(timeout_ep.cptr, &badge, tfep_thread.reply.cptr);
    seL4_Word data = seL4_GetMR(seL4_Timeout_Data);
    /* run this N_CLIENTSx to get the results we want */
    for (int j = 0; j < N_CLIENTS + 1; j++) {
        /* set the clients budgets to be small */
        /* hot cache */
        for (int i = 0; i < N_CLIENTS; i++) {
            ZF_LOGV("Fault from %"PRIuPTR"\n", data);
            assert(data < N_CLIENTS);
            budgets[data] += US_IN_MS;
            SEL4BENCH_READ_CCNT(start);
            handle_timeout_extend(sched_ctrl, data, budgets[data], 100 * US_IN_MS);
            SEL4BENCH_READ_CCNT(end);
            results->extend_cost[j * N_CLIENTS + i] = end - start;
            seL4_ReplyRecv(timeout_ep.cptr, seL4_MessageInfo_new(0, 0, 0, 0), &badge, tfep_thread.reply.cptr);
            data = seL4_GetMR(seL4_Timeout_Data);
        }

        /* cold cache */
        reset_budgets(sched_ctrl, budgets);
        for (int i = 0; i < N_CLIENTS; i++) {
                ZF_LOGV("Fault from %"PRIiPTR"\n", data);
                budgets[data] += US_IN_MS;
                seL4_BenchmarkFlushCaches();
                SEL4BENCH_READ_CCNT(start);
                handle_timeout_extend(sched_ctrl, data, budgets[data], 100 * US_IN_MS);
                SEL4BENCH_READ_CCNT(end);
                results->extend_cost_cold[j * N_CLIENTS + i] = end - start;
                seL4_ReplyRecv(timeout_ep.cptr, seL4_MessageInfo_new(0, 0, 0, 0), &badge, tfep_thread.reply.cptr);
                data = seL4_GetMR(seL4_Timeout_Data);
        }
       reset_budgets(sched_ctrl, budgets);
    }

    /* finished */
    seL4_Send(tfep_thread.reply.cptr, seL4_MessageInfo_new(0, 0, 0, 0));
	seL4_Send(done_ep.cptr, seL4_MessageInfo_new(0, 0, 0, 0));
    seL4_Wait(stop_ep.cptr, NULL);
}

void
measure_ccnt_overhead(ccnt_t *results)
{
    ccnt_t start, end;
    for (int i = 0; i < N_RUNS; i++) {
        SEL4BENCH_READ_CCNT(start);
        SEL4BENCH_READ_CCNT(end);
        results[i] = (end - start);
    }
}

void reset_sc(env_t *env, uint64_t budget, uint64_t period, uint32_t refills, uint32_t badge,
              sel4utils_thread_t *thread)
{
    /* unbind the sc before reconfiguring so we start afresh */
    int error = seL4_SchedContext_Unbind(thread->sched_context.cptr);
    ZF_LOGF_IF(error, "Failed to unbind sc");

    error = seL4_SchedControl_Configure(simple_get_sched_ctrl(&env->simple, 0),
            thread->sched_context.cptr, budget, period, refills, badge);
    ZF_LOGF_IF(error, "Failed to configure sc");

    error = seL4_SchedContext_Bind(thread->sched_context.cptr, thread->tcb.cptr);
    ZF_LOGF_IF(error, "Failed to rebind sc");
}

/* start the server and the timeout fault handler */
void benchmark_start_server_tf(env_t *env, void *timeout_fn) {
    /* we use the servers sc as a backup for init -> don't let it run out */
    reset_sc(env, 100000 * US_IN_S, 100000 * US_IN_S, 0, 0, &server_thread);
    /* don't let the timeout fault handler run out either */
    reset_sc(env, 100000 * US_IN_S, 100000 * US_IN_S, 0, 0, &tfep_thread);

    int error = sel4utils_start_thread(&tfep_thread, timeout_fn, NULL, NULL, true);
    ZF_LOGF_IF(error != 0, "Failed to start tfep thread");

    /* let it initialise */
    error = seL4_TCB_SetPriority(simple_get_tcb(&env->simple), seL4_MinPrio);
    ZF_LOGF_IF(error, "failed to set own prio");

    error = seL4_TCB_SetPriority(simple_get_tcb(&env->simple), seL4_MaxPrio);
    ZF_LOGF_IF(error, "failed to set own prio");

    /* start the server */
    error = sel4utils_start_thread(&server_thread, server_fn, (void *) ep.cptr,
            (void *) server_thread.reply.cptr, true);
    ZF_LOGF_IF(error != 0, "Failed to start server");

    /* wait for server to init and convert to passive */
    seL4_Wait(init_ep.cptr, NULL);
    error = seL4_SchedContext_Unbind(server_thread.sched_context.cptr);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to convert server to passive");

    /* checkpoint server */
    sel4utils_checkpoint_thread(&server_thread, &cp, false);
}

void
benchmark_setup(env_t *env, void *timeout_fn)
{
    benchmark_start_server_tf(env, timeout_fn);

    /* start the clients */
    for (int i = 0; i < N_CLIENTS; i++) {
        reset_sc(env, 5 * US_IN_MS, 10 * US_IN_MS, 0, i, &clients[i]);
        /* start the client */
        int error = sel4utils_start_thread(&clients[i], client_fn, NULL, NULL, true);
        ZF_LOGF_IF(error != seL4_NoError, "failed to start client %d\n", i);
    }
}

void
benchmark_teardown(env_t *env)
{
    /* kill the clients */
    UNUSED int error;
    for (int i = 0; i < N_CLIENTS; i++) {
        error = seL4_TCB_Suspend(clients[i].tcb.cptr);
        assert(error == seL4_NoError);
    }

    /* kill the server */
    error = seL4_TCB_Suspend(server_thread.tcb.cptr);
    assert(error == seL4_NoError);
    sel4utils_free_checkpoint(&cp);

    /* rebind servers sc */
    error = seL4_SchedContext_Bind(server_thread.sched_context.cptr,
                                   server_thread.tcb.cptr);
    assert(error == seL4_NoError);

    /* kill the tfep */
    error = seL4_TCB_Suspend(tfep_thread.tcb.cptr);
    assert(error == seL4_NoError);
}

static void benchmark_throughput(uint64_t step, uint64_t period, tput_results_t *results, env_t *env)
{

    /* reset timeout fault ep */
    seL4_CapData_t guard = seL4_CapData_Guard_new(0, seL4_WordBits - CONFIG_SEL4UTILS_CSPACE_SIZE_BITS);
    int error = seL4_TCB_SetSpace(server_thread.tcb.cptr, seL4_CapNull, timeout_ep.cptr,
                              SEL4UTILS_CNODE_SLOT, guard, SEL4UTILS_PD_SLOT,
                              seL4_CapData_Guard_new(0, 0));

    for (int i = 0; i < N_THROUGHPUT; i++) {
        /* configure A */
        uint64_t a_budget = get_budget_for_index(i, step);
        uint64_t b_budget = period - a_budget;
        seL4_Word refills = 0;//seL4_MaxExtraRefills(seL4_MinSchedContextBits);
        ZF_LOGD("A: %"PRIu64"/%"PRIu64, a_budget, (uint64_t) period);
        ZF_LOGD("B: %"PRIu64"/%"PRIu64, b_budget, (uint64_t) period);

        for (int j = 0; j  < N_RUNS; j++) {
            ZF_LOGD("Throughput %d: %d\n", i, j);
            /* start the server and timeout fault handler */
            benchmark_start_server_tf(env, tfep_fn_rollback_infinite);

            if (a_budget) {
                reset_sc(env, a_budget, period, refills, 1, &clients[0]);
                error = sel4utils_start_thread(&clients[0], counting_client_fn,
                        (void *) ep.cptr, (void *) &results->A[i][j], true);
                ZF_LOGF_IF(error, "Failed to start A");
            } else {
                results->A[i][j] = 0;
            }

            if (b_budget) {
                reset_sc(env, b_budget, period, refills, 2, &clients[1]);
                error = sel4utils_start_thread(&clients[1], counting_client_fn,
                        (void *) ep.cptr, (void *) &results->B[i][j], true);
                ZF_LOGF_IF(error, "Failed to start B");
            } else {
                results->B[i][j] = 0;
            }


            uint64_t *ipcbuffer = (uint64_t *) &(seL4_GetIPCBuffer()->msg[0]);
            seL4_BenchmarkResetLog();

            benchmark_wait_children(done_ep.cptr, "B", !!a_budget + !!b_budget);
            ZF_LOGV("Got "CCNT_FORMAT" "CCNT_FORMAT"\n", results->A[i][j], results->B[i][j]);
            seL4_BenchmarkFinalizeLog();
            results->util[i][j] = ipcbuffer[BENCHMARK_TOTAL_UTILISATION] - ipcbuffer[BENCHMARK_IDLE_UTILISATION];
            seL4_TCB_Suspend(clients[0].tcb.cptr);
            seL4_TCB_Suspend(clients[1].tcb.cptr);
            seL4_TCB_Suspend(server_thread.tcb.cptr);
            seL4_TCB_Suspend(tfep_thread.tcb.cptr);
        }
    }

    ZF_LOGD("Running base line throughput benchmark");

    /* remove the servers tfep */
    error = seL4_TCB_SetSpace(server_thread.tcb.cptr, seL4_CapNull, seL4_CapNull,
                              SEL4UTILS_CNODE_SLOT, guard, SEL4UTILS_PD_SLOT,
                              seL4_CapData_Guard_new(0, 0));
    for (int i = 0; i < N_THROUGHPUT; i++) {
        uint64_t a_budget = get_budget_for_index(i, step);
        for (int j = 0; j < N_RUNS; j++) {
            if (a_budget) {
                benchmark_start_server_tf(env, tfep_fn_rollback_infinite);
                reset_sc(env, a_budget, period, 0, 1, &clients[0]);
                error = sel4utils_start_thread(&clients[0], counting_client_fn,
                        (void *) ep.cptr, (void *) &results->baseline[i][j], true);
                ZF_LOGF_IF(error, "Failed to start A");
                benchmark_wait_children(done_ep.cptr, "A", 1);
                seL4_TCB_Suspend(clients[0].tcb.cptr);
                seL4_TCB_Suspend(server_thread.tcb.cptr);
                seL4_TCB_Suspend(tfep_thread.tcb.cptr);
            } else {
                results->baseline[i][j] = 0;
            }
        }
    }
}


static size_t object_freq[seL4_ObjectTypeCount] = {0};

int
main(int argc, char **argv)
{
    UNUSED int error;

    object_freq[seL4_TCBObject] = 2 + N_CLIENTS;
    object_freq[seL4_EndpointObject] = 4;
    object_freq[seL4_ReplyObject] = 2 + N_CLIENTS;
    object_freq[seL4_SchedContextObject] = 2 + N_CLIENTS;

    sel4bench_init();
    env_t *env = benchmark_get_env(argc, argv, sizeof(aes_results_t), object_freq);
    results = (aes_results_t *) env->results;

    sched_ctrl = simple_get_sched_ctrl(&env->simple, 0);

    measure_ccnt_overhead(results->overhead);

    /* allocate an ep for client <-> server */
    error = vka_alloc_endpoint(&env->slab_vka, &ep);
    ZF_LOGF_IF(error != 0, "Failed to allocate ep");

    /* allocate an init ep for server <-> tfep */
    error = vka_alloc_endpoint(&env->slab_vka, &init_ep);
    ZF_LOGF_IF(error != 0, "Failed to allocate ep");

    /* allocate a timeout ep */
    error = vka_alloc_endpoint(&env->slab_vka, &timeout_ep);
    ZF_LOGF_IF(error != 0, "Failed to allocate tfep");

    /* create an ep for clients to signal on when they are done */
    error = vka_alloc_endpoint(&env->slab_vka, &done_ep);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to allocate ep");

    /* create an ep for clients to block on when they are done */
    error = vka_alloc_endpoint(&env->slab_vka, &stop_ep);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to allocate ep");

    /* allocate threads */
    benchmark_configure_thread(env, 0, seL4_MaxPrio - 2, "server", &server_thread);
    benchmark_configure_thread(env, 0, seL4_MaxPrio - 1, "tfep", &tfep_thread);
    for (int i = 0; i < N_CLIENTS; i++) {
        benchmark_configure_thread(env, 0, seL4_MaxPrio - 3, "client", &clients[i]);
    }

    /* set servers tfep */
    seL4_CapData_t guard = seL4_CapData_Guard_new(0, seL4_WordBits - CONFIG_SEL4UTILS_CSPACE_SIZE_BITS);
    error = seL4_TCB_SetSpace(server_thread.tcb.cptr, seL4_CapNull, timeout_ep.cptr,
                              SEL4UTILS_CNODE_SLOT, guard, SEL4UTILS_PD_SLOT,
                              seL4_CapData_Guard_new(0, 0));
    ZF_LOGD("Starting rollback benchmark\n");
    benchmark_setup(env, tfep_fn_rollback);
    /* wait for timeout fault handler to finish - it will exit once it has enough samples */
    benchmark_wait_children(done_ep.cptr, "tfep", 1);
    benchmark_teardown(env);

    /* next benchmark - use emergency sc's instead */
    ZF_LOGD("Starting emergency budget benchmark\n");
    benchmark_setup(env, tfep_fn_emergency_budget);
    benchmark_wait_children(done_ep.cptr, "tfep", 1);
    benchmark_teardown(env);

    ZF_LOGD("Running extend benchmark");
    benchmark_setup(env, tfep_fn_extend);
    benchmark_wait_children(done_ep.cptr, "tfep-extend", 1);
    benchmark_teardown(env);

    ZF_LOGD("Running kill benchmark");
    benchmark_setup(env, tfep_fn_kill);
    benchmark_wait_children(done_ep.cptr, "tfep-kill", 1);
    benchmark_teardown(env);

    ZF_LOGD("Running shared passive server benchmark");
    benchmark_throughput(BUDGET, PERIOD, &results->ten_ms, env);
    benchmark_throughput(BUDGET * 10, PERIOD * 10, &results->hundred_ms, env);
    benchmark_throughput(BUDGET* 100, PERIOD * 100, &results->thousand_ms, env);
   /* done -> results are stored in shared memory so we can now return */
    benchmark_finished(EXIT_SUCCESS);
    return 0;
}

