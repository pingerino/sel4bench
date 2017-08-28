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

#include "crypto.h"
#include "rijndael-alg-fst.h"

#include <aes.h>

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
static cspacepath_t slot;
static seL4_CPtr done_ep;
static seL4_CPtr init_ep;
static seL4_CPtr stop_ep;

#define THROUGHPUT_SIZE (1024 * 1024)

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

void server_fn(seL4_CPtr ep, seL4_CPtr reply)
{
    state_t s2, s;
    st = NULL;

    /* init */
    uint8_t key[AES256_KEY_BITS / 8];
    for (unsigned i = 0; i < sizeof key; i++)
             key[i] = i;



    ZF_LOGV("Server started\n");
    seL4_NBSendRecv(init_ep, seL4_MessageInfo_new(0, 0, 0, 0), ep, NULL, reply);

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
        seL4_ReplyRecv(ep, seL4_MessageInfo_new(0, 0, 0, 4), NULL, reply);
        st = NULL;
    }

    /* server never exits */
}

void
client_fn(seL4_CPtr ep, seL4_CPtr unused)
{
    seL4_Word mr0, mr1, mr2, mr3;

    mr3 = 0;
    while (true) {
		if (mr3 != 0) {
            seL4_SetMR(0, mr0);
            seL4_SetMR(1, mr1);
            seL4_SetMR(2, mr2);
            seL4_SetMR(3, mr3);
        } else {
            seL4_SetMR(0, 0);
            seL4_SetMR(3, sizeof(dummy_pt));
        }

        seL4_Call(ep, seL4_MessageInfo_new(0, 0, 0, 4));

        mr0 = seL4_GetMR(0);
        mr1 = seL4_GetMR(1);
        mr2 = seL4_GetMR(2);
        mr3 = seL4_GetMR(3);
    }
}

void
counting_client_fn(seL4_CPtr ep, uint64_t *res)
{
    seL4_MessageInfo_t info = seL4_MessageInfo_new(0, 0, 0, 4);
    /* set MR0 to 0 for the first request */
    seL4_Word mr0 = 0;
    seL4_Word mr1 = 0;
    seL4_Word mr2 = 0;
    seL4_Word mr3 = THROUGHPUT_SIZE;

    ccnt_t start, end;
    SEL4BENCH_READ_CCNT(start);
    while (mr3 > 0) {
        info = seL4_CallWithMRs(ep, info, &mr0, &mr1, &mr2, &mr3);
        /* did not make any progress */
        if (mr3 >= THROUGHPUT_SIZE) {
            ZF_LOGF("Failed to make progress\n");
        }
    }
    SEL4BENCH_READ_CCNT(end);
    *res = end - start;

    seL4_Send(done_ep, info);
    seL4_Wait(stop_ep, NULL);
}

static inline void
kill_child(seL4_CPtr ep)
{
    /* invoke the reply cap  - this will return the client sc along the call chain */
    seL4_Send(slot.capPtr, seL4_MessageInfo_new(0, 0, 0, 0));

    //give server time to get back on ep (or could extend client budget)
    int error = seL4_SchedContext_Bind(server_thread.sched_context.cptr, server_thread.tcb.cptr);
    ZF_LOGF_IF(error != 0, "Failed to bind sc to server");

    ZF_LOGD("Killed client\n");
    /* restore server */
    st = NULL;
    sel4utils_checkpoint_restore(&cp, false, true);

    ZF_LOGD("Waiting for server to reply\n");
    // wait for server to init and take context back
    seL4_Wait(init_ep, NULL);

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
    seL4_CPtr tfep = atol(argv[0]);
    seL4_CPtr ep   = atol(argv[1]);
    ccnt_t start, end;
    seL4_Word badge, data;

    ZF_LOGV("TFE started\n");
    seL4_Wait(tfep, &badge);
    data = seL4_GetMR(seL4_Timeout_Data);

    /* hot cache */
    for (int j = 0; j < (N_RUNS / N_CLIENTS); j++) {
        for (int i = 0; i < N_CLIENTS; i++) {
            ZF_LOGV("Fault from %d\n", data);
            assert(data < N_CLIENTS);
            SEL4BENCH_READ_CCNT(start);
            kill_child(ep);
            SEL4BENCH_READ_CCNT(end);
            results->kill_cost[j * (N_CLIENTS) + i] = end - start;
        }
        restart_clients();
    }

    /* cold cache */
    for (int j = 0; j < N_RUNS / N_CLIENTS; j++) {
        for (int i = 0; i < N_CLIENTS; i++) {
            ZF_LOGV("Fault from %d\n", data);
            assert(data < N_CLIENTS);
            seL4_BenchmarkFlushCaches();
            SEL4BENCH_READ_CCNT(start);
            kill_child(ep);
            SEL4BENCH_READ_CCNT(end);
            results->kill_cost_cold[j * (N_CLIENTS) + i] = end - start;
        }
        restart_clients();
    }

    seL4_Send(done_ep, seL4_MessageInfo_new(0, 0, 0, 0));
    seL4_Wait(stop_ep, NULL);
}

static inline void
handle_timeout_extend(seL4_CPtr sched_ctrl, seL4_Word data, uint64_t more, uint64_t period)
{
    /* give the client more budget */
    int error = seL4_SchedControl_Configure(sched_ctrl, clients[data].sched_context.cptr, more, period, 0, data);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to extend budget");
}

static inline void
handle_timeout_emergency_budget(seL4_CPtr ep, seL4_Word data, seL4_CPtr reply)
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

    ZF_LOGV("Call server\n");
    seL4_Send(reply, seL4_MessageInfo_new(0, 0, 0, 0));
}

static inline void
handle_timeout_rollback(seL4_CPtr ep, seL4_Word badge)
{
    /* restore client */
    if (st != NULL) {
        ZF_LOGV("Restored client %d, %u left\n", badge, st->len);
        seL4_SetMR(0, (seL4_Word) st->vector);
        seL4_SetMR(1, (seL4_Word) st->pt);
        seL4_SetMR(2, (seL4_Word) st->ct);
        seL4_SetMR(3, (seL4_Word) st->len);
    } else {
        ZF_LOGV("Failed\n");
        seL4_SetMR(3, sizeof(dummy_pt));
    }
    /* reply to client */
    seL4_Send(slot.capPtr, seL4_MessageInfo_new(0, 0, 0, 4));

    st = NULL;
    sel4utils_checkpoint_restore(&cp, false, true);
    //give server time to get back on ep (or could extend client budget)
    UNUSED int error = seL4_SchedContext_Bind(server_thread.sched_context.cptr, server_thread.tcb.cptr);
    assert(error == 0);

     // wait for server to init and take context back
    seL4_Wait(init_ep, NULL);

    /* convert server back to passive */
    error = seL4_SchedContext_Unbind(server_thread.sched_context.cptr);
    assert(error == 0);
}

void
tfep_fn_emergency_budget(int argc, char **argv)
{
    seL4_CPtr tfep = atol(argv[0]);
    seL4_CPtr ep   = atol(argv[1]);
    seL4_CPtr reply = atol(argv[2]);

    seL4_Word badge;
    ccnt_t start, end;
     for (int i = 0; i < N_RUNS; i++) {
        seL4_Recv(tfep, &badge, reply);
        ZF_LOGV("Fault from %d\n", seL4_GetMR(0));
        SEL4BENCH_READ_CCNT(start);
        handle_timeout_emergency_budget(ep, seL4_GetMR(seL4_Timeout_Data), reply);
        /* call the server with a fake finished request */
        seL4_SetMR(0, 0xdeadbeef);
        seL4_SetMR(3, 0);
        SEL4BENCH_READ_CCNT(end);
        results->emergency_cost[i] = end - start;
        seL4_Call(ep, seL4_MessageInfo_new(0, 0, 0, 4));
        /* server is done! remove emergency budget */
        seL4_SchedContext_Unbind(server_thread.sched_context.cptr);
     }

    /* cold cache */
    for (int i = 0; i < N_RUNS; i++) {
        seL4_Recv(tfep, &badge, reply);
        ZF_LOGV("Fault from %d\n", seL4_GetMR(0));
        seL4_BenchmarkFlushCaches();
        SEL4BENCH_READ_CCNT(start);
        handle_timeout_emergency_budget(ep, seL4_GetMR(seL4_Timeout_Data), reply);
        seL4_SetMR(0, 0xdeadbeef);
        seL4_SetMR(3, 0);
        SEL4BENCH_READ_CCNT(end);
        results->emergency_cost_cold[i] = end - start;
        seL4_Call(ep, seL4_MessageInfo_new(0, 0, 0, 4));
        /* server is done! remove emergency budget */
        seL4_SchedContext_Unbind(server_thread.sched_context.cptr);
    }

    /* finished */
	seL4_Send(done_ep, seL4_MessageInfo_new(0, 0, 0, 0));
    seL4_Wait(stop_ep, NULL);
}

/* timeout fault handler for doing rollbacks */
void
tfep_fn_rollback(int argc, char **argv)
{
    seL4_CPtr tfep = atol(argv[0]);
    seL4_CPtr ep   = atol(argv[1]);
    seL4_CPtr reply = atol(argv[2]);
    ZF_LOGV("TFE started\n");
    ccnt_t start, end;
    seL4_Word badge;

    /* hot cache */
    for (int i = 0; i < N_RUNS; i++) {
        seL4_Recv(tfep, &badge, reply);
        ZF_LOGV("Fault from %d\n", seL4_GetMR(0));
        SEL4BENCH_READ_CCNT(start);
        handle_timeout_rollback(ep, badge);
        SEL4BENCH_READ_CCNT(end);
        results->rollback_cost[i] = end - start;
    }

    /* cold cache */
    for (int i = 0; i < N_RUNS; i++) {
        seL4_Recv(tfep, &badge, reply);
        ZF_LOGV("Fault from %d\n", seL4_GetMR(0));
        seL4_BenchmarkFlushCaches();
        SEL4BENCH_READ_CCNT(start);
        handle_timeout_rollback(ep, badge);
        SEL4BENCH_READ_CCNT(end);
        results->rollback_cost_cold[i] = end - start;
        ZF_LOGV("Recorded cost "CCNT_FORMAT, results->rollback_cost_cold[i]);
    }

    /* finished */
	seL4_Send(done_ep, seL4_MessageInfo_new(0, 0, 0, 0));
    seL4_Wait(stop_ep, NULL);
}

void tfep_fn_rollback_infinite(int arc, char **argv) {
    seL4_CPtr tfep = atol(argv[0]);
    seL4_CPtr ep   = atol(argv[1]);
    seL4_CPtr reply = atol(argv[2]);

    while (1) {
        seL4_Word badge;
        seL4_Recv(tfep, &badge, reply);
        badge = seL4_GetMR(seL4_Timeout_Data);
        handle_timeout_rollback(ep, badge);
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
    seL4_CPtr tfep = atol(argv[0]);
    seL4_CPtr sched_ctrl   = atol(argv[1]);
    seL4_CPtr reply = atol(argv[2]);
    ZF_LOGV("TFE started\n");
    ccnt_t start, end;
    seL4_Word badge;
    uint64_t budgets[N_CLIENTS] = {0};

    seL4_Recv(tfep, &badge, reply);
    seL4_Word data = seL4_GetMR(seL4_Timeout_Data);
    /* run this N_CLIENTSx to get the results we want */
    for (int j = 0; j < N_CLIENTS + 1; j++) {
        /* set the clients budgets to be small */
        /* hot cache */
        for (int i = 0; i < N_CLIENTS; i++) {
            ZF_LOGV("Fault from %d\n", data);
            assert(data < N_CLIENTS);
            budgets[data] += US_IN_MS;
            SEL4BENCH_READ_CCNT(start);
            handle_timeout_extend(sched_ctrl, data, budgets[data], 100 * US_IN_MS);
            SEL4BENCH_READ_CCNT(end);
            results->extend_cost[j * N_CLIENTS + i] = end - start;
            seL4_ReplyRecv(tfep, seL4_MessageInfo_new(0, 0, 0, 0), &badge, reply);
            data = seL4_GetMR(seL4_Timeout_Data);
        }

        /* cold cache */
        reset_budgets(sched_ctrl, budgets);
        for (int i = 0; i < N_CLIENTS; i++) {
                ZF_LOGV("Fault from %d\n", data);
                budgets[data] += US_IN_MS;
                seL4_BenchmarkFlushCaches();
                SEL4BENCH_READ_CCNT(start);
                handle_timeout_extend(sched_ctrl, data, budgets[data], 100 * US_IN_MS);
                SEL4BENCH_READ_CCNT(end);
                results->extend_cost_cold[j * N_CLIENTS + i] = end - start;
                seL4_ReplyRecv(tfep, seL4_MessageInfo_new(0, 0, 0, 0), &badge, reply);
                data = seL4_GetMR(seL4_Timeout_Data);
        }
       reset_budgets(sched_ctrl, budgets);
    }

    /* finished */
    seL4_Send(reply, seL4_MessageInfo_new(0, 0, 0, 0));
	seL4_Send(done_ep, seL4_MessageInfo_new(0, 0, 0, 0));
    seL4_Wait(stop_ep, NULL);
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

/* start the server and the timeout fault handler */
void benchmark_start_server_tf(env_t *env, seL4_CPtr ep, seL4_CPtr tfep, void *timeout_fn, seL4_CPtr arg0, seL4_CPtr arg1, seL4_CPtr arg2) {
    /* we use the servers sc as a backup for init -> don't let it run out */
    int error = seL4_SchedControl_Configure(simple_get_sched_ctrl(&env->simple, 0),
            server_thread.sched_context.cptr,
            1000 * US_IN_S, 1000 * US_IN_S, 0, 0);
    ZF_LOGF_IF(error, "Failed to configure server sc");

    /* don't let the timeout fault handler run out either */
    error = seL4_SchedControl_Configure(simple_get_sched_ctrl(&env->simple, 0),
            tfep_thread.sched_context.cptr,
            1000 * US_IN_S, 1000 * US_IN_S, 0, 0);
    ZF_LOGF_IF(error, "Failed to configure server sc");

    error = sel4utils_start_thread(&server_thread, (sel4utils_thread_entry_fn) server_fn, (void *) ep,
            (void *) slot.capPtr, true);
    ZF_LOGF_IF(error != 0, "Failed to start server");



    /* wait for server to init and convert to passive */
    seL4_Wait(init_ep, NULL);
    error = seL4_SchedContext_Unbind(server_thread.sched_context.cptr);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to convert server to passive");

    /* checkpoint server */
    sel4utils_checkpoint_thread(&server_thread, &cp, false);

    /* start the temporal fault handler */
    char timeout_args[N_TIMEOUT_ARGS][WORD_STRING_SIZE];
    char *timeout_argv[N_TIMEOUT_ARGS];
    sel4utils_create_word_args(timeout_args, timeout_argv, N_TIMEOUT_ARGS, arg0, arg1, arg2);

    error = sel4utils_start_thread(&tfep_thread, timeout_fn, (void *) N_TIMEOUT_ARGS, timeout_argv, true);
    ZF_LOGF_IF(error != 0, "Failed to start tfep thread");

       /* let it initialise */
    error = seL4_TCB_SetPriority(simple_get_tcb(&env->simple), seL4_MinPrio);
    ZF_LOGF_IF(error, "failed to set own prio");

    error = seL4_TCB_SetPriority(simple_get_tcb(&env->simple), seL4_MaxPrio);
    ZF_LOGF_IF(error, "failed to set own prio");
}

void
benchmark_setup(env_t *env, seL4_CPtr ep, seL4_CPtr tfep, void *timeout_fn, seL4_CPtr arg0, seL4_CPtr arg1, seL4_CPtr arg2)
{
    benchmark_start_server_tf(env, ep, tfep, timeout_fn, arg0, arg1, arg2);

    /* create and start the clients */
    for (int i = 0; i < N_CLIENTS; i++) {
        /* set client budget */
        int error = sel4utils_start_thread(&clients[i], (sel4utils_thread_entry_fn) client_fn, (void *) ep, (void *) done_ep, true);
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

static size_t object_freq[seL4_ObjectTypeCount] = {0};

int
main(int argc, char **argv)
{
    UNUSED int error;
    vka_object_t ep, tfep, timeout_reply, server_reply;

    object_freq[seL4_TCBObject] = 2 + N_CLIENTS;
    object_freq[seL4_EndpointObject] = 4;
    object_freq[seL4_ReplyObject] = 2;
    object_freq[seL4_SchedContextObject] = 2 + N_CLIENTS;

    sel4bench_init();
    env_t *env = benchmark_get_env(argc, argv, sizeof(aes_results_t), object_freq);
    results = (aes_results_t *) env->results;

    measure_ccnt_overhead(results->overhead);

    /* allocate an ep for client <-> server */
    error = vka_alloc_endpoint(&env->slab_vka, &ep);
    ZF_LOGF_IF(error != 0, "Failed to allocate ep");

    /* allocate an init ep for server <-> tfep */
    vka_object_t init_epo;
    error = vka_alloc_endpoint(&env->slab_vka, &init_epo);
    ZF_LOGF_IF(error != 0, "Failed to allocate ep");
    init_ep = init_epo.cptr;

    /* allocate a timeout ep */
    error = vka_alloc_endpoint(&env->slab_vka, &tfep);
    ZF_LOGF_IF(error != 0, "Failed to allocate tfep");

    /* allocate a reply object for server*/
    error = vka_alloc_reply(&env->slab_vka, &server_reply);
    ZF_LOGF_IF(error != 0, "Failed to allocate cslot for tfep");
    vka_cspace_make_path(&env->slab_vka, server_reply.cptr, &slot);

    /* allocate a reply object for timeout handlers */
    error = vka_alloc_reply(&env->slab_vka, &timeout_reply);
    ZF_LOGF_IF(error != 0, "Failed to allocate cslot for tfep");

    /* create an ep for clients to signal on when they are done */
    vka_object_t done;
    error = vka_alloc_endpoint(&env->slab_vka, &done);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to allocate ep");
    done_ep = done.cptr;

    /* create an ep for clients to block on when they are done */
    vka_object_t stop;
    error = vka_alloc_endpoint(&env->slab_vka, &stop);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to allocate ep");
    stop_ep = stop.cptr;

    /* allocate threads */
    benchmark_configure_thread(env, 0, seL4_MaxPrio - 2, "server", &server_thread);
    benchmark_configure_thread(env, 0, seL4_MaxPrio - 1, "tfep", &tfep_thread);
    for (int i = 0; i < N_CLIENTS; i++) {
        benchmark_configure_thread(env, 0, seL4_MaxPrio - 3, "client", &clients[i]);
        /* set client budget */
        error = seL4_SchedControl_Configure(simple_get_sched_ctrl(&env->simple, 0),
                clients[i].sched_context.cptr, 5 * US_IN_MS, 10 * US_IN_MS, 0, i);
        ZF_LOGF_IF(error != seL4_NoError, "Failed to configure sc");
    }

    /* set servers tfep */
    seL4_CapData_t guard = seL4_CapData_Guard_new(0, seL4_WordBits - CONFIG_SEL4UTILS_CSPACE_SIZE_BITS);
    error = seL4_TCB_SetSpace(server_thread.tcb.cptr, seL4_CapNull, tfep.cptr,
                              SEL4UTILS_CNODE_SLOT, guard, SEL4UTILS_PD_SLOT,
                              seL4_CapData_Guard_new(0, 0));

    ZF_LOGV("Starting rollback benchmark\n");
    benchmark_setup(env, ep.cptr, tfep.cptr, tfep_fn_rollback, tfep.cptr, ep.cptr, timeout_reply.cptr);
    /* wait for timeout fault handler to finish - it will exit once it has enough samples */
    benchmark_wait_children(done.cptr, "tfep", 1);
    benchmark_teardown(env);

    /* next benchmark - use emergency sc's instead */
    ZF_LOGV("Starting emergency budget benchmark\n");
    benchmark_setup(env, ep.cptr, tfep.cptr, tfep_fn_emergency_budget, tfep.cptr, ep.cptr, timeout_reply.cptr);
    benchmark_wait_children(done.cptr, "tfep", 1);
    benchmark_teardown(env);

    ZF_LOGV("Running extend benchmark");
    benchmark_setup(env, ep.cptr, tfep.cptr, tfep_fn_extend, tfep.cptr,
            simple_get_sched_ctrl(&env->simple, 0), timeout_reply.cptr);
    benchmark_wait_children(done.cptr, "tfep-extend", 1);
    benchmark_teardown(env);

    ZF_LOGV("Running kill benchmark");
    benchmark_setup(env, ep.cptr, tfep.cptr, tfep_fn_kill, tfep.cptr, ep.cptr, 0);
    benchmark_wait_children(done.cptr, "tfep-kill", 1);
    benchmark_teardown(env);

    ZF_LOGV("Running shared passive server benchmark");
    /* set up two clients */
    benchmark_configure_thread(env, 0, seL4_MaxPrio - 3, "A", &clients[0]);
    benchmark_configure_thread(env, 0, seL4_MaxPrio - 3, "B", &clients[1]);

    /* start the server and timeout fault handler - they both keep running throughout this entire benchmark */
    benchmark_start_server_tf(env, ep.cptr, tfep.cptr, tfep_fn_rollback_infinite, tfep.cptr, ep.cptr, timeout_reply.cptr);

    for (int i = 0; i < N_THROUGHPUT; i++) {
        /* configure A */
        uint64_t a_budget = get_budget_for_index(i);
        uint64_t b_budget = PERIOD - a_budget;
        seL4_Word refills = 0;//seL4_MaxExtraRefills(seL4_MinSchedContextBits);

        if (a_budget) {
            error = seL4_SchedControl_Configure(simple_get_sched_ctrl(&env->simple, 0),
                clients[0].sched_context.cptr, a_budget, 10 * US_IN_MS, refills, 0);
            ZF_LOGF_IF(error, "Failed to configure A");
        }

        if (b_budget) {
            error = seL4_SchedControl_Configure(simple_get_sched_ctrl(&env->simple, 0),
                clients[1].sched_context.cptr, b_budget, 10 * US_IN_MS, refills, 1);
            ZF_LOGF_IF(error, "Failed to configure B");
        }

        for (int j = 0; j  < N_RUNS; j++) {
            ZF_LOGV("Throughput %d: %d\n", i, j);

            if (a_budget) {
                error = sel4utils_start_thread(&clients[0], (sel4utils_thread_entry_fn) counting_client_fn,
                        (void *) ep.cptr, (void *) &results->throughput_A[i][j], true);
                ZF_LOGF_IF(error, "Failed to start A");
            } else {
                results->throughput_A[i][j] = 0;
            }

            if (b_budget) {
                error = sel4utils_start_thread(&clients[1], (sel4utils_thread_entry_fn) counting_client_fn,
                        (void *) ep.cptr, (void *) &results->throughput_B[i][j], true);
                ZF_LOGF_IF(error, "Failed to start B");
            } else {
                results->throughput_B[i][j] = 0;
            }

            benchmark_wait_children(done_ep, "B", !!a_budget + !!b_budget);
            ZF_LOGV("Got "CCNT_FORMAT" "CCNT_FORMAT"\n", results->throughput_A[i][j], results->throughput_B[i][j]);
            seL4_TCB_Suspend(clients[0].tcb.cptr);
            seL4_TCB_Suspend(clients[1].tcb.cptr);
        }
    }

    /* done -> results are stored in shared memory so we can now return */
    benchmark_finished(EXIT_SUCCESS);
    return 0;
}

