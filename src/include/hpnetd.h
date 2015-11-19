#ifndef __MMUTCPD_H__
#define __MMUTCPD_H__

#include "socket.h"
#include <sys/queue.h>

struct mmutcpd_thread_context
{
    int       cpu;
    pthread_t thread;
    uint8_t   done:1,
              exit:1,
              interrupt:1;

    mmutcpd_manager_t *mmt;

    /* TODO */
    void *io_private_context;

    pthread_mutex_t smap_lock;
    pthread_mutex_t flow_pool_lock;
    pthread_mutex_t socket_pool_lock;

};
typedef struct mmutcpd_thread_context * mmutcpd_thread_context_t;

struct mmutcpd_sender
{
    int ifidx;

    TAILQ_HEAD(control_head, tcp_stream) control_list;
    TAILQ_HEAD(send_head, tcp_stream) send_list;
    TAILQ_HEAD(ack_head, tcp_stream) ack_list;

    int control_list_cnt;
    int send_list_cnt;
    int ack_list_cnt;
};
typedef struct mmutcpd_sender * mmutcpd_sender_t;

struct mmutcpd_manager
{
    /* TODO */
    mempool_t     flow_pool;          /* pool for tcp_stream */
    mempool_t     recv_vars_pool;     /* pool for recv vars */
    mempool_t     send_vars_pool;     /* pool for send vars */
    mempool_t     monitor_vars_pool;  /* pool for monitor vars */

    /* TODO */
    send_buffer_manager_t rbm_snd;
    recv_buffer_manager_t rbm_rcv;

    /* TODO */
    flow_hash_table_t tcp_flow_table;

    uint32_t     s_index:24;          /* stream index */
    socket_map_t smap;
    TAILQ_HEAD(, socket_map) free_smap;

    /* TODO */
    addr_pool_t  ap;                  /* address pool */

    uint32_t     g_id;                /* id space in a thread */
    uint32_t     flow_cnt;            /* number of current floes */

    mmutcpd_thread_context_t ctx;

    /* vars for event */
    struct epool *ep;
    uint32_t     ts_last_event;

    struct tcp_listener *listener;

    stream_queue_t connectq;
    stream_queue_t sendq;
    stream_queue_t ackq;

    stream_queue_t closeq;
    stream_queue_int_t closeq_int;
    stream_queue_t resetq;
    stream_queue_t resetq_int;
    
    stream_queue_t destroyq;

    mmutcpd_sender_t g_sender;
    mmutcpd_sender_t n_sender[MAX_NICS];

    /* list related to timeout */
    /* TODO */
    struct rto_hashstore *rto_store;
    TAILQ_HEAD(timewait_head, tcp_stream) timewait_list;
    TAILQ_HEAD(timeout_head, tcp_stream) timeout_list;
    int rto_list_cnt;
    int timewait_list_cnt;
    int timeout_list_cnt;

#if BLOCKING_SUPPORT
    TAILQ_HEAD(rcv_br_head, tcp_stream) rcv_br_list;
    TAILQ_HEAD(snd_br_head, tcp_stream) snd_br_list;
    int rcv_br_list_cnt;
    int snd_br_list_cnt;
#endif /* BLOCKING_SUPPORT */

    uint32_t cur_ts;

    int wakeup_flag;
    int is_sleeping;

    /* TODO */
    struct io_module_func *iom;
};
typedef struct mmutcpd_manager * mmutcpd_manager_t;

mmutcpd_manager_t g_mmutcpd[MAX_CPUS];

#endif