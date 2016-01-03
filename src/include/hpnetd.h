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
    mem_pool_t     flow_pool;          /* pool for tcp_stream */
    mem_pool_t     recv_vars_pool;     /* pool for recv vars */
    mem_pool_t     send_vars_pool;     /* pool for send vars */
    mem_pool_t     monitor_vars_pool;  /* pool for monitor vars */

    /* TODO */
    send_buffer_manager_t rbm_snd;
    recv_buffer_manager_t rbm_rcv;

    tcp_flow_hashtable_t tcp_flow_hstable;

    uint32_t     s_index:24;          /* stream index */
    socket_map_t smap;
    TAILQ_HEAD(, socket_map) free_smap;

    /* TODO */
    addr_pool_t  ap;                  /* address pool */

    uint32_t     g_id;                /* id space in a thread */
    uint32_t     flow_cnt;            /* number of current floes */

    mmutcpd_thread_context_t ctx;

    /* vars for event */
    struct epoll *ep;
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

    /* socket queue */
    socket_queue_t socketq;
};
typedef struct mmutcpd_manager * mmutcpd_manager_t;


/* Global variables ! */
mmutcpd_manager_t g_mmutcpd[MAX_CPUS];
mmutcpd_thread_context_t g_pctx[MAX_CPUS];

pthread_t g_thread[MAX_CPUS];
sem_t     g_init_sem[MAX_CPUS];
int       running[MAX_CPUS];

typedef void (*mmutcpd_sighandler_t) (int);
mmutcpd_sighandler_t app_signal_handler;
int sigint_cnt[MAX_CPUS];
struct timeval sigint_ts[MAX_CPUS];

/* handle the signal */
void 
handle_signal(int signal);

/* register signal */
mmutcpd_sighandler_t 
mmutcpd_register_signal(int signum, mmutcpd_sighandler_t handler);

/* attach device */
int 
attach_device(mmutcpd_thread_context_t ctx);

/* STAT */
inline void 
init_stat_counter(stat_counter_t counter);

inline void 
update_state_counter(stat_counter_t counter, int64_t val);

inline uint64_t 
get_average_stat(stat_counter_t counter);

inline int64_t 
time_diff_us(struct timeval *t2, struct timeval *t1);

inline void 
print_thread_net_stat(mmutcpd_manager_t mmutcpd, net_stat_t ns);

inline void 
print_thread_round_stat(mmutcpd_manager_t mmutcpd, run_stat_t rs);

inline void 
print_thread_round_time(mmutcpd_manager_t mmutcpd);

inline void 
print_event_stat(int core, epoll_stat_t stat);

inline void 
print_net_stat(mmutcpd_manager_t mmutcpd, uint32_t cur_ts);

/* process events */
/* flush epoll event */
inline void 
flush_epoll_event(mmutcpd_manager_t mmutcpd, uint32_t cur_ts);

/* handle app calls */
inline void 
handle_app_calls(mmutcpd_manager_t mmutcpd, uint32_t cur_ts);

/* write packets to chunks */
inline void 
write_pkt_to_chunks(mmutcpd_manager_t mmutcpd, uint32_t cur_ts);

/* interrupt app */
void 
interrupt_app(mmutcpd_manager_t mmutcpd);

/* create sender */
mmutcpd_sender_t 
create_mmutcpd_sender(int ifidx);

/* destroy sender */
destroy_mmutcpd_sender(mmutcpd_sender_t sender);

/* mmutcpd destroy */
void 
mmutcpd_destroy();

/* mmutcpd init */
int 
mmutcpd_init(char *config);

/* mmutcpd get conf */
int 
mmutcpd_get_conf();

/* mmutcpd set conf */
int 
mmutcpd_set_conf();

/* functions */
mmutcpd_manager_t 
init_mmutcpd_manager(mmutcpd_thread_context_t mmutcpd_ctx);

/* create thread */
mmutcpd_create_context(int cpu);
/* destroy thread */
mmutcpd_destroy_context(int cpu);

/* mmutcpd run thread */
void * 
mmutcpd_run_thread(void *arg);

/* run main loop */
void 
run_main_loop(mmutcpd_thread_context_t ctx);


#endif