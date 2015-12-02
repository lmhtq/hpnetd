#ifndef __STREAM_H_
#define __STREAM_H_

#include <netinet/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <sys/queue.h>
#include "config.h"

#if TCP_OPT_SACK_ENABLED
struct sack_entry
{
    uint32_t left_edge;
    uint32_t right_edge;
    uint32_t expire;
};
#endif /* TCP_OPT_SACK_ENABLED */

typedef struct tcp_ring_buffer * tcp_ring_buffer_t;
typedef struct tcp_send_buffer * tcp_send_buffer_t;

struct tcp_recv_vars
{
    /* receiver side vars */
    uint32_t rcv_wnd;        /* receive window (unscaled) */
    uint32_t irs;            /* inital receiving sequence */
    uint32_t snd_wl1;        /* segment seq num for last window update */
    uint32_t snd_wl2;        /* segment ack num for last window update */

    /* for fast retransmission */
    uint32_t last_ack_seq;   /* last acked seq */
    uint8_t  dup_acks;       /* num of duplicated acks */

    /* timestamp */
    uint32_t ts_recent;      /* timestamp of recent peer */
    uint32_t ts_last_ack_rcv;/* timestamp of last ack recv */
    uint32_t ts_last_ts_upd; /* timestamp of last peer update */

    /* RTT */
    uint32_t srtt;           /* smoothed round trip time << 3 (scaled) */
    uint32_t mdev;           /* medium deviatuin */
    uint32_t mdev_max;       /* maximal mdev for the last rtt period */
    uint32_t rttvar;         /* smoothed mdev_max */
    uint32_t rtt_seq;        /* seqence number to update rttvar */

    /* SACK: TODO */

    /* ring buffer */
    struct tcp_ring_buffer *rcvbuf;

#if USE_SPIN_LOCK 
    pthread_spinlock_t read_lock;
#else
    pthread_mutex_t read_lock;
#endif /*USE_SPIN_LOCK*/

    TAILQ_ENTRY(tcp_stream) hash_entry_table_link;

#if BLOCKING_SUPPORT
    TAILQ_ENTRY(tcp_stream) rcv_br_link;
    pthread_cond_t read_cond;
#endif/* BLOCKING_SUPPORT */

};
typedef struct tcp_recv_vars * tcp_recv_vars_t;



struct tcp_send_vars
{
    /* IP-level information */
    uint16_t ip_id;
    uint16_t mss;            /* maximum segment size */
    uint16_t eff_mss;        /* effective segment size (without tcp option) */
    uint8_t  wscale;         /* window scale */
    int8_t   nif_out;        /* cached output network interface */
    unsigned char *d_haddr;  /* cached dest MAC addr */

    /* send seqence variable */
    uint32_t snd_una;        /* send unacknoleged */
    uint32_t snd_wnd;        /* send window (unscaled) */
    uint32_t peer_wnd;       /* peer window size */
    uint32_t iss;            /* initial sending seq */
    uint32_t fss;            /* final sending seq */

    /* RTO vars */
    uint8_t  nrtx;            /* number of retransmission */
    uint8_t  max_nrtx;        /* max number of retransmission */
    uint32_t rto;             /* the value of RTO (a time interval) */
    uint32_t ts_rto;          /* timestamp of RTO (after it, 
                                 mean the stream timeout) */

    /* congestion control vars */
    uint32_t cwnd;            /* congestion window */
    uint32_t ssthresh;        /* slow start threshold */

    /* timestamp */
    uint32_t ts_last_ack_snd; /* last ack sent time */

    uint8_t  is_wack:1,       /* is ack for window adertisement? */
             ack_cnt:6;       /* num of acks to send. max 64 */

    uint8_t  on_control_list:1,
             on_send_list:1,
             on_ack_list:1,
             on_sendq:1,
             on_ackq:1,
             on_closeq:1,
             on_resetq:1;

    uint8_t  on_closeq_int:1,
             on_resetq_int:1,
             is_fin_sent:1,
             is_fin_ackd:1;


    TAILQ_ENTRY(tcp_stream) control_link;
    TAILQ_ENTRY(tcp_stream) send_link;
    TAILQ_ENTRY(tcp_stream) ack_link;
    TAILQ_ENTRY(tcp_stream) timer_link;   /* rto list, tw list */
    TAILQ_ENTRY(tcp_stream) timeout_link; /* connection timeout */
    
    struct tcp_send_buffer *sndbuf;

#if USE_SPIN_LOCK
    pthread_spinlock_t write_lock;
#else
    pthread_mutex_t write_lock;
#endif /* USE_SPIN_LOCK */

#if BLOCKING_SUPPORT
    TAILQ_ENTRY(tcp_stream) snd_br_link;
    pthread_cond_t write_cond;
#endif
};
typedef struct tcp_send_vars * tcp_send_vars_t;

struct tcp_stream
{
    socket_map_t sk;

    /* identity */
    uint32_t id:24,
             stream_type:8;
    /* in network order */
    uint32_t saddr;
    uint32_t daddr;
    uint32_t sport;
    uint32_t dport;
    
    /* tcp state */
    uint8_t  state;
    uint8_t  close_reason;

    uint8_t  closed;
    uint8_t  is_bound_addr;
    uint8_t  need_wnd_adv;
    
    uint8_t  on_hash_table;
    uint8_t  on_rto_idx;
    uint8_t  on_timewait_list;
    uint8_t  control_list_waiting;
    uint8_t  sack_permit;   /* whether peer permits SACK */
    uint8_t  saw_timestamp; /* whether peer sends timestamp */

    
    /* send/recv next */
    uint32_t snd_nxt;
    uint32_t rev_nxt;

    /* last active timestamp */
    uint32_t last_active_ts;
    
    /* send side vars */
    struct tcp_send_vars *snd_var;
    
    /* receive side vars */
    struct tcp_recv_vars *rcv_var;
    
    /* option vars */
    struct tcp_option_vars *opt_var;

};

typedef struct tcp_stream * tcp_stream_t;

#if 1
/* basic stream function */
/* create tcp stream */
tcp_stream_t
create_tcp_stream(mmutcpd_manager_t mmt, socket_map_t sk, int type, 
    uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);

/* destroy the tcp stream */
void 
destroy_tcp_stream(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* dump stream */
void 
dump_stream(mmutcpd_manager_t mmt, tcp_stream_t stream);
#endif /* basic stream function */

#if 1
/* structure for tcp_stream identify */
#define SHASH_ENTRY 249997

struct hash_bucket_head
{
    tcp_stream_t tqh_first;
    tcp_stream_t *tqh_last;
}; 
typedef struct hash_bucket_head hash_bucket_head;

/* tcp_flow_hashtable structure */
struct tcp_flow_hashtable
{
    uint8_t ht_count;  /* count for # entry */
    hash_bucket_head ht_table[SHASH_ENTRY];
};
typedef struct tcp_flow_hashtable * tcp_flow_hashtable_t;

#endif /* end for structure fot tcp_stram identify */

/* create stream queue */
tcp_stream_t
create_stream_queue(int size);

/* dequeue from the queue */
tcp_stream_t
stream_dequeue(stream_queue_t sq);

/* enqueue from the queue */
int
stream_enqueue(stream_queue_t sq, tcp_stream_t cur);


#if 1
/* functions for tcp_stream hash identify */
/* create a tcp_flow_hashtable */
tcp_flow_hashtable_t 
create_tcp_flow_hashtable();

/* hash of a tcp stream flow */
uint32_t
hash_of_stream(const tcp_stream_t item);

/* two tcp_stream equal */
inline int 
stream_is_equal(const tcp_stream_t s1, const tcp_stream_t s2);

/* destroy the tcp_flow_hashtable */
void 
destroy_tcp_flow_hashtable(tcp_flow_hashtable_t ht);

/* insert a tcp_stream into the tcp_flow_hashtable */
int 
insert_tcp_flow_hashtable(tcp_flow_hashtable_t ht, tcp_stream_t item);

/* remove the tcp_stream from the tcp_flow_hashtable */
void*
remove_tcp_flow_hashtable(tcp_flow_hashtable_t, tcp_stream_t item);

/* search the tcp_stream from the tcp_flow_hashtable */
tcp_stream_t
search_tcp_flow_hashtable(tcp_flow_hashtable_t ht, const tcp_stream_t item);

#endif /* functions for tcp_stream hash identify */

#if 1
/* event in stream */
/* raise read event  */
inline void 
raise_read_event(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* raise write event  */
inline void 
raise_write_event(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* raise close event  */
inline void 
raise_close_event(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* raise error event  */
inline void 
raise_error_event(mmutcpd_manager_t mmt, tcp_stream_t stream);

#endif /* event in stream */

#endif /* __STREAM_H_ */