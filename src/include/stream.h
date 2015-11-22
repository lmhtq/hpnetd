#ifndef __STREAM_H_
#define __STREAM_H_

#include <netinet/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <sys/queue.h>
#include "config.h"


enum tcp_state
{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING,    /* Now a valid a state */

    TCP_MAX_STATES  /* Leave at the end! */
};

enum tcp_close_reason
{
    TCP_NOT_CLOSED = 0,
    TCP_ACTIVE_CLOSE,
    TCP_PASSIVE_CLOSE,
    TCP_CONN_FAIL,
    TCP_CONN_LOST,
    TCP_RESET,
    TCP_NO_MEM,
    TCP_NOT_ACCEPTED,
    TCP_TIMEOUT
};

#if TCP_OPT_SACK_ENABLED
struct sack_entry
{
    uint32_t left_edge;
    uint32_t right_edge;
    uint32_t expire;
};
#endif /* TCP_OPT_SACK_ENABLED */

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

    uint8_t  on_ctrl_list:1,
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
    
    /* send/recv next */
    uint32_t snd_nxt;
    uint32_t rev_nxt;
    
    /* send side vars */
    struct tcp_send_vars *snd_var;
    
    /* receive side vars */
    struct tcp_recv_vars *rcv_var;
    
    /* option vars */
    struct tcp_option_vars *opt_var;

};

typedef struct tcp_stream * tcp_stream_t;

#endif /* __STREAM_H_ */