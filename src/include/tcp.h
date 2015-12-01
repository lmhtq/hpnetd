#ifndef _TCP_H_
#define _TCP_H_

#if 1
/* tcp_out */
#define TCP_HEADER_LEN 20

#define TCP_CALC_CHECKSUM     TRUE
#define ACK_PIGGYBACK         TRUE

#define TCP_MAX_WND           65535

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20
#define TCP_FLAG_SACK 0x40
#define TCP_FLAG_WACK 0x80

#define TCP_OPT_FLAG_MSS         0x02
#define TCP_OPT_FLAG_WSCALE      0x04
#define TCP_OPT_FLAG_SACK_PERMIT 0x08
#define TCP_OPT_FLAG_SACK        0x10
#define TCP_OPT_FLAG_TIMESTAMP   0x20

#define TCP_OPT_MSS_LEN         4
#define TCP_OPT_WSCALE_LEN      3
#define TCP_OPT_SACK_PERMIT_LEN 2
#define TCP_OPT_SACK_LEN        10
#define TCP_OPT_TIMESTAMP_LEN   10

#define TCP_DEFAULT_MSS 1460
#define TCP_DEFAULT_WSCALE 7
#define TCP_MAXSEQ 0xffffffff
#define TCP_INIT_WINDOW 14600

#define TCP_SEQ_LT(a,b)   ((int32_t)((a)-(b)) < 0)
#define TCP_SEQ_LEQ(a,b)  ((int32_t)((a)-(b)) <= 0)
#define TCP_SEQ_GT(a,b)   ((int32_t)((a)-(b)) > 0)
#define TCP_SEQ_GET(a,b)  ((int32_t)((a)-(b)) >= 0)
#define TCP_SEQ_BT(a,b,c) (TCP_SEQ_LEQ(a,b) && TCP_SEQ_GEQ(a,c)) //b<=a<=c

//TS is in ms
#define TIMEVAL_TO_TS(t)  ((uint32_t)((t)->tv_sec*1000+(t)->tv_usec/1000))
#define TS_TO_MSEC(t)     (t)
#define TS_TO_USEC(t)     ((t)*1000)
#define TS_TO_SEC(t)      ((t)/1000)
#define USEC_TO_TS(t)     ((t)/1000)
#define SEC_TO_TS(t)      ((t)*1000)

#define TCP_TIMEWAIT_VAL  (0)   //0ms
#define TCP_INIT_RTO_VAL  (500) //500ms
#define TCP_FIN_RTO_VAL   (500) //500ms
#define TCP_TIMEOUT_VAL   (500) //500ms

#define TCP_MAX_RTX       16
#define TCP_MAX_SYN_RETRY 7
#define TCP_MAX_BACKOFF   7

enum tcp_state
{
    TCP_CLOSE = 0,
    TCP_ESTABLISHED,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
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

char *tcp_state_str[] =
{
    "TCP_CLOSE",
    "TCP_ESTABLISHED",
    "TCP_SYN_SENT",
    "TCP_SYN_RECV",
    "TCP_FIN_WAIT1",
    "TCP_FIN_WAIT2",
    "TCP_TIME_WAIT",
    "TCP_CLOSE_WAIT",
    "TCP_LAST_ACK",
    "TCP_LISTEN",
    "TCP_CLOSING",    /* Now a valid a state */

    "TCP_MAX_STATES"  /* Leave at the end! */
};

char *tcp_close_reason_str[] =
{
    "TCP_NOT_CLOSED",
    "TCP_ACTIVE_CLOSE",
    "TCP_PASSIVE_CLOSE",
    "TCP_CONN_FAIL",
    "TCP_CONN_LOST",
    "TCP_RESET",
    "TCP_NO_MEM",
    "TCP_NOT_ACCEPTED",
    "TCP_TIMEOUT"
};


enum tcp_option
{
    TCP_OPT_END = 0,
    TCP_OPT_NOP,
    TCP_OPT_MSS,
    TCP_OPT_WSACLE,
    TCP_OPT_SACK_PERMIT,
    TCP_OPT_SACK,
    TCP_OPT_TIMESTAMP
};

/* calcalute the length of the tcp option */
inline uint16_t 
calc_opt_length(uint8_t flags);

/* generate tcp timestamp */
inline void 
generate_tcp_timestamp(tcp_stream_t cur, uint8_t *tcpopt, uint32_t cur_ts);

/* generate tcp options */
inline void
generate_tcp_option(tcp_stream_t cur, uint32_t cur_ts, uint8_t flags, 
    uint8_t *tcpopt, uint16_t optlen);

/* tcp checksum calc */
inline uint16_t
tcp_calc_check(*buf, uint16_t len, uint32_t saddr, uint32_t daddr);

/* send tcp packet standalone */
int
send_tcp_packet_standalone(mmutcpd_manager_t mmt, 
    uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, 
    uint32_t seq, uint32_t ack_seq, uint16_t window, uint8_t flags, 
    uint8_t *payload, uint16_t payloadlen,
    uint32_t cur_ts, uint32_t echo_ts);

/* send tcp packet */
int 
send_tcp_packet(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t cur_ts, 
    uint8_t flags, uint8_t *payload, uint16_t payloadlen);

/* flush tcp sending buffer */
int 
flush_tcp_sending_buffer(mmutcpd_manager_t mmt, 
    tcp_stream_t cur, uint32_t cur_ts);

/* send control packet */
inline int 
send_control_packet(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t cur_ts);

/* write tcp control list */
inline int 
write_tcp_control_list(mmutcpd_manager_t mmt, mmutcpd_sender_t *sender, 
    uint32_t cur_ts, int thresh);

/* write tcp data list */
inline int 
write_tcp_data_list(mmutcpd_manager_t mmt, mmutcpd_sender_t *sender, 
    uint32_t cur_ts, int thresh);

/* write tcp ack list */
inline int 
write_tcp_ack_list(mmutcpd_manager_t mmt, mmutcpd_sender_t *sender, 
    uint32_t cur_ts, int thresh);

/* get sender */
inline mmutcpd_sender_t
get_sender(mmutcpd_manager_t mmt, tcp_stream_t cur);

/* add to control list */
inline void 
add_to_control_list(mmutcpd_manager_t mmt, tcp_stream_t cur);

/* add to send list */
inline void
add_to_send_list(mmutcpd_manager_t mmt, tcp_stream_t cur);

/* add to ack list */
inline void 
add_to_ack_list(mmutcpd_manager_t mmt, tcp_stream_t cur);

/* enqueue ack, this maybe a import position to change */
inline void 
enqueue_ack(mmutcpd_manager_t mmt, tcp_stream_t cur, 
    uint32_t cur_ts, uint8_t opt);

/* remove from control list */
inline void 
remove_from_control_list(mmutcpd_manager_t mmt, tcp_stream_t cur);

/* remove from send list */
inline void
remove_from_send_list(mmutcpd_manager_t mmt, tcp_stream_t cur);

/* remove from ack list */
inline void
remove_from_ack_list(mmutcpd_manager_t mmt, tcp_stream_t cur);

/* add to rto list */
inline void 
add_to_rto_list(mmutcpd_manager_t mmt, tcp_stream_t cur);

/* update timeout list */
inline void 
update_timeout_list(mmutcpd_manager_t mmt, tcp_stream_t cur);

/* remove from rto list */
inline void
remove_from_rto_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* remove from timewait list */
inline void
remove_from_timewait_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* remove from timeout list */
inline void
remove_from_timeout_list(mmutcpd_manager_t mmt, tcp_stream_t stream);
#endif /* tcp_out */

#endif /* _TCP_H_ */