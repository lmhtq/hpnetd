#ifndef _TCP_H_
#define _TCP_H_

/* remove from control list */
inline void 
remove_from_control_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* remove from send list */
inline void
remove_from_send_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* remove from ack list */
inline void
remove_from_ack_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* remove from rto list */
inline void
remove_from_rto_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* remove from timewait list */
inline void
remove_from_timewait_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* remove from timeout list */
inline void
remove_from_timeout_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

#endif /* _TCP_H_ */