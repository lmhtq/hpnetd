#include "tcp.h"

/* calcalute the length of the tcp option */
inline uint16_t 
/* TODO: need to be optimize!, or in a nicer way */
calc_opt_length(uint8_t flags)
{
    uint16_t optlen = 0;

    if (flags & TCP_FLAG_SYN) {
        optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
        optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
        optlen += 2;//for padding
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
#endif /* TCP_OPT_SACK_ENABLED */

#if TCP_OPT_TIMESTAMP_ENABLED
        optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
        optlen += 2;//for padding
#endif /* TCP_OPT_SACK_ENABLED */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

        optlen += TCP_OPT_WSCALE_LEN + 1;
    } else {
#if TCP_OPT_TIMESTAMP_ENABLED
        optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

#if TCP_OPT_SACK_ENABLED
        if (flags & TCP_FLAG_SACK) {
            optlen += TCP_OPT_SACK_LEN + 2;
        }
#endif /* TCP_OPT_SACK_ENABLED */
    }

    assert(optlen % 4 == 0);
}

/* generate tcp timestamp */
inline void 
generate_tcp_timestamp(tcp_stream_t cur, uint8_t *tcpopt, uint32_t cur_ts)
{
    uint32_t *ts = (uint32_t *)(tcpopt + 2);
    tcpopt[0] = TCP_OPT_TIMESTAMP;
    tcpopt[1] = TCP_OPT_TIMESTAMP_LEN;
    ts[0] = htonl(cur_ts);
    ts[1] = htonl(cur->rcv_var->ts_recent);
}

/* generate tcp options */
inline void
generate_tcp_option(tcp_stream_t cur, uint32_t cur_ts, uint8_t flags, 
    uint8_t *tcpopt, uint16_t optlen)
{
    int i = 0;

    if (flags & TCP_FLAG_SYN) {
        /* mss option */
        uint16_t mss;
        mss = cur->snd_var->mss;//init in create_tcp_stream
        tcpopt[i++] = TCP_OPT_MSS;
        tcpopt[i++] = TCP_OPT_MSS_LEN;
        tcpopt[i++] = mss >> 8;
        tcpopt[i++] = mss % 256;
    
        /* TODO: sack option */

        /* timestamp */
#if TCP_OPT_TIMESTAMP_ENABLED
#if !TCP_OPT_SACK_ENABLED
        tcpopt[i++] = TCP_OPT_NOP;
        tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_SACK_ENABLED */
        generate_tcp_timestamp(cur, tcpopt + i, cur_ts);
        i += TCP_OPT_TIMESTAMP_LEN;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
        
        /* window scale */
        tcpopt[i++] = TCP_OPT_NOP;
        tcpopt[i++] = TCP_OPT_WSACLE;
        tcpopt[i++] = TCP_OPT_WSCALE_LEN;
        tcpopt[i++] = cur->snd_var->wscale;
    } else {
        /* TODO: sack */

        /* timestamp */
#if TCP_OPT_TIMESTAMP_ENABLED
        tcpopt[i++] = TCP_OPT_NOP;
        tcpopt[i++] = TCP_OPT_NOP;
        generate_tcp_timestamp(cur, tcpopt + i, cur_ts);
        i += TCP_OPT_TIMESTAMP_LEN;
#endif/* TCP_OPT_TIMESTAMP_ENABLED */

    }

    assert(i == optlen);
}

/* tcp checksum calc 
 * TODO: need to be optimised */
inline uint16_t
tcp_calc_check(*buf, uint16_t len, uint32_t saddr, uint32_t daddr)
{
    uint32_t sum;
    uint16_t *w;
    int nleft;

    sum = 0;
    nleft = len;
    w = buf;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft) {
        sum += *w & ntohs(0xff00);
    }

    /* pseudo header */
    sum += (saddr & 0x0000ffff) + (saddr >> 16);
    sum += (daddr & 0x0000ffff) + (daddr >> 16);
    sum += htons(len);
    sum += htons(IPPROTO_TCP);

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    sum = ~sum;

    return (uint16_t)sum;
}

/* send tcp packet standalone */
int
send_tcp_packet_standalone(mmutcpd_manager_t mmt, 
    uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, 
    uint32_t seq, uint32_t ack_seq, uint16_t window, uint8_t flags, 
    uint8_t *payload, uint16_t payloadlen,
    uint32_t cur_ts, uint32_t echo_ts)
{
    struct tcphdr *tcph;
    uint8_t       *tcpopt;
    uint32_t      *ts;
    uint16_t      optlen;

    optlen = calc_opt_length(flags);
    if (payloadlen > TCP_DEFAULT_MSS) {
        fprintf(stderr, "payloadlen size %u exceeds MSS\n", (uint32_t)payloadlen);
        assert(0);
        return ERROR;
    }

    /* TODO: */
    tcph = (struct tcphdr *)ip_outpout_standalone();
    if (!tcph) {
        return NULL;
    }
    
    memset(tcph, 0, TCP_HEADER_LEN + optlen);
    tcph->source = sport;
    tcph->dest = dport;
    if (flags & TCP_FLAG_SYN)
        tcph->syn = TRUE;
    if (flags & TCP_FLAG_FIN)
        tcph->fin = TRUE;
    if (flags & TCP_FLAG_RST)
        tcph->rst = TRUE;
    if (flags & TCP_FLAG_PSH)
        tcph->psh = TRUE;
    tcph->seq = htonl(seq);
    if (flags & TCP_FLAG_ACK) {
        tcph->ack = TRUE;
        tcph->ack_seq = htonl(ack_seq);
    }
    tcph->window = htons(MIN(window, TCP_MAX_WND));

    tcpopt = (uint8_t *)tcph + TCP_HEADER_LEN;
    ts = (uint32_t *)(tcpopt + 4);
    tcpopt[0] = TCP_OPT_NOP;
    tcpopt[1] = TCP_OPT_NOP;
    tcpopt[2] = TCP_OPT_TIMESTAMP;
    tcpopt[3] = TCP_OPT_TIMESTAMP_LEN;
    ts[0] = htonl(cur_ts);
    ts[1] = htonl(echo_ts);

    tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
    /* copy payload if exist */
    if (payloadlen > 0) {
        memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
    }
#if TCP_CALC_CHECKSUM
    tcph->check = tcp_calc_check((uint16_t *)tcph, 
        TCP_HEADER_LEN + optlen + payloadlen, saddr, daddr);
#endif /* TCP_CALC_CHECKSUM */

    if (tcph->syn || tcph->fin) {
        payloadlen++;
    }

    return payloadlen;
}

/* send tcp packet */
int 
send_tcp_packet(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t cur_ts, 
    uint8_t flags, uint8_t *payload, uint16_t payloadlen)
{
    struct tcphdr *tcph;
    uint16_t      optlen;
    uint8_t       wscale = 0;
    uint32_t      window32 = 0;

    optlen = calc_opt_length(flags);
    if (payloadlen > cur->snd_var->mss) {
        fprintf(stderr, "payloadlen %u exceeds mss\n", (uint32_t)payloadlen);
    }

    tcph = (struct tcphdr*)ip_outpout_standalone();
    if (!tcph) {
        return -2;
    }
    memset(tcph, 0, TCP_HEADER_LEN, optlen);

    tcph->source = cur->sport;
    tcph->dest = cur->dport;

    if (flags & TCP_FLAG_SYN) {
        tcph->syn = TRUE;
        if (cur->snd_nxt != cur->snd_var->iss) {
            fprintf(stderr, "stream %d: weird SYN seq."
                "snd_nxt:%u, iss:%u\n", cur->id, 
                cur->snd_nxt, cur->snd_var->iss);
        }
    }

    if (flags & TCP_FLAG_RST) {
        tcph->rst = TRUE;
    }

    if (flags & TCP_FLAG_PSH) {
        tcph->psh = TRUE;
    }

    if (flags & TCP_FLAG_WACK) {
        tcph->seq = htonl(cur->snd_nxt - 1);
        fprintf(stderr, "stream %u: sending ack to get new window adv. "
            "seq:%u, peer_wnd:%u, snd_nxt - snd_una:%u\n", cur->id, 
            cur->snd_nxt-1, cur->snd_var->peer_wnd, 
            cur->snd_nxt - cur->snd_var->snd_una);
    } else if (flags & TCP_FLAG_FIN) {
        tcph->fin = TRUE;
        if (cur->snd_var->fss == 0) {
            fprintf(stderr, "stream %u: not fss set. closed:%u\n", 
                cur->id, cur->closed);
        }
        tcph->seq = htonl(cur->snd_var->fss);
        cur->snd_var->is_fin_sent = TRUE;
        fprintf(stderr, "stream %d, sending FIN. seq: %u, ack_seq:%u\n", 
            cur->id, cur->snd_nxt, cur->rcv_nxt);
    } else {
        tcph->seq = htonl(cur->snd_nxt);
    }

    if (flags & TCP_FLAG_ACK) {
        tcph->ack = TRUE;
        tcph->ack_seq = htonl(cur->rcv_nxt);
        cur->snd_var->ts_last_ack_snd = cur_ts;
        cur->last_active_ts = cur_ts;
        update_timeout_list(mmt, cur);
    }

    if (flags & TCP_FLAG_SYN) {
        wscale = 0;
    } else {
        wscale = cur->snd_var->wscale;
    }

    window32 = cur->rcv_var->rcv_wnd >> wscale;
    tcph->window = htons(MIN((uint16_t)window32, TCP_MAX_WND));
    /* if the advertised window is 0, we need to advertise again later */
    if (window32 == 0) {
        cur->need_wnd_adv = TRUE;
    }

    generate_tcp_option(cur, cur_ts, flags, 
        (uint8_t *)tcph + TCP_HEADER_LEN, optlen);

    tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
    /* copy payload if exist */
    if (payloadlen > 0) {
        memcpy((uint8_t *)tcph, TCP_HEADER_LEN + optlen, payload, payloadlen);
    }
#if TCP_CALC_CHECKSUM
    tcph->check = tcp_calc_check((uint16_t *)tcph, 
        TCP_HEADER_LEN + optlen + payloadlen, cur->saddr, cur->daddr);
#endif /* TCP_CALC_CHECKSUM */

    cur->snd_nxt += payloadlen;

    if (tcph->syn || tcph->fin) {
        cur->snd_nxt++;
        payloadlen++;
    }

    if (payloadlen > 0) {
        if (cur->state > TCP_ESTABLISHED) {
            fprintf(stderr, "payload after TCP_ESTABLISHED: length:%d,"
                " snd_nxt:%u\n", payloadlen, cur->snd_nxt);
        }
        /* update rto timer if have payload */
        cur->snd_var->ts_rto = cur_ts + cur->snd_var->rto;
        fprintf(stderr, "stream %u: updating rto timer. "
            "cur_ts:%u, rto %u, ts_rto: %u\n", cur->id, cur_ts, 
            cur->snd_var->rto, cur->snd_var->ts_rto);
        add_to_rto_list(mmt, cur);
    }

    return payloadlen;
}

/* flush tcp sending buffer: a core (send data) function
 * this function is to send the whole sending buffer 
 * by calls the send_tcp_packet() many times until the 
 * whole buffer is sent */
int 
flush_tcp_sending_buffer(mmutcpd_manager_t mmt, 
    tcp_stream_t cur, uint32_t cur_ts)
{
    tcp_send_vars_t snd_var = cur->snd_var;
    uint32_t        maxlen = snd_var->mss - calc_opt_length(TCP_FLAG_ACK);
    uint8_t         *data;
    uint32_t        buffered_len;
    uint32_t        seq;
    uint16_t        len;
    int16_t         sndlen;
    uint32_t        window;
    int             packets = 0;

    if (!snd_var->sndbuf) {
        fprintf(stderr, "Stream %d: No sending buffer avaliable.\n", cur->id);
        assert(0);
        return 0;
    }

    pthread_spin_lock(&snd_var->write_lock);

    if (snd_var->sndbuf->len == 0) {
        packets = 0;
        pthread_spin_unlock(&snd_var->write_lock);
        return packets;
    } 

    window = MIN(snd_var->cwnd, snd_var->peer_wnd);
    while (1) {
        seq = cur->snd_nxt;
        if (TCP_SEQ_LT(seq, snd_var->sndbuf->head_seq)) {
            fprintf(stderr, "Stream %d: invalid seq to send. "
                "state:%s, seq:%u, head_seq:%u.\n", cur->id, 
                tcp_state_str[cur->state], seq, snd_var->sndbuf->head_seq);
            assert(0);
            break;
        }
        buffered_len = snd_var->sndbuf->head_seq + snd_var->sndbuf->len - seq;
        if (cur->state > TCP_ESTABLISHED) {
            fprintf(stderr, "head_seq:%u, seq:%u, buffered_len:%u\n", 
                snd_var->sndbuf->head_seq, snd_var->sndbuf->len, buffered_len);
        }
        if (buffered_len == 0) {
            break;
        }

        data = snd_var->sndbuf->head + (seq - snd_var->sndbuf->head_seq);

        len = MIN(buffered_len, maxlen);
        if (len <= 0) {
            break;
        }

        if (cur->state > TCP_ESTABLISHED) {
            fprintf(stderr, "Flushing after TCP_ESTABLISHED:seq:%u, len:%u, "
                "buffered_len:%u\n", seq, len, buffered_len);
        }

        if (seq - snd_var->snd_una + len > window) {
            /* ask for new window advertisement to peer */
            if (seq - snd_var->snd_una + len > snd_var->peer_wnd) {
                if (TS_TO_MSEC(cur_ts - snd_var->ts_last_ack_snd) > 
                    TCP_TIMEOUT_VAL) {
                        enqueue_ack(mmt, cur, cur_ts, ACK_OPT_WACK);
                }
                packets = -3;
                pthread_spin_unlock(&snd_var->write_lock);
                return packets;
            }
        }

        sndlen = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, data, len);
        if (sndlen < 0) {
            packets = sndlen;
            pthread_spin_unlock(&snd_var->write_lock);
            return packets;
        }
        packets++;
    }

    return packets;
}

/* send control packet: a core function
 * the tcp state machine */
inline int 
send_control_packet(mmutcpd_manager_t mmt, tcp_stream_t cur, uint32_t cur_ts)
{
    tcp_send_vars_t snd_var = cur->snd_var;
    int             ret = 0;

    switch (cur->state) {
        case TCP_SYN_SENT://send syn packet here
            ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_SYN, NULL, 0);
            break;

        case TCP_SYN_RECV://send syn/ack packet here
            cur->snd_nxt = snd_var->iss;
            ret = send_tcp_packet(mmt, cur, cur_ts, 
                TCP_FLAG_SYN|TCP_FLAG_ACK, NULL, 0);
            break;

        case TCP_ESTABLISHED://send ack here
            ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, NULL, 0);
            break;

        case TCP_CLOSE_WAIT://send ack for the fin
            ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, NULL, 0);
            break;

        case TCP_LAST_ACK:
            //if it is on ack list, send it after sending ack
            if (snd_var->on_send_list || snd_var->on_ack_list) {
                ret = -1;
            }  else {//send fin/ack here
                ret = send_tcp_packet(mmt, cur, cur_ts, 
                    TCP_FLAG_FIN|TCP_FLAG_ACK, NULL, 0);
            }
            break;

        case TCP_FIN_WAIT1:
            //if it is on ack list, send it after sending ack
            if (snd_var->on_send_list || snd_var->on_ack_list) {
                ret = -1;
            }  else {//send fin/ack here
                ret = send_tcp_packet(mmt, cur, cur_ts, 
                    TCP_FLAG_FIN|TCP_FLAG_ACK, NULL, 0);
            }
            break;

        case TCP_FIN_WAIT2://send ack here
            ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, NULL, 0);
            break;

        case TCP_CLOSING:
            if (snd_var->is_fin_sent) {
                /* if the seq is for FIN, send FIN */
                if (cur->snd_nxt == snd_var->fss) {/* TODO: FIN seq?? */
                    ret = send_tcp_packet(mmt, cur, cur_ts, 
                        TCP_FLAG_ACK|TCP_FLAG_FIN, NULL, 0);
                } else {
                    ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, 
                        NULL, 0);
                }
            } else {
                /* if FIN is not sent, send FIN with ack */
                ret = send_tcp_packet(mmt, cur, cur_ts, 
                    TCP_FLAG_FIN|TCP_FLAG_ACK, NULL, 0);
            }
            break;

        case TCP_TIME_WAIT://send ack here
            ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_ACK, NULL, 0);
            break;

        case TCP_CLOSE://closed, send RST here
            fprintf(stderr, "stream %d: try sending RST.\n", cur->id);
            /* first flush the data and ack */
            if (snd_var->on_send_list || snd_var->on_ack_list) {
                ret = -1;
            } else {
                ret = send_tcp_packet(mmt, cur, cur_ts, TCP_FLAG_RST, NULL, 0);
                if (ret >= 0) {
                    destroy_tcp_stream(mmt, cur);
                }
            }
            break;

        case default:
            ret = -1;
            break;
    }

    return ret;
}

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
add_to_control_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* add to send list */
inline void
add_to_send_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* add to ack list */
inline void 
add_to_ack_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* add to rto list */
inline void 
add_to_rto_list(mmutcpd_manager_t mmt, tcp_stream_t stream);

/* enqueue ack, this maybe a import position to change */
inline void 
enqueue_ack(mmutcpd_manager_t mmt, tcp_stream_t cur, 
    uint32_t cur_ts, uint8_t opt);

/* update timeout list */
inline void 
update_timeout_list(mmutcpd_manager_t mmt, tcp_stream_t cur)
{

}

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
#endif /* tcp_out */